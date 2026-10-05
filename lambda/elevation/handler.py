"""Just-in-time elevation: the record, the confirmation, and the backstop.

One function, four actions. The first three are steps of the elevation
workflow (infra/aws/elevation.tf); the fourth runs on its own schedule.

    request   validate the justification and the window, record the request
    granted   confirm Identity Center finished the assignment, record it, alert
    revoked   confirm the assignment is gone, record it
    sweep     every 15 minutes: remove any ElevatedAdmin assignment that no
              running elevation accounts for, or that has outlived the
              longest window; stop an execution that has

Every record is one JSON object in the log store under elevations/, Object
Locked and under the evidence key, beside the CloudTrail it corroborates.
requested_by is what the helper asserts. CloudTrail's StartExecution event,
which names the execution, is the authoritative caller.

The workflow fixes the user, the permission set and the account in its
definition. The input carries only the justification and the window, so
starting an elevation cannot elevate anyone else, or to anything else.
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

BUCKET = os.environ["LOG_BUCKET"]
TOPIC_ARN = os.environ["ALERT_TOPIC_ARN"]
INSTANCE_ARN = os.environ["INSTANCE_ARN"]
PERMISSION_SET_ARN = os.environ["PERMISSION_SET_ARN"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN", "")

MIN_JUSTIFICATION = 20
MIN_MINUTES, DEFAULT_MINUTES, MAX_MINUTES = 15, 60, 240
# The longest window, plus the time a grant and a revocation take.
MAX_AGE = timedelta(minutes=MAX_MINUTES + 15)
CONFIRM_ATTEMPTS = 20  # x 3 s; an assignment normally settles in seconds

s3 = boto3.client("s3")
sns = boto3.client("sns")
sso = boto3.client("sso-admin")
sfn = boto3.client("stepfunctions")


class Rejected(Exception):
    """The request fails validation. Named so the workflow's history says why."""


def validate(request: dict) -> tuple[str, int]:
    """Pure, so the tests can feed it what must be refused."""
    justification = str(request.get("justification") or "").strip()
    if len(justification) < MIN_JUSTIFICATION:
        raise Rejected(f"justification must be at least {MIN_JUSTIFICATION} characters")
    minutes = request.get("minutes", DEFAULT_MINUTES)
    if isinstance(minutes, bool) or not isinstance(minutes, int):
        raise Rejected("minutes must be a whole number")
    if not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise Rejected(f"minutes must be between {MIN_MINUTES} and {MAX_MINUTES}")
    return justification, minutes


def record(execution: str, phase: str, body: dict) -> str:
    now = datetime.now(timezone.utc)
    name = execution.rsplit(":", 1)[-1] if execution else "sweep"
    key = f"elevations/dt={now:%Y-%m-%d}/{name}-{phase}-{now:%H%M%S}.json"
    entry = {"phase": phase, "at": now.isoformat(), "execution": execution, **body}
    s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(entry).encode(), ContentType="application/json")
    return key


def alert(subject: str, message: dict) -> None:
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=json.dumps(message, indent=2))


def _settle(describe, field: str, request_id: str) -> dict:
    status = {}
    for _ in range(CONFIRM_ATTEMPTS):
        status = describe(InstanceArn=INSTANCE_ARN, **{field: request_id})
        status = status.get("AccountAssignmentCreationStatus") or status.get("AccountAssignmentDeletionStatus")
        if status["Status"] != "IN_PROGRESS":
            return status
        time.sleep(3)
    return status


def assignments() -> list[dict]:
    found, token = [], None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = sso.list_account_assignments(InstanceArn=INSTANCE_ARN, AccountId=ACCOUNT_ID,
                                            PermissionSetArn=PERMISSION_SET_ARN, **kwargs)
        found += page["AccountAssignments"]
        token = page.get("NextToken")
        if not token:
            return found


def revoke(principal_id: str, principal_type: str) -> dict:
    request = sso.delete_account_assignment(
        InstanceArn=INSTANCE_ARN, TargetId=ACCOUNT_ID, TargetType="AWS_ACCOUNT",
        PermissionSetArn=PERMISSION_SET_ARN, PrincipalType=principal_type, PrincipalId=principal_id,
    )["AccountAssignmentDeletionStatus"]
    return _settle(sso.describe_account_assignment_deletion_status,
                   "AccountAssignmentDeletionRequestId", request["RequestId"])


def running_executions() -> list[dict]:
    found, token = [], None
    while True:
        kwargs = {"nextToken": token} if token else {}
        page = sfn.list_executions(stateMachineArn=STATE_MACHINE_ARN, statusFilter="RUNNING", **kwargs)
        found += page["executions"]
        token = page.get("nextToken")
        if not token:
            return found


def sweep_decision(assigned: list[dict], running: list[dict], now: datetime) -> tuple[list[dict], list[dict]]:
    """Pure: which executions to stop, and which assignments to remove.

    An execution older than MAX_AGE is stopped, whatever it is doing. An
    assignment is removed when no execution young enough to account for it
    is still running -- a workflow that failed before revoking, one that
    was stopped, or an assignment made by hand.
    """
    stale = [e for e in running if now - e["startDate"] > MAX_AGE]
    live = [e for e in running if e not in stale]
    orphaned = assigned if not live else []
    return stale, orphaned


def handler(event, context):
    action = event.get("action")
    execution = event.get("execution", "")

    if action == "request":
        request = event.get("input") or {}
        try:
            justification, minutes = validate(request)
        except Rejected as error:
            record(execution, "refused", {"input": request, "why": str(error)})
            raise
        key = record(execution, "requested", {
            "justification": justification, "minutes": minutes,
            "requested_by": request.get("requested_by"),
        })
        return {"seconds": minutes * 60, "minutes": minutes, "justification": justification, "record": key}

    if action == "granted":
        status = _settle(sso.describe_account_assignment_creation_status,
                         "AccountAssignmentCreationRequestId", event["request_id"])
        body = {"status": status.get("Status"), "failure": status.get("FailureReason"),
                "justification": event.get("justification"), "minutes": event.get("minutes")}
        record(execution, "granted" if status.get("Status") == "SUCCEEDED" else "grant-failed", body)
        if status.get("Status") != "SUCCEEDED":
            raise RuntimeError(f"assignment did not succeed: {status.get('FailureReason')}")
        alert("Elevation granted: ElevatedAdmin", {**body, "execution": execution})
        return {"status": "SUCCEEDED"}

    if action == "revoked":
        status = _settle(sso.describe_account_assignment_deletion_status,
                         "AccountAssignmentDeletionRequestId", event["request_id"])
        record(execution, "revoked" if status.get("Status") == "SUCCEEDED" else "revoke-failed",
               {"status": status.get("Status"), "failure": status.get("FailureReason")})
        if status.get("Status") != "SUCCEEDED":
            raise RuntimeError(f"revocation did not succeed: {status.get('FailureReason')}")
        return {"status": "SUCCEEDED"}

    if action == "sweep":
        now = datetime.now(timezone.utc)
        stale, orphaned = sweep_decision(assignments(), running_executions(), now)
        for e in stale:
            sfn.stop_execution(executionArn=e["executionArn"], cause="exceeded the longest elevation window")
        removed = []
        for a in orphaned:
            status = revoke(a["PrincipalId"], a["PrincipalType"])
            removed.append({"principal": a["PrincipalId"], "status": status.get("Status"),
                            "failure": status.get("FailureReason")})
        if stale or removed:
            body = {"stopped": [e["executionArn"] for e in stale], "removed": removed}
            record("", "swept", body)
            alert("Elevation backstop acted", body)
        return {"stopped": len(stale), "removed": len(removed)}

    raise ValueError(f"unknown action {action!r}")
