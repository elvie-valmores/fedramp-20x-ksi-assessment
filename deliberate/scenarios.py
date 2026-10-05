"""The deliberate test scenarios. Each takes a boto3 session and returns
(passed, expected, observed). The catalogue, with the rows each answers, is
scenarios.yaml; the runner and the record are run.py.

Each scenario states what a broken control would produce, and passes only
on the opposite. A test that cannot tell the two apart proves nothing.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

REGION = "us-east-1"
LOG_BUCKET = "fedramp-20x-ksi-log-store-437672023758"
STATE_BUCKET = "fedramp-20x-ksi-tfstate-437672023758"
REPOSITORY = "elvie-valmores/fedramp-20x-ksi-assessment"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _refused(call) -> str | None:
    """The error code if the call was refused, None if it went through."""
    try:
        call()
    except ClientError as error:
        return error.response["Error"]["Code"]
    return None


def object_lock_rejects_change(session) -> tuple[bool, str, dict]:
    s3 = session.client("s3", region_name=REGION)
    # The newest collector run record: always within its 7-day lock, and
    # duplicated in that run's CI artifact, so the least costly to lose if
    # the lock did not hold.
    versions = s3.list_object_versions(Bucket=LOG_BUCKET, Prefix="collector-runs/")["Versions"]
    target = max(versions, key=lambda v: v["LastModified"])
    key, version = target["Key"], target["VersionId"]
    before = s3.head_object(Bucket=LOG_BUCKET, Key=key, VersionId=version)
    attempts = {
        "delete the version": _refused(lambda: s3.delete_object(Bucket=LOG_BUCKET, Key=key, VersionId=version)),
        "delete it, bypassing governance": _refused(lambda: s3.delete_object(
            Bucket=LOG_BUCKET, Key=key, VersionId=version, BypassGovernanceRetention=True)),
        "shorten its retention": _refused(lambda: s3.put_object_retention(
            Bucket=LOG_BUCKET, Key=key, VersionId=version,
            Retention={"Mode": "COMPLIANCE", "RetainUntilDate": _now() + dt.timedelta(hours=1)})),
    }
    after = s3.head_object(Bucket=LOG_BUCKET, Key=key, VersionId=version)
    survived = after["ObjectLockRetainUntilDate"] == before["ObjectLockRetainUntilDate"]
    observed = {"object": key, "version": version, "mode": before.get("ObjectLockMode"),
                "retain_until": str(before["ObjectLockRetainUntilDate"]),
                "refused_with": attempts, "version_intact_with_same_retention": survived}
    return (all(attempts.values()) and survived,
            "every attempt refused, and the version still present with its retention unchanged", observed)


def _drift_run(after: dt.datetime) -> dict:
    subprocess.run(["gh", "workflow", "run", "drift.yml", "--repo", REPOSITORY], check=True, capture_output=True)
    run = None
    for _ in range(40):
        time.sleep(10)
        runs = json.loads(subprocess.run(
            ["gh", "run", "list", "--repo", REPOSITORY, "--workflow", "drift.yml", "--event", "workflow_dispatch",
             "-L", "5", "--json", "databaseId,createdAt,status,conclusion"],
            check=True, capture_output=True, text=True).stdout)
        mine = [r for r in runs if dt.datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00")) >= after]
        if mine and mine[0]["status"] == "completed":
            run = mine[0]
            break
    if run is None:
        raise TimeoutError("the drift run did not finish within ~7 minutes")
    log = subprocess.run(["gh", "run", "view", str(run["databaseId"]), "--repo", REPOSITORY, "--log"],
                         capture_output=True, text=True).stdout
    return {"run": run["databaseId"], "conclusion": run["conclusion"], "log": log}


def out_of_band_change_detected(session) -> tuple[bool, str, dict]:
    logs = session.client("logs", region_name=REGION)
    account = session.client("sts").get_caller_identity()["Account"]
    group = "/aws/lambda/fedramp-20x-ksi-elevation"
    arn = f"arn:aws:logs:{REGION}:{account}:log-group:{group}"
    address = "aws_cloudwatch_log_group.elevation"
    stamp = _now().strftime("%Y%m%dT%H%M%SZ")

    changed_at = _now()
    logs.tag_resource(resourceArn=arn, tags={"deliberate-test": stamp})
    try:
        drifted = _drift_run(changed_at)
    finally:
        logs.untag_resource(resourceArn=arn, tagKeys=["deliberate-test"])
    reverted_at = _now()
    clean = _drift_run(reverted_at)
    caught = drifted["conclusion"] == "failure" and address in drifted["log"] and "deliberate-test" in drifted["log"]
    observed = {"changed": {"resource": group, "tag": stamp, "at": changed_at.isoformat()},
                "drift_run": {"id": drifted["run"], "conclusion": drifted["conclusion"],
                              "named_the_resource": address in drifted["log"]},
                "after_revert": {"id": clean["run"], "conclusion": clean["conclusion"]},
                "detected_within_minutes": round((_now() - changed_at).total_seconds() / 60, 1)}
    return (caught and clean["conclusion"] == "success",
            "the drift run after the change fails naming the tagged resource, and the run after reverting passes",
            observed)


def delivery_failure_alerts(session) -> tuple[bool, str, dict]:
    lam = session.client("lambda", region_name=REGION)
    cw = session.client("cloudwatch", region_name=REGION)
    alarm = "fedramp-20x-ksi-normalize-events-errors"
    event = {"Records": [{"s3": {"bucket": {"name": LOG_BUCKET},
                                 "object": {"key": f"deliberate-test/missing-{int(time.time())}.json.gz"}}}]}
    invoked_at = _now()
    result = lam.invoke(FunctionName="fedramp-20x-ksi-normalize-events", Payload=json.dumps(event).encode())
    failed = "FunctionError" in result
    entered = None
    for _ in range(60):  # the alarm's period is 5 minutes; allow 10
        history = cw.describe_alarm_history(AlarmName=alarm, HistoryItemType="StateUpdate",
                                            StartDate=invoked_at, MaxRecords=10)["AlarmHistoryItems"]
        to_alarm = [h for h in history if json.loads(h["HistoryData"])["newState"]["stateValue"] == "ALARM"]
        if to_alarm:
            entered = to_alarm[-1]
            break
        time.sleep(10)
    actions = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0]["AlarmActions"]
    observed = {"invoked_at": invoked_at.isoformat(), "function_failed": failed,
                "alarm_entered_at": entered and entered["Timestamp"].isoformat(),
                "minutes_to_alarm": entered and round((entered["Timestamp"] - invoked_at).total_seconds() / 60, 1),
                "alarm_notifies": actions}
    return (failed and entered is not None and any("detection" in a for a in actions),
            "the normalizer fails, and its error alarm enters ALARM and notifies the detection topic", observed)


def prior_state_recoverable(session) -> tuple[bool, str, dict]:
    s3 = session.client("s3", region_name=REGION)
    ecs = session.client("ecs", region_name=REGION)
    key = "aws/terraform.tfstate"
    versions = [v for v in s3.list_object_versions(Bucket=STATE_BUCKET, Prefix=key)["Versions"] if v["Key"] == key]
    current = next(v for v in versions if v["IsLatest"])
    oldest = min(versions, key=lambda v: v["LastModified"])
    state = lambda v: json.loads(s3.get_object(Bucket=STATE_BUCKET, Key=key, VersionId=v["VersionId"])["Body"].read())
    now_state, old_state = state(current), state(oldest)
    families = ecs.list_task_definitions(familyPrefix="fedramp-20x-ksi-api", sort="ASC", status="INACTIVE")["taskDefinitionArns"] \
        or ecs.list_task_definitions(familyPrefix="fedramp-20x-ksi-api", sort="ASC")["taskDefinitionArns"]
    task = ecs.describe_task_definition(taskDefinition=families[0])["taskDefinition"] if families else None
    observed = {"state_versions": len(versions), "oldest": str(oldest["LastModified"]),
                "depth_days": (_now() - oldest["LastModified"]).days,
                "oldest_serial": old_state.get("serial"), "current_serial": now_state.get("serial"),
                "same_lineage": old_state.get("lineage") == now_state.get("lineage"),
                "oldest_resources": len(old_state.get("resources", [])),
                "task_definition": task and {"arn": task["taskDefinitionArn"], "status": task["status"],
                                             "image": task["containerDefinitions"][0]["image"]}}
    ok = (len(versions) > 1 and old_state.get("serial", 0) < now_state.get("serial", 0)
          and observed["same_lineage"] and old_state.get("resources") and task is not None)
    return ok, "an older state version of the same lineage and a prior task definition are both retrievable", observed


def historical_advisory_surfaced(session) -> tuple[bool, str, dict]:
    expected = {"CVE-2021-33503", "GHSA-q2q7-5pp4-w6pg"}
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp) / "requirements.txt"
        manifest.write_text("urllib3==1.26.4\n")
        out = subprocess.run([sys.executable, "-m", "pip_audit", "-r", str(manifest), "--no-deps", "--disable-pip",
                              "--progress-spinner", "off", "-f", "json"], capture_output=True, text=True)
    if not out.stdout.strip():
        raise RuntimeError(f"pip-audit produced nothing: {out.stderr.strip()[:300]}")
    report = json.loads(out.stdout)
    found = {i for d in report.get("dependencies", []) for v in d.get("vulns", [])
             for i in [v["id"], *v.get("aliases", [])]}
    observed = {"package": "urllib3==1.26.4", "advisories_reported": sorted(found),
                "expected_among_them": sorted(expected & found), "exit_code": out.returncode}
    return bool(expected & found) and out.returncode != 0, \
        "pip-audit reports CVE-2021-33503 for urllib3 1.26.4 and exits non-zero, which fails a build", observed


SCENARIOS = {f.__name__: f for f in (object_lock_rejects_change, out_of_band_change_detected,
                                       delivery_failure_alerts, prior_state_recoverable,
                                       historical_advisory_surfaced)}
