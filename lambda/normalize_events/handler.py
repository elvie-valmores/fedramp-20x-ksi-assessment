"""Converts raw CloudTrail logs into a normalized, queryable format.

Runs automatically whenever CloudTrail drops a new log file into the
central log store. Reads that file, rewrites each event into a common
schema, and writes the result back to the same bucket under a separate
prefix.

Why rewrite at all: CloudTrail's own format is AWS-shaped, and the
eventual goal is querying AWS and GCP events together. Both clouds get
mapped to the same field names -- loosely following OCSF, an open
schema for security events -- so a single query can span both. AWS calls
something a user that GCP calls an account; normalizing here means the
query doesn't have to care.

Output is newline-delimited JSON, one event per line, gzipped, written
to a path that encodes the source and date:

    normalized-raw/source=aws/dt=2026-09-19/<id>.json.gz

That layout is what makes the data cheap to query. Athena reads the
partition values straight out of the path, so a query filtered to one
day only opens that day's files.
"""

import gzip
import json
import time
import urllib.parse
from datetime import datetime, timezone

import boto3

s3 = boto3.client("s3")

# Events that represent someone or something authenticating. Everything
# else is treated as general API activity. Two classes is deliberate --
# these are the ones worth alerting on, and unmapped events still land
# and stay queryable, just less specifically labeled.
AUTH_EVENT_NAMES = {
    "ConsoleLogin",
    "AssumeRole",
    "AssumeRoleWithSAML",
    "AssumeRoleWithWebIdentity",
    "GetSessionToken",
    "GetFederationToken",
    # Identity Center sign-in, the workforce path since 2026-09-22. Missing
    # until 2026-10-01, so every workforce sign-in -- failed or not -- was
    # filed as API Activity, where the failed-authentication detection
    # never looks.
    "ExternalIdPDirectoryLogin",
    "UserAuthentication",
    "CredentialChallenge",
    "CredentialVerification",
    "Authenticate",
    "Federate",
}


def _failed(record: dict) -> bool:
    """Whether CloudTrail recorded this event as a failure.

    Two conventions. Most API calls fail by carrying an errorCode. Sign-in
    events do not: ConsoleLogin, ExternalIdPDirectoryLogin and their kin
    report the outcome as {"<eventName>": "Failure"} in responseElements,
    with no errorCode at all. Reading errorCode alone recorded every failed
    sign-in as a success (DECISIONS.md, 2026-10-01).
    """
    if record.get("errorCode"):
        return True
    response = record.get("responseElements")
    if isinstance(response, dict):
        return response.get(record.get("eventName")) == "Failure"
    return False


def _to_ocsf(record: dict, account_id: str) -> dict:
    """Rewrite one CloudTrail event into the normalized schema."""
    event_name = record.get("eventName", "")
    is_auth = event_name in AUTH_EVENT_NAMES
    failed = _failed(record)

    # Timestamps become epoch milliseconds so events from different
    # clouds sort together without any timezone ambiguity. If CloudTrail
    # sends something unparseable, fall back to now rather than dropping
    # the event entirely.
    try:
        parsed = datetime.strptime(
            record.get("eventTime"), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        time_ms = int(parsed.timestamp() * 1000)
    except (TypeError, ValueError):
        time_ms = int(time.time() * 1000)

    user_identity = record.get("userIdentity", {}) or {}

    return {
        "time": time_ms,
        # Numeric class IDs come from OCSF; the names are carried
        # alongside so queries can be written either way.
        "class_uid": 3002 if is_auth else 6003,
        "class_name": "Authentication" if is_auth else "API Activity",
        "category_uid": 3 if is_auth else 6,
        "severity_id": 1,
        "status": "Failure" if failed else "Success",
        # The errorCode where there is one; a sign-in failure has only its
        # message ("Failed authentication", "Responses must contain exactly
        # one Assertion").
        "status_detail": record.get("errorCode") or (record.get("errorMessage") if failed else None),
        "cloud": {
            "provider": "AWS",
            "account_uid": account_id,
            "region": record.get("awsRegion"),
        },
        "actor": {
            "user": {
                # Named users have userName; assumed roles and services
                # only carry an ARN; an Identity Center user carries
                # neither, only the directory's user ID in onBehalfOf.
                "name": user_identity.get("userName")
                or user_identity.get("arn")
                or (user_identity.get("onBehalfOf") or {}).get("userId"),
                "uid": user_identity.get("principalId"),
                "type": user_identity.get("type"),
            }
        },
        "api": {
            "operation": event_name,
            "service": {"name": record.get("eventSource")},
            # CloudTrail's own read/write classification, so a query for
            # changes need not guess from operation names (2026-10-06).
            "read_only": record.get("readOnly"),
        },
        # Whether a sign-in used MFA: ConsoleLogin's MFAUsed, as OCSF's
        # is_mfa. Null on everything that is not a console sign-in.
        "is_mfa": _mfa_used(record),
        "src_endpoint": {"ip": record.get("sourceIPAddress")},
        # What the call acted on, e.g. the key a Decrypt used. Kept since
        # 2026-10-02: without it no query can tell a customer key from an
        # AWS-managed one, or which store a data event touched.
        # The connection's TLS, absent when the request was not over TLS --
        # or when AWS made the call internally, which a query tells apart
        # by the source being a service name rather than an address
        # (2026-10-02).
        "tls": {
            "version": (record.get("tlsDetails") or {}).get("tlsVersion"),
            "cipher": (record.get("tlsDetails") or {}).get("cipherSuite"),
        },
        "resources": [
            {"uid": r.get("ARN"), "type": r.get("type")}
            for r in (record.get("resources") or [])
        ],
        "metadata": {
            "original_source": "aws_cloudtrail",
            "original_event_id": record.get("eventID"),
            # Management, Data or Insight: what a query for configuration
            # changes filters to (2026-10-06).
            "event_category": record.get("eventCategory"),
        },
    }


def _mfa_used(record: dict):
    used = (record.get("additionalEventData") or {}).get("MFAUsed")
    return None if used is None else used == "Yes"


def handler(event, context):
    """Entry point. Receives an S3 notification, writes normalized output."""
    # The account ID isn't in the S3 event, but it is in this function's
    # own ARN: arn:aws:lambda:<region>:<account>:function:<name>
    account_id = context.invoked_function_arn.split(":")[4]
    processed = 0

    # One notification can reference several objects.
    for notification in event.get("Records", []):
        bucket = notification["s3"]["bucket"]["name"]
        # S3 URL-encodes object keys in notifications, so decode before use.
        key = urllib.parse.unquote_plus(notification["s3"]["object"]["key"])

        obj = s3.get_object(Bucket=bucket, Key=key)
        payload = json.loads(gzip.decompress(obj["Body"].read()))

        # CloudTrail batches many events into one file.
        normalized = [
            _to_ocsf(cloudtrail_event, account_id)
            for cloudtrail_event in payload.get("Records", [])
        ]
        if not normalized:
            continue

        # Newline-delimited JSON: one object per line, which is what lets
        # a query engine split a file across readers.
        body = "\n".join(json.dumps(item) for item in normalized).encode("utf-8")

        partition_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        out_key = (
            f"normalized-raw/source=aws/dt={partition_date}/"
            f"{context.aws_request_id}.json.gz"
        )

        s3.put_object(
            Bucket=bucket,
            Key=out_key,
            Body=gzip.compress(body),
            ContentType="application/x-ndjson",
            ContentEncoding="gzip",
        )
        processed += len(normalized)

    return {"processed": processed}
