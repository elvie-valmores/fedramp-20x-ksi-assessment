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
}


def _to_ocsf(record: dict, account_id: str) -> dict:
    """Rewrite one CloudTrail event into the normalized schema."""
    event_name = record.get("eventName", "")
    is_auth = event_name in AUTH_EVENT_NAMES
    error_code = record.get("errorCode")

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
        # CloudTrail reports failure by including an errorCode, not by a
        # status field, so absence of that key means success.
        "status": "Failure" if error_code else "Success",
        "status_detail": error_code,
        "cloud": {
            "provider": "AWS",
            "account_uid": account_id,
            "region": record.get("awsRegion"),
        },
        "actor": {
            "user": {
                # Named users have userName; assumed roles and services
                # only carry an ARN.
                "name": user_identity.get("userName") or user_identity.get("arn"),
                "uid": user_identity.get("principalId"),
                "type": user_identity.get("type"),
            }
        },
        "api": {
            "operation": event_name,
            "service": {"name": record.get("eventSource")},
        },
        "src_endpoint": {"ip": record.get("sourceIPAddress")},
        "metadata": {
            "original_source": "aws_cloudtrail",
            "original_event_id": record.get("eventID"),
        },
    }


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
