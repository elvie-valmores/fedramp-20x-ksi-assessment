"""KSI-MLA-OSM build item 2 (scoped): schema normalization, AWS side.

Triggered by S3 ObjectCreated on the central log store's CloudTrail
prefix. Reads a CloudTrail log file, maps each event to an OCSF-lite
record -- critical event classes first (Authentication, API Activity),
per the documented adoption norm -- and writes normalized NDJSON,
partitioned by source and date, back into the same object-locked store.

Scope for this build: AWS side only, NDJSON rather than compiled
Parquet. See docs/DECISIONS.md, 2026-09-19. GCP-side normalization and
NDJSON-to-Parquet compaction are deferred.
"""

import gzip
import json
import time
import urllib.parse
from datetime import datetime, timezone

import boto3

s3 = boto3.client("s3")

AUTH_EVENT_NAMES = {
    "ConsoleLogin",
    "AssumeRole",
    "AssumeRoleWithSAML",
    "AssumeRoleWithWebIdentity",
    "GetSessionToken",
    "GetFederationToken",
}


def _to_ocsf(record: dict, account_id: str) -> dict:
    event_name = record.get("eventName", "")
    is_auth = event_name in AUTH_EVENT_NAMES
    error_code = record.get("errorCode")

    event_time = record.get("eventTime")
    try:
        dt = datetime.strptime(event_time, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        time_ms = int(dt.timestamp() * 1000)
    except (TypeError, ValueError):
        time_ms = int(time.time() * 1000)

    user_identity = record.get("userIdentity", {}) or {}

    return {
        "time": time_ms,
        "class_uid": 3002 if is_auth else 6003,
        "class_name": "Authentication" if is_auth else "API Activity",
        "category_uid": 3 if is_auth else 6,
        "severity_id": 1,
        "status": "Failure" if error_code else "Success",
        "status_detail": error_code,
        "cloud": {
            "provider": "AWS",
            "account_uid": account_id,
            "region": record.get("awsRegion"),
        },
        "actor": {
            "user": {
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
    account_id = context.invoked_function_arn.split(":")[4]
    processed = 0

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])

        obj = s3.get_object(Bucket=bucket, Key=key)
        raw = gzip.decompress(obj["Body"].read())
        payload = json.loads(raw)

        ocsf_records = [_to_ocsf(r, account_id) for r in payload.get("Records", [])]
        if not ocsf_records:
            continue

        ndjson = "\n".join(json.dumps(r) for r in ocsf_records).encode("utf-8")
        compressed = gzip.compress(ndjson)

        dt_partition = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        out_key = (
            f"normalized-raw/source=aws/dt={dt_partition}/"
            f"{context.aws_request_id}.json.gz"
        )

        s3.put_object(
            Bucket=bucket,
            Key=out_key,
            Body=compressed,
            ContentType="application/x-ndjson",
            ContentEncoding="gzip",
        )
        processed += len(ocsf_records)

    return {"processed": processed}
