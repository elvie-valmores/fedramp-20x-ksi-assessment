"""The extract service.

Periodically copies recent measurements out of Postgres into the S3 landing
prefix, where the GCP analytics pipeline picks them up. This is the AWS half
of the single cross-cloud data path in the architecture.

It has no listener and no ingress. Its security group permits outbound to the
database and to the VPC endpoints and nothing else, and no security group
anywhere permits inbound to it -- which is what makes the KSI-CNA-MAT
service-to-service test meaningful rather than decorative.
"""

import json
import logging
import os
import signal
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from common.db import connect, DatabaseUnavailable

LOG = logging.getLogger("worker")

_stop = False


def _handle_term(signum, frame) -> None:
    """Finish the current extract, then exit.

    ECS sends SIGTERM and waits before SIGKILL. Exiting mid-extract would
    leave a partial object in the landing prefix that the pipeline would
    read as complete.
    """
    global _stop
    LOG.info("signal %d received, stopping after this cycle", signum)
    _stop = True


def extract_since(cutoff: datetime) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, customer, metric, value, recorded_at
            FROM measurements
            WHERE recorded_at >= %s
            ORDER BY recorded_at
            """,
            (cutoff,),
        ).fetchall()

    return [
        {
            "id": r[0],
            "customer": r[1],
            "metric": r[2],
            "value": float(r[3]),
            "recorded_at": r[4].isoformat(),
        }
        for r in rows
    ]


def land(records: list[dict], bucket: str, prefix: str, region: str) -> str:
    """Write one newline-delimited JSON object into the landing prefix.

    Partitioned by date so the analytics side can read a day without
    scanning everything, matching the partitioning the log corpus already
    uses.
    """
    now = datetime.now(timezone.utc)
    key = (
        f"{prefix}/dt={now:%Y-%m-%d}/measurements-{now:%Y%m%dT%H%M%SZ}.ndjson"
    )

    body = "\n".join(json.dumps(record) for record in records).encode("utf-8")

    boto3.client("s3", region_name=region).put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType="application/x-ndjson",
        # The bucket enforces this too. Setting it here as well means a
        # misconfigured bucket fails the write rather than silently
        # accepting an unencrypted object.
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=os.environ["EXTRACT_KMS_KEY_ARN"],
    )

    return key


def cycle(bucket: str, prefix: str, region: str, window_minutes: int) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    try:
        records = extract_since(cutoff)
    except DatabaseUnavailable as exc:
        # Not fatal. The next cycle re-reads the same window, so a
        # transient database failure costs latency rather than data.
        LOG.warning("extract skipped: %s", exc)
        return

    if not records:
        # Recorded rather than passed over in silence. KSI-MLA-RVL's
        # position is that absence of a finding is only evidence if the
        # looking was recorded.
        LOG.info("extract window empty, nothing landed (cutoff=%s)", cutoff.isoformat())
        return

    try:
        key = land(records, bucket, prefix, region)
    except (BotoCoreError, ClientError) as exc:
        # Also not fatal, and for the same reason the database failure
        # above is not: the extract window overlaps the interval, so the
        # next cycle re-reads these rows and lands them. Letting this
        # propagate would exit the process, and ECS would replace a task
        # whose only problem was a transient S3 error.
        LOG.warning("landing failed, will retry next cycle: %s", exc.__class__.__name__)
        return

    LOG.info("landed %d records at s3://%s/%s", len(records), bucket, key)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    signal.signal(signal.SIGTERM, _handle_term)
    signal.signal(signal.SIGINT, _handle_term)

    bucket = os.environ["EXTRACT_BUCKET"]
    prefix = os.environ["EXTRACT_PREFIX"]
    region = os.environ["AWS_REGION"]
    interval = int(os.environ["EXTRACT_INTERVAL_SECONDS"])
    # Overlaps the interval deliberately. A window exactly equal to the
    # interval drops rows written during the extract itself.
    window_minutes = int(os.environ["EXTRACT_WINDOW_MINUTES"])

    LOG.info("worker started, extracting every %ds", interval)

    while not _stop:
        cycle(bucket, prefix, region, window_minutes)

        # Sleep in short steps so SIGTERM is noticed promptly rather than
        # after a full interval, which would mean ECS killing the task.
        slept = 0
        while slept < interval and not _stop:
            time.sleep(1)
            slept += 1

    LOG.info("worker stopped cleanly")


if __name__ == "__main__":
    main()
