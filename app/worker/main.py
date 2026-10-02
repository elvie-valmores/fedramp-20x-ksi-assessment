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
import re
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


# How far behind the previous extract's mark each extract starts. A row is
# stamped when its transaction starts (recorded_at defaults to now()) but is
# visible only once it commits, so a row can be stamped before a mark and
# appear after it. The overlap re-reads that tail; the analytics MERGE on
# (id, recorded_at) makes the repeat harmless.
OVERLAP = timedelta(minutes=5)

# The mark's place in the object key, and the pattern that reads it back.
MARK_FORMAT = "%Y%m%dT%H%M%SZ"
_MARK_IN_KEY = re.compile(r"-through-(\d{8}T\d{6}Z)\.ndjson$")


def extract_after(mark: datetime | None) -> tuple[datetime, list[dict]]:
    """The rows past the previous mark, and the mark this extract reads through.

    The new mark is the database's clock, read before the rows: every row
    stamped at or before it either is in this result or was uncommitted at
    the time, which is what the overlap covers. Taking it from the database
    rather than the worker means a skewed task clock cannot open a gap.
    With no previous mark, every row is read; the table is rebuilt each
    session, so that is the session's rows and no more.
    """
    query = "SELECT id, customer, metric, value, recorded_at FROM measurements"
    params: tuple = ()
    if mark is not None:
        query += " WHERE recorded_at > %s"
        params = (mark - OVERLAP,)

    with connect() as conn:
        through = conn.execute("SELECT now()").fetchone()[0]
        rows = conn.execute(query + " ORDER BY recorded_at", params).fetchall()

    return through, [
        {
            "id": r[0],
            "customer": r[1],
            "metric": r[2],
            "value": float(r[3]),
            "recorded_at": r[4].isoformat(),
        }
        for r in rows
    ]


def land(records: list[dict], through: datetime, bucket: str, prefix: str, region: str) -> str:
    """Write one newline-delimited JSON object into the landing prefix.

    Partitioned by date so the analytics side can read a day without
    scanning everything, matching the partitioning the log corpus already
    uses.

    The key carries the extract's high-water mark: `-through-<mark>` is
    the database time this extract read through, and the next cycle starts
    from it (see landed_mark). That is the worker's durable state. The
    worker itself restarts with no memory and ECS replaces it freely, but
    the extracts outlive it, and a mark that lives on the extract it
    describes cannot claim rows that never landed: a failed write leaves
    no key, so the previous mark stands and the next cycle re-reads the
    same rows.

    Until 2026-10-02 there was no mark, only a window: each cycle read the
    last twenty minutes, every fifteen. A failed landing's rows older than
    the five-minute overlap had left the window by the next cycle and were
    never landed. See DECISIONS.md, 2026-10-02.

    **This is at-least-once delivery.** Rows in the overlap behind each
    mark land twice, and a retry after a write whose response was lost
    lands them again. It is a contract the analytics side has to honour:
    **deduplicate on (`id`, `recorded_at`)**, which together name one row
    across landings and across database rebuilds; `id` alone restarts with
    every rebuilt database.
    """
    now = datetime.now(timezone.utc)
    # Wall-clock first, so keys list in landing order for a reader.
    key = (
        f"{prefix}/dt={now:%Y-%m-%d}/"
        f"measurements-{now:%Y%m%dT%H%M%SZ}-through-{through.astimezone(timezone.utc):{MARK_FORMAT}}.ndjson"
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


def landed_mark(bucket: str, prefix: str, region: str) -> datetime | None:
    """The newest landed extract's mark, or None if no extract carries one.

    Read from key names by listing, so the worker needs no read access to
    the extracts themselves. The listing is the whole prefix: extracts
    expire after thirty days, which bounds it at a few pages. The largest
    mark wins, not the last key: keys sort by the worker's clock, marks by
    the database's, and only the database's decides what was read. An
    extract landed before marks existed carries none and is passed over.
    """
    s3 = boto3.client("s3", region_name=region)
    mark = None
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=f"{prefix}/"):
        for obj in page.get("Contents", []):
            found = _MARK_IN_KEY.search(obj["Key"])
            # Fixed-width, so the largest string is the latest time.
            if found and (mark is None or found.group(1) > mark):
                mark = found.group(1)
    if mark is None:
        return None
    return datetime.strptime(mark, MARK_FORMAT).replace(tzinfo=timezone.utc)


def cycle(bucket: str, prefix: str, region: str) -> None:
    try:
        mark = landed_mark(bucket, prefix, region)
    except (BotoCoreError, ClientError) as exc:
        # Without the mark the cycle cannot know where to start. Skipping
        # costs latency; guessing could cost rows.
        LOG.warning("extract skipped, high-water mark unreadable: %s", exc.__class__.__name__)
        return

    try:
        through, records = extract_after(mark)
    except DatabaseUnavailable as exc:
        # Not fatal. The mark has not moved, so the next cycle reads the
        # same rows: a transient database failure costs latency, not data.
        LOG.warning("extract skipped: %s", exc)
        return

    if not records:
        # Recorded rather than passed over in silence. KSI-MLA-RVL's
        # position is that absence of a finding is only evidence if the
        # looking was recorded.
        LOG.info("nothing new since the high-water mark, nothing landed (mark=%s)", mark.isoformat() if mark else None)
        return

    try:
        key = land(records, through, bucket, prefix, region)
    except (BotoCoreError, ClientError) as exc:
        # Also not fatal, and for the same reason the database failure
        # above is not: nothing landed, so the mark has not moved and the
        # next cycle re-reads these rows. Letting this propagate would exit
        # the process, and ECS would replace a task whose only problem was
        # a transient S3 error.
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

    LOG.info("worker started, extracting every %ds", interval)

    while not _stop:
        cycle(bucket, prefix, region)

        # Sleep in short steps so SIGTERM is noticed promptly rather than
        # after a full interval, which would mean ECS killing the task.
        slept = 0
        while slept < interval and not _stop:
            time.sleep(1)
            slept += 1

    LOG.info("worker stopped cleanly")


if __name__ == "__main__":
    main()
