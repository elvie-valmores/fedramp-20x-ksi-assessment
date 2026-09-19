"""Scheduled detection: alerts on failed authentication attempts.

Runs daily. Queries the normalized log corpus for authentication events
that failed in the last 24 hours, and sends an alert if it finds any.
Silent when there is nothing to report.

This is detection-as-code: the query is versioned in this file rather
than configured in a console, so a change to what counts as suspicious
shows up in the repo's history.

Where alerts go is temporary. They currently land on a standalone SNS
topic because the project's shared incident-response path doesn't exist
yet. When it does, only the ALERT_TOPIC_ARN environment variable needs
to change.
"""

import os
import time

import boto3

athena = boto3.client("athena")
sns = boto3.client("sns")

DATABASE = os.environ["ATHENA_DATABASE"]
WORKGROUP = os.environ["ATHENA_WORKGROUP"]
TOPIC_ARN = os.environ["ALERT_TOPIC_ARN"]

# The dt filter is what keeps this cheap: it limits the scan to the last
# two days of files rather than the whole corpus. Two days, not one, so
# events near midnight aren't missed when the partition rolls over.
QUERY = """
SELECT time, actor.user.name AS user_name, src_endpoint.ip AS source_ip
FROM normalized_events
WHERE class_name = 'Authentication'
  AND status = 'Failure'
  AND dt >= date_format(date_add('day', -1, current_date), '%Y-%m-%d')
"""

POLL_INTERVAL_SECONDS = 2
POLL_ATTEMPTS = 30


def handler(event, context):
    # Athena is asynchronous: this returns an ID immediately, and the
    # query runs in the background.
    execution = athena.start_query_execution(
        QueryString=QUERY,
        QueryExecutionContext={"Database": DATABASE},
        WorkGroup=WORKGROUP,
    )
    query_id = execution["QueryExecutionId"]

    state = "RUNNING"
    for _ in range(POLL_ATTEMPTS):
        status = athena.get_query_execution(QueryExecutionId=query_id)
        state = status["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(POLL_INTERVAL_SECONDS)

    # Raising makes the Lambda invocation fail, which trips the error
    # alarm. A detection that silently stopped running is worse than one
    # that loudly breaks.
    if state != "SUCCEEDED":
        reason = status["QueryExecution"]["Status"].get("StateChangeReason", "unknown")
        raise RuntimeError(f"detection query {state}: {reason}")

    results = athena.get_query_results(QueryExecutionId=query_id)
    rows = results["ResultSet"]["Rows"][1:]  # row 0 is the column header

    if rows:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="fedramp-20x-ksi: failed authentication detected",
            Message=(
                f"Detection query found {len(rows)} failed authentication "
                "event(s) in the last 24h."
            ),
        )

    return {"matches": len(rows)}
