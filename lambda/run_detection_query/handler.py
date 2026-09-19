"""KSI-MLA-OSM build item 5 (scoped): one detection query.

Fired on a schedule by EventBridge. Queries the normalized corpus via
Athena for failed authentication events in the last 24 hours and
publishes to the interim alert topic if it finds any.

Interim, not final: this should route into the shared detection path
(KSI-IAM-SUS's build), which doesn't exist yet. Routes to a standalone
SNS topic instead until that's built. See docs/DECISIONS.md, 2026-09-19.
"""

import os
import time

import boto3

athena = boto3.client("athena")
sns = boto3.client("sns")

DATABASE = os.environ["ATHENA_DATABASE"]
WORKGROUP = os.environ["ATHENA_WORKGROUP"]
TOPIC_ARN = os.environ["ALERT_TOPIC_ARN"]

QUERY = """
SELECT time, actor.user.name AS user_name, src_endpoint.ip AS source_ip
FROM normalized_events
WHERE class_name = 'Authentication'
  AND status = 'Failure'
  AND dt >= date_format(date_add('day', -1, current_date), '%Y-%m-%d')
"""


def handler(event, context):
    execution = athena.start_query_execution(
        QueryString=QUERY,
        QueryExecutionContext={"Database": DATABASE},
        WorkGroup=WORKGROUP,
    )
    query_id = execution["QueryExecutionId"]

    state = "RUNNING"
    for _ in range(30):
        status = athena.get_query_execution(QueryExecutionId=query_id)
        state = status["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(2)

    if state != "SUCCEEDED":
        reason = status["QueryExecution"]["Status"].get("StateChangeReason", "unknown")
        raise RuntimeError(f"detection query {state}: {reason}")

    results = athena.get_query_results(QueryExecutionId=query_id)
    rows = results["ResultSet"]["Rows"][1:]  # skip header row

    if rows:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="fedramp-20x-ksi: failed console login detection",
            Message=(
                f"Detection query found {len(rows)} failed authentication "
                "event(s) in the last 24h."
            ),
        )

    return {"matches": len(rows)}
