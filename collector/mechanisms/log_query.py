"""Mechanism: run a SQL query against the normalized log corpus.

Used for evidence that depends on what actually happened, rather than on
how something is configured. Queries run through Athena against the
tables built in infra/aws/log_normalization.tf.

Check params:
    region      AWS region to query in
    database    Glue database holding the tables
    workgroup   Athena workgroup (carries the per-query scan limit)
    query       the SQL to run
    expect      "any_rows" (default) or "no_rows"

The SQL lives in the check definition rather than being assembled here.
Evidence queries vary too much to express as parameters, and a query
written out in full is also the clearest record of what was asked.

"no_rows" is the more common shape in practice: most security evidence is
the absence of something, e.g. "no unencrypted buckets," and an empty
result set is what proves it.
"""

from __future__ import annotations

import time

import boto3

from base import CheckDefinition, CheckResult, Mechanism

POLL_INTERVAL_SECONDS = 2
POLL_ATTEMPTS = 30  # ~60s ceiling; these queries scan very little data


class LogQuery(Mechanism):
    name = "log_query"

    def run(self, check: CheckDefinition) -> CheckResult:
        expect = check.params.get("expect", "any_rows")
        client = boto3.client("athena", region_name=check.params["region"])

        # Athena is asynchronous: starting a query returns an ID, and the
        # results have to be collected separately once it finishes.
        execution = client.start_query_execution(
            QueryString=check.params["query"],
            QueryExecutionContext={"Database": check.params["database"]},
            WorkGroup=check.params["workgroup"],
        )
        query_id = execution["QueryExecutionId"]

        state = "RUNNING"
        for _ in range(POLL_ATTEMPTS):
            status = client.get_query_execution(QueryExecutionId=query_id)
            state = status["QueryExecution"]["Status"]["State"]
            if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(POLL_INTERVAL_SECONDS)

        # A query that failed proves nothing either way, so it is a failed
        # check rather than an empty result.
        if state != "SUCCEEDED":
            reason = status["QueryExecution"]["Status"].get(
                "StateChangeReason", "unknown"
            )
            return CheckResult(
                check.id, False, {"state": state, "reason": reason}, f"query {state}"
            )

        results = client.get_query_results(QueryExecutionId=query_id)
        rows = results["ResultSet"]["Rows"][1:]  # row 0 is the column header

        passed = bool(rows) if expect == "any_rows" else not rows
        return CheckResult(
            check.id,
            passed,
            {"row_count": len(rows), "expect": expect},
            f"query returned {len(rows)} row(s), expected {expect}",
        )
