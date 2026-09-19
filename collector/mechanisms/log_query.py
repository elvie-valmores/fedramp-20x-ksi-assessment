"""log_query: run a SQL query against the normalized log corpus (Athena
over collector's KSI-MLA-OSM tables) and assert a condition against the
result.

Real, as of the normalization/query-layer build in infra/aws/
log_normalization.tf and detection.tf -- scoped to AWS-side, JSON-format
events only (see docs/DECISIONS.md, 2026-09-19). A check definition
supplies the SQL directly rather than this mechanism guessing intent
from parameters, since query intent varies too much per evidence row to
usefully templatize.
"""

from __future__ import annotations

import time

import boto3

from base import CheckDefinition, CheckResult, Mechanism

POLL_INTERVAL_SECONDS = 2
POLL_ATTEMPTS = 30


class LogQuery(Mechanism):
    name = "log_query"

    def run(self, check: CheckDefinition) -> CheckResult:
        region = check.params.get("region", "us-east-1")
        database = check.params["database"]
        workgroup = check.params["workgroup"]
        query = check.params["query"]
        expect = check.params.get("expect", "any_rows")  # "any_rows" or "no_rows"

        client = boto3.client("athena", region_name=region)
        execution = client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={"Database": database},
            WorkGroup=workgroup,
        )
        query_id = execution["QueryExecutionId"]

        state = "RUNNING"
        for _ in range(POLL_ATTEMPTS):
            status = client.get_query_execution(QueryExecutionId=query_id)
            state = status["QueryExecution"]["Status"]["State"]
            if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(POLL_INTERVAL_SECONDS)

        if state != "SUCCEEDED":
            reason = status["QueryExecution"]["Status"].get(
                "StateChangeReason", "unknown"
            )
            return CheckResult(
                check.id, False, {"state": state, "reason": reason}, f"query {state}"
            )

        results = client.get_query_results(QueryExecutionId=query_id)
        rows = results["ResultSet"]["Rows"][1:]  # skip header row

        passed = bool(rows) if expect == "any_rows" else not rows
        evidence = {"row_count": len(rows), "expect": expect}
        message = f"query returned {len(rows)} row(s), expected {expect}"
        return CheckResult(check.id, passed, evidence, message)
