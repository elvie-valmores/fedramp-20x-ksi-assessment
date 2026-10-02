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

        if state != "SUCCEEDED":
            reason = status["QueryExecution"]["Status"].get(
                "StateChangeReason", "unknown"
            )
            passed, detail = evaluate_query(state, 0, expect)
            return CheckResult(check.id, passed, {"state": state, "reason": reason}, detail)

        results = client.get_query_results(QueryExecutionId=query_id)
        rows = results["ResultSet"]["Rows"][1:]  # row 0 is the column header

        passed, detail = evaluate_query(state, len(rows), expect)
        header = [c.get("VarCharValue") for c in results["ResultSet"]["Rows"][0]["Data"]] if results["ResultSet"]["Rows"] else []
        # The rows are the evidence for a standing query that should return
        # none: which actor, which call, when. The first 20 are kept.
        sample = [dict(zip(header, [c.get("VarCharValue") for c in r["Data"]])) for r in rows[:20]]
        return CheckResult(check.id, passed, {"row_count": len(rows), "expect": expect, "rows": sample,
                                              "query_id": query_id}, detail)


def evaluate_query(state: str, row_count: int, expect: str) -> tuple[bool, str]:
    """The judgement, pure, so self_test.py can feed it what must fail.

    A query that did not succeed proves nothing either way, so it fails
    whatever was expected: for "no_rows" an error would otherwise read as
    the clean zero-result a standing query hopes for.
    """
    if state != "SUCCEEDED":
        return False, f"query {state}"
    if expect not in ("any_rows", "no_rows"):
        return False, f"unknown expectation {expect!r}"
    passed = row_count > 0 if expect == "any_rows" else row_count == 0
    return passed, f"query returned {row_count} row(s), expected {expect}"
