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
    judge       optional: "decrypt_model" -- the rows are judged rather than
                counted (see judge_decrypt_events)
    model_from  with judge: the check file whose declared models to use

The SQL lives in the check definition rather than being assembled here.
Evidence queries vary too much to express as parameters, and a query
written out in full is also the clearest record of what was asked.

"no_rows" is the more common shape in practice: most security evidence is
the absence of something, e.g. "no unencrypted buckets," and an empty
result set is what proves it.
"""

from __future__ import annotations

import fnmatch
import json
import re
import time
from pathlib import Path

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

        header = [c.get("VarCharValue") for c in results["ResultSet"]["Rows"][0]["Data"]] if results["ResultSet"]["Rows"] else []
        if check.params.get("judge") == "decrypt_model":
            records = [dict(zip(header, [c.get("VarCharValue") for c in r["Data"]])) for r in rows]
            return self._judge_decrypts(check, records, query_id)
        passed, detail = evaluate_query(state, len(rows), expect)
        # The rows are the evidence for a standing query that should return
        # none: which actor, which call, when. The first 20 are kept.
        sample = [dict(zip(header, [c.get("VarCharValue") for c in r["Data"]])) for r in rows[:20]]
        return CheckResult(check.id, passed, {"row_count": len(rows), "expect": expect, "rows": sample,
                                              "query_id": query_id}, detail)


    @staticmethod
    def _judge_decrypts(check: CheckDefinition, records: list[dict], query_id: str) -> CheckResult:
        """Resolve each key the rows name, then judge each actor against its model."""
        checks_dir = Path(__file__).resolve().parents[1] / "checks"
        declared = json.loads((checks_dir / f"{check.params['model_from']}.json").read_text())["params"]["declared"]
        kms = boto3.client("kms", region_name=check.params["region"])
        keys = {}
        for uid in sorted({r["key"] for r in records}):
            try:
                meta = kms.describe_key(KeyId=uid)["KeyMetadata"]
                aliases = [a["AliasName"] for a in kms.list_aliases(KeyId=meta["KeyId"])["Aliases"]]
                keys[uid] = {"manager": meta["KeyManager"], "aliases": aliases}
            except kms.exceptions.NotFoundException:
                keys[uid] = None
        passed, detail, evidence = judge_decrypt_events(records, keys, declared)
        evidence["query_id"] = query_id
        return CheckResult(check.id, passed, evidence, detail)


_ASSUMED = re.compile(r"^arn:aws:sts::\d+:assumed-role/([^/]+)/")


def judge_decrypt_events(records: list[dict], keys: dict[str, dict | None],
                         declared: dict[str, list[str]]) -> tuple[bool, str, dict]:
    """Every decrypt of a customer key by a principal its model declares.

    records: {key, actor_type, actor, events}. AWS-managed keys are outside
    every model and skipped. A decrypt by an AWS service is recorded, not
    judged: the normalized event does not say which service. A role is
    matched by name against the last segment of each declared pattern,
    since an assumed-role ARN drops the role's path. A customer key with no
    model, or one KMS no longer knows, fails: nothing can vouch for it.
    """
    violations, unattributed, judged = [], 0, 0
    for r in records:
        info = keys.get(r["key"])
        if info is not None and info["manager"] != "CUSTOMER":
            continue
        if r["actor_type"] == "AWSService":
            unattributed += int(r["events"])
            continue
        judged += int(r["events"])
        if info is None:
            violations.append({**r, "why": "key unknown to KMS"})
            continue
        model = next((declared[a] for a in info["aliases"] if a in declared), None)
        if model is None:
            violations.append({**r, "why": f"customer key {info['aliases'] or r['key']} has no declared model"})
            continue
        match = _ASSUMED.match(r["actor"] or "")
        name = match.group(1) if match else None
        if not name or not any(not p.startswith("service:") and fnmatch.fnmatchcase(name, p.rsplit("/", 1)[-1])
                               for p in model):
            violations.append({**r, "why": "actor not in the key's declared model"})
    evidence = {"violations": violations[:20], "judged_events": judged, "service_events_unattributed": unattributed}
    if violations:
        return False, f"{len(violations)} decrypt pattern(s) outside a declared model", evidence
    return True, f"{judged} decrypt(s) of customer keys, all by declared principals", evidence


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
