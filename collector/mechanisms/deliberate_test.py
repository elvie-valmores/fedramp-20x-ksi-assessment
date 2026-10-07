"""Mechanism: the latest recorded outcome of a deliberate test.

The test itself is run by deliberate/run.py, which does something a control
should stop or catch, observes whether it did, and records the outcome in
the log store under deliberate-tests/scenario=<id>/ -- Object Locked, so a
recorded failure cannot be withdrawn and a recorded pass cannot be edited
into one. This mechanism reads the newest record for the scenario.

Check params:
    scenario      the scenario id (deliberate/scenarios.yaml)
    max_age_days  how old the newest record may be: the scenario's declared
                  cadence, plus a little

Built 2026-10-05. Until then the deliberate test rows had no evidence at
all; the harness and this reader landed together.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import boto3

from base import CheckDefinition, CheckResult, Mechanism

LOG_BUCKET = "fedramp-20x-ksi-log-store-437672023758"
REGION = "us-east-1"


class DeliberateTest(Mechanism):
    name = "deliberate_test"

    def run(self, check: CheckDefinition) -> CheckResult:
        scenario = check.params["scenario"]
        s3 = boto3.client("s3", region_name=REGION)
        if scenario == "*":
            return self._catalogue(check, s3)
        prefix = f"deliberate-tests/scenario={scenario}/"
        keys = [o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=LOG_BUCKET, Prefix=prefix)
                for o in page.get("Contents", [])]
        record = None
        if keys:
            latest = max(keys)  # keys are UTC timestamps, so they sort in time
            record = json.loads(s3.get_object(Bucket=LOG_BUCKET, Key=latest)["Body"].read())
            record["_key"] = latest
        ok, detail, evidence = evaluate_test_record(record, scenario, datetime.now(timezone.utc),
                                                    check.params["max_age_days"], len(keys))
        return CheckResult(check.id, ok, evidence, detail)

    def _catalogue(self, check: CheckDefinition, s3) -> CheckResult:
        """Every scenario in deliberate/scenarios.yaml, each against its own cadence."""
        import yaml
        from pathlib import Path
        catalogue = yaml.safe_load((Path(__file__).resolve().parents[2] / "deliberate" / "scenarios.yaml").read_text())["scenarios"]
        now = datetime.now(timezone.utc)
        results = {}
        for sid, spec in catalogue.items():
            record, runs = _latest(s3, sid)
            ok, detail, _ = evaluate_test_record(record, sid, now, spec["cadence_days"] + check.params.get("grace_days", 5), runs)
            results[sid] = (ok, detail)
        ok, detail, evidence = evaluate_catalogue(results)
        return CheckResult(check.id, ok, evidence, detail)


def _latest(s3, scenario: str) -> tuple[dict | None, int]:
    prefix = f"deliberate-tests/scenario={scenario}/"
    keys = [o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=LOG_BUCKET, Prefix=prefix)
            for o in page.get("Contents", [])]
    if not keys:
        return None, 0
    record = json.loads(s3.get_object(Bucket=LOG_BUCKET, Key=max(keys))["Body"].read())
    record["_key"] = max(keys)
    return record, len(keys)


def evaluate_catalogue(results: dict[str, tuple[bool, str]]) -> tuple[bool, str, dict]:
    """KSI-RPL-TRC validate 1: every catalogued test has a recent passing record."""
    failing = {sid: detail for sid, (ok, detail) in results.items() if not ok}
    evidence = {"scenarios": {sid: detail for sid, (_, detail) in results.items()}, "failing": failing}
    if not results:
        return False, "the catalogue is empty -- nothing to judge", evidence
    if failing:
        return False, f"{len(failing)} of {len(results)} tests not current: {', '.join(sorted(failing))}", evidence
    return True, f"all {len(results)} catalogued tests passed within their cadence", evidence


def evaluate_test_record(record: dict | None, scenario: str, now: datetime, max_age_days: int,
                         runs: int) -> tuple[bool, str, dict]:
    """The newest record exists, is this scenario's, passed, and is recent enough."""
    if record is None:
        return False, f"no recorded run of {scenario} -- the test has never been run", {"runs": 0}
    started = datetime.fromisoformat(record["started_at"])
    age = (now - started).total_seconds() / 86400
    evidence = {"runs": runs, "latest": record.get("_key"), "age_days": round(age, 2),
                "passed": record.get("passed"), "expected": record.get("expected"),
                "observed": record.get("observed"), "error": record.get("error"), "operator": record.get("operator")}
    if record.get("scenario") != scenario:
        return False, f"the newest record is for {record.get('scenario')!r}, not {scenario!r}", evidence
    if record.get("passed") is not True:
        return False, f"the newest run failed: {record.get('expected')}", evidence
    if age > max_age_days:
        return False, f"the newest passing run is {age:.0f} days old, over {max_age_days}", evidence
    return True, f"passed {age:.1f} day(s) ago: {record.get('expected')}", evidence
