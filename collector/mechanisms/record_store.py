"""Mechanism: the collector's own record store, read back.

Every CI run writes its results to the log store under collector-runs/,
Object Locked and under the evidence key (collect.yml). The standing log
queries are the review queries (DECISIONS.md, 2026-09-14: periodic human
review cut, the queries kept), so this store is the review record:

    latest_complete  the newest CI record is recent and holds an outcome
                     for every check of the named mechanisms, nil results
                     included
    continuous       over the lookback, no gap between consecutive CI
                     records longer than the queries' window, so no stretch
                     of events went unreviewed

Built 2026-10-06; until then the mechanism was registered and unbuilt.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import boto3

from base import CheckDefinition, CheckResult, Mechanism

LOG_BUCKET = "fedramp-20x-ksi-log-store-437672023758"
REGION = "us-east-1"
CHECKS = Path(__file__).resolve().parents[1] / "checks"


class RecordStore(Mechanism):
    name = "record_store"

    def run(self, check: CheckDefinition) -> CheckResult:
        p = check.params
        s3 = boto3.client("s3", region_name=REGION)
        since = date.today() - timedelta(days=p.get("lookback_days", 30))
        keys = [(o["Key"], o["LastModified"]) for page in s3.get_paginator("list_objects_v2").paginate(
                    Bucket=LOG_BUCKET, Prefix="collector-runs/") for o in page.get("Contents", [])
                if date.fromisoformat(o["Key"].split("dt=")[1][:10]) >= since]
        now = datetime.now(timezone.utc)
        if p["assertion"] == "continuous":
            ok, detail, evidence = evaluate_continuity([t for _, t in keys], now, p["max_gap_days"])
        elif p["assertion"] == "latest_complete":
            record = None
            if keys:
                key = max(keys, key=lambda k: k[1])[0]
                record = json.loads(s3.get_object(Bucket=LOG_BUCKET, Key=key)["Body"].read())
                record["_key"] = key
            expected = sorted(json.loads(f.read_text())["id"] for f in CHECKS.glob("*.json")
                              if json.loads(f.read_text())["mechanism"] in p["mechanisms"])
            ok, detail, evidence = evaluate_latest_complete(record, expected, now, p["max_age_hours"])
        else:
            raise NotImplementedError(f"record_store has no assertion {p['assertion']!r}")
        return CheckResult(check.id, ok, evidence, detail)


def evaluate_latest_complete(record: dict | None, expected: list[str], now: datetime,
                             max_age_hours: int) -> tuple[bool, str, dict]:
    """The newest CI record is young enough and carries every expected check's outcome."""
    if record is None:
        return False, "no CI record in the store", {}
    started = datetime.fromisoformat(record["started_at"])
    age = (now - started).total_seconds() / 3600
    present = {o["check"]["id"]: o["status"] for o in record.get("outcomes", [])}
    missing = [c for c in expected if c not in present]
    evidence = {"record": record.get("_key"), "age_hours": round(age, 1), "runtime": (record.get("run") or {}).get("runtime"),
                "outcomes": {c: present.get(c) for c in expected}, "missing": missing}
    if (record.get("run") or {}).get("runtime") != "ci":
        return False, "the newest record is not a CI run's", evidence
    if missing:
        return False, f"{len(missing)} expected check(s) have no outcome in the newest record: {', '.join(missing[:4])}", evidence
    if age > max_age_hours:
        return False, f"the newest record is {age:.0f} hours old, over {max_age_hours}", evidence
    return True, f"the newest CI record ({age:.0f}h old) holds an outcome for all {len(expected)} checks", evidence


def evaluate_continuity(times: list[datetime], now: datetime, max_gap_days: float) -> tuple[bool, str, dict]:
    """No gap between consecutive records -- or since the last one -- longer than the window."""
    ordered = sorted(times)
    gaps = [(b - a).total_seconds() / 86400 for a, b in zip(ordered, ordered[1:])]
    if ordered:
        gaps.append((now - ordered[-1]).total_seconds() / 86400)
    worst = max(gaps) if gaps else None
    evidence = {"records": len(ordered), "first": ordered and ordered[0].isoformat(),
                "longest_gap_days": worst and round(worst, 2)}
    if not ordered:
        return False, "no records in the lookback", evidence
    if worst > max_gap_days:
        return False, f"a {worst:.1f}-day gap between records, over the {max_gap_days}-day window", evidence
    return True, f"{len(ordered)} records, longest gap {worst:.1f} days, within the {max_gap_days}-day window", evidence
