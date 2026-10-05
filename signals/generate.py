#!/usr/bin/env python3
"""The shared signal report generator.

    generate.py --history DIR --out signal-report.json [--period-days N]

Computes every signal signals.yaml declares, per indicator, over the period
ending today. Sources: the collector's run history (the record store,
fetched by collect.yml), the registers, GitHub's run records, and three
AWS reads -- the detection topic's publish count, GuardDuty's findings and
the elevation records' names. A signal that cannot be computed is reported
with its error and no value, and signal_report_complete then fails the
report: a missing signal must not read as a quiet one.

One generator for every indicator that declares signals, run daily by
collect.yml before the checks (DECISIONS.md, 2026-09-14 and 2026-10-05).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import statistics
import subprocess
import sys
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "sdr"))
from emit import load_history  # noqa: E402

REPOSITORY = "elvie-valmores/fedramp-20x-ksi-assessment"
REGION = "us-east-1"
LOG_BUCKET = "fedramp-20x-ksi-log-store-437672023758"
TOPIC = "fedramp-20x-ksi-detection-interim"
GATES = ["build-and-push.yml", "policy.yml", "drift.yml", "collect.yml"]


def register(name: str) -> dict:
    return yaml.safe_load((REPO / "registers" / name).read_text()) or {}


# --- Sources ---

def github(path: str) -> dict:
    token = os.environ.get("GITHUB_TOKEN") or subprocess.run(
        ["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
    request = urllib.request.Request(f"https://api.github.com/{path}", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def workflow_runs(workflow: str, start: dt.date, **filters) -> list[dict]:
    query = "&".join(f"{k}={v}" for k, v in filters.items())
    runs, page = [], 1
    while True:
        batch = github(f"repos/{REPOSITORY}/actions/workflows/{workflow}/runs"
                       f"?branch=main&per_page=100&page={page}&created=>={start}&{query}")["workflow_runs"]
        runs += batch
        if len(batch) < 100:
            return runs
        page += 1


# --- Pure computations, so test_generate.py can feed them what must count ---

def gate_runs(runs_by_gate: dict[str, list[dict]]) -> dict:
    out = {}
    for gate, runs in runs_by_gate.items():
        done = [r for r in runs if r.get("status") == "completed"]
        out[gate] = {"runs": len(done), "failed": sum(r.get("conclusion") == "failure" for r in done)}
    return out


def gates_never_failed(counts: dict) -> list[str]:
    return sorted(g for g, c in counts.items() if c["runs"] > 0 and c["failed"] == 0)


def finding_to_fix_days(history: dict[dt.date, dict]) -> dict:
    """Days from a check's first failing day to its next passing day."""
    spans, failing_since = [], {}
    for day in sorted(history):
        for o in history[day]["outcomes"]:
            cid, status = o["check"]["id"], o["status"]
            if status in ("FAIL", "ERROR") and cid not in failing_since:
                failing_since[cid] = day
            elif status == "PASS" and cid in failing_since:
                spans.append((day - failing_since.pop(cid)).days)
    return {"fixed": len(spans), "median_days": statistics.median(spans) if spans else 0,
            "max_days": max(spans) if spans else 0, "still_failing": len(failing_since)}


def check_days(history: dict[dt.date, dict], select) -> dict:
    """Days a selection of checks all passed, of the days any was judged."""
    judged = passed = 0
    for run in history.values():
        mine = [o for o in run["outcomes"] if select(o) and o["status"] != "NOT_STANDING"]
        if mine:
            judged += 1
            passed += all(o["status"] == "PASS" for o in mine)
    return {"passed_days": passed, "judged_days": judged}


def minutes_in(text: str) -> int | None:
    if not isinstance(text, str):
        return None
    if text.lower().startswith("immediate"):
        return 0
    m = re.search(r"(\d+)\s*minutes?", text) or re.search(r"(\d+)\s*hours?", text)
    if not m:
        return None
    return int(m.group(1)) * (60 if "hour" in m.group(0) else 1)


def objectives(resources: dict) -> dict[str, int | None]:
    out = {}
    for cls, entry in (resources.get("classes") or {}).items():
        objective = entry.get("objective")
        if isinstance(objective, dict) and "rto" in objective:
            out[cls] = minutes_in(objective["rto"])
    return out


def tests_in(period: tuple[dt.date, dt.date], tests: list[dict]) -> list[dict]:
    return [t for t in tests if period[0] <= dt.date.fromisoformat(str(t["date"])) <= period[1]]


def by(items, key) -> dict:
    out: dict[str, int] = {}
    for item in items:
        out[str(item.get(key))] = out.get(str(item.get(key)), 0) + 1
    return dict(sorted(out.items()))


# --- The signals, by id ---

def compute(sid: str, ctx: dict):
    period, history, today = ctx["period"], ctx["history"], ctx["period"][1]
    if sid == "gate_runs":
        return ctx["gates"]
    if sid == "gates_never_failed":
        return gates_never_failed(ctx["gates"])
    if sid == "reverts":
        # HEAD, not main: CI checks out a detached commit. collect.yml
        # fetches full history for this; a shallow clone would count 0.
        log = subprocess.run(["git", "-C", str(REPO), "log", "--first-parent", "HEAD", f"--since={period[0]}",
                              "--format=%s"], capture_output=True, text=True, check=True).stdout
        return sum(line.startswith("Revert") for line in log.splitlines())
    if sid == "emergency_modifications":
        entries = register("change-exceptions.yaml").get("entries") or []
        return len([e for e in entries if e.get("category") == "emergency_response"
                    and period[0] <= dt.date.fromisoformat(str(e["date"])) <= period[1]])
    if sid == "policy_exceptions_live":
        entries = (yaml.safe_load((REPO / "policy" / "exceptions.yaml").read_text()) or {}).get("exceptions") or []
        return len([e for e in entries if e["expires"] >= today])
    if sid == "finding_to_fix_days":
        return finding_to_fix_days(history)
    if sid == "supply_chain_risks":
        return by(register("supply-chain-risks.yaml").get("risks") or [], "disposition")
    if sid == "risks_past_review":
        risks = register("supply-chain-risks.yaml").get("risks") or []
        return len([r for r in risks if r.get("review_by") and dt.date.fromisoformat(str(r["review_by"])) < today])
    if sid == "third_parties_unmonitored":
        entries = register("third-parties.yaml").get("entries") or {}
        return sorted(k for k, e in entries.items() if (e.get("monitoring") or {}).get("status") == "unavailable")
    if sid == "dependency_audit_failures":
        failed = 0
        for run in workflow_runs("build-and-push.yml", period[0], status="completed"):
            jobs = github(f"repos/{REPOSITORY}/actions/runs/{run['id']}/jobs")["jobs"]
            failed += any(j["name"].startswith("scan-dependencies") and j["conclusion"] == "failure" for j in jobs)
        return failed
    if sid == "objectives_declared":
        return len(objectives(register("resources.yaml")))
    if sid == "objectives_measured":
        return len(tests_in(period, register("recovery-tests.yaml").get("tests") or []))
    if sid == "objectives_missed":
        declared = objectives(register("resources.yaml"))
        missed = [t for t in tests_in(period, register("recovery-tests.yaml").get("tests") or [])
                  if declared.get(t["class"]) is not None
                  and t["measured"]["rto_minutes"] > declared[t["class"]]]
        return len(missed)
    if sid == "recovery_paths_encoded":
        return len(register("recovery-paths.yaml").get("paths") or {})
    if sid == "recovery_paths_exercised":
        return len({t["path"] for t in tests_in(period, register("recovery-tests.yaml").get("tests") or [])})
    if sid == "backups_restorable_days":
        return check_days(history, lambda o: o["check"]["id"] == "svc-sin-cfg-aws-backups-restorable")
    if sid == "alerts_published":
        import boto3
        cw = boto3.client("cloudwatch", region_name=REGION)
        points = cw.get_metric_statistics(
            Namespace="AWS/SNS", MetricName="NumberOfMessagesPublished",
            Dimensions=[{"Name": "TopicName", "Value": TOPIC}], Statistics=["Sum"], Period=86400,
            StartTime=dt.datetime.combine(period[0], dt.time(), dt.timezone.utc),
            EndTime=dt.datetime.now(dt.timezone.utc))["Datapoints"]
        return int(sum(p["Sum"] for p in points))
    if sid == "guardduty_findings":
        import boto3
        gd = boto3.client("guardduty", region_name=REGION)
        detector = gd.list_detectors()["DetectorIds"][0]
        since = int(dt.datetime.combine(period[0], dt.time(), dt.timezone.utc).timestamp() * 1000)
        ids, token = [], None
        while True:
            page = gd.list_findings(DetectorId=detector, NextToken=token or "",
                                    FindingCriteria={"Criterion": {"updatedAt": {"GreaterThanOrEqual": since}}})
            ids += page["FindingIds"]
            token = page.get("NextToken")
            if not token:
                break
        bands = {"low": 0, "medium": 0, "high": 0}
        for i in range(0, len(ids), 50):
            for f in gd.get_findings(DetectorId=detector, FindingIds=ids[i:i + 50])["Findings"]:
                bands["high" if f["Severity"] >= 7 else "medium" if f["Severity"] >= 4 else "low"] += 1
        return bands
    if sid in ("elevations_granted", "backstop_actions"):
        return len([k for k in ctx["elevation_records"] if k.endswith(".json") and
                    ("-granted-" if sid == "elevations_granted" else "-swept-") in k])
    if sid == "days_served":
        return check_days(history, lambda o: o["check"].get("requires_environment") == "aws-phase1")["judged_days"]
    if sid == "lifecycle_stages":
        return by(register("lifecycle.yaml").get("stages") or [], "status")
    if sid == "principles":
        return by((register("lifecycle.yaml").get("principles") or {}).values(), "position")
    if sid == "policy_gate_failures":
        return gate_runs({"policy.yml": [r for r in ctx["policy_runs"] if r["event"] == "push"]})["policy.yml"]
    if sid == "checks_passing":
        if not history:
            return {"day": None, "passed": 0, "judged": 0}
        last = max(history)
        judged = [o for o in history[last]["outcomes"] if o["status"] != "NOT_STANDING"]
        return {"day": str(last), "passed": sum(o["status"] == "PASS" for o in judged), "judged": len(judged)}
    raise KeyError(f"no computation for signal {sid!r}")


def elevation_records(start: dt.date) -> list[str]:
    import boto3
    s3 = boto3.client("s3", region_name=REGION)
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=LOG_BUCKET, Prefix="elevations/"):
        keys += [o["Key"] for o in page.get("Contents", [])
                 if dt.date.fromisoformat(o["Key"].split("dt=")[1][:10]) >= start]
    return keys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--period-days", type=int)
    args = parser.parse_args()

    declared = yaml.safe_load((Path(__file__).parent / "signals.yaml").read_text())
    days = args.period_days or declared["period_days"]
    today = dt.date.today()
    period = (today - dt.timedelta(days=days - 1), today)
    history = {d: r for d, r in (load_history(args.history) if args.history.exists() else {}).items()
               if period[0] <= d <= period[1]}

    ctx = {"period": period, "history": history}
    errors = {}
    for name, loader in (("gates", lambda: gate_runs({g: workflow_runs(g, period[0]) for g in GATES})),
                         ("policy_runs", lambda: workflow_runs("policy.yml", period[0])),
                         ("elevation_records", lambda: elevation_records(period[0]))):
        try:
            ctx[name] = loader()
        except Exception as exc:  # each signal that needs it reports the error
            ctx[name], errors[name] = None, f"{type(exc).__name__}: {exc}"

    sections = {}
    for ksi, section in declared["sections"].items():
        signals = {}
        for sid, what in section["signals"].items():
            try:
                value = compute(sid, ctx)
                if value is None:
                    raise RuntimeError(errors.get({"gate_runs": "gates", "gates_never_failed": "gates",
                                                   "policy_gate_failures": "policy_runs"}.get(sid, ""), "no value"))
                signals[sid] = {"what": what, "value": value}
            except Exception as exc:
                signals[sid] = {"what": what, "value": None, "error": f"{type(exc).__name__}: {exc}"}
        sections[ksi] = {"purpose": section["purpose"], "signals": signals,
                         "not_collected": section.get("not_collected") or {}}

    report = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "period": {"start": str(period[0]), "end": str(period[1]), "days": days},
              "history_days": len(history), "commit": os.environ.get("GITHUB_SHA"), "sections": sections}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, default=str))

    missing = [f"{k}.{s}" for k, sec in sections.items() for s, v in sec["signals"].items() if v["value"] is None]
    total = sum(len(sec["signals"]) for sec in sections.values())
    print(f"signal report: {len(sections)} sections, {total - len(missing)} of {total} signals computed"
          + (f"; not computed: {', '.join(missing)}" if missing else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
