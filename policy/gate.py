#!/usr/bin/env python3
"""The policy gate: KSI-MLA-EVC, evaluated against Terraform plans.

    gate.py --plan aws=aws.json --plan gcp=gcp.json --plan bootstrap=b.json [--out results.json]
            [--exceptions exceptions.yaml]

Each plan is `terraform show -json` output. Two evaluators run over it:

    authored  the rules in rules/, through OPA, each mapped in coverage.yaml
    scanner   Trivy's embedded rules, over the same plan

A finding at or above its threshold blocks unless an unexpired entry in
exceptions.yaml names it. The gate fails on any blocking finding, on an
exception that matches nothing, on a rule and its coverage entry falling
out of step, and on an evaluator that could not read a plan. That last one
was found building this (2026-10-05): Trivy turned pending data sources into
HCL it could not parse, logged an error, and reported the plan clean.

OPA and Trivy are found as $OPA and $TRIVY, or on PATH.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RULE_ID = re.compile(r'violation\("([A-Z]+-[A-Z0-9]+-\d+)"')


# --- The judgements, pure, so test_gate.py can feed them what must fail ---

def coverage_problems(rule_ids: set[str], coverage: dict) -> list[str]:
    """Every rule in rules/ mapped, and every mapping naming a rule."""
    mapped = coverage.get("rules") or {}
    problems = [f"{r}: in rules/ but not in coverage.yaml" for r in sorted(rule_ids - set(mapped))]
    problems += [f"{r}: in coverage.yaml but in no rule" for r in sorted(set(mapped) - rule_ids)]
    for rid, entry in sorted(mapped.items()):
        if entry.get("severity") not in SEVERITY:
            problems.append(f"{rid}: severity {entry.get('severity')!r} is not one of {', '.join(SEVERITY)}")
        if not entry.get("determinations"):
            problems.append(f"{rid}: names no determination")
    return problems


def exception_problems(exceptions: list[dict]) -> list[str]:
    """Every entry carries what it excuses, a reason and an expiry."""
    problems = []
    for i, e in enumerate(exceptions):
        for field in ("rule", "root", "address", "reason", "expires"):
            if not str(e.get(field) or "").strip():
                problems.append(f"exception {i} ({e.get('rule')} on {e.get('address')}): no {field}")
        if e.get("expires") and not isinstance(e["expires"], dt.date):
            problems.append(f"exception {i}: expires {e['expires']!r} is not a date")
    return problems


def judge(findings: list[dict], exceptions: list[dict], today: dt.date) -> dict:
    """Split findings into blocking, excepted and reported; find stale exceptions.

    findings: {root, source, rule, address, severity, block_at, msg}.
    An expired exception does not apply, and is listed as expired rather
    than stale, since what it named is still there.
    """
    live = [e for e in exceptions if isinstance(e.get("expires"), dt.date) and e["expires"] >= today]
    used: set[int] = set()
    blocking, excepted, reported = [], [], []
    for f in findings:
        match = next((i for i, e in enumerate(exceptions) if e in live and e["rule"] == f["rule"]
                      and e["root"] == f["root"] and e["address"] == f["address"]), None)
        if SEVERITY.get(f["severity"], 0) < SEVERITY[f["block_at"]]:
            reported.append(f)
            if match is not None:
                used.add(match)
        elif match is not None:
            used.add(match)
            excepted.append({**f, "reason": exceptions[match]["reason"], "expires": str(exceptions[match]["expires"])})
        else:
            blocking.append(f)
    expired = [e for e in exceptions if e not in live]
    stale = [e for i, e in enumerate(exceptions) if i not in used and e in live]
    return {"blocking": blocking, "excepted": excepted, "reported": reported,
            "expired_exceptions": [_plain(e) for e in expired], "stale_exceptions": [_plain(e) for e in stale]}


def scanner_parse_failed(stderr: str) -> list[str]:
    """Trivy's log lines saying it could not turn a plan into something it scans.

    The fallback to embedded checks also logs at ERROR and is expected, so
    only parser failures count.
    """
    return [line for line in stderr.splitlines()
            if "ERROR" in line and ("parser" in line or "Error parsing" in line)]


def scanner_view(plan: dict) -> dict:
    """The plan without data sources, which is what Trivy can parse.

    Data sources still pending at plan time -- here, IAM policy documents
    that name a role not yet created -- become HCL Trivy rejects. Their
    content is already inlined in the resources that use them.
    """
    def strip(module: dict) -> None:
        module["resources"] = [r for r in module.get("resources", []) if r.get("mode") != "data"]
        for child in module.get("child_modules", []):
            strip(child)
    view = json.loads(json.dumps(plan))
    strip(view.get("planned_values", {}).get("root_module", {}))
    return view


def _plain(e: dict) -> dict:
    return {k: (str(v) if isinstance(v, dt.date) else v) for k, v in e.items()}


# --- Running the evaluators ---

def authored_findings(root: str, plan_path: Path, coverage: dict) -> list[dict]:
    opa = os.environ.get("OPA", "opa")
    out = subprocess.run([opa, "eval", "--format", "json", "-d", str(HERE / "rules"), "-i", str(plan_path),
                          "data.fedramp.policy.violations"], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"opa could not evaluate {root}: {out.stderr.strip()}")
    result = json.loads(out.stdout)["result"]
    violations = result[0]["expressions"][0]["value"] if result else []
    findings = []
    for v in violations:
        entry = coverage["rules"].get(v["rule"], {})
        findings.append({"root": root, "source": "authored", "rule": v["rule"], "address": v["address"],
                         "severity": entry.get("severity", "CRITICAL"), "block_at": coverage["block_at"],
                         "msg": v["msg"], "determinations": entry.get("determinations", [])})
    return findings


def scanner_findings(root: str, plan: dict, block_at: str) -> list[dict]:
    trivy = os.environ.get("TRIVY", "trivy")
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "plan" / f"{root}.tfplan.json"
        target.parent.mkdir()
        target.write_text(json.dumps(scanner_view(plan)))
        report = Path(tmp) / "trivy.json"
        out = subprocess.run([trivy, "config", "--skip-version-check", "--skip-check-update",
                              "--cache-dir", str(Path(tmp) / "cache"), "--format", "json",
                              "--output", str(report), str(target.parent)], capture_output=True, text=True)
        failed = scanner_parse_failed(out.stderr)
        if out.returncode != 0 or failed or not report.exists():
            raise RuntimeError(f"trivy could not scan {root}: {(failed or [out.stderr.strip()])[0]}")
        data = json.loads(report.read_text())
    findings = []
    for result in data.get("Results") or []:
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            findings.append({"root": root, "source": "scanner", "rule": m["ID"],
                             "address": (m.get("CauseMetadata") or {}).get("Resource") or "",
                             "severity": m["Severity"], "block_at": block_at, "msg": m["Title"]})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plan", action="append", required=True, metavar="ROOT=PATH")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--exceptions", type=Path, default=HERE / "exceptions.yaml",
                        help="the exception register (deliberate_test.py runs with an empty one)")
    args = parser.parse_args()

    coverage = yaml.safe_load((HERE / "coverage.yaml").read_text())
    exceptions = (yaml.safe_load(args.exceptions.read_text()) or {}).get("exceptions") or []
    rule_ids = {m for f in (HERE / "rules").glob("*.rego") if not f.name.endswith("_test.rego")
                for m in RULE_ID.findall(f.read_text())}

    problems = coverage_problems(rule_ids, coverage) + exception_problems(exceptions)
    findings = []
    for spec in args.plan:
        root, _, path = spec.partition("=")
        plan_path = Path(path)
        plan = json.loads(plan_path.read_text())
        if not plan.get("resource_changes"):
            problems.append(f"{root}: the plan holds no resources -- nothing was evaluated")
            continue
        try:
            findings += authored_findings(root, plan_path, coverage)
            findings += scanner_findings(root, plan, coverage["scanner"]["block_at"])
        except RuntimeError as error:
            problems.append(str(error))

    verdict = judge(findings, exceptions, dt.date.today())
    problems += [f"stale exception: {e['rule']} on {e['root']}:{e['address']} matches nothing"
                 for e in verdict["stale_exceptions"]]
    passed = not problems and not verdict["blocking"]
    record = {"passed": passed, "evaluated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "commit": os.environ.get("GITHUB_SHA"), "roots": [p.partition("=")[0] for p in args.plan],
              "rules_authored": len(rule_ids), "problems": problems, **verdict}
    if args.out:
        args.out.write_text(json.dumps(record, indent=2))

    for f in verdict["blocking"]:
        print(f"BLOCK  {f['severity']:<8} {f['rule']:<11} {f['root']}:{f['address']} -- {f['msg']}")
    for f in verdict["excepted"]:
        print(f"EXCEPT {f['severity']:<8} {f['rule']:<11} {f['root']}:{f['address']} (until {f['expires']})")
    for p in problems:
        print(f"ERROR  {p}")
    print(f"{'PASS' if passed else 'FAIL'}: {len(verdict['blocking'])} blocking, {len(verdict['excepted'])} excepted, "
          f"{len(verdict['reported'])} below threshold, {len(problems)} problem(s); "
          f"{len(rule_ids)} authored rules over {len(args.plan)} plan(s)")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
