#!/usr/bin/env python3
"""The deliberate test: KSI-MLA-EVC validate rows 1, 2 and 3.

Plans fixtures/variable_case twice, offline, and runs the gate on each:

    validate 2  the default (a private range) passes the gate
    validate 1  -var allowed_cidr=0.0.0.0/0 is blocked, by AWS-NET-01
    validate 3  a source scan of the same fixture passes -- the
                misconfiguration exists only in the plan, so only plan
                evaluation catches it

Each outcome is the opposite of what the broken version of the control
would produce, so a pass here means the gate both blocks and lets through,
and reads the plan rather than the source. Writes a record with --out.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "variable_case"


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def plan_json(tmp: Path, name: str, extra: list[str]) -> Path:
    out = tmp / f"{name}.tfplan"
    planned = run(["terraform", f"-chdir={FIXTURE}", "plan", "-input=false", "-lock=false", f"-out={out}", *extra])
    if planned.returncode != 0:
        sys.exit(f"planning the {name} case failed:\n{planned.stderr}")
    shown = run(["terraform", f"-chdir={FIXTURE}", "show", "-json", str(out)])
    path = tmp / f"{name}.json"
    path.write_text(shown.stdout)
    return path


def gate(tmp: Path, plan: Path, name: str) -> dict:
    empty = tmp / "no-exceptions.yaml"
    empty.write_text("exceptions: []\n")
    result = tmp / f"{name}-gate.json"
    run([sys.executable, str(HERE / "gate.py"), "--plan", f"fixture={plan}",
         "--exceptions", str(empty), "--out", str(result)])
    return json.loads(result.read_text())


def source_scan_blocks() -> list[str]:
    trivy = os.environ.get("TRIVY", "trivy")
    with tempfile.TemporaryDirectory() as cache:
        out = run([trivy, "config", "--skip-version-check", "--skip-check-update", "--cache-dir", cache,
                   "--format", "json", "--severity", "HIGH,CRITICAL", str(FIXTURE)])
    if out.returncode != 0:
        sys.exit(f"the source scan failed:\n{out.stderr}")
    report = json.loads(out.stdout)
    return [m["ID"] for r in report.get("Results") or [] for m in r.get("Misconfigurations") or []
            if m.get("Status") == "FAIL"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    init = run(["terraform", f"-chdir={FIXTURE}", "init", "-input=false", "-backend=false"])
    if init.returncode != 0:
        sys.exit(f"terraform init failed:\n{init.stderr}")
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        compliant = gate(tmp, plan_json(tmp, "compliant", []), "compliant")
        violating = gate(tmp, plan_json(tmp, "violating", ["-var", "allowed_cidr=0.0.0.0/0"]), "violating")
    source = source_scan_blocks()

    blocked_by = sorted({f["rule"] for f in violating["blocking"]})
    outcomes = {
        "validate.2 compliant plan passes": compliant["passed"],
        "validate.1 violating plan is blocked by AWS-NET-01": not violating["passed"] and "AWS-NET-01" in blocked_by,
        "validate.3 the source scan passes what the plan evaluation blocks": not source and not violating["passed"],
    }
    record = {"outcomes": outcomes, "violating_blocked_by": blocked_by, "source_scan_findings": source,
              "commit": os.environ.get("GITHUB_SHA")}
    if args.out:
        args.out.write_text(json.dumps(record, indent=2))
    for name, ok in outcomes.items():
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    return 0 if all(outcomes.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
