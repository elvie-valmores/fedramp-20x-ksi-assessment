#!/usr/bin/env python3
"""Runs every check definition and reports what passed.

Reads each JSON file in checks/, hands it to the mechanism it names, and
prints one line per check. Exits non-zero if anything failed, so this can
be wired into CI unchanged.

With --json PATH it also writes every outcome, including skips and errors,
with the full evidence each verdict was based on. That file is what the
SDR emitter reads: an outcome that is only printed is an outcome nothing
downstream can cite.

Usage:
    cd collector && python run_checks.py [--json results.json]
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from base import CheckDefinition
from registry import MECHANISMS

CHECKS_DIR = Path(__file__).resolve().parent / "checks"


def load_checks() -> list[CheckDefinition]:
    """Read every check definition from checks/, sorted by filename."""
    checks = []
    for path in sorted(CHECKS_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        checks.append(CheckDefinition(**data))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", type=Path, help="also write every outcome to this file")
    parser.add_argument(
        "--only", action="append", metavar="GLOB",
        help="run only checks whose id matches; repeatable",
    )
    args = parser.parse_args()

    checks = load_checks()
    if args.only:
        checks = [c for c in checks if any(fnmatch.fnmatchcase(c.id, g) for g in args.only)]
    if not checks:
        print("no check definitions found in collector/checks/")
        return 1

    started = datetime.now(timezone.utc).isoformat()
    outcomes = []
    all_passed = True
    for check in checks:
        outcome = {"check": asdict(check), "status": None, "message": None, "result": None}
        outcomes.append(outcome)
        mechanism = MECHANISMS.get(check.mechanism)

        # A name that isn't in the registry is a typo in the check file,
        # and a silently ignored check is worse than a loud one.
        if mechanism is None:
            outcome.update(status="SKIP", message=f"unknown mechanism {check.mechanism!r}")
            print(f"[{check.id}] SKIP -- {outcome['message']}")
            all_passed = False
            continue

        try:
            result = mechanism.run(check)
        except NotImplementedError as exc:
            # The mechanism exists but its dependencies don't yet. Not a
            # failure of the thing being assessed, so it doesn't fail the run.
            outcome.update(status="SKIP", message=str(exc))
            print(f"[{check.id}] SKIP -- {exc}")
            continue
        except Exception as exc:
            # Anything else means the check itself broke. Report and keep
            # going so one bad check doesn't hide the rest.
            outcome.update(status="ERROR", message=str(exc))
            print(f"[{check.id}] ERROR -- {exc}")
            all_passed = False
            continue

        status = "PASS" if result.passed else "FAIL"
        outcome.update(status=status, message=result.message, result=asdict(result))
        print(f"[{check.id}] {status} -- {result.message}")
        if not result.passed:
            all_passed = False

    if args.json:
        args.json.write_text(json.dumps(
            {"started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
             "outcomes": outcomes},
            indent=2, default=str,
        ) + "\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
