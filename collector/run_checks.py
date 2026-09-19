#!/usr/bin/env python3
"""Runs every check definition and reports what passed.

Reads each JSON file in checks/, hands it to the mechanism it names, and
prints one line per check. Exits non-zero if anything failed, so this can
be wired into CI unchanged.

Usage:
    cd collector && python run_checks.py
"""

from __future__ import annotations

import json
import sys
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
    checks = load_checks()
    if not checks:
        print("no check definitions found in collector/checks/")
        return 1

    all_passed = True
    for check in checks:
        mechanism = MECHANISMS.get(check.mechanism)

        # A name that isn't in the registry is a typo in the check file,
        # and a silently ignored check is worse than a loud one.
        if mechanism is None:
            print(f"[{check.id}] SKIP -- unknown mechanism {check.mechanism!r}")
            all_passed = False
            continue

        try:
            result = mechanism.run(check)
        except NotImplementedError as exc:
            # The mechanism exists but its dependencies don't yet. Not a
            # failure of the thing being assessed, so it doesn't fail the run.
            print(f"[{check.id}] SKIP -- {exc}")
            continue
        except Exception as exc:
            # Anything else means the check itself broke. Report and keep
            # going so one bad check doesn't hide the rest.
            print(f"[{check.id}] ERROR -- {exc}")
            all_passed = False
            continue

        print(f"[{check.id}] {'PASS' if result.passed else 'FAIL'} -- {result.message}")
        if not result.passed:
            all_passed = False

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
