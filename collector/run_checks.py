#!/usr/bin/env python3
"""CLI entry point for the collector framework.

Loads check definitions (one JSON file per evidence row) from
collector/checks/, executes each through its declared mechanism, and
reports pass/fail. This is the "380 lines of configuration" the
mechanism-first build order calls for (docs/PROJECT-CONTEXT.md) -- right
now there are only a handful of checks, proving the framework itself
works; the rest get added as configuration in build order step 7.

Usage:
    python run_checks.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from base import CheckDefinition
from registry import MECHANISMS

CHECKS_DIR = Path(__file__).resolve().parent / "checks"


def load_checks() -> list[CheckDefinition]:
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
        if mechanism is None:
            print(f"[{check.id}] SKIP -- unknown mechanism {check.mechanism!r}")
            all_passed = False
            continue

        try:
            result = mechanism.run(check)
        except NotImplementedError as exc:
            print(f"[{check.id}] SKIP -- {exc}")
            continue
        except Exception as exc:
            print(f"[{check.id}] ERROR -- {exc}")
            all_passed = False
            continue

        status = "PASS" if result.passed else "FAIL"
        print(f"[{check.id}] {status} -- {result.message}")
        if not result.passed:
            all_passed = False

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
