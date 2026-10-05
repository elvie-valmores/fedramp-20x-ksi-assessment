#!/usr/bin/env python3
"""Run deliberate test scenarios and record their outcomes.

    AWS_PROFILE=caliper-elevated python deliberate/run.py SCENARIO [SCENARIO ...]
    python deliberate/run.py --list

Each outcome is written to the log store as
deliberate-tests/scenario=<id>/<UTC timestamp>.json, Object Locked and
under the evidence key, so a recorded result can be neither edited nor
withdrawn. A failed scenario is recorded too: a test that only records its
passes is not evidence. Writing the record needs the elevated profile.

--dry-run runs without recording, for trying a scenario out.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import traceback
from pathlib import Path

import boto3
import yaml

sys.path.insert(0, str(Path(__file__).parent))
from scenarios import LOG_BUCKET, REGION, SCENARIOS  # noqa: E402

CATALOGUE = yaml.safe_load((Path(__file__).parent / "scenarios.yaml").read_text())["scenarios"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenario", nargs="*")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.list or not args.scenario:
        for sid, s in CATALOGUE.items():
            print(f"{sid:<32} {s['runs_as']:<9} {s['requires']:<11} every {s['cadence_days']}d  {', '.join(s['rows'])}")
        return 0
    unknown = [s for s in args.scenario if s not in CATALOGUE or s not in SCENARIOS]
    if unknown:
        sys.exit(f"unknown scenario(s): {', '.join(unknown)}")

    session = boto3.Session()
    operator = session.client("sts").get_caller_identity()["Arn"]
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    s3 = session.client("s3", region_name=REGION)
    failed = 0
    for sid in args.scenario:
        started = dt.datetime.now(dt.timezone.utc)
        print(f"{sid}: running ...", flush=True)
        try:
            passed, expected, observed = SCENARIOS[sid](session)
            error = None
        except Exception as exc:  # recorded, not swallowed: an error is a failed test
            passed, expected, observed, error = False, CATALOGUE[sid]["what"], {}, traceback.format_exc(limit=3)
        record = {"scenario": sid, "rows": CATALOGUE[sid]["rows"], "what": CATALOGUE[sid]["what"],
                  "passed": passed, "expected": expected, "observed": observed, "error": error,
                  "started_at": started.isoformat(), "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "operator": operator, "commit": commit}
        failed += not passed
        print(f"{sid}: {'PASS' if passed else 'FAIL'} -- {expected}")
        print(json.dumps(observed, indent=2, default=str) if not error else error)
        if args.dry_run:
            continue
        key = f"deliberate-tests/scenario={sid}/{started:%Y%m%dT%H%M%SZ}.json"
        s3.put_object(Bucket=LOG_BUCKET, Key=key, Body=json.dumps(record, indent=2, default=str).encode(),
                      ContentType="application/json")
        print(f"{sid}: recorded at s3://{LOG_BUCKET}/{key}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
