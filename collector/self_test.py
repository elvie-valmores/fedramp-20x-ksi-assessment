#!/usr/bin/env python3
"""Proves the checks can actually fail.

Every check in checks/ currently passes. That is either evidence that the
pipeline is configured correctly, or evidence of nothing at all, and the
two are indistinguishable from the outside -- which is the failure mode
this project cares most about. Four controls were found this month that
were configured, deployed, and completely inert while reporting nothing.

So each assertion is run against input that should satisfy it and input
that should not -- a good and a broken workflow for pipeline_config_read,
a clean and a drifted Terraform plan for declared_versus_live_comparison.
An assertion that passes both is reported as broken, because a check that
cannot fail is not a check.

This is the same argument inventory/self_test.py makes by seeding a
resource and confirming the inventory notices: absence of a finding is
only evidence if the looking was recorded.

Usage:
    cd collector && python self_test.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from base import CheckDefinition
import mechanisms.declared_versus_live_comparison as dvl
import mechanisms.pipeline_config_read as pcr

GOOD = """
name: good
on:
  push:
    branches: [main]
permissions:
  contents: read
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: check out
        uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
      - name: scan dependencies
        run: pip-audit
      - name: build and push
        run: docker buildx build --push .
      - name: verify the signature
        run: cosign verify
      - name: record the digest
        run: echo "$DIGEST"
"""

# Each field below violates exactly one assertion, so a failure names the
# assertion rather than leaving it to be inferred.
BAD = """
name: bad
on:
  push:
    branches: [main, develop]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    steps:
      - name: check out
        uses: actions/checkout@v5
      - name: record the digest
        run: echo "$DIGEST"
      - name: verify the signature
        run: cosign verify
"""

# assertion -> extra params, and why the bad fixture violates it.
CASES = [
    ("actions_pinned_to_sha", {}, "checkout pinned to the tag v5"),
    ("no_static_cloud_credentials", {}, "AWS_ACCESS_KEY_ID referenced"),
    ("permissions_declared", {}, "no permissions block at all"),
    ("step_present", {"job": "build", "step": "scan dependencies"}, "no scanning step"),
    (
        "step_precedes",
        {"job": "build", "before": "verify the signature", "after": "record the digest"},
        "digest recorded before the signature is verified",
    ),
    ("triggers_limited_to", {"branches": ["main"]}, "also triggers from develop"),
]


def definition(assertion: str, workflow: str, extra: dict) -> CheckDefinition:
    return CheckDefinition(
        id=f"self-test-{assertion}",
        indicator="n/a",
        mechanism="pipeline_config_read",
        evidence_type="OPS",
        description=f"self-test of {assertion}",
        required_cadence="on every collector change",
        params={"workflow": workflow, "assertion": assertion, **extra},
    )


def pipeline_config_read() -> list[str]:
    mechanism = pcr.PipelineConfigRead()

    with tempfile.TemporaryDirectory() as tmp:
        fixtures = Path(tmp)
        (fixtures / "good.yml").write_text(GOOD)
        (fixtures / "bad.yml").write_text(BAD)

        # The mechanism reads the repository's own workflow directory. Point
        # it at the fixtures instead, and put it back afterwards so a later
        # import in the same process is unaffected.
        original = pcr.WORKFLOWS_DIR
        pcr.WORKFLOWS_DIR = fixtures
        try:
            broken = []
            for assertion, extra, why in CASES:
                good = mechanism.run(definition(assertion, "good.yml", extra))
                bad = mechanism.run(definition(assertion, "bad.yml", extra))

                ok = good.passed and not bad.passed
                print(
                    f"[{assertion}] {'PASS' if ok else 'BROKEN'} -- "
                    f"good={'pass' if good.passed else 'FAIL'} "
                    f"bad={'fail' if not bad.passed else 'PASS'} ({why})"
                )
                if not ok:
                    broken.append(assertion)
                    print(f"    good: {good.message}")
                    print(f"    bad : {bad.message}")
        finally:
            pcr.WORKFLOWS_DIR = original

    return broken


# --- declared_versus_live_comparison ---
#
# Plans reduced to the fields the mechanism reads. Two resources in state,
# so "all of them match" and "one of them does not" are both expressible.


def _plan(changes: dict[str, list[str]], drift: dict[str, list[str]], in_state: int = 2) -> dict:
    state = [{"address": f"aws_s3_bucket.b{i}", "mode": "managed"} for i in range(in_state)]
    return {
        "prior_state": {"values": {"root_module": {"resources": state}}},
        "resource_changes": [
            {
                "address": r["address"],
                "mode": "managed",
                "change": {
                    "actions": changes.get(r["address"], ["no-op"]),
                    "before": {"tags": {"a": "1"}},
                    "after": {"tags": {"a": "1"} if r["address"] not in changes else {}},
                },
            }
            for r in state
        ],
        "resource_drift": [
            {"address": a, "change": {"actions": acts}} for a, acts in drift.items()
        ],
    }


def _knock_on() -> dict:
    # b0 changed out of band; b1's only difference is a value Terraform
    # cannot know until b0's change applies.
    plan = _plan({"aws_s3_bucket.b0": ["update"], "aws_s3_bucket.b1": ["update"]},
                 {"aws_s3_bucket.b0": ["update"]})
    b1 = plan["resource_changes"][1]["change"]
    b1["after"] = {"tags": {"a": "1"}, "policy": None}
    b1["before"]["policy"] = "{}"
    b1["after_unknown"] = {"policy": True}
    return plan


PLANS = {
    "clean": _plan({}, {}),
    # Refresh saw b0's tags move, but the provider's own comparison calls it
    # equal and the plan proposes nothing -- the null-against-{} case found
    # on the real roots. Must pass no_drift, or every run is noise.
    "refresh-noise": _plan({}, {"aws_s3_bucket.b0": ["update"]}),
    "out-of-band": _plan({"aws_s3_bucket.b0": ["update"]}, {"aws_s3_bucket.b0": ["update"]}),
    "not-applied": _plan({"aws_s3_bucket.b0": ["update"]}, {}),
    "deleted": _plan({"aws_s3_bucket.b0": ["create"]}, {"aws_s3_bucket.b0": ["delete"]}),
    "knock-on": _knock_on(),
    "empty-state": _plan({}, {}, in_state=0),
}

# assertion -> plans it must pass, plans it must fail. An out-of-band
# update must NOT fail declared_exists_live: the object is there, it has
# only changed, and an assertion that fails on everything discriminates
# nothing.
DVL_CASES = [
    ("no_drift", ["clean", "refresh-noise"], ["out-of-band", "not-applied", "deleted", "knock-on", "empty-state"]),
    ("declared_exists_live", ["clean", "refresh-noise", "out-of-band", "not-applied", "knock-on"], ["deleted", "empty-state"]),
]


def declared_versus_live_comparison() -> list[str]:
    broken = []
    for assertion, should_pass, should_fail in DVL_CASES:
        wrong = [n for n in should_pass if not dvl.evaluate(assertion, PLANS[n])[0]]
        wrong += [n for n in should_fail if dvl.evaluate(assertion, PLANS[n])[0]]
        print(
            f"[{assertion}] {'PASS' if not wrong else 'BROKEN'} -- "
            f"passes {', '.join(should_pass)}; fails {', '.join(should_fail)}"
        )
        if wrong:
            broken.append(assertion)
            print(f"    wrong verdict on: {', '.join(wrong)}")

    # The attribution is the evidence's main use, so it is asserted too.
    causes = {
        name: [c["cause"] for c in dvl.evaluate("no_drift", PLANS[name])[1]["changes"]]
        for name in ("out-of-band", "not-applied", "knock-on")
    }
    ok = causes == {
        "out-of-band": ["changed outside Terraform"],
        "not-applied": ["declaration not applied"],
        "knock-on": ["changed outside Terraform", "follows from another change"],
    }
    print(f"[no_drift attribution] {'PASS' if ok else 'BROKEN'} -- {causes}")
    if not ok:
        broken.append("no_drift attribution")
    return broken


def main() -> int:
    broken = pipeline_config_read()
    print()
    broken += declared_versus_live_comparison()
    total = len(CASES) + len(DVL_CASES) + 1

    print()
    if broken:
        print(f"{len(broken)} of {total} assertion(s) do not discriminate: {', '.join(broken)}")
        return 1

    print(f"all {total} assertions distinguish input that should pass from input that should not")
    return 0


if __name__ == "__main__":
    sys.exit(main())
