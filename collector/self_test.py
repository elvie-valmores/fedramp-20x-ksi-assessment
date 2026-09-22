#!/usr/bin/env python3
"""Proves the pipeline checks can actually fail.

Every check in checks/ currently passes. That is either evidence that the
pipeline is configured correctly, or evidence of nothing at all, and the
two are indistinguishable from the outside -- which is the failure mode
this project cares most about. Four controls were found this month that
were configured, deployed, and completely inert while reporting nothing.

So each assertion is run twice: once against a workflow that should
satisfy it, and once against a deliberately broken one that should not.
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


def main() -> int:
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

    print()
    if broken:
        print(f"{len(broken)} assertion(s) do not discriminate: {', '.join(broken)}")
        return 1

    print(f"all {len(CASES)} assertions distinguish a good workflow from a bad one")
    return 0


if __name__ == "__main__":
    sys.exit(main())
