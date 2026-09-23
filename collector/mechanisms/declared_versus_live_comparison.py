"""Mechanism: compare what Terraform declares against what is actually running.

Used for KSI-SVC-ACM's evidence that configuration has not drifted, and
that everything in the declared baseline still exists. Later for
KSI-IAM-AAM's Identity Center drift, which asks the same question of a
different root.

The mechanism runs Terraform itself rather than reading the drift
workflow's result. Reading CI's verdict would be checking that a check
passed, not checking, and drift.yml covers AWS only.

How the verdict is reached, and why it is not a refresh-only plan:

    A refresh-only plan's `resource_drift` is the obvious source -- it lists
    exactly what changed outside Terraform. Tried against the real roots on
    2026-09-23, it reported ten changes and not one was drift: null against
    {}, server-side etags, a BigQuery access list returned in a different
    order under legacy role names. It compares raw stored values, without
    the provider's own rules for when two values mean the same thing.
    Filtering that noise by hand means writing rules that could equally
    hide a real change.

    So the verdict comes from a full plan, which applies those provider
    rules, and `resource_drift` is used only for what it is reliable at:
    telling an out-of-band change apart from a declaration nobody applied,
    and spotting a declared object that no longer exists.

    What this gives up: an attribute the configuration does not manage is
    invisible to a full plan. A bucket policy attached out of band to a
    bucket whose policy resource is not standing would not fail this
    check. That is a job for a config-read check on the attribute itself.

Scope is every managed address in state, passed as -target. Untargeted,
a plan evaluates the whole configuration, and with the application
environment torn down that fails on references to resources that are not
standing -- and, without refresh-only mode, proposes creating all of
them. Targeting what is in state checks everything standing: the
persistent set between sessions, the whole environment while it is up.

Check params:
    root        "aws" or "gcp" -- the directory under infra/
    assertion   "no_drift" or "declared_exists_live"
    variables   TF_VAR_ names that must be set in the environment. Listed
                in the check so the definition records what the plan was
                evaluated with. A missing one is an error, never a pass:
                the plan would evaluate a different configuration.

The variables must match what the environment was applied with. Run
against a standing phase 2 without deploy_services=true and the plan
proposes destroying the services -- which is reported, correctly, as
declared and live disagreeing under the configuration given.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from base import CheckDefinition, CheckResult, Mechanism

INFRA_DIR = Path(__file__).resolve().parents[2] / "infra"

TIMEOUT_SECONDS = 600

# One plan per root per process. Both assertions read the same plan, and
# a run of the collector is one moment in time -- planning twice would
# double a slow step to answer the same question. Nothing survives the
# process, for the reason aws_source gives: a cached answer describes
# what existed last time, not now.
_PLANS: dict[str, dict[str, Any]] = {}


class DeclaredVersusLiveComparison(Mechanism):
    name = "declared_versus_live_comparison"

    def run(self, check: CheckDefinition) -> CheckResult:
        assertion = check.params["assertion"]
        if assertion not in ASSERTIONS:
            raise NotImplementedError(
                f"declared_versus_live_comparison has no handler for "
                f"assertion={assertion!r} yet -- add one as new checks need it."
            )

        missing = [v for v in check.params["variables"] if not os.environ.get(v)]
        if missing:
            raise RuntimeError(
                f"required Terraform variables not set: {', '.join(missing)}"
            )

        root = check.params["root"]
        if root not in _PLANS:
            _PLANS[root] = plan(root)

        passed, evidence, message = evaluate(assertion, _PLANS[root])
        evidence["root"] = root
        return CheckResult(check.id, passed, evidence, message)


# --- running Terraform ---


def plan(root: str) -> dict[str, Any]:
    """Plan every managed address in state and return the plan as JSON.

    Raises on any Terraform failure. A plan that errors is not a plan that
    found nothing, and drift.yml draws the same three-way line.
    """
    workdir = INFRA_DIR / root
    if not (workdir / ".terraform").is_dir():
        raise RuntimeError(f"infra/{root} is not initialised -- run terraform init there")

    addresses = [
        a for a in _terraform(workdir, "state", "list").splitlines()
        if a and not a.startswith("data.")
    ]
    if not addresses:
        # Nothing in state is a finding, not a pass. evaluate() says so,
        # but only if it is handed a plan to say it about.
        return {"prior_state": {}, "resource_changes": [], "resource_drift": []}

    with tempfile.TemporaryDirectory() as tmp:
        planfile = Path(tmp) / "plan"
        _terraform(
            workdir,
            "plan", "-input=false", "-no-color", "-lock-timeout=60s",
            f"-out={planfile}",
            *(f"-target={a}" for a in addresses),
        )
        result = json.loads(_terraform(workdir, "show", "-json", str(planfile)))

    if result.get("errored"):
        raise RuntimeError(f"terraform plan in infra/{root} reported errors")
    return result


def _terraform(workdir: Path, *args: str) -> str:
    completed = subprocess.run(
        ["terraform", *args],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout).strip()[-800:]
        raise RuntimeError(f"terraform {args[0]} failed in {workdir.name}: {tail}")
    return completed.stdout


# --- reading the plan ---
#
# Pure functions of the plan JSON, so self_test.py can prove each one
# fails on a plan that should fail it, without a cloud to break.


def evaluate(assertion: str, plan_json: dict[str, Any]) -> tuple[bool, dict, str]:
    return ASSERTIONS[assertion](plan_json)


def _no_drift(plan_json: dict[str, Any]) -> tuple[bool, dict, str]:
    """Passes if the plan proposes no change to anything in state.

    Each proposed change is attributed, because the causes have different
    owners and different remedies:

      changed outside Terraform   refresh saw the live object move since
                                  the last apply
      follows from another change every differing attribute is unknown
                                  until apply -- typically a data source
                                  whose read is deferred because something
                                  it depends on has a pending change.
                                  Found on the live test: tagging the
                                  extract bucket made the cross-cloud
                                  role's policy, built from a document
                                  that names the bucket, show as changing
      declaration not applied     otherwise -- the code moved and the
                                  environment did not

    All three are declared and live disagreeing, so all three fail.
    """
    checked = _managed_in_state(plan_json)
    drifted_outside = {d["address"] for d in plan_json.get("resource_drift", [])}

    changes = []
    for rc in plan_json.get("resource_changes", []):
        actions = rc["change"]["actions"]
        if rc.get("mode") != "managed" or actions == ["no-op"]:
            continue
        known, unknown = _changed_attributes(rc["change"])
        if rc["address"] in drifted_outside:
            cause = "changed outside Terraform"
        elif unknown and not known and actions == ["update"]:
            cause = "follows from another change"
        else:
            cause = "declaration not applied"
        changes.append({
            "address": rc["address"],
            "actions": actions,
            "cause": cause,
            # Names only. Values can be secrets, and the evidence is kept.
            "attributes": sorted(known | unknown),
        })

    evidence = {"resources_checked": len(checked), "changes": changes}
    if not checked:
        return False, evidence, "nothing in state to compare -- a check over nothing cannot pass"
    if changes:
        return False, evidence, f"{len(changes)} of {len(checked)} resources differ from their declaration"
    return True, evidence, f"all {len(checked)} resources match their declaration"


def _declared_exists_live(plan_json: dict[str, Any]) -> tuple[bool, dict, str]:
    """Passes if every managed resource in state still exists.

    Refresh reports a vanished object as drift with the action "delete".
    That entry is reliable where refresh's attribute diffs are not: an
    object is either there or it is not.
    """
    checked = _managed_in_state(plan_json)
    missing = sorted(
        d["address"]
        for d in plan_json.get("resource_drift", [])
        if d["change"]["actions"] == ["delete"]
    )

    evidence = {"resources_checked": len(checked), "missing": missing}
    if not checked:
        return False, evidence, "nothing in state to compare -- a check over nothing cannot pass"
    if missing:
        return False, evidence, f"{len(missing)} of {len(checked)} declared resources no longer exist"
    return True, evidence, f"all {len(checked)} declared resources exist"


ASSERTIONS = {
    "no_drift": _no_drift,
    "declared_exists_live": _declared_exists_live,
}


def _managed_in_state(plan_json: dict[str, Any]) -> list[str]:
    def walk(module: dict) -> list[dict]:
        found = list(module.get("resources", []))
        for child in module.get("child_modules", []):
            found.extend(walk(child))
        return found

    root = plan_json.get("prior_state", {}).get("values", {}).get("root_module", {})
    return [r["address"] for r in walk(root) if r.get("mode") == "managed"]


def _changed_attributes(change: dict) -> tuple[set[str], set[str]]:
    """Top-level attribute names that differ: (known after, unknown until apply)."""
    before = change.get("before") or {}
    after = change.get("after") or {}
    pending = change.get("after_unknown") or {}
    unknown = {k for k, v in pending.items() if v}
    known = {
        k for k in set(before) | set(after)
        if k not in unknown and before.get(k) != after.get(k)
    }
    return known, unknown
