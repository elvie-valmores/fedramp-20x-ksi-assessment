"""Mechanism: reconcile the live inventory against a register in the repository.

Built 2026-10-03, replacing the stub in not_yet_built.py. A register is a
versioned file of recorded positions -- registers/resources.yaml holds one
entry per resource class, one position per dimension. The matrix asks, in a
dozen determinations, that every resource in the inventory carry such a
position; this is where that is checked.

Check params:
    register    path from the repository root, e.g. "registers/resources.yaml"
    assertion   "covers_inventory"
    dimension   the position every inventoried class must carry
    region      AWS region for the AWS inventory
    project_id  GCP project for the GCP inventory

The inventory is generated live, as inventory_reconciliation does, so a
class that appears in the account without a register entry fails the day
it appears. A class with no resources is not required, but its entry, if
present, is still validated: a register is read whole.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

import _paths  # noqa: F401  (puts inventory/ on the import path)
import aws_source
import gcp_source
from base import CheckDefinition, CheckResult, Mechanism

REPO = Path(__file__).resolve().parents[2]
CHECKS = REPO / "collector" / "checks"


class RegisterRead(Mechanism):
    name = "register_read"

    def run(self, check: CheckDefinition) -> CheckResult:
        p = check.params
        if p["assertion"] != "covers_inventory":
            raise NotImplementedError(f"register_read has no assertion {p['assertion']!r}")
        register = yaml.safe_load((REPO / p["register"]).read_text())
        counts = _class_counts(p["region"], p["project_id"])
        existing = {f.stem for f in CHECKS.glob("*.json")}
        ok, detail, evidence = evaluate_register_coverage(counts, register, p["dimension"], existing)
        return CheckResult(check.id, ok, evidence, detail)


@lru_cache(maxsize=None)
def _class_counts(region: str, project_id: str) -> dict[str, int]:
    """Resources per class across both inventories, generated once per run:
    every register check reads the same inventory, and generating it is the
    slow part."""
    counts: dict[str, int] = {}
    for r in aws_source.generate(region=region) + gcp_source.generate(project_id=project_id):
        counts[r["resource_type"]] = counts.get(r["resource_type"], 0) + 1
    return counts


def _position_problem(dimension: str, value, plan: dict, existing_checks: set[str]) -> str | None:
    """Why a recorded position is not a position, or None if it is one."""
    if value in (None, "", {}):
        return "no position recorded"
    if dimension == "availability":
        if not value.get("posture") or not value.get("recovery"):
            return "posture and recovery both required"
        if "reduced" in value["posture"].lower() and not value.get("reason"):
            return "a reduced posture needs its reason"
    elif dimension == "backup":
        if not value.get("coverage"):
            return "coverage required"
        if value["coverage"].strip().lower() == "none" and not value.get("reason"):
            return "no backup needs a recorded reason"
    elif dimension == "objective":
        if not (value.get("rto") and value.get("rpo")) and not value.get("not_applicable"):
            return "an RTO and RPO pair, or a not-applicable reason"
    elif dimension == "evaluation":
        if not value.get("by"):
            return "what evaluates it is required"
        days = value.get("interval_days")
        if days is None or days > plan.get("sample_max_days", 3):
            return f"interval {days} days exceeds the plan's {plan.get('sample_max_days')}"
    elif dimension == "data_store":
        if not isinstance(value.get("holds_data"), bool):
            return "holds_data must be true or false"
        if value["holds_data"] and value.get("encryption_check") not in existing_checks:
            return f"names no existing encryption check ({value.get('encryption_check')})"
    elif not isinstance(value, str) or not value.strip():
        return "a statement is required"
    return None


def evaluate_register_coverage(counts: dict[str, int], register: dict, dimension: str,
                               existing_checks: set[str]) -> tuple[bool, str, dict]:
    """Every inventoried class has an entry carrying a valid position on the dimension.

    Pure, for self_test.py. counts: {class: number of resources}.
    """
    classes = register.get("classes") or {}
    plan = register.get("evaluation_plan") or {}
    problems = {}
    for cls in sorted(set(counts) | set(classes)):
        if cls in counts and cls not in classes:
            problems[cls] = f"{counts[cls]} in the inventory, no register entry"
            continue
        if cls in classes:
            why = _position_problem(dimension, classes[cls].get(dimension), plan, existing_checks)
            if why:
                problems[cls] = why
    evidence = {"dimension": dimension, "inventoried": counts, "problems": problems}
    if not counts:
        return False, "the inventory is empty -- nothing to reconcile", evidence
    if problems:
        return False, f"{len(problems)} class(es) without a valid {dimension} position: {', '.join(sorted(problems))}", evidence
    return True, f"all {len(counts)} inventoried classes carry a recorded {dimension} position", evidence
