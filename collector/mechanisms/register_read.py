"""Mechanism: reconcile the live inventory against a register in the repository.

Built 2026-10-03, replacing the stub in not_yet_built.py. A register is a
versioned file of recorded positions -- registers/resources.yaml holds one
entry per resource class, one position per dimension. The matrix asks, in a
dozen determinations, that every resource in the inventory carry such a
position; this is where that is checked.

Check params:
    register    path from the repository root, e.g. "registers/resources.yaml"
    assertion   "covers_inventory", "plan_covers_classes" or "secrets_owned"
    dimension   covers_inventory: the position every inventoried class must carry
    required_classes  plan_covers_classes: the classes the design names
    types       secrets_owned: the inventory classes that are secrets, keys or certificates
    region      AWS region for the AWS inventory
    project_id  GCP project for the GCP inventory

The inventory is generated live, as inventory_reconciliation does, so a
class that appears in the account without a register entry fails the day
it appears. A class with no resources is not required, but its entry, if
present, is still validated: a register is read whole.
"""

from __future__ import annotations

import fnmatch
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
        register = yaml.safe_load((REPO / p["register"]).read_text())
        if p["assertion"] == "covers_inventory":
            counts = _class_counts(p["region"], p["project_id"])
            existing = {f.stem for f in CHECKS.glob("*.json")}
            ok, detail, evidence = evaluate_register_coverage(counts, register, p["dimension"], existing)
        elif p["assertion"] == "plan_covers_classes":
            ok, detail, evidence = evaluate_plan_classes(register, p["required_classes"])
        elif p["assertion"] == "entries_complete":
            ok, detail, evidence = evaluate_entries_complete(register.get("entries") or [])
        elif p["assertion"] == "secrets_owned":
            members = [r for r in _inventory(p["region"], p["project_id"]) if r["resource_type"] in p["types"]]
            ok, detail, evidence = evaluate_secrets_owned(members, register)
        else:
            raise NotImplementedError(f"register_read has no assertion {p['assertion']!r}")
        return CheckResult(check.id, ok, evidence, detail)


@lru_cache(maxsize=None)
def _inventory(region: str, project_id: str) -> tuple[dict, ...]:
    """Both inventories, generated once per run: every register check reads
    the same inventory, and generating it is the slow part."""
    return tuple(aws_source.generate(region=region) + gcp_source.generate(project_id=project_id))


def _class_counts(region: str, project_id: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in _inventory(region, project_id):
        counts[r["resource_type"]] = counts.get(r["resource_type"], 0) + 1
    return counts


def evaluate_entries_complete(entries: list[dict]) -> tuple[bool, str, dict]:
    """Every entry has a reason and an expiry: days, or the event it expires with."""
    problems = []
    for e in entries:
        days = e.get("expiry_days")
        has_expiry = (isinstance(days, int) and not isinstance(days, bool) and days >= 0) or bool(e.get("expires_with"))
        if not (e.get("reason") or "").strip():
            problems.append(f"{e.get('what')}: no reason")
        if not has_expiry:
            problems.append(f"{e.get('what')}: no expiry")
    evidence = {"entries": len(entries), "problems": problems}
    if not entries:
        return False, "the register is empty", evidence
    if problems:
        return False, f"{len(problems)} incomplete: {'; '.join(problems)}", evidence
    return True, f"all {len(entries)} entries carry a reason and an expiry", evidence


def evaluate_plan_classes(register: dict, required: list[str]) -> tuple[bool, str, dict]:
    """Every required class is planned: a mechanism, member rules, and an
    interval -- or, where the class has no member yet, a recorded deferral
    in place of an interval."""
    classes = register.get("classes") or {}
    problems = {}
    for name in required:
        c = classes.get(name)
        if not c:
            problems[name] = "not in the plan"
        elif not c.get("mechanism") or not c.get("members"):
            problems[name] = "mechanism and member rules required"
        elif not isinstance(c.get("interval_days"), int) and not c.get("deferred"):
            problems[name] = "an interval in days, or a recorded deferral"
    evidence = {"classes": {k: v.get("interval_days") for k, v in classes.items()}, "problems": problems}
    if problems:
        return False, f"{len(problems)} class(es) unplanned: {', '.join(sorted(problems))}", evidence
    return True, f"all {len(required)} classes planned", evidence


def evaluate_secrets_owned(members: list[dict], register: dict) -> tuple[bool, str, dict]:
    """Every secret, key and certificate in the inventory matches a class."""
    rules = [(name, m) for name, c in (register.get("classes") or {}).items() for m in c.get("members", [])]
    owners, orphans = {}, []
    for r in members:
        owner = next((name for name, m in rules if m["resource_type"] == r["resource_type"]
                      and fnmatch.fnmatchcase(r.get("name") or "", m["name"])), None)
        if owner:
            owners[owner] = owners.get(owner, 0) + 1
        else:
            orphans.append(f"{r['resource_type']} {r.get('name') or r['resource_id']}")
    evidence = {"owned": owners, "unowned": orphans}
    if not members:
        return False, "no secrets, keys or certificates in the inventory -- nothing to judge", evidence
    if orphans:
        return False, f"{len(orphans)} without an owning class: {', '.join(orphans[:5])}", evidence
    return True, f"all {len(members)} owned: " + ", ".join(f"{n} {k}" for k, n in sorted(owners.items())), evidence


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
