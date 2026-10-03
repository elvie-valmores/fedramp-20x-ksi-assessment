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
        elif p["assertion"] == "third_parties_cover":
            used = _third_parties_used(p["region"], p["project_id"], p.get("also_used", []))
            ok, detail, evidence = evaluate_third_parties(used, register.get("entries") or {}, p["position"])
        elif p["assertion"] in ("sources_positioned", "sources_tiered", "audited_reviewed"):
            existing = {f.stem for f in CHECKS.glob("*.json")}
            ok, detail, evidence = evaluate_sources(register.get("sources") or {}, p["assertion"], existing)
        elif p["assertion"] == "paths_authenticated":
            ok, detail, evidence = evaluate_paths_authenticated(register)
        elif p["assertion"] == "exceptions_bounded":
            ok, detail, evidence = evaluate_exceptions_bounded(register, p["categories"])
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


def _third_parties_used(region: str, project_id: str, also_used: list[dict]) -> list[dict]:
    """Every third party actually in use, from the places that declare it."""
    import re

    used = [{"inventory_cloud": c} for c in sorted({r["cloud"] for r in _inventory(region, project_id)})]
    for wf in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        for job in (yaml.safe_load(wf.read_text()) or {}).get("jobs", {}).values():
            for ref in [job.get("uses")] + [s.get("uses") for s in job.get("steps") or []]:
                if ref and not ref.startswith("./"):
                    used.append({"action_owner": ref.split("/", 1)[0]})
    for dockerfile in sorted(REPO.glob("app/*/Dockerfile")):
        for m in re.finditer(r"^FROM\s+(\S+)", dockerfile.read_text(), re.M):
            used.append({"base_image": m.group(1).split("@", 1)[0]})
    for lock in sorted(REPO.glob("infra/*/.terraform.lock.hcl")):
        for m in re.finditer(r'^provider "([^"]+)"', lock.read_text(), re.M):
            used.append({"terraform_provider": m.group(1)})
    if list(REPO.glob("**/requirements.txt")):
        used.append({"package_index": "pypi"})
    unique = {tuple(sorted(u.items())) for u in used + list(also_used)}
    return [dict(u) for u in sorted(unique)]


def evaluate_third_parties(used: list[dict], entries: dict, position: str) -> tuple[bool, str, dict]:
    """Every third party in use matches an entry, and that entry carries the position.

    position: "comparison" (basis, automated) or "monitoring" (mechanism,
    status of automatic, partial or unavailable).
    """
    def matches(u, m):
        return set(u) == set(m) and all(fnmatch.fnmatchcase(str(u[k]), str(m[k])) for k in u)

    problems, covered = [], {}
    for u in used:
        owner = next((name for name, e in entries.items() if any(matches(u, m) for m in e.get("matches", []))), None)
        if owner is None:
            problems.append(f"no entry for {u}")
            continue
        covered.setdefault(owner, []).append(u)
    for name, e in entries.items():
        pos = e.get(position) or {}
        if position == "comparison" and (not pos.get("basis") or pos.get("automated") not in (True, False, "partial")):
            problems.append(f"{name}: comparison needs a basis and whether it is automated")
        if position == "monitoring" and (not pos.get("mechanism") or pos.get("status") not in ("automatic", "partial", "unavailable")):
            problems.append(f"{name}: monitoring needs a mechanism and a status")
    evidence = {"used": used, "covered_by": {k: len(v) for k, v in covered.items()}, "problems": problems}
    if not used:
        return False, "found no third party in use -- nothing to judge", evidence
    if problems:
        return False, f"{len(problems)} problem(s): {'; '.join(problems[:4])}", evidence
    return True, f"all {len(used)} third parties in use registered with a {position} position", evidence


STATES = ("yes", "partial", "no")
TIERS = ("sensitive", "operational", "public-safe")


def evaluate_sources(sources: dict, assertion: str, existing_checks: set[str]) -> tuple[bool, str, dict]:
    """The event type list, judged one way per assertion.

    sources_positioned  events, expected interval and destination stated, and
                        logged, monitored and audited each yes, partial or no,
                        with how (KSI-MLA-LET verify 3)
    sources_tiered      a tier with its reason (KSI-MLA-ALA verify 1, validate 5)
    audited_reviewed    every source audited in any part names the standing
                        checks that review it, and they exist (KSI-MLA-RVL validate 5)
    """
    problems = []
    for name, s in sources.items():
        if assertion == "sources_positioned":
            for field in ("events", "expected", "destination"):
                if not (s.get(field) or "").strip():
                    problems.append(f"{name}: no {field}")
            for axis in ("logged", "monitored", "audited"):
                pos = s.get(axis) or {}
                if pos.get("state") not in STATES or not (pos.get("how") or "").strip():
                    problems.append(f"{name}: {axis} needs a state of yes, partial or no, and how")
        elif assertion == "sources_tiered":
            tier = s.get("tier") or {}
            if tier.get("name") not in TIERS or not (tier.get("reason") or "").strip():
                problems.append(f"{name}: tier needs one of {', '.join(TIERS)} and a reason")
        elif assertion == "audited_reviewed":
            audited = s.get("audited") or {}
            if audited.get("state") in ("yes", "partial"):
                checks = audited.get("reviewed_by") or []
                if not checks:
                    problems.append(f"{name}: audited, but names no review")
                problems += [f"{name}: review {c} does not exist" for c in checks if c not in existing_checks]
    evidence = {"sources": len(sources), "problems": problems}
    if not sources:
        return False, "the event type list is empty", evidence
    if problems:
        return False, f"{len(problems)} problem(s): {'; '.join(problems[:4])}", evidence
    return True, f"all {len(sources)} sources pass {assertion}", evidence


def evaluate_paths_authenticated(register: dict) -> tuple[bool, str, dict]:
    """Every flow records its authenticity mechanism, and its rules name declared groups."""
    groups = set(register.get("groups") or [])
    problems = []
    for name, f in (register.get("flows") or {}).items():
        if not (f.get("authenticity") or "").strip():
            problems.append(f"{name}: no authenticity mechanism")
        for r in f.get("rules") or []:
            for g in (r.get("group"), r.get("peer")):
                if g and g.startswith("fedramp-") and g not in groups:
                    problems.append(f"{name}: unknown group {g}")
    flows = register.get("flows") or {}
    evidence = {"flows": len(flows), "problems": problems}
    if not flows:
        return False, "the flow register is empty", evidence
    if problems:
        return False, f"{len(problems)} problem(s): {'; '.join(problems[:3])}", evidence
    return True, f"all {len(flows)} paths record how each end is authenticated", evidence


def evaluate_exceptions_bounded(register: dict, allowed: list[str]) -> tuple[bool, str, dict]:
    """Only the declared categories; every entry dated, reasoned and in one;
    every standing exception with a closing condition (KSI-CMT-RMV verify 2)."""
    problems = []
    categories = set((register.get("categories") or {}).keys())
    if categories != set(allowed):
        problems.append(f"categories {sorted(categories)} are not exactly {sorted(allowed)}")
    for e in register.get("entries") or []:
        if e.get("category") not in allowed:
            problems.append(f"{e.get('what')}: category {e.get('category')!r} is not a declared one")
        if not (e.get("reason") or "").strip() or not e.get("date"):
            problems.append(f"{e.get('what')}: needs a date and a reason")
    for s in register.get("standing") or []:
        if not (s.get("closing_condition") or "").strip():
            problems.append(f"{s.get('what')}: a standing exception needs its closing condition")
    evidence = {"entries": len(register.get("entries") or []), "standing": len(register.get("standing") or []), "problems": problems}
    if problems:
        return False, f"{len(problems)} problem(s): {'; '.join(problems[:3])}", evidence
    return True, f"{evidence['entries']} exception(s), all in the two declared categories with reasons; {evidence['standing']} standing, each with a closing condition", evidence


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
