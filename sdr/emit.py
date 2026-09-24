#!/usr/bin/env python3
"""Emits the Security Decision Record: the project's actual deliverable.

Reads the 46 determinations from docs/KSI-Design-Matrix.xlsx and the
collector's latest results, and writes one SDR in FedRAMP's schema, as JSON
and as a human-readable rendering of that same JSON. Validates against the
pinned schema before writing anything; a validation error fails the run.

    cd sdr && ../.venv/bin/python emit.py --results ../collector/results.json

See docs/SDR-Emitter-Spec.md for the mapping, and DECISIONS.md, 2026-09-23,
for the choices made where the spec left one open.

What the output does not claim, stated here and in the rendering:

    No independent assessor is engaged. ksiAssessment carries the provider's
    own assurance reasoning and says so, rather than wearing an assessor's
    label.

    fedRampRequirements is emitted empty. The project determined the 46
    indicators and not the FRR rules; --frr is a switch so that the omission
    is a stated choice, not a silent one.

    SDR-CSX-KMT's historical metrics do not exist. There is no record store
    and no collector schedule, so the evidence is one run. The collection
    window is stated on every indicator.

    certificationPackageOverviewUri points at the repository README at the
    emitting commit. It is the project's overview. It is not a FedRAMP
    Certification Package Overview, and the rendering says so.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOCS = REPO / "docs"
MATRIX = DOCS / "KSI-Design-Matrix.xlsx"
OUT = Path(__file__).resolve().parent / "out"
REPOSITORY_URL = "https://github.com/elvie-valmores/fedramp-20x-ksi-assessment"

# Pinned by filename, internal version and hash. The filename is dated and
# does not change when the content does -- the SDR schema moved from 1.0.3
# to 1.1.1 under the same name -- so all three are checked.
SCHEMAS = {
    "sdr": ("fedramp-security-decision-record-schema-2026-06-24.json", "1.1.1",
            "94580404e8d4276ee3ced2a3c39cce5cc6565df6ae38a91f60f26cb96d833188"),
    "common": ("fedramp-common-definitions-schema-2026-06-24.json", "0.4.0",
               "be90c62c8dd8d270d48965b92e3a2a831b8b81791d509cc92557b72ccb0a1b44"),
}

# A project-level fact, not a per-row one: the determinations state a
# required cycle, and nothing yet runs the collectors on it.
CYCLE_PRACTICE = (
    "Current practice: the collector is run by hand. No collector schedule or "
    "runtime exists yet, so the required cycle is a requirement of the "
    "determination, not yet a property of the system (DECISIONS.md, 2026-09-23)."
)
NO_ASSESSOR = (
    "**No independent assessor is engaged.** The statements below are the "
    "provider's own assurance reasoning from the determination. They are not an "
    "independent assessment and should not be read as one."
)
STATUS = {
    "IN SCOPE": "Implemented",
    "IN SCOPE, PARTIALLY SATISFIED": "Partially Implemented",
    "DEFERRED": "Not Implemented",
}


# --- reading the determinations ---


@dataclass
class Determination:
    ksi_id: str
    title: str
    status: str
    sections: dict[str, str] = field(default_factory=dict)
    tables: dict[str, list[list[str]]] = field(default_factory=dict)

    @property
    def deferred(self) -> bool:
        return self.status == "DEFERRED"


TITLE = re.compile(r"^(KSI-[A-Z]{3}-[A-Z]{3}) — (.+?)\s{2,}(" + "|".join(map(re.escape, STATUS)) + r")\s*$")
LABEL = re.compile(
    r"^(Requirement(?: \(Class C variant\))?|Design rationale(?: for deferral)?|"
    r"Automation assurance|Remediation|Limitations and residual risk):\s+(.*)$",
    re.S,
)
TABLE = re.compile(r"^(BUILD|VERIFY|VALIDATE|PROVE) — ")
NOT_DETERMINATIONS = {"Index", "Responsibility Matrix", "Assertion Coverage"}


def read_determinations() -> list[Determination]:
    """Every determination in the matrix, or an error naming what was not understood.

    Anything inside a determination block that is not a known label, table
    header or table row stops the run. A parser that skipped what it did not
    recognise would drop text from the SDR without anyone knowing.
    """
    import openpyxl

    workbook = openpyxl.load_workbook(MATRIX, read_only=True)
    found, problems = [], []
    for sheet in workbook.worksheets:
        if sheet.title in NOT_DETERMINATIONS:
            continue
        current, table = None, None
        for number, row in enumerate(sheet.iter_rows(values_only=True), start=1):
            cells = ["" if c is None else str(c).strip() for c in row]
            first = cells[0] if cells else ""
            if not any(cells):
                continue
            if title := TITLE.match(first):
                current = Determination(title.group(1), title.group(2).strip(), title.group(3))
                found.append(current)
                table = None
            elif current is None:
                continue  # the sheet's own heading and introduction
            elif label := LABEL.match(first):
                key = "Requirement" if label.group(1).startswith("Requirement") else label.group(1)
                current.sections[key] = label.group(2).strip()
                table = None
            elif header := TABLE.match(first):
                table = header.group(1)
                current.tables.setdefault(table, [])
            elif table:
                current.tables[table].append(cells[:5])
            else:
                problems.append(f"{sheet.title}!R{number}: not understood: {first[:60]!r}")
    if problems:
        sys.exit("the matrix has content the emitter does not understand:\n  " + "\n  ".join(problems))
    return found


# --- building the record ---


def build_statement(row: list[str]) -> str:
    number, what, configuration, cloud, provisioned = row
    return f"**{number}. {what}** — {configuration} *({cloud}; provisioned by {provisioned})*"


def evidence_row_statement(row: list[str]) -> str:
    kind, artifact, source, required, implemented = row
    return f"**{kind}** — {artifact}. Source: {source}. Required every {required}; implemented: {implemented}."


def indicator(det: Determination, outcomes: list[dict], context: dict, controls: dict) -> dict:
    mine = [o for o in outcomes if o["check"]["indicator"] == det.ksi_id]
    s = det.sections

    if det.deferred:
        implementation = [
            f"**Deferred.** {s['Design rationale for deferral']}",
            f"**Resulting risk.** {s['Limitations and residual risk']}",
        ]
    else:
        implementation = [s["Design rationale"]] + [build_statement(r) for r in det.tables.get("BUILD", [])]

    cadences = sorted({r[3] for t in ("VERIFY", "VALIDATE", "PROVE") for r in det.tables.get(t, []) if r[3]})
    validation = [
        f"**Cycle.** Required: {', '.join(cadences) or 'not stated'}. {CYCLE_PRACTICE}",
        *[evidence_row_statement(r) for t in ("VERIFY", "VALIDATE", "PROVE") for r in det.tables.get(t, [])],
        collection_statement(mine, context),
    ]

    assessment = [NO_ASSESSOR]
    if "Automation assurance" in s:
        assessment.append(f"**Automation assurance.** {s['Automation assurance']}")
    assessment.append(f"**Limitations and residual risk.** {s['Limitations and residual risk']}")

    return {
        "ksiId": det.ksi_id,
        "ksiImplementationStatus": STATUS[det.status],
        "ksiImplementation": implementation,
        "ksiValidation": validation,
        "ksiAssessment": assessment,
        "ksiTests": tests(det, mine, controls),
        "ksiEvidence": [evidence(o, context) for o in mine],
    }


def collection_statement(mine: list[dict], context: dict) -> str:
    if not mine:
        return (
            "**Automated evidence.** No collector check exists for this indicator yet, so no "
            "evidence is attached. The rows above are the determination's design."
        )
    counts = {}
    for o in mine:
        counts[o["status"]] = counts.get(o["status"], 0) + 1
    tally = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
    return (
        f"**Automated evidence.** {len(mine)} collector check(s) in one run on "
        f"{context['run_date']}: {tally}. Collection window: that single run. No historical "
        "metrics exist (no record store, no schedule), so SDR-CSX-KMT's 30-day and yearly "
        "summaries cannot be produced."
    )


def tests(det: Determination, mine: list[dict], controls: dict) -> list[str]:
    found = []
    for o in mine:
        check = o["check"]
        key = check["params"].get("assertion") or check["params"].get("resource")
        if (check["mechanism"], key) in controls:
            found.append(
                f"Negative control for `{check['id']}` (collector/self_test.py): "
                f"{controls[(check['mechanism'], key)]}."
            )
    # Test scenarios the determination designs but nothing runs yet. Listed
    # as designed, because a test that has not run has not validated anything.
    for row in det.tables.get("VALIDATE", []):
        if re.search(r"deliberate|test", f"{row[1]} {row[2]}", re.I):
            found.append(f"Designed, not yet automated: {row[1]} ({row[2]}).")
    if not found:
        found.append("None run or designed." if det.deferred else "No test is automated for this indicator yet.")
    return found


def evidence(outcome: dict, context: dict) -> dict:
    check, result = outcome["check"], outcome.get("result") or {}
    if check["evidence_type"] == "CFG":
        kind = "Configuration"
    elif check["mechanism"] == "log_query":
        kind = "Log"
    else:
        kind = "Report"
    ran = (result.get("ran_at") or context["started_at"])[:10]
    return {
        "evidenceType": kind,
        "evidenceDescription": f"{check['description']}. Result: {outcome['status']} — {outcome['message']}",
        "evidenceLocation": f"{REPOSITORY_URL}/blob/{context['commit']}/collector/checks/{check['id']}.json",
        "evidenceText": json.dumps(
            {"check": check["id"], "status": outcome["status"], "evidence": result.get("evidence")},
            indent=2, default=str,
        ),
        "lastUpdated": ran,
    }


def record(dets, outcomes, context, controls, frr: str) -> dict:
    if frr != "empty":
        raise NotImplementedError(
            "--frr populated needs FRR determinations (MAS, VDR, IVV, SDR), which do not exist yet"
        )
    return {
        "certificationPackageOverviewUri": f"{REPOSITORY_URL}/blob/{context['commit']}/README.md",
        "metadata": {
            "version": context["version"],
            "lastUpdated": context["emitted_at"],
            "updateSource": (
                "Automated: sdr/emit.py, from docs/KSI-Design-Matrix.xlsx and the collector run "
                f"started {context['started_at']}"
            ),
        },
        "fedRampRequirements": [],
        "keySecurityIndicators": [indicator(d, outcomes, context, controls) for d in dets],
    }


# --- checking what was built ---


def load_schemas() -> tuple[dict, dict]:
    loaded = {}
    for key, (name, version, digest) in SCHEMAS.items():
        raw = (DOCS / name).read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        schema = json.loads(raw)
        if actual != digest or schema.get("$schemaVersion") != version:
            sys.exit(
                f"{name} does not match its pin: sha256 {actual[:12]}…, "
                f"$schemaVersion {schema.get('$schemaVersion')} (pinned {digest[:12]}…, {version})"
            )
        loaded[key] = schema
    return loaded["sdr"], loaded["common"]


def validate(sdr: dict, schema: dict, common: dict) -> list[str]:
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource

    registry = Registry().with_resource(common["$id"], Resource.from_contents(common))
    validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
    problems = [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in validator.iter_errors(sdr)]

    # jsonschema checks "uri" and "date-time" formats only when optional
    # packages are installed, so a pass would not mean they were checked.
    # These are checked here instead, and so is the spec's own rule that an
    # evidence object is never empty even though the schema allows it.
    uri = re.compile(r"^https://\S+$")
    if not uri.match(sdr["certificationPackageOverviewUri"]):
        problems.append("certificationPackageOverviewUri is not an https URI")
    datetime.fromisoformat(sdr["metadata"]["lastUpdated"])
    for k in sdr["keySecurityIndicators"]:
        for i, e in enumerate(k["ksiEvidence"]):
            where = f"{k['ksiId']} evidence {i}"
            if not (e.get("evidenceType") and e.get("evidenceDescription")):
                problems.append(f"{where}: missing type or description")
            if not (e.get("evidenceLocation") or e.get("evidenceText")):
                problems.append(f"{where}: neither location nor text")
            if e.get("evidenceLocation") and not uri.match(e["evidenceLocation"]):
                problems.append(f"{where}: evidenceLocation is not an https URI")
            date.fromisoformat(e["lastUpdated"])
    return problems


# --- the rendering ---


def render(sdr: dict, context: dict) -> str:
    """Markdown generated from the emitted JSON, never from the matrix.

    Rendering the record rather than re-deriving it means the two formats
    cannot say different things.
    """
    ksis = sdr["keySecurityIndicators"]
    counts = {}
    for k in ksis:
        counts[k["ksiImplementationStatus"]] = counts.get(k["ksiImplementationStatus"], 0) + 1
    evidence_total = sum(len(k["ksiEvidence"]) for k in ksis)
    covered = sum(1 for k in ksis if k["ksiEvidence"])

    lines = [
        "# Security Decision Record — Caliper",
        "",
        f"Version `{sdr['metadata']['version']}`, emitted {sdr['metadata']['lastUpdated']}. "
        f"Schema {SCHEMAS['sdr'][0]} `$schemaVersion` {SCHEMAS['sdr'][1]}; validated on emit.",
        "",
        "## What this record does and does not claim",
        "",
        f"- **{len(ksis)} indicators**: " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())) + ".",
        f"- **Automated evidence** for {covered} of {len(ksis)} indicators, {evidence_total} evidence objects, "
        f"from one collector run started {context['started_at']}.",
        "- **No independent assessor is engaged.** Assessment statements are the provider's own reasoning.",
        "- **`fedRampRequirements` is empty.** The project determined the 46 indicators, not the FRR rules.",
        "- **No historical metrics (SDR-CSX-KMT).** No record store and no collector schedule exist, "
        "so the collection window is one run.",
        f"- **`certificationPackageOverviewUri`** points at the project README. It is not a FedRAMP "
        "Certification Package Overview.",
        "",
    ]
    for k in ksis:
        lines += [f"## {k['ksiId']} — {k['ksiImplementationStatus']}", ""]
        for heading, key in (("Implementation", "ksiImplementation"), ("Validation", "ksiValidation"),
                             ("Assessment", "ksiAssessment")):
            lines += [f"### {heading}", ""] + [f"- {x}" for x in k[key]] + [""]
        lines += ["### Tests", ""] + [f"- {x}" for x in k["ksiTests"]] + [""]
        lines += ["### Evidence", ""]
        if not k["ksiEvidence"]:
            lines += ["None attached.", ""]
        for e in k["ksiEvidence"]:
            lines += [f"- *{e['evidenceType']}, {e['lastUpdated']}* — {e['evidenceDescription']} "
                      f"([definition]({e['evidenceLocation']}))"]
        lines += [""]
    return "\n".join(lines)


# --- running it ---


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True, help="collector output from run_checks.py --json")
    parser.add_argument("--frr", choices=["empty", "populated"], required=True,
                        help="how to emit fedRampRequirements; only 'empty' is possible today")
    args = parser.parse_args()

    schema, common = load_schemas()
    run = json.loads(args.results.read_text())
    commit = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain"))
    context = {
        "commit": commit,
        # Evidence links point at this commit. If the tree has uncommitted
        # changes, the links may not show what was run, and the version says so.
        "version": commit[:12] + ("-dirty" if dirty else ""),
        "emitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "started_at": run["started_at"],
        "run_date": run["started_at"][:10],
    }

    sys.path.insert(0, str(REPO / "collector"))
    import self_test

    dets = read_determinations()
    ids = [d.ksi_id for d in dets]
    if len(ids) != len(set(ids)):
        sys.exit("a KSI appears twice in the matrix")
    unknown = sorted({o["check"]["indicator"] for o in run["outcomes"]} - set(ids))
    if unknown:
        # Evidence for an indicator the SDR does not contain would vanish.
        sys.exit(f"collector results name indicators the matrix does not: {', '.join(unknown)}")

    sdr = record(dets, run["outcomes"], context, self_test.negative_controls(), args.frr)
    problems = validate(sdr, schema, common)
    if problems:
        print("the record does not validate; nothing written:", *problems[:40], sep="\n  ")
        return 1

    OUT.mkdir(exist_ok=True)
    (OUT / "sdr.json").write_text(json.dumps(sdr, indent=2) + "\n")
    (OUT / "sdr.md").write_text(render(sdr, context))
    print(f"wrote sdr/out/sdr.json and sdr/out/sdr.md: {len(dets)} indicators, "
          f"{sum(len(k['ksiEvidence']) for k in sdr['keySecurityIndicators'])} evidence objects, "
          f"version {context['version']}, valid against {SCHEMAS['sdr'][0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
