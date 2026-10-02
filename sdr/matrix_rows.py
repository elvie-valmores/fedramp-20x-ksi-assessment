#!/usr/bin/env python3
"""The matrix's evidence rows, the checks that link to them, and the coverage between.

The design matrix has 380 evidence rows: the VERIFY and VALIDATE tables under
each determination. Until 2026-10-02 a check named only its indicator, so
"12 of 46 indicators have automated evidence" was the finest statement the
project could make. One check per indicator counted the indicator as covered
whether it proved one of its rows or all of them.

Rows have no identifiers in the workbook, so they are given positional ones:
KSI-SVC-SIN.verify.1 is the first VERIFY row under KSI-SVC-SIN. Positions
move if a row is inserted above, which would move every link after it onto
the wrong row without any error. docs/matrix-rows.json is the guard: it
records each id with its row's text, and --check fails when the workbook no
longer produces the same file. A shifted row then shows up as a diff, and
the links get re-read before the snapshot is regenerated.

A check links rows in its "matrix_rows" list:

    {"row": "KSI-SVC-SIN.verify.2", "covers": "full"}
    {"row": "KSI-SVC-ACM.verify.3", "covers": "full", "with": ["svc-acm-cfg-gcp-declared-exists-live"]}
    {"row": "KSI-SVC-SIN.verify.6", "covers": "partial", "gap": "AWS keys only; Cloud KMS IAM is not read"}

"full" means the check proves the row as the matrix writes it. "with" means
full only together with the named checks; each must link the same row back,
naming this one. "partial" names what is missing. A check with no row it
proves carries "unlinked_reason" instead, so a check is never silently
outside the matrix.

    .venv/bin/python sdr/matrix_rows.py           # regenerate both files
    .venv/bin/python sdr/matrix_rows.py --check   # CI: fail if either is stale or a link is wrong
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SNAPSHOT = REPO / "docs" / "matrix-rows.json"
REPORT = REPO / "docs" / "MATRIX-COVERAGE.md"
CHECKS = REPO / "collector" / "checks"
TABLES = ("VERIFY", "VALIDATE")


def read_rows() -> list[dict]:
    """Every evidence row, through the emitter's parser, which rejects what it does not understand."""
    sys.path.insert(0, str(HERE))
    from emit import read_determinations

    return rows_from(read_determinations())


def rows_from(determinations) -> list[dict]:
    rows = []
    for det in determinations:
        for table in TABLES:
            for n, (kind, artifact, source, required, implemented) in enumerate(det.tables.get(table, []), start=1):
                rows.append({
                    "id": f"{det.ksi_id}.{table.lower()}.{n}",
                    "indicator": det.ksi_id,
                    "determination": det.status,
                    "type": kind,
                    "artifact": artifact,
                    "source": source,
                    "required": required,
                    "implemented": implemented,
                })
    return rows


def load_checks() -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(CHECKS.glob("*.json"))]


def link_problems(checks: list[dict], rows: list[dict]) -> list[str]:
    """Every way a check's links can be wrong. Empty means all are sound."""
    known = {r["id"] for r in rows}
    by_id = {c["id"]: c for c in checks}
    problems = []

    def links(check: dict) -> dict[str, dict]:
        return {link["row"]: link for link in check.get("matrix_rows", [])}

    for c in checks:
        cid, mine = c["id"], c.get("matrix_rows", [])
        reason = c.get("unlinked_reason", "").strip()
        if bool(mine) == bool(reason):
            problems.append(f"{cid}: needs exactly one of matrix_rows or unlinked_reason")
        seen = set()
        for link in mine:
            row = link.get("row")
            if row in seen:
                problems.append(f"{cid}: links {row} twice")
            seen.add(row)
            if row not in known:
                problems.append(f"{cid}: links {row}, which the matrix does not have")
            covers = link.get("covers")
            if covers not in ("full", "partial"):
                problems.append(f"{cid}: {row}: covers must be full or partial, not {covers!r}")
            if covers == "partial" and not link.get("gap", "").strip():
                problems.append(f"{cid}: {row}: a partial link must say what is missing")
            if covers == "full" and link.get("gap"):
                problems.append(f"{cid}: {row}: a full link has no gap")
            if link.get("with") and covers != "full":
                problems.append(f"{cid}: {row}: 'with' applies to full links only")
            for other in link.get("with", []):
                theirs = links(by_id[other]).get(row) if other in by_id else None
                if theirs is None:
                    problems.append(f"{cid}: {row}: names {other}, which does not link that row")
                elif theirs.get("covers") != "full" or cid not in theirs.get("with", []):
                    problems.append(f"{cid}: {row}: {other} links it back without naming {cid} as full")
    return problems


def coverage(checks: list[dict], rows: list[dict]) -> dict[str, dict]:
    """Per row: "full", "partial" or "none", the checks behind it, and the gaps."""
    result = {r["id"]: {"status": "none", "checks": [], "gaps": [], "environments": {}} for r in rows}
    for c in checks:
        for link in c.get("matrix_rows", []):
            entry = result.get(link["row"])
            if entry is None:
                continue
            entry["checks"].append(c["id"])
            if c.get("requires_environment"):
                # Judged only while that environment stands; said wherever
                # the check is named, so a row is never read as proven daily
                # when it is proven per session.
                entry["environments"][c["id"]] = c["requires_environment"]
            if link["covers"] == "full":
                # A "with" group is checked whole by link_problems; any
                # member's full link stands for the group.
                entry["status"] = "full"
            else:
                entry["gaps"].append(f"{c['id']}: {link['gap']}")
                if entry["status"] == "none":
                    entry["status"] = "partial"
    return result


def report(checks: list[dict], rows: list[dict]) -> str:
    cov = coverage(checks, rows)
    counts = {s: sum(1 for v in cov.values() if v["status"] == s) for s in ("full", "partial", "none")}
    indicators = sorted({r["indicator"] for r in rows})
    touched = sorted({r["indicator"] for r in rows if cov[r["id"]]["status"] != "none"})
    unlinked = [c for c in checks if c.get("unlinked_reason")]

    out = [
        "# Evidence row coverage",
        "",
        "Generated by `sdr/matrix_rows.py` from `docs/KSI-Design-Matrix.xlsx` and `collector/checks/`. "
        "Do not edit by hand; CI fails when this file is stale.",
        "",
        f"**{len(rows)} evidence rows** across {len(indicators)} determinations with VERIFY or VALIDATE "
        f"tables, from {len(checks)} checks:",
        "",
        f"- **{counts['full']} full**: a check, or a named group of checks, proves the row as written.",
        f"- **{counts['partial']} partial**: a check proves part of the row; what is missing is stated.",
        f"- **{counts['none']} none**: no check yet.",
        "",
        f"{len(touched)} of {len(indicators)} determinations have at least one row with automated evidence.",
        f"{sum(1 for v in cov.values() if v['status'] != 'none' and v['environments'] and set(v['environments']) == set(v['checks']))} "
        "of the covered rows rest only on checks of the ephemeral environment, marked \"while ... stands\": "
        "those are judged in sessions when it is applied, not daily.",
        "A row id is positional (`KSI-SVC-SIN.verify.1` is the first VERIFY row under KSI-SVC-SIN); "
        "`docs/matrix-rows.json` holds each id with its row's text.",
        "",
    ]
    if unlinked:
        out += ["## Checks that prove no row", ""]
        out += [f"- `{c['id']}` ({c['indicator']}): {c['unlinked_reason']}" for c in unlinked]
        out.append("")

    for ksi in indicators:
        mine = [r for r in rows if r["indicator"] == ksi]
        done = sum(1 for r in mine if cov[r["id"]]["status"] == "full")
        part = sum(1 for r in mine if cov[r["id"]]["status"] == "partial")
        out += [f"## {ksi}", "", f"{done} full, {part} partial, {len(mine) - done - part} none, of {len(mine)}.", ""]
        out += ["| Row | Type | Artifact | Coverage |", "|---|---|---|---|"]
        for r in mine:
            v = cov[r["id"]]
            cell = {"full": "**full**", "partial": "partial", "none": "—"}[v["status"]]
            if v["checks"]:
                cell += ": " + ", ".join(
                    f"`{c}`" + (f" (while {v['environments'][c]} stands)" if c in v["environments"] else "")
                    for c in v["checks"])
            if v["status"] == "partial":
                cell += ". Missing: " + " ".join(dict.fromkeys(g.split(": ", 1)[1] for g in v["gaps"]))
            artifact, cell = (x.replace("|", "\\|") for x in (r["artifact"], cell))
            out.append(f"| `{r['id'].split('.', 1)[1]}` | {r['type']} | {artifact} | {cell} |")
        out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if a generated file is stale or a link is wrong")
    args = parser.parse_args()

    rows, checks = read_rows(), load_checks()
    problems = link_problems(checks, rows)
    files = {
        SNAPSHOT: json.dumps(rows, indent=2, ensure_ascii=False) + "\n",
        REPORT: report(checks, rows),
    }
    if args.check:
        stale = [p.relative_to(REPO) for p, text in files.items() if not p.exists() or p.read_text() != text]
        problems += [f"{p} is stale; run sdr/matrix_rows.py and review the diff" for p in stale]
        if problems:
            print("matrix links:", *problems, sep="\n  ")
            return 1
        print(f"matrix links: {len(rows)} rows, {len(checks)} checks, all links sound, generated files current")
        return 0
    if problems:
        print("links are wrong; nothing written:", *problems, sep="\n  ")
        return 1
    for path, text in files.items():
        path.write_text(text)
    cov = coverage(checks, rows)
    print(f"wrote {SNAPSHOT.relative_to(REPO)} and {REPORT.relative_to(REPO)}: "
          + ", ".join(f"{sum(1 for v in cov.values() if v['status'] == s)} {s}" for s in ("full", "partial", "none")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
