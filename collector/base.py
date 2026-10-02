"""The two data types and one interface the collector framework is built on.

A CheckDefinition is a single piece of evidence to gather, written as
data (a JSON file in checks/) rather than as code. A Mechanism is the
code that knows how to gather a whole category of them.

The split matters because the assessment needs roughly 380 pieces of
evidence, and they reduce to only nine ways of gathering evidence. Adding
evidence means adding a JSON file. Adding a *new way* of gathering it --
rare -- means adding a Mechanism.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckDefinition:
    """One piece of evidence to gather. Loaded from a JSON file."""

    id: str
    indicator: str  # which requirement this is evidence for, e.g. "KSI-PIY-GIV"
    mechanism: str  # which Mechanism runs it; a key in registry.MECHANISMS
    evidence_type: str  # "CFG" proves a thing is configured; "OPS" proves it works
    description: str
    required_cadence: str  # how often the framework requires this be re-checked
    params: dict[str, Any] = field(default_factory=dict)  # mechanism-specific inputs
    # The design matrix's evidence rows this check proves, fully or in part,
    # e.g. {"row": "KSI-SVC-SIN.verify.2", "covers": "partial", "gap": "..."}.
    # A check that proves no row says why in unlinked_reason instead. Both
    # are validated by sdr/matrix_rows.py (DECISIONS.md, 2026-10-02).
    matrix_rows: list[dict[str, Any]] = field(default_factory=list)
    unlinked_reason: str = ""


@dataclass
class CheckResult:
    """The outcome of running one CheckDefinition."""

    check_id: str
    passed: bool
    evidence: dict[str, Any]  # the raw data the verdict was based on
    message: str  # one line, human-readable
    ran_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Mechanism(abc.ABC):
    """One way of gathering evidence. Subclasses implement run()."""

    name: str

    @abc.abstractmethod
    def run(self, check: CheckDefinition) -> CheckResult:
        ...
