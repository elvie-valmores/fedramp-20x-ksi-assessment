"""Shared types for the collector framework.

380 evidence rows across the 46 indicators reduce to nine evidence
mechanisms (docs/PROJECT-CONTEXT.md's shared-components table). A
CheckDefinition is one evidence row, expressed as data rather than code;
a Mechanism knows how to execute a whole class of them. Build order step
7 adds the remaining ~377 check definitions as more of these; it does
not add more mechanisms.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckDefinition:
    id: str
    indicator: str  # e.g. "KSI-PIY-GIV"
    mechanism: str  # registry key, e.g. "cloud_api_config_read"
    evidence_type: str  # "CFG" (verify) or "OPS" (validate), per the design matrix's own columns
    description: str
    required_cadence: str  # "3 days" or "3 months", per the catalog's cycle
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    check_id: str
    passed: bool
    evidence: dict[str, Any]
    message: str
    ran_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Mechanism(abc.ABC):
    """One of the nine evidence mechanisms. Subclasses implement run()."""

    name: str

    @abc.abstractmethod
    def run(self, check: CheckDefinition) -> CheckResult:
        ...
