"""inventory_reconciliation: confirm the live inventory contains at
least the expected resources of a given type.

Wraps the inventory generator (inventory/aws_source.py,
inventory/gcp_source.py) rather than querying providers directly --
this mechanism's whole point is to check against the inventory GIV
built, not to duplicate what generates it. Once the consolidated
resource register exists, most of this mechanism's real check
definitions will target specific expected resource IDs from that
register rather than a bare minimum count like the examples in
collector/checks/ do today.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "inventory"))

import aws_source  # noqa: E402
import gcp_source  # noqa: E402

from base import CheckDefinition, CheckResult, Mechanism  # noqa: E402


class InventoryReconciliation(Mechanism):
    name = "inventory_reconciliation"

    def run(self, check: CheckDefinition) -> CheckResult:
        provider = check.params["provider"]
        resource_type = check.params["resource_type"]
        min_count = check.params.get("min_count", 1)

        if provider == "aws":
            resources = aws_source.generate(region=check.params.get("region", "us-east-1"))
        elif provider == "gcp":
            resources = gcp_source.generate(
                project_id=check.params.get("project_id", "fedramp-20x-ksi-assessment")
            )
        else:
            raise ValueError(f"unsupported provider {provider!r}")

        matches = [r for r in resources if r["resource_type"] == resource_type]
        passed = len(matches) >= min_count

        evidence = {
            "resource_type": resource_type,
            "matched_count": len(matches),
            "min_count": min_count,
            "matched_ids": [r["resource_id"] for r in matches],
        }
        message = f"found {len(matches)} of type {resource_type} (need >= {min_count})"
        return CheckResult(check.id, passed, evidence, message)
