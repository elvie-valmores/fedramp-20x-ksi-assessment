"""Mechanism: check the live inventory contains the resources it should.

Used for evidence of the form "everything we expect to exist is
accounted for." Calls the inventory generator rather than querying the
clouds directly -- the point is to test what the inventory reports, so
re-querying the providers here would be testing something else.

Check params:
    provider       "aws" or "gcp"
    resource_type  the type to count, e.g. "AWS::S3::Bucket"
    min_count      how many must be present (default 1)
    region         required when provider is "aws"
    project_id     required when provider is "gcp"

The min_count form is a placeholder. Once the project has a register of
expected resources, these checks will assert on specific resource IDs
instead of a floor count.
"""

from __future__ import annotations

import _paths  # noqa: F401  (puts inventory/ on the import path)
import aws_source
import gcp_source
from base import CheckDefinition, CheckResult, Mechanism


class InventoryReconciliation(Mechanism):
    name = "inventory_reconciliation"

    def run(self, check: CheckDefinition) -> CheckResult:
        provider = check.params["provider"]
        resource_type = check.params["resource_type"]
        min_count = check.params.get("min_count", 1)

        if provider == "aws":
            resources = aws_source.generate(region=check.params["region"])
        elif provider == "gcp":
            resources = gcp_source.generate(project_id=check.params["project_id"])
        else:
            raise ValueError(f"unsupported provider {provider!r}")

        matches = [r for r in resources if r["resource_type"] == resource_type]

        evidence = {
            "resource_type": resource_type,
            "matched_count": len(matches),
            "min_count": min_count,
            # The IDs themselves are the evidence -- a count alone can't
            # be audited back to specific resources.
            "matched_ids": [r["resource_id"] for r in matches],
        }
        return CheckResult(
            check.id,
            len(matches) >= min_count,
            evidence,
            f"found {len(matches)} of type {resource_type} (need >= {min_count})",
        )
