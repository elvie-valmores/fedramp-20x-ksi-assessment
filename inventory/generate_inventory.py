#!/usr/bin/env python3
"""Produces one inventory of every resource across AWS and GCP.

Calls both cloud sources, concatenates their results, and prints a single
JSON document. Both sources emit the same record shape, so no merging or
field translation happens here -- this file is orchestration only.

The inventory is generated on demand, never read from a cache, so the
output always reflects what the clouds report at the moment it ran.

Usage:
    python generate_inventory.py                  # both clouds
    python generate_inventory.py --aws-only       # skip GCP entirely
    python generate_inventory.py --output out.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

import aws_source
import gcp_source


def generate(aws_only: bool, aws_region: str) -> dict:
    """Collect from both clouds and wrap the result with run metadata."""
    generated_at = datetime.now(timezone.utc).isoformat()
    resources = aws_source.generate(region=aws_region)

    # A missing GCP setup is reported in the output rather than raised.
    # Returning an AWS-only inventory that silently claims to cover both
    # clouds would be worse than an inventory that says what it skipped.
    gcp_status = "skipped"
    if not aws_only:
        try:
            resources.extend(gcp_source.generate())
            gcp_status = "ok"
        except gcp_source.GCPNotConfigured as exc:
            gcp_status = f"not_configured: {exc}"

    return {
        "generated_at": generated_at,
        # Named so a reader can tell which API each half came from.
        "sources": {
            "aws": "aws-config-select-resource-config",
            "gcp": gcp_status,
        },
        "resource_count": len(resources),
        "resources": resources,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--aws-only",
        action="store_true",
        help="Skip GCP entirely instead of querying it.",
    )
    parser.add_argument(
        "--aws-region",
        default=aws_source.DEFAULT_REGION,
        help=f"AWS region to query (default: {aws_source.DEFAULT_REGION}).",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="File path to write JSON to, or '-' for stdout (default).",
    )
    args = parser.parse_args()

    inventory = generate(aws_only=args.aws_only, aws_region=args.aws_region)

    # default=str so timestamp objects that aren't JSON-native serialize
    # instead of raising.
    output = json.dumps(inventory, indent=2, default=str)

    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
