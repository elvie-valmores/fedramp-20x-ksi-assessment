#!/usr/bin/env python3
"""KSI-PIY-GIV, build item 3: the inventory generator.

Single command producing a normalized inventory across both clouds at
query time. No cached intermediate — every run queries the authoritative
provider services (AWS Config, GCP Cloud Asset Inventory) live. See
docs/KSI-Design-Matrix.xlsx, PIY tab, KSI-PIY-GIV for the full design
rationale and docs/PROJECT-CONTEXT.md for how this fits the rest of the
build.

Usage:
    python generate_inventory.py                 # both clouds
    python generate_inventory.py --aws-only       # GCP not set up yet
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
    generated_at = datetime.now(timezone.utc).isoformat()
    resources = aws_source.generate(region=aws_region)

    gcp_status = "skipped"
    if not aws_only:
        try:
            resources.extend(gcp_source.generate())
            gcp_status = "ok"
        except gcp_source.GCPNotConfigured as exc:
            gcp_status = f"not_configured: {exc}"

    return {
        "generated_at": generated_at,
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
        help="Skip GCP entirely instead of recording it as not_configured.",
    )
    parser.add_argument("--aws-region", default="us-east-1")
    parser.add_argument(
        "--output",
        default="-",
        help="File path to write JSON to, or '-' for stdout (default).",
    )
    args = parser.parse_args()

    inventory = generate(aws_only=args.aws_only, aws_region=args.aws_region)
    output = json.dumps(inventory, indent=2, default=str)

    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
