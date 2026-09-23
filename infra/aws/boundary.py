#!/usr/bin/env python3
"""The persistence boundary, derived once and consumed by two callers.

Ten files hold everything that survives a teardown. Everything else is the
application environment, rebuilt on the next apply:

    log_corpus.tf         the Object Locked store, Athena, Glue
    log_normalization.tf  the OCSF normalization Lambda
    detection.tf          the detection query Lambda and its alarms
    inventory.tf          CloudTrail and the Config recorder
    billing.tf            the budget guardrail
    pipeline_identity.tf  the OIDC provider and the drift role
    registry.tf           the container registry and the extract bucket
    artifacts_key.tf      the key both of those encrypt with
    pipeline.tf           the build role
    cross_cloud.tf        the role the GCP pipeline assumes

pipeline_identity.tf is not about cost -- an OIDC provider and IAM roles are
free. It is there because the drift check runs while the application
environment is down, so the identity that runs it cannot go down with it. A
correct plan executed by a principal that does not exist is still no signal.

The registry persists so that images survive a teardown -- otherwise every
session that wants to deploy must first run a full build. It was also meant to
give the vulnerability scanner something to look at between sessions, but the
scanner is declared in posture.tf, which is ephemeral, so for now that part
of the reason does not hold (DECISIONS.md, 2026-09-23). The artifacts key
follows because both stores encrypt with it.

In each case the *store* persists and the *grants to transient principals* do
not: registry_grants.tf holds the policies naming roles from compute.tf, and
the artifacts key authorises those roles through their own IAM policies rather
than through its key policy. See DECISIONS.md, 2026-09-22.

pipeline.tf and cross_cloud.tf joined them on 2026-09-23, once the registry and
the artifacts key persisted and neither file had an ephemeral dependency left.
Both are IAM-only and cost nothing. The point is that the build role no longer
dies with the environment, so CI can run against a torn-down one -- which is
what it needs to do, since its whole job is producing the images the
environment is waiting for.

Two consumers, opposite halves:

    teardown.sh   --ephemeral   what to destroy between sessions
    drift.yml     --persistent  what to check for drift while it is down

They must agree. A boundary implemented twice is a boundary that diverges,
and the two failure modes are silent in opposite directions: a resource the
teardown forgets bills forever, and a resource the drift check forgets stops
being watched. Deriving both halves from one declaration is what stops that.

The mapping is from state address back to the .tf file that declares it, not
from a written list. A written list rots -- a resource added to compute.tf
later would silently survive every teardown, and nothing would report it.
Deriving means a new resource is ephemeral by default, and only a deliberate
placement in one of the named files exempts it.

Relies on one property, verified 2026-09-22 and worth re-checking before
moving a resource between files: nothing in the persistent files
references a resource declared outside them. `terraform plan -target` pulls
in dependencies, so if that stopped holding, --persistent would quietly drag
application resources into the drift plan.
"""

import argparse
import glob
import os
import re
import subprocess
import sys

PERSISTENT_FILES = {
    "pipeline_identity.tf",
    "registry.tf",
    "artifacts_key.tf",
    "pipeline.tf",
    "cross_cloud.tf",
    "log_corpus.tf",
    "log_normalization.tf",
    "detection.tf",
    "inventory.tf",
    "billing.tf",
}


def declaring_files():
    """Map (resource type, name) -> the .tf file declaring it."""
    declared = {}
    for path in glob.glob("*.tf"):
        with open(path) as handle:
            source = handle.read()
        for match in re.finditer(r'^resource\s+"([^"]+)"\s+"([^"]+)"', source, re.M):
            declared[(match.group(1), match.group(2))] = path
    return declared


def state_addresses():
    result = subprocess.run(
        ["terraform", "state", "list"], capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.exit(f"terraform state list failed:\n{result.stderr}")
    return result.stdout.split()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--persistent", action="store_true", help="what survives a teardown")
    group.add_argument("--ephemeral", action="store_true", help="what a teardown removes")
    group.add_argument(
        "--files",
        action="store_true",
        help="list the files that define the persistent side, and stop",
    )
    parser.add_argument(
        "--target-flags",
        action="store_true",
        help="emit as -target=ADDR lines rather than bare addresses",
    )
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Callers display this; nobody should keep a second copy of the list.
    if args.files:
        print(" ".join(sorted(PERSISTENT_FILES)))
        return

    declared = declaring_files()
    selected, unmapped = [], []

    for address in state_addresses():
        # Data sources are not managed, so neither half applies to them.
        if address.startswith("data."):
            continue
        match = re.match(r"^([a-z0-9_]+)\.([A-Za-z0-9_-]+)", address)
        path = declared.get((match.group(1), match.group(2))) if match else None
        if path is None:
            unmapped.append(address)
        elif (path in PERSISTENT_FILES) == bool(args.persistent):
            selected.append(address)

    # A resource in state that no .tf declares is drift, an orphan, or a
    # rename mid-flight. Guessing which is not this script's job: destroying
    # it could be wrong and ignoring it could be worse, so stop and let a
    # human look.
    if unmapped:
        sys.exit(
            "unmapped resources in state, refusing to guess:\n  "
            + "\n  ".join(unmapped)
        )

    prefix = "-target=" if args.target_flags else ""
    for address in selected:
        print(f"{prefix}{address}")


if __name__ == "__main__":
    main()
