#!/usr/bin/env python3
"""Compares the pinned schemas against FedRAMP's published copies.

The filenames are dated and do not change when the content does, so the
only way to learn that FedRAMP revised a schema is to fetch it and compare.
Exits 1 on any difference in hash or $schemaVersion, naming which.

    cd sdr && ../.venv/bin/python verify_pins.py
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request

from emit import SCHEMAS

UPSTREAM = "https://raw.githubusercontent.com/FedRAMP/schemas/main/"


def main() -> int:
    drifted = []
    for name, version, digest in SCHEMAS.values():
        with urllib.request.urlopen(UPSTREAM + name, timeout=30) as response:
            raw = response.read()
        actual = hashlib.sha256(raw).hexdigest()
        upstream_version = json.loads(raw).get("$schemaVersion")
        same = actual == digest and upstream_version == version
        print(f"{'ok     ' if same else 'DRIFTED'} {name}: upstream {upstream_version} {actual[:12]}…, "
              f"pinned {version} {digest[:12]}…")
        if not same:
            drifted.append(name)
    return 1 if drifted else 0


if __name__ == "__main__":
    sys.exit(main())
