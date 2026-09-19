"""Makes the sibling `inventory/` package importable from `collector/`.

The two are separate top-level directories rather than one installed
package, so Python does not find one from the other by default. Importing
this module once puts `inventory/` on the import path.

Any collector module that imports from inventory should `import _paths`
first. It is safe to import repeatedly -- the path is only added once.
"""

from __future__ import annotations

import sys
from pathlib import Path

INVENTORY_DIR = Path(__file__).resolve().parents[1] / "inventory"

if str(INVENTORY_DIR) not in sys.path:
    sys.path.insert(0, str(INVENTORY_DIR))
