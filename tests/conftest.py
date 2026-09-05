"""Pytest conftest — make redveil_ui.api importable from tests/."""
import os
import sys
from pathlib import Path

# Point the redveil-ui package at the existing data dir BEFORE any
# import that triggers `redveil_ui.api.db` module-load evaluation.
# Tests rely on target_id=1 being seeded in this DB.
_TEST_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
os.environ.setdefault("REDVEIL_DATA_DIR", str(_TEST_DATA_DIR))

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
# `redveil_ui` is the new top-level package (was `ui/backend/redveil_api`).
# `redveil_ui/` must be on sys.path so `from redveil_ui.api.X import Y` works.
REDVEIL_UI_PKG = ROOT / "redveil_ui"

for p in (str(SRC), str(REDVEIL_UI_PKG)):
    if p not in sys.path:
        sys.path.insert(0, p)
