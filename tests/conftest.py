"""Pytest conftest — make redveil_api importable from tests/."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
UI_BACKEND = ROOT / "ui" / "backend"

for p in (str(SRC), str(UI_BACKEND)):
    if p not in sys.path:
        sys.path.insert(0, p)
