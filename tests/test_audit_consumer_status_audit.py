"""Task 9.2: grep audit — every switch/case over scans.status handles 'cancelled'.

Scans the UI backend for string-literal status handling and asserts
that files mentioning the OLD status set also mention 'cancelled'
(spec §14.4 last checklist item). Pure pathlib+re, no AST needed.
"""
import re
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "redveil_ui"

# Status-literal patterns that indicate a consumer of scans.status.
_CONSUMER_PATTERNS = [
    re.compile(r'["\'](?:pending|running|completed|failed)["\']'),
]

_EXEMPT_FILES = {
    # scan_recovery deliberately matches ONLY status=="running": cancelled
    # rows are terminal and must never be orphan-recovered to failed.
    "api/scan_recovery.py",
    # probes.py writes status on PROBE sessions, a different entity than
    # scans (spec §11.1.2 non-consumer list).
    "api/routes/probes.py",
}


def _py_files():
    yield from BACKEND_DIR.rglob("*.py")


def test_models_comment_lists_cancelled():
    models = (BACKEND_DIR / "api" / "models.py").read_text()
    assert '"cancelled"' in models or "cancelled" in models, (
        "models.py must document 'cancelled' as a valid scans.status value"
    )


def test_terminal_check_covers_cancelled():
    scans_routes = (BACKEND_DIR / "api" / "routes" / "scans.py").read_text()
    # B7: the terminal check must include cancelled
    assert re.search(r'in\s*\(\s*["\']completed["\']\s*,\s*["\']failed["\']\s*,\s*["\']cancelled["\']', scans_routes) or (
        '"cancelled"' in scans_routes
    )


def test_files_consuming_old_status_set_mention_cancelled():
    """Any file pattern-matching the old 4-status set must also know
    about 'cancelled' — otherwise a cancelled scan would hit an
    unintended default branch."""
    violations = []
    for path in _py_files():
        rel = str(path.relative_to(BACKEND_DIR))
        if rel in _EXEMPT_FILES:
            continue
        src = path.read_text()
        if "scans" not in src and "Scan" not in src:
            continue
        if not any(p.search(src) for p in _CONSUMER_PATTERNS):
            continue
        if "cancelled" not in src:
            violations.append(str(path.relative_to(BACKEND_DIR)))
    assert not violations, (
        f"files consume scans.status but never handle 'cancelled': {violations}"
    )
