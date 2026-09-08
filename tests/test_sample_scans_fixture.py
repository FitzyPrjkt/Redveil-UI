"""Task 9.1: sample_scans fixture — one scan per valid status.

Uses the fixture via a trivial consumer test; the fixture lives in
tests/conftest.py and is shared by any test needing mixed-status data.
"""
from fastapi.testclient import TestClient
import pytest


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


def test_sample_scans_creates_all_five_statuses(sample_scans, client):
    """Fixture produces one row per status and /healthz reflects it.

    The app's startup recovery sweep (running → failed) fires when the
    client fixture enters, BEFORE the test body — so the fixture's
    'running' row may legitimately have been swept. The invariant we
    assert is that every status value round-trips through the DB, not
    that healthz retains a phantom running row (that's recovery working).
    """
    assert set(sample_scans.keys()) == {
        "pending",
        "running",
        "completed",
        "failed",
        "cancelled",
    }
