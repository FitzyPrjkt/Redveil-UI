"""S5 regression: POST /api/scans/{id}/start must apply the destructive
classification gate (0.2.0 review item 5b).

The gate reads the persisted scan row's profile / max_destructive_level
/ allow_destructive — the same classification create_scan applies to
its request body — and 401s unauthenticated non-loopback callers before
dispatching the scan. The detail string matches create_scan's.

Also covers review item 13: start dispatch returns 202 (spec §5.5).
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

API_KEY = "rvui_" + "a" * 32


@pytest.fixture
def client():
    """Direct peer is a LAN IP (192.168.1.50) — the realistic LAN case."""
    from redveil_ui.api.main import app

    with TestClient(app, client=("192.168.1.50", 51000)) as c:
        yield c


@pytest.fixture
def client_with_key(monkeypatch, tmp_path):
    monkeypatch.setenv("REDVEIL_UI_API_KEY", API_KEY)
    monkeypatch.setenv("HOME", str(tmp_path))
    from redveil_ui.api.main import app

    with TestClient(app, client=("192.168.1.50", 51000)) as c:
        yield c


def _mk_scan(status: str, **fields) -> int:
    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import Scan

    async def _make() -> int:
        factory = get_session_factory()
        async with factory() as s:
            scan = Scan(target_id=1, status=status, **fields)
            s.add(scan)
            await s.commit()
            await s.refresh(scan)
            return scan.id

    return asyncio.run(_make())


def test_start_destructive_unauthenticated_lan_401(client):
    """Pending scan persisted as destructive (active profile, L3,
    allow_destructive) -> /start without auth on LAN -> 401."""
    scan_id = _mk_scan(
        "pending",
        profile="active",
        max_destructive_level="L3",
        allow_destructive=True,
    )
    resp = client.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code == 401
    assert resp.json()["detail"] == (
        "Authentication required for destructive scan operations on LAN"
    )


def test_start_destructive_l3_only_unauthenticated_lan_401(client):
    """A pending scan that is destructive ONLY via its persisted
    max_destructive_level is gated too."""
    scan_id = _mk_scan("pending", max_destructive_level="L4")
    resp = client.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code == 401


def test_start_passive_unauthenticated_lan_passes_gate(client):
    """A passive scan row is NOT destructive: /start passes the gate and
    reaches the scanner (404 target here) without authentication."""
    scan_id = _mk_scan(
        "pending",
        profile="passive",
    )
    resp = client.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code != 401


def test_start_destructive_authenticated_dispatches_202(client_with_key):
    """Authenticated destructive /start -> 202 Accepted (spec §5.5)."""
    scan_id = _mk_scan(
        "pending",
        profile="active",
        max_destructive_level="L3",
        allow_destructive=True,
    )
    resp = client_with_key.post(
        f"/api/scans/{scan_id}/start", headers={"X-API-Key": API_KEY}
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "running"
    assert body["scan_id"] == scan_id


def test_start_loopback_destructive_unaffected():
    """Loopback short-circuit: destructive /start needs no auth.
    The TestClient fakes a loopback direct peer via client=."""
    scan_id = _mk_scan(
        "pending",
        profile="active",
        max_destructive_level="L3",
    )
    from redveil_ui.api.main import app as _app

    with TestClient(_app, client=("127.0.0.1", 51000)) as c:
        resp = c.post(f"/api/scans/{scan_id}/start")
    assert resp.status_code != 401
