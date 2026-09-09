"""audit_log: destructive action entries written by AuditLogMiddleware."""
import asyncio

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Direct ASGI peer is loopback: audit entries for allowed/denied
    outcomes are written regardless, and destructive routes stay open
    for loopback (the LAN 401 gate itself is covered in
    test_route_gates.py)."""
    from redveil_ui.api.main import app

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        yield c


def _audit_rows():
    from sqlalchemy import select

    from redveil_ui.api.db import get_session_factory
    from redveil_ui.api.models import AuditLog

    async def _get():
        factory = get_session_factory()
        async with factory() as s:
            rows = list((await s.execute(select(AuditLog))).scalars().all())
            return rows

    return asyncio.run(_get())


def test_destructive_scan_create_writes_audit_entry(client):
    """Loopback POST /api/scans with a destructive body → audited.

    The seeded target's own URL fails the scope check (its scope_yaml
    allows /api/* etc. but the bare URL path is '/'), so the route
    answers 403 — the request WAS authorized (loopback) but refused on
    its merits, which the middleware records as result='denied' with
    the route's detail string (401/403 = denied is the standing
    semantic; 404 = not_found; everything else = allowed).
    """
    resp = client.post(
        "/api/scans",
        json={"target_id": 1, "profile": "active", "allow_destructive": True},
    )
    assert resp.status_code == 403  # scope violation, not auth
    rows = [r for r in _audit_rows() if r.action == "scan.create"]
    assert len(rows) >= 1
    row = rows[-1]
    assert row.result == "denied"
    assert "scope violation" in (row.deny_reason or "")
    assert row.actor in ("loopback", "anonymous") or row.actor.startswith("key:")
    assert row.ts is not None


def test_audit_denied_outcome_on_auth_failure():
    """Unauthenticated LAN destructive create → 401 → result='denied'
    with the gate's detail string as deny_reason."""
    import os

    from redveil_ui.api.main import app

    api_key = "rvui_" + "b" * 32
    os.environ["REDVEIL_UI_API_KEY"] = api_key
    try:
        with TestClient(app, client=("192.168.1.50", 51000)) as c:
            resp = c.post(
                "/api/scans",
                json={"target_id": 1, "profile": "active", "allow_destructive": True},
            )
            assert resp.status_code == 401
            rows = [r for r in _audit_rows() if r.action == "scan.create"]
    finally:
        os.environ.pop("REDVEIL_UI_API_KEY", None)
    assert rows
    row = rows[-1]
    assert row.result == "denied"
    assert "Authentication required" in (row.deny_reason or "")


def test_audit_not_found_outcome(client):
    """404 on an audited action path → result='not_found': the action
    targeted a missing resource — not allowed, not auth-denied."""
    client.post("/api/scans/999999/cancel")
    rows = [r for r in _audit_rows() if r.action == "scan.cancel"]
    assert len(rows) >= 1
    row = rows[-1]
    assert row.result == "not_found"
    assert row.deny_reason == "scan not found"


def test_audit_request_meta_carries_no_auth_material(client):
    """request_meta has client_ip/path/user_agent — never keys or cookies."""
    client.post(
        "/api/scans",
        json={"target_id": 1, "profile": "active", "allow_destructive": True},
    )
    rows = [r for r in _audit_rows() if r.action == "scan.create"]
    assert rows
    import json

    meta = json.loads(rows[-1].request_meta)
    assert set(meta.keys()) == {"client_ip", "user_agent", "request_path"}


def test_probe_custom_audit_even_when_denied(client):
    """probe.custom is audited with result=denied when DWYOR missing (403)."""
    client.post(
        "/api/probes/custom",
        json={"target_id": 1, "payloads": ["x"], "method": "GET",
              "position": "q", "position_kind": "query", "confirmed_dwyor": False},
    )
    rows = [r for r in _audit_rows() if r.action == "probe.custom"]
    assert len(rows) >= 1
    assert rows[-1].result == "denied"
    assert rows[-1].deny_reason is not None


def test_cancel_writes_audit_entry(client):
    """POST /api/scans/{id}/cancel is audited (spec §7.2 scan.cancel)."""
    client.post("/api/scans/999999/cancel")  # 404 — still shouldn't audit non-action? spec: audit the action
    # 404 means no operator action was possible; middleware audits only when it routed to /cancel.
    # We assert the row exists because the ENDPOINT was addressed (attempt is audit-worthy).
    rows = [r for r in _audit_rows() if r.action == "scan.cancel"]
    assert len(rows) >= 1
