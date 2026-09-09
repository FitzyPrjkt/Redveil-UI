"""Route-level auth gates (S3 review fix).

POST /api/probes/custom and DELETE /api/targets/{id} are destructive
regardless of the request body, so they must require authentication on
LAN — an unauthenticated non-loopback request gets 401 BEFORE any
scope/DWYOR/target handling. Loopback requests are unaffected
(AuthMiddleware short-circuits is_authenticated=True there).
"""
import pytest
from fastapi.testclient import TestClient

API_KEY = "rvui_" + "a" * 32
LAN_XFF = {"X-Forwarded-For": "192.168.1.50"}


@pytest.fixture
def app_with_key(monkeypatch, tmp_path):
    monkeypatch.setenv("REDVEIL_UI_API_KEY", API_KEY)
    monkeypatch.setenv("HOME", str(tmp_path))
    from redveil_ui.api.main import app

    return app


def _lan_client(app):
    """Direct peer is a LAN IP: destructive gates must 401 without auth."""
    return TestClient(app, client=("192.168.1.50", 51000))


def _loopback_client(app):
    """Direct peer is loopback: gates are short-circuited by middleware."""
    return TestClient(app, client=("127.0.0.1", 51000))


def test_delete_target_unauthenticated_lan_401(app_with_key):
    """Unauthenticated LAN request -> 401 before the target lookup."""
    with _lan_client(app_with_key) as c:
        resp = c.delete("/api/targets/999999")
    assert resp.status_code == 401


def test_delete_target_with_header_key_passes_auth_layer(app_with_key):
    """With a valid X-API-Key the gate passes; the request reaches the
    route and 404s on the unknown target id."""
    with _lan_client(app_with_key) as c:
        resp = c.delete(
            "/api/targets/999999", headers={"X-API-Key": API_KEY}
        )
    assert resp.status_code == 404


def test_delete_target_loopback_unaffected(app_with_key):
    """Loopback direct peer keeps working — no auth needed."""
    with _loopback_client(app_with_key) as c:
        resp = c.delete("/api/targets/999999")
    assert resp.status_code == 404


def test_post_probes_custom_unauthenticated_lan_401(app_with_key):
    """Unauthenticated LAN request -> 401 even with confirmed_dwyor=true
    (the DWYOR flag must not substitute for authentication)."""
    with _lan_client(app_with_key) as c:
        resp = c.post(
            "/api/probes/custom",
            json={
                "target_id": 999999,
                "payloads": ["x"],
                "method": "GET",
                "position": "q",
                "position_kind": "query",
                "confirmed_dwyor": True,
            },
        )
    assert resp.status_code == 401


def test_post_probes_custom_loopback_unaffected(app_with_key):
    """Loopback DWYOR'd probe against a missing target -> 404 (not 401):
    the gate short-circuits only for non-authenticated LAN callers."""
    with _loopback_client(app_with_key) as c:
        resp = c.post(
            "/api/probes/custom",
            json={
                "target_id": 999999,
                "payloads": ["x"],
                "method": "GET",
                "position": "q",
                "position_kind": "query",
                "confirmed_dwyor": True,
            },
        )
    assert resp.status_code == 404


def test_post_probes_custom_lan_with_header_key_reaches_route(app_with_key):
    with _lan_client(app_with_key) as c:
        resp = c.post(
            "/api/probes/custom",
            json={
                "target_id": 999999,
                "payloads": ["x"],
                "method": "GET",
                "position": "q",
                "position_kind": "query",
                "confirmed_dwyor": True,
            },
            headers={"X-API-Key": API_KEY},
        )
    assert resp.status_code == 404
