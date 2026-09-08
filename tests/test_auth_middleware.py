import time

import pytest
from fastapi.testclient import TestClient

from redveil_ui.api.auth import SESSION_TTL_SECONDS, _cookie_value_for, issue_session_cookie

API_KEY = "rvui_" + "a" * 32


@pytest.fixture
def client_with_key(monkeypatch, tmp_path):
    monkeypatch.setenv("REDVEIL_UI_API_KEY", API_KEY)
    monkeypatch.setenv("HOME", str(tmp_path))  # no .api_key file
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


def test_loopback_request_does_not_require_auth(client_with_key):
    """127.0.0.1 origin bypasses auth entirely."""
    response = client_with_key.get(
        "/api/info", headers={"X-Forwarded-For": "127.0.0.1"}
    )
    assert response.status_code != 401


def test_lan_request_without_auth_returns_401_on_destructive(client_with_key):
    """Non-loopback client, no auth, destructive scan create -> 401."""
    response = client_with_key.post(
        "/api/scans",
        json={
            "target_id": 1,
            "profile": "active",
            "max_destructive_level": "L3",
            "allow_destructive": True,
        },
        headers={"X-Forwarded-For": "192.168.1.50"},
    )
    assert response.status_code == 401


def test_lan_request_with_valid_header_auth_passes(client_with_key):
    """X-API-Key header authenticates a non-loopback request."""
    response = client_with_key.post(
        "/api/scans",
        json={
            "target_id": 1,
            "profile": "active",
            "max_destructive_level": "L3",
            "allow_destructive": True,
        },
        headers={
            "X-Forwarded-For": "192.168.1.50",
            "X-API-Key": API_KEY,
        },
    )
    assert response.status_code != 401


def test_lan_request_with_valid_cookie_passes(client_with_key):
    """Cookie with valid HMAC authenticates a non-loopback request."""
    cookie_value, _ = issue_session_cookie(API_KEY)
    response = client_with_key.post(
        "/api/scans",
        json={
            "target_id": 1,
            "profile": "active",
            "max_destructive_level": "L3",
            "allow_destructive": True,
        },
        headers={
            "X-Forwarded-For": "192.168.1.50",
            "Cookie": f"redveil_session={cookie_value}",
        },
    )
    assert response.status_code != 401


def test_expired_cookie_rejected(client_with_key):
    """Cookie issued more than SESSION_TTL_SECONDS ago -> 401."""
    long_ago = int(time.time()) - SESSION_TTL_SECONDS - 60
    expired = _cookie_value_for(API_KEY, long_ago)
    response = client_with_key.post(
        "/api/scans",
        json={"target_id": 1, "profile": "active"},
        headers={
            "X-Forwarded-For": "192.168.1.50",
            "Cookie": f"redveil_session={expired}",
        },
    )
    assert response.status_code == 401
