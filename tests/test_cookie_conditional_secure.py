import pytest
from fastapi.testclient import TestClient

from redveil_ui.api.auth import _cookie_value_for, issue_session_cookie
from redveil_ui.api.middleware import reset_rate_limiter_for_tests

API_KEY = "rvui_" + "a" * 32


@pytest.fixture(autouse=True)
def _isolated_limiter():
    """The shared limiter is module-global; tests that hit /api/auth/login
    must not inherit buckets from other test files (login: 5/min/IP)."""
    reset_rate_limiter_for_tests()
    yield
    reset_rate_limiter_for_tests()


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("REDVEIL_UI_API_KEY", API_KEY)
    monkeypatch.setenv("HOME", str(tmp_path))
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


def test_login_returns_cookie_with_https_flag_on_https(client):
    """HTTPS request -> Set-Cookie includes Secure flag."""
    response = client.post(
        "/api/auth/login",
        json={"api_key": API_KEY},
        headers={"X-Forwarded-Proto": "https"},
    )
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    assert "Secure" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=strict" in set_cookie.lower()


def test_login_omits_secure_flag_on_http(client):
    """HTTP request -> Set-Cookie does NOT include Secure flag."""
    response = client.post(
        "/api/auth/login",
        json={"api_key": API_KEY},
        headers={"X-Forwarded-Proto": "http"},
    )
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    assert "Secure" not in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=strict" in set_cookie.lower()


def test_login_with_valid_key_accepted_on_default_headers(client):
    """Plain TestClient (no X-Forwarded-Proto) -> 200, cookie set, no Secure."""
    response = client.post("/api/auth/login", json={"api_key": API_KEY})
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    assert "Secure" not in set_cookie
    issued = response.cookies.get("redveil_session")
    assert issued is not None
    # The issued cookie must validate against the API key
    from redveil_ui.api.auth import validate_session_cookie

    assert validate_session_cookie(issued, API_KEY) is True


def test_login_with_invalid_key_returns_401(client):
    response = client.post("/api/auth/login", json={"api_key": "wrong"})
    assert response.status_code == 401


def test_login_with_x_api_key_header_key_succeeds(client):
    """Login also works by supplying the raw key via X-API-Key (CLI flow)."""
    response = client.post(
        "/api/auth/login",
        content=b"",
        headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
    )
    assert response.status_code == 200


def test_logout_clears_cookie(client):
    response = client.post("/api/auth/logout")
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    assert "redveil_session=" in set_cookie
    # Cookie should be expired (Max-Age=0 or expires in past)
    assert "Max-Age=0" in set_cookie or "expires=" in set_cookie.lower()
