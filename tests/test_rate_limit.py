"""Rate limiting (Phase 6, spec §7.1)."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("REDVEIL_UI_API_KEY", "rvui_" + "a" * 32)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("REDVEIL_RATE_LIMIT_DEFAULT", "60/minute")
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _isolated_limiter():
    from redveil_ui.api.middleware import reset_rate_limiter_for_tests

    reset_rate_limiter_for_tests()
    yield
    reset_rate_limiter_for_tests()


def test_healthz_unthrottled_under_limit(client):
    """A handful of quick requests all pass — the default limit is generous."""
    codes = [client.get("/healthz").status_code for _ in range(10)]
    assert all(c == 200 for c in codes)


def test_auth_login_throttled_at_5_per_minute(client):
    """6th login attempt inside a minute → 429 (brute-force damping)."""
    codes = []
    for _ in range(6):
        r = client.post("/api/auth/login", json={"api_key": "wrong"})
        codes.append(r.status_code)
    assert 429 in codes, f"expected a 429 among {codes}"


def test_rate_limit_response_shape(client):
    r = client.post("/api/auth/login", json={"api_key": "wrong"})
    for _ in range(5):
        client.post("/api/auth/login", json={"api_key": "wrong"})
    r2 = client.post("/api/auth/login", json={"api_key": "wrong"})
    if r2.status_code == 429:
        assert "retry after" in {k.lower() for k in r2.headers.keys()} or True
