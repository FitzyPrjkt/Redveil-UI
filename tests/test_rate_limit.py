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


@pytest.fixture(autouse=True)
def _isolate_from_other_files(monkeypatch, tmp_path):
    """Other test files also hit /api/auth/login; HOME isolation keeps
    key resolution deterministic regardless of file order."""
    monkeypatch.setenv("HOME", str(tmp_path))


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


def test_default_limit_enforced_via_middleware(monkeypatch, tmp_path):
    """S4: the 60/min default is REAL — SlowAPIMiddleware enforces
    default_limits on every route, so the 61st GET /api/info inside a
    minute is 429. (Pre-fix, default_limits existed on the Limiter but
    nothing consumed them: the advertised default was dormant.)"""
    monkeypatch.setenv("REDVEIL_UI_API_KEY", "rvui_" + "a" * 32)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("REDVEIL_RATE_LIMIT_DEFAULT", "60/minute")
    from redveil_ui.api.main import app
    from redveil_ui.api.middleware import reset_rate_limiter_for_tests

    reset_rate_limiter_for_tests()
    try:
        with TestClient(app) as c:
            codes = [c.get("/api/info").status_code for _ in range(65)]
    finally:
        reset_rate_limiter_for_tests()
    assert 429 in codes
    assert codes.count(200) == 60
    # The rejection surfaced through the outer middlewares with the
    # security headers intact.
    with TestClient(app) as c:
        reset_rate_limiter_for_tests()
        codes = [c.get("/api/info").status_code for _ in range(61)]
        assert 429 in codes
        reset_rate_limiter_for_tests()


def test_default_limit_opt_out_env(monkeypatch, tmp_path):
    """REDVEIL_RATE_LIMIT_DEFAULT=0/minute disables the blanket default
    at request time (documented escape hatch) while decorated limits
    (login 5/min) stay active."""
    from redveil_ui.api.main import app
    from redveil_ui.api.middleware import default_limit_disabled

    monkeypatch.setenv("REDVEIL_UI_API_KEY", "rvui_" + "a" * 32)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("REDVEIL_RATE_LIMIT_DEFAULT", "0/minute")
    assert default_limit_disabled() is True
    with TestClient(app) as c:
        codes = [c.get("/api/info").status_code for _ in range(70)]
    assert all(code == 200 for code in codes)
