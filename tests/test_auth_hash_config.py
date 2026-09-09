"""S2 regression: hash-only auth config must be able to authenticate.

0.2.0 review finding: `auth.api_key_hash` was accepted by the
fail-closed startup check but could never authenticate a request —
login required a resolvable raw key and the middleware had no
hash-validation path. With REDVEIL_UI_API_KEY unset and no .api_key
file, a config carrying only auth.api_key_hash must still allow:

- POST /api/auth/login with the correct raw key -> 200
- POST /api/auth/login with a wrong key -> 401
- X-API-Key header authenticates destructive requests (hash-only)
- unauthenticated destructive requests stay 401 (fail-closed)
"""
import hashlib

import pytest
from fastapi.testclient import TestClient

from redveil_ui.api.middleware import reset_rate_limiter_for_tests

API_KEY = "rvui_" + "c" * 32


@pytest.fixture(autouse=True)
def _isolated_limiter():
    """Login is throttled 5/min/IP; clear shared buckets between tests."""
    reset_rate_limiter_for_tests()
    yield
    reset_rate_limiter_for_tests()


@pytest.fixture
def hash_only_client(monkeypatch, tmp_path):
    """No raw key anywhere — config.yaml carries only the sha256 hash."""
    monkeypatch.delenv("REDVEIL_UI_API_KEY", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "host: 0.0.0.0\n"
        "auth:\n"
        f"  api_key_hash: sha256:{hashlib.sha256(API_KEY.encode()).hexdigest()}\n"
    )
    monkeypatch.setenv("REDVEIL_CONFIG", str(config_path))
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


def test_hash_only_login_correct_key_returns_200(hash_only_client):
    resp = hash_only_client.post("/api/auth/login", json={"api_key": API_KEY})
    assert resp.status_code == 200


def test_hash_only_login_wrong_key_returns_401(hash_only_client):
    resp = hash_only_client.post(
        "/api/auth/login", json={"api_key": "rvui_" + "d" * 32}
    )
    assert resp.status_code == 401


def test_hash_only_header_key_authenticates_destructive(hash_only_client):
    """X-API-Key validates against the stored hash; the request passes
    the destructive gate and reaches the target lookup (404)."""
    resp = hash_only_client.post(
        "/api/scans",
        json={"target_id": 999999, "profile": "active", "allow_destructive": True},
        headers={"X-API-Key": API_KEY, "X-Forwarded-For": "192.168.1.50"},
    )
    assert resp.status_code != 401
    assert resp.status_code == 404  # auth passed; target lookup ran


def test_hash_only_unauthenticated_destructive_is_401(hash_only_client):
    resp = hash_only_client.post(
        "/api/scans",
        json={"target_id": 999999, "profile": "active", "allow_destructive": True},
        headers={"X-Forwarded-For": "192.168.1.50"},
    )
    assert resp.status_code == 401


def test_key_matches_config_hash_unit(monkeypatch, tmp_path):
    """Unit: _key_matches_config_hash validates the raw key, honors
    REDVEIL_CONFIG, tolerates the sha256: prefix, rejects wrong keys."""
    from redveil_ui.api.auth import _key_matches_config_hash

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "auth:\n"
        f"  api_key_hash: {hashlib.sha256(API_KEY.encode()).hexdigest()}\n"
    )
    monkeypatch.setenv("REDVEIL_CONFIG", str(config_path))
    assert _key_matches_config_hash(API_KEY) is True
    assert _key_matches_config_hash("rvui_" + "e" * 32) is False
    assert _key_matches_config_hash("") is False

    monkeypatch.setenv("REDVEIL_CONFIG", str(tmp_path / "missing.yaml"))
    assert _key_matches_config_hash(API_KEY) is False


def test_has_config_hash_honors_redveil_config(monkeypatch, tmp_path):
    """_has_config_hash must look at the SAME file routes/config.py and
    server.py look at (REDVEIL_CONFIG), not only ~/.redveil-ui."""
    from redveil_ui.api.auth import _has_config_hash

    monkeypatch.delenv("REDVEIL_UI_API_KEY", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "auth:\n"
        f"  api_key_hash: sha256:{hashlib.sha256(API_KEY.encode()).hexdigest()}\n"
    )
    monkeypatch.setenv("REDVEIL_CONFIG", str(config_path))
    assert _has_config_hash() is True

    monkeypatch.setenv("REDVEIL_CONFIG", str(tmp_path / "missing.yaml"))
    assert _has_config_hash() is False
