"""Security headers middleware (Phase 5, spec §8)."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


def test_csp_header_present_on_every_response(client):
    response = client.get("/api/info")
    csp = response.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp  # Next.js styled-jsx
    assert "img-src 'self' data:" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp


def test_x_content_type_options_set(client):
    response = client.get("/api/info")
    assert response.headers.get("x-content-type-options") == "nosniff"


def test_x_frame_options_set(client):
    response = client.get("/api/info")
    assert response.headers.get("x-frame-options") == "DENY"


def test_referrer_policy_set(client):
    response = client.get("/api/info")
    assert response.headers.get("referrer-policy") == "no-referrer"


def test_permissions_policy_set(client):
    response = client.get("/api/info")
    pp = response.headers.get("permissions-policy", "")
    assert "camera=()" in pp
    assert "microphone=()" in pp
    assert "geolocation=()" in pp


def test_headers_on_healthz_too(client):
    """'every response' includes unauthenticated endpoints."""
    response = client.get("/healthz")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert "content-security-policy" in response.headers
