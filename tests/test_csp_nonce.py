"""CSP nonce for SPA inline scripts (e2e follow-up).

Next.js static export pages ship inline flight-payload <script> tags.
With CSP script-src 'self' those are blocked, hydration dies (React
#412) and every dynamic route renders blank. The middleware now injects
a per-response nonce into inline script tags and names it in the CSP.
"""
import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


def _csp(response):
    return response.headers.get("content-security-policy", "")


def test_json_response_csp_has_empty_nonce_and_no_unsafe_inline_script(client):
    """Non-HTML responses keep the plain CSP: script-src 'self' plus an
    empty nonce slot (never 'unsafe-inline' for scripts)."""
    r = client.get("/api/info")
    csp = _csp(r)
    script_dir = csp.split("script-src")[1].split(";")[0]
    assert "'self'" in script_dir
    assert "unsafe-inline" not in script_dir


def test_api_response_csp_has_no_nonce_and_still_self_only(client):
    r = client.get("/api/info")
    csp = _csp(r)
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]


def test_html_body_inline_scripts_get_nonce_injected(client):
    """Serve an HTML page; every inline <script> in the body must carry
    the exact nonce the CSP header names."""
    from fastapi.responses import HTMLResponse
    from fastapi import FastAPI

    from redveil_ui.api.main import app

    @app.get("/__test_html__", include_in_schema=False)
    def _html_page():
        return HTMLResponse(
            "<html><body><script>var a = 1;</script>"
            '<script src="/static/x.js"></script>'
            "<script>var b = 2;</script></body></html>"
        )

    with TestClient(app) as c:
        r = c.get("/__test_html__")
    nonce_match = re.search(r"nonce-([A-Za-z0-9_\-]+)", _csp(r))
    assert nonce_match, "CSP must name a nonce on HTML responses"
    nonce = nonce_match.group(1)

    body = r.text
    inline_scripts = re.findall(r"<script\b[^>]*>", body)
    nonced = [t for t in inline_scripts if f'nonce="{nonce}"' in t]
    with_src = [t for t in inline_scripts if "src=" in t]
    # 2 inline scripts, 1 external — the externals must NOT be nonced.
    assert len(inline_scripts) == 3
    assert len(nonced) == 2, f"both inline scripts nonced, got {inline_scripts}"
    assert len(with_src) == 1 and "nonce" not in with_src[0]
    # The script payload survived the rewrite.
    assert "var a = 1;" in body and "var b = 2;" in body


def test_nonce_differs_per_response(client):
    from fastapi.responses import HTMLResponse
    from redveil_ui.api.main import app

    @app.get("/__test_html2__", include_in_schema=False)
    def _html_page():
        return HTMLResponse("<html><body><script>x()</script></body></html>")

    with TestClient(app) as c:
        n1 = re.search(r"nonce-([A-Za-z0-9_\-]+)", _csp(c.get("/__test_html2__"))).group(1)
        n2 = re.search(r"nonce-([A-Za-z0-9_\-]+)", _csp(c.get("/__test_html2__"))).group(1)
    assert n1 != n2, "nonce must be per-response, not a static value"
