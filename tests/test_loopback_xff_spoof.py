"""S1 regression: _is_loopback must not trust X-Forwarded-For from
arbitrary peers. XFF is honored only when the direct peer is a trusted
proxy (REDVEIL_TRUSTED_PROXIES, default loopback).

A LAN client sending X-Forwarded-For: 127.0.0.1 must NOT be treated as
loopback — the pre-fix middleware granted authentication to that
spoofed identity.
"""
import pytest
from starlette.requests import Request

from redveil_ui.api.middleware import AuthMiddleware


def _request_for(client: tuple[str, int], xff: str | None = None) -> Request:
    """Build a starlette Request over a minimal ASGI scope."""
    headers: list[tuple[bytes, bytes]] = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/info",
        "headers": headers,
        "query_string": b"",
        "client": client,
        "server": ("testserver", 80),
    }
    return Request(scope)


def _middleware() -> AuthMiddleware:
    return AuthMiddleware(app=None)  # dispatch is never invoked here


def test_lan_client_with_spoofed_loopback_xff_is_not_loopback(monkeypatch):
    """The core S1 case: remote peer + XFF: 127.0.0.1 -> NOT loopback."""
    monkeypatch.delenv("REDVEIL_TRUSTED_PROXIES", raising=False)
    request = _request_for(("192.168.1.50", 12345), xff="127.0.0.1")
    assert _middleware()._is_loopback(request) is False


def test_lan_client_without_xff_is_not_loopback(monkeypatch):
    monkeypatch.delenv("REDVEIL_TRUSTED_PROXIES", raising=False)
    request = _request_for(("192.168.1.50", 12345))
    assert _middleware()._is_loopback(request) is False


def test_direct_loopback_client_is_loopback(monkeypatch):
    monkeypatch.delenv("REDVEIL_TRUSTED_PROXIES", raising=False)
    request = _request_for(("127.0.0.1", 54321), xff="192.168.1.50")
    assert _middleware()._is_loopback(request) is True


def test_trusted_proxy_xff_loopback_is_loopback(monkeypatch):
    """A trusted (loopback) proxy forwarding from a loopback client is
    still loopback — the legitimate reverse-proxy-on-same-host case."""
    monkeypatch.delenv("REDVEIL_TRUSTED_PROXIES", raising=False)
    request = _request_for(("127.0.0.1", 54321), xff="127.0.0.1")
    assert _middleware()._is_loopback(request) is True


def test_trusted_proxy_env_extends_xff_trust(monkeypatch):
    """Operators may declare additional trusted proxies via env."""
    monkeypatch.setenv("REDVEIL_TRUSTED_PROXIES", "10.0.0.2,::1")
    request = _request_for(("10.0.0.2", 54321), xff="127.0.0.1")
    assert _middleware()._is_loopback(request) is True
    # A peer NOT in the set stays untrusted even with the same XFF.
    request_lan = _request_for(("10.0.0.3", 54321), xff="127.0.0.1")
    assert _middleware()._is_loopback(request_lan) is False


def test_missing_client_is_not_loopback(monkeypatch):
    monkeypatch.delenv("REDVEIL_TRUSTED_PROXIES", raising=False)
    request = _request_for(None, xff="127.0.0.1")
    assert _middleware()._is_loopback(request) is False
