"""Auth middleware (0.2.0 Phase 3).

AuthMiddleware authenticates every request via cookie or X-API-Key
header and sets request.state.is_authenticated / request.state.api_key.
It does NOT block requests itself — destructive-action gating happens
per-route (Task 3.3) using the classification helper.

Loopback requests (direct client host or X-Forwarded-For) short-circuit
to authenticated, preserving the 0.1.x localhost behavior exactly.
"""
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from redveil_ui.api.auth import (
    LOOPBACK_BINDS,
    _has_config_hash,
    _resolve_api_key,
    validate_session_cookie,
)

COOKIE_NAME = "redveil_session"
HEADER_NAME = "X-API-Key"


class AuthMiddleware(BaseHTTPMiddleware):
    """Authenticate every request via cookie or header.

    Sets request.state.is_authenticated and request.state.api_key.
    Does NOT block requests — gating is done per-route via the
    destructive-action classification (see scanner.is_destructive_request).
    """

    def _is_loopback(self, request: Request) -> bool:
        # Check direct client
        if request.client and request.client.host in LOOPBACK_BINDS:
            return True
        # Check X-Forwarded-For (first hop; trusted-proxy validation
        # lands in Phase 6 rate limiting)
        xff = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if xff in LOOPBACK_BINDS:
            return True
        return False

    async def dispatch(self, request: Request, call_next):
        request.state.is_authenticated = False
        request.state.api_key = None

        if self._is_loopback(request):
            request.state.is_authenticated = True  # loopback is always trusted
            return await call_next(request)

        # LAN mode: require either cookie or header
        api_key = _resolve_api_key()
        if api_key is None and not _has_config_hash():
            # No key configured at all — middleware can't authenticate
            # anyone. Per-route logic must handle this (and refuse to
            # process destructive requests).
            return await call_next(request)

        # Try header first
        header_key = request.headers.get(HEADER_NAME)
        if header_key and api_key and header_key == api_key:
            request.state.is_authenticated = True
            request.state.api_key = api_key
            return await call_next(request)

        # Try cookie
        cookie_value = request.cookies.get(COOKIE_NAME)
        if cookie_value and api_key and validate_session_cookie(cookie_value, api_key):
            request.state.is_authenticated = True
            request.state.api_key = api_key
            return await call_next(request)

        return await call_next(request)
