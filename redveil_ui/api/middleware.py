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


# --- Audit log middleware (0.2.0 Task 4.4, spec §7.2) -----------------------

import json as _json  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

_AUDITED_ACTIONS = {
    ("POST", "/api/scans"): "scan.create",
    ("POST", "/api/probes/custom"): "probe.custom",
    ("DELETE", None): "target.delete",  # resolved per-request below
}


def _classify_audit(request: Request) -> str | None:
    """Map (method, path) to an audit action name, or None to skip.

    Spec §7.2 scope boundary: audit_log records operator actions that
    affect state — NOT scan lifecycle events (those go to SSE).
    """
    method = request.method.upper()
    path = request.url.path

    if method == "POST" and path == "/api/scans":
        return "scan.create"
    if method == "POST" and path == "/api/probes/custom":
        return "probe.custom"  # ALWAYS destructive regardless of body
    if method == "POST" and path.startswith("/api/scans/") and path.endswith("/cancel"):
        return "scan.cancel"
    if method == "POST" and path.startswith("/api/scans/") and path.endswith("/start"):
        return "scan.start"
    if method == "DELETE" and path.startswith("/api/targets/"):
        return "target.delete"
    return None


async def _read_body_safely(request: Request) -> dict:
    """Read a JSON body without breaking downstream consumers.

    BaseHTTPMiddleware consumes the stream; we cache it back onto the
    request so the route handler can still parse it. Any parse failure
    yields {} — audit must never break the request.
    """
    try:
        raw = await request.body()
        if not raw:
            return {}
        return _json.loads(raw)
    except Exception:  # noqa: BLE001
        return {}


def _resolve_actor(request: Request) -> str:
    if getattr(request.state, "is_authenticated", False):
        api_key = getattr(request.state, "api_key", None)
        if api_key and len(api_key) >= 4:
            return f"key:{api_key[-4:]}"  # suffix only — never the raw key
        return "loopback"
    return "anonymous"


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Write destructive operator actions to the append-only audit_log.

    Writes happen AFTER call_next so `result` reflects the actual
    outcome (allowed / denied + reason). Audit failures are swallowed
    with a log line: observability must not take down the request path.
    """

    def __init__(self, app):
        super().__init__(app)
        from redveil_ui.api.db import get_session_factory

        self._factory = None  # resolved lazily — engine may not exist yet

    async def dispatch(self, request: Request, call_next):
        action = _classify_audit(request)
        if action is None:
            return await call_next(request)

        body = await _read_body_safely(request)
        response = await call_next(request)

        try:
            await self._write_entry(request, response, action, body)
        except Exception as e:  # noqa: BLE001
            import logging

            logging.getLogger(__name__).warning("audit write failed: %s", e)
        return response

    async def _write_entry(self, request, response, action: str, body: dict) -> None:
        from redveil_ui.api.db import get_session_factory
        from redveil_ui.api.models import AuditLog

        denied = response.status_code in (401, 403)
        deny_reason = None
        if denied:
            try:
                deny_reason = _json.loads(response.body.decode()).get("detail")
            except Exception:  # noqa: BLE001
                deny_reason = f"HTTP {response.status_code}"

        # Determine target id where the path carries one
        target_id = None
        parts = request.url.path.rstrip("/").split("/")
        if len(parts) >= 3 and parts[-1] in ("cancel", "start"):
            target_id = parts[-2]
        elif request.method == "DELETE" and len(parts) >= 3:
            target_id = parts[-1]

        meta = {
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "request_path": request.url.path,
        }

        if self._factory is None:
            self._factory = get_session_factory()
        async with self._factory() as session:
            session.add(
                AuditLog(
                    ts=datetime.now(timezone.utc).isoformat(),
                    actor=_resolve_actor(request),
                    action=action,
                    target_kind="scan" if "scan" in action else (
                        "probe" if action == "probe.custom" else "target"
                    ),
                    target_id=target_id,
                    request_meta=_json.dumps(meta),
                    result="denied" if denied else "allowed",
                    deny_reason=deny_reason,
                )
            )
            await session.commit()


# --- Security headers middleware (0.2.0 Phase 5, spec §8) -------------------

CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "  # Next.js styled-jsx (tightening: 0.3.0)
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Stamp the spec §8 headers onto every response, both modes."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response
