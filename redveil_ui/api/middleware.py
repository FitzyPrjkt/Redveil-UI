"""Auth middleware (0.2.0 Phase 3).

AuthMiddleware authenticates every request via cookie or X-API-Key
header and sets request.state.is_authenticated / request.state.api_key.
It does NOT block requests itself — destructive-action gating happens
per-route (Task 3.3) using the classification helper.

Loopback requests (direct client host, or X-Forwarded-For received
FROM a trusted proxy) short-circuit to authenticated, preserving the
0.1.x localhost behavior exactly. XFF from any other peer is ignored:
a LAN client sending `X-Forwarded-For: 127.0.0.1` must not be able to
spoof itself into the loopback trust zone.
"""
import hmac as _hmac  # noqa: E402
import os as _os  # noqa: E402

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from redveil_ui.api.auth import (
    LOOPBACK_BINDS,
    _has_config_hash,
    _key_matches_config_hash,
    _resolve_api_key,
    validate_session_cookie,
)
from redveil_ui.api.db_retry import retry_on_lock

COOKIE_NAME = "redveil_session"
HEADER_NAME = "X-API-Key"


def _trusted_proxies() -> frozenset[str]:
    """Peers allowed to set X-Forwarded-For.

    Default: loopback only. Operators running a reverse proxy on
    another host extend this via REDVEIL_TRUSTED_PROXIES (comma-
    separated). Shares the same env contract as the rate limiter's
    _client_ip so both layers trust the same proxies.
    """
    return frozenset(
        s.strip()
        for s in _os.environ.get("REDVEIL_TRUSTED_PROXIES", "127.0.0.1,::1").split(",")
        if s.strip()
    )


class AuthMiddleware(BaseHTTPMiddleware):
    """Authenticate every request via cookie or header.

    Sets request.state.is_authenticated and request.state.api_key.
    Does NOT block requests — gating is done per-route via the
    destructive-action classification (see scanner.is_destructive_request).
    """

    def _is_loopback(self, request: Request) -> bool:
        # Direct client host is authoritative.
        if request.client and request.client.host in LOOPBACK_BINDS:
            return True
        # X-Forwarded-For is trusted ONLY from a trusted-proxy peer.
        # A remote client cannot nominate itself as loopback by
        # setting the header (S1: an untrusted XFF would otherwise
        # hand out the loopback trust zone to the whole LAN).
        direct = request.client.host if request.client else None
        if direct is not None and direct in _trusted_proxies():
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

        # LAN mode: require either cookie or header.
        api_key = _resolve_api_key()
        has_hash = _has_config_hash()
        if api_key is None and not has_hash:
            # No key configured at all — middleware can't authenticate
            # anyone. Per-route logic must handle this (and refuse to
            # process destructive requests).
            return await call_next(request)

        # Try header first. Works hash-only: with no resolvable raw key
        # but a stored sha256, the supplied key is validated against the
        # hash in constant time.
        header_key = request.headers.get(HEADER_NAME)
        if header_key:
            if api_key and _hmac.compare_digest(header_key, api_key):
                request.state.is_authenticated = True
                request.state.api_key = api_key
                return await call_next(request)
            if api_key is None and has_hash and _key_matches_config_hash(header_key):
                # Hash-only mode: the raw key never lived on the server,
                # so we cannot echo it back onto state.api_key.
                request.state.is_authenticated = True
                return await call_next(request)

        # Try cookie. A cookie HMAC can only be verified against the RAW
        # key (it is the HMAC signing key), so this branch requires the
        # key to be resolvable — in hash-only mode cookie sessions cannot
        # be validated (login still works and issues a cookie, but the
        # middleware falls back to the X-API-Key header path).
        cookie_value = request.cookies.get(COOKIE_NAME)
        if cookie_value and api_key and validate_session_cookie(cookie_value, api_key):
            request.state.is_authenticated = True
            request.state.api_key = api_key
            return await call_next(request)

        return await call_next(request)


# --- Audit log middleware (0.2.0 Task 4.4, spec §7.2) -----------------------

import json as _json  # noqa: E402
from datetime import datetime, timezone  # noqa: E402


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


def _resolve_actor(request: Request) -> str:
    if getattr(request.state, "is_authenticated", False):
        api_key = getattr(request.state, "api_key", None)
        if api_key and len(api_key) >= 4:
            return f"key:{api_key[-4:]}"  # suffix only — never the raw key
        return "loopback"
    return "anonymous"


async def _response_body(response) -> bytes | None:
    """Best-effort read of the response body for deny_reason extraction.

    BaseHTTPMiddleware wraps the route's response in a streaming
    response whose chunks have not been pulled yet at post-call_next
    time, so ``response.body`` may not exist. Drain the iterator
    (re-wrapping the chunks so the client still receives them) — any
    failure yields None and the audit entry falls back to 'HTTP <n>'.
    """
    body = getattr(response, "body", None)
    if isinstance(body, bytes):
        return body
    iterator = getattr(response, "body_iterator", None)
    if iterator is None:
        return None
    chunks: list[bytes] = []

    async def _drain():
        try:
            async for chunk in iterator:
                if isinstance(chunk, bytes):
                    chunks.append(chunk)
                else:
                    chunks.append(str(chunk).encode())
        except Exception:  # noqa: BLE001
            pass

    await _drain()
    if not chunks:
        return None
    joined = b"".join(chunks)

    async def _replay():
        for c in chunks:
            yield c

    response.body_iterator = _replay()
    return joined


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Write destructive operator actions to the append-only audit_log.

    Writes happen AFTER call_next so `result` reflects the actual
    outcome (allowed / denied / not_found). The request body is NOT
    read here — nothing in the audit entry needs it, and consuming the
    stream inside BaseHTTPMiddleware risks starving the route handler.
    Audit failures are swallowed with a log line: observability must
    not take down the request path.
    """

    def __init__(self, app):
        super().__init__(app)
        from redveil_ui.api.db import get_session_factory

        self._factory = None  # resolved lazily — engine may not exist yet

    async def dispatch(self, request: Request, call_next):
        action = _classify_audit(request)
        if action is None:
            return await call_next(request)

        response = await call_next(request)

        try:
            await self._write_entry(request, response, action)
        except Exception as e:  # noqa: BLE001
            import logging

            logging.getLogger(__name__).warning("audit write failed: %s", e)
        return response

    # @retry_on_lock: same defense-in-depth as the finding-write path —
    # one row per audited operator action, concurrent with scan writes.
    # (Review note, Phase 1: plan Step 4 named the audit write a retry
    # candidate; this closes that gap. Failures still land in the
    # log-and-continue handler above.)
    @retry_on_lock()
    async def _write_entry(self, request, response, action: str) -> None:
        from redveil_ui.api.db import get_session_factory
        from redveil_ui.api.models import AuditLog

        # Outcome semantics:
        #   allowed   — the action was authorized and executed (2xx, or
        #               any non-error response outside 401/403/404)
        #   denied    — the action was refused by auth/authorization
        #               (401/403); deny_reason carries the detail
        #   not_found — the action targeted a resource that does not
        #               exist (404). Honest third outcome: nothing was
        #               executed, but this is not an authorization
        #               failure either, and conflating it with
        #               "denied" would pollute security review of the
        #               audit trail.
        if response.status_code in (401, 403):
            result = "denied"
        elif response.status_code == 404:
            result = "not_found"
        else:
            result = "allowed"

        deny_reason = None
        if response.status_code in (401, 403, 404):
            raw = await _response_body(response)
            if raw is not None:
                try:
                    deny_reason = _json.loads(raw).get("detail")
                except Exception:  # noqa: BLE001
                    deny_reason = None
            if not deny_reason:
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
                    result=result,
                    deny_reason=deny_reason,
                )
            )
            await session.commit()


# --- Security headers middleware (0.2.0 Phase 5, spec §8) -------------------

import re as _re  # noqa: E402
import secrets as _secrets  # noqa: E402

_SCRIPT_SRC_RE = _re.compile(r"(<script\b(?![^>]*\bsrc=)[^>]*?)(/?>)")
_STYLE_SRC_RE = _re.compile(r"(<style\b[^>]*?)(/?>)")


def _csp_policy(nonce: str) -> str:
    """CSP with per-response nonce for inline scripts + styles (0.3.0 tightened).

    Next.js static export emits inline <script> flight payloads and
    <style> styled-jsx tags. Both are now nonced so 'unsafe-inline' is gone.
    """
    if nonce:
        return (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
    return (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )


# Kept for callers that stamp the header without a nonce (API responses
# don't carry HTML bodies, so no injection is needed there).
CSP_POLICY = _csp_policy("")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Stamp the spec §8 headers onto every response, both modes.

    For GET responses with an HTML body (the SPA pages), a fresh nonce
    is generated, injected into every inline <script> tag in the body,
    and the CSP names it — so hydration works without opening the door
    to arbitrary inline script execution.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        content_type = response.headers.get("content-type", "")
        nonce = None
        if request.method == "GET" and content_type.startswith("text/html"):
            nonce = _secrets.token_urlsafe(24)
            body = await _drain_html(response)
            if body is not None:
                html = body.decode("utf-8", "replace")
                # Inject nonce into both <script> and <style> inline tags
                html = _SCRIPT_SRC_RE.sub(lambda m: f'{m.group(1)} nonce="{nonce}"{m.group(2)}', html)
                html = _STYLE_SRC_RE.sub(lambda m: f'{m.group(1)} nonce="{nonce}"{m.group(2)}', html)
                new_body = html.encode("utf-8")
                response.headers["content-length"] = str(len(new_body))

                async def _stream():
                    yield new_body

                response.body_iterator = _stream()
        csp = _csp_policy(nonce) if nonce else CSP_POLICY
        response.headers.setdefault("Content-Security-Policy", csp)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response


async def _drain_html(response) -> bytes | None:
    """Drain a streaming response body and hand it back for rewrite."""
    body = getattr(response, "body", None)
    if isinstance(body, bytes):
        return body
    iterator = getattr(response, "body_iterator", None)
    if iterator is None:
        return None
    chunks: list[bytes] = []
    async for chunk in iterator:
        if isinstance(chunk, bytes):
            chunks.append(chunk)
        else:
            chunks.append(str(chunk).encode())
    joined = b"".join(chunks)

    async def _replay():
        yield joined

    response.body_iterator = _replay()
    return joined


# --- Rate limiting (0.2.0 Phase 6, spec §7.1) --------------------------------

from slowapi import Limiter  # noqa: E402
from slowapi.middleware import SlowAPIMiddleware  # noqa: E402


def _client_ip(request: Request) -> str:
    """Client IP for rate limiting, distrusting X-Forwarded-For by default.

    Only trusted proxies (default: loopback) may set XFF — an attacker
    on the LAN must not be able to rotate their apparent IP to dodge
    the per-IP bucket.
    """
    trusted = {
        s.strip()
        for s in _os.environ.get("REDVEIL_TRUSTED_PROXIES", "127.0.0.1,::1").split(",")
        if s.strip()
    }
    direct = request.client.host if request.client else "unknown"
    if direct in trusted:
        xff = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if xff:
            return xff
    return direct


limiter = Limiter(
    key_func=_client_ip,
    default_limits=[_os.environ.get("REDVEIL_RATE_LIMIT_DEFAULT", "60/minute")],
)


def reset_rate_limiter_for_tests() -> None:
    """Clear in-memory buckets (test isolation — see tests/test_rate_limit.py)."""
    limiter.reset()


def default_limit_disabled() -> bool:
    """True when REDVEIL_RATE_LIMIT_DEFAULT opts the default limit out.

    Set REDVEIL_RATE_LIMIT_DEFAULT=0/minute to disable the blanket
    per-route default while keeping decorated limits (login 5/min).
    Read at REQUEST time so deployments can toggle it without
    re-importing the app.
    """
    return _os.environ.get("REDVEIL_RATE_LIMIT_DEFAULT", "").strip() in (
        "0/minute",
        "0",
    )


class _OptionalDefaultLimitMiddleware(SlowAPIMiddleware):
    """SlowAPIMiddleware that can opt out at request time.

    The slowapi stock middleware is registered unconditionally (its
    position in the stack is fixed at import time), but when the
    operator disables the blanket default via REDVEIL_RATE_LIMIT_DEFAULT
    it must stop enforcing it. Decorated route limits (login's 5/min)
    stay active regardless — they are consumed by the decorator path,
    not this middleware.
    """

    async def dispatch(self, request, call_next):
        if default_limit_disabled():
            return await call_next(request)
        return await super().dispatch(request, call_next)
