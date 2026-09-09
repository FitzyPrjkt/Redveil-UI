"""Auth routes (0.2.0 Phase 3): /api/auth/login + /api/auth/logout.

Login accepts the raw API key via JSON body OR the X-API-Key header
(CLI/curl convenience). Issues an HMAC session cookie:
HttpOnly + SameSite=Strict + Path=/ + Max-Age=SESSION_TTL, with the
Secure flag set iff the effective scheme is HTTPS (request scheme or
X-Forwarded-Proto: https).

Key validation covers both storage modes (S2 review fix):
- raw key resolvable (env / .api_key file) → direct constant-time
  comparison;
- hash-only install (auth.api_key_hash in config.yaml) → supplied key
  is sha256'd and compared against the stored digest in constant time.
"""
import hmac

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

from redveil_ui.api.auth import (
    _has_config_hash,
    _key_matches_config_hash,
    _resolve_api_keys,
    issue_session_cookie,
)
from redveil_ui.api.middleware import limiter

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Brute-force damping (spec §7.1): 5/min/IP on login.
LOGIN_RATE_LIMIT = "5/minute"


class LoginIn(BaseModel):
    api_key: Optional[str] = None


def _effective_scheme(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-proto", "").lower()
    if forwarded == "https":
        return "https"
    return request.url.scheme


@router.post("/login")
@limiter.limit(LOGIN_RATE_LIMIT)
def login(request: Request, body: LoginIn | None = None):
    expected_keys = _resolve_api_keys()
    supplied = body.api_key if (body is not None and body.api_key) else None
    if not supplied:
        supplied = request.headers.get("x-api-key")

    # Try raw keys first (env/file), then hash list (config) as fallback — multi-key
    matched = None
    for k in expected_keys:
        if supplied and hmac.compare_digest(supplied, k):
            matched = k
            break
    if matched is not None:
        api_key = matched
    elif _has_config_hash() and supplied and _key_matches_config_hash(supplied):
        # Hash-only or additional keys in config
        api_key = supplied
    else:
        raise HTTPException(status_code=401, detail="Invalid API key")

    cookie_value, max_age = issue_session_cookie(api_key)
    secure = _effective_scheme(request) == "https"
    response = JSONResponse({"status": "authenticated"})
    response.set_cookie(
        key="redveil_session",
        value=cookie_value,
        max_age=max_age,
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/",
    )
    return response


@router.post("/logout")
def logout():
    response = JSONResponse({"status": "logged_out"})
    response.delete_cookie("redveil_session", path="/")
    return response
