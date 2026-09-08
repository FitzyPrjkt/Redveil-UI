"""Auth routes (0.2.0 Phase 3): /api/auth/login + /api/auth/logout.

Login accepts the raw API key via JSON body OR the X-API-Key header
(CLI/curl convenience). Issues an HMAC session cookie:
HttpOnly + SameSite=Strict + Path=/ + Max-Age=SESSION_TTL, with the
Secure flag set iff the effective scheme is HTTPS (request scheme or
X-Forwarded-Proto: https).
"""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

from redveil_ui.api.auth import _resolve_api_key, issue_session_cookie

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    api_key: Optional[str] = None


def _effective_scheme(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-proto", "").lower()
    if forwarded == "https":
        return "https"
    return request.url.scheme


@router.post("/login")
def login(request: Request, body: LoginIn | None = None):
    expected = _resolve_api_key()
    if expected is None:
        raise HTTPException(status_code=401, detail="Invalid API key")

    supplied = body.api_key if (body is not None and body.api_key) else None
    if not supplied:
        supplied = request.headers.get("x-api-key")
    if not supplied or supplied != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")

    cookie_value, max_age = issue_session_cookie(expected)
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
