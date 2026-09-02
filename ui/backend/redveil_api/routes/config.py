"""Active configuration view for the UI.

Returns a *safe*, read-only projection of the framework config the scanner
would use right now. Sensitive fields (bearer tokens, basic passwords,
cookie values, custom header values) are NEVER exposed — only structural
metadata (which auth method, how many principals, principal names).

This is intentionally read-only for v1. A bad config change could brick
in-flight scans, so mutating the active config is deferred to a later
wave after proper validation is in place.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil.config import (
    AuthorizationConfig,
    AuthConfig,
    AuthMethod,
    LimitsConfig,
    ReportingConfig,
)

from redveil_api.db import get_session_factory

router = APIRouter()


# --- Response schemas ------------------------------------------------------


class LimitsOut(BaseModel):
    requests_per_second: float
    max_requests: int
    timeout_seconds: float
    max_response_size_bytes: int
    max_concurrent_requests: int
    connection_pool_size: int

    @classmethod
    def from_config(cls, limits: LimitsConfig) -> LimitsOut:
        return cls(
            requests_per_second=limits.requests_per_second,
            max_requests=limits.max_requests,
            timeout_seconds=limits.timeout_seconds,
            max_response_size_bytes=limits.max_response_size_bytes,
            max_concurrent_requests=limits.max_concurrent_requests,
            connection_pool_size=limits.connection_pool_size,
        )


class AuthorizationOut(BaseModel):
    active_testing: bool
    allow_destructive: bool
    max_destructive_level: int = Field(ge=1, le=6)
    acknowledged_safety_terms: bool
    out_of_band_callback_domain: str | None

    @classmethod
    def from_config(cls, auth: AuthorizationConfig) -> AuthorizationOut:
        return cls(
            active_testing=auth.active_testing,
            allow_destructive=auth.allow_destructive,
            max_destructive_level=auth.max_destructive_level,
            acknowledged_safety_terms=auth.acknowledged_safety_terms,
            out_of_band_callback_domain=auth.out_of_band_callback_domain,
        )


class ReportingOut(BaseModel):
    output_dir: str
    formats: list[Literal["markdown", "json", "html"]]
    redact_secrets: bool

    @classmethod
    def from_config(
        cls,
        reporting: ReportingConfig,
        resolved_output_dir: str | None,
    ) -> ReportingOut:
        # Prefer the on-disk output_dir the scanner last wrote to so the
        # operator sees a real path. Fall back to the configured default.
        return cls(
            output_dir=resolved_output_dir or str(reporting.output_dir),
            formats=list(reporting.formats),
            redact_secrets=reporting.redact_secrets,
        )


class PrincipalSummary(BaseModel):
    name: str
    auth_method: str


class AuthOut(BaseModel):
    method: AuthMethod
    principals: list[PrincipalSummary]

    @classmethod
    def from_config(cls, auth: AuthConfig) -> AuthOut:
        principals: list[PrincipalSummary] = []
        for p in auth.principals:
            # Derive a *summary* of which auth method this principal uses.
            # We deliberately don't leak the actual material — just the kind.
            if p.bearer_token:
                kind = "bearer"
            elif p.basic_username and p.basic_password:
                kind = "basic"
            elif p.cookies:
                kind = "cookie"
            else:
                kind = "none"
            principals.append(PrincipalSummary(name=p.name, auth_method=kind))
        return cls(method=auth.method, principals=principals)


class DefaultsOut(BaseModel):
    """Defaults applied to a new scan if the operator doesn't override them."""

    gate_mode: Literal["interactive", "non_interactive", "strict"]
    profile: Literal["passive", "low_impact", "active"]


class ActiveConfigOut(BaseModel):
    limits: LimitsOut
    authorization: AuthorizationOut
    reporting: ReportingOut
    auth: AuthOut
    defaults: DefaultsOut


# --- Endpoint --------------------------------------------------------------


async def _get_session() -> AsyncSession:
    factory = get_session_factory()
    async with factory() as session:
        yield session


@router.get("", response_model=ActiveConfigOut)
async def get_active_config(
    request: Request,
    session: AsyncSession = Depends(_get_session),
) -> ActiveConfigOut:
    """Return the active config the scanner would use right now.

    For v1 we synthesize the view from the framework defaults plus the
    most-recent scan's resolved output_dir (so the operator sees a real
    filesystem path). Future work: persist an editable active config in
    the DB and surface it here.
    """
    # Resolve the scanner's reporting base dir from the last completed
    # scan, if any. Keeps the page useful without mutating global state.
    resolved_output_dir: str | None = None
    try:
        # Local import to avoid pulling models when this endpoint is
        # imported but unused (e.g. during test collection).
        from redveil_api.models import Scan as ScanORM

        result = await session.execute(
            select(ScanORM.output_dir)
            .where(ScanORM.output_dir.is_not(None))
            .order_by(ScanORM.id.desc())
            .limit(1)
        )
        row = result.first()
        if row is not None:
            resolved_output_dir = row[0]
    except Exception:  # noqa: BLE001
        # The view endpoint must never fail just because we couldn't peek
        # at the DB — fall back to the configured default.
        resolved_output_dir = None

    # Re-use the scanner's reported OUTPUT_BASE_DIR if available so the
    # UI shows the operator the real base path, not a stale default.
    scanner = getattr(request.app.state, "scanner", None)
    reporting = ReportingConfig()
    if scanner is not None:
        base = getattr(scanner, "_output_base_dir", None)
        if base is not None:
            reporting.output_dir = base

    payload = ActiveConfigOut(
        limits=LimitsOut.from_config(LimitsConfig()),
        authorization=AuthorizationOut.from_config(AuthorizationConfig()),
        reporting=ReportingOut.from_config(reporting, resolved_output_dir),
        auth=AuthOut.from_config(AuthConfig()),
        defaults=DefaultsOut(gate_mode="non_interactive", profile="passive"),
    )
    return payload


@router.post("/reset", status_code=501)
async def reset_config() -> dict[str, Any]:
    """Reset to defaults — deferred until PATCH validation is in place."""
    raise HTTPException(
        status_code=501,
        detail="config reset not implemented yet (deferred for safety)",
    )