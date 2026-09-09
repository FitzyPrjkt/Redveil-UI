"""Raw Repeater — replay an arbitrary request N times (A4).

POST /api/replay/custom — operator provides method/url/headers/body, we run
ReplayEngine with the same variance analysis as finding replay. Scoped to the
target host, rate-limited, and gated via scope check. No finding required.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from redveil.config import LimitsConfig
from redveil.core.scope import ScopeController
from redveil.http.client import HttpClient
from redveil.http.session import AnonymousAuth
from redveil.validation.replay import ReplayEngine, ReplayRecipe

from redveil_ui.api.schemas import ReplayOut, ReplaySample

router = APIRouter()


class RawReplayIn(BaseModel):
    method: str = Field(default="GET", pattern=r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$")
    url: str = Field(..., min_length=1, max_length=2048)
    headers: dict[str, str] | None = Field(default=None, description="Optional headers")
    body: str | None = Field(default=None, description="Optional body")
    samples: int = Field(default=3, ge=1, le=10, description="Replay count 1..10")


def _derive_scope_for_url(url: str) -> ScopeController:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    from redveil.config import ScopeConfig

    scope_cfg = ScopeConfig(
        allowed_hosts=[host] if host else [],
        allowed_paths=["/*"],
        follow_redirects=True,
        max_redirects=5,
    )
    return ScopeController(scope_cfg)


def _verdict(reliable: bool, consistent: bool, success_count: int, sample_count: int) -> str:
    if sample_count == 0 or success_count == 0:
        return "Not verified"
    if not reliable:
        return "Not verified"
    if not consistent:
        return "Flaky"
    return "Reproducible"


@router.post("/custom", response_model=ReplayOut)
async def replay_raw(body: RawReplayIn) -> ReplayOut:
    """Replay an arbitrary request. Scope-enforced, rate-limited."""
    # Validate URL
    parsed = urlparse(body.url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=422, detail="url must be http(s)")
    if not parsed.hostname:
        raise HTTPException(status_code=422, detail="url must have host")

    # Build recipe
    recipe = ReplayRecipe(
        method=body.method.upper(),
        url=body.url,
        headers=dict(body.headers or {}),
        body=body.body,
        observed_at=datetime.now(UTC),
    )
    scope = _derive_scope_for_url(body.url)
    # Scope check fail-closed
    try:
        scope.check(body.url, body.method.upper())
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"scope violation: {e}")

    limits = LimitsConfig(
        requests_per_second=2.0,
        max_requests=body.samples + 2,
        timeout_seconds=10.0,
        max_response_size_bytes=5_000_000,
        max_concurrent_requests=1,
        connection_pool_size=2,
    )
    started = datetime.now(UTC)
    try:
        async with HttpClient(
            scope=scope,
            limits=limits,
            auth=AnonymousAuth(),
            follow_redirects=True,
        ) as http_client:
            engine = ReplayEngine(http_client)
            replay_result = await engine.replay(recipe, samples=body.samples)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"replay failed: {exc}") from exc

    elapsed = (datetime.now(UTC) - started).total_seconds() * 1000.0
    success_count = 0
    sample_outs: list[ReplaySample] = []
    for idx, resp in enumerate(replay_result.responses, start=1):
        if 200 <= resp.status_code < 400 and not resp.error:
            success_count += 1
        sample_outs.append(
            ReplaySample(
                index=idx,
                status_code=resp.status_code,
                elapsed_ms=round(resp.elapsed_ms, 1),
                body_length=len(resp.body or ""),
                body_excerpt=(resp.body or "")[:200],
                error=resp.error,
            )
        )
    reliable = bool(replay_result.is_reliable())
    consistent = bool(replay_result.consistent)
    verdict = _verdict(reliable, consistent, success_count, replay_result.sample_count)
    return ReplayOut(
        wpoc_id="RAW",
        finding_title="Raw Repeater",
        target_url=body.url,
        method=body.method.upper(),
        samples=sample_outs,
        sample_count=replay_result.sample_count,
        success_count=success_count,
        total_duration_ms=round(elapsed, 1),
        consistent=consistent,
        status_variance=replay_result.status_variance,
        body_length_variance=replay_result.body_length_variance,
        body_content_match=replay_result.body_content_match,
        timing_variance_ms=round(replay_result.timing_variance_ms, 1),
        reliable=reliable,
        verdict=verdict,
        notes="",
        executed_at=started.isoformat(),
    )
