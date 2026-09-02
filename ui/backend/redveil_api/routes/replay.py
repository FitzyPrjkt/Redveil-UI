"""Replay endpoints — re-trigger a finding's recipe against its target.

The ReplayEngine in ``redveil.validation.replay`` runs the sanitized request
N times and reports whether the observable signal is consistent. This module
wraps it in an HTTP endpoint so the UI can show the operator what happened.

A finding must have ``replay_recipe`` populated to be replayable. Checks
that built the recipe saved it as a serialized dict under
``finding_data["replay_recipe"]`` — see ``redveil.checks.session_cookie``
for an example.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil.config import LimitsConfig
from redveil.core.scope import ScopeController
from redveil.http.client import HttpClient
from redveil.http.session import AnonymousAuth
from redveil.validation.replay import ReplayEngine, ReplayRecipe

from redveil_api.db import get_session
from redveil_api.models import Finding
from redveil_api.schemas import ReplayOut, ReplaySample

router = APIRouter()


def _build_recipe(recipe_dict: dict) -> ReplayRecipe:
    """Construct a ReplayRecipe from a serialized dict.

    Tolerates missing optional fields so older findings still replay.
    """
    from redveil.validation.replay import ReplayRecipe as _Recipe

    observed_at_raw = recipe_dict.get("observed_at")
    observed_at = datetime.now(UTC)
    if observed_at_raw:
        try:
            observed_at = datetime.fromisoformat(observed_at_raw)
        except ValueError:
            observed_at = datetime.now(UTC)

    return _Recipe(
        method=str(recipe_dict.get("method", "GET")).upper(),
        url=str(recipe_dict.get("url", "")),
        headers=dict(recipe_dict.get("headers") or {}),
        body=recipe_dict.get("body"),
        expected_status=recipe_dict.get("expected_status"),
        expected_body_excerpt=str(recipe_dict.get("expected_body_excerpt") or ""),
        expected_body_length=recipe_dict.get("expected_body_length"),
        expected_timing_ms=recipe_dict.get("expected_timing_ms"),
        observed_at=observed_at,
        notes=str(recipe_dict.get("notes") or ""),
    )


def _derive_scope_for_url(url: str) -> ScopeController:
    """Auto-allow the target host so a replay request passes scope.

    Replays are read-only re-triggers of the original probe; they target
    the same host as the finding, which the operator already authorized.
    """
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
    """Map the ReplayResult + sample success into an operator-facing verdict."""
    if sample_count == 0 or success_count == 0:
        return "Not verified"
    if not reliable:
        # is_reliable() is the strict gate — variance thresholds.
        return "Not verified"
    if not consistent:
        # Samples succeeded but disagree — typical flaky pattern.
        return "Flaky"
    return "Reproducible"


@router.post("/{wpoc_id}/replay", response_model=ReplayOut)
async def replay_finding(
    wpoc_id: str,
    request: Request,
    samples: int = 3,
    session: AsyncSession = Depends(get_session),
) -> ReplayOut:
    """Replay a finding's recipe N times (default 3) and report consistency.

    Path param: ``wpoc_id`` — the finding's public ID (e.g. ``WPOC-AB12CD``).

    Query param: ``samples`` — number of replays (1..10, default 3).

    The endpoint reads the finding, extracts its ``replay_recipe``,
    builds a fresh ``HttpClient`` scoped to the recipe's host, and runs
    the ``ReplayEngine``. The result includes each sample's status +
    timing + body length, aggregate consistency metrics, and a
    human-facing verdict badge string.
    """
    # ---- load finding --------------------------------------------------
    result = await session.execute(select(Finding).where(Finding.wpoc_id == wpoc_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    recipe_dict = (finding.finding_data or {}).get("replay_recipe")
    if not recipe_dict or not isinstance(recipe_dict, dict):
        raise HTTPException(
            status_code=422,
            detail=(
                "finding has no replay_recipe — the check that produced it "
                "did not populate one"
            ),
        )

    if not recipe_dict.get("url"):
        raise HTTPException(status_code=422, detail="replay_recipe is missing url")

    samples = max(1, min(int(samples), 10))

    # ---- run replay -----------------------------------------------------
    recipe = _build_recipe(recipe_dict)
    scope = _derive_scope_for_url(recipe.url)
    limits = LimitsConfig(
        requests_per_second=2.0,
        max_requests=samples + 2,
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
            replay_result = await engine.replay(recipe, samples=samples)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502,
            detail=f"replay failed before completion: {exc}",
        ) from exc

    elapsed = (datetime.now(UTC) - started).total_seconds() * 1000.0

    # ---- shape response -------------------------------------------------
    body_excerpt = ""
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
        if not body_excerpt and resp.body:
            body_excerpt = resp.body[:200]

    reliable = bool(replay_result.is_reliable())
    consistent = bool(replay_result.consistent)
    sample_count = replay_result.sample_count
    verdict = _verdict(reliable, consistent, success_count, sample_count)

    return ReplayOut(
        wpoc_id=finding.wpoc_id,
        finding_title=finding.title,
        target_url=recipe.url,
        method=recipe.method,
        samples=sample_outs,
        sample_count=sample_count,
        success_count=success_count,
        total_duration_ms=round(elapsed, 1),
        consistent=consistent,
        status_variance=replay_result.status_variance,
        body_length_variance=replay_result.body_length_variance,
        body_content_match=replay_result.body_content_match,
        timing_variance_ms=round(replay_result.timing_variance_ms, 1),
        reliable=reliable,
        verdict=verdict,
        notes=replay_result.notes,
        executed_at=started.isoformat(),
    )