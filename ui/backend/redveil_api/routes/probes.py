"""Probe Builder endpoints — operator-driven custom/preset payload probing.

This route exposes the Wave 14 Probe Builder feature. It is distinct
from the check plugin pipeline: probes are operator-initiated, run
through the same HttpClient so ScopeController + LimitsConfig apply,
and emit a synthetic Scan + Finding so results show up in the existing
Evidence Log.

Spec safety invariants (re-stated from the route module docstring):

1. The request body MUST set ``confirmed_dwyor=true`` for Custom mode.
   The endpoint refuses the request with 403 if missing — the
   two-gate client confirmation is the only allowed path.

2. The HttpClient is constructed per-request from the target's
   stored ``scope_yaml`` (or auto-allow target host as fallback). No
   shared HttpClient instance lives at the route layer; lifecycle is
   per-probe-session.

3. The runner does NOT take action through the Check plugin contract
   (no ActionPlan, no ActionGate). It still respects the global
   ``limits.max_requests`` because the HttpClient enforces it.

4. Preset mode payloads come from the check's own ``_DELAY_PAYLOADS``
   / ``_CANARIES`` set — the client passes ``payload_index``, the
   server resolves the string. The client never sends a payload
   string for Preset mode.

5. Audit: every probe is logged with probe_id, target_id, payload
   count, mode (preset/custom), and a brief summary. Custom probes
   additionally log the operator-supplied payload (the whole point
   of the audit trail — the operator wrote it themselves).
"""
from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil.config import (
    AuthorizationConfig,
    LimitsConfig,
    ScopeConfig,
)
from redveil.core.scope import ScopeController
from redveil.http.client import HttpClient
from redveil.http.session import AnonymousAuth
from redveil.probe.runner import (
    CUSTOM_PROBE_CHECK_ID,
    DWYOR_CONFIRM_STRING,
    ProbeRunResult,
    ProbeRunner,
    new_probe_id,
)
from redveil_api.db import get_session
from redveil_api.models import Finding, Scan, Target
from redveil_api.schemas import (
    ProbeRunIn,
    ProbeRunOut,
    ProbeSampleOut,
)

log = logging.getLogger(__name__)

router = APIRouter()


# --- Preset payload registry ---------------------------------------------
#
# Each check's payload set is private to the check. The endpoint
# exposes a small registry so the Preset mode frontend can list
# available sets. Custom mode is the only path that lets the operator
# supply their own strings.
_PRESET_PAYLOAD_SETS: dict[str, dict[str, Any]] = {
    "sqli-time-based": {
        "kind": "delay",
        "label": "Time-Based SQL Injection (sqli-time-based)",
        "payloads": [
            ("mysql", "1' AND SLEEP(3)-- -"),
            ("mysql", "1) AND SLEEP(3)-- -"),
            ("postgresql", "1' AND pg_sleep(3)-- -"),
            ("mssql", "1'; WAITFOR DELAY '00:00:03'-- -"),
        ],
    },
    "command-injection": {
        "kind": "delay",
        "label": "Command Injection (command-injection)",
        "payloads": [
            ("; sleep 3",),
            ("| sleep 3",),
            ("`sleep 3`",),
            ("$(sleep 3)",),
        ],
    },
    "xss-reflected": {
        "kind": "canary",
        "label": "Reflected XSS (xss-reflected)",
        "payloads": [
            ("redveilXSSProbe12345",),
            ("redv&quot;ail12345",),
            ("redveilXSSanglebracketless12345",),
        ],
    },
}


# --- Limits ----------------------------------------------------------------


def _build_limits(body_max_requests: int | None) -> LimitsConfig:
    """Build the LimitsConfig the HttpClient will enforce.

    ProbeRunner reuses the production default limits. The operator's
    per-request budget is the payload count. If the operator's
    payload count exceeds the global cap, the runner truncates to
    the cap (see endpoint logic below). For v1 we use the production
    defaults — the config endpoint already exposes them so the
    frontend can read them and warn the operator if a planned probe
    exceeds the cap.
    """
    if body_max_requests is None or body_max_requests <= 0:
        return LimitsConfig()
    # Apply the operator's payload count as the per-session budget,
    # capped by the production default of 500. Operators requesting
    # more than 500 payloads must do it in multiple probes.
    return LimitsConfig(
        requests_per_second=2.0,
        max_requests=min(body_max_requests, 500),
        timeout_seconds=10.0,
        max_response_size_bytes=5_000_000,
        max_concurrent_requests=5,
        connection_pool_size=10,
    )


# --- Scope parsing ---------------------------------------------------------


def _parse_scope_yaml(scope_yaml: str | None, target_url: str) -> ScopeConfig:
    """Parse a target's stored scope_yaml into a ScopeConfig, falling
    back to auto-allow the target host if parsing fails or the YAML
    is missing.
    """
    if scope_yaml:
        try:
            parsed = yaml.safe_load(scope_yaml) or {}
        except yaml.YAMLError:
            parsed = {}
    else:
        parsed = {}
    allowed_hosts = parsed.get("allowed_hosts") or []
    allowed_paths = parsed.get("allowed_paths") or ["/*"]
    excluded_paths = parsed.get("excluded_paths") or []
    if not allowed_hosts:
        # Auto-allow the target host so the probe can run at all.
        from urllib.parse import urlparse
        host = (urlparse(target_url).hostname or "").lower()
        allowed_hosts = [host] if host else []
    return ScopeConfig(
        allowed_hosts=allowed_hosts,
        allowed_paths=allowed_paths,
        excluded_paths=excluded_paths,
        follow_redirects=parsed.get("follow_redirects", True),
        max_redirects=parsed.get("max_redirects", 5),
    )


# --- Audit -----------------------------------------------------------------


def _audit_log(
    *,
    probe_id: str,
    target_id: int,
    mode: str,
    method: str,
    payloads: list[str],
    confirmed: bool,
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit one audit log line per probe.

    Custom payloads are logged in full (the operator wrote them —
    that IS the audit trail). Preset payloads are logged as a count
    + the preset's check_id.
    """
    if mode == "custom":
        log.warning(
            "PROBE: id=%s target=%d mode=custom method=%s confirmed_dwyor=%s payloads=%d body=%s",
            probe_id,
            target_id,
            method,
            confirmed,
            len(payloads),
            json.dumps(payloads)[:2000],  # cap audit log
        )
    else:
        log.info(
            "PROBE: id=%s target=%d mode=preset method=%s confirmed_dwyor=%s payload_count=%d preset=%s",
            probe_id,
            target_id,
            method,
            confirmed,
            len(payloads),
            (extra or {}).get("preset_check_id", "?"),
        )


# --- Validation -------------------------------------------------------------


def _validate_payloads(payloads: list[str]) -> None:
    """Catch obviously-malformed inputs early so we don't waste an
    HttpClient round-trip.
    """
    for i, p in enumerate(payloads):
        if not isinstance(p, str):
            raise HTTPException(
                status_code=422,
                detail=f"payloads[{i}] must be a string",
            )
        if len(p) > 4096:
            raise HTTPException(
                status_code=422,
                detail=f"payloads[{i}] exceeds 4096 chars",
            )
        # Control characters other than tab/newline/cr — refuse.
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", p):
            raise HTTPException(
                status_code=422,
                detail=f"payloads[{i}] contains control characters",
            )


# --- Preset resolution ------------------------------------------------------


def _resolve_preset_payloads(
    preset_check_id: str, payload_indices: list[int]
) -> list[str]:
    """Resolve Preset mode ``payload_indices`` against the registered
    payload set for ``preset_check_id``. Raises 422 if any index is
    out of range.
    """
    preset = _PRESET_PAYLOAD_SETS.get(preset_check_id)
    if preset is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"unknown preset_check_id: {preset_check_id}; "
                f"available: {sorted(_PRESET_PAYLOAD_SETS.keys())}"
            ),
        )
    set_payloads = preset["payloads"]
    out: list[str] = []
    for idx in payload_indices:
        if not (0 <= idx < len(set_payloads)):
            raise HTTPException(
                status_code=422,
                detail=(
                    f"payload index {idx} out of range for "
                    f"preset {preset_check_id} (size {len(set_payloads)})"
                ),
            )
        # The tuples are 2-element: (family_label, payload_string).
        # Preset mode runs the payload, not the family label.
        out.append(set_payloads[idx][1])
    return out


# --- Synthetic scan + finding persistence ----------------------------------


async def _persist_probe(
    session: AsyncSession,
    *,
    target: Target,
    probe_id: str,
    mode: str,
    method: str,
    target_url: str,
    payloads: list[str],
    result: ProbeRunResult,
) -> tuple[int, str]:
    """Create a synthetic Scan row + Finding row that wraps the probe.

    The Finding's ``check_id`` is ``"custom-probe"`` and its
    ``finding_data`` carries the evidence_ids list so the existing
    Evidence Log endpoint surfaces the probe samples unchanged.
    """
    scan = Scan(
        target_id=target.id,
        status="completed",
        profile="custom",
        scan_type="custom-probe",
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        total_requests=result.total_executed,
        max_destructive_level="L2",
        allow_destructive=False,
        gate_mode="non_interactive",
    )
    session.add(scan)
    await session.flush()  # need scan.id for the FK

    evidence_ids = [
        f"EV-PROBE-{probe_id}-{i:04d}" for i in range(len(result.samples))
    ]
    finding_data: dict[str, Any] = {
        "evidence_ids": evidence_ids,
        "summary": (
            f"Custom probe via {mode} mode — "
            f"{result.total_executed}/{result.total_requested} payloads "
            f"executed against {target.url}"
        ),
        "technical_explanation": (
            f"Operator-initiated probe using {len(payloads)} "
            f"{mode} payload(s) via {method} against {target_url}."
        ),
        "impact": (
            "N/A — this is an operator-driven probe, not an automatic "
            "finding. Results are summarized below for manual review."
        ),
        "remediation": [
            "Review each sample's status code, response length, and "
            "timing for anomalies consistent with the intended check.",
        ],
        "cwe": [],
        "owasp": [],
    }
    finding = Finding(
        scan_id=scan.id,
        wpoc_id=f"WPOC-{probe_id}",
        severity="info",
        confidence="tentative",
        status="discovered",
        title=(
            f"Custom probe {probe_id} — "
            f"{result.total_executed}/{result.total_requested} executed"
        ),
        endpoint=target_url[:1024] if target_url else None,
        check_id=CUSTOM_PROBE_CHECK_ID,
        finding_data=finding_data,
    )
    session.add(finding)
    await session.commit()
    return scan.id, finding.wpoc_id


# --- Routes ----------------------------------------------------------------


@router.get("/payload-sets", response_model=list[dict])
async def list_payload_sets() -> list[dict]:
    """Enumerate the payload sets available to Preset mode.

    Custom mode does NOT use this — the operator writes the payload
    string directly into the textarea. This endpoint is the only
    way the UI can list what Preset mode has to offer.
    """
    out: list[dict] = []
    for cid, meta in _PRESET_PAYLOAD_SETS.items():
        out.append(
            {
                "check_id": cid,
                "label": meta["label"],
                "kind": meta["kind"],
                "payload_count": len(meta["payloads"]),
            }
        )
    return out


@router.post("/custom", response_model=ProbeRunOut)
async def run_custom_probe(
    body: ProbeRunIn,
    session: AsyncSession = Depends(get_session),
) -> ProbeRunOut:
    """Execute a probe session.

    Body: ``ProbeRunIn`` with payloads + DWYOR confirmation. The
    endpoint refuses any request where ``confirmed_dwyor`` is not
    strictly True — there is no fallback, no default, no override.
    """
    # ---- 1. DWYOR gate (server-side) ----------------------------------
    if not body.confirmed_dwyor:
        # 403, not 400: this is an authorization failure, not a
        # malformed request. The two-gate client confirmation flow
        # must end with this exact flag.
        raise HTTPException(
            status_code=403,
            detail=(
                "confirmed_dwyor must be true; the operator must complete "
                "the two-gate client confirmation before this endpoint "
                "will execute a custom probe"
            ),
        )

    # ---- 2. Load target + build limits ---------------------------------
    target = (
        await session.execute(select(Target).where(Target.id == body.target_id))
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")

    limits = _build_limits(body_max_requests=len(body.payloads))
    if limits.max_requests < len(body.payloads):
        # Operator asked for more than the global cap. We silently
        # truncate to the cap. The UI surfaces the truncated count.
        body_payloads = body.payloads[: limits.max_requests]
    else:
        body_payloads = list(body.payloads)

    # ---- 3. Resolve payloads (Custom vs Preset) -------------------------
    mode = "preset" if body.preset_check_id else "custom"
    if body.preset_check_id:
        # Preset mode: the operator's ``payloads`` field is interpreted
        # as a list of indices into the preset's payload set.
        try:
            payload_indices = [int(p) for p in body_payloads]
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Preset mode requires payload INDICES (integers), "
                    "not raw payload strings"
                ),
            ) from exc
        resolved_payloads = _resolve_preset_payloads(
            body.preset_check_id, payload_indices
        )
    else:
        _validate_payloads(body_payloads)
        resolved_payloads = body_payloads

    # ---- 4. Audit log BEFORE execution ---------------------------------
    probe_id = new_probe_id()
    _audit_log(
        probe_id=probe_id,
        target_id=target.id,
        mode=mode,
        method=body.method,
        payloads=resolved_payloads,
        confirmed=body.confirmed_dwyor,
        extra={"preset_check_id": body.preset_check_id},
    )

    # ---- 5. Build HttpClient scoped to target -------------------------
    scope_cfg = _parse_scope_yaml(target.scope_yaml, target.url)
    scope = ScopeController(scope_cfg)
    auth = AnonymousAuth()  # ProbeBuilder does not inject auth material

    target_url = target.url.rstrip("/")
    # operator may supply path_template; if not, use base URL + position
    # as query param (handled inside ProbeRunner via position_kind)

    started_at = datetime.now(UTC)
    try:
        async with HttpClient(
            scope=scope,
            limits=limits,
            auth=auth,
            follow_redirects=True,
        ) as http:
            runner = ProbeRunner(http, scope)
            result = await runner.run(
                target_url=target_url,
                payloads=resolved_payloads,
                method=body.method,
                position=body.position,
                position_kind=body.position_kind,
                path_template=body.path_template,
                body_template=body.body_template,
                extra_headers=body.extra_headers,
            )
    except Exception as exc:  # noqa: BLE001
        log.exception("probe: runner setup failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"probe runner setup failed: {exc}",
        ) from exc

    completed_at = datetime.now(UTC)

    # ---- 6. Persist synthetic scan + finding for Evidence Log --------
    scan_id, finding_wpoc_id = await _persist_probe(
        session,
        target=target,
        probe_id=probe_id,
        mode=mode,
        method=body.method,
        target_url=target_url,
        payloads=resolved_payloads,
        result=result,
    )

    # ---- 7. Shape response -------------------------------------------
    return ProbeRunOut(
        probe_id=probe_id,
        target_id=target.id,
        scan_id=scan_id,
        finding_wpoc_id=finding_wpoc_id,
        mode=mode,
        method=body.method,
        target_url=target_url,
        total_requested=result.total_requested,
        total_executed=result.total_executed,
        skipped=result.skipped,
        scope_rejections=result.scope_rejections,
        samples=[
            ProbeSampleOut(
                index=s.index,
                payload=s.payload,
                status_code=s.status_code,
                elapsed_ms=s.elapsed_ms,
                body_length=s.body_length,
                body_excerpt=s.body_excerpt,
                error=s.error,
                method=s.method,
                target_url=s.target_url,
                position=s.position,
                started_at=s.started_at,
            )
            for s in result.samples
        ],
        started_at=started_at.isoformat(),
        completed_at=completed_at.isoformat(),
    )


__all__ = ["router", "DWYOR_CONFIRM_STRING"]