"""Findings endpoints: cross-scan list + per-finding detail + annotations + AI explain (D1)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_ui.api.db import get_session
from redveil_ui.api.models import AiConfigStore, Evidence, Finding
from redveil_ui.api.schemas import FindingDetailOut, FindingOut, FindingPatchIn, FindingPatchOut

router = APIRouter()


@router.get("", response_model=list[FindingOut])
async def list_findings(
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),
    check_id: str | None = Query(None),
    scan_id: int | None = Query(None),
    include_fp: bool = Query(
        False,
        description=(
            "Include false_positive findings in the response. "
            "Default (false) hides them so the Findings list shows only "
            "actionable items. Pass true to surface FPs for audit / triage."
        ),
    ),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> list[Finding]:
    stmt = select(Finding).order_by(Finding.id.desc()).offset(offset).limit(limit)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if check_id is not None:
        stmt = stmt.where(Finding.check_id == check_id)
    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if not include_fp:
        # Default behavior: hide false_positive so the Findings list
        # shows only actionable items. Operators can pass include_fp=true
        # (or use the "show all" toggle in the UI) to surface FPs.
        stmt = stmt.where(Finding.status != "false_positive")
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/{wpoc_id}", response_model=FindingDetailOut)
async def get_finding(wpoc_id: str, session: AsyncSession = Depends(get_session)) -> Finding:
    result = await session.execute(select(Finding).where(Finding.wpoc_id == wpoc_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@router.patch("/{wpoc_id}", response_model=FindingPatchOut)
async def patch_finding(
    wpoc_id: str, body: FindingPatchIn, session: AsyncSession = Depends(get_session)
) -> Finding:
    """Update operator notes for a finding (0.3.0 annotations)."""
    result = await session.execute(select(Finding).where(Finding.wpoc_id == wpoc_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    # Normalize: strip, None if empty
    notes = body.notes.strip() if body.notes and body.notes.strip() else None
    finding.notes = notes
    finding.annotated_at = datetime.now(UTC) if notes else None
    await session.commit()
    await session.refresh(finding)
    return finding


@router.post("/{wpoc_id}/explain", response_model=dict)
async def explain_finding_route(
    wpoc_id: str, session: AsyncSession = Depends(get_session)
) -> dict:
    """AI explain for a finding (D1 read-only). Uses sanitized evidence.

    Returns {"ok": True, "explanation": ..., "remediation": ...} or {"ok": False, "error": ...}.
    Never mutates finding. Failure-isolated: AI disabled/down → ok=False.
    """
    result = await session.execute(select(Finding).where(Finding.wpoc_id == wpoc_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    # Load AI config
    res2 = await session.execute(select(AiConfigStore).limit(1))
    row = res2.scalars().first()
    if not row or not isinstance(row.config, dict):
        return {"ok": False, "error": "AI not configured"}
    cfg_dict = row.config
    if not cfg_dict.get("enabled"):
        return {"ok": False, "error": "AI disabled (enabled=false)"}

    # Load evidence for this finding (via evidence_data ids or DB)
    evidence_payloads: list[dict] = []
    try:
        # Try DB evidence indexed by scan_id
        res3 = await session.execute(select(Evidence).where(Evidence.scan_id == finding.scan_id).limit(5))
        for ev in res3.scalars().all():
            evidence_payloads.append(ev.evidence_data or {})
        # If finding has evidence_ids, filter to those
        f_data = finding.finding_data or {}
        e_ids = f_data.get("evidence_ids") or []
        if e_ids and evidence_payloads:
            # evidence_data may not have id field; keep all if mismatch
            pass
    except Exception:
        pass

    # Fallback to finding_data itself
    finding_dict = {
        "id": finding.wpoc_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": finding.status,
        "endpoint": finding.endpoint,
        "check_id": finding.check_id,
        "finding_data": finding.finding_data,
    }

    try:
        from redveil.ai.analysis import explain_finding as _explain

        out = await _explain(finding=finding_dict, evidence=evidence_payloads, ai_config=cfg_dict)
        return out
    except Exception as e:
        return {"ok": False, "error": str(e)}
