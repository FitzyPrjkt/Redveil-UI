"""Targets CRUD endpoints."""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_api.db import get_session
from redveil_api.models import Finding, Scan, Target
from redveil_api.schemas import (
    SiteMapEndpointOut,
    SiteMapOut,
    TargetCreate,
    TargetOut,
    TargetUpdate,
)

router = APIRouter()


@router.get("", response_model=list[TargetOut])
async def list_targets(session: AsyncSession = Depends(get_session)) -> list[Target]:
    result = await session.execute(select(Target).order_by(Target.id.desc()))
    return list(result.scalars().all())


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(
    body: TargetCreate, session: AsyncSession = Depends(get_session)
) -> Target:
    # Uniqueness check
    existing = await session.execute(select(Target).where(Target.url == body.url))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"target with url {body.url!r} already exists",
        )
    target = Target(url=body.url, name=body.name, scope_yaml=body.scope_yaml)
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(target_id: int, session: AsyncSession = Depends(get_session)) -> Target:
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")
    return target


@router.patch("/{target_id}", response_model=TargetOut)
async def update_target(
    target_id: int,
    body: TargetUpdate,
    session: AsyncSession = Depends(get_session),
) -> Target:
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")
    if body.name is not None:
        target.name = body.name
    if body.scope_yaml is not None:
        target.scope_yaml = body.scope_yaml
    await session.commit()
    await session.refresh(target)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: int, session: AsyncSession = Depends(get_session)) -> None:
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")
    await session.delete(target)
    await session.commit()


def _parse_endpoint(endpoint: str) -> tuple[str, str]:
    """Split ``"METHOD https://host/path?x=y"`` into ``(method, path)``.

    The Finding.endpoint column stores ``f"{method} {scheme}://{host}{path}"``.
    Returns ``("GET", endpoint)`` if no method prefix is found so we never
    drop rows for legacy or malformed data.
    """
    if not endpoint:
        return "GET", ""
    parts = endpoint.split(maxsplit=1)
    if len(parts) == 2 and parts[1].startswith(("http://", "https://")):
        method = parts[0].upper()
        url = parts[1]
        parsed = urlparse(url)
        return method, parsed.path or "/"
    # Bare path
    return "GET", endpoint


@router.get("/{target_id}/sitemap", response_model=SiteMapOut)
async def get_target_sitemap(
    target_id: int, session: AsyncSession = Depends(get_session)
) -> SiteMapOut:
    """Aggregate per-endpoint finding counts for the target's most recent scan.

    Findings are grouped by (method, path). The path's first segment is
    used to populate the "folder" list shown in the Site Map tab.
    """
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")

    # Pull every scan for this target; use the most recent one's findings.
    scans_result = await session.execute(
        select(Scan).where(Scan.target_id == target_id).order_by(Scan.id.desc())
    )
    scans = list(scans_result.scalars().all())
    if not scans:
        return SiteMapOut(
            target_id=target_id, target_url=target.url, endpoints=[], folders=[]
        )

    # Aggregate across every scan for this target (operator expects history).
    findings_result = await session.execute(
        select(Finding).where(Finding.scan_id.in_([s.id for s in scans]))
    )
    findings = list(findings_result.scalars().all())

    # (method, path) -> severity histogram
    hist: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    for f in findings:
        method, path = _parse_endpoint(f.endpoint or "")
        sev = (f.severity or "info").lower()
        hist[(method, path)][sev] = hist[(method, path)].get(sev, 0) + 1

    endpoints: list[SiteMapEndpointOut] = []
    folders: set[str] = set()
    for (method, path), counts in sorted(hist.items(), key=lambda kv: kv[0][1]):
        endpoints.append(
            SiteMapEndpointOut(
                endpoint=path or "/",
                method=method,
                finding_count=sum(counts.values()),
                high_count=counts.get("high", 0) + counts.get("critical", 0),
                medium_count=counts.get("medium", 0),
                low_count=counts.get("low", 0),
                info_count=counts.get("info", 0),
                severity_counts=dict(counts),
            )
        )
        # First non-empty path segment becomes the folder.
        segments = [s for s in (path or "/").split("/") if s]
        if segments:
            folders.add("/" + segments[0])

    return SiteMapOut(
        target_id=target_id,
        target_url=target.url,
        endpoints=endpoints,
        folders=sorted(folders),
    )
