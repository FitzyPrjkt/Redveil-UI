"""Scope endpoints: per-target scope summary.

The active scope for a target is the union of:
- The target's own ``scope_yaml`` (user-authored, optional)
- The auto-allow rule derived from the target's URL (always allowed)

This module parses the ``scope_yaml`` field and returns a structured view
suitable for the Target / Site Map page.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import yaml
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_api.db import get_session
from redveil_api.models import Target
from redveil_api.schemas import ScopeOut

log = logging.getLogger(__name__)

router = APIRouter()


def _parse_scope_yaml(scope_yaml: str | None) -> dict:
    """Parse a user-authored scope YAML block.

    Accepts either a top-level scope dict (``allowed_hosts: ...``) or a
    nested scope block (``scope: { allowed_hosts: ... }``). Returns an
    empty dict if the YAML is missing or invalid.
    """
    if not scope_yaml:
        return {}
    try:
        parsed = yaml.safe_load(scope_yaml)
    except yaml.YAMLError as e:
        log.warning("failed to parse scope_yaml: %s", e)
        return {}
    if not isinstance(parsed, dict):
        return {}
    if "allowed_hosts" in parsed or "allowed_paths" in parsed:
        return parsed
    nested = parsed.get("scope")
    if isinstance(nested, dict):
        return nested
    return {}


@router.get("/targets/{target_id}/scope", response_model=ScopeOut)
async def get_target_scope(
    target_id: int, session: AsyncSession = Depends(get_session)
) -> ScopeOut:
    """Return the active scope for a target.

    Reads ``Target.scope_yaml`` and falls back to an auto-allow rule on the
    target's URL host so the result always has at least one allowed host.
    """
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="target not found")

    parsed = _parse_scope_yaml(target.scope_yaml)

    # Auto-allow the target's host as a baseline so the page is never empty.
    parsed_host = urlparse(target.url).hostname or ""
    allowed_hosts = list(parsed.get("allowed_hosts") or [])
    if parsed_host and parsed_host.lower() not in {h.lower() for h in allowed_hosts}:
        allowed_hosts.insert(0, parsed_host.lower())

    return ScopeOut(
        allowed_hosts=allowed_hosts,
        allowed_paths=list(parsed.get("allowed_paths") or ["/*"]),
        excluded_paths=list(parsed.get("excluded_paths") or []),
        follow_redirects=bool(parsed.get("follow_redirects", True)),
        max_redirects=int(parsed.get("max_redirects", 5)),
        raw_yaml=target.scope_yaml,
    )