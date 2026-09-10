"""AI Gateway config + status for /ai page (Phase C)."""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_ui.api.db import get_session
from redveil_ui.api.models import AiConfigStore

router = APIRouter()


def _redact_config(cfg: dict) -> dict:
    """Redact api_key for display."""
    if not isinstance(cfg, dict):
        return cfg
    out = dict(cfg)
    prov = out.get("provider")
    if isinstance(prov, dict):
        p = dict(prov)
        if p.get("api_key"):
            p["api_key"] = "***REDACTED***"
        # Show env var name but not value
        out["provider"] = p
    return out


@router.get("/config", response_model=dict)
async def get_ai_config(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(AiConfigStore).limit(1))
    row = result.scalars().first()
    if not row:
        return {"enabled": False, "provider": None, "capabilities": None, "models": None}
    return _redact_config(row.config)


@router.put("/config", response_model=dict)
async def put_ai_config(body: dict, session: AsyncSession = Depends(get_session)):
    # Validate via AiConfig if available
    try:
        from redveil.ai.config import AiConfig
        cfg = AiConfig(**body)
        # Do not persist raw api_key if provided via env; keep api_key_env
        # But allow direct api_key for self-hosted (will be redacted on read)
        body = cfg.model_dump(exclude_none=False)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid AiConfig: {e}")

    result = await session.execute(select(AiConfigStore).limit(1))
    row = result.scalars().first()
    if row:
        row.config = body
    else:
        row = AiConfigStore(config=body)
        session.add(row)
    await session.commit()
    await session.refresh(row)
    return _redact_config(row.config)


class AiTestIn(BaseModel):
    prompt: str = Field(default="hello", max_length=2000)
    max_tokens: int | None = Field(default=50, ge=1, le=500)


@router.post("/test", response_model=dict)
async def test_ai(body: AiTestIn, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(AiConfigStore).limit(1))
    row = result.scalars().first()
    if not row or not isinstance(row.config, dict):
        raise HTTPException(status_code=400, detail="AI not configured")
    cfg_dict = row.config
    if not cfg_dict.get("enabled"):
        raise HTTPException(status_code=400, detail="AI disabled (enabled=false)")
    provider_cfg = cfg_dict.get("provider")
    if not provider_cfg:
        raise HTTPException(status_code=400, detail="provider not configured")
    # Build provider and try complete
    try:
        from redveil.ai.config import AiConfig
        ai_cfg = AiConfig(**cfg_dict)
        from redveil.ai.provider import build_ai_provider as _build
        provider = _build(ai_cfg) if callable(_build) else None
        if provider is None:
            raise RuntimeError("no provider builder (AI disabled)")
        # Provider.complete expects messages list
        messages = [{"role": "user", "content": body.prompt}]
        resp = await provider.complete(messages=messages)
        # Normalize response
        if isinstance(resp, dict):
            text = resp.get("text") or resp.get("content") or str(resp)[:500]
        else:
            text = getattr(resp, "text", None) or getattr(resp, "content", None) or str(resp)[:500]
        return {"ok": True, "response": text, "provider": provider_cfg.get("type"), "model": provider_cfg.get("model")}
    except HTTPException:
        raise
    except Exception as e:
        return {"ok": False, "error": str(e), "provider": provider_cfg.get("type")}


@router.post("/capabilities/detect", response_model=dict)
async def detect_capabilities(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(AiConfigStore).limit(1))
    row = result.scalars().first()
    if not row or not isinstance(row.config, dict):
        raise HTTPException(status_code=400, detail="AI not configured")
    cfg_dict = row.config
    provider_cfg = cfg_dict.get("provider") if isinstance(cfg_dict, dict) else None
    if not provider_cfg or not isinstance(provider_cfg, dict):
        raise HTTPException(status_code=400, detail="provider not configured")
    base_url = provider_cfg.get("base_url")
    if not base_url:
        raise HTTPException(status_code=400, detail="base_url required")
    # Try best-effort GET /v1/models via detect_capabilities(AiProviderConfig, explicit)
    try:
        from redveil.ai.capability import detect_capabilities
        from redveil.ai.config import AiProviderConfig, AiCapabilities
        prov_cfg = AiProviderConfig(**provider_cfg)
        explicit = None
        if isinstance(cfg_dict.get("capabilities"), dict):
            try:
                explicit = AiCapabilities(**cfg_dict["capabilities"])
            except Exception:
                explicit = None
        caps = await detect_capabilities(prov_cfg, explicit) if callable(detect_capabilities) else explicit
        # caps is AiCapabilities
        caps_dict = caps.model_dump() if hasattr(caps, "model_dump") else (dict(caps) if isinstance(caps, dict) else {"raw": str(caps)})
        return {"ok": True, "base_url": base_url, "capabilities": caps_dict}
    except Exception as e:
        # Fallback to explicit capabilities from config
        explicit = cfg_dict.get("capabilities")
        return {"ok": False, "error": str(e), "explicit": explicit}
