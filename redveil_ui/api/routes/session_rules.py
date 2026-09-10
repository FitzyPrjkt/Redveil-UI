"""Session Rules editor for /session-rules page (Phase C)."""
from __future__ import annotations

import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_ui.api.db import get_session
from redveil_ui.api.models import SessionRuleSet

router = APIRouter()


class SessionRuleTestIn(BaseModel):
    extract_url: str = Field(..., description="URL to fetch for extraction")
    extract: dict = Field(..., description="{from: body|header|json, regex, header_name, json_path}")
    inject: dict | None = Field(default=None)


class SessionRuleTestOut(BaseModel):
    token: str | None = None
    extracted: bool = False
    preview: str | None = None
    error: str | None = None
    status_code: int | None = None


@router.get("", response_model=dict)
async def get_session_rules(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(SessionRuleSet).limit(1))
    row = result.scalars().first()
    if not row:
        # Default empty config
        return {"rules": [], "reauth": {"enabled": False}}
    return row.config


@router.put("", response_model=dict)
async def put_session_rules(body: dict, session: AsyncSession = Depends(get_session)):
    # Validate via SessionHandlingConfig if available
    try:
        from redveil.http.session_rules import SessionHandlingConfig
        # Will raise if invalid
        cfg = SessionHandlingConfig(**body)
        body = cfg.model_dump(by_alias=True)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid session_handling: {e}")

    result = await session.execute(select(SessionRuleSet).limit(1))
    row = result.scalars().first()
    if row:
        row.config = body
    else:
        row = SessionRuleSet(config=body)
        session.add(row)
    await session.commit()
    await session.refresh(row)
    return row.config


@router.post("/test", response_model=SessionRuleTestOut)
async def test_rule(body: SessionRuleTestIn):
    """Test a single rule extraction without persisting."""
    try:
        from redveil.http.session_rules import SessionHandlingConfig, SessionRuleConfig, SessionExtractConfig, SessionInjectConfig
        # Build a minimal rule for testing
        rule_dict = {
            "name": "test",
            "extract_url": body.extract_url,
            "extract": body.extract,
            "inject": body.inject or {"to": "header", "name": "X-Test"},
            "ttl_seconds": 300,
        }
        # Validate rule
        rule = SessionRuleConfig(**rule_dict)
        # Use a temporary SessionRuleEngine + HttpClient mock? Instead do direct fetch via httpx respecting scope? 
        # For MVP, we do a simple httpx fetch bypassing scope, to preview extraction.
        import httpx
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            resp = await client.get(body.extract_url)
            source = ""
            from_ = getattr(rule.extract, "from_", "body")
            if from_ == "body":
                source = resp.text
            elif from_ == "header":
                hn = (rule.extract.header_name or "").lower()
                for k, v in resp.headers.items():
                    if k.lower() == hn:
                        source = v
                        break
            elif from_ == "json":
                try:
                    data = resp.json()
                    cur: Any = data
                    jp = getattr(rule.extract, "json_path", None)
                    if jp:
                        for part in jp.split("."):
                            if isinstance(cur, dict):
                                cur = cur.get(part)
                            else:
                                cur = None
                                break
                    source = str(cur) if cur is not None else ""
                except Exception:
                    source = resp.text
            else:
                source = resp.text

            m = re.search(rule.extract.regex, source, re.DOTALL)
            if m:
                token = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                return SessionRuleTestOut(token=token, extracted=True, preview=token[:80], status_code=resp.status_code)
            else:
                return SessionRuleTestOut(token=None, extracted=False, preview=source[:200], status_code=resp.status_code, error="regex did not match")
    except HTTPException:
        raise
    except Exception as e:
        return SessionRuleTestOut(token=None, extracted=False, error=str(e))
