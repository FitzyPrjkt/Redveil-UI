"""OpenAPI specs management for /openapi page (Phase C)."""
from __future__ import annotations

import json
from datetime import datetime, UTC

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_ui.api.db import get_session
from redveil_ui.api.models import OpenApiSpec

router = APIRouter()


class OpenApiParseIn(BaseModel):
    spec: str = Field(..., min_length=1, max_length=200_000, description="Raw yaml/json spec content")


class OpenApiParseOut(BaseModel):
    endpoints: list[dict] = Field(default_factory=list)
    count: int = 0
    error: str | None = None


class OpenApiSpecCreate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    spec: str = Field(..., min_length=1, max_length=200_000)


class OpenApiSpecOut(BaseModel):
    id: int
    name: str | None
    spec: str
    created_at: datetime
    endpoints: list[dict] | None = None
    count: int = 0

    class Config:
        from_attributes = True


def _parse_spec_to_endpoints(spec_str: str) -> tuple[list[dict], str | None]:
    """Parse spec string (yaml or json) to endpoint list, return (endpoints, error)."""
    s = spec_str.strip()
    if not s:
        return [], "empty spec"
    # Detect json vs yaml by starting char
    is_json = s.lstrip().startswith("{")
    spec_dict = None
    try:
        if is_json:
            spec_dict = json.loads(s)
        else:
            spec_dict = yaml.safe_load(s)
        if not isinstance(spec_dict, dict):
            return [], "spec must be object with 'paths'"
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        return [], f"parse error: {e}"
    if "paths" not in spec_dict and "openapi" not in spec_dict and "swagger" not in spec_dict:
        return [], "spec must contain 'paths' or 'openapi'/'swagger'"
    try:
        from redveil.attack_surface.openapi import parse_openapi_spec
        eps = parse_openapi_spec(spec_dict)
        out = []
        for ep in eps:
            out.append({
                "method": ep.method,
                "path": ep.path,
                "parameters": [{"name": p.name, "location": p.location.value if hasattr(p.location, "value") else str(p.location)} for p in ep.parameters],
                "source": ep.source,
            })
        return out, None
    except Exception as e:
        return [], f"parse failed: {e}"


@router.post("/parse", response_model=OpenApiParseOut)
async def parse_openapi(body: OpenApiParseIn):
    endpoints, err = _parse_spec_to_endpoints(body.spec)
    return OpenApiParseOut(endpoints=endpoints, count=len(endpoints), error=err)


@router.get("/specs", response_model=list[OpenApiSpecOut])
async def list_specs(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(OpenApiSpec).order_by(OpenApiSpec.id.desc()))
    rows = list(result.scalars().all())
    out = []
    for r in rows:
        parsed = r.parsed or {}
        eps = parsed.get("endpoints") if isinstance(parsed, dict) else None
        out.append(OpenApiSpecOut(
            id=r.id, name=r.name, spec=r.spec, created_at=r.created_at,
            endpoints=eps, count=len(eps) if isinstance(eps, list) else 0,
        ))
    return out


@router.post("/specs", response_model=OpenApiSpecOut, status_code=201)
async def create_spec(body: OpenApiSpecCreate, session: AsyncSession = Depends(get_session)):
    endpoints, err = _parse_spec_to_endpoints(body.spec)
    if err:
        raise HTTPException(status_code=400, detail=err)
    row = OpenApiSpec(
        name=body.name,
        spec=body.spec,
        parsed={"endpoints": endpoints},
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return OpenApiSpecOut(
        id=row.id, name=row.name, spec=row.spec, created_at=row.created_at,
        endpoints=endpoints, count=len(endpoints),
    )


@router.get("/specs/{spec_id}", response_model=OpenApiSpecOut)
async def get_spec(spec_id: int, session: AsyncSession = Depends(get_session)):
    row = await session.get(OpenApiSpec, spec_id)
    if not row:
        raise HTTPException(status_code=404, detail="spec not found")
    parsed = row.parsed or {}
    eps = parsed.get("endpoints") if isinstance(parsed, dict) else None
    return OpenApiSpecOut(
        id=row.id, name=row.name, spec=row.spec, created_at=row.created_at,
        endpoints=eps, count=len(eps) if isinstance(eps, list) else 0,
    )


@router.delete("/specs/{spec_id}", status_code=204)
async def delete_spec(spec_id: int, session: AsyncSession = Depends(get_session)):
    row = await session.get(OpenApiSpec, spec_id)
    if not row:
        raise HTTPException(status_code=404, detail="spec not found")
    await session.delete(row)
    await session.commit()
    return None
