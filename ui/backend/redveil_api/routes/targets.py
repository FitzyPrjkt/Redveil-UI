"""Targets CRUD endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redveil_api.db import get_session
from redveil_api.models import Target
from redveil_api.schemas import TargetCreate, TargetOut, TargetUpdate

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
