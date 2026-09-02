"""Check plugin metadata endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from redveil_api.schemas import CheckDetailOut, CheckOut

router = APIRouter()


def _get_scanner(request: Request):
    scanner = getattr(request.app.state, "scanner", None)
    if scanner is None:
        raise HTTPException(status_code=503, detail="scanner not initialized")
    return scanner


@router.get("", response_model=list[CheckOut])
async def list_checks(request: Request) -> list[CheckOut]:
    scanner = _get_scanner(request)
    return scanner.list_checks()


@router.get("/{check_id}", response_model=CheckDetailOut)
async def get_check(check_id: str, request: Request) -> CheckDetailOut:
    scanner = _get_scanner(request)
    check = scanner.get_check(check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="check not found")
    return CheckDetailOut(**check.model_dump())
