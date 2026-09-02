"""Lab routes — STUBS for Wave 5.

All endpoints return 501 Not Implemented so the frontend can wire them up
without breaking. The real implementation lands in a later wave.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.post("/start", status_code=501)
async def start_lab() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content={"detail": "lab control is not implemented yet (Wave 5)"},
    )


@router.post("/stop", status_code=501)
async def stop_lab() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content={"detail": "lab control is not implemented yet (Wave 5)"},
    )


@router.get("/status", status_code=501)
async def lab_status() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content={"detail": "lab control is not implemented yet (Wave 5)"},
    )
