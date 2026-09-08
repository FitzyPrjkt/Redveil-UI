"""Token entropy analysis endpoint.

Reuses :func:`redveil.checks.session_cookie.shannon_entropy` and the
``_ENTROPY_CONFIRMED`` / ``_ENTROPY_LIKELY`` thresholds so the verdict
matches what the session-cookie check would emit. We deliberately do
NOT port the entropy math to JavaScript — the spec requires the live
Python implementation.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from redveil.checks.session_cookie import (
    _ENTROPY_CONFIRMED,
    _ENTROPY_LIKELY,
    shannon_entropy,
)

router = APIRouter()


class EntropyRequest(BaseModel):
    """Request body for ``POST /api/entropy/analyze``."""

    value: str = Field(..., description="Token / cookie value to analyze")


class EntropyResponse(BaseModel):
    """Response payload for the entropy analysis endpoint."""

    bits_per_char: float = Field(
        ...,
        description="Shannon entropy of the value, in bits per character.",
    )
    length: int = Field(..., description="Length of the input value, in chars.")
    verdict: str = Field(
        ...,
        description=(
            "'weak' if bits_per_char is below _ENTROPY_CONFIRMED, "
            "'ok' if at or above _ENTROPY_LIKELY, "
            "'marginal' otherwise."
        ),
    )
    confirmed_threshold: float = Field(
        ..., description="_ENTROPY_CONFIRMED — below this is 'weak'."
    )
    likely_threshold: float = Field(
        ..., description="_ENTROPY_LIKELY — at/above this is 'ok'."
    )


def _classify(bits_per_char: float) -> str:
    """Map bits_per_char to a verdict string.

    Mirrors the logic from the session-cookie check: below
    ``_ENTROPY_CONFIRMED`` is weak, at/above ``_ENTROPY_LIKELY`` is
    strong enough, in between is marginal.
    """
    if bits_per_char < _ENTROPY_CONFIRMED:
        return "weak"
    if bits_per_char >= _ENTROPY_LIKELY:
        return "ok"
    return "marginal"


@router.post("/analyze", response_model=EntropyResponse)
async def analyze_entropy(body: EntropyRequest) -> EntropyResponse:
    """Compute Shannon entropy of ``body.value`` and return a verdict.

    Returns ``bits_per_char`` (Shannon entropy), ``length``, and a
    ``verdict`` of ``weak`` / ``marginal`` / ``ok`` based on the
    session-cookie thresholds.
    """
    value = body.value
    if value is None:
        raise HTTPException(status_code=400, detail="value is required")

    length = len(value)
    bits = shannon_entropy(value)

    return EntropyResponse(
        bits_per_char=round(bits, 4),
        length=length,
        verdict=_classify(bits),
        confirmed_threshold=_ENTROPY_CONFIRMED,
        likely_threshold=_ENTROPY_LIKELY,
    )