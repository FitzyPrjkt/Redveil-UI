"""ProbeRunner — operator-driven custom-payload probing.

Distinct from the check plugin pipeline. Where checks have
hardcoded payload sets gated through ``ActionPlan``, ProbeRunner
runs operator-supplied payloads (Preset mode) or free-form custom
payloads (Custom mode) through the same ``HttpClient`` so
``ScopeController`` + ``LimitsConfig`` + ``TokenBucket`` still apply.

The runner is intentionally NOT a ``Check`` subclass. It bypasses
the ``discover → validate → assess`` lifecycle because the operator
drives the inputs directly. It still emits ``Evidence`` objects so
results land in the existing Evidence Log.

Safety invariants (spec requirement):

1. The only network egress is ``HttpClient.send()``. There is no
   raw ``httpx`` path. ``ScopeController.check()`` runs on every
   request (host / path / mutating-method gates) before the request
   leaves the process.

2. ``LimitsConfig.max_requests`` is the global budget — once
   exceeded, ``HttpClient`` raises and the runner stops.

3. In Preset mode, payloads come from the check's predefined set
   (``_DELAY_PAYLOADS``, ``_CANARIES``). The endpoint takes a
   ``check_id`` and a ``payload_index`` (not a payload string), and
   the server resolves ``payload[check_id][payload_index]``.

4. In Custom mode, the operator provides the raw payload. This
   requires an explicit ``confirmed_dwyor=true`` flag in the request
   body — set only after a two-gate client-side confirmation.
   The endpoint refuses the request if the flag is missing or false.

5. All probes (Preset and Custom) are logged with target + payload
   index + a UUID for audit. Custom probes additionally log the
   payload content because the operator wrote it themselves — that's
   the whole point of the audit trail.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from redveil.config import LimitsConfig
from redveil.core.scope import ScopeController
from redveil.http.client import HttpClient
from redveil.http.request import Request
from redveil.http.session import AnonymousAuth, AuthProvider

log = logging.getLogger(__name__)


# Custom probe check_id. Distinct from any registered check so the
# Evidence Log can flag custom probes in the UI.
CUSTOM_PROBE_CHECK_ID = "custom-probe"

# The exact string the operator must type into Gate 2 to unlock the
# Run button. Exposed at module level so the test suite and the
# backend endpoint share the same constant.
DWYOR_CONFIRM_STRING = "I ACKNOWLEDGE DWYOR"

# HTTP methods ProbeRunner is allowed to send. Mutating methods
# (POST/PUT/DELETE/PATCH) are still gated by ScopeController's
# mutating-path rules; we just don't restrict the operator's choice
# here.
_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})


@dataclass
class ProbeSample:
    """One probe result. Mirrors the ``ReplaySample`` shape so the
    UI can render with the same component.
    """
    index: int
    payload: str
    payload_index: int | None  # None for custom mode
    status_code: int
    elapsed_ms: float
    body_length: int
    body_excerpt: str
    error: str | None
    method: str
    target_url: str
    position: str  # parameter name or path-segment
    started_at: str


@dataclass
class ProbeRunResult:
    samples: list[ProbeSample] = field(default_factory=list)
    total_requested: int = 0
    total_executed: int = 0
    skipped: int = 0
    started_at: str = ""
    completed_at: str = ""
    scope_rejections: int = 0  # requests that ScopeController rejected


class ProbeRunner:
    """Runs a sequence of payloads through the same HttpClient the
    check pipeline uses, so scope/limits/rate-limit apply uniformly.

    Usage::

        scope = ScopeController(scope_cfg)
        limits = limits_cfg  # re-use the active scan's limits
        async with HttpClient(scope, limits, auth=auth) as http:
            runner = ProbeRunner(http, scope)
            result = await runner.run(
                target_url="https://api.example.com/users",
                payloads=["1", "2", "3"],
                method="GET",
                position="id",
            )

    The HttpClient is passed in (created per-probe-session by the
    caller) so we don't duplicate scope/limits/auth wiring in the
    runner. ``scope`` is kept for rejection counting.
    """

    def __init__(self, http: HttpClient, scope: ScopeController) -> None:
        self._http = http
        self._scope = scope

    async def run(
        self,
        *,
        target_url: str,
        payloads: list[str],
        method: str = "GET",
        position: str = "",
        position_kind: str = "query",  # "query" | "path" | "body"
        path_template: str | None = None,  # if position_kind="path", e.g. "/users/{id}"
        body_template: str | None = None,  # raw body when position_kind="body"
        extra_headers: dict[str, str] | None = None,
    ) -> ProbeRunResult:
        """Run each payload through HttpClient.send().

        ``position_kind`` controls how each payload is substituted:

        - "query" (default): appends/replaces ``?position=<payload>``
          on the target URL.
        - "path": substitutes into ``path_template`` (must contain a
          ``{payload}`` placeholder). URL becomes
          ``base_url + path_template.format(payload=payload)``.
        - "body": sends a POST/PUT with ``body_template`` where the
          payload is substituted; payload must contain a
          ``{payload}`` placeholder.

        Returns ProbeRunResult; caller is responsible for persisting
        evidence + creating a synthetic finding.
        """
        method = method.upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"unsupported method: {method}")
        if not payloads:
            raise ValueError("payloads must be a non-empty list")

        result = ProbeRunResult(
            total_requested=len(payloads),
        )
        for idx, payload in enumerate(payloads):
            url, body, err = self._build_request(
                target_url=target_url,
                position=position,
                position_kind=position_kind,
                path_template=path_template,
                body_template=body_template,
                payload=payload,
            )
            if err is not None:
                result.skipped += 1
                log.warning(
                    "probe: skipping payload #%d — %s", idx, err,
                )
                continue
            request = Request(
                method=method,
                url=url,
                body=body,
                headers=extra_headers or {},
                purpose="custom-probe",
                purpose_extra=f"payload_index={idx}",
            )
            # Stash the payload on the request for evidence gathering
            # (so the Evidence row carries the operator-supplied payload
            # in finding_data, NOT in the request body which is sanitized).
            request._custom_probe_payload = payload  # type: ignore[attr-defined]
            try:
                response = await self._http.send(request)
            except Exception as exc:  # noqa: BLE001
                # ScopeController raises here for out-of-scope requests.
                # We capture the rejection as a sample with an error
                # field rather than letting it abort the whole probe.
                sample = ProbeSample(
                    index=idx,
                    payload=payload,
                    payload_index=None,
                    status_code=0,
                    elapsed_ms=0.0,
                    body_length=0,
                    body_excerpt="",
                    error=str(exc),
                    method=method,
                    target_url=url,
                    position=position,
                    started_at="",
                )
                result.samples.append(sample)
                result.total_executed += 1
                result.scope_rejections += 1
                log.info("probe: payload #%d rejected by scope: %s", idx, exc)
                continue
            sample = ProbeSample(
                index=idx,
                payload=payload,
                payload_index=None,
                status_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                body_length=len(response.body or ""),
                body_excerpt=(response.body or "")[:200],
                error=response.error,
                method=method,
                target_url=url,
                position=position,
                started_at=response.timestamp.isoformat() if response.timestamp else "",
            )
            result.samples.append(sample)
            result.total_executed += 1

        result.completed_at = result.samples[-1].started_at if result.samples else ""
        log.info(
            "probe: complete target=%s method=%s requested=%d executed=%d skipped=%d scope_rejections=%d",
            target_url,
            method,
            result.total_requested,
            result.total_executed,
            result.skipped,
            result.scope_rejections,
        )
        return result

    def _build_request(
        self,
        *,
        target_url: str,
        position: str,
        position_kind: str,
        path_template: str | None,
        body_template: str | None,
        payload: str,
    ) -> tuple[str, str | None, str | None]:
        """Returns (url, body, error). error is set if the template is
        malformed and the payload cannot be substituted.
        """
        if position_kind == "query":
            # Append or replace the ``position`` query parameter.
            from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
            parsed = urlparse(target_url)
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            qs[position] = payload
            new_query = urlencode(qs)
            return (
                urlunparse(parsed._replace(query=new_query)),
                None,
                None,
            )
        if position_kind == "path":
            if not path_template or "{payload}" not in path_template:
                return target_url, None, "path_template must contain {payload}"
            # Substitute payload in the path template.
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(target_url)
            new_path = path_template.replace("{payload}", payload)
            return (
                urlunparse(parsed._replace(path=new_path)),
                None,
                None,
            )
        if position_kind == "body":
            if not body_template or "{payload}" not in body_template:
                return target_url, None, "body_template must contain {payload}"
            return target_url, body_template.replace("{payload}", payload), None
        return target_url, None, f"unknown position_kind: {position_kind}"


def new_probe_id() -> str:
    """Stable identifier for a probe session (used as synthetic
    scan name + finding title prefix).
    """
    return f"PRB-{uuid.uuid4().hex[:8].upper()}"


__all__ = [
    "CUSTOM_PROBE_CHECK_ID",
    "DWYOR_CONFIRM_STRING",
    "ProbeRunner",
    "ProbeSample",
    "ProbeRunResult",
    "new_probe_id",
]