"""Probe Builder runtime — vendored in redveil-ui.

This module provides the ProbeRunner that the Probe Builder feature
(`/probe-builder` in the UI) uses to dispatch operator-supplied payloads
through the production HttpClient.

Why it lives here, not in ``redveil.probe.runner``: redveil 1.9.6 does
not expose a public probe module. The UI's Probe Builder needs the
runner to work end-to-end when installed from PyPI, so the implementation
lives in the UI package. When redveil eventually exposes
``redveil.probe.runner`` as public, the import in
``redveil_ui.api.routes.probes`` will pick that up first and this
module becomes a fallback.

The runner is intentionally minimal: it consumes the production
HttpClient so the same ScopeController, LimitsConfig, and rate limiting
apply as for automatic checks. Operators get exactly the same wire-
level behavior as an automated check would.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from redveil.config import ScopeConfig
from redveil.http.client import HttpClient, Request, Response

CUSTOM_PROBE_CHECK_ID = "custom-probe"
DWYOR_CONFIRM_STRING = "I have authorization to probe this target"


def new_probe_id() -> str:
    """Return a fresh probe id (uuid4 hex)."""
    return uuid.uuid4().hex


@dataclass
class ProbeSample:
    """One outbound attempt produced by the ProbeRunner.

    Mirrors the fields the route exposes in ProbeSampleOut — adding
    a field here is safe; renaming or removing is breaking.
    """

    index: int
    payload: str
    status_code: int = 0
    elapsed_ms: float = 0.0
    body_length: int = 0
    body_excerpt: str = ""
    error: str | None = None
    method: str = ""
    target_url: str = ""
    position: str = ""
    started_at: str = ""


@dataclass
class ProbeRunResult:
    """Aggregate result from one ``ProbeRunner.run()`` invocation."""

    total_requested: int = 0
    total_executed: int = 0
    skipped: int = 0
    scope_rejections: int = 0
    samples: list[ProbeSample] = field(default_factory=list)


class ProbeRunner:
    """Dispatches payloads through a scoped HttpClient.

    The runner is constructed per-probe-session by the route layer
    (no shared instance lives at module level) so each probe gets a
    fresh HttpClient built from the target's stored ``scope_yaml``.
    ScopeController and LimitsConfig are inherited from the HttpClient
    — the runner does not relax either.
    """

    def __init__(self, http: HttpClient, scope: ScopeConfig) -> None:
        self._http = http
        self._scope = scope

    async def run(
        self,
        *,
        target_url: str,
        payloads: list[str],
        method: str = "GET",
        position: str = "",
        position_kind: str = "query",
        path_template: str | None = None,
        body_template: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> ProbeRunResult:
        """Execute ``payloads`` against ``target_url`` sequentially.

        Each payload produces one ``ProbeSample``. The runner honors
        the HttpClient's scope_controller before dispatching the
        request — a scope rejection increments ``scope_rejections``
        and the sample is recorded with ``status_code=0`` and
        ``error="scope-rejected"`` so the operator can audit it.
        """
        result = ProbeRunResult(total_requested=len(payloads))

        for i, payload in enumerate(payloads):
            sample = ProbeSample(
                index=i,
                payload=payload,
                method=method,
                position=position,
                started_at=datetime.now(UTC).isoformat(),
            )

            try:
                url, body = self._build_request(
                    target_url=target_url,
                    payload=payload,
                    position=position,
                    position_kind=position_kind,
                    path_template=path_template,
                    body_template=body_template,
                )
            except ValueError as exc:
                sample.error = f"build-failed: {exc}"
                result.samples.append(sample)
                result.skipped += 1
                continue

            sample.target_url = url

            # Scope check — do not bypass. The HttpClient would refuse
            # anyway, but recording it here makes the operator's audit
            # trail explicit.
            try:
                if self._http.scope_controller is not None:
                    decision = self._http.scope_controller.check(url, method)
                    if not decision.allowed:
                        sample.error = "scope-rejected"
                        result.samples.append(sample)
                        result.scope_rejections += 1
                        result.skipped += 1
                        continue
            except AttributeError:
                # ScopeController API mismatch — fall back to HttpClient
                # enforcement. Should not happen with redveil >= 1.9.6.
                pass
            except Exception:  # noqa: BLE001
                # Defensive: a buggy scope controller must not abort
                # the whole probe session. Let HttpClient enforce it.
                pass

            try:
                req = Request(
                    method=method,
                    url=url,
                    headers=dict(extra_headers or {}),
                    body=body,
                    purpose="probe",
                )
                resp: Response = await self._http.send(req)
            except Exception as exc:  # noqa: BLE001
                sample.error = f"send-failed: {exc.__class__.__name__}: {exc}"
                result.samples.append(sample)
                result.skipped += 1
                continue

            sample.status_code = resp.status_code
            sample.elapsed_ms = resp.elapsed_ms
            sample.body_length = len(resp.body or "")
            sample.body_excerpt = (resp.body_excerpt or "")[:512]
            if resp.error:
                sample.error = str(resp.error)

            result.samples.append(sample)
            result.total_executed += 1

        return result

    # -- internal helpers ------------------------------------------------

    @staticmethod
    def _build_request(
        *,
        target_url: str,
        payload: str,
        position: str,
        position_kind: str,
        path_template: str | None,
        body_template: str | None,
    ) -> tuple[str, str | None]:
        """Apply ``payload`` into the request URL or body per ``position_kind``.

        Returns ``(url, body)`` — ``body`` is None for non-body positions.
        Raises ``ValueError`` if the templates are missing for path/body mode.
        """
        if position_kind == "query":
            return _inject_query(target_url, position, payload), None
        if position_kind == "path":
            if not path_template:
                raise ValueError("path_template is required for position_kind=path")
            return _inject_path(target_url, path_template, payload), None
        if position_kind == "body":
            if body_template is None:
                raise ValueError("body_template is required for position_kind=body")
            return target_url, _inject_body(body_template, payload)
        raise ValueError(f"unknown position_kind: {position_kind}")


def _inject_query(url: str, key: str, value: str) -> str:
    """Append/replace a query parameter on ``url``.

    If ``key`` is empty, the payload is added as ``?{value}`` (bare
    key=value with no key name). If ``key`` matches an existing
    parameter, that parameter's value is replaced.
    """
    parsed = urlparse(url)
    existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if key:
        existing[key] = value
    elif value:
        # No key — use the first token of the payload as the key
        # if the operator didn't specify one.
        if "=" in value:
            k, _, v = value.partition("=")
            existing[k] = v
        else:
            existing["payload"] = value
    new_query = urlencode(existing, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _inject_path(url: str, template: str, payload: str) -> str:
    """Substitute ``payload`` into ``template`` then append to the URL path.

    The template is a relative path (e.g. ``/api/v1/users/{p}/profile``).
    The base URL's path is preserved; the template replaces it.
    """
    parsed = urlparse(url)
    rendered = template.replace("{p}", payload).replace("{payload}", payload)
    if not rendered.startswith("/"):
        rendered = "/" + rendered
    return urlunparse(parsed._replace(path=rendered))


def _inject_body(template: str, payload: str) -> str:
    """Substitute ``payload`` into ``template``.

    Template uses ``{p}`` or ``{payload}`` as the placeholder. If
    neither is present, the payload is appended with a newline.
    """
    if "{p}" in template or "{payload}" in template:
        return template.replace("{p}", payload).replace("{payload}", payload)
    return template + payload


__all__ = [
    "CUSTOM_PROBE_CHECK_ID",
    "DWYOR_CONFIRM_STRING",
    "ProbeRunner",
    "ProbeRunResult",
    "ProbeSample",
    "new_probe_id",
]
