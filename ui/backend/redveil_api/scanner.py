"""Scanner wrapper around the redveil Orchestrator.

The :class:`Scanner` builds a full redveil stack (config + http + orchestrator)
and runs it as a background asyncio task. It subscribes to the orchestrator's
event bus and translates every relevant event into a dict that the SSE
endpoint streams to the browser.
"""

from __future__ import annotations

import asyncio
import json
import logging
import traceback
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from sqlalchemy.ext.asyncio import async_sessionmaker

from redveil.config import (
    AuthorizationConfig,
    AuthConfig,
    EnvironmentConfig,
    LimitsConfig,
    RedVeilConfig,
    ReportingConfig,
    SafetyProfile,
    ScopeConfig,
    TargetConfig,
)
from redveil.core.event_bus import Event, EventBus, EventType
from redveil.core.lifecycle import ScanContext
from redveil.core.orchestrator import Orchestrator, OrchestratorDeps
from redveil.core.scope import ScopeController
from redveil.findings.finding import Finding
from redveil.http.client import HttpClient
from redveil.http.session import AnonymousAuth
from redveil.plugins.loader import build_default_registry

from redveil_api.models import Finding as FindingORM
from redveil_api.schemas import CheckOut

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

OUTPUT_BASE_DIR = Path("/workspace/projects/Redveil/data/reports")
DATA_DIR = Path("/workspace/projects/Redveil/data")


def _safe_target_name(url: str) -> str:
    """Turn a URL into a filesystem-safe directory name."""
    return url.replace("/", "_").replace(":", "_").rstrip("_") or "target"


def _build_config(
    target_url: str,
    target_name: str | None,
    scope_yaml: str | None,
    profile: str,
    max_requests: int | None,
    rps: float | None,
    max_destructive_level: str = "L2",
    allow_destructive: bool = False,
) -> RedVeilConfig:
    """Construct a RedVeilConfig from UI-friendly kwargs.

    If ``scope_yaml`` is provided we merge the scope block on top of the
    defaults; otherwise we auto-allow the target host so the scan can run
    against the URL the user picked.
    """
    profile_enum = SafetyProfile(profile.lower())

    # Auto-allow the target's host so the user doesn't have to author a
    # full scope file just to launch a scan.
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()

    scope_cfg: dict[str, Any] = {
        "allowed_hosts": [host] if host else [],
        "allowed_paths": ["/*"],
        "follow_redirects": True,
        "max_redirects": 5,
    }
    if scope_yaml:
        try:
            user = yaml.safe_load(scope_yaml) or {}
            if isinstance(user, dict):
                # user might be a full RedVeilConfig dict or just a scope block
                if "allowed_hosts" in user or "allowed_paths" in user:
                    scope_cfg.update({k: v for k, v in user.items() if k in scope_cfg})
                elif "scope" in user and isinstance(user["scope"], dict):
                    scope_cfg.update(
                        {k: v for k, v in user["scope"].items() if k in scope_cfg}
                    )
        except yaml.YAMLError as e:
            log.warning("failed to parse scope_yaml, using defaults: %s", e)

    limits = LimitsConfig()
    if max_requests is not None:
        limits.max_requests = max_requests
    if rps is not None:
        limits.requests_per_second = rps

    # AuthorizationConfig already accepts both "L1".."L6" and "1".."6" via
    # its own validator and normalizes to int. We can pass the string through.
    authorization = AuthorizationConfig(
        allow_destructive=allow_destructive,
        max_destructive_level=max_destructive_level,
    )

    return RedVeilConfig(
        target=TargetConfig(base_url=target_url, name=target_name),
        scope=ScopeConfig(**scope_cfg),
        limits=limits,
        authorization=authorization,
        auth=AuthConfig(),
        reporting=ReportingConfig(
            output_dir=OUTPUT_BASE_DIR,
            formats=["markdown", "json"],
        ),
        environment=EnvironmentConfig(environments="dev"),
        profile=profile_enum,
    )


class Scanner:
    """Run redveil scans on demand and stream events to an asyncio queue."""

    def __init__(
        self,
        session_factory: async_sessionmaker,
        output_base_dir: Path = OUTPUT_BASE_DIR,
    ) -> None:
        self._session_factory = session_factory
        self._output_base_dir = output_base_dir
        self._registry = build_default_registry()

    # ----- public API -----

    def list_checks(self) -> list[CheckOut]:
        """Return metadata for every registered check plugin."""
        out: list[CheckOut] = []
        for c in self._registry.all():
            meta = c.meta
            out.append(
                CheckOut(
                    id=meta.id,
                    name=meta.name,
                    category=meta.category.value,
                    safety_profile=meta.safety_profile.value,
                    description=meta.description,
                    max_risk=meta.max_risk,
                    version=meta.version,
                )
            )
        out.sort(key=lambda x: x.id)
        return out

    def get_check(self, check_id: str) -> CheckOut | None:
        for c in self._registry.all():
            if c.id == check_id:
                meta = c.meta
                return CheckOut(
                    id=meta.id,
                    name=meta.name,
                    category=meta.category.value,
                    safety_profile=meta.safety_profile.value,
                    description=meta.description,
                    max_risk=meta.max_risk,
                    version=meta.version,
                )
        return None

    async def run_scan(
        self,
        target_url: str,
        scope_yaml: str | None,
        profile: str,
        scan_id: int,
        target_name: str | None = None,
        max_destructive_level: str = "L2",
        allow_destructive: bool = False,
        gate_mode: str = "non_interactive",
    ) -> AsyncIterator[dict[str, Any]]:
        """Async-iterator wrapper around a single scan run.

        Yields dicts shaped like ``{"event": "...", "data": {...}}`` suitable
        for ``event_generator()``. Exceptions are turned into a terminal
        ``scan.failed`` event so the SSE stream always closes cleanly.
        """
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        # Run the producer concurrently; the consumer is the SSE endpoint.
        producer = asyncio.create_task(
            self._run_producer(
                queue=queue,
                target_url=target_url,
                scope_yaml=scope_yaml,
                profile=profile,
                scan_id=scan_id,
                target_name=target_name,
                max_destructive_level=max_destructive_level,
                allow_destructive=allow_destructive,
                gate_mode=gate_mode,
            )
        )
        try:
            while True:
                item = await queue.get()
                if item is None:
                    return
                yield item
        finally:
            if not producer.done():
                producer.cancel()
                try:
                    await producer
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass

    async def get_finding_data(self, scan_id: int, output_dir: str | None) -> list[dict]:
        """Read findings.json from the scan's output dir, if it exists.

        Returns the raw finding dicts as stored in the file. If the file
        isn't there yet (scan still running) an empty list is returned.
        """
        if not output_dir:
            return []
        p = Path(output_dir) / "findings.json"
        if not p.exists():
            return []
        try:
            payload = json.loads(p.read_text())
            return payload.get("findings", [])
        except (json.JSONDecodeError, OSError) as e:
            log.warning("failed to read findings.json at %s: %s", p, e)
            return []

    # ----- internals -----

    async def _run_producer(
        self,
        queue: asyncio.Queue[dict[str, Any] | None],
        target_url: str,
        scope_yaml: str | None,
        profile: str,
        scan_id: int,
        target_name: str | None,
        max_destructive_level: str = "L2",
        allow_destructive: bool = False,
        gate_mode: str = "non_interactive",
    ) -> None:
        """Build the redveil stack, hook events, run the scan."""
        try:
            cfg = _build_config(
                target_url=target_url,
                target_name=target_name,
                scope_yaml=scope_yaml,
                profile=profile,
                max_requests=None,
                rps=None,
                max_destructive_level=max_destructive_level,
                allow_destructive=allow_destructive,
            )
        except Exception as e:
            await self._put(
                queue,
                "scan.failed",
                {"scan_id": scan_id, "error": f"config error: {e}"},
            )
            await queue.put(None)
            return

        safe_name = _safe_target_name(target_name or target_url)
        target_output_dir = self._output_base_dir / f"scan-{scan_id}-{safe_name}"
        cfg.reporting.output_dir = target_output_dir

        # TODO: wire gate_mode into Orchestrator instantiation.
        # The Orchestrator instantiates its ActionGate internally today; for
        # now we just record the requested mode in the scan.started payload
        # so the operator's choice is visible in the SSE stream. Future
        # work: extend Orchestrator/OrchestratorDeps to accept a GateMode
        # and inject a pre-built ActionGate.
        log.info(
            "scan %s: gate_mode=%s, max_destructive_level=%s, allow_destructive=%s "
            "(gate_mode not yet wired to orchestrator)",
            scan_id,
            gate_mode,
            max_destructive_level,
            allow_destructive,
        )

        await self._put(
            queue,
            "scan.started",
            {
                "scan_id": scan_id,
                "target_url": target_url,
                "profile": profile,
                "max_destructive_level": max_destructive_level,
                "allow_destructive": allow_destructive,
                "gate_mode": gate_mode,
                "output_dir": str(target_output_dir),
                "started_at": datetime.now(UTC).isoformat(),
            },
        )

        bus = EventBus()
        # Subscribe BEFORE the orchestrator emits anything. We need to see
        # SCAN_STARTED too so the UI knows the orchestrator is alive.
        bus.subscribe_all(self._make_subscriber(queue, scan_id))

        ctx = ScanContext(target_name=target_name or target_url, run_id=f"scan-{scan_id}")

        try:
            async with HttpClient(
                scope=ScopeController(cfg.scope),
                limits=cfg.limits,
                auth=AnonymousAuth(),
                follow_redirects=cfg.scope.follow_redirects,
            ) as http:
                deps = OrchestratorDeps(
                    bus=bus,
                    registry=self._registry,
                    config=cfg,
                    http=http,
                )
                orch = Orchestrator(deps, ctx)
                await orch.run()
        except Exception as e:
            log.exception("scan %s failed", scan_id)
            await self._put(
                queue,
                "scan.failed",
                {
                    "scan_id": scan_id,
                    "error": str(e),
                    "type": type(e).__name__,
                    "traceback": traceback.format_exc().splitlines()[-5:],
                },
            )
            await queue.put(None)
            return

        # Persist findings to the DB so the UI can show them.
        await self._persist_findings(scan_id, ctx.findings, target_output_dir)

        await self._put(
            queue,
            "scan.completed",
            {
                "scan_id": scan_id,
                "findings_count": len(ctx.findings),
                "output_dir": str(target_output_dir),
                "completed_at": datetime.now(UTC).isoformat(),
            },
        )
        await queue.put(None)

    async def _persist_findings(
        self,
        scan_id: int,
        findings: list[Finding],
        output_dir: Path,
    ) -> None:
        """Write findings to the SQLite DB and the report directory."""
        # 1) Report files (markdown + json) — best effort, failures logged.
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            from redveil.reporting.markdown import write_report

            target_name = f"scan-{scan_id}"
            write_report(findings, target_name, output_dir)
        except Exception as e:
            log.warning("write_report failed for scan %s: %s", scan_id, e)

        # 2) DB rows — done with a fresh session.
        try:
            async with self._session_factory() as session:
                for f in findings:
                    row = FindingORM(
                        scan_id=scan_id,
                        wpoc_id=f.id,
                        severity=f.severity.value,
                        confidence=f.confidence.value,
                        status=f.status.value,
                        title=f.title,
                        endpoint=(
                            f"{f.target.method} {f.target.scheme}://"
                            f"{f.target.host}{f.target.endpoint}"
                            if f.target
                            else None
                        ),
                        check_id=f.check.id if f.check else None,
                        fingerprint=f.fingerprint,
                        finding_data=f.to_dict(),
                    )
                    session.add(row)
                await session.commit()
        except Exception as e:
            log.warning("failed to persist findings for scan %s: %s", scan_id, e)

    # ----- helpers -----

    @staticmethod
    async def _put(
        queue: asyncio.Queue[dict[str, Any] | None],
        event: str,
        data: dict[str, Any],
    ) -> None:
        await queue.put({"event": event, "data": data})

    def _make_subscriber(
        self, queue: asyncio.Queue[dict[str, Any] | None], scan_id: int
    ):
        """Return an event-bus subscriber that pushes SSE-shaped dicts."""

        async def subscriber(event: Event) -> None:
            if event.type is EventType.SCAN_STARTED:
                await self._put(
                    queue,
                    "scan.started",
                    {"scan_id": scan_id, "data": event.data},
                )
            elif event.type is EventType.CHECK_STARTED:
                await self._put(
                    queue,
                    "check.started",
                    {"scan_id": scan_id, "check_id": event.source, "data": event.data},
                )
            elif event.type is EventType.CHECK_ENDED:
                await self._put(
                    queue,
                    "check.completed",
                    {"scan_id": scan_id, "check_id": event.source, "data": event.data},
                )
            elif event.type is EventType.FINDING_DETECTED:
                await self._put(
                    queue,
                    "finding.detected",
                    {"scan_id": scan_id, "check_id": event.source, "data": event.data},
                )
            elif event.type is EventType.FINDING_CONFIRMED:
                await self._put(
                    queue,
                    "finding.detected",
                    {
                        "scan_id": scan_id,
                        "check_id": event.source,
                        "confirmed": True,
                        "data": event.data,
                    },
                )
            elif event.type is EventType.ERROR:
                await self._put(
                    queue,
                    "scan.failed",
                    {"scan_id": scan_id, "error": event.data},
                )

        return subscriber
