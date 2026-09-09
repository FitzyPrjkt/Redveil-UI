"""FastAPI application entry point for the redveil-ui API package.

* CORS origins are env-driven (REDVEIL_CORS_ORIGINS) — default empty so the
  self-host installer serves frontend from the same origin and needs no CORS.
* Binds to 127.0.0.1:8000 by default — never 0.0.0.0.
* Lifespan initializes the DB schema and warms the plugin registry.
* The SPA catch-all route (if any) is registered by ``redveil_ui.server``
  AFTER all API routers here — not in this module.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redveil_ui.api.db import DATA_DIR, Base, get_engine, get_session
from redveil_ui.api.routes import (
    auth,
    audit,
    checks,
    config,
    entropy,
    findings,
    issue_definitions,
    lab,
    probes,
    replay,
    scans,
    schedules,
    scope,
    targets,
)
from redveil_ui.api.models import Scan
from redveil_ui.api.scanner import Scanner

# Structured logging (0.3.0): LOG_FORMAT=json -> JSON lines for Loki/ELK
_log_format = os.environ.get("LOG_FORMAT", os.environ.get("REDVEIL_LOG_FORMAT", "")).lower()
if _log_format == "json":
    try:
        from pythonjsonlogger import jsonlogger  # type: ignore

        _handler = logging.StreamHandler()
        _handler.setFormatter(jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logging.basicConfig(level=logging.INFO, handlers=[_handler])
    except ImportError:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s | %(message)s")
else:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s | %(message)s")
log = logging.getLogger("redveil_ui.api")


def _cors_origins() -> list[str]:
    """Read CORS origins from REDVEIL_CORS_ORIGINS env var (comma-separated).

    Default empty — the self-host installer serves the frontend from the
    same origin, so no CORS is needed. Set the env var (e.g.
    ``REDVEIL_CORS_ORIGINS=http://localhost:3000``) when running the
    frontend on a different port in dev mode.
    """
    env = os.environ.get("REDVEIL_CORS_ORIGINS", "")
    if env:
        return [o.strip() for o in env.split(",") if o.strip()]
    return []  # self-host: frontend served by same backend, no CORS needed


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialize the DB schema and build the plugin registry."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    engine = get_engine()
    # Create tables on startup. For prod we'd run Alembic migrations, but
    # this project ships with `Base.metadata.create_all` since the schema
    # is small and migrations would be premature.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # 0.3.0 migration: add notes columns if missing (existing DBs)
        try:
            from sqlalchemy import text

            result = await conn.execute(text("PRAGMA table_info(findings)"))
            cols = {row[1] for row in result.fetchall()}
            if "notes" not in cols:
                await conn.execute(text("ALTER TABLE findings ADD COLUMN notes TEXT"))
            if "annotated_at" not in cols:
                await conn.execute(text("ALTER TABLE findings ADD COLUMN annotated_at DATETIME"))
        except Exception:
            pass
    log.info("DB schema initialized at %s", engine.url)

    # Recovery sweep (0.2.0): any scan left 'running' by a previous
    # unclean shutdown is transitioned to 'failed' BEFORE the app
    # accepts requests, so the dashboard never shows a dead scan as
    # live.
    from redveil_ui.api.scan_recovery import recover_orphan_scans

    recovery_factory = async_sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False
    )
    async with recovery_factory() as session:
        recovered = await recover_orphan_scans(session)
    if recovered:
        log.warning("recovered %d orphan scan(s) at startup", recovered)

    # Stash the Scanner on app state so route modules can find it.
    # The Scanner builds the plugin registry internally (cacheable on
    # first hit). Output dir is derived from DATA_DIR so the self-host
    # installer only needs to set REDVEIL_DATA_DIR (or app.state.data_dir)
    # before the lifespan runs.
    from redveil_ui.api.db import get_session_factory

    output_dir = getattr(_app.state, "data_dir", DATA_DIR) / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    _app.state.scanner = Scanner(
        session_factory=get_session_factory(),
        output_base_dir=output_dir,
    )
    log.info("Scanner ready (output_dir=%s)", output_dir)

    # Scheduler (0.3.0): load cron schedules
    try:
        from redveil_ui.api.scheduler import load_schedules

        await load_schedules()
    except Exception as e:  # noqa: BLE001
        log.warning("Scheduler failed to start: %s", e)

    try:
        yield
    finally:
        try:
            from redveil_ui.api.scheduler import stop_scheduler

            stop_scheduler()
        except Exception:
            pass
        await engine.dispose()


app = FastAPI(
    title="redveil-ui API",
    description="FastAPI backend for the redveil-ui security scanner UI.",
    version="0.2.0",
    lifespan=lifespan,
)

# Auth middleware (0.2.0): authenticates via X-API-Key header or HMAC
# session cookie; loopback short-circuits. Route-level gates decide
# what to do with request.state.is_authenticated.
from redveil_ui.api.middleware import (
    AuthMiddleware,
    AuditLogMiddleware,
    SecurityHeadersMiddleware,
    limiter,
)  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402
from slowapi import _rate_limit_exceeded_handler  # noqa: E402

# Security headers FIRST (outermost) so they stamp every response,
# including auth/audit rejections.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuthMiddleware)
# Audit AFTER auth in the stack: it reads request.state.is_authenticated.
app.add_middleware(AuditLogMiddleware)
# SlowAPIMiddleware INSIDE the audit/ auth middleware (S4 review fix):
# it enforces the limiter's default_limits on every route — the 60/min
# default advertised in the README is real, not just a dormant value.
# Registered after AuditLogMiddleware so 429 responses still flow out
# through the audit + security-headers layers. Rate limiting is a
# transport concern: it must run OUTSIDE auth (429 even when
# unauthenticated) but INSIDE the response-stamping middlewares.
# REDVEIL_RATE_LIMIT_DEFAULT=0/minute disables the blanket default at
# request time (decorated limits like login's 5/min stay active).
from redveil_ui.api.middleware import _OptionalDefaultLimitMiddleware  # noqa: E402

app.add_middleware(_OptionalDefaultLimitMiddleware)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORSMiddleware only registered when origins are explicitly configured
# (i.e. dev mode with split frontend/backend ports).
_cors = _cors_origins()
if _cors:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.get("/api/info")
async def api_info() -> dict:
    """Service discovery endpoint. Returns the API version and a list of
    available routes. The root path ``/`` is reserved for the SPA shell
    (see ``redveil_ui.server.run_server``).
    """
    return {
        "service": "redveil-ui-api",
        "version": "0.2.0",
        "endpoints": [
            "/api/targets",
            "/api/scans",
            "/api/findings",
            "/api/checks",
            "/api/lab",
            "/api/info",
            "/healthz",
        ],
    }


@app.get("/healthz")
async def healthz(session: AsyncSession = Depends(get_session)) -> dict:
    """Liveness + fleet snapshot (0.2.0, spec §9).

    Per-status counts are a stable, flat interface for monitoring tools:
    adding a sixth status is a deliberate breaking change to this shape.
    Cancelled is enumerated explicitly so it can never silently merge
    into 'failed'.
    """
    db_ok = (await session.execute(text("SELECT 1"))).scalar() == 1

    counts: dict[str, int] = {}
    for status in ("pending", "running", "completed", "failed", "cancelled"):
        counts[f"scans_{status}"] = await session.scalar(
            select(func.count()).select_from(Scan).where(Scan.status == status)
        )

    return {
        "status": "ok" if db_ok else "degraded",
        "db": "ok" if db_ok else "error",
        **counts,
    }


# Routers
# auth.router declares its own /api/auth prefix.
app.include_router(auth.router, tags=["auth"])
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(checks.router, prefix="/api/checks", tags=["checks"])
app.include_router(lab.router, prefix="/api/lab", tags=["lab"])
app.include_router(config.router, prefix="/api/config", tags=["config"])
app.include_router(scope.router, prefix="/api", tags=["scope"])
app.include_router(issue_definitions.router, prefix="/api", tags=["issue-definitions"])
app.include_router(entropy.router, prefix="/api/entropy", tags=["entropy"])
app.include_router(replay.router, prefix="/api/findings", tags=["replay"])
app.include_router(probes.router, prefix="/api/probes", tags=["probes"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"])
