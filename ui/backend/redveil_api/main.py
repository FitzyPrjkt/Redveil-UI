"""FastAPI application entry point for the redveil UI backend.

* CORS allows the local frontend on either ``localhost`` or ``127.0.0.1``.
* Binds to 127.0.0.1:8000 — never 0.0.0.0.
* Lifespan initializes the DB schema and warms the plugin registry.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from redveil_api.db import DATA_DIR, Base, get_engine
from redveil_api.routes import (
    checks,
    config,
    entropy,
    findings,
    issue_definitions,
    lab,
    scans,
    scope,
    targets,
)
from redveil_api.scanner import Scanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s | %(message)s")
log = logging.getLogger("redveil_api")

CORS_ORIGINS = [
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:3001",
    "http://localhost:3001",
]


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
    log.info("DB schema initialized at %s", engine.url)

    # Stash the Scanner on app state so route modules can find it.
    # The Scanner builds the plugin registry internally (cacheable on
    # first hit).
    from redveil_api.db import get_session_factory

    _app.state.scanner = Scanner(session_factory=get_session_factory())
    log.info("Scanner ready")
    try:
        yield
    finally:
        await engine.dispose()


app = FastAPI(
    title="redveil API",
    description="FastAPI backend for the redveil security scanner UI.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root() -> dict:
    return {
        "service": "redveil-api",
        "version": "0.1.0",
        "endpoints": [
            "/api/targets",
            "/api/scans",
            "/api/findings",
            "/api/checks",
            "/api/lab",
        ],
    }


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


# Routers
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(checks.router, prefix="/api/checks", tags=["checks"])
app.include_router(lab.router, prefix="/api/lab", tags=["lab"])
app.include_router(config.router, prefix="/api/config", tags=["config"])
app.include_router(scope.router, prefix="/api", tags=["scope"])
app.include_router(issue_definitions.router, prefix="/api", tags=["issue-definitions"])
app.include_router(entropy.router, prefix="/api/entropy", tags=["entropy"])
