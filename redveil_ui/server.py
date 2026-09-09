"""Server runner for the redveil-ui installer.

Reads config from ~/.redveil-ui/config.yaml (or $REDVEIL_CONFIG),
configures the FastAPI app from redveil_ui.api.main, mounts the
bundled Next.js frontend as static files, and runs uvicorn on
the configured port.
"""
from __future__ import annotations

import os
from pathlib import Path

import uvicorn
import yaml
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

WEB_DIR = Path(__file__).parent / "web"


def _placeholder_for(path: str) -> str | None:
    """Map a dynamic route path to its static-export placeholder.

    Next.js's ``output: 'export'`` only pre-renders dynamic routes for
    the values returned by ``generateStaticParams``. For our SPA those
    return a single ``_`` placeholder, so a request like
    ``/findings/WPOC-001`` must be served from ``findings/_.html`` so
    the client-side router can hydrate the right page. Static pages
    (no dynamic segment) are served directly and don't need a
    placeholder.

    The static-export layout is::

        web/<route>/_.html            (top-level dynamic page)
        web/<route>/_/<sub>.html       (nested dynamic page)

    Both are pre-rendered for ``wpoc_id="_"`` (etc.) by each route's
    ``generateStaticParams``.
    """
    parts = path.split("/")
    if len(parts) < 2 or not parts[0]:
        return None
    if parts[0] not in {"findings", "scans", "targets"}:
        return None
    # Top-level: /<route>/<id>        -> <route>/_.html
    # Nested:   /<route>/<id>/<sub>    -> <route>/_/<sub>.html
    if len(parts) == 2:
        return f"{parts[0]}/_.html"
    return f"{parts[0]}/_/{'/'.join(parts[2:])}.html"


def _resolve_spa_path(path: str) -> str | None:
    """Resolve a URL path to the SPA's pre-rendered HTML file.

    Next.js's ``output: "export"`` produces a mix of three file
    layouts depending on the route type, and we have to probe all of
    them because the URL alone does not tell us which form the route
    used at build time. The list below is the AUTHORITATIVE order to
    check; add new layouts here as they appear, do not special-case them
    at the call site.

    Try, in order:

      1. ``web/<path>`` is a file on disk
         (e.g. ``/_next/static/chunks/main.js`` — assets with their
         own extension baked in)

      2. ``web/<path>.html`` is a file
         (Next strips ``.html`` from the served URL but writes the
         file with that extension — this is the default form for
         static pages like ``/probe-builder`` → ``probe-builder.html``)

      3. ``web/<path>/index.html`` is a file
         (static page that opted into ``trailingSlash: true`` at build
         time, OR a folder with no trailing slash whose only entry is
         ``index.html`` — both produce this layout)

      4. ``web/<route>/_.html`` is a file, for top-level dynamic routes
         where ``<route>`` is the first path segment and the
         ``generateStaticParams`` placeholder was emitted as
         ``<id>="_"``. Only the routes that have dynamic segments
         (``findings``, ``scans``, ``targets``) are eligible, and the
         request must have at least one segment after the route name.

      5. ``web/<route>/_/<sub>.html`` is a file, for nested dynamic
         routes (e.g. ``/scans/1/evidence`` → ``scans/_/evidence.html``,
         ``/findings/WPOC-001/replay`` → ``findings/_/replay.html``).

    Returns the relative path under ``web/`` of the HTML to serve, or
    ``None`` if no match. The caller falls back to ``web/index.html``
    in that case (the SPA shell renders a 404 client-side).
    """
    # (1) file as-is
    if (WEB_DIR / path).is_file():
        return path

    # (2) flat-file form
    flat = WEB_DIR / f"{path}.html"
    if flat.is_file():
        return f"{path}.html"

    # (3) directory form
    if (WEB_DIR / path / "index.html").is_file():
        return f"{path}/index.html"

    # (4) top-level dynamic placeholder: /<route>/<id>
    if _placeholder_for(path) is not None:
        placeholder = _placeholder_for(path)
        if placeholder is not None and (WEB_DIR / placeholder).is_file():
            return placeholder

    return None


def _resolve_config_path(config_path: str | None) -> Path:
    """Resolve the config file path without loading it."""
    return Path(
        config_path
        or os.environ.get("REDVEIL_CONFIG", Path.home() / ".redveil-ui" / "config.yaml")
    ).expanduser()


def _find_free_port(host: str, preferred: int) -> int:
    """Walk forward from preferred until free on host (like first_run.find_free_port)."""
    import socket

    port = preferred
    # For 0.0.0.0 we probe 0.0.0.0; for 127.0.0.1 probe that; fallback to 127.0.0.1 if host is ::1 etc.
    probe_host = host if host in {"127.0.0.1", "0.0.0.0", "::1"} else "127.0.0.1"
    while port < 65535:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((probe_host, port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("No free port in 1..65534")


def _load_config(config_path: str | None) -> dict:
    """Load config from REDVEIL_CONFIG env or default ~/.redveil-ui/config.yaml."""
    path = _resolve_config_path(config_path)
    if not path.exists():
        raise SystemExit(
            f"Config not found at {path}. Run 'redveil-ui init' first."
        )
    return yaml.safe_load(path.read_text())


def run_server(config_path: str | None = None):
    config = _load_config(config_path)
    data_dir = Path(config["data_dir"])

    # === Step 0: fail-closed auth check (0.2.0) ===
    # MUST run before the listening socket is opened: a non-loopback
    # bind without an API key in any storage location refuses to start.
    from redveil_ui.api.auth import check_auth_or_fail  # noqa: E402

    check_auth_or_fail(bind=str(config["host"]))

    # Set the env var BEFORE any code that imports api.db, so the
    # lazy engine picks up the right path on first get_engine() call.
    os.environ["REDVEIL_DATA_DIR"] = str(data_dir)

    # Now safe to import — api.db resolves DATA_DIR from REDVEIL_DATA_DIR
    # env var at module load, so DB_PATH is already pointing at the right
    # place without any post-import reassignment.
    data_dir.mkdir(parents=True, exist_ok=True)
    from redveil_ui.api import db as api_db  # noqa: E402
    from redveil_ui.api.main import app as fastapi_app  # noqa: E402

    # Initialize DB schema on startup
    import asyncio
    asyncio.run(_init_schema_async())

    app: FastAPI = fastapi_app
    app.state.data_dir = data_dir
    app.state.reports_dir = Path(config["reports_dir"])

    # === Step A: register all /api/* routers FIRST ===
    # (the FastAPI app is built in redveil_ui.api.main with all routers
    # already included at import time, so they're already on `app`)

    # === Step B: mount static assets + SPA catch-all LAST ===
    if WEB_DIR.exists() and (WEB_DIR / "index.html").exists():
        static_dir = WEB_DIR / "_next" / "static"
        if static_dir.exists():
            app.mount(
                "/_next/static",
                StaticFiles(directory=str(static_dir)),
                name="static",
            )

        @app.get("/", include_in_schema=False)
        @app.head("/", include_in_schema=False)
        async def spa_root():
            return FileResponse(str(WEB_DIR / "index.html"))

        @app.get("/{path:path}", include_in_schema=False)
        @app.head("/{path:path}", include_in_schema=False)
        async def spa_fallback(path: str):
            """Serve the SPA shell for any non-API path.

            For dynamic routes (e.g. /findings/<id>, /scans/<id>/evidence),
            the Next.js static export only pre-renders a single
            ``_``-suffixed placeholder per route. We map the requested
            path to that placeholder so the SPA client-side router
            takes over and renders the correct page. Real HTML assets
            inside the bundle (CSS, fonts, etc.) are served directly.
            """
            spa = _resolve_spa_path(path)
            if spa is not None:
                return FileResponse(str(WEB_DIR / spa))
            return FileResponse(str(WEB_DIR / "index.html"))
    else:
        import logging
        log = logging.getLogger("redveil_ui")
        log.warning(
            "Frontend bundle not found in %s — only API routes will be served",
            WEB_DIR,
        )

    # === Step C: pick a free port if configured one is busy (start-time fallback) ===
    # init already walked forward, but the port may have been taken between
    # init and start. Walk again so `redveil-ui start` never fails with
    # "Address already in use" — it just picks the next free port and
    # persists it back to the config file so the operator's next start
    # doesn't retry the same busy port.
    preferred_port = int(config["port"])
    host = str(config["host"])
    chosen_port = _find_free_port(host, preferred_port)
    if chosen_port != preferred_port:
        import yaml as _yaml

        cfg_path = _resolve_config_path(config_path)
        config["port"] = chosen_port
        try:
            cfg_path.write_text(_yaml.safe_dump(config))
        except OSError:
            pass  # best-effort persist; start still proceeds on chosen_port
        # Use rich if available, else plain print
        try:
            from rich.console import Console as _Console

            _Console().print(
                f"[yellow]Port {preferred_port} in use, using {chosen_port}.[/yellow]"
            )
        except Exception:
            print(f"Port {preferred_port} in use, using {chosen_port}.")

    # Friendly link output (always, even when port didn't change)
    tls_cfg = config.get("tls", {})
    tls_enabled = bool(tls_cfg.get("enabled"))
    scheme = "https" if tls_enabled else "http"
    try:
        from rich.console import Console as _Console2

        _Console2().print(f"\n[bold green]Here's the link:[/bold green] {scheme}://{host}:{chosen_port}/")
        _Console2().print(f"[dim]API: {scheme}://{host}:{chosen_port}/api/info  •  Health: {scheme}://{host}:{chosen_port}/healthz[/dim]\n")
        if tls_enabled:
            _Console2().print("[dim]TLS: Local CA — run `redveil-ui tls install-ca` on clients to remove browser warning[/dim]\n")
    except Exception:
        print(f"\nHere's the link: {scheme}://{host}:{chosen_port}/")

    # Start uvicorn — TLS if enabled
    if tls_enabled:
        certfile = tls_cfg.get("certfile")
        keyfile = tls_cfg.get("keyfile")
        # Auto-ensure certs exist (e.g. after manual config edit)
        if not certfile or not keyfile or not Path(certfile).exists() or not Path(keyfile).exists():
            try:
                from redveil_ui.tls import ensure_tls_assets

                _, certfile_p, keyfile_p = ensure_tls_assets()
                certfile, keyfile = str(certfile_p), str(keyfile_p)
            except SystemExit as e:
                print(f"TLS enabled but cert generation failed: {e}")
                print("Falling back to http. Fix with `redveil-ui init --tls --yes`")
                tls_enabled = False
            except Exception as e:  # noqa: BLE001
                print(f"TLS cert error: {e}")
                tls_enabled = False
        if tls_enabled:
            uvicorn.run(
                app,
                host=host,
                port=chosen_port,
                log_level="info",
                ssl_certfile=certfile,
                ssl_keyfile=keyfile,
            )
            return
    uvicorn.run(
        app,
        host=host,
        port=chosen_port,
        log_level="info",
    )


async def _init_schema_async():
    from sqlalchemy import text

    from redveil_ui.api.db import Base, get_engine

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # 0.3.0 migration: add notes columns if missing (existing DBs)
        try:
            result = await conn.execute(text("PRAGMA table_info(findings)"))
            cols = {row[1] for row in result.fetchall()}
            if "notes" not in cols:
                await conn.execute(text("ALTER TABLE findings ADD COLUMN notes TEXT"))
            if "annotated_at" not in cols:
                await conn.execute(text("ALTER TABLE findings ADD COLUMN annotated_at DATETIME"))
        except Exception:
            pass
    await engine.dispose()