"""First-run interactive setup for the redveil-ui installer.

Tasks:
- Pick a free port (default 8000, walk forward if in use)
- Confirm DWYOR acknowledgment (skip with --yes)
- Write config to ~/.redveil-ui/config.yaml (FIXED path, regardless
  of --data-dir; the data_dir is stored INSIDE the config)
- Initialize the SQLite database schema
- Print a summary so the user knows where to find things
"""
from __future__ import annotations

import os
import socket
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.prompt import Confirm

console = Console()

DEFAULT_PORT = 8000
DEFAULT_HOST = "127.0.0.1"
DEFAULT_GATE_MODE = "non_interactive"
DEFAULT_MAX_DESTRUCTIVE_LEVEL = "L2"
DEFAULT_ALLOW_DESTRUCTIVE = False
DEFAULT_CONFIG_DIR = Path.home() / ".redveil-ui"
DEFAULT_DATA_DIR = DEFAULT_CONFIG_DIR / "data"


def find_free_port(preferred: int) -> int:
    """Walk forward from `preferred` until we find a free port."""
    port = preferred
    while port < 65535:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("No free port in 1..65534")


def run_init(
    port: int | None,
    data_dir: str | None,
    skip_dwyor: bool,
    config_path: str | None,
):
    # 1. Resolve config location (FIXED, regardless of --data-dir).
    # The data_dir is stored INSIDE the config, not used to compute
    # the config path. This ensures `redveil-ui start` can always find
    # the config without needing the --data-dir flag.
    cfg_path = (
        Path(config_path).expanduser()
        if config_path
        else DEFAULT_CONFIG_DIR / "config.yaml"
    )
    cfg_path.parent.mkdir(parents=True, exist_ok=True)

    # 2. Resolve data directory
    if data_dir is None:
        data_dir_path = DEFAULT_DATA_DIR
    else:
        data_dir_path = Path(data_dir).expanduser().resolve()
    data_dir_path.mkdir(parents=True, exist_ok=True)

    # 3. Pick port (auto-detect if default is busy)
    preferred = port if port is not None else DEFAULT_PORT
    chosen_port = find_free_port(preferred)
    if chosen_port != preferred:
        console.print(
            f"[yellow]Port {preferred} in use, using {chosen_port}.[/yellow]"
        )

    # 4. DWYOR acknowledgement
    if not skip_dwyor:
        console.print("\n[bold red]DWYOR — Do With Your Own Risk[/bold red]")
        console.print(
            "By running redveil-ui you accept full responsibility for any\n"
            "security testing you perform. Active probes can damage systems\n"
            "if misused. Ensure you have explicit permission to probe any target."
        )
        if not Confirm.ask("Do you understand and accept?", default=False):
            raise typer.Exit(code=1)

    # 5. Generate config
    config = {
        "host": DEFAULT_HOST,  # FIXED — LAN exposure is opt-in (not via init)
        "port": chosen_port,
        "data_dir": str(data_dir_path),
        "db_path": str(data_dir_path / "redveil-ui.db"),
        "reports_dir": str(data_dir_path / "reports"),
        # Safety defaults — match the API schema defaults so the installer's
        # persisted config is a complete, self-documenting record of the
        # install-time safety posture. Hand-edits to ~/.redveil-ui/config.yaml
        # can override these; per-scan overrides via the API still win.
        "gate_mode": DEFAULT_GATE_MODE,
        "max_destructive_level": DEFAULT_MAX_DESTRUCTIVE_LEVEL,
        "allow_destructive": DEFAULT_ALLOW_DESTRUCTIVE,
    }
    cfg_path.write_text(yaml.safe_dump(config))

    # 6. Initialize DB schema
    # Set the env var BEFORE importing api.db so the lazy engine
    # picks up the right path on first get_engine() call.
    os.environ["REDVEIL_DATA_DIR"] = config["data_dir"]
    from redveil_ui.api import db as api_db  # noqa: E402 (deliberate late import)
    api_db.DATA_DIR = Path(config["data_dir"])
    api_db.DB_PATH = Path(config["db_path"])
    api_db.DATA_DIR.mkdir(parents=True, exist_ok=True)
    import asyncio
    asyncio.run(_init_schema())

    # 7. Print summary
    console.print("\n[bold green]redveil-ui initialized[/bold green]")
    console.print(f"  Config:    {cfg_path}")
    console.print(f"  Database:  {config['db_path']}  [green](schema created)[/green]")
    console.print(f"  Reports:   {config['reports_dir']}")
    console.print(f"  URL:       http://{DEFAULT_HOST}:{chosen_port}/")
    console.print(
        f"  Safety:    gate_mode={config['gate_mode']} "
        f"max_destructive_level={config['max_destructive_level']} "
        f"allow_destructive={config['allow_destructive']}"
    )
    console.print(f"\nRun [bold]redveil-ui start[/bold] to launch.")
    console.print(
        "\n[dim]Tip: redveil-ui is pipx-installable. See README.[/dim]"
    )


async def _init_schema():
    from redveil_ui.api.db import Base, get_engine
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()