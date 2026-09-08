"""CLI entry point for redveil-ui.

Subcommands:
  - init: first-run setup (pick port, generate config, init DB, DWYOR check)
  - start: run the bundled server (API + frontend on one port)
"""
from __future__ import annotations

from typing import Optional

import typer

app = typer.Typer(
    help="redveil-ui: self-hosted web dashboard for redveil security scans",
    no_args_is_help=True,
)


@app.command()
def init(
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Backend port (default: 8000)"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir", help="Data directory (default: ~/.redveil-ui/data)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip DWYOR confirmation"),
    config: Optional[str] = typer.Option(None, "--config", help="Path to config file (default: ~/.redveil-ui/config.yaml)"),
):
    """First-run setup: pick port, generate config, initialize database."""
    from redveil_ui.first_run import run_init
    run_init(port=port, data_dir=data_dir, skip_dwyor=yes, config_path=config)


@app.command()
def start(
    config: Optional[str] = typer.Option(None, "--config", help="Path to config file (default: ~/.redveil-ui/config.yaml)"),
):
    """Start the server (API + frontend on one port)."""
    from redveil_ui.server import run_server
    run_server(config_path=config)


def main():
    app()


if __name__ == "__main__":
    main()