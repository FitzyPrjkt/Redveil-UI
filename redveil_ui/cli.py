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
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip DWYOR + LAN exposure confirmations"),
    config: Optional[str] = typer.Option(None, "--config", help="Path to config file (default: ~/.redveil-ui/config.yaml)"),
    bind: Optional[str] = typer.Option(None, "--bind", help="Bind address (default: 127.0.0.1; non-loopback triggers the LAN exposure warning)"),
    tls: bool = typer.Option(False, "--tls", help="Enable TLS with Local CA (auto-generates certs, browser trust via 'redveil-ui tls install-ca')"),
):
    """First-run setup: pick port, generate config, initialize database."""
    from redveil_ui.first_run import run_init
    run_init(port=port, data_dir=data_dir, skip_dwyor=yes, config_path=config, bind=bind, yes=yes, enable_tls=tls)


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


# Sub-apps (registered after app definition; keep cli.py thin)
from redveil_ui.cli_auth import auth_app  # noqa: E402
from redveil_ui.cli_tls import tls_app  # noqa: E402

app.add_typer(auth_app, name="auth")
app.add_typer(tls_app, name="tls")