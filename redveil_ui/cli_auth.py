"""Auth-related CLI subcommands: rotate-key, audit-rotate (0.2.0)."""
from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

import typer
import yaml

auth_app = typer.Typer(help="Auth management")


@auth_app.command("rotate-key")
def rotate_key(
    config: str = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
):
    """Generate a new API key, replacing the current one.

    All existing sessions are invalidated immediately (the HMAC
    cookie can no longer be verified against the new key).
    """
    config_dir = (
        Path(config).expanduser().parent
        if config
        else Path.home() / ".redveil-ui"
    )
    config_dir.mkdir(parents=True, exist_ok=True)

    new_key = "rvui_" + secrets.token_hex(16)
    api_key_file = config_dir / ".api_key"
    api_key_file.write_text(new_key)
    api_key_file.chmod(0o600)

    # Update the hash in config.yaml
    config_path = config_dir / "config.yaml"
    if config_path.is_file():
        cfg = yaml.safe_load(config_path.read_text()) or {}
        cfg.setdefault("auth", {})["api_key_hash"] = (
            "sha256:" + hashlib.sha256(new_key.encode()).hexdigest()
        )
        config_path.write_text(yaml.safe_dump(cfg))

    typer.echo(f"New API key: {new_key}")
    typer.echo("⚠ This is the only time the full key will be shown.")
    typer.echo("If you lose it, run 'redveil-ui rotate-key' again.")
