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


@auth_app.command("audit-rotate")
def audit_rotate(
    days: int = typer.Option(90, "--days", help="Delete entries older than this many days"),
):
    """Delete audit_log entries older than `days` (default 90).

    This is the ONLY deletion path for the append-only audit trail,
    and it logs itself into the same table (action='audit.rotate').
    """
    import asyncio
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import delete, select
    from redveil_ui.api.db import init_engine_for_cli, get_session_factory
    from redveil_ui.api.models import AuditLog

    engine = init_engine_for_cli()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    async def _rotate() -> int:
        factory = get_session_factory()
        async with factory() as s:
            result = await s.execute(
                delete(AuditLog).where(AuditLog.ts < cutoff)
            )
            deleted = result.rowcount
            s.add(
                AuditLog(
                    ts=datetime.now(timezone.utc).isoformat(),
                    actor="cli",
                    action="audit.rotate",
                    target_kind=None,
                    target_id=None,
                    request_meta=f'{{"deleted": {deleted}, "days": {days}}}',
                    result="allowed",
                    deny_reason=None,
                )
            )
            await s.commit()
            return deleted

    try:
        deleted = asyncio.run(_rotate())
    finally:
        asyncio.run(engine.dispose())

    typer.echo(f"Deleted {deleted} audit entr{'y' if deleted == 1 else 'ies'} older than {days} days.")
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
