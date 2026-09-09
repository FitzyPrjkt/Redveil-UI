"""Auth-related CLI subcommands: rotate-key, add-key, list-keys, remove-key, audit-rotate (0.3.0 multi-key)."""
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
    typer.echo("If you lose it, run 'redveil-ui auth rotate-key' again.")


@auth_app.command("add-key")
def add_key(
    config: str = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
):
    """Generate an additional API key without invalidating existing ones (multi-key)."""
    import os

    cfg_path_env = os.environ.get("REDVEIL_CONFIG")
    if config:
        config_dir = Path(config).expanduser().parent
    elif cfg_path_env:
        config_dir = Path(cfg_path_env).expanduser().parent
    else:
        config_dir = Path.home() / ".redveil-ui"
    config_dir.mkdir(parents=True, exist_ok=True)
    new_key = "rvui_" + secrets.token_hex(16)
    config_path = config_dir / "config.yaml"
    cfg = {}
    if config_path.is_file():
        cfg = yaml.safe_load(config_path.read_text()) or {}
    hashes = cfg.setdefault("auth", {}).setdefault("api_key_hashes", [])
    # Migrate single hash to list if present
    single = cfg["auth"].pop("api_key_hash", None)
    if single and single not in hashes:
        hashes.append(single)
    new_hash = "sha256:" + hashlib.sha256(new_key.encode()).hexdigest()
    hashes.append(new_hash)
    config_path.write_text(yaml.safe_dump(cfg))
    typer.echo(f"New API key: {new_key}")
    typer.echo(f"Hash: {new_hash} (appended to auth.api_key_hashes, {len(hashes)} total)")
    typer.echo("Existing keys remain valid. Use `redveil-ui auth list-keys` to see suffixes.")


@auth_app.command("list-keys")
def list_keys(
    config: str = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
):
    """List API key hashes by suffix (never prints raw keys)."""
    import os

    cfg_path_env = os.environ.get("REDVEIL_CONFIG")
    if config:
        config_dir = Path(config).expanduser().parent
    elif cfg_path_env:
        config_dir = Path(cfg_path_env).expanduser().parent
    else:
        config_dir = Path.home() / ".redveil-ui"
    config_path = config_dir / "config.yaml"
    if not config_path.is_file():
        typer.echo("No config.yaml found")
        raise typer.Exit(1)
    cfg = yaml.safe_load(config_path.read_text()) or {}
    auth = cfg.get("auth", {}) or {}
    hashes: list[str] = []
    if auth.get("api_key_hash"):
        hashes.append(str(auth["api_key_hash"]))
    hashes.extend(auth.get("api_key_hashes") or [])
    if not hashes:
        typer.echo("No API keys configured")
        return
    for i, h in enumerate(hashes, 1):
        suffix = h[-8:] if len(h) >= 8 else h
        typer.echo(f"{i}. ...{suffix} ({h[:12]}...)")

    # Also check env/file
    import os

    env = os.environ.get("REDVEIL_UI_API_KEY") or os.environ.get("REDVEIL_UI_API_KEYS")
    if env:
        typer.echo(f"Env keys: {env[:12]}... (suffix ...{env.strip()[-4:]})")
    api_key_file = config_dir / ".api_key"
    if api_key_file.is_file():
        try:
            txt = api_key_file.read_text().strip()
            typer.echo(f".api_key file: ...{txt[-4:]}")
        except OSError:
            pass


@auth_app.command("remove-key")
def remove_key(
    suffix: str = typer.Argument(..., help="Suffix of hash to remove (last 4-8 chars)"),
    config: str = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
):
    """Remove an API key by hash suffix (multi-key)."""
    import os

    cfg_path_env = os.environ.get("REDVEIL_CONFIG")
    if config:
        config_dir = Path(config).expanduser().parent
    elif cfg_path_env:
        config_dir = Path(cfg_path_env).expanduser().parent
    else:
        config_dir = Path.home() / ".redveil-ui"
    config_path = config_dir / "config.yaml"
    if not config_path.is_file():
        typer.echo("No config.yaml found")
        raise typer.Exit(1)
    cfg = yaml.safe_load(config_path.read_text()) or {}
    auth = cfg.get("auth", {}) or {}
    hashes: list[str] = []
    single = auth.get("api_key_hash")
    if single:
        hashes.append(str(single))
    hashes.extend(auth.get("api_key_hashes") or [])
    if not hashes:
        typer.echo("No keys to remove")
        raise typer.Exit(1)
    # Find by suffix
    matched = [h for h in hashes if h.strip().endswith(suffix.strip())]
    if not matched:
        typer.echo(f"No key ending with '{suffix}' found")
        raise typer.Exit(1)
    if len(matched) > 1:
        typer.echo(f"Multiple keys match suffix '{suffix}': {matched} — be more specific")
        raise typer.Exit(1)
    to_remove = matched[0]
    # Remove from both places
    if auth.get("api_key_hash") == to_remove:
        auth.pop("api_key_hash", None)
    if to_remove in (auth.get("api_key_hashes") or []):
        auth["api_key_hashes"].remove(to_remove)
    # Clean up empty list
    if not auth.get("api_key_hashes"):
        auth.pop("api_key_hashes", None)
    config_path.write_text(yaml.safe_dump(cfg))
    typer.echo(f"Removed ...{suffix} ({to_remove[:12]}...) — {len(hashes)-1} keys remain")


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
