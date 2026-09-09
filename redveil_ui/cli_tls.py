"""TLS CLI: redveil-ui tls * (0.3.0 Local CA)."""
from __future__ import annotations

import typer
from pathlib import Path

tls_app = typer.Typer(help="TLS / Local CA management")


@tls_app.command("status")
def tls_status():
    """Show TLS config + cert paths + CA trust status."""
    from redveil_ui.tls import get_tls_paths, get_lan_ips

    config_path = Path.home() / ".redveil-ui" / "config.yaml"
    if config_path.is_file():
        import yaml

        cfg = yaml.safe_load(config_path.read_text()) or {}
        tls_cfg = cfg.get("tls", {})
        typer.echo(f"Config TLS: {tls_cfg}")
    else:
        typer.echo("No config.yaml found — run `redveil-ui init --tls` first.")
        raise typer.Exit(1)

    ca_pem, cert_pem, key_pem = get_tls_paths()
    for label, p in [("CA", ca_pem), ("Cert", cert_pem), ("Key", key_pem)]:
        typer.echo(f"{label}: {p} — {'exists' if p.exists() else 'missing'}")
    typer.echo(f"LAN IPs for SAN: {', '.join(get_lan_ips())}")


@tls_app.command("init-ca")
def tls_init_ca():
    """Generate Local CA + server cert (idempotent)."""
    from redveil_ui.tls import ensure_tls_assets

    ca_pem, cert_pem, key_pem = ensure_tls_assets()
    typer.echo(f"CA: {ca_pem}")
    typer.echo(f"Cert: {cert_pem}")
    typer.echo(f"Key: {key_pem}")
    typer.echo("Done. Next: `redveil-ui tls install-ca` to trust CA in your system/browser.")


@tls_app.command("install-ca")
def tls_install_ca():
    """Install CA to system trust store (requires sudo)."""
    from redveil_ui.tls import install_ca

    msg = install_ca()
    typer.echo(msg)
