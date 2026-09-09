"""TLS helpers for redveil-ui Local CA mode (0.3.0).

- CA lives in ~/.redveil-ui/ca/ (ca.key, ca.pem) — 10y, self-signed, CA:TRUE
- Server cert lives in ~/.redveil-ui/certs/ (cert.pem, key.pem) — 825d, signed by CA, SAN for localhost + LAN IPs
- `ensure_tls_assets` is idempotent: reuses existing CA, regenerates server cert if SAN set changed
- `install_ca` copies ca.pem to system trust store (requires sudo)
"""
from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

CA_DIR_NAME = "ca"
CERTS_DIR_NAME = "certs"
CA_KEY = "ca.key"
CA_PEM = "ca.pem"
SERVER_KEY = "key.pem"
SERVER_PEM = "cert.pem"

# 10 years for CA, 825 days for leaf (Apple limit)
CA_DAYS = 3650
LEAF_DAYS = 825


def _config_dir() -> Path:
    return Path.home() / ".redveil-ui"


def _ca_dir(config_dir: Path | None = None) -> Path:
    return (config_dir or _config_dir()) / CA_DIR_NAME


def _certs_dir(config_dir: Path | None = None) -> Path:
    return (config_dir or _config_dir()) / CERTS_DIR_NAME


def get_lan_ips() -> list[str]:
    """Collect LAN IPs for SAN. Best-effort, always includes 127.0.0.1 + ::1."""
    ips: set[str] = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        for fam, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = sockaddr[0]
            # Filter link-local and loopback duplicates
            try:
                addr = ipaddress.ip_address(ip.split("%")[0])
                if addr.is_loopback:
                    continue
                if addr.is_link_local:
                    continue
                ips.add(str(addr))
            except ValueError:
                continue
    except Exception:
        pass
    # Also try UDP connect trick to get default route IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(ips)


def _ensure_cryptography():
    try:
        import cryptography  # noqa: F401
    except ImportError as e:
        raise SystemExit(
            "cryptography is required for TLS. Install with: pip install cryptography\n"
            f"Original error: {e}"
        )


def generate_ca(config_dir: Path | None = None) -> tuple[Path, Path]:
    """Generate CA key + cert if missing. Returns (ca_key_path, ca_pem_path)."""
    _ensure_cryptography()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cdir = _ca_dir(config_dir)
    cdir.mkdir(parents=True, exist_ok=True)
    ca_key_path = cdir / CA_KEY
    ca_pem_path = cdir / CA_PEM

    if ca_key_path.exists() and ca_pem_path.exists():
        return ca_key_path, ca_pem_path

    # RSA 2048
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "redveil Local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "redveil-ui"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Local CA"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    ca_key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    ca_key_path.chmod(0o600)
    ca_pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ca_pem_path.chmod(0o644)
    return ca_key_path, ca_pem_path


def generate_server_cert(
    san_ips: list[str] | None = None,
    san_dns: list[str] | None = None,
    config_dir: Path | None = None,
) -> tuple[Path, Path]:
    """Generate server key + cert signed by CA. Returns (key_path, cert_path)."""
    _ensure_cryptography()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    san_ips = san_ips or get_lan_ips()
    san_dns = san_dns or ["localhost"]

    ca_key_path, ca_pem_path = generate_ca(config_dir)

    # Load CA
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    ca_key = load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_pem_path.read_bytes())

    certs_dir = _certs_dir(config_dir)
    certs_dir.mkdir(parents=True, exist_ok=True)
    key_path = certs_dir / SERVER_KEY
    cert_path = certs_dir / SERVER_PEM

    # Always regenerate server cert to pick up new LAN IPs (cheap)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "redveil-ui"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "redveil-ui"),
        ]
    )
    now = datetime.now(timezone.utc)
    # Build SAN
    san_list: list[x509.GeneralName] = []
    for dns in san_dns:
        san_list.append(x509.DNSName(dns))
    for ip_str in san_ips:
        try:
            # Strip zone index for IPv6
            ip_clean = ip_str.split("%")[0]
            san_list.append(x509.IPAddress(ipaddress.ip_address(ip_clean)))
        except ValueError:
            continue

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=LEAF_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    # Write cert + CA chain (server cert first, then CA for chain)
    cert_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM) + ca_pem_path.read_bytes()
    )
    cert_path.chmod(0o644)
    return key_path, cert_path


def ensure_tls_assets(config_dir: Path | None = None) -> tuple[Path, Path, Path]:
    """Ensure CA + server cert exist. Returns (ca_pem, cert_pem, key_pem)."""
    cdir = config_dir or _config_dir()
    ca_key, ca_pem = generate_ca(cdir)
    key_pem, cert_pem = generate_server_cert(config_dir=cdir)
    return ca_pem, cert_pem, key_pem


def get_tls_paths(config_dir: Path | None = None) -> tuple[Path, Path, Path]:
    """Return expected paths without generating."""
    cdir = config_dir or _config_dir()
    return (
        _ca_dir(cdir) / CA_PEM,
        _certs_dir(cdir) / SERVER_PEM,
        _certs_dir(cdir) / SERVER_KEY,
    )


def _install_firefox_ca(ca_pem: Path) -> list[str]:
    """Install CA to all Firefox-based forks + Flatpak via certutil."""
    import shutil

    msgs: list[str] = []
    if shutil.which("certutil") is None:
        return ["certutil not found — Firefox auto-install skipped (install libnss3-tools)"]

    # All Firefox-based profile roots (native + Flatpak)
    base_dirs = [
        Path.home() / ".mozilla" / "firefox",  # Firefox, ESR
        Path.home() / ".librewolf",  # LibreWolf
        Path.home() / ".waterfox",  # Waterfox
        Path.home() / ".floorp",  # Floorp
        Path.home() / ".zen",  # Zen Browser
        Path.home() / ".mullvad-browser",  # Mullvad Browser (also Tor-based but we try)
        Path.home() / ".moonchild productions" / "pale moon",  # Pale Moon
        Path.home() / ".moonchild productions" / "basilisk",  # Basilisk
        Path.home() / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",  # Flatpak Firefox
        Path.home() / ".var" / "app" / "io.gitlab.librewolf" / ".librewolf",  # Flatpak LibreWolf
        Path.home() / ".var" / "app" / "org.mullvad.MullvadBrowser" / ".mullvad-browser",  # Flatpak Mullvad
    ]
    # Also handle Waterfox classic: ~/.waterfox/*.default*
    found_any = False
    for base in base_dirs:
        if not base.is_dir():
            continue
        # Some forks store profiles directly under base, some under base/*.default*
        # Try both: base itself if it is a profile (contains cert9.db), else glob
        candidates: list[Path] = []
        if (base / "cert9.db").exists() or (base / "cert8.db").exists():
            candidates.append(base)
        candidates.extend([p for p in base.glob("*.default*") if p.is_dir()])
        # LibreWolf/Floorp/Zen may use *.<profile> without .default, so also glob *
        if not candidates:
            candidates.extend([p for p in base.iterdir() if p.is_dir() and (p / "cert9.db").exists()])
        for profile in candidates:
            found_any = True
            label = f"{base.name}/{profile.name}" if profile != base else base.name
            db_arg = f"sql:{profile}"
            try:
                result = subprocess.run(["certutil", "-L", "-d", db_arg], capture_output=True, text=True)
                if "redveil Local CA" in result.stdout:
                    msgs.append(f"Firefox {label}: already trusted")
                    continue
            except Exception:
                pass
            try:
                subprocess.run(["certutil", "-A", "-n", "redveil Local CA", "-t", "C,,", "-i", str(ca_pem), "-d", db_arg], check=True, capture_output=True)
                msgs.append(f"Firefox {label}: installed")
            except subprocess.CalledProcessError as e:
                msgs.append(f"Firefox {label}: failed ({e})")
            except Exception as e:  # noqa: BLE001
                msgs.append(f"Firefox {label}: failed ({e})")
    if not found_any:
        # Fallback scan for any firefox-like dir under ~/.var/app
        var_app = Path.home() / ".var" / "app"
        if var_app.is_dir():
            for app_dir in var_app.iterdir():
                if "firefox" in app_dir.name.lower() or "librewolf" in app_dir.name.lower():
                    for profile in app_dir.rglob("cert9.db"):
                        msgs.append(f"Firefox {app_dir.name}: found {profile.parent} (manual import needed)")
        if not msgs:
            msgs.append("No Firefox-based profiles found — skipping Firefox")
    return msgs


def _install_chrome_nss_ca(ca_pem: Path) -> list[str]:
    """Install CA to Chrome/Chromium + Brave/Vivaldi etc. NSS DBs if they exist.

    Chromium-based browsers on Linux that don't use system p11-kit still check
    ~/.pki/nssdb. Brave/Vivaldi/Opera etc. also fall back there, so one write
    covers all of them. Firefox forks are handled separately.
    """
    import shutil

    if shutil.which("certutil") is None:
        return []
    msgs: list[str] = []
    # Primary NSS DB used by Chrome/Chromium and most forks on Linux
    nss_dbs = [
        Path.home() / ".pki" / "nssdb",  # Chrome, Chromium, Brave, Vivaldi, Opera, Edge, Arc, Thorium, etc.
    ]
    # Some forks keep their own NSS DB (rare on Linux, but check)
    brave_nss = Path.home() / ".config" / "BraveSoftware" / "Brave-Browser"
    if brave_nss.is_dir():
        # Brave still uses .pki/nssdb on Linux, but check anyway
        pass
    for nss_db in nss_dbs:
        if not nss_db.is_dir():
            continue
        try:
            result = subprocess.run(["certutil", "-L", "-d", f"sql:{nss_db}"], capture_output=True, text=True)
            if "redveil Local CA" in result.stdout:
                msgs.append("Chrome NSS (~/.pki/nssdb): already trusted (covers Chrome, Chromium, Edge, Brave, Vivaldi, Opera, Arc, etc.)")
                continue
        except Exception:
            pass
        try:
            subprocess.run(["certutil", "-A", "-n", "redveil Local CA", "-t", "C,,", "-i", str(ca_pem), "-d", f"sql:{nss_db}"], check=True, capture_output=True)
            msgs.append("Chrome NSS (~/.pki/nssdb): installed (covers all Chromium-based)")
        except Exception as e:  # noqa: BLE001
            msgs.append(f"Chrome NSS: failed ({e})")
    # WebKit (GNOME Web/Epiphany) uses system store, already covered by system install.
    # Tor Browser is intentionally not auto-trusted (privacy isolation) — user must import manually if they really want.
    if not msgs:
        msgs.append("Chrome NSS: no DB found (Chromium will use system store, already covered)")
    return msgs


def install_ca(config_dir: Path | None = None) -> str:
    """Install CA to system + Firefox + Chrome NSS. Returns combined status."""
    ca_pem = _ca_dir(config_dir) / CA_PEM
    if not ca_pem.exists():
        raise SystemExit(f"CA not found at {ca_pem}. Run `redveil-ui init --tls` first.")

    system = platform.system()
    msgs: list[str] = []

    # 1. System store
    if system == "Linux":
        if Path("/usr/local/share/ca-certificates").exists():
            dest = Path("/usr/local/share/ca-certificates/redveil-ca.crt")
            try:
                subprocess.run(["sudo", "cp", str(ca_pem), str(dest)], check=True)
                subprocess.run(["sudo", "update-ca-certificates"], check=True)
                msgs.append(f"System: installed to {dest} (Debian/Ubuntu)")
            except subprocess.CalledProcessError as e:
                msgs.append(f"System: failed ({e})")
            except FileNotFoundError:
                msgs.append("System: sudo not found — run sudo cp ... && sudo update-ca-certificates")
        elif Path("/etc/pki/ca-trust/source/anchors").exists():
            dest = Path("/etc/pki/ca-trust/source/anchors/redveil-ca.crt")
            try:
                subprocess.run(["sudo", "cp", str(ca_pem), str(dest)], check=True)
                subprocess.run(["sudo", "update-ca-trust"], check=True)
                msgs.append(f"System: installed to {dest} (Fedora/RHEL)")
            except subprocess.CalledProcessError as e:
                msgs.append(f"System: failed ({e})")
        else:
            msgs.append("System: unknown CA store — manual copy needed")
    elif system == "Darwin":
        try:
            subprocess.run(
                ["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", str(ca_pem)],
                check=True,
            )
            msgs.append("System: installed to System.keychain (macOS)")
        except subprocess.CalledProcessError as e:
            msgs.append(f"System: failed ({e})")
    elif system == "Windows":
        try:
            subprocess.run(["certutil", "-addstore", "-f", "ROOT", str(ca_pem)], check=True)
            msgs.append("System: installed to Windows ROOT")
        except subprocess.CalledProcessError as e:
            msgs.append(f"System: failed ({e})")
    else:
        msgs.append(f"System: unsupported OS {system}")

    # 2. Firefox-based (all forks + Flatpak) — covers Firefox, ESR, LibreWolf, Waterfox, Floorp, Zen, Pale Moon, Basilisk, Mullvad
    msgs.extend(_install_firefox_ca(ca_pem))
    # 3. Chrome NSS (Linux) — covers all Chromium-based via ~/.pki/nssdb (Chrome, Edge, Brave, Vivaldi, Opera, etc.)
    #    System store already covers WebKit (Safari macOS, GNOME Web/Epiphany, Falkon) and most Chromium via p11-kit.
    msgs.extend(_install_chrome_nss_ca(ca_pem))
    # 4. Tor Browser is intentionally not auto-trusted — it isolates its own profile under ~/tor-browser* and should stay isolated.

    # Also handle case where certutil missing for Firefox/Chrome
    if not any("Firefox" in m for m in msgs):
        # _install_firefox_ca already returned message if certutil missing
        pass

    msgs.append("Restart browsers. Test: curl https://127.0.0.1:8000/healthz (no -k) should succeed.")
    return "\n".join(msgs)
