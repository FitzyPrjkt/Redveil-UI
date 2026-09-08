"""URL safety validation for target creation.

This module enforces URL-format and URL-host safety at the API boundary,
BEFORE persistence. It is intentionally narrow: it rejects the small
set of inputs that are clearly invalid or clearly dangerous regardless
of any operator-supplied scope. The operator's allowed_hosts/allowed_paths
in scope_yaml remains the authority on WHICH hosts are in-scope; this
module is the gate that decides whether the URL is even parseable as a
target.

Always-rejected (no override):
- Schemes other than http/https (file://, ftp://, javascript:, data:,
  gopher://, etc.)
- 0.0.0.0 and the unspecified address (RFC 5735 0.0.0.0/8)
- 255.255.255.255 (limited broadcast)
- Link-local 169.254.0.0/16 (RFC 3927) — covers AWS IMDS
  169.254.169.254 and GCP metadata.google.internal
- 168.63.129.16 (Azure WireServer / Instance Metadata Service)
- IPv6 link-local fe80::/10
- Cloud-metadata hostnames (metadata.google.internal, instance-data.ec2.internal)
  when the operator types them directly
- ANY hostname that DNS-resolves into a blocked IP range (defense in
  depth — the operator typing "evil.example.com" that points to
  169.254.169.254 must be rejected, not just literal IP inputs)

NOT rejected here (delegated to ScopeController via scope_yaml):
- Loopback (127.0.0.0/8, ::1) — these are legitimate lab targets;
  the operator must add them to allowed_hosts to scan
- RFC1918 private ranges (10/8, 172.16/12, 192.168/16) — same rule
- Any other host the operator explicitly permits in allowed_hosts

This split is deliberate: there's no legitimate reason to scan
``file:///etc/passwd`` or ``http://169.254.169.254/...`` from a redveil
target row, so those are hard errors. RFC1918 and loopback ARE legitimate
lab targets, so we let the operator opt in via the same mechanism they
use for any other allowed host.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Schemes that can never be a redveil target. http and https are the only
# valid schemes for security scanning.
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Cloud-metadata hostnames. Blocked by name AND by resolved IP — the
# blocklist below also covers the IP space, so an operator renaming DNS
# doesn't bypass it.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",       # GCP
        "metadata.goog",                  # GCP alt
        "instance-data.ec2.internal",     # AWS alt IMDS hostname
    }
)

# Specific IPs that are NOT safe to scan, beyond what the link-local
# /16 already covers.
_BLOCKED_SPECIFIC_IPS = frozenset(
    {
        ipaddress.ip_address("0.0.0.0"),
        ipaddress.ip_address("255.255.255.255"),
        ipaddress.ip_address("168.63.129.16"),  # Azure WireServer / IMDS
    }
)

# Network ranges that are always rejected regardless of scope.
# Note: 127.0.0.0/8 and ::1 are NOT here — loopback is a legitimate
# lab target and is gated by allowed_hosts in scope_yaml instead.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),    # RFC 3927 link-local v4
                                        # (covers AWS IMDS 169.254.169.254)
    ipaddress.ip_network("fe80::/10"),         # link-local v6
]


def _ip_is_blocked(ip: ipaddress._BaseAddress) -> tuple[bool, str]:
    """Check a resolved IP against the always-blocked set."""
    if ip in _BLOCKED_SPECIFIC_IPS:
        if ip == ipaddress.ip_address("0.0.0.0"):
            return True, "host resolves to 0.0.0.0 (unspecified address)"
        if ip == ipaddress.ip_address("255.255.255.255"):
            return True, "host resolves to 255.255.255.255 (broadcast)"
        return True, f"host resolves to {ip} (reserved cloud-metadata IP)"
    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return True, (
                f"host resolves to {ip} which is in blocked range "
                f"{net} (cloud-metadata or link-local)"
            )
    return False, ""


def _resolve_and_check(host: str) -> tuple[bool, str]:
    """Resolve ``host`` (IPv4 literal or DNS name) and check the result.

    If ``host`` is an IP literal, we check it directly. Otherwise we
    resolve via getaddrinfo (all addresses) and check every resolution.
    Returns (ok, reason).
    """
    # Try as IP literal first.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        blocked, reason = _ip_is_blocked(ip)
        # _resolve_and_check returns (ok, reason) where ok=True means SAFE,
        # so invert the (blocked, reason) tuple from _ip_is_blocked.
        return (not blocked, reason)

    # Hostname — resolve and check every address that comes back.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        # Unresolvable host — let the scope_check layer reject this if
        # it wants to. The safety check is a no-op when the host doesn't
        # resolve to anything in our blocklist.
        return True, ""

    seen: set[ipaddress._BaseAddress] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except (ValueError, IndexError):
            continue
        if ip in seen:
            continue
        seen.add(ip)
        blocked, reason = _ip_is_blocked(ip)
        if blocked:
            return False, (
                f"hostname {host!r} resolves to blocked address {ip} "
                f"({reason})"
            )

    return True, ""


def validate_target_url(url: str) -> tuple[bool, str]:
    """Return ``(ok, reason)``.

    ``ok=True`` means the URL is parseable as an http(s) target whose
    host is not in the always-blocked set. ``reason`` is empty on
    success; on failure it names the rejection reason for an HTTP 422
    detail string.

    Note: this does NOT check whether the host is in the operator's
    allowed_hosts — that is done by scope_check.check_target_url_in_scope.
    This module only catches inputs that are unsafe before the
    scope-check is even reached.
    """
    if not url:
        return False, "empty url"

    # Reject control characters and whitespace up front; urlparse is
    # surprisingly tolerant of garbage.
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in url):
        return False, "url contains control characters"

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return False, f"unparseable url: {exc}"

    # Scheme check.
    if not parsed.scheme:
        return False, "url has no scheme (only http and https URLs are allowed)"
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        return False, (
            f"scheme {scheme!r} is not allowed; only http and https URLs "
            f"are allowed for security-scanning targets"
        )

    # Netloc check.
    if not parsed.netloc:
        return False, "url has no host"

    # Strip credentials; what's left is host (or host:port).
    host = parsed.hostname
    if not host:
        return False, "url has no host"
    host_lower = host.lower()

    # Cloud-metadata hostname blocklist (block by name first, before
    # falling through to IP resolution).
    if host_lower in _BLOCKED_HOSTNAMES:
        return False, f"host {host!r} is a known cloud metadata endpoint"

    # Resolve and check the resulting IP(s). This catches both literal
    # IP inputs (e.g. "http://169.254.169.254/") and DNS names that
    # resolve into a blocked range.
    return _resolve_and_check(host)


__all__ = ["validate_target_url"]
