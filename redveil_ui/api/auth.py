# redveil_ui/api/auth.py
"""Authentication config + helpers for redveil-ui.

Defines the fail-closed check (Task 2.2), API key resolution (Task
2.3+), cookie HMAC issue/validate (Phase 3), and effective-scheme
detection (Phase 3).

This file is imported by both the server startup path and the
middleware, so it must NOT import FastAPI middleware machinery at
module load — keep imports local to functions where needed.
"""
from __future__ import annotations

# Exact error message template. The text is asserted by a snapshot
# test in tests/test_server_fail_closed_error_message.py — DO NOT
# edit the message body without updating the golden file.
FAIL_CLOSED_MESSAGE = """Refusing to start: bind={bind} requires authentication.

redveil-ui will not bind to a non-loopback address without
an API key. To fix this, do one of:

  1. Set REDVEIL_UI_API_KEY environment variable, OR
  2. Run 'redveil-ui init' to generate a key (existing
     config is preserved), OR
  3. Set 'auth.api_key_hash' in ~/.redveil-ui/config.yaml
     (sha256 hex digest of the raw key).

For more information, see the LAN deployment section in
the README.
"""


class AuthConfigError(Exception):
    """Raised at server startup when bind != loopback and no API key is set.

    Hard fail-closed. The server MUST NOT bind the listening socket
    in this case. The error message is the user's only signal that
    they need to take action before the server can start.
    """

    def __init__(self, bind: str):
        self.bind = bind
        super().__init__(FAIL_CLOSED_MESSAGE.format(bind=bind))


import hashlib  # noqa: E402
import hmac  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402

LOOPBACK_BINDS = frozenset({"127.0.0.1", "::1", "localhost"})


def _config_path() -> Path:
    """Locate config.yaml.

    Single source of truth for every config lookup in the API package:
    $REDVEIL_CONFIG when set, else ~/.redveil-ui/config.yaml. This
    matches redveil_ui/server.py and api/routes/config.py — the
    fail-closed check, the middleware's hash validation and the
    config-reset endpoint must all agree on WHICH config is live.
    """
    return Path(
        os.environ.get("REDVEIL_CONFIG")
        or Path.home() / ".redveil-ui" / "config.yaml"
    )


def _load_auth_hash() -> str | None:
    """Read auth.api_key_hash from config.yaml, or None.

    Tolerates (and strips) the legacy "sha256:" prefix written by
    `redveil-ui init` / `auth rotate-key`.
    """
    hashes = _load_auth_hashes()
    return hashes[0] if hashes else None


def _load_auth_hashes() -> list[str]:
    """Read all auth hashes (single + list) from config.yaml."""
    config_path = _config_path()
    if not config_path.is_file():
        return []
    try:
        import yaml

        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
        auth = cfg.get("auth", {}) or {}
        out: list[str] = []
        # Single
        single = auth.get("api_key_hash")
        if single:
            s = str(single).strip()
            if s.lower().startswith("sha256:"):
                s = s[len("sha256:") :]
            if s:
                out.append(s)
        # List
        lst = auth.get("api_key_hashes") or auth.get("api_keys")
        if isinstance(lst, list):
            for item in lst:
                s = str(item).strip()
                if s.lower().startswith("sha256:"):
                    s = s[len("sha256:") :]
                if s:
                    out.append(s)
        # Dedupe preserve order
        seen: set[str] = set()
        uniq: list[str] = []
        for h in out:
            if h not in seen:
                seen.add(h)
                uniq.append(h)
        return uniq
    except Exception:  # noqa: BLE001 — corrupt config must never 500 the auth path
        return []


def _resolve_api_key() -> str | None:
    """Resolve the API key from one of three storage locations.

    Precedence (first match wins):
      1. REDVEIL_UI_API_KEY env var
      2. ~/.redveil-ui/.api_key file (mode 0600)
      3. None — auth.api_key_hash in config cannot PRODUCE a key,
         only VALIDATE one (see _key_matches_config_hash). The
         request-time middleware and login route use that validator
         so hash-only installs still authenticate.
    """
    keys = _resolve_api_keys()
    return keys[0] if keys else None


def _resolve_api_keys() -> list[str]:
    """All resolvable raw keys (env comma-separated + file)."""
    out: list[str] = []
    env_key = os.environ.get("REDVEIL_UI_API_KEY")
    if env_key:
        # Support REDVEIL_UI_API_KEY=rvui_aaa,rvui_bbb or single
        for part in env_key.split(","):
            p = part.strip()
            if p:
                out.append(p)
    # Also support REDVEIL_UI_API_KEYS plural
    env_keys = os.environ.get("REDVEIL_UI_API_KEYS")
    if env_keys:
        for part in env_keys.split(","):
            p = part.strip()
            if p:
                out.append(p)
    api_key_file = Path.home() / ".redveil-ui" / ".api_key"
    if api_key_file.is_file():
        try:
            txt = api_key_file.read_text().strip()
            # File may contain one key or comma-separated
            for part in txt.split(","):
                p = part.strip()
                if p:
                    out.append(p)
        except OSError:
            pass
    # Dedupe
    seen: set[str] = set()
    uniq: list[str] = []
    for k in out:
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq

def _has_config_hash() -> bool:
    """Check if any auth hash is set in the config file."""
    return len(_load_auth_hashes()) > 0


def _key_matches_config_hash(supplied: str) -> bool:
    """Validate a raw key against any stored hash (single or list).

    Constant-time comparison of sha256(supplied) against each stored
    hex digest. Used by the login route and the middleware's header
    branch so a hash-only install can still authenticate.
    """
    if not supplied:
        return False
    hashes = _load_auth_hashes()
    if not hashes:
        return False
    supplied_hex = hashlib.sha256(supplied.encode()).hexdigest()
    # Use any match, but still constant-time per compare
    for h in hashes:
        if hmac.compare_digest(supplied_hex, h):
            return True
    return False


def _key_matches_any(stored_hashes: list[str], supplied: str) -> bool:
    """Helper for multi-key: check supplied against list of hashes."""
    if not supplied or not stored_hashes:
        return False
    supplied_hex = hashlib.sha256(supplied.encode()).hexdigest()
    for h in stored_hashes:
        if hmac.compare_digest(supplied_hex, h):
            return True
    return False

def check_auth_or_fail(bind: str) -> None:
    """Hard fail-closed check at server startup.

    If bind is a non-loopback address and no API key is configured
    in any of the three storage locations, raises AuthConfigError
    with the user-facing remediation message. Otherwise returns
    silently.

    Must be called BEFORE the listening socket is opened. The
    caller (redveil_ui/server.py) is responsible for that ordering.
    """
    if bind in LOOPBACK_BINDS:
        return
    if _resolve_api_key() is not None:
        return
    if _has_config_hash():
        return
    raise AuthConfigError(bind=bind)


import time  # noqa: E402

SESSION_TTL_SECONDS = int(os.environ.get("REDVEIL_UI_SESSION_TTL", 86400))  # 24h

def _cookie_value_for(api_key: str, issued_at: int) -> str:
    """Build the cookie value: '{issued_at}.{hmac_hex}'."""
    msg = str(issued_at).encode()
    digest = hmac.new(api_key.encode(), msg, hashlib.sha256).hexdigest()[:32]
    return f"{issued_at}.{digest}"

def issue_session_cookie(api_key: str) -> tuple[str, int]:
    """Returns (cookie_value, max_age_seconds)."""
    issued_at = int(time.time())
    return _cookie_value_for(api_key, issued_at), SESSION_TTL_SECONDS

def validate_session_cookie(cookie_value: str, api_key: str) -> bool:
    """Returns True iff the cookie is well-formed, signed by api_key,
    and not older than SESSION_TTL_SECONDS."""
    try:
        issued_at_str, provided_digest = cookie_value.split(".", 1)
        issued_at = int(issued_at_str)
    except (ValueError, AttributeError):
        return False
    if abs(int(time.time()) - issued_at) > SESSION_TTL_SECONDS:
        return False
    expected = hmac.new(
        api_key.encode(), str(issued_at).encode(), hashlib.sha256
    ).hexdigest()[:32]
    return hmac.compare_digest(provided_digest, expected)


def validate_session_cookie_any(cookie_value: str, api_keys: list[str]) -> bool:
    """Try cookie against any of the known raw keys (multi-key)."""
    for k in api_keys:
        if validate_session_cookie(cookie_value, k):
            return True
    return False
