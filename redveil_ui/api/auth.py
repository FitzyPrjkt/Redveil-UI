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
import os  # noqa: E402
from pathlib import Path  # noqa: E402

LOOPBACK_BINDS = frozenset({"127.0.0.1", "::1", "localhost"})

def _resolve_api_key() -> str | None:
    """Resolve the API key from one of three storage locations.

    Precedence (first match wins):
      1. REDVEIL_UI_API_KEY env var
      2. ~/.redveil-ui/.api_key file (mode 0600)
      3. auth.api_key_hash in config (returns None; the hash is
         used to VALIDATE a key, not to PRODUCE one. The
         check_auth_or_fail function only needs to know if a key
         is configured, not what it is. The full validation path
         runs at request time in Phase 3 middleware.)
    """
    env_key = os.environ.get("REDVEIL_UI_API_KEY")
    if env_key:
        return env_key

    api_key_file = Path.home() / ".redveil-ui" / ".api_key"
    if api_key_file.is_file():
        try:
            return api_key_file.read_text().strip()
        except OSError:
            pass

    # Config-file hash is checked separately in _has_config_hash()
    return None

def _has_config_hash() -> bool:
    """Check if auth.api_key_hash is set in the config file."""
    config_path = Path.home() / ".redveil-ui" / "config.yaml"
    if not config_path.is_file():
        return False
    try:
        import yaml
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return bool(cfg.get("auth", {}).get("api_key_hash"))
    except (OSError, ImportError):
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
