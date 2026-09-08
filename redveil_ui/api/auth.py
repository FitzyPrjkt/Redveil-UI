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
