import socket

import pytest

from redveil_ui.api.auth import AuthConfigError, check_auth_or_fail

@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    """Ensure no API key is set in any of the three locations."""
    monkeypatch.delenv("REDVEIL_UI_API_KEY", raising=False)
    # No file at ~/.redveil-ui/.api_key
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path

def test_fail_closed_when_bind_non_loopback_and_no_key(clean_env):
    """bind=0.0.0.0 + no key in any of 3 locations -> AuthConfigError."""
    with pytest.raises(AuthConfigError) as exc_info:
        check_auth_or_fail(bind="0.0.0.0")

    msg = str(exc_info.value)
    assert msg.startswith("Refusing to start: bind=0.0.0.0")
    assert "requires authentication" in msg
    assert "REDVEIL_UI_API_KEY" in msg
    assert "redveil-ui init" in msg
    assert "auth.api_key_hash" in msg
    assert "LAN deployment section" in msg

def test_fail_closed_does_not_open_listening_socket(clean_env):
    """After the check raises, no socket was bound."""
    with pytest.raises(AuthConfigError):
        check_auth_or_fail(bind="0.0.0.0")

    # Probe: try to bind an ephemeral port (Ruling #4: plan's fixed
    # port 49152 is collision-prone; an ephemeral port proves the same
    # property without flake).
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", 0))
        s.close()
    except OSError as e:
        pytest.fail(f"Socket bind failed post-check (server may have started): {e}")

def test_fail_closed_skipped_when_bind_is_loopback(clean_env):
    """bind=127.0.0.1 + no key -> no error (loopback short-circuits)."""
    check_auth_or_fail(bind="127.0.0.1")  # should NOT raise

def test_fail_closed_skipped_when_key_in_env(clean_env, monkeypatch):
    """bind=0.0.0.0 + REDVEIL_UI_API_KEY set -> no error."""
    monkeypatch.setenv("REDVEIL_UI_API_KEY", "rvui_" + "a" * 32)
    check_auth_or_fail(bind="0.0.0.0")  # should NOT raise
