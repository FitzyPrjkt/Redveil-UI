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

def test_fail_closed_raises_before_any_socket_operations(clean_env, monkeypatch):
    """check_auth_or_fail must raise BEFORE the caller can open a socket.

    The previous version of this test bound an ephemeral port AFTER the
    check raised — which always succeeds regardless of the check, a
    tautology. The property actually guaranteed (and asserted here) is
    ordering: the check is a pure config-validation function that opens
    no socket itself, and it raises. The caller's obligation to invoke
    it before binding stays with redveil_ui/server.py (documented
    there).
    """
    opened: list[tuple] = []

    class _GuardedSocket:
        def __init__(self, *args):
            opened.append(args)

        def bind(self, *args, **kwargs):  # pragma: no cover — must never run
            raise AssertionError("socket.bind called after fail-closed raise")

    import socket as _socket

    monkeypatch.setattr(_socket, "socket", lambda *a, **k: _GuardedSocket(*a, **k))

    with pytest.raises(AuthConfigError):
        check_auth_or_fail(bind="0.0.0.0")

    # The check raised without performing any socket operations.
    assert opened == []

def test_fail_closed_skipped_when_bind_is_loopback(clean_env):
    """bind=127.0.0.1 + no key -> no error (loopback short-circuits)."""
    check_auth_or_fail(bind="127.0.0.1")  # should NOT raise

def test_fail_closed_skipped_when_key_in_env(clean_env, monkeypatch):
    """bind=0.0.0.0 + REDVEIL_UI_API_KEY set -> no error."""
    monkeypatch.setenv("REDVEIL_UI_API_KEY", "rvui_" + "a" * 32)
    check_auth_or_fail(bind="0.0.0.0")  # should NOT raise

def test_fail_closed_skipped_when_only_config_hash(clean_env, monkeypatch, tmp_path):
    """bind=0.0.0.0 + auth.api_key_hash in config -> no error (S2:
    hash-only installs fail closed at startup, then authenticate via
    the hash validator at request time)."""
    import hashlib

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "host: 0.0.0.0\n"
        "auth:\n"
        f"  api_key_hash: sha256:{hashlib.sha256(b'rvui_x').hexdigest()}\n"
    )
    monkeypatch.setenv("REDVEIL_CONFIG", str(config_path))
    check_auth_or_fail(bind="0.0.0.0")  # should NOT raise
