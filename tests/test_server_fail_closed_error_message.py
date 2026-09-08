from pathlib import Path

from redveil_ui.api.auth import FAIL_CLOSED_MESSAGE, AuthConfigError

GOLDEN_PATH = Path(__file__).parent / "fixtures" / "auth_error_message.txt"

def test_error_message_matches_golden():
    """The fail-closed message is asserted verbatim against a golden.

    If you intentionally change the message, manually update
    tests/fixtures/auth_error_message.txt in the same commit — the
    message is user-facing UX and its degradation is a regression.
    """
    assert FAIL_CLOSED_MESSAGE.format(bind="0.0.0.0") == GOLDEN_PATH.read_text()

def test_auth_config_error_formats_bind():
    err = AuthConfigError(bind="192.168.1.50")
    assert str(err).startswith("Refusing to start: bind=192.168.1.50")
    assert err.bind == "192.168.1.50"
