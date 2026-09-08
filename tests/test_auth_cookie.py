"""Cookie HMAC helper tests (Task 3.1)."""
import time

from redveil_ui.api.auth import (
    SESSION_TTL_SECONDS,
    _cookie_value_for,
    issue_session_cookie,
    validate_session_cookie,
)

API_KEY = "rvui_" + "a" * 32


def test_issue_returns_ttl():
    value, ttl = issue_session_cookie(API_KEY)
    assert ttl == SESSION_TTL_SECONDS
    # value shape: <issued_at>.<32 hex>
    issued_at, digest = value.split(".", 1)
    assert issued_at.isdigit()
    assert len(digest) == 32
    assert int(issued_at) <= int(time.time())


def test_validate_accepts_fresh_cookie():
    value, _ = issue_session_cookie(API_KEY)
    assert validate_session_cookie(value, API_KEY) is True


def test_validate_rejects_wrong_key():
    value, _ = issue_session_cookie(API_KEY)
    assert validate_session_cookie(value, "rvui_" + "b" * 32) is False


def test_validate_rejects_expired_cookie():
    long_ago = int(time.time()) - SESSION_TTL_SECONDS - 60
    expired = _cookie_value_for(API_KEY, long_ago)
    assert validate_session_cookie(expired, API_KEY) is False


def test_validate_rejects_future_issued_cookie():
    """abs() check — a cookie 'issued' beyond TTL in the future is also invalid."""
    future = _cookie_value_for(API_KEY, int(time.time()) + SESSION_TTL_SECONDS + 60)
    assert validate_session_cookie(future, API_KEY) is False


def test_validate_rejects_tampered_digest():
    value, _ = issue_session_cookie(API_KEY)
    tampered = value[:-4] + "0000"
    assert validate_session_cookie(tampered, API_KEY) is False


def test_validate_rejects_malformed_values():
    assert validate_session_cookie("garbage", API_KEY) is False
    assert validate_session_cookie("", API_KEY) is False
    assert validate_session_cookie("12345.nothex", API_KEY) is False
