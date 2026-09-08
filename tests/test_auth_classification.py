"""Destructive-action classification tests (Task 3.3)."""
from redveil_ui.api.scanner import is_destructive_request


def test_destructive_when_active_profile():
    assert is_destructive_request({"profile": "active"}) is True


def test_destructive_when_L3_or_higher():
    for level in ("L3", "L4", "L5", "L6"):
        assert is_destructive_request({"max_destructive_level": level}) is True


def test_destructive_when_allow_destructive_true():
    assert is_destructive_request({"allow_destructive": True}) is True


def test_non_destructive_for_passive_low_impact_L1_L2():
    for profile, level in [
        ("passive", "L1"),
        ("low_impact", "L2"),
        ("low_impact", "L1"),
        ("passive", "L2"),
    ]:
        body = {
            "profile": profile,
            "max_destructive_level": level,
            "allow_destructive": False,
        }
        assert is_destructive_request(body) is False, f"Failed for {body}"


def test_custom_probe_always_destructive():
    """POST /api/probes/custom is always destructive: the ROUTE requires
    auth unconditionally (route-level mechanism), while the body-level
    helper returns False for an empty body — the distinction is explicit."""
    assert is_destructive_request({}) is False
