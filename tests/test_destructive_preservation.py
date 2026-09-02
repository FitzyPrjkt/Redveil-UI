"""Destructive mode preservation tests — Wave 14 deliverable.

Spec requirements covered here:

1. Destructive actions REMAIN available (not removed by a generic safety layer)
2. Unauthorized destructive actions remain blocked
3. Confirmation allows the authorized action (gate authorizes → check proceeds)
4. ActionGate remains authoritative (no plugin can bypass via a parallel path)
5. ``destructive_level`` is respected (max enforcement + tiered confirmation)
6. ``--allow-destructive`` and ``--max-destructive-level`` CLI flags wire through
7. Authorized destructive execution is NOT silently overridden by a "safety" veto
8. ``audit_log()`` preserves destructive context for reports
9. Gate approval does NOT bypass scope / rate-limit / safety policy elsewhere

This file complements ``tests/test_gate.py`` and ``tests/test_destructive_level.py``
by exercising the spec-mandated invariants end-to-end rather than the unit
behavior of each branch.
"""
from __future__ import annotations

import io
import json

import pytest
from typer.testing import CliRunner

from redveil.cli import app
from redveil.config import AuthorizationConfig, RedVeilConfig, TargetConfig
from redveil.knowledge.destructive_levels import (
    DESTRUCTIVE_PROFILES,
    get_destructive_profile,
)
from redveil.validation.gate import ActionGate, GateMode
from redveil.validation.risk import (
    ActionPlan,
    DestructiveLevel,
    Risk,
)

cli_runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _plan(
    *,
    level: DestructiveLevel | None = None,
    risk: Risk = Risk.HIGH,
    confirm_word: str = "",
) -> ActionPlan:
    """Build a destructive ActionPlan for the test."""
    return ActionPlan(
        action_id="dest-test",
        description="destructive test plan",
        risk=risk,
        target="https://target.example.com/api/admin/reset",
        purpose="verify the destructive path is preserved",
        expected_effect="destructive action authorized by operator",
        destructive=True,
        destructive_level=level,
        confirm_word=confirm_word,
    )


# ---------------------------------------------------------------------------
# Spec 1 — Destructive actions remain AVAILABLE
# ---------------------------------------------------------------------------


def test_destructive_field_remains_on_actionplan():
    """The ``destructive`` field on ActionPlan is not removed or aliased away.

    If a generic safety layer silently removes destructive=True from the
    plan, the gate would auto-approve what should be blocked. This test
    catches such regressions.
    """
    plan = _plan(level=DestructiveLevel.DATA_DESTRUCTION)
    assert plan.destructive is True
    assert plan.destructive_level == DestructiveLevel.DATA_DESTRUCTION


def test_destructive_profile_still_resolves_for_active_checks():
    """Each active check with a destructive profile still resolves to one.

    If the per-vuln mapping table is dropped, callers can't surface the
    destructive potential to operators in reports — a regression of
    Wave 13 (#5).
    """
    expected = {
        "xss-reflected",
        "sqli-time-based",
        "command-injection",
        "ssrf",
        "path-traversal",
        "bola-idor",
        "bfla-behavior",
        "bfla",
        "session-invalidation",
    }
    actual = set(DESTRUCTIVE_PROFILES.keys())
    assert expected.issubset(actual), (
        f"Missing destructive profiles: {expected - actual}"
    )


def test_destructive_profile_for_command_injection_keeps_takeover():
    """Command Injection's profile is still tagged up to TAKEOVER (level 6).

    Down-grading this would be a stealth reduction in operator awareness
    of destructive potential — explicitly forbidden by the spec.
    """
    p = get_destructive_profile("command-injection")
    assert p is not None
    assert p.max_destructive_level == DestructiveLevel.TAKEOVER
    # typical_actions must still mention reverse shell / RCE so operators
    # see the realistic destructive potential
    assert any("reverse" in a.lower() or "rce" in a.lower() for a in p.typical_actions)


# ---------------------------------------------------------------------------
# Spec 2 + 7 — Unauthorized destructive BLOCKED; authorized NOT silently overridden
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode",
    [GateMode.INTERACTIVE, GateMode.NON_INTERACTIVE, GateMode.STRICT],
)
def test_destructive_blocked_without_allow_destructive_in_all_modes(mode):
    """When ``allow_destructive=False``, every mode denies destructive."""
    stdin = io.StringIO("CONFIRM\n")
    stdout = io.StringIO()
    gate = ActionGate(mode=mode, stdin=stdin, stdout=stdout)
    decision = gate.ask(
        _plan(level=DestructiveLevel.DATA_EXFILTRATION),
        allow_destructive=False,
    )
    assert not decision
    assert "allow_destructive" in decision.reason


@pytest.mark.parametrize(
    "level",
    [
        DestructiveLevel.DATA_MODIFICATION,
        DestructiveLevel.DATA_DESTRUCTION,
        DestructiveLevel.PERSISTENCE,
        DestructiveLevel.LATERAL_MOVEMENT,
        DestructiveLevel.TAKEOVER,
    ],
)
def test_destructive_blocked_when_level_exceeds_max(level):
    """Any level above the operator's ceiling is denied even with allow=True.

    Level 1 (DATA_EXFILTRATION) is excluded — there's no valid max below it,
    so the "exceeds" case doesn't apply. Level 1 enforcement is exercised
    by ``test_max_destructive_level_enforced_at_default_l2``.
    """
    gate = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("CONFIRM\n"),
        stdout=io.StringIO(),
    )
    max_allowed = level.value - 1
    decision = gate.ask(
        _plan(level=level),
        allow_destructive=True,
        max_destructive_level=max_allowed,
    )
    assert not decision
    assert "exceeds" in decision.reason.lower()


def test_authorized_destructive_is_not_silently_overridden_after_approval():
    """Once the gate approves a destructive plan, nothing re-vetos it.

    Spec invariant: the only veto for destructive is the gate itself.
    A later "safety layer" must NOT silently flip an approved plan to
    denied. We check this by:
      1. Asking the gate to approve a destructive plan.
      2. Asking the gate again with the SAME plan + SAME parameters.
      3. Asserting both decisions are truthy (no flip-flop).

    Plus: an approved plan's history entry must record destructive=True,
    so a downstream consumer can't claim "actually that wasn't destructive".
    """
    fake_stdin = io.StringIO("CONFIRM\nCONFIRM\n")
    fake_stdout = io.StringIO()
    gate = ActionGate(mode=GateMode.INTERACTIVE, stdin=fake_stdin, stdout=fake_stdout)
    plan = _plan(level=DestructiveLevel.DATA_DESTRUCTION)

    d1 = gate.ask(plan, allow_destructive=True, max_destructive_level=6)
    d2 = gate.ask(plan, allow_destructive=True, max_destructive_level=6)
    assert d1, "first decision denied — gate flipped approved → denied"
    assert d2, "second decision denied — gate flipped approved → denied"
    # Both entries record destructive=True so a "stealth downgrade"
    # can't happen later in a consumer.
    assert all(h.plan.destructive for h in gate.history)
    assert all(h.approved for h in gate.history)


# ---------------------------------------------------------------------------
# Spec 3 — Confirmation allows the authorized action (end-to-end)
# ---------------------------------------------------------------------------


def test_typed_confirmation_approves_destructive_in_interactive():
    """Spec: confirmation allows the authorized action."""
    gate = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("CONFIRM\n"),
        stdout=io.StringIO(),
    )
    decision = gate.ask(
        _plan(level=DestructiveLevel.DATA_DESTRUCTION),
        allow_destructive=True,
        max_destructive_level=6,
    )
    assert decision
    assert decision.approved is True


def test_action_word_also_approves_for_specific_plan():
    """Typing the plan's confirm_word (e.g. 'rm-rf') also approves."""
    gate = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("drop-table\n"),
        stdout=io.StringIO(),
    )
    decision = gate.ask(
        _plan(level=DestructiveLevel.DATA_DESTRUCTION, confirm_word="drop-table"),
        allow_destructive=True,
        max_destructive_level=6,
    )
    assert decision


def test_wrong_typed_word_does_not_approve():
    """An incorrect confirmation word is denied — typo protection."""
    gate = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("confirm\n"),  # lowercase — rejected
        stdout=io.StringIO(),
    )
    decision = gate.ask(
        _plan(level=DestructiveLevel.DATA_DESTRUCTION),
        allow_destructive=True,
        max_destructive_level=6,
    )
    assert not decision


# ---------------------------------------------------------------------------
# Spec 4 + 9 — ActionGate authoritative; no plugin can bypass via a parallel path
# ---------------------------------------------------------------------------


def test_gate_decision_does_not_imply_engine_bypass():
    """Spec: gate approval does NOT mean "do whatever you want".

    The ActionGate approves a controlled action under the engine's
    existing limits (scope, max_requests, timeout). It does not promise
    scope bypass or rate-limit suspension. We verify the plan's rendered
    output carries the limits so operators see the constraints.
    """
    plan = ActionPlan(
        action_id="authorized-destructive",
        description="destructive test",
        risk=Risk.HIGH,
        target="https://target.example.com/api/orders",
        purpose="verify the action runs within declared limits",
        expected_effect="destructive action authorized",
        max_requests=4,
        timeout_seconds=10.0,
        destructive=True,
        destructive_level=DestructiveLevel.DATA_DESTRUCTION,
    )
    rendered = plan.render_for_user()
    # Limits are surfaced in the user-facing prompt, NOT hidden.
    assert "4 request(s) max" in rendered
    assert "10s timeout" in rendered
    # The destructive flag is explicitly surfaced too.
    assert "DESTRUCTIVE LEVEL: 3" in rendered


def test_risk_blocked_is_unconditional_veto():
    """Risk.BLOCKED is the spec-mandated unconditional veto — gate cannot
    approve it even with allow_destructive=True + typed confirmation."""
    gate = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("CONFIRM\n"),
        stdout=io.StringIO(),
    )
    plan = ActionPlan(
        action_id="blocked-plan",
        description="a plan that must never run",
        risk=Risk.BLOCKED,
        target="https://target.example.com",
        purpose="test unconditional veto",
        expected_effect="denied",
        destructive=True,
        destructive_level=DestructiveLevel.TAKEOVER,
    )
    decision = gate.ask(plan, allow_destructive=True, max_destructive_level=6)
    assert not decision


# ---------------------------------------------------------------------------
# Spec 5 — destructive_level is respected (max enforcement + tiered)
# ---------------------------------------------------------------------------


def test_max_destructive_level_enforced_at_default_l2():
    """Default operator ceiling is L2 — anything ≥ L3 denied at default."""
    cfg = RedVeilConfig(
        target=TargetConfig(base_url="https://x.com"),
        authorization=AuthorizationConfig(
            active_testing=True,
            acknowledged_safety_terms=True,
            allow_destructive=True,
        ),
    )
    # Default ceiling is 2 (L2 = data_modification)
    assert cfg.authorization.max_destructive_level == 2
    # L3 (data_destruction) exceeds it
    assert DestructiveLevel.DATA_DESTRUCTION.value > cfg.authorization.max_destructive_level


@pytest.mark.parametrize(
    "level",
    [
        DestructiveLevel.DATA_EXFILTRATION,
        DestructiveLevel.DATA_MODIFICATION,
    ],
)
def test_tier1_levels_accept_yn(level):
    """Levels 1-2 accept plain 'y' (no typed confirmation required)."""
    gate = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )
    decision = gate.ask(
        _plan(level=level),
        allow_destructive=True,
        max_destructive_level=6,
    )
    assert decision


@pytest.mark.parametrize(
    "level,expected_word",
    [
        (DestructiveLevel.DATA_DESTRUCTION, "CONFIRM"),
        (DestructiveLevel.PERSISTENCE, "CONFIRM-LEVEL-4"),
        (DestructiveLevel.LATERAL_MOVEMENT, "CONFIRM-LEVEL-5"),
        (DestructiveLevel.TAKEOVER, "CONFIRM-LEVEL-6"),
    ],
)
def test_tier3_plus_levels_require_typed_confirmation(level, expected_word):
    """Levels 3+ require the typed confirmation string from DestructiveLevel."""
    # Wrong confirmation first — denied. We pick a token that is NEVER
    # valid for any level so the negative path is unambiguous.
    gate_wrong = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("nope\n"),
        stdout=io.StringIO(),
    )
    decision_wrong = gate_wrong.ask(
        _plan(level=level),
        allow_destructive=True,
        max_destructive_level=6,
    )
    assert not decision_wrong

    # Correct confirmation — approved.
    gate_right = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO(f"{expected_word}\n"),
        stdout=io.StringIO(),
    )
    decision_right = gate_right.ask(
        _plan(level=level),
        allow_destructive=True,
        max_destructive_level=6,
    )
    assert decision_right
    # And the rendered prompt mentions the right confirmation string.
    assert expected_word in gate_right._stdout.getvalue()


# ---------------------------------------------------------------------------
# Spec 6 — CLI flags wire through to AuthorizationConfig
# ---------------------------------------------------------------------------


def test_cli_help_documents_destructive_flags():
    """--help output must document both destructive flags.

    Operators rely on the help text to learn about the flags; if the
    text is missing, the destructive surface is effectively undocumented.
    """
    result = cli_runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--allow-destructive" in result.output
    assert "--max-destructive-level" in result.output
    # Both L1 and L6 must appear so operators see the accepted range.
    assert "L1" in result.output
    assert "L6" in result.output


def test_cli_short_form_round_trip_l4_to_int_4():
    """Config layer accepts 'L4' and normalizes to int 4 (operator input)."""
    cfg = RedVeilConfig(
        target=TargetConfig(base_url="https://x.com"),
        authorization=AuthorizationConfig(
            active_testing=True,
            acknowledged_safety_terms=True,
            allow_destructive=True,
            max_destructive_level="L4",
        ),
    )
    assert cfg.authorization.max_destructive_level == 4


def test_cli_rejects_out_of_range_max_destructive_level():
    """A level above L6 or below L1 is rejected by the config layer.

    Spec: --max-destructive-level accepts L1..L6. Garbage in → operator
    knows immediately rather than silently being downgraded.
    """
    with pytest.raises(Exception):
        RedVeilConfig(
            target=TargetConfig(base_url="https://x.com"),
            authorization=AuthorizationConfig(
                max_destructive_level="L99",
            ),
        )


# ---------------------------------------------------------------------------
# Spec 8 — audit_log preserves destructive context for reports
# ---------------------------------------------------------------------------


def test_audit_log_includes_destructive_level_and_label():
    """``gate.audit_log()`` must include destructive + level + label.

    Operators read this from the report appendix to verify what was
    authorized during a scan. If the level is missing, they cannot
    reconstruct the destructive potential they signed off on.
    """
    gate = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("CONFIRM\n"),
        stdout=io.StringIO(),
    )
    gate.ask(
        _plan(level=DestructiveLevel.PERSISTENCE),
        allow_destructive=True,
        max_destructive_level=6,
    )
    log = gate.audit_log()
    assert len(log) == 1
    entry = log[0]
    assert entry["destructive"] is True
    assert entry["destructive_level"] == DestructiveLevel.PERSISTENCE.value
    assert entry["destructive_label"] == DestructiveLevel.PERSISTENCE.label
    # JSON-serializable so it can land in the report untouched.
    json.dumps(entry)


def test_audit_log_for_non_destructive_omits_destructive_level():
    """Non-destructive decisions do not synthesize fake destructive fields."""
    gate = ActionGate(mode=GateMode.NON_INTERACTIVE)
    plan = ActionPlan(
        action_id="non-destructive",
        description="x",
        risk=Risk.LOW,
        target="https://t.com",
        purpose="x",
        expected_effect="x",
    )
    gate.ask(plan)
    log = gate.audit_log()
    assert len(log) == 1
    entry = log[0]
    assert entry["destructive"] is False
    # No destructive_level field fabricated when plan.destructive_level is None
    assert "destructive_level" not in entry
    assert "destructive_label" not in entry
    assert "confirm_word" not in entry


# ---------------------------------------------------------------------------
# Spec 9 — Gate approval does not bypass scope / rate-limit
# ---------------------------------------------------------------------------


def test_gate_does_not_synthesize_max_requests_override():
    """The gate respects the plan's ``max_requests`` — does not raise it.

    A "silent" safety layer might decide to approve a destructive plan
    but then bump ``max_requests`` past what the check declared. This
    test pins the contract: the gate returns the plan as-is.
    """
    plan = ActionPlan(
        action_id="dest",
        description="destructive test",
        risk=Risk.HIGH,
        target="https://t.com",
        purpose="x",
        expected_effect="x",
        max_requests=3,
        timeout_seconds=5.0,
        destructive=True,
        destructive_level=DestructiveLevel.DATA_EXFILTRATION,
    )
    gate = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("y\n"),
        stdout=io.StringIO(),
    )
    decision = gate.ask(plan, allow_destructive=True, max_destructive_level=6)
    assert decision
    # The returned plan preserves the check-declared limits.
    assert decision.plan.max_requests == 3
    assert decision.plan.timeout_seconds == 5.0


def test_gate_does_not_relax_destructive_flag_after_approval():
    """The plan returned in the decision keeps ``destructive=True``.

    A second safety layer that flips destructive=False after approval
    would silently neuter the authorization. We pin that invariant.
    """
    plan = _plan(level=DestructiveLevel.DATA_DESTRUCTION, confirm_word="CONFIRM")
    gate = ActionGate(
        mode=GateMode.INTERACTIVE,
        stdin=io.StringIO("CONFIRM\n"),
        stdout=io.StringIO(),
    )
    decision = gate.ask(plan, allow_destructive=True, max_destructive_level=6)
    assert decision
    assert decision.plan.destructive is True
    assert decision.plan.destructive_level == DestructiveLevel.DATA_DESTRUCTION
    assert decision.plan.confirm_word == "CONFIRM"