"""#413 / §A57 — deny-surface tone audit + rewrite tests for
``iam-jit denies recent`` CLI.

Per [[ambient-value-prop-and-friction-framing]]:
  * Lead with "Your bouncer caught..." NEVER "ERROR" / "DENIED" /
    "BLOCKED".
  * Categorize by structured-deny classifier output so the operator
    scans the high-signal bucket first.
  * Adversarial classifications STILL escalate; ambiguous +
    legitimate get the easy-allow nudge.
"""

from __future__ import annotations

import pytest

# These tests target the pure formatter (no CLI runner required).
from iam_jit.cli_profile_allow import _format_denies_table
from iam_jit.profile_allow.denies import DenyRow


def _row(
    *,
    action: str = "s3:GetObject",
    resource: str = "arn:aws:s3:::cache-bucket/x.json",
    deny_source: str = "static_profile",
    deny_reason: str = "profile 'safe-default' has no matching allow",
    bouncer: str = "ibounce",
    suggested: str | None = None,
    when: str = "2026-05-23T10:00:00Z",
) -> DenyRow:
    return DenyRow(
        when=when,
        bouncer=bouncer,
        agent_session_id="sess-1",
        action=action,
        resource=resource,
        deny_reason=deny_reason,
        deny_source=deny_source,
        rule_id_if_dynamic=None,
        suggested_allow_command=(
            suggested
            if suggested is not None
            else (
                f"iam-jit profile allow --target '{resource}' "
                f"--action '{action}' --reason \"<why this is safe>\""
            )
        ),
    )


def test_denies_recent_cli_uses_caught_framing_not_error() -> None:
    """The output MUST NOT lead with ERROR / DENIED / BLOCKED per
    [[ambient-value-prop-and-friction-framing]]."""
    rows = [_row()]
    out = _format_denies_table(rows, notes=[])
    first_line = out.splitlines()[0]
    assert "caught" in first_line.lower()
    for forbidden in ("ERROR", "DENIED", "BLOCKED"):
        assert forbidden not in first_line


def test_denies_recent_cli_caught_framing_with_no_rows() -> None:
    """Empty window also uses caught framing ("caught nothing"), NOT
    "no denies in window" / "no errors found"."""
    out = _format_denies_table([], notes=[])
    assert "caught nothing" in out.lower()
    for forbidden in ("ERROR", "DENIED", "BLOCKED"):
        assert forbidden not in out


def test_denies_recent_cli_categorizes_by_classifier_output() -> None:
    """The output MUST split rows into the three category buckets
    (adversarial / ambiguous / legit) so an operator can scan the
    high-signal one first.

    Driving rows with a destructive verb forces appears_adversarial
    via the structural-heuristic backstop in
    :func:`iam_jit.structured_deny.classify_injection_likelihood`."""
    rows = [
        _row(action="s3:DeleteObject", resource="arn:aws:s3:::prod-data/x"),
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache/x"),
    ]
    out = _format_denies_table(rows, notes=[])
    # Both buckets surfaced as headings.
    assert "likely-adversarial" in out
    # The non-destructive row is either ambiguous or legit.
    assert ("ambiguous" in out) or ("likely-legit" in out)
    # The total summary in the lead line reflects every row.
    assert "Your bouncer caught 2 thing(s)" in out


def test_denies_recent_cli_adversarial_recommends_halt_escalate() -> None:
    """Per [[ibounce-honest-positioning]] + the brief: adversarial
    classifications surface a halt-escalate recommendation; they do
    NOT lead with the allow-if-legit nudge."""
    rows = [_row(action="iam:DeleteUser", resource="arn:aws:iam::123:user/svc")]
    out = _format_denies_table(rows, notes=[])
    assert "halt + escalate" in out
    # The suggested-allow is still surfaced as a "if reviewed + still
    # safe" parenthetical so the framing is honest (not hidden) but
    # not the lead recommendation.
    assert "if reviewed + still safe" in out


def test_denies_recent_cli_legit_leads_with_allow_nudge() -> None:
    """A non-destructive verb is classified ambiguous (no LLM backend
    in tests) → it gets the easy-allow nudge (allow-if-legit), NOT a
    halt-escalate."""
    rows = [_row(action="s3:GetObject", resource="arn:aws:s3:::cache/x")]
    out = _format_denies_table(rows, notes=[])
    assert "allow if legit" in out
    assert "halt + escalate" not in out
