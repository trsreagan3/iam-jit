"""#402 / §A48 — structured agent-facing deny response tests.

Covers:
  * deny response leads `caught_by_bouncer` (NOT `ERROR`/`DENIED`)
  * suggested_allow_command included for legit denies
  * classifier tag present (placeholder if #404 not landed)
  * iam_jit_handle_deny MCP returns full context
  * recommended_action returns easy-allow for legit
  * recommended_action returns halt+escalate for high-confidence adversarial
"""

from __future__ import annotations

import pytest

from iam_jit.structured_deny import (
    RECOMMENDED_ACTION_EASY_ALLOW,
    RECOMMENDED_ACTION_HALT_ESCALATE,
    StructuredDenyResponse,
    build_structured_deny,
    classify_injection_likelihood,
    derive_recommended_action,
    handle_deny_for_mcp,
)
from iam_jit.structured_deny.response import (
    INJECTION_AMBIGUOUS,
    INJECTION_APPEARS_ADVERSARIAL,
    INJECTION_APPEARS_LEGITIMATE,
    RECOMMENDED_ACTION_REPHRASE_RETRY,
)


# ---------------------------------------------------------------------------
# Lead-text + structure
# ---------------------------------------------------------------------------


def test_deny_response_structure_lead_caught_by_bouncer() -> None:
    """The structured payload's caught_by_bouncer field IS the lead. The
    human_summary() must lead with `caught` (not ERROR/DENIED/BLOCKED)."""
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache-bucket/data.json",
        deny_reason="profile 'safe-default' has no matching allow",
        deny_source="static_profile",
        agent_session_id="sess-1",
        when="2026-05-23T10:00:00Z",
    )
    assert sd.caught_by_bouncer == "ibounce"
    summary = sd.human_summary()
    assert "caught something" in summary.lower()
    # Per [[ambient-value-prop-and-friction-framing]] no ERROR/DENIED/BLOCKED lead text.
    first_line = summary.splitlines()[0]
    for forbidden in ("ERROR", "DENIED", "BLOCKED"):
        assert forbidden not in first_line


def test_deny_response_includes_suggested_allow_command() -> None:
    """For a profile-shape deny that's eligible for easy-allow, the
    suggested_allow_command must be a paste-able `iam-jit profile allow`."""
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::staging-cache-bucket/x.json",
        deny_reason="profile 'safe-default' has no matching allow",
        deny_source="static_profile",
    )
    assert "iam-jit profile allow" in sd.suggested_allow_command
    assert "--action 's3:GetObject'" in sd.suggested_allow_command
    assert "arn:aws:s3:::staging-cache-bucket/x.json" in sd.suggested_allow_command


def test_deny_response_classifier_tag_present() -> None:
    """`is_likely_injection_classification` MUST be one of the three
    valid values. Without an LLM backend configured the #404 classifier
    returns 'ambiguous' + we surface that as the result + hook name."""
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
    )
    assert sd.is_likely_injection_classification in (
        INJECTION_APPEARS_LEGITIMATE,
        INJECTION_AMBIGUOUS,
        INJECTION_APPEARS_ADVERSARIAL,
    )
    # With no LLM backend the deny_classifier returns ambiguous.
    assert sd.is_likely_injection_classification == INJECTION_AMBIGUOUS
    # classifier_hook reflects which classifier was consulted; either
    # empty (no #404 module) or `deny_classifier:...` when integrated.
    assert sd.classifier_hook == "" or sd.classifier_hook.startswith(
        "deny_classifier:"
    )


def test_recommended_action_legit_returns_easy_allow() -> None:
    """A non-destructive verb on a static_profile deny → easy-allow."""
    action = derive_recommended_action(
        deny_source="static_profile",
        classification=INJECTION_AMBIGUOUS,
        suggested_allow_command="iam-jit profile allow --target 'x' --action 's3:GetObject' --reason 'x'",
    )
    assert action == RECOMMENDED_ACTION_EASY_ALLOW


def test_recommended_action_high_confidence_adversarial_returns_halt_escalate() -> None:
    """Adversarial classification overrides everything → halt+escalate."""
    action = derive_recommended_action(
        deny_source="static_profile",
        classification=INJECTION_APPEARS_ADVERSARIAL,
        suggested_allow_command="iam-jit profile allow --target x --action y --reason z",
    )
    assert action == RECOMMENDED_ACTION_HALT_ESCALATE


def test_recommended_action_dynamic_deny_returns_rephrase() -> None:
    """Dynamic-deny rules + profile_only_* floors get rephrase+retry
    because they can't be easy-allowed."""
    action = derive_recommended_action(
        deny_source="dynamic_deny",
        classification=INJECTION_AMBIGUOUS,
        suggested_allow_command="# this deny is from a dynamic-deny rule",
    )
    assert action == RECOMMENDED_ACTION_REPHRASE_RETRY


def test_structural_heuristic_flags_destructive_verbs_as_adversarial() -> None:
    """Until #404 the placeholder heuristic flags `Delete*` / `Destroy*`
    as appears_adversarial so the agent halts."""
    cls, hook = classify_injection_likelihood(
        action="iam:DeleteRole",
        resource="arn:aws:iam::*:role/AdminRole",
        deny_source="static_profile",
        deny_reason="profile 'safe-default'",
    )
    assert cls == INJECTION_APPEARS_ADVERSARIAL
    assert hook == "structural_heuristic"


def test_classifier_hook_dispatch_loads_external_fn(monkeypatch: pytest.MonkeyPatch) -> None:
    """An IAM_JIT_INJECTION_CLASSIFIER_HOOK env var pointing at a callable
    must override the placeholder. Future #404 wires here."""
    import sys
    import types

    fake = types.ModuleType("_iam_jit_test_classifier")

    def _classify(**kwargs):
        return (INJECTION_APPEARS_LEGITIMATE, "test_hook")
    fake.classify = _classify
    sys.modules["_iam_jit_test_classifier"] = fake
    monkeypatch.setenv(
        "IAM_JIT_INJECTION_CLASSIFIER_HOOK",
        "_iam_jit_test_classifier:classify",
    )
    cls, hook = classify_injection_likelihood(
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_source="static_profile",
        deny_reason="x",
    )
    assert cls == INJECTION_APPEARS_LEGITIMATE
    assert hook == "test_hook"


def test_build_structured_deny_deny_event_id_is_stable() -> None:
    """The synthesized deny_event_id MUST be deterministic for the same
    underlying deny so handle_deny lookups work."""
    kwargs = dict(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
        when="2026-05-23T10:00:00Z",
    )
    a = build_structured_deny(**kwargs)
    b = build_structured_deny(**kwargs)
    assert a.deny_event_id == b.deny_event_id
    assert a.deny_event_id.startswith("evt_ibounce_")


# ---------------------------------------------------------------------------
# iam_jit_handle_deny MCP
# ---------------------------------------------------------------------------


def test_handle_deny_mcp_missing_id_returns_error() -> None:
    out = handle_deny_for_mcp({})
    assert out["status"] == "error"
    assert out["code"] == "missing_deny_event_id"


def test_handle_deny_mcp_returns_full_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the fetcher returns a matching DenyRow, handle_deny_for_mcp
    returns the structured payload + recent_audit + classifier_reasoning."""
    from iam_jit.profile_allow.denies import DenyRow
    from iam_jit.structured_deny import response as resp_mod

    seed_row = DenyRow(
        when="2026-05-23T10:00:00Z",
        bouncer="ibounce",
        agent_session_id="sess-1",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache/x",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
        rule_id_if_dynamic=None,
        suggested_allow_command=(
            "iam-jit profile allow --target 'arn:aws:s3:::cache/x' "
            "--action 's3:GetObject' --reason \"<why this is safe>\""
        ),
    )

    # Synthesize the id the same way build_structured_deny would.
    sd_template = build_structured_deny(
        bouncer=seed_row.bouncer,
        action=seed_row.action,
        resource=seed_row.resource,
        deny_reason=seed_row.deny_reason,
        deny_source=seed_row.deny_source,
        rule_id_if_dynamic=seed_row.rule_id_if_dynamic,
        suggested_allow_command=seed_row.suggested_allow_command,
        agent_session_id=seed_row.agent_session_id,
        when=seed_row.when,
    )

    def _fake_fetch(*, since=None, agent_session_id=None, limit=200, **_):
        return [seed_row], []

    # Patch the function on the module the MCP backend imports.
    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.fetch_recent_denies",
        _fake_fetch,
    )

    out = handle_deny_for_mcp({"deny_event_id": sd_template.deny_event_id})
    assert out["status"] == "ok"
    payload = out["structured_deny"]
    assert payload["caught_by_bouncer"] == "ibounce"
    assert payload["action"] == "s3:GetObject"
    assert payload["recommended_action"] == RECOMMENDED_ACTION_EASY_ALLOW
    # classifier_reasoning is the rationale string.
    assert "classifier_reasoning" in out
    assert isinstance(out["classifier_reasoning"], str)
    # recent_audit included by default
    assert "recent_audit" in out
    assert any(r["bouncer"] == "ibounce" for r in out["recent_audit"])


def test_handle_deny_mcp_not_found_returns_status_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """When no deny matches the id, status=not_found + helpful message."""
    def _fake_fetch(*, since=None, agent_session_id=None, limit=200, **_):
        return [], []
    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.fetch_recent_denies",
        _fake_fetch,
    )
    out = handle_deny_for_mcp({"deny_event_id": "evt_ibounce_doesnotexist"})
    assert out["status"] == "not_found"
    assert "lookback_minutes" in out


def test_response_has_no_lead_error_or_blocked_or_denied_text() -> None:
    """Discipline: no operator-visible response field contains the
    forbidden lead text per [[ambient-value-prop-and-friction-framing]]."""
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache",
        deny_reason="caught by safe-default profile",
        deny_source="safe_default",
    )
    d = sd.as_dict()
    for value in d.values():
        if not isinstance(value, str):
            continue
        upper = value.upper()
        # No ALL-CAPS ERROR/DENIED/BLOCKED lead text in the payload
        # itself. deny_reason can contain operator-language explanation
        # so we only assert ALL-CAPS forms aren't there.
        assert "ERROR:" not in upper
        assert not upper.startswith("DENIED")
        assert not upper.startswith("BLOCKED")
