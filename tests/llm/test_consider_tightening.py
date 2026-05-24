"""Phase 13 — ``iam_jit_consider_tightening`` MCP tool.

Per docs/PROFILE-GENERATION-DESIGN.md §6 Phase 13 + §10.3 + §11.2
and memory ``[[progressive-tightening-as-injection-detector]]``.

State-verification convention per docs/CONTRIBUTING.md: every test
that asserts a reported response shape MUST also assert the
observable content (per-shape suspect_patterns entries, narrowing
proposals carry-through, operator_attention_required boolean math,
provenance honesty surface).

Covers:
  1. Empty input → both arrays empty + attention_required=False.
  2. Narrowing proposals flow through the Phase 8 improve pipeline.
  3. KNOWN_ADVERSARIAL event → suspect_patterns includes
     known_adversarial_pattern_match + BLOCK_PROACTIVELY.
  4. Unprecedented action → suspect_patterns includes
     unprecedented_action.
  5. Sudden friction-spike → suspect_patterns includes
     sudden_friction_spike.
  6. Velocity anomaly → suspect_patterns includes velocity_anomaly.
  7. Attack chain (3 KNOWN_ADVERSARIAL within 60s same session) →
     suspect_patterns includes attack_chain_signature + INVESTIGATE_NOW
     + high confidence.
  8. operator_attention_required OR logic verified across triggers.
  9. Provenance surfaces calibration state (narrowing_calibrated=True,
     suspect_pattern_calibrated=False) per
     [[ibounce-honest-positioning]].
 10. friction_budget carries through to improve pipeline.
 11. History-depth warning fires when supplied history covers far less
     than declared depth.
 12. Sabotage-check: monkeypatching is_known_adversarial to always
     False makes test 3 fail (proves the pattern detection is the
     load-bearing logic).
 13. MCP round-trip via _handle_request — TighteningResponse
     serialises cleanly.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from iam_jit.llm.tightening import (
    NarrowingProposal,
    SuspectPattern,
    TighteningResponse,
    consider_tightening,
    consider_tightening_for_mcp,
    serialize_tightening_response,
)


# ---------------------------------------------------------------------------
# Event helpers — synthetic OCSF-shape events used across the suite.
# ---------------------------------------------------------------------------


_BASE_MS = 1_700_000_000_000


def _event(
    *,
    action: str,
    resource: str = "",
    time_ms: int | None = None,
    outcome: str = "allow",
    session: str = "sess-default",
) -> dict[str, Any]:
    """Construct an OCSF-shape audit event with a (service:Operation)
    action + a resource ARN + an event_code outcome + an iam-jit
    agent session id. The shape matches what the audit-export
    pipeline emits per src/iam_jit/llm/simulator.py."""
    if ":" in action:
        svc, op = action.split(":", 1)
    else:
        svc, op = "", action
    return {
        "time": time_ms if time_ms is not None else _BASE_MS,
        "metadata": {"event_code": outcome},
        "api": {
            "service": {"name": svc},
            "operation": op,
            "resources": [{"name": resource}] if resource else [],
        },
        "unmapped": {
            "iam_jit": {
                "agent_session_id": session,
            },
        },
    }


def _profile_empty() -> dict[str, Any]:
    """Generator-shape profile with no allow / deny rules — used for
    tests that don't exercise narrowing."""
    return {
        "profile_name": "test-profile",
        "bouncer": "ibounce",
        "allows": [],
        "denies": [],
    }


# ---------------------------------------------------------------------------
# 1. Empty audit window → empty arrays + attention_required=False.
# ---------------------------------------------------------------------------


def test_consider_tightening_empty_returns_empty_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No events → narrowing pipeline returns no_change → no proposals.
    No events → no suspect-pattern detector fires → no suspects.
    Therefore operator_attention_required must be False."""
    # Stub the improve pipeline so the test doesn't depend on profile
    # store side-effects.
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=[],
        bouncer_kind="ibounce",
        history_events=[],
    )
    assert isinstance(resp, TighteningResponse)
    assert resp.narrowing_proposals == []
    assert resp.suspect_patterns == []
    assert resp.operator_attention_required is False
    # Observable state: provenance still surfaces honest calibration.
    assert resp.provenance["narrowing_calibrated"] is True
    assert resp.provenance["suspect_pattern_calibrated"] is False


# ---------------------------------------------------------------------------
# 2. Narrowing proposals reuse the Phase 8 improve pipeline.
# ---------------------------------------------------------------------------


def test_consider_tightening_narrowing_proposals_from_improve_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The narrowing block is the improve pipeline's proposed_removals
    converted into NarrowingProposal dataclasses. The conversion MUST
    preserve (action, target) faithfully."""
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals = [
            {"action": "s3:GetObject", "target": "arn:aws:s3:::cache"},
            {"action": "s3:PutObject", "target": "arn:aws:s3:::cache"},
        ]
        warnings = ["upstream warning fixture"]
        friction_metrics_baseline = {}
        friction_metrics_if_applied = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=[_event(action="s3:GetObject")],
        bouncer_kind="ibounce",
    )
    assert len(resp.narrowing_proposals) == 2
    # Observable state: rule_to_add carries the original (action, target).
    actions = {p.rule_to_add["action"] for p in resp.narrowing_proposals}
    assert actions == {"s3:GetObject", "s3:PutObject"}
    for p in resp.narrowing_proposals:
        assert p.rule_to_add["operation"] == "remove_allow_rule"
        assert p.rule_to_add["target"] == "arn:aws:s3:::cache"
    # Upstream improve warnings propagate via provenance.
    assert any(
        "upstream warning fixture" in w
        for w in resp.provenance["warnings"]
    )


# ---------------------------------------------------------------------------
# 3. KNOWN_ADVERSARIAL → suspect_patterns surfaces it.
# ---------------------------------------------------------------------------


def test_consider_tightening_known_adversarial_surfaces_suspect_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An audit event matching the KNOWN_ADVERSARIAL_PATTERNS catalogue
    (here iam:CreateAccessKey) MUST surface a suspect_pattern of shape
    known_adversarial_pattern_match with BLOCK_PROACTIVELY action.
    Per design §11.3 this is the ONLY shape that can recommend block."""
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    bad_event = _event(action="iam:CreateAccessKey", resource="*")
    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=[bad_event],
        bouncer_kind="ibounce",
    )
    shapes = {sp.shape for sp in resp.suspect_patterns}
    assert "known_adversarial_pattern_match" in shapes
    # Observable: BLOCK_PROACTIVELY is the only safe-floor block.
    adv = [
        sp for sp in resp.suspect_patterns
        if sp.shape == "known_adversarial_pattern_match"
    ]
    assert adv and adv[0].recommended_action == "BLOCK_PROACTIVELY"
    assert adv[0].events == [bad_event]
    # operator_attention_required must fire on BLOCK_PROACTIVELY.
    assert resp.operator_attention_required is True
    # Provenance carries the calibration warning.
    assert any(
        "NOT corpus-validated" in w for w in resp.provenance["warnings"]
    )


# ---------------------------------------------------------------------------
# 4. Unprecedented action.
# ---------------------------------------------------------------------------


def test_consider_tightening_unprecedented_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An action absent from the trailing history surfaces a suspect
    pattern of shape unprecedented_action. LOG_AND_OBSERVE per
    design §11.3 (noisy by design)."""
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    # History: only s3:GetObject ever.
    history = [
        _event(action="s3:GetObject", resource=f"bucket/{i}",
               time_ms=_BASE_MS - i * 60_000)
        for i in range(20)
    ]
    # Window: s3:GetObject + a NEW action (ec2:RunInstances).
    window = [
        _event(action="s3:GetObject", resource="bucket/normal"),
        _event(action="ec2:RunInstances", resource="i-novel"),
    ]
    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=window,
        bouncer_kind="ibounce",
        history_events=history,
    )
    shapes = {sp.shape for sp in resp.suspect_patterns}
    assert "unprecedented_action" in shapes
    # Observable: the surfaced events are the ec2:RunInstances entries.
    unp = [
        sp for sp in resp.suspect_patterns
        if sp.shape == "unprecedented_action"
    ]
    assert unp
    surfaced_actions = {
        f"{ev['api']['service']['name']}:{ev['api']['operation']}"
        for sp in unp
        for ev in sp.events
    }
    assert "ec2:RunInstances" in surfaced_actions
    assert all(
        sp.recommended_action == "LOG_AND_OBSERVE" for sp in unp
    )


# ---------------------------------------------------------------------------
# 5. Sudden friction-spike.
# ---------------------------------------------------------------------------


def test_consider_tightening_friction_spike(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Current window denial rate >> trailing-history baseline → fires.

    Setup: history has 100 events with 5 denies (5%). Window has 10
    events with 6 denies (60%) — 12x baseline, well over the 3x
    floor. Must surface sudden_friction_spike + INVESTIGATE_NOW."""
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    history = []
    for i in range(95):
        history.append(_event(
            action="s3:GetObject",
            resource=f"bucket/{i}",
            time_ms=_BASE_MS - 86400_000 - i * 1000,
        ))
    for i in range(5):
        history.append(_event(
            action="s3:DeleteObject",
            resource=f"bucket/{i}",
            time_ms=_BASE_MS - 86400_000 - i * 1000,
            outcome="deny",
        ))

    window = []
    for i in range(4):
        window.append(_event(
            action="s3:GetObject",
            resource=f"bucket/{i}",
            time_ms=_BASE_MS + i * 1000,
        ))
    for i in range(6):
        window.append(_event(
            action="s3:DeleteObject",
            resource=f"bucket/{i}",
            time_ms=_BASE_MS + i * 1000,
            outcome="deny",
        ))

    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=window,
        bouncer_kind="ibounce",
        history_events=history,
    )
    shapes = {sp.shape for sp in resp.suspect_patterns}
    assert "sudden_friction_spike" in shapes
    spike = [
        sp for sp in resp.suspect_patterns
        if sp.shape == "sudden_friction_spike"
    ]
    assert spike and spike[0].recommended_action == "INVESTIGATE_NOW"
    # Observable: the spike block surfaces the actual deny events
    # (not the allows) — the operator needs to inspect what was denied.
    deny_events_in_spike = spike[0].events
    assert all(
        ev["metadata"]["event_code"] == "deny"
        for ev in deny_events_in_spike
    )


# ---------------------------------------------------------------------------
# 6. Velocity anomaly.
# ---------------------------------------------------------------------------


def test_consider_tightening_velocity_anomaly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An action at >5x its historical per-event rate fires."""
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    # History: 100 events; s3:GetObject is 1% (1 event out of 100).
    history = [
        _event(action="s3:HeadObject", resource=f"bucket/{i}",
               time_ms=_BASE_MS - 86400_000 - i * 1000)
        for i in range(99)
    ]
    history.append(_event(
        action="s3:GetObject", resource="bucket/0",
        time_ms=_BASE_MS - 86400_000 - 99 * 1000,
    ))
    # Window: 10 events, s3:GetObject is 80% (8 events) → 80x baseline.
    window = [
        _event(action="s3:GetObject", resource=f"bucket/{i}",
               time_ms=_BASE_MS + i * 1000)
        for i in range(8)
    ] + [
        _event(action="s3:HeadObject", resource=f"bucket/{i}",
               time_ms=_BASE_MS + (8 + i) * 1000)
        for i in range(2)
    ]
    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=window,
        bouncer_kind="ibounce",
        history_events=history,
    )
    shapes = {sp.shape for sp in resp.suspect_patterns}
    assert "velocity_anomaly" in shapes
    vel = [
        sp for sp in resp.suspect_patterns
        if sp.shape == "velocity_anomaly"
    ]
    assert vel and vel[0].recommended_action == "INVESTIGATE_NOW"


# ---------------------------------------------------------------------------
# 7. Attack chain.
# ---------------------------------------------------------------------------


def test_consider_tightening_attack_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """3 KNOWN_ADVERSARIAL events within 60s on the same session
    surface attack_chain_signature + INVESTIGATE_NOW + high confidence.
    """
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    base = _BASE_MS
    window = [
        _event(
            action="iam:CreateAccessKey",
            resource="user/victim",
            time_ms=base + 0,
            session="sess-chain",
        ),
        _event(
            action="iam:AttachUserPolicy",
            resource="user/victim",
            time_ms=base + 10_000,
            session="sess-chain",
        ),
        _event(
            action="cloudtrail:StopLogging",
            resource="trail/audit",
            time_ms=base + 30_000,
            session="sess-chain",
        ),
    ]
    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=window,
        bouncer_kind="ibounce",
    )
    shapes = {sp.shape for sp in resp.suspect_patterns}
    assert "attack_chain_signature" in shapes
    chain = [
        sp for sp in resp.suspect_patterns
        if sp.shape == "attack_chain_signature"
    ]
    assert chain
    assert chain[0].recommended_action == "INVESTIGATE_NOW"
    # High confidence per design — KNOWN_ADVERSARIAL is calibrated +
    # temporal clustering is meaningful.
    assert chain[0].confidence >= 0.85, (
        f"attack_chain confidence too low: {chain[0].confidence}"
    )
    # Observable: surfaced events are the chain itself.
    assert len(chain[0].events) >= 2
    # Plus the KNOWN_ADVERSARIAL detector fires its own
    # BLOCK_PROACTIVELY for EACH hit; operator_attention_required must
    # be True.
    assert resp.operator_attention_required is True


# ---------------------------------------------------------------------------
# 8. operator_attention_required boolean math.
# ---------------------------------------------------------------------------


def test_consider_tightening_operator_attention_required_logic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per design §6 Step 5:
       * BLOCK_PROACTIVELY → True
       * INVESTIGATE_NOW with confidence>=0.7 → True
       * narrowing_proposals count > 5 → True
       * else False
    """
    from iam_jit.llm.tightening import _operator_attention_required

    # No signals → False.
    assert _operator_attention_required(
        suspect_patterns=[],
        narrowing_proposals=[],
    ) is False

    # 5 narrowings (not >5) → False.
    five = [
        NarrowingProposal(
            rule_to_add={}, expected_friction_delta=0,
            confidence=0.5, rationale="",
        )
        for _ in range(5)
    ]
    assert _operator_attention_required(
        suspect_patterns=[],
        narrowing_proposals=five,
    ) is False

    # 6 narrowings → True.
    six = five + [
        NarrowingProposal(
            rule_to_add={}, expected_friction_delta=0,
            confidence=0.5, rationale="",
        )
    ]
    assert _operator_attention_required(
        suspect_patterns=[],
        narrowing_proposals=six,
    ) is True

    # BLOCK_PROACTIVELY → True regardless of confidence.
    block = SuspectPattern(
        shape="known_adversarial_pattern_match",
        confidence=0.1,
        events=[],
        recommended_action="BLOCK_PROACTIVELY",
        mitre_atlas_tag="T1078",
        rationale="",
    )
    assert _operator_attention_required(
        suspect_patterns=[block],
        narrowing_proposals=[],
    ) is True

    # INVESTIGATE_NOW with low confidence (<0.7) → NOT True.
    low = SuspectPattern(
        shape="sudden_friction_spike",
        confidence=0.5,
        events=[],
        recommended_action="INVESTIGATE_NOW",
        mitre_atlas_tag="TA0001",
        rationale="",
    )
    assert _operator_attention_required(
        suspect_patterns=[low],
        narrowing_proposals=[],
    ) is False

    # INVESTIGATE_NOW with confidence >= 0.7 → True.
    high = SuspectPattern(
        shape="sudden_friction_spike",
        confidence=0.7,
        events=[],
        recommended_action="INVESTIGATE_NOW",
        mitre_atlas_tag="TA0001",
        rationale="",
    )
    assert _operator_attention_required(
        suspect_patterns=[high],
        narrowing_proposals=[],
    ) is True

    # LOG_AND_OBSERVE only → False.
    observe = SuspectPattern(
        shape="unprecedented_action",
        confidence=0.9,  # high but action is just observe
        events=[],
        recommended_action="LOG_AND_OBSERVE",
        mitre_atlas_tag="TA0004",
        rationale="",
    )
    assert _operator_attention_required(
        suspect_patterns=[observe],
        narrowing_proposals=[],
    ) is False


# ---------------------------------------------------------------------------
# 9. Provenance carries calibration state per [[ibounce-honest-positioning]].
# ---------------------------------------------------------------------------


def test_consider_tightening_provenance_calibrated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provenance MUST carry:
       * narrowing_calibrated = True (Phase 10 corpus shipped)
       * suspect_pattern_calibrated = False (Phase 16 follow-up)
       * a warning that explains the NOT-YET-CALIBRATED state for
         suspect patterns when any are surfaced
       * engine identifier
    """
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    # No suspects → no calibration warning (avoids noise on empty path).
    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=[],
        bouncer_kind="ibounce",
    )
    assert resp.provenance["narrowing_calibrated"] is True
    assert resp.provenance["suspect_pattern_calibrated"] is False
    assert resp.provenance["engine"] == "consider-tightening-python"
    # No suspects → no calibration warning (the warning only fires when
    # operators are actually consuming suspect output).
    assert not any(
        "NOT corpus-validated" in w
        for w in resp.provenance["warnings"]
    )

    # With suspects → calibration warning fires.
    resp2 = consider_tightening(
        profile=_profile_empty(),
        audit_events=[_event(action="iam:CreateAccessKey", resource="*")],
        bouncer_kind="ibounce",
    )
    assert any(
        "NOT corpus-validated" in w
        for w in resp2.provenance["warnings"]
    )
    # AND the prompt-injection-AWARE qualifier is surfaced.
    assert any(
        "prompt-injection-AWARE" in w
        for w in resp2.provenance["warnings"]
    )


# ---------------------------------------------------------------------------
# 10. friction_budget carries through.
# ---------------------------------------------------------------------------


def test_consider_tightening_friction_budget_carries_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``friction_budget`` MUST be passed to the improve pipeline. We
    monkeypatch to capture the kwargs."""
    from iam_jit.improve import pipeline as pipe

    captured: dict[str, Any] = {}

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings = ["friction-budget gate refused 1 narrowing(s)"]
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    def _capture(**kw: Any) -> _StubResult:
        captured.update(kw)
        return _StubResult()

    monkeypatch.setattr(pipe, "improve_profile", _capture)

    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=[_event(action="s3:GetObject")],
        bouncer_kind="ibounce",
        friction_budget=10,
    )
    assert captured["friction_budget"] == 10
    # Upstream warning carries through to provenance so the operator
    # sees that narrowings WERE refused — the observable trace, not a
    # silently dropped count.
    assert any(
        "refused" in w.lower() for w in resp.provenance["warnings"]
    )


# ---------------------------------------------------------------------------
# 11. History-depth warning.
# ---------------------------------------------------------------------------


def test_consider_tightening_history_depth_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """history_depth_days=30 + actual history span only ~1 day →
    provenance.history_depth_warning fires AND surfaces in warnings."""
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    history = [
        _event(action="s3:GetObject", time_ms=_BASE_MS - i * 60_000)
        for i in range(10)
    ]
    # ~10 minutes of history; we declare 30d depth.
    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=[_event(action="s3:GetObject")],
        bouncer_kind="ibounce",
        history_events=history,
        history_depth_days=30,
    )
    assert resp.provenance["history_depth_warning"], (
        f"expected history_depth_warning to fire; "
        f"got provenance={resp.provenance}"
    )
    # Surfaced in warnings too.
    assert any(
        "REDUCED CONFIDENCE" in w for w in resp.provenance["warnings"]
    )


# ---------------------------------------------------------------------------
# 12. Sabotage check — monkeypatching is_known_adversarial breaks test 3.
# ---------------------------------------------------------------------------


def test_consider_tightening_sabotage_known_adversarial_breaks_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage-check per CONTRIBUTING.md: monkeypatch
    is_known_adversarial to always return False. Test 3's assertion
    (iam:CreateAccessKey → BLOCK_PROACTIVELY) MUST then fail, proving
    test 3's green is load-bearing on the real catalogue + not a
    fixture coincidence.
    """
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    # Sabotage the import that tightening.py uses internally.
    monkeypatch.setattr(
        "iam_jit.llm.tightening.is_known_adversarial",
        lambda *_a, **_kw: False,
    )

    bad_event = _event(action="iam:CreateAccessKey", resource="*")
    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=[bad_event],
        bouncer_kind="ibounce",
    )
    shapes = {sp.shape for sp in resp.suspect_patterns}
    # With sabotage in place the KNOWN_ADVERSARIAL detection cannot
    # fire — so the suspect_patterns block must NOT contain the
    # adversarial-match shape.
    assert "known_adversarial_pattern_match" not in shapes, (
        f"sabotage failed — known_adversarial still fired; "
        f"shapes={shapes}"
    )
    # And without that detector, operator_attention_required is NOT
    # forced True by this single event (no other detector applies on
    # this empty-history input).
    assert resp.operator_attention_required is False

    # Counter-evidence: with the sabotage UNDONE the same event DOES
    # surface the adversarial pattern. We can't undo a single
    # monkeypatch.setattr easily, so we re-stub to the real function
    # by re-importing from the source module.
    from iam_jit.deny_classifier.classifier import (
        is_known_adversarial as _real,
    )
    monkeypatch.setattr(
        "iam_jit.llm.tightening.is_known_adversarial", _real,
    )
    resp2 = consider_tightening(
        profile=_profile_empty(),
        audit_events=[bad_event],
        bouncer_kind="ibounce",
    )
    shapes2 = {sp.shape for sp in resp2.suspect_patterns}
    assert "known_adversarial_pattern_match" in shapes2, (
        f"counter-evidence failed — restoring is_known_adversarial "
        f"did NOT make detection fire; shapes={shapes2}"
    )


# ---------------------------------------------------------------------------
# 13. MCP round-trip via _handle_request.
# ---------------------------------------------------------------------------


def test_consider_tightening_mcp_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end MCP dispatch:
       * tools/list MUST advertise iam_jit_consider_tightening
       * tools/call MUST round-trip a synthetic adversarial event
         and a synthetic legit window, returning the serialised
         TighteningResponse shape.
    """
    from iam_jit.improve import pipeline as pipe
    from iam_jit.mcp_server import _handle_request

    class _StubResult:
        proposed_removals: list[dict[str, Any]] = []
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    # tools/list must advertise the new tool with the right schema.
    list_resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    tools_by_name = {t["name"]: t for t in list_resp["result"]["tools"]}
    assert "iam_jit_consider_tightening" in tools_by_name
    schema = tools_by_name["iam_jit_consider_tightening"]["inputSchema"]
    props = schema["properties"]
    for required in ("profile", "audit_events", "bouncer_kind"):
        assert required in props
    assert set(schema["required"]) == {
        "profile", "audit_events", "bouncer_kind",
    }

    # tools/call with an adversarial event must surface the
    # KNOWN_ADVERSARIAL suspect block + BLOCK_PROACTIVELY.
    bad_event = _event(action="iam:CreateAccessKey", resource="*")
    call_resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "iam_jit_consider_tightening",
            "arguments": {
                "profile": _profile_empty(),
                "audit_events": [bad_event],
                "bouncer_kind": "ibounce",
            },
        },
    })
    sc = call_resp["result"]["structuredContent"]
    assert sc["bouncer_kind"] == "ibounce"
    assert sc["operator_attention_required"] is True
    shapes = {sp["shape"] for sp in sc["suspect_patterns"]}
    assert "known_adversarial_pattern_match" in shapes
    # Provenance carries the honest framing.
    assert sc["provenance"]["narrowing_calibrated"] is True
    assert sc["provenance"]["suspect_pattern_calibrated"] is False
    # The "text" block carries the JSON-serialised structuredContent
    # too (MCP text-format consumers).
    text = call_resp["result"]["content"][0]["text"]
    parsed = json.loads(text)
    assert (
        parsed["operator_attention_required"]
        == sc["operator_attention_required"]
    )

    # tools/call with a benign synthetic window must NOT raise
    # operator_attention_required (no BLOCK_PROACTIVELY, no
    # INVESTIGATE_NOW with conf>=0.7, ≤5 narrowings).
    benign_event = _event(action="s3:GetObject", resource="bucket/object")
    call_resp2 = _handle_request({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "iam_jit_consider_tightening",
            "arguments": {
                "profile": _profile_empty(),
                "audit_events": [benign_event],
                "bouncer_kind": "ibounce",
            },
        },
    })
    sc2 = call_resp2["result"]["structuredContent"]
    assert sc2["operator_attention_required"] is False
    assert sc2["suspect_patterns"] == []


# ---------------------------------------------------------------------------
# Serialisation determinism — explicit per [[ibounce-honest-positioning]].
# ---------------------------------------------------------------------------


def test_serialize_tightening_response_round_trips_through_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The serialiser output MUST be JSON-safe — frozen-dataclass
    nesting cannot leak. We round-trip through json.dumps/loads to
    verify."""
    from iam_jit.improve import pipeline as pipe

    class _StubResult:
        proposed_removals = [
            {"action": "s3:GetObject", "target": "arn:aws:s3:::cache"},
        ]
        warnings: list[str] = []
        friction_metrics_baseline: dict[str, Any] = {}
        friction_metrics_if_applied: dict[str, Any] = {}

    monkeypatch.setattr(
        pipe, "improve_profile", lambda **_kw: _StubResult(),
    )

    resp = consider_tightening(
        profile=_profile_empty(),
        audit_events=[_event(action="iam:CreateAccessKey", resource="*")],
        bouncer_kind="ibounce",
    )
    serialised = serialize_tightening_response(resp)
    blob = json.dumps(serialised)
    parsed = json.loads(blob)
    assert parsed["bouncer_kind"] == "ibounce"
    assert "narrowing_proposals" in parsed
    assert "suspect_patterns" in parsed
    assert parsed["operator_attention_required"] is True
