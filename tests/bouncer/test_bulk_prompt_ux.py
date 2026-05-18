"""Tests for #253 — bulk-prompt-answer UX for burst-of-denies (ibounce).

Covers:
- BurstDetector fires at threshold; resets after operator answer
- BurstDetector re-arms after cool-down even without answer
- Bulk-answer creates time-bounded ALLOW rule with correct expires_at
- Rule sweeper removes expired rules from active RuleSet; preserves
  rows in DB for audit per [[creates-never-mutates]]
- Profile-switch option hot-swaps active profile + marks prompts answered
- Pre-burst hint suppression contract (non-TTY)
- MCP bulk-answer tool default-disabled error
- MCP bulk-answer tool with operator-set token works
- MCP bulk-answer tool rejects wrong tokens
- Neutral-language scan (no FORBIDDEN_ALERT_WORDS in user-facing strings)

Per [[deliberate-feature-completion]]: every slice of the feature is
exercised end-to-end here so a future regression caught by ONE of
these is immediately attributable to a specific seam.

Per [[security-team-positioning-safety-not-surveillance]]: the
neutral-language scan asserts the burst event + CLI strings + MCP
returns stay clean.
"""

from __future__ import annotations

import datetime as _dt
import time

import click.testing
import pytest

from iam_jit.bouncer.audit_export.alerts import FORBIDDEN_ALERT_WORDS
from iam_jit.bouncer.burst import (
    EVENT_TYPE_BURST_DETECTED,
    BurstDetector,
    bulk_answer_mcp_token_configured,
    make_burst_detected_event,
    register_burst_detector,
    reset_for_tests,
    set_bulk_answer_mcp_token,
    verify_bulk_answer_mcp_token,
)
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_burst_module():
    """Each test starts with a clean module-level singleton + token."""
    reset_for_tests()
    set_bulk_answer_mcp_token(None)
    yield
    reset_for_tests()
    set_bulk_answer_mcp_token(None)


@pytest.fixture
def store(tmp_path):
    db = BouncerStore(db_path=str(tmp_path / "bulk.db"))
    yield db
    db.close()


# ---------------------------------------------------------------------------
# BurstDetector — sliding-window + cool-down
# ---------------------------------------------------------------------------


def test_burst_detector_fires_at_threshold():
    """Threshold N events within window T → BURST_DETECTED."""
    emitted: list[dict] = []
    d = BurstDetector(threshold=3, window_seconds=10, emit=emitted.append)
    now = 1_000.0
    assert d.observe(now=now) is False  # 1
    assert d.observe(now=now + 1) is False  # 2
    fired = d.observe(now=now + 2)  # 3 — crosses threshold
    assert fired is True
    assert len(emitted) == 1
    event = emitted[0]
    assert event["activity_name"] == "prompt_burst_detected"
    assert event["activity_id"] == 99
    assert event["severity_id"] == 2  # Low per spec
    assert event["class_uid"] == 6003
    ext = event["unmapped"]["iam_jit"]["ext"]
    assert ext["pending_count"] == 3
    assert ext["window_seconds"] == 10
    assert ext["oldest_pending_seconds_ago"] >= 0


def test_burst_detector_under_threshold_does_not_fire():
    emitted: list[dict] = []
    d = BurstDetector(threshold=5, window_seconds=10, emit=emitted.append)
    for i in range(4):
        assert d.observe(now=1000.0 + i) is False
    assert emitted == []


def test_burst_detector_window_eviction():
    """Old timestamps fall out of the window + don't count."""
    emitted: list[dict] = []
    d = BurstDetector(threshold=3, window_seconds=10, emit=emitted.append)
    # Two events in initial window, then jump well past window.
    d.observe(now=1_000.0)
    d.observe(now=1_001.0)
    # 20s later — the prior two have aged out.
    assert d.observe(now=1_020.0) is False
    assert d.observe(now=1_021.0) is False
    assert emitted == []


def test_burst_detector_resets_after_operator_answer():
    """`reset()` clears the window + re-arms the detector."""
    emitted: list[dict] = []
    d = BurstDetector(threshold=3, window_seconds=60, emit=emitted.append)
    for i in range(3):
        d.observe(now=1_000.0 + i)
    assert len(emitted) == 1
    d.reset()
    # New burst should fire again.
    for i in range(3):
        d.observe(now=2_000.0 + i)
    assert len(emitted) == 2


def test_burst_detector_cool_down_re_arms():
    """If operator never answers, cool-down elapses → re-fire allowed."""
    emitted: list[dict] = []
    d = BurstDetector(
        threshold=2, window_seconds=10, cool_down_seconds=60,
        emit=emitted.append,
    )
    d.observe(now=1_000.0)
    d.observe(now=1_001.0)  # fires
    assert len(emitted) == 1
    # Same window, more observations — suppressed.
    d.observe(now=1_002.0)
    d.observe(now=1_003.0)
    assert len(emitted) == 1
    # Long-after the cool-down — fires again.
    d.observe(now=1_100.0)
    d.observe(now=1_101.0)
    assert len(emitted) == 2


def test_burst_detector_pending_hint_returns_none_when_not_firing():
    d = BurstDetector(threshold=5, window_seconds=10)
    assert d.pending_hint(now=1_000.0) is None


def test_burst_detector_pending_hint_returns_dict_when_firing():
    d = BurstDetector(threshold=2, window_seconds=10)
    d.observe(now=1_000.0)
    d.observe(now=1_001.0)
    hint = d.pending_hint(now=1_002.0)
    assert hint is not None
    assert hint["pending_count"] == 2
    assert hint["window_seconds"] == 10
    assert hint["threshold"] == 2


def test_burst_detector_validation():
    with pytest.raises(ValueError):
        BurstDetector(threshold=0, window_seconds=10)
    with pytest.raises(ValueError):
        BurstDetector(threshold=1, window_seconds=0)
    with pytest.raises(ValueError):
        BurstDetector(threshold=1, window_seconds=10, cool_down_seconds=-1)


def test_burst_detector_emit_failure_is_swallowed():
    """A broken transport must not kill the detector / proxy."""
    def boom(_event):
        raise RuntimeError("transport down")
    d = BurstDetector(threshold=2, window_seconds=10, emit=boom)
    # Should not raise.
    d.observe(now=1_000.0)
    d.observe(now=1_001.0)


# ---------------------------------------------------------------------------
# OCSF event builder
# ---------------------------------------------------------------------------


def test_make_burst_detected_event_shape():
    e = make_burst_detected_event(
        pending_count=7,
        window_seconds=60,
        oldest_pending_seconds_ago=45,
    )
    assert e["class_uid"] == 6003
    assert e["class_name"] == "API Activity"
    assert e["category_uid"] == 6
    assert e["activity_id"] == 99
    assert e["activity_name"] == "prompt_burst_detected"
    assert e["severity_id"] == 2
    assert e["severity"] == "Low"
    assert e["status_id"] == 99
    assert e["unmapped"]["iam_jit"]["event_type"] == EVENT_TYPE_BURST_DETECTED
    assert e["unmapped"]["iam_jit"]["ext"]["pending_count"] == 7
    assert e["unmapped"]["iam_jit"]["ext"]["window_seconds"] == 60
    assert e["unmapped"]["iam_jit"]["ext"]["oldest_pending_seconds_ago"] == 45
    assert e["metadata"]["product"]["name"] == "ibounce"
    assert e["metadata"]["product"]["vendor_name"] == "iam-jit"


# ---------------------------------------------------------------------------
# Time-bounded rule support (expires_at column + sweeper)
# ---------------------------------------------------------------------------


def test_rule_with_expires_at_persists_through_round_trip(store):
    expiry = (
        _dt.datetime.now(_dt.UTC) + _dt.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    rid = store.add_rule(ProxyRule(
        pattern="s3:GetObject",
        effect=Effect.ALLOW,
        arn_scope="arn:aws:s3:::b/*",
        region_scope=None,
        note="time-bounded",
        origin="bulk-allow-time-bounded",
        expires_at=expiry,
    ))
    fetched = store.get_rule(rid)
    assert fetched is not None
    assert fetched.expires_at == expiry
    assert fetched.origin == "bulk-allow-time-bounded"


def test_list_active_rules_filters_expired(store):
    """Expired rules are hidden from list_active_rules + are still in
    list_rules (audit preservation per creates-never-mutates)."""
    past = (
        _dt.datetime.now(_dt.UTC) - _dt.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    future = (
        _dt.datetime.now(_dt.UTC) + _dt.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    store.add_rule(ProxyRule(
        pattern="s3:PutObject", effect=Effect.ALLOW,
        expires_at=past, note="expired",
    ))
    store.add_rule(ProxyRule(
        pattern="s3:GetObject", effect=Effect.ALLOW,
        expires_at=future, note="active",
    ))
    store.add_rule(ProxyRule(
        pattern="s3:ListBucket", effect=Effect.ALLOW,
        expires_at=None, note="permanent",
    ))
    all_rules = store.list_rules()
    active_rules = store.list_active_rules()
    assert len(all_rules) == 3
    active_patterns = {r.pattern for _, r in active_rules}
    assert "s3:GetObject" in active_patterns
    assert "s3:ListBucket" in active_patterns
    assert "s3:PutObject" not in active_patterns  # expired


def test_expire_rules_at_emits_config_event_once_per_rule(store):
    """Sweeper fires the `rule_expired` audit event idempotently."""
    past = (
        _dt.datetime.now(_dt.UTC) - _dt.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    rid = store.add_rule(ProxyRule(
        pattern="s3:DeleteObject", effect=Effect.ALLOW,
        expires_at=past, note="expired",
    ))
    newly = store.expire_rules_at()
    assert rid in newly
    # Second call within the same process — already seen, no re-fire.
    newly2 = store.expire_rules_at()
    assert newly2 == []
    events = store.list_config_events(kind_filter="rule_expired")
    assert len(events) == 1
    assert events[0]["target_id"] == rid


def test_expired_rules_preserved_in_db(store):
    """Per [[creates-never-mutates]]: rows are NEVER deleted by expiry."""
    past = (
        _dt.datetime.now(_dt.UTC) - _dt.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    rid = store.add_rule(ProxyRule(
        pattern="s3:PutObject", effect=Effect.ALLOW,
        expires_at=past, note="expired",
    ))
    store.expire_rules_at()
    fetched = store.get_rule(rid)
    assert fetched is not None  # NOT deleted
    assert fetched.expires_at == past


# ---------------------------------------------------------------------------
# Bulk-answer behavior — time-bounded
# ---------------------------------------------------------------------------


def _seed_pending_prompts(store, *, count: int, service="s3", action="GetObject"):
    """Insert `count` pending deny-prompts via the store's API (the
    bulk-answer helpers read pending_prompts, not raw rows)."""
    for i in range(count):
        # Each call mints a fresh decision row.
        from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
        dec_id = store.record_decision(DecisionRecord(
            decision=Decision.DENY,
            mode=Mode.ENFORCE,
            service=service,
            action=action,
            arn=f"arn:aws:s3:::bucket-{i}",
            region="us-east-1",
            matched_rule=None,
            reason="test seed",
        ))
        store.add_pending_prompt(
            decision_id=dec_id,
            service=service,
            action=action,
            arn=f"arn:aws:s3:::bucket-{i}",
            region="us-east-1",
            deny_reason="test seed",
        )


def test_apply_bulk_time_bounded_creates_rules_with_expiry(store):
    from iam_jit.bouncer_cli import _apply_bulk_time_bounded
    _seed_pending_prompts(store, count=4)
    pending = store.list_pending_prompts(status="pending", kind="deny-prompt")
    assert len(pending) == 4
    rules_added, answered, expires_at = _apply_bulk_time_bounded(
        store=store, pending_rows=pending,
        duration_key="10min", actor="tester",
    )
    assert rules_added == 4
    assert answered == 4
    # Verify expires_at is ~10min in the future (allow 5s skew)
    expires_dt = _dt.datetime.strptime(
        expires_at, "%Y-%m-%dT%H:%M:%SZ",
    ).replace(tzinfo=_dt.UTC)
    delta = (expires_dt - _dt.datetime.now(_dt.UTC)).total_seconds()
    assert 590 <= delta <= 610
    # Verify the rules exist + are time-bounded
    rules = store.list_rules()
    bulk_rules = [r for _, r in rules if r.origin == "bulk-allow-time-bounded"]
    assert len(bulk_rules) == 4
    for r in bulk_rules:
        assert r.expires_at == expires_at
        assert r.effect == Effect.ALLOW
    # Verify pending prompts are answered
    still_pending = store.list_pending_prompts(status="pending", kind="deny-prompt")
    assert len(still_pending) == 0


def test_apply_bulk_time_bounded_session_duration(store):
    from iam_jit.bouncer_cli import _apply_bulk_time_bounded
    _seed_pending_prompts(store, count=2)
    pending = store.list_pending_prompts(status="pending", kind="deny-prompt")
    _, _, expires_at = _apply_bulk_time_bounded(
        store=store, pending_rows=pending,
        duration_key="session", actor="tester",
    )
    expires_dt = _dt.datetime.strptime(
        expires_at, "%Y-%m-%dT%H:%M:%SZ",
    ).replace(tzinfo=_dt.UTC)
    delta = (expires_dt - _dt.datetime.now(_dt.UTC)).total_seconds()
    # session = 3600s (60min)
    assert 3590 <= delta <= 3610


def test_apply_bulk_time_bounded_3h_duration(store):
    from iam_jit.bouncer_cli import _apply_bulk_time_bounded
    _seed_pending_prompts(store, count=2)
    pending = store.list_pending_prompts(status="pending", kind="deny-prompt")
    _, _, expires_at = _apply_bulk_time_bounded(
        store=store, pending_rows=pending,
        duration_key="3h", actor="tester",
    )
    expires_dt = _dt.datetime.strptime(
        expires_at, "%Y-%m-%dT%H:%M:%SZ",
    ).replace(tzinfo=_dt.UTC)
    delta = (expires_dt - _dt.datetime.now(_dt.UTC)).total_seconds()
    assert (3 * 3600 - 10) <= delta <= (3 * 3600 + 10)


def test_apply_bulk_time_bounded_dedupes_same_service_action(store):
    """4 prompts for s3:GetObject across 4 different ARNs → 4 rules
    (different arn_scope each). 4 prompts for same ARN → 1 rule."""
    from iam_jit.bouncer_cli import _apply_bulk_time_bounded
    from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
    # All same ARN
    for _ in range(3):
        dec_id = store.record_decision(DecisionRecord(
            decision=Decision.DENY, mode=Mode.ENFORCE,
            service="s3", action="GetObject",
            arn="arn:aws:s3:::same/*", region="us-east-1",
            matched_rule=None, reason="seed",
        ))
        store.add_pending_prompt(
            decision_id=dec_id, service="s3", action="GetObject",
            arn="arn:aws:s3:::same/*", region="us-east-1",
            deny_reason="seed",
        )
    pending = store.list_pending_prompts(status="pending", kind="deny-prompt")
    assert len(pending) == 3
    rules_added, answered, _ = _apply_bulk_time_bounded(
        store=store, pending_rows=pending,
        duration_key="10min", actor="tester",
    )
    assert rules_added == 1
    assert answered == 3


def test_apply_bulk_time_bounded_rejects_bad_duration(store):
    from iam_jit.bouncer_cli import _apply_bulk_time_bounded
    with pytest.raises(ValueError):
        _apply_bulk_time_bounded(
            store=store, pending_rows=[],
            duration_key="forever", actor="tester",
        )


# ---------------------------------------------------------------------------
# Bulk-answer behavior — profile switch
# ---------------------------------------------------------------------------


def test_apply_bulk_profile_switch_hot_swaps_active_profile(store, monkeypatch):
    from iam_jit.bouncer.proxy import (
        active_profile_override,
        set_session_profile_override,
    )
    from iam_jit.bouncer_cli import _apply_bulk_profile_switch
    # Ensure clean override slot
    set_session_profile_override(None)
    # Seed pending prompts
    _seed_pending_prompts(store, count=3)
    pending = store.list_pending_prompts(status="pending", kind="deny-prompt")
    # Use the built-in `full-user` profile which is always available
    profile_obj, answered = _apply_bulk_profile_switch(
        store=store, pending_rows=pending,
        profile_name="full-user", actor="tester",
    )
    assert profile_obj.name == "full-user"
    assert answered == 3
    # In-process override is now set
    assert active_profile_override() is not None
    assert active_profile_override().name == "full-user"
    # Pending prompts answered with profile-switch marker
    answered_rows = store.list_pending_prompts(status="answered", kind="deny-prompt")
    assert len(answered_rows) == 3
    for r in answered_rows:
        assert r["answer_target"].startswith("profile-switch:")
    # Clean up the override
    set_session_profile_override(None)


def test_apply_bulk_profile_switch_unknown_profile_raises(store):
    from iam_jit.bouncer_cli import _apply_bulk_profile_switch
    with pytest.raises(ValueError, match="not found"):
        _apply_bulk_profile_switch(
            store=store, pending_rows=[],
            profile_name="not-a-real-profile-xyz-123", actor="tester",
        )


# ---------------------------------------------------------------------------
# CLI surface — `prompts bulk-answer`
# ---------------------------------------------------------------------------


def test_cli_bulk_answer_non_interactive_with_decision(tmp_path, monkeypatch):
    from iam_jit.bouncer_cli import main
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "cli.db"))
    # Seed pending prompts via store
    s = BouncerStore(db_path=str(tmp_path / "cli.db"))
    try:
        _seed_pending_prompts(s, count=3)
    finally:
        s.close()
    runner = click.testing.CliRunner()
    result = runner.invoke(
        main,
        ["prompts", "bulk-answer", "--non-interactive",
         "--decision", "10min"],
    )
    assert result.exit_code == 0, result.output
    assert "allowed 3" in result.output or "1" in result.output
    # Verify rules exist
    s = BouncerStore(db_path=str(tmp_path / "cli.db"))
    try:
        rules = s.list_rules()
        bulk = [r for _, r in rules if r.origin == "bulk-allow-time-bounded"]
        assert len(bulk) == 3
    finally:
        s.close()


def test_cli_bulk_answer_decision_none_is_noop(tmp_path, monkeypatch):
    from iam_jit.bouncer_cli import main
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "cli.db"))
    s = BouncerStore(db_path=str(tmp_path / "cli.db"))
    try:
        _seed_pending_prompts(s, count=3)
    finally:
        s.close()
    runner = click.testing.CliRunner()
    result = runner.invoke(
        main,
        ["prompts", "bulk-answer", "--non-interactive",
         "--decision", "none"],
    )
    assert result.exit_code == 0, result.output
    s = BouncerStore(db_path=str(tmp_path / "cli.db"))
    try:
        # Pending still pending
        assert len(s.list_pending_prompts(status="pending")) == 3
        # No rules added
        assert len(s.list_rules()) == 0
    finally:
        s.close()


def test_cli_bulk_answer_no_pending_is_friendly(tmp_path, monkeypatch):
    from iam_jit.bouncer_cli import main
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "cli.db"))
    runner = click.testing.CliRunner()
    result = runner.invoke(
        main, ["prompts", "bulk-answer", "--non-interactive",
               "--decision", "10min"],
    )
    assert result.exit_code == 0
    assert "no pending" in result.output.lower()


def test_cli_bulk_answer_non_interactive_without_decision_errors(
    tmp_path, monkeypatch,
):
    from iam_jit.bouncer_cli import main
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "cli.db"))
    s = BouncerStore(db_path=str(tmp_path / "cli.db"))
    try:
        _seed_pending_prompts(s, count=5)
    finally:
        s.close()
    runner = click.testing.CliRunner()
    # No --decision + stdin is not TTY (test runner) → must error
    result = runner.invoke(
        main, ["prompts", "bulk-answer", "--non-interactive"],
    )
    assert result.exit_code == 2
    assert "TTY required" in result.output or "TTY" in result.output


# ---------------------------------------------------------------------------
# MCP tool gating — default disabled
# ---------------------------------------------------------------------------


def test_mcp_bulk_answer_default_disabled():
    """No token configured → MCP tool returns the documented error."""
    from iam_jit.mcp_server import _bouncer_prompts_bulk_answer_for_mcp
    # Default state (autouse fixture cleared)
    assert bulk_answer_mcp_token_configured() is False
    result = _bouncer_prompts_bulk_answer_for_mcp({
        "decision": "10min", "token": "anything",
    })
    assert "error" in result
    assert "disabled by default" in result["error"]
    assert "--bulk-answer-mcp-token" in result["error"]


def test_mcp_bulk_answer_rejects_wrong_token():
    set_bulk_answer_mcp_token("correct-token-xyz")
    assert bulk_answer_mcp_token_configured() is True
    from iam_jit.mcp_server import _bouncer_prompts_bulk_answer_for_mcp
    result = _bouncer_prompts_bulk_answer_for_mcp({
        "decision": "10min", "token": "wrong-token",
    })
    assert result.get("error") == "invalid token"


def test_mcp_bulk_answer_rejects_missing_token():
    set_bulk_answer_mcp_token("correct-token-xyz")
    from iam_jit.mcp_server import _bouncer_prompts_bulk_answer_for_mcp
    result = _bouncer_prompts_bulk_answer_for_mcp({"decision": "10min"})
    assert "error" in result
    assert "token" in result["error"].lower()


def test_mcp_bulk_answer_accepts_correct_token(tmp_path, monkeypatch):
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "mcp.db"))
    set_bulk_answer_mcp_token("correct-token")
    s = BouncerStore(db_path=str(tmp_path / "mcp.db"))
    try:
        _seed_pending_prompts(s, count=3)
    finally:
        s.close()
    from iam_jit.mcp_server import _bouncer_prompts_bulk_answer_for_mcp
    result = _bouncer_prompts_bulk_answer_for_mcp({
        "decision": "10min", "token": "correct-token",
    })
    assert "error" not in result
    assert result["applied"] == "10min"
    assert result["rules_added"] == 3
    assert result["prompts_answered"] == 3
    assert result["expires_at"] is not None


def test_verify_token_constant_time_against_unset():
    """No token configured → verify returns False regardless of input."""
    assert verify_bulk_answer_mcp_token("anything") is False
    assert verify_bulk_answer_mcp_token("") is False
    assert verify_bulk_answer_mcp_token(None) is False


def test_verify_token_correct_and_wrong():
    set_bulk_answer_mcp_token("right")
    assert verify_bulk_answer_mcp_token("right") is True
    assert verify_bulk_answer_mcp_token("wrong") is False
    assert verify_bulk_answer_mcp_token(None) is False


# ---------------------------------------------------------------------------
# MCP read tool — bulk_pending
# ---------------------------------------------------------------------------


def test_mcp_bulk_pending_returns_options(tmp_path, monkeypatch):
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "rd.db"))
    s = BouncerStore(db_path=str(tmp_path / "rd.db"))
    try:
        _seed_pending_prompts(s, count=2)
    finally:
        s.close()
    from iam_jit.mcp_server import _bouncer_prompts_bulk_pending_for_mcp
    result = _bouncer_prompts_bulk_pending_for_mcp({})
    assert result["pending_count"] == 2
    keys = {o["key"] for o in result["options"]}
    assert keys == {"profile", "session", "3h", "10min", "none"}
    assert "language_note" in result


def test_mcp_bulk_pending_with_burst_firing(tmp_path, monkeypatch):
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "rd.db"))
    s = BouncerStore(db_path=str(tmp_path / "rd.db"))
    try:
        _seed_pending_prompts(s, count=6)
    finally:
        s.close()
    # Install a detector with a low threshold to make it fire.
    d = BurstDetector(threshold=3, window_seconds=60)
    for i in range(3):
        d.observe(now=time.time() + i)
    register_burst_detector(d)
    try:
        from iam_jit.mcp_server import _bouncer_prompts_bulk_pending_for_mcp
        result = _bouncer_prompts_bulk_pending_for_mcp({})
        assert result["burst_firing"] is True
        assert result["pending_count"] == 6
    finally:
        register_burst_detector(None)


# ---------------------------------------------------------------------------
# Neutral-language scan per [[security-team-positioning-...]]
# ---------------------------------------------------------------------------


def test_burst_event_strings_are_neutral():
    """The BURST_DETECTED event's user-facing strings must not contain
    any FORBIDDEN_ALERT_WORD ('violation' / 'infraction' /
    'unauthorized')."""
    e = make_burst_detected_event(
        pending_count=10, window_seconds=60,
        oldest_pending_seconds_ago=30,
    )
    haystack = (e.get("status_detail", "") + " " + e.get("activity_name", "")).lower()
    for bad in FORBIDDEN_ALERT_WORDS:
        assert bad not in haystack, (
            f"FORBIDDEN_ALERT_WORD {bad!r} appeared in BURST_DETECTED "
            f"status_detail: {e.get('status_detail')!r}"
        )


def test_cli_bulk_answer_output_is_neutral(tmp_path, monkeypatch):
    """The CLI bulk-answer subcommand's output must not contain
    FORBIDDEN_ALERT_WORDS."""
    from iam_jit.bouncer_cli import main
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "cli.db"))
    s = BouncerStore(db_path=str(tmp_path / "cli.db"))
    try:
        _seed_pending_prompts(s, count=3)
    finally:
        s.close()
    runner = click.testing.CliRunner()
    result = runner.invoke(
        main,
        ["prompts", "bulk-answer", "--non-interactive",
         "--decision", "session"],
    )
    out = (result.output or "").lower()
    for bad in FORBIDDEN_ALERT_WORDS:
        assert bad not in out, (
            f"FORBIDDEN_ALERT_WORD {bad!r} appeared in bulk-answer "
            f"CLI output: {result.output!r}"
        )


def test_mcp_bulk_pending_language_note_neutral():
    from iam_jit.mcp_server import _bouncer_prompts_bulk_pending_for_mcp
    result = _bouncer_prompts_bulk_pending_for_mcp({})
    # The language_note itself is a meta-instruction to agents; the
    # OPTION LABELS must stay clean.
    for opt in result["options"]:
        label = opt["label"].lower()
        for bad in FORBIDDEN_ALERT_WORDS:
            assert bad not in label, (
                f"FORBIDDEN_ALERT_WORD {bad!r} in bulk option label: "
                f"{opt['label']!r}"
            )


# ---------------------------------------------------------------------------
# End-to-end: bulk-answer makes the active RuleSet allow subsequent
# requests of the same shape.
# ---------------------------------------------------------------------------


def test_bulk_allow_rule_lets_subsequent_call_through(store):
    """After bulk-answer creates a time-bounded ALLOW rule, a subsequent
    decide() call for the same shape returns ALLOW."""
    from iam_jit.bouncer.decisions import (
        Decision, DefaultPolicy, Mode, decide,
    )
    from iam_jit.bouncer.rules import RuleSet
    from iam_jit.bouncer_cli import _apply_bulk_time_bounded

    _seed_pending_prompts(store, count=3, service="s3", action="GetObject")
    pending = store.list_pending_prompts(status="pending", kind="deny-prompt")
    _apply_bulk_time_bounded(
        store=store, pending_rows=pending,
        duration_key="10min", actor="tester",
    )
    # Now build a RuleSet from list_active_rules and verify ALLOW
    active = store.list_active_rules()
    rs = RuleSet(rules=[r for _, r in active])
    rec = decide(
        rs, mode=Mode.ENFORCE, default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
        arn="arn:aws:s3:::bucket-0",
    )
    assert rec.decision == Decision.ALLOW


def test_expired_bulk_rule_does_not_let_subsequent_call_through(store):
    """After an expired bulk-allow rule, decide() falls back to DENY."""
    from iam_jit.bouncer.decisions import (
        Decision, DefaultPolicy, Mode, decide,
    )
    from iam_jit.bouncer.rules import RuleSet

    past = (
        _dt.datetime.now(_dt.UTC) - _dt.timedelta(seconds=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    store.add_rule(ProxyRule(
        pattern="s3:GetObject", effect=Effect.ALLOW,
        arn_scope="arn:aws:s3:::b/*", expires_at=past,
        origin="bulk-allow-time-bounded",
    ))
    active = store.list_active_rules()
    rs = RuleSet(rules=[r for _, r in active])
    rec = decide(
        rs, mode=Mode.ENFORCE, default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
        arn="arn:aws:s3:::b/x",
    )
    assert rec.decision == Decision.DENY
