"""Tests for `bouncer pause` — timed escape hatch (#6a).

Covers:
- start_pause writes a row, returns id, sets ends_at = now + duration
- start_pause rejects duration <= 0
- start_pause rejects duration > 24h
- start_pause refuses if another pause is already active
- get_active_pause returns the live row, None when no pause active
- get_active_pause auto-expires past-its-end pauses (no daemon needed)
- end_pause marks ended_at_actual + end_kind=resumed_early
- end_pause returns None when no pause was active
- record_decision threads pause_id correctly
- list_recent_pauses returns history
- evaluate_request demotes mode TRANSPARENT → COOPERATIVE when paused
- _parse_duration accepts 30m / 2h / 90s; rejects garbage
"""

from __future__ import annotations

import datetime as dt
import time

import pytest

from iam_jit.bouncer.decisions import (
    Decision,
    DecisionRecord,
    DefaultPolicy,
    Mode,
)
from iam_jit.bouncer.proxy import ProxyMode, evaluate_request
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260517/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fake"
    )


# ---------------------------------------------------------------------------
# Store-level
# ---------------------------------------------------------------------------


def test_start_pause_writes_row_with_correct_ends_at(tmp_path) -> None:
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    before = dt.datetime.now(dt.UTC).replace(microsecond=0)
    pid = s.start_pause(duration_seconds=600, reason="test", started_by="me")
    after = dt.datetime.now(dt.UTC).replace(microsecond=0) + dt.timedelta(seconds=1)
    assert pid > 0
    active = s.get_active_pause()
    assert active is not None
    ends = dt.datetime.fromisoformat(active["ends_at"].replace("Z", "+00:00"))
    # Stored timestamps are truncated to second precision; compare on
    # second-aligned bounds.
    expected_lo = before + dt.timedelta(seconds=600)
    expected_hi = after + dt.timedelta(seconds=600)
    assert expected_lo <= ends <= expected_hi, (
        f"ends={ends} not in [{expected_lo}, {expected_hi}]"
    )
    assert active["reason"] == "test"
    assert active["started_by"] == "me"
    s.close()


def test_start_pause_rejects_zero_and_negative(tmp_path) -> None:
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    with pytest.raises(ValueError):
        s.start_pause(duration_seconds=0, reason="", started_by="me")
    with pytest.raises(ValueError):
        s.start_pause(duration_seconds=-1, reason="", started_by="me")
    s.close()


def test_start_pause_rejects_over_24h(tmp_path) -> None:
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    with pytest.raises(ValueError, match="24h"):
        s.start_pause(
            duration_seconds=24 * 3600 + 1, reason="", started_by="me",
        )
    s.close()


def test_start_pause_refuses_overlapping(tmp_path) -> None:
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    s.start_pause(duration_seconds=600, reason="", started_by="me")
    with pytest.raises(ValueError, match="already active"):
        s.start_pause(duration_seconds=300, reason="", started_by="me")
    s.close()


def test_get_active_pause_auto_expires_past_pauses(tmp_path) -> None:
    """The lazy-GC in _active_pause_locked is the auto-revert mechanism
    — no daemon thread, works in tests/serverless/anywhere."""
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    s.start_pause(duration_seconds=1, reason="", started_by="me")
    # Manually expire by sleeping past the window
    time.sleep(1.1)
    active = s.get_active_pause()
    assert active is None
    # And history should reflect the auto-expiry
    rows = s.list_recent_pauses()
    assert rows[0]["end_kind"] == "expired"
    assert rows[0]["ended_at_actual"] is not None
    s.close()


def test_end_pause_marks_resumed_early(tmp_path) -> None:
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    pid = s.start_pause(duration_seconds=600, reason="", started_by="me")
    ended = s.end_pause(ended_by="me")
    assert ended == pid
    assert s.get_active_pause() is None
    rows = s.list_recent_pauses()
    assert rows[0]["end_kind"] == "resumed_early"
    assert rows[0]["ended_at_actual"] is not None
    s.close()


def test_end_pause_returns_none_when_no_pause(tmp_path) -> None:
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    assert s.end_pause(ended_by="me") is None
    s.close()


def test_record_decision_links_pause_id(tmp_path) -> None:
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    pid = s.start_pause(duration_seconds=600, reason="", started_by="me")
    dec = DecisionRecord(
        decision=Decision.ALLOW, mode=Mode.ENFORCE,
        service="s3", action="GetObject", arn=None, region="us-east-1",
        matched_rule=None, reason="test",
    )
    s.record_decision(dec, pause_id=pid)
    # Read back: list_decisions should preserve pause_id (verify via the
    # raw column since list_decisions doesn't expose pause_id yet)
    cur = s._conn.execute("SELECT pause_id FROM decisions LIMIT 1")
    row = cur.fetchone()
    assert row[0] == pid
    s.close()


# ---------------------------------------------------------------------------
# Proxy-integration: pause demotes TRANSPARENT → COOPERATIVE
# ---------------------------------------------------------------------------


def test_pause_demotes_transparent_to_cooperative(tmp_path) -> None:
    """Critical safety property: when a pause is active, the proxy's
    decision verdict text is preserved (so audit reviewers can see
    what WOULD have been denied), but the observation's mode is
    demoted so the forwarding layer doesn't return 403 to the
    client."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    # No rules → default-deny in transparent enforce mode
    pid = store.start_pause(duration_seconds=600, reason="", started_by="me")

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/my-bucket/x",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    # Decision is still DENY (audit preserved)
    assert obs.decision_verdict == "deny"
    # But mode in the observation is demoted so forwarding stays open
    assert obs.mode_at_decision == ProxyMode.COOPERATIVE.value
    # And the audit row has pause_id == pid
    cur = store._conn.execute("SELECT pause_id FROM decisions LIMIT 1")
    row = cur.fetchone()
    assert row[0] == pid
    store.close()


def test_no_pause_preserves_transparent_mode(tmp_path) -> None:
    """Regression guard: without a pause, transparent mode stays
    transparent. Otherwise the pause check would silently disable
    enforcement for everyone."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/my-bucket/x",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    assert obs.mode_at_decision == ProxyMode.TRANSPARENT.value
    cur = store._conn.execute("SELECT pause_id FROM decisions LIMIT 1")
    row = cur.fetchone()
    assert row[0] is None
    store.close()


def test_pause_does_not_change_cooperative_mode(tmp_path) -> None:
    """If the proxy was already cooperative, a pause is a no-op for
    enforcement behavior (cooperative is already advisory). The
    audit row still records pause_id so reviewers can see the
    window, but mode_at_decision shouldn't change."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.start_pause(duration_seconds=600, reason="", started_by="me")

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/my-bucket/x",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
    )
    assert obs.mode_at_decision == ProxyMode.COOPERATIVE.value
    store.close()


def test_expired_pause_no_longer_demotes_mode(tmp_path) -> None:
    """After expiry, the next evaluate_request hits the lazy-GC path
    and clears the pause. Subsequent calls enforce normally."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.start_pause(duration_seconds=1, reason="", started_by="me")
    time.sleep(1.1)

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/my-bucket/x",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    # No pause active → mode stays transparent → forwarding layer
    # would 403 the client.
    assert obs.mode_at_decision == ProxyMode.TRANSPARENT.value
    store.close()


# ---------------------------------------------------------------------------
# CLI duration parser
# ---------------------------------------------------------------------------


def test_parse_duration_accepts_canonical_forms() -> None:
    from iam_jit.bouncer_cli import _parse_duration
    assert _parse_duration("30s") == 30
    assert _parse_duration("30m") == 30 * 60
    assert _parse_duration("2h") == 2 * 3600
    assert _parse_duration(" 90s ") == 90


def test_parse_duration_rejects_garbage() -> None:
    from click import BadParameter

    from iam_jit.bouncer_cli import _parse_duration
    with pytest.raises(BadParameter):
        _parse_duration("30")  # missing suffix
    with pytest.raises(BadParameter):
        _parse_duration("xx")
    with pytest.raises(BadParameter):
        _parse_duration("30d")  # day not supported
    with pytest.raises(BadParameter):
        _parse_duration("0m")
    with pytest.raises(BadParameter):
        _parse_duration("-5m")
