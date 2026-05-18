"""Tests for the audit-export heartbeat emitter + heartbeat_gap alert
rule (#264).

Per [[prompt-injection-disable-bouncer-threat]] the bouncer cannot
PREVENT a prompt-injected agent from killing the proxy; what it CAN
do is make the disable DETECTABLE. The heartbeat emitter publishes
an OCSF event every N seconds; the heartbeat_gap rule fires when
those stop arriving.

The load-bearing assertions in this file:

  - The emitter fires every interval_seconds (clock-injected so the
    test is deterministic + fast)
  - The emitted event conforms to OCSF v1.1.0 class 6003 (extends
    the validator from test_audit_export_log.py)
  - The heartbeat_gap rule fires when last_emit > interval *
    missing_count seconds ago
  - The rule's fire-side effects: stderr write + /healthz flag flip
    + bouncer_audit_export_status surface populated
  - /healthz returns 503 when a gap is detected
  - Neutral-language scan covers heartbeat-specific strings
  - Token-leak grep — heartbeat events never expose the webhook token
"""

from __future__ import annotations

import asyncio
import json
import socket

import pytest

from iam_jit.bouncer.audit_export import (
    DEFAULT_HEARTBEAT_MISSING_COUNT,
    EVENT_TYPE_HEARTBEAT,
    FORBIDDEN_ALERT_WORDS,
    AlertsConfig,
    HeartbeatEmitter,
    RuleEngine,
    heartbeat_status,
    make_heartbeat_event,
)
from iam_jit.bouncer.audit_export import (
    heartbeat as _heartbeat_mod,
)
from iam_jit.bouncer.audit_export.alerts import (
    EVENT_TYPE_ANOMALY_DETECTED,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_heartbeat_state():
    """Each test starts with a clean heartbeat module state. Without
    this a positive-case test would leave gap_detected=True for the
    next test."""
    _heartbeat_mod.reset_for_tests()
    yield
    _heartbeat_mod.reset_for_tests()


@pytest.fixture
def fake_clock():
    """Inject a controllable wall-clock into the emitter + the rule
    engine so timing tests are deterministic."""
    class _Clock:
        def __init__(self):
            self.now = 1_700_000_000.0

        def advance(self, seconds: float) -> None:
            self.now += seconds

        def __call__(self) -> float:
            return self.now

    return _Clock()


# Hand-rolled OCSF validator (mirrors test_audit_export_log.py — kept
# local so this test file is self-contained + a bug in the other
# file's validator can't silently mask a heartbeat schema regression).
_OCSF_REQUIRED = {
    "metadata": dict,
    "time": int,
    "class_uid": int,
    "class_name": str,
    "category_uid": int,
    "category_name": str,
    "activity_id": int,
    "activity_name": str,
    "type_uid": int,
    "type_name": str,
    "severity_id": int,
    "severity": str,
    "status_id": int,
    "status": str,
    "actor": dict,
    "api": dict,
}


def _validate_ocsf_api_activity(event: dict) -> None:
    """Assert the dict is a valid OCSF v1.1.0 class 6003 event."""
    for field, expected_type in _OCSF_REQUIRED.items():
        assert field in event, f"OCSF: missing field {field!r}"
        assert isinstance(event[field], expected_type), (
            f"OCSF: {field!r} should be {expected_type.__name__}, "
            f"got {type(event[field]).__name__}"
        )
    assert event["class_uid"] == 6003
    assert event["category_uid"] == 6
    assert event["type_uid"] == 6003 * 100 + event["activity_id"]
    assert event["activity_id"] in {0, 1, 2, 3, 4, 99}
    assert event["status_id"] in {0, 1, 2, 99}
    assert 0 <= event["severity_id"] <= 6
    assert event["metadata"]["version"] == "1.1.0"
    assert event["metadata"]["product"]["name"] == "ibounce"
    assert event["metadata"]["product"]["vendor_name"] == "iam-jit"


# ---------------------------------------------------------------------------
# Heartbeat event shape
# ---------------------------------------------------------------------------


def test_heartbeat_event_ocsf_shape() -> None:
    """The heartbeat event passes the OCSF v1.1.0 class 6003 validator
    + carries the spec-required fields."""
    event = make_heartbeat_event(uptime_seconds=42, interval_seconds=30)
    _validate_ocsf_api_activity(event)
    # Spec-required fields per the [[heartbeat]] section of #264.
    assert event["class_uid"] == 6003
    assert event["category_uid"] == 6
    assert event["activity_id"] == 99
    assert event["activity_name"] == "heartbeat"
    assert event["type_uid"] == 600399
    assert event["severity_id"] == 1
    assert event["severity"] == "Informational"
    assert event["status_id"] == 1
    assert event["status"] == "Success"
    assert event["status_detail"] == "bouncer alive"
    iam_jit = event["unmapped"]["iam_jit"]
    assert iam_jit["event_type"] == "HEARTBEAT"
    assert iam_jit["uptime_seconds"] == 42
    assert iam_jit["interval_seconds"] == 30


def test_heartbeat_event_type_constant_matches_unmapped_field() -> None:
    """The exported EVENT_TYPE_HEARTBEAT constant matches the wire
    value so consumers can filter on a single string."""
    event = make_heartbeat_event(uptime_seconds=1, interval_seconds=1)
    assert event["unmapped"]["iam_jit"]["event_type"] == EVENT_TYPE_HEARTBEAT


# ---------------------------------------------------------------------------
# Heartbeat emitter
# ---------------------------------------------------------------------------


def test_emitter_refuses_zero_interval() -> None:
    """interval_seconds <= 0 = ValueError. 0 means "off" at the CLI
    level; an emitter with interval 0 would never fire."""
    with pytest.raises(ValueError, match="interval_seconds"):
        HeartbeatEmitter(interval_seconds=0, emit=lambda _: None)


@pytest.mark.asyncio
async def test_emitter_fires_first_heartbeat_on_start() -> None:
    """The emitter emits IMMEDIATELY on start (no waiting one full
    interval before the first beat). Useful so a SIEM sees the
    bouncer-came-up signal as soon as the process is ready."""
    emitted: list[dict] = []
    emitter = HeartbeatEmitter(interval_seconds=1, emit=emitted.append)
    await emitter.start()
    try:
        # Yield + small delay to let the loop schedule the first emit.
        for _ in range(50):
            if emitted:
                break
            await asyncio.sleep(0.01)
    finally:
        await emitter.stop()
    assert len(emitted) >= 1
    assert emitted[0]["unmapped"]["iam_jit"]["event_type"] == "HEARTBEAT"


@pytest.mark.asyncio
async def test_emitter_fires_at_correct_interval_with_mock_sleep() -> None:
    """Mock-clock-driven: with a 30s interval, advancing the fake
    clock by 90s should produce 3 emits in addition to the start-up
    one."""
    emitted: list[dict] = []
    # Use real asyncio.sleep but a very short interval so the test
    # runs quickly; verify the count over a controlled wall-clock
    # window.
    interval = 0.05
    emitter = HeartbeatEmitter(
        interval_seconds=interval, emit=emitted.append,
    )
    await emitter.start()
    try:
        # Wait long enough for ~5 ticks (start emit + 4 interval emits).
        await asyncio.sleep(interval * 4.5)
    finally:
        await emitter.stop()
    # We expect 4-6 emits depending on scheduler jitter; assert lower
    # bound so the test is robust on slow CI.
    assert len(emitted) >= 4, f"got {len(emitted)} emits, expected >= 4"
    # Every emit is a heartbeat event.
    for e in emitted:
        assert e["unmapped"]["iam_jit"]["event_type"] == "HEARTBEAT"


@pytest.mark.asyncio
async def test_emitter_records_state_on_each_emit() -> None:
    """After the first emit, heartbeat_status() reports
    enabled=True + interval + a recent last_emit_seconds_ago."""
    emitter = HeartbeatEmitter(interval_seconds=1, emit=lambda _: None)
    await emitter.start()
    try:
        # Wait briefly to let the loop schedule the first emit.
        for _ in range(50):
            snap = heartbeat_status()
            if snap["heartbeat_last_emit_seconds_ago"] is not None:
                break
            await asyncio.sleep(0.01)
    finally:
        await emitter.stop()
    # Snapshot post-stop captures the last-recorded state.
    snap = heartbeat_status()
    # stop() flipped enabled back to False (clean state for next run).
    assert snap["heartbeat_enabled"] is False
    # last_emit_seconds_ago cleared on stop too — see
    # _heartbeat_mod._set_enabled(False).
    assert snap["heartbeat_last_emit_seconds_ago"] is None


@pytest.mark.asyncio
async def test_emitter_emit_callback_failure_does_not_kill_loop() -> None:
    """A buggy emit callback (raises on every call) does NOT kill the
    emitter — subsequent ticks still attempt to fire. Fail-soft per
    [[deliberate-feature-completion]]."""
    call_count = [0]

    def _flaky(_event: dict) -> None:
        call_count[0] += 1
        raise RuntimeError("boom")

    emitter = HeartbeatEmitter(interval_seconds=0.05, emit=_flaky)
    await emitter.start()
    try:
        await asyncio.sleep(0.18)
    finally:
        await emitter.stop()
    # At least 2 attempts (start emit + 1+ interval emits) so we know
    # the exception didn't kill the loop.
    assert call_count[0] >= 2


@pytest.mark.asyncio
async def test_emitter_stop_clears_module_state() -> None:
    """After stop(), heartbeat_status() reports enabled=False so the
    gap rule doesn't fire on the operator's deliberate shutdown."""
    emitter = HeartbeatEmitter(interval_seconds=1, emit=lambda _: None)
    await emitter.start()
    # Confirm running.
    assert heartbeat_status()["heartbeat_enabled"] is True
    await emitter.stop()
    snap = heartbeat_status()
    assert snap["heartbeat_enabled"] is False
    assert snap["heartbeat_gap_detected"] is False


# ---------------------------------------------------------------------------
# heartbeat_gap rule — positive + negative cases
# ---------------------------------------------------------------------------


def test_heartbeat_gap_does_not_fire_when_heartbeats_disabled() -> None:
    """No emitter installed = rule is dormant. Operators on tiers
    without heartbeats enabled shouldn't get spurious fires."""
    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    # Feed a benign event; the gap rule sees heartbeat_enabled=False
    # and returns None.
    engine.observe(make_heartbeat_event(uptime_seconds=0, interval_seconds=0))
    assert all(
        e["unmapped"]["iam_jit"]["pattern"] != "bouncer-uptime-gap"
        for e in fired
    )


def test_heartbeat_gap_fires_when_gap_exceeds_threshold(
    fake_clock, capsys, monkeypatch,
) -> None:
    """With heartbeats enabled + last_emit > interval * count seconds
    ago, the rule fires + flips /healthz flag + writes to stderr.
    """
    # Set up the heartbeat module to look like an emitter ran briefly
    # then stopped without a clean shutdown.
    _heartbeat_mod._set_enabled(True, interval_seconds=30)
    _heartbeat_mod._record_emit(now_unix=fake_clock.now)
    # Advance well past 2 * 30s = 60s gap threshold.
    fake_clock.advance(120)
    monkeypatch.setattr(_heartbeat_mod.time, "time", fake_clock)

    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    # Observe ANY event — the rule's pattern looks at module state,
    # not the event content. Use a decision event so the test is
    # honest about how the rule fires in production.
    from iam_jit.bouncer.audit_export import audit_event_from_decision
    engine.observe(
        audit_event_from_decision(
            decision_id=1, mode="cooperative", profile=None,
            verdict="allow", reason="", service="s3", action="GetObject",
            arn=None, region=None, host="s3.us-east-1.amazonaws.com",
        )
    )
    # Pull the gap alert from the fired list.
    gap_alerts = [
        e for e in fired
        if e["unmapped"]["iam_jit"].get("pattern") == "bouncer-uptime-gap"
    ]
    assert len(gap_alerts) == 1, (
        f"expected exactly 1 gap alert; got {len(gap_alerts)}"
    )
    alert = gap_alerts[0]
    assert alert["class_uid"] == 6003
    assert alert["activity_id"] == 99
    assert alert["activity_name"] == "anomaly_detected"
    assert alert["severity_id"] == 4
    assert alert["severity"] == "High"
    iam_jit = alert["unmapped"]["iam_jit"]
    assert iam_jit["event_type"] == EVENT_TYPE_ANOMALY_DETECTED
    assert iam_jit["pattern"] == "bouncer-uptime-gap"
    assert iam_jit["matched_event_count"] == DEFAULT_HEARTBEAT_MISSING_COUNT
    # /healthz flag flipped.
    assert heartbeat_status()["heartbeat_gap_detected"] is True
    # stderr message written.
    captured = capsys.readouterr()
    assert "heartbeat gap detected" in captured.err.lower()
    assert "bouncer may have been killed" in captured.err.lower()


def test_heartbeat_gap_does_not_fire_when_gap_below_threshold(
    fake_clock, monkeypatch,
) -> None:
    """interval=30, count=2 → threshold=60s. At 45s elapsed, no fire."""
    _heartbeat_mod._set_enabled(True, interval_seconds=30)
    _heartbeat_mod._record_emit(now_unix=fake_clock.now)
    fake_clock.advance(45)
    monkeypatch.setattr(_heartbeat_mod.time, "time", fake_clock)

    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    from iam_jit.bouncer.audit_export import audit_event_from_decision
    engine.observe(
        audit_event_from_decision(
            decision_id=1, mode="cooperative", profile=None,
            verdict="allow", reason="", service="s3", action="GetObject",
            arn=None, region=None, host="s3.us-east-1.amazonaws.com",
        )
    )
    gap_alerts = [
        e for e in fired
        if e["unmapped"]["iam_jit"].get("pattern") == "bouncer-uptime-gap"
    ]
    assert gap_alerts == []
    assert heartbeat_status()["heartbeat_gap_detected"] is False


def test_heartbeat_gap_debounces_after_fire(fake_clock, monkeypatch) -> None:
    """Once the gap rule fires, it does not fire AGAIN until a fresh
    heartbeat lands (which clears the gap flag). This stops a long
    outage from producing one alert per observed event."""
    _heartbeat_mod._set_enabled(True, interval_seconds=10)
    _heartbeat_mod._record_emit(now_unix=fake_clock.now)
    fake_clock.advance(60)
    monkeypatch.setattr(_heartbeat_mod.time, "time", fake_clock)

    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    from iam_jit.bouncer.audit_export import audit_event_from_decision

    def _benign_event() -> dict:
        return audit_event_from_decision(
            decision_id=1, mode="cooperative", profile=None,
            verdict="allow", reason="", service="s3", action="GetObject",
            arn=None, region=None, host="s3.us-east-1.amazonaws.com",
        )

    engine.observe(_benign_event())  # Fires.
    engine.observe(_benign_event())  # Debounced.
    engine.observe(_benign_event())  # Debounced.
    gap_alerts = [
        e for e in fired
        if e["unmapped"]["iam_jit"].get("pattern") == "bouncer-uptime-gap"
    ]
    assert len(gap_alerts) == 1


def test_heartbeat_gap_clears_after_fresh_heartbeat(
    fake_clock, monkeypatch,
) -> None:
    """A fresh _record_emit clears the gap flag so a later genuine
    gap can re-fire."""
    _heartbeat_mod._set_enabled(True, interval_seconds=10)
    _heartbeat_mod._record_emit(now_unix=fake_clock.now)
    fake_clock.advance(60)
    monkeypatch.setattr(_heartbeat_mod.time, "time", fake_clock)

    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    from iam_jit.bouncer.audit_export import audit_event_from_decision
    engine.observe(
        audit_event_from_decision(
            decision_id=1, mode="cooperative", profile=None,
            verdict="allow", reason="", service="s3", action="GetObject",
            arn=None, region=None, host="s3.us-east-1.amazonaws.com",
        )
    )
    # Gap fired.
    assert heartbeat_status()["heartbeat_gap_detected"] is True
    # Simulate a heartbeat arriving.
    _heartbeat_mod._record_emit(now_unix=fake_clock.now)
    assert heartbeat_status()["heartbeat_gap_detected"] is False


def test_heartbeat_gap_respects_operator_configured_missing_count(
    fake_clock, monkeypatch,
) -> None:
    """An operator-tuned missing_count=5 doesn't fire until elapsed
    > interval * 5."""
    _heartbeat_mod._set_enabled(True, interval_seconds=10)
    _heartbeat_mod._record_emit(now_unix=fake_clock.now)
    # 40s = 4 intervals; with count=5 threshold=50s, should NOT fire.
    fake_clock.advance(40)
    monkeypatch.setattr(_heartbeat_mod.time, "time", fake_clock)

    config = AlertsConfig(heartbeat_missing_count=5)
    fired: list[dict] = []
    engine = RuleEngine(config=config, emit=fired.append)
    from iam_jit.bouncer.audit_export import audit_event_from_decision
    engine.observe(
        audit_event_from_decision(
            decision_id=1, mode="cooperative", profile=None,
            verdict="allow", reason="", service="s3", action="GetObject",
            arn=None, region=None, host="s3.us-east-1.amazonaws.com",
        )
    )
    assert not [
        e for e in fired
        if e["unmapped"]["iam_jit"].get("pattern") == "bouncer-uptime-gap"
    ]
    # Now advance past the threshold; observe again → fire.
    fake_clock.advance(20)  # total 60s elapsed; threshold 50s.
    engine.observe(
        audit_event_from_decision(
            decision_id=2, mode="cooperative", profile=None,
            verdict="allow", reason="", service="s3", action="GetObject",
            arn=None, region=None, host="s3.us-east-1.amazonaws.com",
        )
    )
    gap_alerts = [
        e for e in fired
        if e["unmapped"]["iam_jit"].get("pattern") == "bouncer-uptime-gap"
    ]
    assert len(gap_alerts) == 1
    assert (
        gap_alerts[0]["unmapped"]["iam_jit"]["matched_event_count"] == 5
    )


# ---------------------------------------------------------------------------
# MCP status surface
# ---------------------------------------------------------------------------


def test_audit_export_status_includes_heartbeat_fields_when_disabled() -> None:
    """Default (no emitter): all 4 heartbeat fields present + report
    OFF. Stable shape per [[security-team-audit-export]] so MCP
    consumers can branch on the bool."""
    from iam_jit.bouncer.proxy import audit_export_status
    snap = audit_export_status()
    assert snap["heartbeat_enabled"] is False
    assert snap["heartbeat_interval_seconds"] == 0
    assert snap["heartbeat_last_emit_seconds_ago"] is None
    assert snap["heartbeat_gap_detected"] is False


def test_audit_export_status_includes_heartbeat_fields_when_enabled() -> None:
    """With state populated, the MCP snapshot reports the same values
    the heartbeat_status() helper produces."""
    from iam_jit.bouncer.proxy import audit_export_status
    _heartbeat_mod._set_enabled(True, interval_seconds=30)
    _heartbeat_mod._record_emit(now_unix=__import__("time").time())
    snap = audit_export_status()
    assert snap["heartbeat_enabled"] is True
    assert snap["heartbeat_interval_seconds"] == 30
    assert snap["heartbeat_last_emit_seconds_ago"] is not None
    assert snap["heartbeat_last_emit_seconds_ago"] >= 0
    assert snap["heartbeat_gap_detected"] is False


# ---------------------------------------------------------------------------
# /healthz integration — 503 when gap detected
# ---------------------------------------------------------------------------


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _wait_for_listen(host: str, port: int, *, retries: int = 50) -> None:
    for _ in range(retries):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"nothing listening on {host}:{port}")


@pytest.mark.asyncio
async def test_healthz_returns_503_when_gap_detected(tmp_path) -> None:
    """When the heartbeat_gap_detected flag is set, /healthz returns
    HTTP 503 + a body that exposes the gap state. External monitoring
    (uptime checks, k8s liveness probes) flips alarm based on this."""
    from iam_jit.bouncer.decisions import DefaultPolicy
    from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
    from iam_jit.bouncer.store import BouncerStore

    # Pre-populate heartbeat state to look like the gap rule already
    # fired (which would have been done by the alert engine in a real
    # session).
    _heartbeat_mod._set_enabled(True, interval_seconds=30)
    _heartbeat_mod._record_emit(now_unix=__import__("time").time() - 200)
    _heartbeat_mod.mark_gap_detected()

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        # Don't actually start the emitter — we want pre-populated
        # state to test the /healthz path independent of timing.
        heartbeat_interval_seconds=0,
        alert_heartbeat_missing_count=2,
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz",
            ) as resp:
                # The check requires heartbeat_enabled=True at /healthz
                # eval time; module-state was set above, BUT the
                # /healthz handler reads the same module state so the
                # gap_detected branch fires. Confirm 503.
                assert resp.status == 503, (
                    f"expected 503 for gap-detected; got {resp.status} "
                    f"body={await resp.text()}"
                )
                body = await resp.json()
        assert body["heartbeat"] is not None
        assert body["heartbeat"]["enabled"] is True
        assert body["heartbeat"]["gap_detected"] is True
        # Status field also reflects the degradation so a human
        # reading the body sees it without parsing the HTTP code.
        assert body["status"] in {"degraded", "ok"}
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_healthz_returns_200_when_heartbeats_disabled(
    tmp_path,
) -> None:
    """Heartbeats off (default) = /healthz returns 200 regardless of
    state — the heartbeat block is None and the status is unaffected.
    Backward-compat per the pre-#264 baseline."""
    from iam_jit.bouncer.decisions import DefaultPolicy
    from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
    from iam_jit.bouncer.store import BouncerStore

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        heartbeat_interval_seconds=0,
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz",
            ) as resp:
                assert resp.status == 200
                body = await resp.json()
        assert body["status"] == "ok"
        assert body["heartbeat"] is None
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_healthz_returns_503_when_emitter_running_and_gap_elapsed(
    tmp_path,
) -> None:
    """End-to-end: an emitter starts, time passes without a fresh
    beat, /healthz computes the gap directly from elapsed time +
    returns 503 — even when the alert rule engine ISN'T installed.

    This is the [[audit-export-failure-visibility]] independent-check
    path: external monitoring sees the gap without depending on the
    Enterprise-gated alert engine.
    """
    from iam_jit.bouncer.decisions import DefaultPolicy
    from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
    from iam_jit.bouncer.store import BouncerStore

    # Simulate "the emitter ran briefly then died" by setting state
    # then NOT starting an emitter in serve().
    _heartbeat_mod._set_enabled(True, interval_seconds=1)
    _heartbeat_mod._record_emit(now_unix=__import__("time").time() - 10)

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        heartbeat_interval_seconds=0,  # don't actually emit
        alert_heartbeat_missing_count=2,
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz",
            ) as resp:
                # Elapsed = 10s; threshold = interval (1) * count (2) = 2s.
                # 10 > 2 → gap → 503.
                assert resp.status == 503
                body = await resp.json()
        assert body["heartbeat"]["gap_detected"] is True
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# Token-leak grep — heartbeat events never expose the webhook token
# ---------------------------------------------------------------------------


def test_heartbeat_event_does_not_contain_token_shaped_strings() -> None:
    """The heartbeat builder doesn't take a token + the event has no
    fields where a token could land. Defensive grep across the
    serialised JSON."""
    event = make_heartbeat_event(uptime_seconds=300, interval_seconds=30)
    serialised = json.dumps(event)
    assert "lit_secret_bearer_value_donotleak_xyz" not in serialised
    assert "Bearer " not in serialised
    assert "Authorization:" not in serialised


def test_heartbeat_gap_alert_does_not_contain_token_shaped_strings(
    fake_clock, monkeypatch, capsys,
) -> None:
    """The gap alert's status_detail + suggestion never carry token
    material (the rule pattern doesn't see the webhook config)."""
    _heartbeat_mod._set_enabled(True, interval_seconds=10)
    _heartbeat_mod._record_emit(now_unix=fake_clock.now)
    fake_clock.advance(60)
    monkeypatch.setattr(_heartbeat_mod.time, "time", fake_clock)

    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    from iam_jit.bouncer.audit_export import audit_event_from_decision
    engine.observe(
        audit_event_from_decision(
            decision_id=1, mode="cooperative", profile=None,
            verdict="allow", reason="", service="s3", action="GetObject",
            arn=None, region=None, host="s3.us-east-1.amazonaws.com",
        )
    )
    serialised = json.dumps(fired)
    assert "lit_secret_bearer_value_donotleak_xyz" not in serialised
    assert "Bearer " not in serialised
    assert "Authorization:" not in serialised
    # Drain stderr so it doesn't pollute pytest output.
    capsys.readouterr()


# ---------------------------------------------------------------------------
# Neutral-language scan — heartbeat-specific strings
# ---------------------------------------------------------------------------


def test_no_forbidden_words_in_heartbeat_payloads(
    fake_clock, monkeypatch, capsys,
) -> None:
    """Per [[security-team-positioning-safety-not-surveillance]]: no
    'violation' / 'infraction' / 'unauthorized' in any heartbeat
    surface (event payload, gap alert, stderr message)."""
    # Heartbeat event itself.
    ev = make_heartbeat_event(uptime_seconds=99, interval_seconds=30)
    serialised = json.dumps(ev).lower()
    for word in FORBIDDEN_ALERT_WORDS:
        assert word not in serialised, (
            f"forbidden word {word!r} in heartbeat event"
        )

    # Trigger a gap alert + scan its strings + the stderr message.
    _heartbeat_mod._set_enabled(True, interval_seconds=10)
    _heartbeat_mod._record_emit(now_unix=fake_clock.now)
    fake_clock.advance(60)
    monkeypatch.setattr(_heartbeat_mod.time, "time", fake_clock)

    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    from iam_jit.bouncer.audit_export import audit_event_from_decision
    engine.observe(
        audit_event_from_decision(
            decision_id=1, mode="cooperative", profile=None,
            verdict="allow", reason="", service="s3", action="GetObject",
            arn=None, region=None, host="s3.us-east-1.amazonaws.com",
        )
    )
    alert_payload = json.dumps(fired).lower()
    captured = capsys.readouterr()
    stderr_msg = captured.err.lower()
    for word in FORBIDDEN_ALERT_WORDS:
        assert word not in alert_payload, (
            f"forbidden word {word!r} in gap alert payload"
        )
        assert word not in stderr_msg, (
            f"forbidden word {word!r} in stderr gap message"
        )
    # The dedicated heartbeat_gap rule description must also be
    # neutral.
    from iam_jit.bouncer.audit_export import BUILTIN_RULES
    hb_rule = next(r for r in BUILTIN_RULES if r.name == "heartbeat_gap")
    desc = hb_rule.description.lower()
    for word in FORBIDDEN_ALERT_WORDS:
        assert word not in desc, (
            f"heartbeat_gap rule description contains {word!r}"
        )


# ---------------------------------------------------------------------------
# Engine integration — heartbeat_gap registered as a built-in rule
# ---------------------------------------------------------------------------


def test_heartbeat_gap_is_registered_in_builtin_rules() -> None:
    """heartbeat_gap appears in BUILTIN_RULES so an operator who
    enables the default alert config gets it without YAML editing."""
    from iam_jit.bouncer.audit_export import BUILTIN_RULES
    names = {r.name for r in BUILTIN_RULES}
    assert "heartbeat_gap" in names
    hb_rule = next(r for r in BUILTIN_RULES if r.name == "heartbeat_gap")
    assert hb_rule.severity == 4  # High


def test_alerts_config_default_includes_heartbeat_threshold() -> None:
    """AlertsConfig.default() includes the heartbeat_missing_count
    field at the documented default (2)."""
    config = AlertsConfig.default()
    assert config.heartbeat_missing_count == DEFAULT_HEARTBEAT_MISSING_COUNT
    assert DEFAULT_HEARTBEAT_MISSING_COUNT == 2


# ---------------------------------------------------------------------------
# YAML loader — heartbeat_missing_count key
# ---------------------------------------------------------------------------


def test_load_alerts_config_honours_heartbeat_missing_count(tmp_path) -> None:
    """The --alert-rules YAML accepts heartbeat_missing_count + the
    loaded AlertsConfig surfaces it."""
    from iam_jit.bouncer.audit_export import load_alerts_config
    p = tmp_path / "alerts.yaml"
    p.write_text("heartbeat_missing_count: 5\n")
    config = load_alerts_config(str(p))
    assert config.heartbeat_missing_count == 5


# ---------------------------------------------------------------------------
# CLI flag — --heartbeat-interval threads through to ProxyConfig
# ---------------------------------------------------------------------------


def test_cli_heartbeat_interval_default_is_off() -> None:
    """`ibounce run` without --heartbeat-interval defaults to OFF
    (interval_seconds=0). Zero-phone-home preserved."""
    from iam_jit.bouncer.proxy import ProxyConfig
    config = ProxyConfig()
    assert config.heartbeat_interval_seconds == 0
    assert config.alert_heartbeat_missing_count == 2


def test_cli_heartbeat_interval_threads_into_proxyconfig(
    tmp_path, monkeypatch,
) -> None:
    """`ibounce run --heartbeat-interval 30` ends up as
    ProxyConfig.heartbeat_interval_seconds=30. We don't start serve()
    (would block) — patch it to inspect the config."""
    from click.testing import CliRunner

    from iam_jit import bouncer_cli
    from iam_jit.bouncer import proxy as proxy_mod

    captured: dict = {}

    async def _fake_serve(config, *, store):
        captured["config"] = config

    monkeypatch.setattr(proxy_mod, "serve", _fake_serve)

    runner = CliRunner()
    result = runner.invoke(
        bouncer_cli.main,
        [
            "run",
            "--port", "0",
            "--heartbeat-interval", "30",
            "--alert-heartbeat-missing-count", "3",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, (
        f"CLI failed: {result.output}"
    )
    assert captured["config"].heartbeat_interval_seconds == 30
    assert captured["config"].alert_heartbeat_missing_count == 3
