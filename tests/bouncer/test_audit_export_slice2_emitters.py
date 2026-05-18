"""Integration tests for #270 Slice 2 synthetic-event emitters.

Per [[security-team-audit-export]] Slice 2, the deterministic rule
engine in `alerts.py` consumes synthetic events emitted by three
upstream paths:

  1. admin_fallback_grant — fires from the proxy hot-path when a
     transparent-mode would-be-deny is demoted to allow because an
     operator pause window is open. The admin_fallback_burst rule
     watches a rolling 5-min window.
  2. pause_end — fires from the proxy hot-path via a
     last-seen-pause-id comparison: when a previous lookup saw an
     active pause + the current lookup sees None (or a different id),
     the pause has just closed. The pause_long rule watches duration.
  3. profile_install — enqueued by the separate-process `ibounce
     profile install --from URL` command into a SQLite queue +
     drained on a 1s tick by the serve process. The
     non_org_profile_install rule watches the source_url against the
     operator's allowlist.

These tests assert each emitter delivers its synthetic event through
the registered rule engine AND that the corresponding alert rule
fires end-to-end when its threshold is crossed.

Per [[deliberate-feature-completion]]: a feature is only "done" when
both halves of its loop work end-to-end. The unit tests in
test_audit_export_alerts.py prove the RULE half; this file proves the
EMITTER half + the integrated proxy/CLI -> RuleEngine -> alert event
flow.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import pathlib
from unittest import mock

import pytest
import yaml as _yaml
from click.testing import CliRunner

from iam_jit.bouncer import proxy as proxy_mod
from iam_jit.bouncer.audit_export import (
    AlertsConfig,
    RuleEngine,
)
from iam_jit.bouncer.audit_export.alerts import (
    EVENT_TYPE_ADMIN_FALLBACK_GRANT,
    EVENT_TYPE_ANOMALY_DETECTED,
    EVENT_TYPE_PAUSE_END,
    EVENT_TYPE_PROFILE_INSTALL,
)
from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyMode,
    evaluate_request,
    register_audit_rule_engine,
)
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260518/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fake"
    )


@pytest.fixture
def store(tmp_path: pathlib.Path):
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    yield s
    s.close()


@pytest.fixture
def reset_proxy_state():
    """Each test starts with a clean module-level pause-tracking +
    rule-engine state. Without this an earlier test's last-seen-pause
    cache or registered engine leaks into the next test."""
    proxy_mod._reset_last_seen_pause_for_tests()
    register_audit_rule_engine(None)
    yield
    proxy_mod._reset_last_seen_pause_for_tests()
    register_audit_rule_engine(None)


@pytest.fixture
def observed_events():
    """Collect every event the rule engine observes — so tests can
    assert the synthetic emitter delivered the event regardless of
    whether the rule itself fired this iteration."""
    captured: list[dict] = []

    class _CapturingEngine:
        def __init__(self, inner: RuleEngine) -> None:
            self._inner = inner

        def observe(self, event: dict) -> list[dict]:
            captured.append(event)
            return self._inner.observe(event)

        def status(self) -> dict:
            return self._inner.status()

    captured.append  # silence unused-var lint
    return captured, _CapturingEngine


# ---------------------------------------------------------------------------
# Emit site 1: admin-fallback grant from proxy hot-path
# ---------------------------------------------------------------------------


def test_admin_fallback_emit_observed_by_rule_engine(
    store, reset_proxy_state, observed_events,
) -> None:
    """When a transparent-mode would-be-deny is demoted to allow by
    an active pause window, the proxy MUST emit a synthetic
    ADMIN_FALLBACK_GRANT event through the rule engine."""
    captured, capturing_engine_cls = observed_events
    inner = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _e: None,
    )
    register_audit_rule_engine(capturing_engine_cls(inner))

    store.start_pause(
        duration_seconds=600, reason="emit test", started_by="alice",
    )

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/bucket/key",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    # Pause-demotion path was taken.
    assert obs.decision_verdict == "deny"
    assert obs.mode_at_decision == ProxyMode.COOPERATIVE.value

    admin_fallback_events = [
        e for e in captured
        if (
            e.get("unmapped", {}).get("iam_jit", {}).get("event_type")
            == EVENT_TYPE_ADMIN_FALLBACK_GRANT
        )
    ]
    assert len(admin_fallback_events) == 1, (
        f"expected 1 admin-fallback synthetic; captured types: "
        f"{[e.get('unmapped', {}).get('iam_jit', {}).get('event_type') for e in captured]}"
    )
    evt = admin_fallback_events[0]
    assert (
        evt["unmapped"]["iam_jit"]["mode"] == "transparent"
    )
    # Principal threading: the pause initiator becomes the principal.
    assert evt["actor"]["user"]["name"] == "alice"


def test_admin_fallback_burst_rule_fires_when_threshold_crossed(
    store, reset_proxy_state,
) -> None:
    """Integration: 4 transparent-mode would-be-denies inside the
    5-min window (with an open pause) fire the admin_fallback_burst
    rule. The rule threshold is `>3` so the 4th demoted request is
    the firing one."""
    fired: list[dict] = []
    inner = RuleEngine(
        config=AlertsConfig.default(), emit=fired.append,
    )
    register_audit_rule_engine(inner)

    store.start_pause(
        duration_seconds=600, reason="burst test", started_by="bob",
    )

    for i in range(4):
        evaluate_request(
            method="GET",
            host="s3.us-east-1.amazonaws.com",
            path=f"/bucket/k{i}",
            headers={
                "host": "s3.us-east-1.amazonaws.com",
                "authorization": _sigv4(service="s3", region="us-east-1"),
            },
            body=None, query=None,
            store=store,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
        )

    admin_burst = [
        e for e in fired
        if (
            e.get("unmapped", {}).get("iam_jit", {}).get("pattern")
            == "admin-fallback-burst"
        )
    ]
    assert len(admin_burst) == 1, (
        f"expected admin_fallback_burst to fire once on the 4th demoted "
        f"request; fired patterns: "
        f"{[e['unmapped']['iam_jit']['pattern'] for e in fired]}"
    )
    alert = admin_burst[0]
    assert alert["unmapped"]["iam_jit"]["matched_event_count"] == 4
    assert alert["severity_id"] == 3


def test_admin_fallback_does_not_emit_when_no_pause_active(
    store, reset_proxy_state, observed_events,
) -> None:
    """Regression guard: a transparent-mode deny WITHOUT an active
    pause must NOT emit an admin-fallback synthetic (the synthetic
    is specifically about the pause-demotion path)."""
    captured, capturing_engine_cls = observed_events
    inner = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _e: None,
    )
    register_audit_rule_engine(capturing_engine_cls(inner))

    evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/bucket/key",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    admin_fallback_events = [
        e for e in captured
        if (
            e.get("unmapped", {}).get("iam_jit", {}).get("event_type")
            == EVENT_TYPE_ADMIN_FALLBACK_GRANT
        )
    ]
    assert admin_fallback_events == []


# ---------------------------------------------------------------------------
# Emit site 2: pause-end transition detection in proxy hot-path
# ---------------------------------------------------------------------------


def test_pause_end_emit_on_explicit_stop(
    store, reset_proxy_state, observed_events,
) -> None:
    """When an operator calls `pause stop`, the next evaluate_request
    sees no active pause + emits a PAUSE_END synthetic for the
    previously-seen pause."""
    captured, capturing_engine_cls = observed_events
    inner = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _e: None,
    )
    register_audit_rule_engine(capturing_engine_cls(inner))

    pid = store.start_pause(
        duration_seconds=600, reason="stop test", started_by="carol",
    )
    # First request: sees the pause active; primes last_seen.
    evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/bucket/k1",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    # Operator stops the pause out-of-band (simulating the CLI).
    store.end_pause(ended_by="carol")
    # Second request: sees no active pause -> transition detected.
    evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/bucket/k2",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )

    pause_ends = [
        e for e in captured
        if (
            e.get("unmapped", {}).get("iam_jit", {}).get("event_type")
            == EVENT_TYPE_PAUSE_END
        )
    ]
    assert len(pause_ends) == 1, (
        f"expected 1 pause_end synthetic; captured event_types: "
        f"{[e.get('unmapped', {}).get('iam_jit', {}).get('event_type') for e in captured]}"
    )
    evt = pause_ends[0]
    assert evt["unmapped"]["iam_jit"]["pause_id"] == str(pid)
    # end_kind is whatever the store wrote on stop — 'resumed_early'.
    assert evt["unmapped"]["iam_jit"]["ext"]["end_kind"] == "resumed_early"
    # Duration is computed from started_at to now; should be >= 0.
    assert evt["unmapped"]["iam_jit"]["ext"]["duration_seconds"] >= 0


def test_pause_end_emit_on_auto_expiry(
    store, reset_proxy_state, observed_events,
) -> None:
    """When a pause auto-expires, the proxy's next lookup hits the
    lazy-GC path inside _active_pause_locked + sees no active pause —
    PAUSE_END must still emit (auto-expiry is the kbounce-sibling
    pattern's other half of pause closes)."""
    import time as _time
    captured, capturing_engine_cls = observed_events
    inner = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _e: None,
    )
    register_audit_rule_engine(capturing_engine_cls(inner))

    store.start_pause(
        duration_seconds=1, reason="expiry test", started_by="dan",
    )
    # First request primes last_seen with the active pause.
    evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/bucket/k1",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    # Wait past the expiry window — the next lookup will auto-GC.
    _time.sleep(1.1)
    evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/bucket/k2",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    pause_ends = [
        e for e in captured
        if (
            e.get("unmapped", {}).get("iam_jit", {}).get("event_type")
            == EVENT_TYPE_PAUSE_END
        )
    ]
    assert len(pause_ends) == 1


def test_pause_long_rule_fires_when_window_exceeds_threshold(
    store, reset_proxy_state,
) -> None:
    """Integration: a pause window observed to exceed
    pause_long_threshold_seconds at close fires the pause_long rule.

    We construct the scenario by writing the pause-events row with a
    backdated started_at (so the duration-from-started_at-to-now is
    > the default 30min threshold), then trigger the close via
    end_pause + a follow-up evaluate_request that primes the
    transition detector."""
    fired: list[dict] = []
    inner = RuleEngine(
        config=AlertsConfig.default(), emit=fired.append,
    )
    register_audit_rule_engine(inner)

    # First lookup: prime last_seen with a real active pause. We
    # start a short-but-real pause, then backdate its started_at in
    # the DB so the duration-from-now check shows > 30min.
    pid = store.start_pause(
        duration_seconds=3600, reason="long test", started_by="erin",
    )
    backdated = _dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=45)
    store._conn.execute(
        "UPDATE pause_events SET started_at = ? WHERE id = ?",
        (backdated.strftime("%Y-%m-%dT%H:%M:%SZ"), pid),
    )

    # Prime the last-seen detector with this (backdated) pause.
    evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/bucket/k1",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    # Stop the pause out-of-band.
    store.end_pause(ended_by="erin")
    # Next request: transition fires PAUSE_END with duration > 30min.
    evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/bucket/k2",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    long_pause_alerts = [
        e for e in fired
        if (
            e.get("unmapped", {}).get("iam_jit", {}).get("pattern")
            == "long-pause"
        )
    ]
    assert len(long_pause_alerts) == 1, (
        f"expected long-pause to fire once; fired: "
        f"{[e['unmapped']['iam_jit']['pattern'] for e in fired]}"
    )
    assert long_pause_alerts[0]["severity_id"] == 3


# ---------------------------------------------------------------------------
# Emit site 3: profile install -> SQLite queue -> serve drain -> rule engine
# ---------------------------------------------------------------------------


def test_profile_install_enqueues_pending_audit_event(
    tmp_path, monkeypatch,
) -> None:
    """`ibounce profile install --from URL` enqueues a row into
    pending_audit_events for each installed profile. The serve
    process's drainer picks them up; this test asserts the enqueue
    half (the drainer half is exercised below)."""
    db_path = tmp_path / "b.db"
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db_path))
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "profiles.yaml"),
    )
    monkeypatch.setenv("IAM_JIT_BOUNCER_ACTOR", "frank")

    payload = _yaml.safe_dump({
        "profiles": {
            "team-staging": {
                "description": "Team staging guardrail",
                "deny_keywords": ["staging"],
            },
        },
    }).encode("utf-8")
    url = "https://internal.example.com/profiles/staging.yaml"

    runner = CliRunner()
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = runner.invoke(
            main, ["profile", "install", "--from", url],
            catch_exceptions=False,
        )
    assert result.exit_code == 0, result.output

    # The pending_audit_events row must be in the SAME DB file the
    # serve process would open (env-var-resolved path).
    s = BouncerStore(db_path=str(db_path))
    try:
        # #278 — profile install now enqueues BOTH the PROFILE_INSTALL
        # synthetic (for the non_org_profile_install alert rule) and
        # an ADMIN_ACTION row (for the cross-product config-change
        # audit stream). Both must land; the test scopes to the
        # PROFILE_INSTALL row that this test was originally pinning.
        assert s.count_pending_audit_events() == 2
        rows = s.drain_pending_audit_events(limit=100)
    finally:
        s.close()
    assert len(rows) == 2
    install_rows = [r for r in rows if r["event_type"] == EVENT_TYPE_PROFILE_INSTALL]
    assert len(install_rows) == 1
    row = install_rows[0]
    payload_back = json.loads(row["payload_json"])
    assert payload_back["profile_name"] == "team-staging"
    assert payload_back["source_url"] == url
    assert payload_back["installed_by"] == "frank"


def test_drain_pending_audit_events_is_atomic(tmp_path) -> None:
    """drain_pending_audit_events MUST atomically pop the rows it
    returns — a second drain call sees an empty queue."""
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        s.enqueue_pending_audit_event(
            event_type=EVENT_TYPE_PROFILE_INSTALL,
            payload_json=json.dumps({
                "profile_name": "p1", "source_url": "https://x/p1.yaml",
                "installed_by": "u",
            }),
        )
        s.enqueue_pending_audit_event(
            event_type=EVENT_TYPE_PROFILE_INSTALL,
            payload_json=json.dumps({
                "profile_name": "p2", "source_url": "https://x/p2.yaml",
                "installed_by": "u",
            }),
        )
        first = s.drain_pending_audit_events(limit=100)
        second = s.drain_pending_audit_events(limit=100)
    finally:
        s.close()
    assert len(first) == 2
    assert second == []


@pytest.mark.asyncio
async def test_drain_loop_delivers_profile_install_to_rule_engine(
    tmp_path, reset_proxy_state,
) -> None:
    """Simulate the serve-process drain loop: a row enqueued by the
    install CLI (separate process) is picked up + delivered to the
    rule engine + the non_org_profile_install rule fires for an URL
    not on the allowlist."""
    # The "install command" enqueues into the shared DB.
    install_store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        install_store.enqueue_pending_audit_event(
            event_type=EVENT_TYPE_PROFILE_INSTALL,
            payload_json=json.dumps({
                "profile_name": "third-party",
                "source_url": "https://random-site.example.org/p.yaml",
                "installed_by": "grace",
            }),
        )
    finally:
        install_store.close()

    # The "serve process" opens its own handle + runs the same drain
    # logic the serve loop uses. We exercise the inner body of
    # _pending_audit_events_drain_loop directly (one iteration)
    # rather than spin up a full serve, so the test stays fast +
    # hermetic.
    fired: list[dict] = []
    config = AlertsConfig(profile_install_allowlist=(
        "https://internal.example.com/approved.yaml",
    ))
    engine = RuleEngine(config=config, emit=fired.append)
    register_audit_rule_engine(engine)

    serve_store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        # Reproduce the loop body in one shot (matches the loop in
        # serve()'s _pending_audit_events_drain_loop).
        from iam_jit.bouncer.audit_export import make_profile_install_event
        from iam_jit.bouncer.audit_export.alerts import (
            EVENT_TYPE_PROFILE_INSTALL as _EVT,
        )
        rows = serve_store.drain_pending_audit_events(limit=100)
        for row in rows:
            assert row["event_type"] == _EVT
            payload = json.loads(row["payload_json"])
            evt = make_profile_install_event(
                profile_name=payload["profile_name"],
                source_url=payload["source_url"],
                installed_by=payload["installed_by"],
            )
            # Mirror the proxy's _emit_audit_event path: deliver
            # to rule engine. (We skip the transport-channel write
            # because this test doesn't register any.)
            engine.observe(evt)
    finally:
        serve_store.close()

    # Rule fired: the URL was not on the allowlist.
    non_org = [
        e for e in fired
        if (
            e.get("unmapped", {}).get("iam_jit", {}).get("pattern")
            == "non-org-profile-install"
        )
    ]
    assert len(non_org) == 1, (
        f"expected non-org-profile-install to fire once; fired: "
        f"{[e['unmapped']['iam_jit']['pattern'] for e in fired]}"
    )
    assert non_org[0]["severity_id"] == 3
    assert (
        "https://random-site.example.org/p.yaml"
        in non_org[0]["status_detail"]
    )


@pytest.mark.asyncio
async def test_serve_drain_loop_picks_up_enqueued_event(
    tmp_path, reset_proxy_state, monkeypatch,
) -> None:
    """End-to-end on the loop logic: spin up just the drain task
    (not the full HTTP server), enqueue a row, wait for the 1s tick,
    and assert the rule engine fires."""
    # Wire the rule engine up.
    fired: list[dict] = []
    config = AlertsConfig(profile_install_allowlist=())  # empty -> fires
    engine = RuleEngine(config=config, emit=fired.append)
    register_audit_rule_engine(engine)

    store = BouncerStore(db_path=str(tmp_path / "b.db"))

    # Patch the drain interval down so the test finishes in <2s.
    # (The production constant is 1.0s; we don't need to override —
    # one tick is enough — but we shrink the sleep to keep the
    # CI run fast.)
    async def _short_drain_loop() -> None:
        try:
            while True:
                await asyncio.sleep(0.05)
                rows = store.drain_pending_audit_events(limit=100)
                if not rows:
                    continue
                from iam_jit.bouncer.audit_export import (
                    make_profile_install_event,
                )
                for row in rows:
                    payload = json.loads(row["payload_json"])
                    evt = make_profile_install_event(
                        profile_name=payload["profile_name"],
                        source_url=payload["source_url"],
                        installed_by=payload["installed_by"],
                    )
                    proxy_mod._emit_audit_event(evt)
        except asyncio.CancelledError:
            return

    task = asyncio.create_task(_short_drain_loop())
    try:
        store.enqueue_pending_audit_event(
            event_type=EVENT_TYPE_PROFILE_INSTALL,
            payload_json=json.dumps({
                "profile_name": "drained",
                "source_url": "https://elsewhere.example.org/p.yaml",
                "installed_by": "henry",
            }),
        )
        # Wait up to ~1s for the loop to pick up + deliver.
        deadline = asyncio.get_event_loop().time() + 1.0
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(0.05)
            if any(
                e.get("unmapped", {}).get("iam_jit", {}).get("pattern")
                == "non-org-profile-install"
                for e in fired
            ):
                break
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()

    non_org = [
        e for e in fired
        if (
            e.get("unmapped", {}).get("iam_jit", {}).get("pattern")
            == "non-org-profile-install"
        )
    ]
    assert len(non_org) == 1


# ---------------------------------------------------------------------------
# Re-entry safety: synthetic events themselves never re-trigger their
# own rules (RuleEngine's ANOMALY_DETECTED guard).
# ---------------------------------------------------------------------------


def test_synthetic_events_do_not_re_enter_rule_engine(
    store, reset_proxy_state,
) -> None:
    """If the rule engine fires an anomaly event AND the proxy emits
    that anomaly through the transport, the engine's re-entry guard
    keeps observe() from acting on it. Belt-and-suspenders check on
    the integrated path."""
    fired: list[dict] = []
    inner = RuleEngine(
        config=AlertsConfig.default(), emit=fired.append,
    )
    register_audit_rule_engine(inner)

    store.start_pause(
        duration_seconds=600, reason="reentry test", started_by="ivy",
    )
    # Trigger a burst -> fires admin_fallback_burst once -> the
    # ANOMALY_DETECTED event would re-enter via the emit callback
    # if the guard were absent.
    for i in range(5):
        evaluate_request(
            method="GET",
            host="s3.us-east-1.amazonaws.com",
            path=f"/bucket/k{i}",
            headers={
                "host": "s3.us-east-1.amazonaws.com",
                "authorization": _sigv4(service="s3", region="us-east-1"),
            },
            body=None, query=None,
            store=store,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
        )

    # We should have fired admin-fallback-burst on the 4th + 5th
    # demoted request (window count > threshold each time). Each
    # fire is an anomaly event that goes through emit(); none of
    # them should themselves fire MORE anomaly events.
    anomaly_count = sum(
        1 for e in fired
        if (
            e.get("unmapped", {}).get("iam_jit", {}).get("event_type")
            == EVENT_TYPE_ANOMALY_DETECTED
        )
    )
    # The engine's emit() captures every fire — but a 2nd-order
    # anomaly fire would more-than-double the count + show patterns
    # other than admin-fallback-burst. Confirm only admin-fallback-
    # burst landed.
    patterns = set(
        e["unmapped"]["iam_jit"]["pattern"] for e in fired
        if e.get("unmapped", {}).get("iam_jit", {}).get("pattern")
    )
    assert patterns == {"admin-fallback-burst"}, (
        f"unexpected patterns fired (re-entry?): {patterns}"
    )
    assert anomaly_count >= 1
