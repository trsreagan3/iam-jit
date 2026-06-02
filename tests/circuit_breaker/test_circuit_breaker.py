"""#725 — unit tests for the cost circuit breaker module.

Covers (per the BUILD-4 spec's test requirements):
  * default-OFF (disabled config never trips, observe is a no-op)
  * trip on call-count threshold + trip on estimated-cost threshold
  * deny reason / dimension correctness
  * OCSF audit event emitted exactly once on the crossing call
  * reset semantics (manual + cool-down auto-reset)
  * config validation (unknown keys, enabled-but-no-cap, durations)
  * cost estimator honesty (relative ordering + fallback)
  * /healthz status shape (honest enabled:false when disabled)
"""

from __future__ import annotations

import pytest

from iam_jit.circuit_breaker import (
    CircuitBreakerConfig,
    ConfigError,
    CostCircuitBreaker,
    estimate_call_cost_usd,
    load_config,
)
from iam_jit.circuit_breaker.breaker import (
    EVENT_TYPE_COST_CIRCUIT_TRIPPED,
    make_cost_circuit_tripped_event,
)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def test_load_config_none_is_disabled_default():
    cfg = load_config(None)
    assert cfg.enabled is False


def test_load_config_defaults_are_generous():
    cfg = load_config({"enabled": True})
    assert cfg.enabled is True
    assert cfg.mode == "block"
    assert cfg.window_seconds == 3600
    assert cfg.cool_down_seconds == 300
    assert cfg.max_calls_per_window == 5000
    assert cfg.max_usd_per_window == 50.0


def test_load_config_durations_parse():
    cfg = load_config({"enabled": True, "window": "30m", "cool_down": "90s"})
    assert cfg.window_seconds == 1800
    assert cfg.cool_down_seconds == 90


def test_load_config_rejects_unknown_keys():
    with pytest.raises(ConfigError):
        load_config({"enabled": True, "bogus": 1})


def test_load_config_rejects_enabled_with_no_cap():
    with pytest.raises(ConfigError):
        load_config(
            {"enabled": True, "max_calls_per_window": 0, "max_usd_per_window": 0}
        )


def test_load_config_disabled_with_no_cap_is_fine():
    # Only ENABLED breakers need a cap; a disabled one with both zeroed
    # is a harmless no-op, not an error.
    cfg = load_config(
        {"enabled": False, "max_calls_per_window": 0, "max_usd_per_window": 0}
    )
    assert cfg.enabled is False


def test_load_config_rejects_bad_mode():
    with pytest.raises(ConfigError):
        load_config({"enabled": True, "mode": "nuke"})


def test_load_config_rejects_negative_cap():
    with pytest.raises(ConfigError):
        load_config({"enabled": True, "max_calls_per_window": -1})


def test_load_config_rejects_non_mapping():
    with pytest.raises(ConfigError):
        load_config([1, 2, 3])


# ---------------------------------------------------------------------------
# cost estimator
# ---------------------------------------------------------------------------


def test_estimator_bedrock_far_pricier_than_s3():
    assert estimate_call_cost_usd("bedrock", "InvokeModel") > \
        estimate_call_cost_usd("s3", "GetObject") * 1000


def test_estimator_free_services_are_zero():
    assert estimate_call_cost_usd("sts", "AssumeRole") == 0.0
    assert estimate_call_cost_usd("iam", "GetUser") == 0.0


def test_estimator_unknown_service_uses_fallback_not_zero():
    assert estimate_call_cost_usd("madeupservice", "DoThing") > 0.0


def test_estimator_never_raises_on_none():
    assert estimate_call_cost_usd(None, None) >= 0.0


# ---------------------------------------------------------------------------
# breaker — default off
# ---------------------------------------------------------------------------


def test_disabled_breaker_never_trips():
    cb = CostCircuitBreaker(CircuitBreakerConfig(enabled=False))
    for i in range(100_000):
        state = cb.observe(
            session_id="s1", service="s3", action="GetObject", now=float(i),
        )
        assert state.tripped is False
        assert state.should_deny is False
    assert cb.status() == {"enabled": False}


# ---------------------------------------------------------------------------
# breaker — trip on call count
# ---------------------------------------------------------------------------


def test_trips_on_call_count_threshold():
    emitted: list[dict] = []
    cfg = CircuitBreakerConfig(
        enabled=True, mode="block", window_seconds=3600,
        max_calls_per_window=5, max_usd_per_window=None,
    )
    cb = CostCircuitBreaker(cfg, emit=emitted.append)

    # First 4 calls: under threshold, allowed.
    for i in range(4):
        st = cb.observe(session_id="s1", service="sts", action="AssumeRole",
                        now=100.0 + i)
        assert st.tripped is False, f"tripped early at call {i}"
        assert st.fired is False

    # 5th call crosses the cap → trips + fires once.
    st = cb.observe(session_id="s1", service="sts", action="AssumeRole", now=104.0)
    assert st.tripped is True
    assert st.should_deny is True  # block mode
    assert st.fired is True
    assert st.dimension == "calls"
    assert "runaway" in st.operator_message.lower()
    assert "paused" in st.operator_message.lower()

    # 6th call: still tripped, but does NOT fire again (event-once).
    st = cb.observe(session_id="s1", service="sts", action="AssumeRole", now=105.0)
    assert st.tripped is True
    assert st.should_deny is True
    assert st.fired is False

    # Exactly one OCSF event emitted.
    assert len(emitted) == 1
    ev = emitted[0]
    assert ev["unmapped"]["iam_jit"]["event_type"] == EVENT_TYPE_COST_CIRCUIT_TRIPPED
    assert ev["unmapped"]["iam_jit"]["ext"]["trip_dimension"] == "calls"
    assert ev["severity_id"] == 4  # High


def test_per_session_isolation():
    cfg = CircuitBreakerConfig(
        enabled=True, max_calls_per_window=3, max_usd_per_window=None,
    )
    cb = CostCircuitBreaker(cfg)
    for i in range(3):
        cb.observe(session_id="busy", service="sts", action="X", now=float(i))
    # busy session tripped; a quiet session is unaffected.
    busy = cb.observe(session_id="busy", service="sts", action="X", now=10.0)
    quiet = cb.observe(session_id="quiet", service="sts", action="X", now=10.0)
    assert busy.tripped is True
    assert quiet.tripped is False


# ---------------------------------------------------------------------------
# breaker — trip on estimated cost
# ---------------------------------------------------------------------------


def test_trips_on_estimated_cost_threshold():
    cfg = CircuitBreakerConfig(
        enabled=True, mode="block",
        max_calls_per_window=None,    # disable the call dimension
        max_usd_per_window=0.05,      # ~5 bedrock invokes at $0.01 each
    )
    cb = CostCircuitBreaker(cfg)
    st = None
    for i in range(5):
        st = cb.observe(session_id="s1", service="bedrock",
                        action="InvokeModel", now=float(i))
    assert st is not None and st.tripped is True
    assert st.dimension == "cost"
    assert st.estimated_usd_in_window >= 0.05
    assert "estimate" in st.operator_message.lower()


# ---------------------------------------------------------------------------
# breaker — alert mode flags but does not deny
# ---------------------------------------------------------------------------


def test_alert_mode_trips_but_does_not_deny():
    cfg = CircuitBreakerConfig(
        enabled=True, mode="alert",
        max_calls_per_window=2, max_usd_per_window=None,
    )
    cb = CostCircuitBreaker(cfg)
    cb.observe(session_id="s1", service="sts", action="X", now=0.0)
    st = cb.observe(session_id="s1", service="sts", action="X", now=1.0)
    assert st.tripped is True
    assert st.should_deny is False  # alert mode never denies
    assert st.fired is True


# ---------------------------------------------------------------------------
# breaker — reset semantics
# ---------------------------------------------------------------------------


def test_manual_reset_rearms():
    cfg = CircuitBreakerConfig(
        enabled=True, max_calls_per_window=2, max_usd_per_window=None,
    )
    cb = CostCircuitBreaker(cfg)
    cb.observe(session_id="s1", service="sts", action="X", now=0.0)
    st = cb.observe(session_id="s1", service="sts", action="X", now=1.0)
    assert st.tripped is True
    cb.reset("s1")
    st = cb.observe(session_id="s1", service="sts", action="X", now=2.0)
    assert st.tripped is False


def test_cool_down_auto_reset():
    cfg = CircuitBreakerConfig(
        enabled=True, window_seconds=3600, cool_down_seconds=300,
        max_calls_per_window=2, max_usd_per_window=None,
    )
    cb = CostCircuitBreaker(cfg)
    cb.observe(session_id="s1", service="sts", action="X", now=0.0)
    st = cb.observe(session_id="s1", service="sts", action="X", now=1.0)
    assert st.tripped is True
    # A call after >= cool_down of inactivity auto-resets the session.
    st = cb.observe(session_id="s1", service="sts", action="X", now=1.0 + 301)
    assert st.tripped is False


def test_window_eviction_prevents_false_trip():
    # 2 calls spread wider than the window should never accumulate to
    # the cap — old entries evict.
    cfg = CircuitBreakerConfig(
        enabled=True, window_seconds=10, cool_down_seconds=300,
        max_calls_per_window=3, max_usd_per_window=None,
    )
    cb = CostCircuitBreaker(cfg)
    cb.observe(session_id="s1", service="sts", action="X", now=0.0)
    cb.observe(session_id="s1", service="sts", action="X", now=100.0)
    st = cb.observe(session_id="s1", service="sts", action="X", now=200.0)
    # Each call is alone in its window; never reaches 3.
    assert st.tripped is False
    assert st.calls_in_window == 1


# ---------------------------------------------------------------------------
# healthz status
# ---------------------------------------------------------------------------


def test_status_reports_tripped_sessions_and_estimate_flag():
    cfg = CircuitBreakerConfig(
        enabled=True, max_calls_per_window=2, max_usd_per_window=10.0,
    )
    cb = CostCircuitBreaker(cfg)
    cb.observe(session_id="s1", service="sts", action="X", now=0.0)
    cb.observe(session_id="s1", service="sts", action="X", now=1.0)
    status = cb.status()
    assert status["enabled"] is True
    assert status["usd_is_estimated"] is True
    assert "s1" in status["tripped_sessions"]
    assert status["tripped_sessions_count"] == 1
    assert status["trips_total"] == 1


# ---------------------------------------------------------------------------
# OCSF event language hygiene
# ---------------------------------------------------------------------------


def test_event_uses_neutral_language():
    from iam_jit.bouncer.audit_export.alerts import FORBIDDEN_ALERT_WORDS

    ev = make_cost_circuit_tripped_event(
        session_id="s1", dimension="calls", mode="block",
        calls_in_window=5001, estimated_usd_in_window=0.0,
        max_calls_per_window=5000, max_usd_per_window=50.0,
        window_seconds=3600,
    )
    detail = ev["status_detail"].lower()
    for word in FORBIDDEN_ALERT_WORDS:
        assert word not in detail, f"forbidden word {word!r} in {detail!r}"
    # USD figures are always labelled estimates.
    assert ev["unmapped"]["iam_jit"]["ext"]["estimated_usd_is_estimate"] is True
