"""#724 / BUILD-3 — ChainTightener (consumer) unit tests.

Covers the consumer decision logic in isolation: a matching signal +
write request tightens (block mode); alert mode flags but does not
tighten; reads are never tightened; tightening-only (no allow when no
signal); independence/fail-soft when the store is unavailable.
"""

from __future__ import annotations

import pytest

from iam_jit.bouncer_chaining.chains import parse_rule
from iam_jit.bouncer_chaining.signal_store import (
    SIGNAL_KIND_PII_OBSERVED,
    SignalStore,
    SignalStoreError,
)
from iam_jit.bouncer_chaining.tightener import ChainTightener


_PII_RULE = parse_rule({
    "trigger": "dbounce.pii_detected",
    "action": "ibounce.tighten_egress",
    "ttl": "1h",
})


@pytest.fixture
def store(tmp_path):
    return SignalStore(db_path=str(tmp_path / "signals.db"))


def _seed_pii(store, session_id="sess-1"):
    store.emit_signal(
        session_id=session_id, kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )


def test_block_mode_tightens_write_with_active_signal(store):
    _seed_pii(store)
    t = ChainTightener(store=store, rules=[_PII_RULE], mode="block")
    res = t.evaluate(session_id="sess-1", is_write=True)
    assert res.tighten is True
    assert res.fired is True
    assert res.source_bouncer == "dbounce"
    assert res.trigger_kind == SIGNAL_KIND_PII_OBSERVED
    assert t.tightenings_total == 1


def test_alert_mode_flags_but_does_not_tighten(store):
    _seed_pii(store)
    t = ChainTightener(store=store, rules=[_PII_RULE], mode="alert")
    res = t.evaluate(session_id="sess-1", is_write=True)
    assert res.tighten is False
    assert res.fired is True   # still emits the audit event
    assert t.tightenings_total == 0


def test_read_is_never_tightened(store):
    """A pure read can't exfiltrate observed PII outward, so we don't
    over-block it (safety-mode-lean-permissive)."""
    _seed_pii(store)
    t = ChainTightener(store=store, rules=[_PII_RULE], mode="block")
    res = t.evaluate(session_id="sess-1", is_write=False)
    assert res.tighten is False
    assert res.fired is False


def test_no_signal_is_noop(store):
    """Tightening-only: with no active signal, the tightener never
    fires — it can only ever ADD a deny, never produce an allow."""
    t = ChainTightener(store=store, rules=[_PII_RULE], mode="block")
    res = t.evaluate(session_id="sess-1", is_write=True)
    assert res.tighten is False
    assert res.fired is False


def test_other_session_signal_does_not_tighten(store):
    _seed_pii(store, session_id="other")
    t = ChainTightener(store=store, rules=[_PII_RULE], mode="block")
    res = t.evaluate(session_id="sess-1", is_write=True)
    assert res.tighten is False


def test_no_session_id_is_noop(store):
    _seed_pii(store)
    t = ChainTightener(store=store, rules=[_PII_RULE], mode="block")
    res = t.evaluate(session_id=None, is_write=True)
    assert res.tighten is False


def test_no_egress_rules_is_noop(store):
    _seed_pii(store)
    t = ChainTightener(store=store, rules=[], mode="block")
    res = t.evaluate(session_id="sess-1", is_write=True)
    assert res.tighten is False
    assert t.egress_rule_count == 0


def test_unavailable_store_fails_soft(store, monkeypatch):
    """Independence guarantee: a signal-store error yields a NO-OP, not
    a crash + not a loosen. The bouncer decides standalone."""
    _seed_pii(store)
    t = ChainTightener(store=store, rules=[_PII_RULE], mode="block")

    def _boom(*a, **k):
        raise SignalStoreError("store is down")

    monkeypatch.setattr(store, "active_signals_for_session", _boom)
    res = t.evaluate(session_id="sess-1", is_write=True)
    assert res.tighten is False
    assert res.fired is False


def test_expired_signal_does_not_tighten(store):
    store.emit_signal(
        session_id="sess-1", kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=1, now=1000.0,
    )
    t = ChainTightener(store=store, rules=[_PII_RULE], mode="block")
    res = t.evaluate(session_id="sess-1", is_write=True, now=2000.0)
    assert res.tighten is False
