"""#724 / BUILD-3 — END-TO-END cross-protocol chain through the proxy.

The ONE concrete chain demonstrated on the Python side:

    dbounce observes PII in a SQL result
      -> writes a `pii_observed` signal keyed on the agent session
      -> ibounce (evaluate_request, HTTP egress) reads that signal and
         TIGHTENS an exfil-shaped (write) egress call for that session
         to DENY, emitting a CHAIN_TIGHTENED audit event that
         attributes dbounce as the source.

Also asserts the invariants the security review scrutinises:
  * default-OFF: no tightener installed -> standalone behaviour;
  * tightening-only: a read for the same session is untouched, and a
    different session is untouched;
  * independence / fail-soft: a down signal store -> standalone decide;
  * audit attribution of the source bouncer.
"""

from __future__ import annotations

import uuid

import pytest

from iam_jit.bouncer import proxy as proxy_mod
from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,  # noqa: F401 - imported for parity with sibling suites
    ProxyMode,
    evaluate_request,
)
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_chaining import (
    EVENT_TYPE_CHAIN_TIGHTENED,
    ChainTightener,
    SignalStore,
    register_chain_tightener,
    reset_for_tests,
)
from iam_jit.bouncer_chaining.chains import parse_rule
from iam_jit.bouncer_chaining.signal_store import SIGNAL_KIND_PII_OBSERVED

_SESSION_ID = str(uuid.uuid4())
_PII_RULE = parse_rule({
    "trigger": "dbounce.pii_detected",
    "action": "ibounce.tighten_egress",
    "ttl": "1h",
})


def _sigv4_auth_header(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260601/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakefakefake"
    )


class _CapturingWriter:
    """Minimal audit-log-writer stand-in: records every emitted event
    so the test can assert the CHAIN_TIGHTENED + decision rows fire."""

    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


@pytest.fixture
def store(tmp_path):
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    yield s
    s.close()


@pytest.fixture
def signal_store(tmp_path):
    return SignalStore(db_path=str(tmp_path / "signals.db"))


@pytest.fixture
def capturing_audit():
    writer = _CapturingWriter()
    proxy_mod.register_audit_log_writer(writer)
    yield writer
    proxy_mod.register_audit_log_writer(None)


@pytest.fixture(autouse=True)
def _clear_tightener():
    reset_for_tests()
    yield
    reset_for_tests()


def _put_s3(*, store, session_id, default_policy=DefaultPolicy.ALLOW):
    """A write-shaped (PUT) S3 egress for `session_id`."""
    return evaluate_request(
        method="PUT",
        host="s3.us-east-1.amazonaws.com",
        path="/exfil-bucket/dump.json",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
            "x-amz-date": "20260601T000000Z",
            "x-agent-name": "claude-code",
            "x-agent-session-id": session_id,
        },
        body=b"{}",
        query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=default_policy,
    )


def _get_s3(*, store, session_id):
    return evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/read-bucket/file.txt",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
            "x-amz-date": "20260601T000000Z",
            "x-agent-name": "claude-code",
            "x-agent-session-id": session_id,
        },
        body=None,
        query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.ALLOW,
    )


# ---------------------------------------------------------------------------
# THE concrete chain
# ---------------------------------------------------------------------------


def test_pii_signal_tightens_egress_end_to_end(store, signal_store, capturing_audit):
    """dbounce PII signal -> ibounce egress write DENIED for the same
    session, with a CHAIN_TIGHTENED audit event attributing dbounce."""
    # 1) Baseline: without a signal, the write is ALLOWed.
    register_chain_tightener(
        ChainTightener(store=signal_store, rules=[_PII_RULE], mode="block")
    )
    obs0 = _put_s3(store=store, session_id=_SESSION_ID)
    assert obs0.decision_verdict == "allow"

    # 2) dbounce observes PII in a SQL result -> writes the signal.
    signal_store.emit_signal(
        session_id=_SESSION_ID,
        kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce",
        ttl_seconds=3600,
        detail={"columns": ["email", "ssn"]},
    )

    # 3) ibounce's NEXT egress write for the same session is tightened.
    obs1 = _put_s3(store=store, session_id=_SESSION_ID)
    assert obs1.decision_verdict == "deny"
    assert obs1.deny_source == "bouncer_chaining"
    assert obs1.enforced is True
    assert "dbounce" in obs1.decision_reason

    # 4) Audit trail: a CHAIN_TIGHTENED event attributing the SOURCE
    #    bouncer (dbounce) fired.
    chain_events = [
        e for e in capturing_audit.events
        if e.get("unmapped", {}).get("iam_jit", {}).get("event_type")
        == EVENT_TYPE_CHAIN_TIGHTENED
    ]
    assert len(chain_events) >= 1
    ext = chain_events[-1]["unmapped"]["iam_jit"]["ext"]
    assert ext["chain_source_bouncer"] == "dbounce"
    assert ext["chain_trigger_kind"] == SIGNAL_KIND_PII_OBSERVED
    assert ext["session_id"] == _SESSION_ID
    # Neutral language only — no "violation"/"unauthorized".
    detail = chain_events[-1]["status_detail"].lower()
    assert "violation" not in detail
    assert "unauthorized" not in detail


def test_read_for_same_session_is_not_tightened(store, signal_store):
    """Tightening-only + narrow scope: a pure READ for the flagged
    session is NOT blocked (it can't carry PII outward)."""
    register_chain_tightener(
        ChainTightener(store=signal_store, rules=[_PII_RULE], mode="block")
    )
    signal_store.emit_signal(
        session_id=_SESSION_ID, kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )
    obs = _get_s3(store=store, session_id=_SESSION_ID)
    assert obs.decision_verdict == "allow"
    assert obs.deny_source is None


def test_different_session_unaffected(store, signal_store):
    """The signal is session-scoped: another agent session is untouched."""
    register_chain_tightener(
        ChainTightener(store=signal_store, rules=[_PII_RULE], mode="block")
    )
    signal_store.emit_signal(
        session_id=_SESSION_ID, kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )
    other = str(uuid.uuid4())
    obs = _put_s3(store=store, session_id=other)
    assert obs.decision_verdict == "allow"


def test_default_off_no_tightener_means_standalone(store, signal_store):
    """Default-OFF: with no tightener installed, even an active PII
    signal does NOT change the standalone verdict."""
    # No register_chain_tightener call -> singleton is None.
    signal_store.emit_signal(
        session_id=_SESSION_ID, kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )
    obs = _put_s3(store=store, session_id=_SESSION_ID)
    assert obs.decision_verdict == "allow"
    assert obs.deny_source is None


def test_independence_store_down_decides_standalone(store, signal_store, monkeypatch):
    """A down/broken signal store -> the proxy decides STANDALONE (the
    write is allowed per the bouncer's own policy), never crashes, and
    never flips to deny because of the chaining error path."""
    register_chain_tightener(
        ChainTightener(store=signal_store, rules=[_PII_RULE], mode="block")
    )
    signal_store.emit_signal(
        session_id=_SESSION_ID, kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )

    from iam_jit.bouncer_chaining.signal_store import SignalStoreError

    def _boom(*a, **k):
        raise SignalStoreError("signal store unavailable")

    monkeypatch.setattr(signal_store, "active_signals_for_session", _boom)
    obs = _put_s3(store=store, session_id=_SESSION_ID)
    # Fail-soft: standalone ALLOW (default policy), NOT a chain deny.
    assert obs.decision_verdict == "allow"
    assert obs.deny_source is None


def test_alert_mode_emits_event_but_allows(store, signal_store, capturing_audit):
    """In alert mode the chain emits the CHAIN_TIGHTENED event but does
    NOT change the verdict (observe-before-enforce)."""
    register_chain_tightener(
        ChainTightener(store=signal_store, rules=[_PII_RULE], mode="alert")
    )
    signal_store.emit_signal(
        session_id=_SESSION_ID, kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )
    obs = _put_s3(store=store, session_id=_SESSION_ID)
    assert obs.decision_verdict == "allow"
    chain_events = [
        e for e in capturing_audit.events
        if e.get("unmapped", {}).get("iam_jit", {}).get("event_type")
        == EVENT_TYPE_CHAIN_TIGHTENED
    ]
    assert len(chain_events) >= 1
    assert chain_events[-1]["unmapped"]["iam_jit"]["ext"]["chain_mode"] == "alert"
