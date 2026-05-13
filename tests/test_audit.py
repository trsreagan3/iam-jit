"""Tamper-evident audit chain tests."""

from __future__ import annotations

import json

from iam_jit import audit


def setup_function(_func) -> None:
    audit.reset_for_tests()


class _Sink:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def append(self, line: str) -> None:
        self.lines.append(line)


def test_chain_links_each_event_to_the_previous() -> None:
    sink = _Sink()
    e1 = audit.emit(actor="admin", kind="context.loaded", summary="boot", sink=sink)
    e2 = audit.emit(actor="dev", kind="request.transition", summary="submit", sink=sink)
    e3 = audit.emit(actor="approver", kind="request.transition", summary="approve", sink=sink)

    assert e1.prev_hash is None
    assert e2.prev_hash == e1.hash
    assert e3.prev_hash == e2.hash
    # Sequence numbers are monotonic from zero.
    assert (e1.seq, e2.seq, e3.seq) == (0, 1, 2)

    events = [json.loads(l) for l in sink.lines]
    ok, bad, reason = audit.verify_chain(events)
    assert ok and bad is None and reason is None


def test_tampering_invalidates_chain() -> None:
    sink = _Sink()
    audit.emit(actor="a", kind="x", summary="one", sink=sink)
    audit.emit(actor="b", kind="x", summary="two", sink=sink)
    audit.emit(actor="c", kind="x", summary="three", sink=sink)

    events = [json.loads(l) for l in sink.lines]
    events[1]["summary"] = "TWO-tampered"
    ok, bad, reason = audit.verify_chain(events)
    assert not ok
    assert bad == 1
    assert "edited" in (reason or "")


def test_context_drift_detection() -> None:
    audit.record_boot_fingerprint("llm.org_context", "abc123")
    current = {"value": "abc123"}
    audit.register_refingerprint("llm.org_context", lambda: current["value"])
    assert audit.detect_context_drift() == []

    current["value"] = "deadbeef"
    drift = audit.detect_context_drift()
    assert len(drift) == 1
    assert drift[0]["name"] == "llm.org_context"
    assert drift[0]["boot"] == "abc123"
    assert drift[0]["current"] == "deadbeef"


def test_fingerprint_is_deterministic_and_short() -> None:
    a = audit.fingerprint("hello")
    b = audit.fingerprint(b"hello")
    assert a == b
    assert len(a) == 16
