"""Comprehensive durability + tamper-detection tests for the audit log.

Each test seeds a chain, applies one specific corruption pattern, and
asserts the verifier flags it with the right index + reason. The goal
is documented coverage: anyone reading this file should see exactly
which attacks are detectable from the log alone vs. which need an
external checkpoint anchor.

Detection summary:
  - in-place edit         → detected (hash mismatch)
  - reorder               → detected (prev_hash mismatch)
  - delete middle row     → detected (seq gap or prev_hash mismatch)
  - delete head row       → detected (seq doesn't start at 0)
  - duplicate row         → detected (duplicate seq)
  - inserted forged row   → detected (prev_hash + hash + seq all break)
  - tail truncation       → detected ONLY with external checkpoint
  - replay (full re-emit) → detected (hashes differ from external anchor)
"""

from __future__ import annotations

import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from iam_jit import audit


def setup_function(_func) -> None:
    audit.reset_for_tests()


class _Sink:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def append(self, line: str) -> None:
        self.lines.append(line)


def _seed(sink: _Sink, n: int = 4) -> list[dict]:
    """Emit n events, return their JSON bodies."""
    for i in range(n):
        audit.emit(actor=f"actor{i}", kind="x", summary=f"event-{i}", sink=sink)
    return [json.loads(line) for line in sink.lines]


# ---- in-place edit ----


def test_in_place_edit_detected_at_edited_row() -> None:
    sink = _Sink()
    events = _seed(sink, 5)
    events[2]["summary"] = "EDITED"
    ok, bad, reason = audit.verify_chain(events)
    assert not ok
    assert bad == 2
    assert "edited" in reason


def test_in_place_detail_edit_detected() -> None:
    sink = _Sink()
    events = _seed(sink, 3)
    events[1]["details"] = {"injected": "field"}
    ok, bad, reason = audit.verify_chain(events)
    assert not ok and bad == 1


def test_in_place_actor_edit_detected() -> None:
    sink = _Sink()
    events = _seed(sink, 3)
    events[0]["actor"] = "different-actor"
    ok, bad, reason = audit.verify_chain(events)
    assert not ok and bad == 0


# ---- reorder ----


def test_reorder_detected() -> None:
    sink = _Sink()
    events = _seed(sink, 4)
    events[1], events[2] = events[2], events[1]
    ok, bad, reason = audit.verify_chain(events)
    assert not ok
    # First detectable break is at the swapped position
    assert bad in (1, 2)


# ---- delete ----


def test_delete_middle_row_detected_via_seq_gap() -> None:
    sink = _Sink()
    events = _seed(sink, 5)
    del events[2]  # remove seq=2
    ok, bad, reason = audit.verify_chain(events)
    assert not ok
    assert "seq gap" in reason or "prev_hash" in reason


def test_delete_head_row_detected() -> None:
    sink = _Sink()
    events = _seed(sink, 5)
    del events[0]  # remove seq=0; now starts at seq=1
    ok, bad, reason = audit.verify_chain(events)
    assert not ok
    assert "seq" in reason.lower()


def test_delete_last_row_detected_only_with_checkpoint() -> None:
    """Tail truncation is the one attack the chain alone CAN'T detect.
    The remaining events still verify cleanly — they just look like
    fewer events happened. An external checkpoint is required to catch
    this.

    This test documents the limitation explicitly."""
    sink = _Sink()
    events = _seed(sink, 5)
    cp = audit.checkpoint()  # seq=4 anchored
    # Now an attacker truncates the tail.
    truncated = events[:3]

    # Without checkpoint: chain still verifies (it's a shorter valid chain).
    ok, bad, reason = audit.verify_chain(truncated)
    assert ok, f"expected truncated chain to verify without anchor, but got {reason}"

    # With checkpoint: detected.
    ok2, bad2, reason2 = audit.verify_chain(truncated, expected_checkpoint=cp)
    assert not ok2
    assert "truncation" in reason2


def test_checkpoint_catches_pre_anchor_edit() -> None:
    """If an attacker anchors a checkpoint THEN edits a row at or before
    the anchor, verification with the checkpoint reveals it."""
    sink = _Sink()
    events = _seed(sink, 5)
    cp = audit.checkpoint()  # seq=4 anchored
    # Attacker edits row 2 (and re-hashes the chain to make it self-consistent).
    # We simulate that by re-emitting from scratch with row 2 changed.
    audit.reset_for_tests()
    sink2 = _Sink()
    for i in range(5):
        summary = "MODIFIED" if i == 2 else f"event-{i}"
        audit.emit(actor=f"actor{i}", kind="x", summary=summary, sink=sink2)
    forged = [json.loads(line) for line in sink2.lines]

    # Forged chain self-verifies (attacker rebuilt all hashes correctly).
    ok, _, _ = audit.verify_chain(forged)
    assert ok

    # But against the original checkpoint, the hash at seq=4 doesn't match.
    ok2, bad2, reason2 = audit.verify_chain(forged, expected_checkpoint=cp)
    assert not ok2
    assert "checkpoint hash mismatch" in reason2


# ---- duplicate / forged inserts ----


def test_duplicate_seq_detected() -> None:
    sink = _Sink()
    events = _seed(sink, 3)
    events.append(copy.deepcopy(events[1]))  # re-insert seq=1
    ok, bad, reason = audit.verify_chain(events)
    assert not ok
    assert "duplicate seq" in reason


def test_inserted_forged_row_breaks_seq_or_chain() -> None:
    """An attacker inserts a fake row in the middle. They can't compute
    a valid hash without seeing the chain, but even if they get the hash
    right they have to renumber every later seq — which we'd detect."""
    sink = _Sink()
    events = _seed(sink, 5)
    fake = {
        "seq": 2,
        "timestamp": 0.0,
        "actor": "ghost",
        "kind": "x",
        "summary": "forged",
        "details": {},
        "prev_hash": events[1]["hash"],
        "hash": "fakehash",
    }
    events.insert(2, fake)
    ok, bad, reason = audit.verify_chain(events)
    assert not ok
    assert bad == 2  # the forged row breaks at its position


# ---- malformed structure ----


def test_missing_seq_field_detected() -> None:
    sink = _Sink()
    events = _seed(sink, 3)
    del events[1]["seq"]
    ok, bad, reason = audit.verify_chain(events)
    assert not ok and reason == "missing seq"


def test_missing_hash_field_detected() -> None:
    sink = _Sink()
    events = _seed(sink, 3)
    del events[1]["hash"]
    ok, bad, reason = audit.verify_chain(events)
    assert not ok
    assert "edited" in reason or "hash" in reason.lower()


# ---- empty + single-row ----


def test_empty_chain_verifies() -> None:
    ok, bad, reason = audit.verify_chain([])
    assert ok and bad is None and reason is None


def test_single_row_chain_verifies() -> None:
    sink = _Sink()
    audit.emit(actor="a", kind="x", summary="alone", sink=sink)
    events = [json.loads(line) for line in sink.lines]
    ok, _, _ = audit.verify_chain(events)
    assert ok


# ---- concurrency ----


def test_concurrent_emits_produce_valid_chain() -> None:
    """Multiple threads emitting simultaneously shouldn't corrupt the
    chain. The internal lock serializes seq + hash assignment; the
    final on-disk ordering reflects the order the lock was acquired,
    not wall-clock — but every row is consistent."""
    sink = _Sink()
    sink_lock = threading.Lock()

    class _ThreadSafeSink:
        def append(self, line: str) -> None:
            with sink_lock:
                sink.lines.append(line)

    safe_sink = _ThreadSafeSink()

    def emit_n(start: int, n: int) -> None:
        for i in range(n):
            audit.emit(
                actor=f"thread-{start}",
                kind="x",
                summary=f"event-{start}-{i}",
                sink=safe_sink,
            )

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(emit_n, t, 20) for t in range(10)]
        for f in futures:
            f.result()

    events = [json.loads(line) for line in sink.lines]
    assert len(events) == 200
    # Sort by seq before verifying — the sink may have observed lines in
    # a different order than the lock granted seq numbers, depending on
    # GIL scheduling. The chain is still valid in seq order.
    events.sort(key=lambda e: e["seq"])
    ok, bad, reason = audit.verify_chain(events)
    assert ok, f"concurrent emit produced invalid chain: bad={bad} reason={reason}"
    # Every seq from 0..199 present, no duplicates.
    seqs = [e["seq"] for e in events]
    assert seqs == list(range(200))


# ---- checkpoint correctness ----


def test_checkpoint_returns_none_for_empty_log() -> None:
    assert audit.checkpoint() is None


def test_checkpoint_advances_with_each_emit() -> None:
    sink = _Sink()
    audit.emit(actor="a", kind="x", summary="one", sink=sink)
    cp1 = audit.checkpoint()
    assert cp1.seq == 0
    audit.emit(actor="b", kind="x", summary="two", sink=sink)
    cp2 = audit.checkpoint()
    assert cp2.seq == 1
    assert cp2.hash != cp1.hash


def test_unmodified_chain_verifies_against_checkpoint() -> None:
    sink = _Sink()
    _seed(sink, 5)
    cp = audit.checkpoint()
    events = [json.loads(line) for line in sink.lines]
    ok, bad, reason = audit.verify_chain(events, expected_checkpoint=cp)
    assert ok, f"clean chain failed verify: {bad} {reason}"


# ---- replay attack ----


def test_replay_with_different_timestamps_detected_by_checkpoint() -> None:
    """If an attacker replays the same events but with new timestamps
    (e.g. to hide tampering by claiming the original log was lost and
    they have a 'recovered' copy), the resulting hashes differ from the
    checkpoint anchor."""
    sink = _Sink()
    _seed(sink, 5)
    cp = audit.checkpoint()

    # Simulate full replay with new timestamps.
    audit.reset_for_tests()
    replay_sink = _Sink()
    _seed(replay_sink, 5)
    replayed = [json.loads(line) for line in replay_sink.lines]

    ok, bad, reason = audit.verify_chain(replayed, expected_checkpoint=cp)
    assert not ok
    assert "checkpoint" in reason.lower()
