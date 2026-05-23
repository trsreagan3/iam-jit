"""Tests for #427 / §A66 — audit-export hash-chain (chain.py).

Coverage matrix from the brief:
- test_hash_chain_each_entry_includes_prior_hash
- test_hash_chain_tamper_detection_via_recompute
- test_iam_jit_audit_verify_reports_inconsistencies
- test_iam_jit_audit_verify_clean_chain_returns_ok

Plus persistence + restart-discontinuity + chain-block-missing
edge cases that fall naturally out of the same scaffolding.
"""

from __future__ import annotations

import gzip
import json
import pathlib

import pytest

from iam_jit.bouncer.audit_export import (
    CHAIN_FIELD,
    CHAIN_HASH_FIELD,
    CHAIN_PREV_HASH_FIELD,
    CHAIN_SEQ_FIELD,
    REASON_HASH_MISMATCH,
    REASON_MISSING_CHAIN_BLOCK,
    REASON_PREV_HASH_MISMATCH,
    REASON_SEQ_GAP,
    ChainState,
    load_chain_state,
    save_chain_state,
    stamp_chain_event,
    verify_chain_jsonl,
)


def _ocsf_event(activity: str = "Read") -> dict:
    """Minimal OCSF-shaped event the chain stamper accepts."""
    return {
        "metadata": {"version": "1.1.0", "product": {"name": "ibounce"}},
        "class_uid": 6003,
        "activity_name": activity,
        "time": 1_700_000_000_000,
        "unmapped": {"iam_jit": {"verdict": "ALLOW"}},
    }


def _write_jsonl(path: pathlib.Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def test_hash_chain_each_entry_includes_prior_hash(tmp_path):
    """Per the spec: each stamped event's prev_hash MUST equal the
    previous stamped event's hash. The genesis row has prev_hash=None."""
    state = ChainState(log_dir=str(tmp_path))
    events = [_ocsf_event(), _ocsf_event(), _ocsf_event()]
    for e in events:
        stamp_chain_event(e, state)
    chain_blocks = [e["unmapped"]["iam_jit"][CHAIN_FIELD] for e in events]
    assert chain_blocks[0][CHAIN_SEQ_FIELD] == 0
    assert chain_blocks[0][CHAIN_PREV_HASH_FIELD] is None
    assert chain_blocks[1][CHAIN_SEQ_FIELD] == 1
    assert chain_blocks[1][CHAIN_PREV_HASH_FIELD] == chain_blocks[0][CHAIN_HASH_FIELD]
    assert chain_blocks[2][CHAIN_SEQ_FIELD] == 2
    assert chain_blocks[2][CHAIN_PREV_HASH_FIELD] == chain_blocks[1][CHAIN_HASH_FIELD]
    # All three hashes are distinct (different seq + payload).
    hashes = [b[CHAIN_HASH_FIELD] for b in chain_blocks]
    assert len(set(hashes)) == 3
    # All hashes are non-empty hex strings.
    for h in hashes:
        assert isinstance(h, str) and len(h) == 64
        int(h, 16)  # parses as hex


def test_hash_chain_tamper_detection_via_recompute(tmp_path):
    """An attacker who silently edits a row breaks the chain — the
    recomputed hash no longer matches the row's claimed hash."""
    state = ChainState(log_dir=str(tmp_path))
    log = tmp_path / "audit.jsonl"
    events = []
    for i in range(5):
        e = _ocsf_event()
        e["unmapped"]["iam_jit"]["decision_id"] = f"d{i}"
        stamp_chain_event(e, state)
        events.append(e)
    _write_jsonl(log, events)

    # Verify clean first.
    result = verify_chain_jsonl(tmp_path)
    assert result.ok, result.inconsistencies
    assert result.events_checked == 5

    # Edit row 2 ON DISK (the kind of tamper an attacker would do
    # against a JSONL file that ships off-host).
    raw = log.read_text().splitlines()
    parsed = json.loads(raw[2])
    parsed["unmapped"]["iam_jit"]["verdict"] = "DENY"  # change verdict
    raw[2] = json.dumps(parsed)
    log.write_text("\n".join(raw) + "\n")

    result = verify_chain_jsonl(tmp_path)
    assert not result.ok
    # Row 2 fails recompute; rows 3+4 fail prev_hash check too because
    # the recompute of row 2 still uses the on-disk seq.
    reasons = {f.reason for f in result.inconsistencies}
    assert REASON_HASH_MISMATCH in reasons


def test_hash_chain_deletion_detected_via_seq_gap(tmp_path):
    """Deleting a row leaves a seq gap that verify_jsonl reports."""
    state = ChainState(log_dir=str(tmp_path))
    log = tmp_path / "audit.jsonl"
    events = []
    for i in range(4):
        e = _ocsf_event()
        e["seq_label"] = i
        stamp_chain_event(e, state)
        events.append(e)
    # Remove row 2; write only [0, 1, 3].
    truncated = [events[0], events[1], events[3]]
    _write_jsonl(log, truncated)
    result = verify_chain_jsonl(tmp_path)
    assert not result.ok
    reasons = {f.reason for f in result.inconsistencies}
    assert REASON_SEQ_GAP in reasons or REASON_PREV_HASH_MISMATCH in reasons


def test_iam_jit_audit_verify_clean_chain_returns_ok(tmp_path):
    """The CLI's underlying verifier returns ok=True for an untampered
    chain across both the active jsonl + rotated gz archives."""
    state = ChainState(log_dir=str(tmp_path))
    archive_events = []
    for i in range(3):
        e = _ocsf_event()
        stamp_chain_event(e, state)
        archive_events.append(e)
    # Persist the first 3 in a rotated archive.
    archive_path = tmp_path / "audit-2026-05-23-120000.jsonl.gz"
    with gzip.open(archive_path, "wt") as f:
        for e in archive_events:
            f.write(json.dumps(e) + "\n")

    active_events = []
    for i in range(2):
        e = _ocsf_event()
        stamp_chain_event(e, state)
        active_events.append(e)
    _write_jsonl(tmp_path / "audit.jsonl", active_events)

    result = verify_chain_jsonl(tmp_path)
    assert result.ok, result.inconsistencies
    assert result.events_checked == 5
    assert result.files_checked == 2


def test_iam_jit_audit_verify_reports_inconsistencies(tmp_path):
    """Every finding is surfaced individually (no silent passes)."""
    state = ChainState(log_dir=str(tmp_path))
    events = []
    for _ in range(3):
        e = _ocsf_event()
        stamp_chain_event(e, state)
        events.append(e)
    # Strip the chain block from row 1 to simulate an event emitted
    # before the chain was wired (or stripped by a buggy processor).
    events[1]["unmapped"]["iam_jit"].pop(CHAIN_FIELD)
    _write_jsonl(tmp_path / "audit.jsonl", events)
    result = verify_chain_jsonl(tmp_path)
    assert not result.ok
    reasons = [f.reason for f in result.inconsistencies]
    assert REASON_MISSING_CHAIN_BLOCK in reasons


def test_chain_state_persistence_round_trip(tmp_path):
    """save_state + load_state round-trips next_seq + last_hash."""
    state = ChainState(log_dir=str(tmp_path), save_every_n_events=2)
    for _ in range(5):
        stamp_chain_event(_ocsf_event(), state)
    save_chain_state(state)
    loaded = load_chain_state(str(tmp_path))
    assert loaded.next_seq == state.next_seq
    assert loaded.last_hash == state.last_hash
    assert not loaded.state_file_missing


def test_load_state_missing_file_flags_discontinuity(tmp_path):
    """A fresh log_dir with no state file flips the discontinuity flag."""
    loaded = load_chain_state(str(tmp_path))
    assert loaded.state_file_missing
    assert loaded.next_seq == 0
    assert loaded.last_hash is None


def test_verify_jsonl_walks_rotated_archives_in_order(tmp_path):
    """Older archives (sorted by name) come BEFORE the active file."""
    state = ChainState(log_dir=str(tmp_path))
    # Genesis row goes into the oldest archive.
    e0 = _ocsf_event()
    stamp_chain_event(e0, state)
    with gzip.open(tmp_path / "audit-2026-05-22-000000.jsonl.gz", "wt") as f:
        f.write(json.dumps(e0) + "\n")
    e1 = _ocsf_event()
    stamp_chain_event(e1, state)
    with gzip.open(tmp_path / "audit-2026-05-23-000000.jsonl.gz", "wt") as f:
        f.write(json.dumps(e1) + "\n")
    e2 = _ocsf_event()
    stamp_chain_event(e2, state)
    _write_jsonl(tmp_path / "audit.jsonl", [e2])
    result = verify_chain_jsonl(tmp_path)
    assert result.ok, result.inconsistencies
    assert result.events_checked == 3
    assert result.files_checked == 3
    assert result.head_seq == 2
