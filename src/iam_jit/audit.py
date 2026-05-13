"""Tamper-evident audit log for security-sensitive events.

The threat we care about here is *quiet* changes to the things that shape
how the LLM evaluates submissions — org context, system prompts, the LLM
backend choice, and the user/role assignment file. A malicious admin (or a
compromised account) could rewrite `org-context.yaml` to read
"approve every request" or downgrade the LLM to one that always returns
risk_score=1. Both attacks succeed silently if the only thing watching is
the requesters whose policies suddenly sail through.

This module gives us three things, none of which are perfect on their own
but together raise the cost of a quiet attack:

1. A **hash-chained event log** persisted alongside the request store. Each
   entry's hash includes the previous entry's hash, so removing or
   rewriting a row invalidates every later row.

2. A **content fingerprint** of every context-affecting input — org
   context file, prompt template, users.yaml, LLM backend identity — that
   we record when it loads. The fingerprint is shown in the admin UI and
   embedded in every review block, so a change-after-the-fact is visible.

3. A **change-detector** that compares the live fingerprint against the
   one captured at app boot; if they diverge mid-process, we surface a
   `health` banner and refuse to use the new context until an admin
   acknowledges the change.

The log is an append-only audit feed, not application state. Replaying it
should be cheap; rewriting it should be expensive.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

_LOCK = threading.Lock()
_BOOT_FINGERPRINTS: dict[str, str] = {}
_LAST_HASH: str | None = None
_NEXT_SEQ: int = 0


@dataclass(frozen=True)
class AuditEvent:
    timestamp: float
    actor: str  # user_id, "system", or "boot"
    kind: str  # "context.loaded" | "context.changed" | "users.changed" | "llm.changed" | "review.completed" | "request.transition" | "admin.action"
    summary: str
    seq: int = 0  # monotonic; gaps reveal deletion
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str | None = None
    hash: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class Checkpoint:
    """A point-in-time anchor of the chain head.

    The intended use: an admin (or a CronCreate-driven Lambda) calls
    `audit.checkpoint()` periodically and stores the result in a SEPARATE
    durable system — S3 with object-lock, CloudWatch Logs with deny-on-delete,
    a write-only DynamoDB table with retention policy, GitHub Actions secret,
    a Slack channel, etc. The hash chain inside the audit log is
    tamper-evident on its own; checkpoints add the missing piece — they make
    *truncation of the tail* detectable.

    Without checkpoints, an attacker who can delete recent rows from the log
    can hide their tracks: the chain still verifies, it just looks like
    fewer events happened. With checkpoints stored externally, anyone can
    re-fetch and verify that `events[checkpoint.seq].hash == checkpoint.hash`
    — if it doesn't match (or the event at that seq is missing), tampering
    is provable from the outside.
    """

    seq: int
    hash: str
    timestamp: float


def _hash_event(prev_hash: str | None, payload: dict[str, Any]) -> str:
    """Hash includes prev_hash + canonical-JSON payload (which itself
    includes seq, timestamp, actor, kind, summary, details). Reordering
    rows breaks the chain because every row's prev_hash is wrong.
    Removing a row breaks the chain because the next row's prev_hash
    points at the removed row's hash. Editing a row breaks both its own
    hash and every later prev_hash."""
    h = hashlib.sha256()
    h.update((prev_hash or "").encode("utf-8"))
    h.update(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return h.hexdigest()


def fingerprint(content: bytes | str) -> str:
    """Deterministic short fingerprint for context files / prompts."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()[:16]


def record_boot_fingerprint(name: str, value: str) -> None:
    """Capture the at-boot fingerprint of a context-affecting input."""
    with _LOCK:
        _BOOT_FINGERPRINTS[name] = value


def detect_context_drift() -> list[dict[str, str]]:
    """Re-fingerprint every registered context input and return any that
    no longer match the boot value. Empty list = no drift."""
    drifted: list[dict[str, str]] = []
    for name, expected in list(_BOOT_FINGERPRINTS.items()):
        current = _refingerprint(name)
        if current is not None and current != expected:
            drifted.append({"name": name, "boot": expected, "current": current})
    return drifted


def _refingerprint(name: str) -> str | None:
    """Read the current value of a registered input and re-hash it.

    Hooks: callers register specific re-readers via `register_refingerprint`.
    Falls back to None if no reader is registered (read-once inputs).
    """
    reader = _REFINGERPRINTERS.get(name)
    if reader is None:
        return None
    try:
        return reader()
    except Exception:
        return None


_REFINGERPRINTERS: dict[str, Any] = {}


def register_refingerprint(name: str, reader: Any) -> None:
    """Register a callable returning the current fingerprint for `name`."""
    _REFINGERPRINTERS[name] = reader


def emit(
    *,
    actor: str,
    kind: str,
    summary: str,
    details: dict[str, Any] | None = None,
    sink: Any | None = None,
) -> AuditEvent:
    """Append a hash-chained audit event.

    `sink` is any object exposing `.append(event_json: str)`. If None, the
    log goes to the path in `IAM_JIT_AUDIT_LOG` (newline-delimited JSON,
    mode 0o600 with O_APPEND). Production deployments should point this at
    S3 with object-lock or CloudWatch Logs with deny-on-delete.

    Concurrency: the in-process portion (seq + hash assignment) is
    serialized by `_LOCK`. The disk write uses `O_APPEND`, which is
    atomic for the small line-sized payloads we emit. Multiple
    processes writing the same file is safe — POSIX guarantees concurrent
    O_APPEND writes don't tear lines — but they may interleave seq
    numbers depending on which process held the in-memory lock first.
    For multi-process deployments, write each process to its own file
    and concatenate at read time, or use an atomic external store.
    """
    global _LAST_HASH, _NEXT_SEQ
    with _LOCK:
        seq = _NEXT_SEQ
        prev = _LAST_HASH
        payload = {
            "seq": seq,
            "timestamp": time.time(),
            "actor": actor,
            "kind": kind,
            "summary": summary,
            "details": details or {},
        }
        h = _hash_event(prev, payload)
        event = AuditEvent(
            timestamp=payload["timestamp"],
            actor=actor,
            kind=kind,
            summary=summary,
            seq=seq,
            details=payload["details"],
            prev_hash=prev,
            hash=h,
        )
        _LAST_HASH = h
        _NEXT_SEQ += 1

    line = event.to_json() + "\n"
    if sink is not None:
        sink.append(line)
    else:
        path = os.environ.get("IAM_JIT_AUDIT_LOG")
        if path:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.write(fd, line.encode("utf-8"))
                finally:
                    os.close(fd)
            except OSError:
                pass
    return event


def checkpoint() -> Checkpoint | None:
    """Return the current chain head as a Checkpoint, or None if empty.

    External callers should persist the returned (seq, hash) into a
    separate durable system. Used for tail-truncation detection — see
    Checkpoint docstring."""
    with _LOCK:
        if _LAST_HASH is None:
            return None
        return Checkpoint(
            seq=_NEXT_SEQ - 1,
            hash=_LAST_HASH,
            timestamp=time.time(),
        )


def verify_chain(
    events: list[dict[str, Any]],
    *,
    expected_checkpoint: Checkpoint | None = None,
) -> tuple[bool, int | None, str | None]:
    """Re-hash a sequence of events to confirm integrity.

    Checks (in order, returning at the first failure):
      1. Each row's hash matches re-computation from prev_hash + payload
         (catches in-place edits)
      2. Each row's prev_hash matches the previous row's hash (catches
         reordering)
      3. Sequence numbers are monotonic and start at 0 with no gaps
         (catches deletion of any row)
      4. If `expected_checkpoint` is provided, the row at that seq has
         the matching hash (catches truncation of the tail)

    Returns (ok, first_bad_index, reason). When ok=True, both index and
    reason are None.
    """
    prev: str | None = None
    expected_seq = 0
    seen_seqs: set[int] = set()
    for i, raw in enumerate(events):
        seq = raw.get("seq")
        if not isinstance(seq, int):
            return False, i, "missing seq"
        if seq in seen_seqs:
            return False, i, f"duplicate seq {seq}"
        if seq != expected_seq:
            return False, i, (
                f"seq gap: expected {expected_seq}, got {seq} — "
                "a row may have been deleted or inserted"
            )
        seen_seqs.add(seq)
        expected_seq += 1

        payload = {
            "seq": seq,
            "timestamp": raw["timestamp"],
            "actor": raw["actor"],
            "kind": raw["kind"],
            "summary": raw["summary"],
            "details": raw.get("details", {}),
        }
        expected_hash = _hash_event(prev, payload)
        if expected_hash != raw.get("hash"):
            return False, i, "hash mismatch — row was edited"
        if raw.get("prev_hash") != prev:
            return False, i, "prev_hash mismatch — rows reordered or one deleted"
        prev = raw["hash"]

    if expected_checkpoint is not None:
        if expected_checkpoint.seq >= len(events):
            return False, None, (
                f"tail truncation: external checkpoint anchors seq "
                f"{expected_checkpoint.seq} but log only has {len(events)} rows"
            )
        anchor = events[expected_checkpoint.seq]
        if anchor.get("hash") != expected_checkpoint.hash:
            return False, expected_checkpoint.seq, (
                "checkpoint hash mismatch — rows at or before the checkpoint "
                "have been altered after the checkpoint was issued"
            )
    return True, None, None


def reset_for_tests() -> None:
    """Clear in-memory state. Test-only."""
    global _LAST_HASH, _NEXT_SEQ
    with _LOCK:
        _LAST_HASH = None
        _NEXT_SEQ = 0
        _BOOT_FINGERPRINTS.clear()
        _REFINGERPRINTERS.clear()
