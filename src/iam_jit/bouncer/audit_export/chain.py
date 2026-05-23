"""Tamper-evident hash-chain for the audit-export JSONL stream — #427 / §A66.

Closes the LAUNCH-BLOCKER §A66 gap that until this slice landed the
bouncer audit-export firehose had NO hash-chain. Per-decision OCSF
events were emitted independently; an attacker (or a buggy log
processor) could quietly delete / re-order / edit rows and the only
integrity check ``verify_integrity()`` (rotation.py:337) shipped was
gzip validity + JSONL syntax. Forensics + compliance require
``each-row-attests-to-the-prior-row`` semantics so tampering is
detectable from the file alone.

Per ``[[v1-scope-bar]]`` this slice REUSES the existing hash
primitives that already ship in ``src/iam_jit/audit.py:88-98``
(``_hash_event`` + ``verify_chain``); the bouncer audit-export
firehose just needed the writer-side wiring + a verify entry point
that walks the on-disk JSONL + rotated gzip archives.

Per ``[[creates-never-mutates]]`` the chain is ADDITIVE — the
existing OCSF event shape is preserved verbatim. Three new fields
land in ``unmapped.iam_jit.audit_chain.*``:

  * ``seq``      — monotonic; gaps reveal deletion
  * ``prev_hash``— previous row's hash (SHA-256 hex) or ``null``
                   on the genesis row
  * ``hash``     — this row's hash; incorporates ``prev_hash`` +
                   the row's canonical-JSON payload

Per ``[[ibounce-honest-positioning]]`` ``verify_jsonl()`` surfaces
EVERY inconsistency it finds — never silently passes a tampered
file. The CLI ``iam-jit audit verify`` calls this module + reports
each finding with line numbers + canonical reason strings so the
operator (or a SOC analyst) can pinpoint the row that broke trust.

Per ``[[deliberate-feature-completion]]`` the chain ships with:
  - writer-side stamping (``stamp_event``)
  - persistent state across restarts (``load_state``/``save_state``)
  - verify entry point for JSONL + rotated archives (``verify_jsonl``)
  - manifest-checkpoint composition (``manifest.py`` consumes the
    ``ChainState`` head + emits signed checkpoints)
  - CLI wiring (``iam-jit audit verify --since DURATION``)
  - tests covering tamper detection + clean-chain + manifest emit

The chain state lives at ``<log_dir>/audit-chain-state.json``
(0o600). It records ``next_seq`` + ``last_hash`` so a process
restart picks up where the previous one left off. If the state
file is missing or corrupt the chain restarts at seq 0; the next
``verify_jsonl()`` run surfaces the discontinuity so the operator
sees it (we don't silently swallow restart-without-state).
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import pathlib
import threading
import time
from typing import Any, Iterable, Iterator

# Reuse the SAME hash function the core iam-jit audit log uses
# (audit.py:88-98). Per [[v1-scope-bar]] don't fork the algorithm.
from ...audit import _hash_event

logger = logging.getLogger(__name__)

# Field names inside the OCSF event's ``unmapped.iam_jit.audit_chain``
# block. Kept as constants so verify_jsonl + tests reference the same
# strings (typo-detect at import time).
CHAIN_FIELD = "audit_chain"
CHAIN_SEQ_FIELD = "seq"
CHAIN_PREV_HASH_FIELD = "prev_hash"
CHAIN_HASH_FIELD = "hash"

# Where the persistent chain-state file lands inside the audit log
# directory. JSON for trivial readability + a single atomic write
# per event-batch. 0o600 so non-owner processes can't manipulate it.
CHAIN_STATE_FILENAME = "audit-chain-state.json"

# Version stamp on the state file. Bump only when the on-disk shape
# changes in a way an older verifier can't read.
CHAIN_STATE_SCHEMA_VERSION = 1


@dataclasses.dataclass
class ChainState:
    """In-memory + on-disk state for one bouncer's audit chain.

    The writer thread owns the only live ``ChainState`` instance.
    ``stamp_event`` mutates ``next_seq`` + ``last_hash`` under the
    writer's stats lock; ``save_state`` persists periodically (after
    every N events) so a crash loses at most that many seq numbers
    of "where the chain was" — which is recoverable from the on-disk
    JSONL itself (the chain is self-describing).

    Per ``[[ibounce-honest-positioning]]`` ``state_file_missing``
    flag lights up when we initialise from scratch + no prior state
    existed; the next ``verify_jsonl()`` surfaces this so the
    operator sees "your bouncer restarted without prior chain state
    — the chain head re-anchored at seq 0" rather than silently
    accepting the discontinuity.
    """

    next_seq: int = 0
    """Sequence number to assign to the NEXT event. 0 = genesis."""

    last_hash: str | None = None
    """Hash of the most recent stamped event, or None on genesis."""

    log_dir: str | None = None
    """Directory hosting audit.jsonl + chain-state.json. None when
    the chain is unwired (no audit log path configured)."""

    state_file_missing: bool = False
    """True when load_state ran but found no on-disk state. Used by
    callers to emit a one-time admin-action so the operator sees
    the chain (re)started fresh."""

    save_every_n_events: int = 50
    """Persist state to disk every N stamped events. Smaller = less
    work to re-derive from JSONL on crash; larger = fewer fsync ops
    in steady state. 50 matches the rotate-aggressively mode's
    expected "events between checks" cadence."""

    _events_since_save: int = 0
    """Internal counter; incremented on each stamp, reset on save."""

    _save_lock: threading.Lock = dataclasses.field(
        default_factory=threading.Lock, repr=False,
    )
    """Serialises the file write so concurrent stampers (shouldn't
    happen with the writer's single-worker shape, but defence-in-
    depth) don't tear the JSON payload."""


def stamp_event(event: dict[str, Any], state: ChainState) -> dict[str, Any]:
    """Stamp ``event`` with chain fields + update ``state``.

    Mutates ``event`` in place + returns the same dict for chaining.
    The stamp lives at ``event["unmapped"]["iam_jit"]["audit_chain"]``
    so it never collides with OCSF top-level fields.

    Per ``[[creates-never-mutates]]`` the original event shape is
    preserved — the chain block is ADDITIVE. Downstream consumers
    that don't speak the chain still see the same OCSF event they
    always did.

    Hash computation: the canonical-JSON payload covers
    ``(seq, prev_hash, event_minus_chain_block)`` so any field change
    invalidates the hash. We exclude the chain block from its own
    hash input — otherwise the hash would chase its own tail.
    """
    unmapped = event.setdefault("unmapped", {})
    iam_jit = unmapped.setdefault("iam_jit", {}) if isinstance(
        unmapped, dict
    ) else None
    if iam_jit is None:
        # Defensive: event has a non-dict `unmapped`. Replace with a
        # dict so the chain block can land — the OCSF emitters in
        # event.py always produce a dict but third-party callers
        # (rule engine alerts, test fixtures) may not.
        event["unmapped"] = {"iam_jit": {}}
        iam_jit = event["unmapped"]["iam_jit"]
    # Build payload-for-hashing: everything in `event` EXCEPT the
    # chain block we're about to assign. Serialise via JSON
    # canonicalisation so the hash is stable across Python versions.
    seq = state.next_seq
    prev_hash = state.last_hash
    # Snapshot the event sans-chain. We pop our own chain field if
    # something else stamped first (idempotency safety).
    iam_jit.pop(CHAIN_FIELD, None)
    payload_for_hash = {
        "seq": seq,
        "prev_hash": prev_hash,
        "event": event,
    }
    h = _hash_event(prev_hash, payload_for_hash)
    iam_jit[CHAIN_FIELD] = {
        CHAIN_SEQ_FIELD: seq,
        CHAIN_PREV_HASH_FIELD: prev_hash,
        CHAIN_HASH_FIELD: h,
    }
    state.next_seq = seq + 1
    state.last_hash = h
    state._events_since_save += 1
    if state._events_since_save >= state.save_every_n_events:
        try:
            save_state(state)
            state._events_since_save = 0
        except OSError as e:
            # Fail-soft: state file write failure does NOT stop the
            # chain in memory. The next save attempt may succeed; if
            # the process dies, verify_jsonl re-derives the chain
            # from the on-disk JSONL itself.
            logger.warning("audit-chain state save failed: %s", e)
    return event


def state_path(log_dir: str | os.PathLike) -> pathlib.Path:
    """Return the on-disk state file path for ``log_dir``."""
    return pathlib.Path(log_dir) / CHAIN_STATE_FILENAME


def load_state(
    log_dir: str | os.PathLike,
    *,
    save_every_n_events: int = 50,
) -> ChainState:
    """Load the on-disk chain state for ``log_dir``.

    Returns a fresh ``ChainState`` (seq 0, hash None) if the state
    file is missing OR corrupt. In the corrupt case the
    ``state_file_missing`` flag flips True so the caller can emit
    a one-time admin-action signalling the chain restarted.

    Per ``[[ibounce-honest-positioning]]`` we never silently mask
    a corrupt state file — surface the restart through the visible
    flag, leave the corrupt file alone (operator forensics may
    want it). The next save_state overwrites it cleanly.
    """
    p = state_path(log_dir)
    state = ChainState(
        log_dir=str(log_dir),
        save_every_n_events=save_every_n_events,
    )
    if not p.is_file():
        state.state_file_missing = True
        return state
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning(
            "audit-chain state file corrupt at %s: %s — restarting chain "
            "at seq 0; the discontinuity will surface via verify_jsonl",
            p, e,
        )
        state.state_file_missing = True
        return state
    if not isinstance(raw, dict):
        state.state_file_missing = True
        return state
    state.next_seq = int(raw.get("next_seq", 0))
    last = raw.get("last_hash")
    state.last_hash = last if isinstance(last, str) else None
    return state


def save_state(state: ChainState) -> None:
    """Persist ``state`` to its log_dir's state file (atomic write).

    Writes to ``audit-chain-state.json.tmp`` then renames over the
    target so a crash mid-write never leaves a partial JSON.
    No-ops when ``log_dir`` is None (chain isn't wired to a dir).
    Permissions 0o600 — the file holds chain head metadata that
    leaks audit volume to non-owner processes.
    """
    if state.log_dir is None:
        return
    payload = {
        "schema_version": CHAIN_STATE_SCHEMA_VERSION,
        "next_seq": state.next_seq,
        "last_hash": state.last_hash,
        "saved_at_unix": int(time.time()),
    }
    target = state_path(state.log_dir)
    tmp = target.with_suffix(target.suffix + ".tmp")
    with state._save_lock:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            str(tmp),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(fd, (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(str(tmp), str(target))


def reset_for_tests(state: ChainState) -> None:
    """Reset state in-memory + remove the on-disk state file. Test-only."""
    state.next_seq = 0
    state.last_hash = None
    state.state_file_missing = False
    state._events_since_save = 0
    if state.log_dir is not None:
        try:
            state_path(state.log_dir).unlink(missing_ok=True)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ChainInconsistency:
    """One finding from verify_jsonl. Lossless: every field a SOC
    analyst would want to triage the row lives here."""

    source: str
    """Filesystem path of the file containing the bad row."""

    line_number: int
    """1-indexed line number inside ``source``. 0 when the finding
    is file-level (header missing, etc.)."""

    seq: int | None
    """The chain seq the row claimed (or None when unreadable)."""

    reason: str
    """Short human-readable failure reason. Stable strings so SIEM
    rules can pattern-match (see KNOWN_REASONS below)."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "line_number": self.line_number,
            "seq": self.seq,
            "reason": self.reason,
        }


@dataclasses.dataclass(frozen=True)
class VerifyResult:
    """Aggregate result of verify_jsonl. Empty ``inconsistencies``
    means the chain verified clean across the inspected range."""

    files_checked: int
    events_checked: int
    head_seq: int | None
    head_hash: str | None
    inconsistencies: list[ChainInconsistency]
    state_file_missing_at_start: bool

    @property
    def ok(self) -> bool:
        return not self.inconsistencies

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_checked": self.files_checked,
            "events_checked": self.events_checked,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "ok": self.ok,
            "state_file_missing_at_start": self.state_file_missing_at_start,
            "inconsistencies": [i.to_dict() for i in self.inconsistencies],
        }


# Stable reason strings for SIEM pattern matching + tests.
REASON_HASH_MISMATCH = "hash mismatch — row was edited or chain payload changed"
REASON_PREV_HASH_MISMATCH = "prev_hash mismatch — rows reordered or one deleted"
REASON_SEQ_GAP = "seq gap — row(s) deleted or inserted"
REASON_MISSING_CHAIN_BLOCK = "missing audit_chain block — event was emitted before chain wiring or block was stripped"
REASON_BAD_JSON = "unparseable JSON line"
REASON_BAD_TYPES = "audit_chain block has wrong types"


def _iter_event_sources(
    log_dir: str | os.PathLike,
    *,
    since_unix: float | None = None,
) -> Iterator[tuple[pathlib.Path, Iterable[tuple[int, str]]]]:
    """Yield (path, line-iterator) pairs across the rotated JSONL
    archives + the active audit.jsonl, in chronological order.

    Each line-iterator yields ``(line_number, line)`` with
    1-indexed line numbers + the trailing newline stripped.
    Files older than ``since_unix`` (by mtime) are skipped — a
    cheap filter for the CLI's ``--since`` semantics.
    """
    import gzip
    d = pathlib.Path(log_dir)
    if not d.is_dir():
        return
    # Collect rotated archives (audit-YYYY-MM-DD-HHMMSS.jsonl.gz)
    # sorted by name (which == chronological for the timestamp
    # pattern) so the chain reads in the order events were written.
    archives = sorted(
        c for c in d.iterdir()
        if c.name.startswith("audit-") and c.name.endswith(".jsonl.gz")
    )
    active = d / "audit.jsonl"
    files: list[pathlib.Path] = list(archives)
    if active.is_file():
        files.append(active)
    for path in files:
        try:
            if since_unix is not None and path.stat().st_mtime < since_unix:
                continue
        except OSError:
            continue
        if path.name.endswith(".gz"):
            def _gz_iter(p: pathlib.Path = path) -> Iterator[tuple[int, str]]:
                with gzip.open(p, "rt", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        yield i, line.rstrip("\n")
            yield path, _gz_iter()
        else:
            def _plain_iter(p: pathlib.Path = path) -> Iterator[tuple[int, str]]:
                with open(p, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        yield i, line.rstrip("\n")
            yield path, _plain_iter()


def _extract_chain_block(event: dict[str, Any]) -> dict[str, Any] | None:
    """Pull the chain block from an OCSF event. Returns None when
    the event lacks the block (which is itself a finding)."""
    try:
        block = event["unmapped"]["iam_jit"][CHAIN_FIELD]
    except (KeyError, TypeError):
        return None
    if not isinstance(block, dict):
        return None
    return block


def verify_jsonl(
    log_dir: str | os.PathLike,
    *,
    since_unix: float | None = None,
    state_file_missing: bool | None = None,
) -> VerifyResult:
    """Walk the JSONL audit log + rotated archives, re-hashing each
    event + checking the chain.

    Returns a ``VerifyResult`` with every finding. Per
    ``[[ibounce-honest-positioning]]`` even ambiguous findings
    (missing chain block on what looks like a pre-wiring event)
    are surfaced — the caller's UI can categorise them, but the
    verifier never silently passes them.

    ``state_file_missing`` (if provided) is recorded in the result
    so the CLI can show the operator the chain has been
    re-anchored since the last full verification.
    """
    files_checked = 0
    events_checked = 0
    head_seq: int | None = None
    head_hash: str | None = None
    findings: list[ChainInconsistency] = []
    prev_hash: str | None = None
    expected_seq = 0
    for path, line_iter in _iter_event_sources(
        log_dir, since_unix=since_unix,
    ):
        files_checked += 1
        for line_no, raw in line_iter:
            if not raw.strip():
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                findings.append(ChainInconsistency(
                    source=str(path),
                    line_number=line_no,
                    seq=None,
                    reason=REASON_BAD_JSON,
                ))
                continue
            block = _extract_chain_block(event)
            if block is None:
                findings.append(ChainInconsistency(
                    source=str(path),
                    line_number=line_no,
                    seq=None,
                    reason=REASON_MISSING_CHAIN_BLOCK,
                ))
                continue
            seq = block.get(CHAIN_SEQ_FIELD)
            prev = block.get(CHAIN_PREV_HASH_FIELD)
            row_hash = block.get(CHAIN_HASH_FIELD)
            if not isinstance(seq, int) or not isinstance(row_hash, str) or (
                prev is not None and not isinstance(prev, str)
            ):
                findings.append(ChainInconsistency(
                    source=str(path),
                    line_number=line_no,
                    seq=seq if isinstance(seq, int) else None,
                    reason=REASON_BAD_TYPES,
                ))
                continue
            events_checked += 1
            if seq != expected_seq:
                findings.append(ChainInconsistency(
                    source=str(path),
                    line_number=line_no,
                    seq=seq,
                    reason=REASON_SEQ_GAP,
                ))
                # Re-anchor the expected_seq to the row we just saw
                # so we don't cascade a single deletion into N gaps;
                # the deletion is recorded as one finding, subsequent
                # rows are validated against the new anchor.
                expected_seq = seq
            if prev != prev_hash:
                findings.append(ChainInconsistency(
                    source=str(path),
                    line_number=line_no,
                    seq=seq,
                    reason=REASON_PREV_HASH_MISMATCH,
                ))
            # Recompute the hash. Strip the chain block, recompute
            # the payload we'd have hashed at stamp time.
            event_for_hash = json.loads(raw)
            try:
                event_for_hash["unmapped"]["iam_jit"].pop(CHAIN_FIELD, None)
            except (KeyError, TypeError):
                pass
            payload = {
                "seq": seq,
                "prev_hash": prev,
                "event": event_for_hash,
            }
            recomputed = _hash_event(prev, payload)
            if recomputed != row_hash:
                findings.append(ChainInconsistency(
                    source=str(path),
                    line_number=line_no,
                    seq=seq,
                    reason=REASON_HASH_MISMATCH,
                ))
            prev_hash = row_hash
            head_seq = seq
            head_hash = row_hash
            expected_seq = seq + 1
    return VerifyResult(
        files_checked=files_checked,
        events_checked=events_checked,
        head_seq=head_seq,
        head_hash=head_hash,
        inconsistencies=findings,
        state_file_missing_at_start=bool(state_file_missing),
    )


__all__ = [
    "CHAIN_FIELD",
    "CHAIN_HASH_FIELD",
    "CHAIN_PREV_HASH_FIELD",
    "CHAIN_SEQ_FIELD",
    "CHAIN_STATE_FILENAME",
    "CHAIN_STATE_SCHEMA_VERSION",
    "ChainInconsistency",
    "ChainState",
    "REASON_BAD_JSON",
    "REASON_BAD_TYPES",
    "REASON_HASH_MISMATCH",
    "REASON_MISSING_CHAIN_BLOCK",
    "REASON_PREV_HASH_MISMATCH",
    "REASON_SEQ_GAP",
    "VerifyResult",
    "load_state",
    "reset_for_tests",
    "save_state",
    "stamp_event",
    "state_path",
    "verify_jsonl",
]
