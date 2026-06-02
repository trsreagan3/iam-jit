"""#724 / BUILD-3 — cross-bouncer signal-store unit tests.

Covers the shared same-host wire format: producer writes, consumer
reads, TTL/expiry, kind filtering, wire round-trip, and the fail-soft
contract (an unavailable store surfaces SignalStoreError, never a
silent loosen).
"""

from __future__ import annotations

import platform
import stat
import time

import pytest

from iam_jit.bouncer_chaining.signal_store import (
    SIGNAL_KIND_PII_OBSERVED,
    SIGNAL_KIND_SECRET_OBSERVED,
    SIGNAL_STORE_VERSION,
    CrossBouncerSignal,
    SignalStore,
    SignalStoreError,
)


@pytest.fixture
def store(tmp_path):
    return SignalStore(db_path=str(tmp_path / "signals.db"))


def test_write_then_read_same_session(store):
    """A signal one bouncer (dbounce) writes is read back by another
    bouncer (the consumer) for the same session."""
    store.emit_signal(
        session_id="sess-1",
        kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce",
        ttl_seconds=3600,
        detail={"columns": ["email", "ssn"]},
    )
    sigs = store.active_signals_for_session("sess-1")
    assert len(sigs) == 1
    assert sigs[0].kind == SIGNAL_KIND_PII_OBSERVED
    assert sigs[0].source == "dbounce"
    assert sigs[0].detail == {"columns": ["email", "ssn"]}


def test_signal_scoped_to_session(store):
    """A signal for one session is NOT visible to another session."""
    store.emit_signal(
        session_id="sess-1", kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )
    assert store.active_signals_for_session("sess-2") == []
    assert len(store.active_signals_for_session("sess-1")) == 1


def test_expired_signal_not_returned(store):
    """A signal past its TTL is filtered out at read time so a stale
    signal can never keep tightening forever."""
    now = 1000.0
    store.emit_signal(
        session_id="sess-1", kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=10, now=now,
    )
    # Within TTL.
    assert len(store.active_signals_for_session("sess-1", now=now + 5)) == 1
    # Past TTL.
    assert store.active_signals_for_session("sess-1", now=now + 11) == []


def test_kind_filter(store):
    store.emit_signal(
        session_id="s", kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )
    store.emit_signal(
        session_id="s", kind=SIGNAL_KIND_SECRET_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )
    pii_only = store.active_signals_for_session(
        "s", kinds=(SIGNAL_KIND_PII_OBSERVED,),
    )
    assert [s.kind for s in pii_only] == [SIGNAL_KIND_PII_OBSERVED]


def test_wire_format_round_trip():
    """to_row / from_row round-trips losslessly (the Go porting
    contract pins to this same column shape)."""
    sig = CrossBouncerSignal(
        session_id="abc",
        kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce",
        created_at=123.0,
        expires_at=456.0,
        detail={"k": "v", "n": 3},
    )
    row = sig.to_row()
    # Emulate a sqlite Row by indexing on column name.
    class _Row(dict):
        pass
    back = CrossBouncerSignal.from_row(_Row(row))
    assert back.session_id == sig.session_id
    assert back.kind == sig.kind
    assert back.source == sig.source
    assert back.created_at == sig.created_at
    assert back.expires_at == sig.expires_at
    assert back.detail == sig.detail


def test_store_version_stamped(store):
    store.emit_signal(
        session_id="s", kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=60,
    )
    assert store.store_version() == SIGNAL_STORE_VERSION


def test_empty_session_id_is_noop(store):
    """A signal with no session id is silently skipped (a non-MCP raw
    call can't participate in session-scoped chaining)."""
    store.emit_signal(
        session_id="", kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=60,
    )
    assert store.active_signals_for_session("") == []


def test_unavailable_store_raises_not_loosens(tmp_path):
    """If the store path can't be created (parent is a FILE, not a
    dir), the consumer read raises SignalStoreError — it never returns
    a spurious 'allow'. The hot-path hook turns this into a no-op
    (tested in the integration suite); the store itself must surface
    the error loudly."""
    # Make the parent path a regular file so mkdir() fails.
    bad_parent = tmp_path / "not-a-dir"
    bad_parent.write_text("i am a file")
    s = SignalStore(db_path=str(bad_parent / "signals.db"))
    with pytest.raises(SignalStoreError):
        s.active_signals_for_session("sess-1")


def test_gc_drops_well_expired_rows(store):
    """The producer GCs rows well past expiry on write so the shared
    file stays small."""
    now = time.time()
    # An ancient signal (expired > GC grace ago).
    store.emit_signal(
        session_id="old", kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=1, now=now - 10_000,
    )
    # A fresh write triggers GC.
    store.emit_signal(
        session_id="new", kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )
    # The ancient one is gone even when queried at its own (long past)
    # creation window.
    assert store.active_signals_for_session("old", now=now - 9_999) == []


@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="POSIX file-mode bits are not meaningful on Windows",
)
def test_freshly_created_db_is_owner_only(tmp_path):
    """The signal DB must land 0600 (and its parent dir 0700) so other
    local users cannot read the session_id/kind activity side-channel
    or reach the forged-signal DoS surface."""
    db_path = tmp_path / "chaining" / "signals.db"
    s = SignalStore(db_path=str(db_path))
    # A write forces the connection + schema + WAL siblings into being.
    s.emit_signal(
        session_id="sess-1", kind=SIGNAL_KIND_PII_OBSERVED,
        source="dbounce", ttl_seconds=3600,
    )

    file_mode = stat.S_IMODE(db_path.stat().st_mode)
    assert file_mode == 0o600, f"signal DB is {oct(file_mode)}, want 0o600"

    dir_mode = stat.S_IMODE(db_path.parent.stat().st_mode)
    assert dir_mode == 0o700, f"signal dir is {oct(dir_mode)}, want 0o700"

    # WAL/SHM siblings (when present) must also be owner-only — they
    # carry the same session data as the main DB.
    for sibling in (
        db_path.with_name(db_path.name + "-wal"),
        db_path.with_name(db_path.name + "-shm"),
    ):
        if sibling.exists():
            sib_mode = stat.S_IMODE(sibling.stat().st_mode)
            assert sib_mode == 0o600, (
                f"{sibling.name} is {oct(sib_mode)}, want 0o600"
            )
