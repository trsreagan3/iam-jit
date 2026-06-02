"""#724 — the shared cross-bouncer SIGNAL STORE (same-host).

This is the wire-format library + producer/consumer for cross-bouncer
chaining. Any Bounce-suite bouncer on the same host can WRITE a signal
(producer) and any can READ active signals for a session (consumer).

Store shape
-----------
A single SQLite file in a shared directory (default
``~/.iam-jit/chaining/signals.db``; overridable via
``IAM_JIT_CHAINING_SIGNAL_DB``). One append-only table:

    signals(
      id            INTEGER PRIMARY KEY,
      session_id    TEXT NOT NULL,   -- canonical X-Agent-Session-Id
      kind          TEXT NOT NULL,   -- e.g. "pii_observed"
      source        TEXT NOT NULL,   -- producing bouncer: "dbounce"
      created_at    REAL NOT NULL,   -- unix epoch seconds (producer clock)
      expires_at    REAL NOT NULL,   -- created_at + ttl_seconds
      detail        TEXT             -- optional JSON blob, redacted by producer
    )

Append-only: signals are never updated. Expiry is a READ-TIME filter
(``expires_at > now``) plus a best-effort vacuum the producer runs on
write. This keeps the format trivially portable to a Go writer — a Go
bouncer needs only the same ``CREATE TABLE`` + an INSERT.

TTL / expiry
------------
Every signal carries an absolute ``expires_at``. Consumers ignore
expired signals at read time, so a stale signal can never keep
tightening forever. The producer also deletes rows whose
``expires_at`` is well past on each write so the file stays small.

Wire-format versioning
-----------------------
``SIGNAL_STORE_VERSION`` is stamped in a ``meta`` table on creation so
a future format change is detectable; the Go porting contract pins to
this version (see ``docs/BOUNCER-CHAINING.md``).

Independence / fail-soft
------------------------
Every method that touches disk raises :class:`SignalStoreError` on
failure rather than crashing. The consumer-side hook treats that as
"no active signals" (fail soft) so a broken/unavailable store can
never stop a bouncer or flip a decision. The store NEVER fails such
that a missing signal would LOOSEN a decision — the worst case is that
a real tightening signal is missed, which degrades to standalone
behaviour (the bouncer's own policy still applies).

Honest scope: same-host only. Producers/consumers share a filesystem.
We do not claim cross-host or real-time-bus semantics.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import pathlib
import platform
import sqlite3
import time
from typing import Any

logger = logging.getLogger(__name__)

SIGNAL_STORE_VERSION = 1

# Canonical signal kinds. The Go bouncers MUST use these exact strings
# (see the porting contract) so a dbounce-written "pii_observed" is
# matched by an ibounce chain rule. New kinds are additive — an unknown
# kind is simply not matched by any rule (forward-compatible).
SIGNAL_KIND_PII_OBSERVED = "pii_observed"
SIGNAL_KIND_SECRET_OBSERVED = "secret_observed"

# Default shared location. Same-host: every bouncer process resolves the
# same path so the producer's write is the consumer's read.
_DEFAULT_DIR = "~/.iam-jit/chaining"
_DEFAULT_DB_NAME = "signals.db"

# Bound on how far past expiry we keep rows before the producer GCs
# them. A small grace window so a consumer with a slightly-behind clock
# still sees a just-expired signal it was mid-read on; the consumer's
# own ``expires_at > now`` filter is the authoritative expiry gate.
_GC_GRACE_SECONDS = 60.0

# Hard cap on detail blob size so a misbehaving producer can't bloat the
# shared file. Detail is advisory metadata only (never load-bearing for
# the tighten decision).
_MAX_DETAIL_BYTES = 4096


class SignalStoreError(RuntimeError):
    """Raised when the shared signal store can't be opened/read/written.

    Callers on the CONSUMER hot path MUST treat this as "no active
    signals" (fail soft) — never let it stop the bouncer."""


@dataclasses.dataclass(frozen=True)
class CrossBouncerSignal:
    """One cross-bouncer signal. This is the wire record."""

    session_id: str
    kind: str
    source: str
    created_at: float
    expires_at: float
    detail: dict[str, Any] | None = None

    def is_active(self, *, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        return self.expires_at > now

    def to_row(self) -> dict[str, Any]:
        """Serialise to the on-disk column dict (wire format)."""
        detail_json: str | None = None
        if self.detail is not None:
            try:
                blob = json.dumps(self.detail, sort_keys=True, default=str)
            except (TypeError, ValueError):
                blob = json.dumps({"_unserialisable": True})
            if len(blob.encode("utf-8")) > _MAX_DETAIL_BYTES:
                blob = json.dumps({"_truncated": True})
            detail_json = blob
        return {
            "session_id": self.session_id,
            "kind": self.kind,
            "source": self.source,
            "created_at": float(self.created_at),
            "expires_at": float(self.expires_at),
            "detail": detail_json,
        }

    @classmethod
    def from_row(cls, row: Any) -> "CrossBouncerSignal":
        """Parse one sqlite row (tuple or Row) back into a signal."""
        detail_raw = row["detail"]
        detail: dict[str, Any] | None = None
        if detail_raw:
            try:
                parsed = json.loads(detail_raw)
                if isinstance(parsed, dict):
                    detail = parsed
            except (TypeError, ValueError, json.JSONDecodeError):
                detail = None
        return cls(
            session_id=str(row["session_id"]),
            kind=str(row["kind"]),
            source=str(row["source"]),
            created_at=float(row["created_at"]),
            expires_at=float(row["expires_at"]),
            detail=detail,
        )


def default_signal_db_path() -> pathlib.Path:
    """Resolve the shared signal-store path.

    Precedence: ``IAM_JIT_CHAINING_SIGNAL_DB`` env override (used by
    tests + operators who want a non-default shared dir), else
    ``~/.iam-jit/chaining/signals.db``."""
    override = os.environ.get("IAM_JIT_CHAINING_SIGNAL_DB")
    if override:
        return pathlib.Path(override).expanduser()
    return pathlib.Path(_DEFAULT_DIR).expanduser() / _DEFAULT_DB_NAME


class SignalStore:
    """Shared same-host signal store. Thread/process-safe via SQLite's
    own locking (WAL). A fresh connection is opened per operation so a
    Go writer in another process never contends a long-lived handle.

    Producers call :meth:`write_signal`. Consumers call
    :meth:`active_signals_for_session`.
    """

    def __init__(self, db_path: pathlib.Path | str | None = None) -> None:
        self._db_path = (
            pathlib.Path(db_path).expanduser()
            if db_path is not None
            else default_signal_db_path()
        )

    @property
    def db_path(self) -> pathlib.Path:
        return self._db_path

    # -- connection -------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        try:
            parent = self._db_path.parent
            parent.mkdir(parents=True, exist_ok=True)
            # The signal DB exposes session_ids + signal kinds (an
            # activity side-channel) and is the forged-signal DoS
            # surface. Lock it down to the same-host owner: 0700 dir /
            # 0600 file — mirrors dynamic_denies/store.py. We tighten an
            # existing-but-looser dir too (chmod even when not freshly
            # created); honor a tighter operator choice by only ever
            # narrowing. All perm ops are best-effort + fail-soft so a
            # chmod refusal never breaks the store.
            self._tighten_perms(parent, 0o700)
            db_existed = self._db_path.exists()
            conn = sqlite3.connect(
                str(self._db_path),
                timeout=2.0,
                isolation_level=None,  # autocommit; each write is atomic
            )
            conn.row_factory = sqlite3.Row
            # WAL so a Go reader/writer in a separate process never blocks
            # the Python proxy hot-path read for long.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=2000")
            self._ensure_schema(conn)
            # chmod the DB file (and WAL/SHM siblings, which WAL mode
            # creates lazily) AFTER the connection + first write so the
            # sibling files exist. Best-effort — a missing sibling or a
            # chmod error must not break the store.
            if not db_existed:
                self._tighten_perms(self._db_path, 0o600)
            for suffix in ("-wal", "-shm"):
                self._tighten_perms(
                    self._db_path.with_name(self._db_path.name + suffix),
                    0o600,
                )
            return conn
        except (sqlite3.Error, OSError) as e:
            raise SignalStoreError(
                f"cannot open cross-bouncer signal store at {self._db_path}: {e}"
            ) from e

    @staticmethod
    def _tighten_perms(path: pathlib.Path, mode: int) -> None:
        """Best-effort, fail-soft chmod to ``mode``. No-op on Windows,
        on a missing path, or if chmod is refused (e.g. operator
        pre-created with specific perms)."""
        if platform.system() == "Windows":
            return
        try:
            os.chmod(path, mode)
        except OSError:  # noqa: SD-1 perms are defense-in-depth; a chmod refusal (operator pre-set tighter, or a not-yet-created WAL/SHM sibling) must never break the store
            pass

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signals (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                kind        TEXT NOT NULL,
                source      TEXT NOT NULL,
                created_at  REAL NOT NULL,
                expires_at  REAL NOT NULL,
                detail      TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_signals_session "
            "ON signals(session_id, expires_at)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
        )
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('version', ?)",
            (str(SIGNAL_STORE_VERSION),),
        )

    # -- producer ---------------------------------------------------

    def write_signal(
        self, signal: CrossBouncerSignal, *, now: float | None = None,
    ) -> None:
        """Append a signal (producer side). Also GCs well-expired rows.

        ``now`` lets a caller (and tests) pin the GC clock to the same
        clock used for ``expires_at`` so a simulated-time write doesn't
        immediately GC itself; production callers omit it and the GC
        uses wall-clock.

        Raises :class:`SignalStoreError` on disk failure. Producers
        (e.g. dbounce after detecting PII in a result) call this; a
        write failure is logged by the producer and the producing
        bouncer continues standalone — chaining is best-effort."""
        if not signal.session_id:
            # No session = nothing to key on; silently skip (a non-MCP
            # raw call with no X-Agent-Session-Id can't participate in
            # session-scoped chaining, and that's the honest answer).
            return
        row = signal.to_row()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO signals "
                "(session_id, kind, source, created_at, expires_at, detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    row["session_id"], row["kind"], row["source"],
                    row["created_at"], row["expires_at"], row["detail"],
                ),
            )
            # Best-effort GC of well-expired rows so the shared file
            # stays small. Read-time filtering is authoritative; this is
            # housekeeping only. Uses the caller's clock when supplied so
            # a simulated-time write doesn't GC itself.
            gc_now = now if now is not None else time.time()
            conn.execute(
                "DELETE FROM signals WHERE expires_at < ?",
                (gc_now - _GC_GRACE_SECONDS,),
            )
        except sqlite3.Error as e:
            raise SignalStoreError(f"signal write failed: {e}") from e
        finally:
            conn.close()

    def emit_signal(
        self,
        *,
        session_id: str,
        kind: str,
        source: str,
        ttl_seconds: float,
        detail: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> CrossBouncerSignal:
        """Convenience producer: build + write a signal in one call.

        Returns the signal that was written (handy for tests + audit).
        """
        now = now if now is not None else time.time()
        signal = CrossBouncerSignal(
            session_id=session_id,
            kind=kind,
            source=source,
            created_at=now,
            expires_at=now + max(0.0, float(ttl_seconds)),
            detail=detail,
        )
        self.write_signal(signal, now=now)
        return signal

    # -- consumer ---------------------------------------------------

    def active_signals_for_session(
        self,
        session_id: str,
        *,
        kinds: tuple[str, ...] | None = None,
        now: float | None = None,
    ) -> list[CrossBouncerSignal]:
        """Return non-expired signals for ``session_id`` (consumer side).

        ``kinds`` optionally restricts to specific signal kinds. Raises
        :class:`SignalStoreError` on disk failure — the CONSUMER HOT
        PATH MUST catch this and treat it as "no active signals"
        (fail soft). Returns ``[]`` for an empty/absent session."""
        if not session_id:
            return []
        now = now if now is not None else time.time()
        conn = self._connect()
        try:
            if kinds:
                placeholders = ",".join("?" for _ in kinds)
                cur = conn.execute(
                    f"SELECT session_id, kind, source, created_at, "
                    f"expires_at, detail FROM signals "
                    f"WHERE session_id = ? AND expires_at > ? "
                    f"AND kind IN ({placeholders}) "
                    f"ORDER BY created_at ASC",
                    (session_id, now, *kinds),
                )
            else:
                cur = conn.execute(
                    "SELECT session_id, kind, source, created_at, "
                    "expires_at, detail FROM signals "
                    "WHERE session_id = ? AND expires_at > ? "
                    "ORDER BY created_at ASC",
                    (session_id, now),
                )
            return [CrossBouncerSignal.from_row(r) for r in cur.fetchall()]
        except sqlite3.Error as e:
            raise SignalStoreError(f"signal read failed: {e}") from e
        finally:
            conn.close()

    def store_version(self) -> int | None:
        """Return the on-disk wire-format version, or None when the
        ``meta`` row is genuinely ABSENT (a pre-versioning store).

        A read/parse FAILURE raises :class:`SignalStoreError` rather
        than returning None, so a caller can distinguish "no version
        recorded" (None) from "couldn't read the store" (error) — the
        None return is therefore a real positive answer, never a
        swallowed failure."""
        conn = self._connect()
        try:
            cur = conn.execute("SELECT value FROM meta WHERE key='version'")
            row = cur.fetchone()
            if row is None:
                return None
            return int(row["value"])
        except (sqlite3.Error, ValueError) as e:
            raise SignalStoreError(f"store version read failed: {e}") from e
        finally:
            conn.close()


__all__ = [
    "SIGNAL_KIND_PII_OBSERVED",
    "SIGNAL_KIND_SECRET_OBSERVED",
    "SIGNAL_STORE_VERSION",
    "CrossBouncerSignal",
    "SignalStore",
    "SignalStoreError",
    "default_signal_db_path",
]
