"""Persistent nonce store for denial receipts — #731 / BUILD-10.

The replay-resistance trust signal (per the build spec): Signet-style
signed-receipt models commonly keep their nonce set IN MEMORY, so a
process restart opens a replay window — every receipt minted before the
restart can be replayed as "fresh" because the in-memory set is empty.
We don't. This store is durable (SQLite in the bouncer state dir) so it
SURVIVES restart: a receipt minted before a restart and replayed after
it is still detected as a replay.

Two operations:

  * ``record_minted(nonce, deny_id, ts)`` — called by the signer when a
    receipt is MINTED. Durably records the nonce as "issued by us".
  * ``check_and_consume(nonce)`` — called by the verifier. Returns a
    :class:`NonceCheck` describing freshness:
      - ``known=False``  → the nonce was never minted by this bouncer.
        Either a forged receipt (but the signature check catches that)
        or a receipt for a deny minted by a DIFFERENT bouncer/keypair.
        The verifier surfaces this as "unrecognised nonce".
      - ``known=True, replay=False`` → first presentation of a genuine
        nonce. The store records the consumption (tombstone) so the
        NEXT presentation of the same nonce is a replay.
      - ``known=True, replay=True`` → the nonce was already consumed —
        a REPLAY. Loud failure.

"crypto-tombstone": when a nonce is consumed at verify time we do not
delete the row; we mark it consumed (a tombstone) so a replay is
distinguishable from an unknown nonce. The tombstone records the
consume count + first/last consume time so an auditor can see HOW MANY
times a receipt was replayed.

LRU bound: the table is capped at ``max_entries`` rows (default 100k).
When the cap is exceeded we evict the oldest-minted rows. Eviction is a
deliberate, bounded operation — per ``[[ibounce-honest-positioning]]``
we never silently lose replay detection without it being a conscious
capacity decision the operator can tune + observe (``evicted`` counter).
A receipt whose nonce was evicted verifies its signature fine but
reports ``known=False`` (treated conservatively as unrecognised, not as
"fresh").

Per ``[[creates-never-mutates]]`` the store is additive bouncer-local
state under the state dir; it never touches the audit JSONL or any AWS
resource.

Per the fail-soft contract: the signer wraps every call to this store
in a try/except so a store error NEVER breaks a deny. This module
raises normally (it's a plain durable store); the SIGNER decides the
calls are non-fatal.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import pathlib
import sqlite3
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_MAX_ENTRIES = 100_000

# Default on-disk location: under the bouncer state dir alongside the
# audit log. The signer/proxy passes an explicit path derived from
# --audit-log-path; this default is the fallback for standalone use.
DEFAULT_NONCE_DB_NAME = "denial-receipt-nonces.sqlite3"


@dataclasses.dataclass(frozen=True)
class NonceCheck:
    """Result of :meth:`NonceStore.check_and_consume`."""

    nonce: str
    known: bool
    """True iff this bouncer minted this nonce (it's in the store)."""

    replay: bool
    """True iff the nonce was ALREADY consumed before this check —
    i.e. a replayed receipt. Only meaningful when ``known`` is True."""

    consume_count: int
    """How many times this nonce has now been consumed INCLUDING this
    check (1 = first/legitimate use; >1 = replay attempts)."""

    minted_ts: str | None = None
    """The ISO timestamp the nonce was minted, when known."""

    def is_fresh(self) -> bool:
        """A genuine, first-time presentation: known + not a replay."""
        return self.known and not self.replay


class _BaseNonceStore:
    def record_minted(self, nonce: str, *, deny_id: str = "", ts: str = "") -> None:
        raise NotImplementedError

    def check_and_consume(self, nonce: str) -> NonceCheck:
        raise NotImplementedError

    def status(self) -> dict[str, Any]:
        raise NotImplementedError


class SqliteNonceStore(_BaseNonceStore):
    """Durable (restart-surviving) SQLite-backed nonce store.

    Thread-safe: a single connection guarded by a lock. SQLite with
    ``check_same_thread=False`` + an explicit lock is the simplest
    correct option for the proxy's mixed sync/async call sites. WAL mode
    keeps reads + writes from blocking each other and survives an
    unclean shutdown.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS denial_receipt_nonces (
        nonce          TEXT PRIMARY KEY,
        deny_id        TEXT NOT NULL DEFAULT '',
        minted_ts      TEXT NOT NULL DEFAULT '',
        minted_at      REAL NOT NULL,
        consume_count  INTEGER NOT NULL DEFAULT 0,
        first_consumed_at REAL,
        last_consumed_at  REAL
    );
    CREATE INDEX IF NOT EXISTS idx_drn_minted_at
        ON denial_receipt_nonces (minted_at);
    """

    def __init__(
        self,
        path: str | os.PathLike,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        self.path = str(path)
        self.max_entries = max(1, int(max_entries))
        self.evicted = 0
        self._lock = threading.Lock()
        p = pathlib.Path(self.path)
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            self.path, check_same_thread=False, isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
        except sqlite3.Error as e:
            # In-memory or odd FS may refuse WAL; not fatal (the store
            # still works in rollback-journal mode) but surface it so an
            # operator debugging durability knows WAL didn't engage.
            logger.warning(
                "denial-receipt nonce store: WAL pragma refused (%s); "
                "falling back to rollback-journal mode", e,
            )
        self._conn.executescript(self._SCHEMA)

    def record_minted(self, nonce: str, *, deny_id: str = "", ts: str = "") -> None:
        now = time.time()
        with self._lock:
            # INSERT OR IGNORE: a nonce is 256 bits of entropy so a
            # genuine collision is astronomically unlikely; IGNORE keeps
            # a re-mint idempotent rather than clobbering consume state.
            self._conn.execute(
                "INSERT OR IGNORE INTO denial_receipt_nonces "
                "(nonce, deny_id, minted_ts, minted_at, consume_count) "
                "VALUES (?, ?, ?, ?, 0)",
                (nonce, deny_id, ts, now),
            )
            self._evict_if_needed_locked()

    def check_and_consume(self, nonce: str) -> NonceCheck:
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT nonce, minted_ts, consume_count "
                "FROM denial_receipt_nonces WHERE nonce = ?",
                (nonce,),
            ).fetchone()
            if row is None:
                # Unknown nonce: never minted by this bouncer (or evicted).
                return NonceCheck(
                    nonce=nonce, known=False, replay=False, consume_count=0,
                )
            prior = int(row["consume_count"])
            new_count = prior + 1
            # Crypto-tombstone: bump the consume count + record the
            # consume window. We never delete the row, so the NEXT
            # presentation sees consume_count>0 → replay.
            if prior == 0:
                self._conn.execute(
                    "UPDATE denial_receipt_nonces "
                    "SET consume_count = ?, first_consumed_at = ?, "
                    "last_consumed_at = ? WHERE nonce = ?",
                    (new_count, now, now, nonce),
                )
            else:
                self._conn.execute(
                    "UPDATE denial_receipt_nonces "
                    "SET consume_count = ?, last_consumed_at = ? WHERE nonce = ?",
                    (new_count, now, nonce),
                )
            return NonceCheck(
                nonce=nonce,
                known=True,
                replay=prior > 0,
                consume_count=new_count,
                minted_ts=row["minted_ts"] or None,
            )

    def _evict_if_needed_locked(self) -> None:
        """LRU-ish eviction by oldest minted_at. Caller holds the lock."""
        count = self._conn.execute(
            "SELECT COUNT(*) AS c FROM denial_receipt_nonces"
        ).fetchone()["c"]
        if count <= self.max_entries:
            return
        to_evict = count - self.max_entries
        self._conn.execute(
            "DELETE FROM denial_receipt_nonces WHERE nonce IN ("
            "  SELECT nonce FROM denial_receipt_nonces "
            "  ORDER BY minted_at ASC LIMIT ?"
            ")",
            (to_evict,),
        )
        self.evicted += to_evict
        logger.info(
            "denial-receipt nonce store evicted %d oldest entries "
            "(cap=%d); receipts for evicted nonces verify signature but "
            "report unrecognised-nonce on replay check",
            to_evict, self.max_entries,
        )

    def count(self) -> int:
        with self._lock:
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) AS c FROM denial_receipt_nonces"
                ).fetchone()["c"]
            )

    def status(self) -> dict[str, Any]:
        return {
            "backend": "sqlite",
            "path": self.path,
            "max_entries": self.max_entries,
            "entries": self.count(),
            "evicted": self.evicted,
        }

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error as e:
                # Close-time errors are non-fatal (we're tearing down) but
                # log so a leaked handle / locked-db on shutdown is visible.
                logger.warning(
                    "denial-receipt nonce store: error on close (%s)", e,
                )


class InMemoryNonceStore(_BaseNonceStore):
    """Volatile nonce store — does NOT survive restart.

    Provided for tests + ephemeral deployments. Per the build's
    replay-resistance point this is explicitly the WEAKER option: a
    restart empties it and reopens the replay window. The proxy defaults
    to :class:`SqliteNonceStore` whenever a state dir is available; this
    is the fallback only when no durable path can be resolved.
    """

    def __init__(self, *, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self.max_entries = max(1, int(max_entries))
        self.evicted = 0
        self._lock = threading.Lock()
        # nonce -> [minted_ts, consume_count, minted_order, deny_id]
        self._d: dict[str, list[Any]] = {}
        self._order = 0

    def record_minted(self, nonce: str, *, deny_id: str = "", ts: str = "") -> None:
        with self._lock:
            if nonce not in self._d:
                self._order += 1
                # deny_id is retained for parity with the SQLite backend
                # so an in-process audit can correlate a nonce to its deny.
                self._d[nonce] = [ts, 0, self._order, deny_id]
            while len(self._d) > self.max_entries:
                oldest = min(self._d, key=lambda n: self._d[n][2])
                self._d.pop(oldest, None)
                self.evicted += 1

    def check_and_consume(self, nonce: str) -> NonceCheck:
        with self._lock:
            entry = self._d.get(nonce)
            if entry is None:
                return NonceCheck(
                    nonce=nonce, known=False, replay=False, consume_count=0,
                )
            prior = int(entry[1])
            entry[1] = prior + 1
            return NonceCheck(
                nonce=nonce,
                known=True,
                replay=prior > 0,
                consume_count=prior + 1,
                minted_ts=entry[0] or None,
            )

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "backend": "memory",
                "max_entries": self.max_entries,
                "entries": len(self._d),
                "evicted": self.evicted,
            }


def open_nonce_store(
    path: str | os.PathLike | None,
    *,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> _BaseNonceStore:
    """Open the durable SQLite store at ``path``, or an in-memory store
    when ``path`` is None.

    The proxy passes a concrete path (under the bouncer state dir);
    tests pass None for the volatile variant or ``":memory:"`` for an
    isolated SQLite db.
    """
    if path is None:
        return InMemoryNonceStore(max_entries=max_entries)
    return SqliteNonceStore(path, max_entries=max_entries)


__all__ = [
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_NONCE_DB_NAME",
    "InMemoryNonceStore",
    "NonceCheck",
    "SqliteNonceStore",
    "open_nonce_store",
]
