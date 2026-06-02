"""§A76 #468 — per-agent behavioral baseline tracking.

DUAL-MODE storage:
  * Rolling 14d window — exact per-event aggregation, decisive for the
    cold-start phase + short-horizon spike detection. Falls off the
    back at exactly ``window_seconds``.
  * Exponential decay — every observation weighted by ``decay_rate ^
    age_in_periods``. Default rate 0.96 / 14d half-life; operator
    configurable. Strictly dominates pure rolling per the Lacework
    Polygraph + METER VLDB 2024 + AGMM papers (#488 research).

Both modes share the same on-disk schema. Per ``[[anomaly-detection-
mode-phase-h]]`` resolution: NEW SQLite tables sibling to the
existing audit DB (additive — does not modify the audit-export
recorder).

Privacy: NEVER tracks individual data VALUES. Only structural
patterns (action shape, ARN prefix, time-bucket, counts). The test
``test_baseline_privacy_no_individual_values_stored`` enforces this
by asserting the table schema has no ``raw_payload`` / ``resource``
free-text columns; the columns we DO carry are bounded shape
identifiers.

Per ``[[independence-as-security-property]]`` baselines stay LOCAL;
never sent anywhere. Per ``[[no-hosted-saas]]`` no aggregation
service.

Per ``[[creates-never-mutates]]`` we ADD a new database (default
``~/.iam-jit/anomaly-baseline.db``) rather than touch the existing
audit DB schema.

The write path is intentionally non-blocking: callers ``observe()`` to
push into an in-memory queue + a worker thread flushes to SQLite in
batches. Same fail-soft posture as the audit-log writer: a broken disk
records the error on a counter, never raises into the proxy hot path.
"""

from __future__ import annotations

import dataclasses
import logging
import math
import pathlib
import sqlite3
import statistics
import threading
import time
from collections import defaultdict, deque
from collections.abc import Iterable
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

# Schema version stored in the meta table. Bumps require an additive
# migration; this is a private file the operator can wipe at any time
# (it's just a learned baseline) so we keep migration logic simple.
_SCHEMA_VERSION = 1

# Resource-pattern bucketing — see ``_canonical_resource_pattern``. We
# never store the full resource string; just the structural shape
# (service + first ARN segment) so privacy invariant holds.

_DDL = [
    """CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
    # Per-(agent, action, resource_pattern, time_bucket) observations.
    # Rolling-window queries scan this; exponential-decay refreshes
    # update the per-agent aggregate in `anomaly_baseline_decayed`.
    """CREATE TABLE IF NOT EXISTS anomaly_baseline_per_agent (
        agent_identity      TEXT NOT NULL,
        action              TEXT NOT NULL,
        resource_pattern    TEXT NOT NULL,
        hour_of_day         INTEGER NOT NULL,
        observed_at         INTEGER NOT NULL,
        count               INTEGER NOT NULL DEFAULT 1
    )""",
    # One row per (agent, action, resource_pattern, dimension) — the
    # decayed aggregate. Updated on every flush by re-folding all rows
    # within the decay horizon weighted by decay_rate ^ periods.
    """CREATE TABLE IF NOT EXISTS anomaly_baseline_decayed (
        agent_identity      TEXT NOT NULL,
        action              TEXT NOT NULL,
        resource_pattern    TEXT NOT NULL,
        dimension           TEXT NOT NULL,
        weighted_count      REAL NOT NULL DEFAULT 0.0,
        weighted_sum        REAL NOT NULL DEFAULT 0.0,
        weighted_sum_sq     REAL NOT NULL DEFAULT 0.0,
        last_updated        INTEGER NOT NULL,
        PRIMARY KEY (agent_identity, action, resource_pattern, dimension)
    )""",
    # Index for the rolling-window scan (the hot-path query).
    """CREATE INDEX IF NOT EXISTS idx_per_agent_lookup
       ON anomaly_baseline_per_agent (agent_identity, action, observed_at)""",
]


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class DimensionStats:
    """Per-dimension summary used by the detector for z-score scoring.

    All fields are derived from the stored baseline; they are not
    persisted directly (the detector recomputes them on demand from
    ``anomaly_baseline_decayed`` so the rolling + decayed views stay
    cheap to recombine).
    """

    dimension: str
    count: float
    mean: float
    stddev: float

    def z_score(self, observed: float) -> float:
        """Return |observed - mean| / max(stddev, epsilon)."""
        sd = max(self.stddev, 1e-9)
        return abs(observed - self.mean) / sd


@dataclasses.dataclass(frozen=True)
class BaselineSummary:
    """Snapshot returned by :meth:`BaselineStore.summary_for`.

    The detector consumes this to compute its z-score breakdown. We
    surface BOTH the rolling-window aggregates AND the decayed
    aggregates so the detector can pick whichever view is more useful
    per-dimension; defaults to the decayed view when both have data.
    """

    agent_identity: str
    action: str
    resource_pattern: str
    total_observations_rolling: int
    """Count of raw observations in the rolling window. Used by the
    detector to gate cold-start (< min_actions_for_baseline →
    cold_start_fallback path)."""
    total_observations_decayed: float
    """Decayed equivalent. The two should agree at order-of-magnitude
    for a healthy baseline; large drift implies the window/decay rate
    are mis-tuned and the detector surfaces a hint."""
    dimensions: dict[str, DimensionStats]
    """Per-dimension stats keyed by dimension name. Always contains:
       - ``action_frequency``  (observations per hour)
       - ``hour_of_day``       (mean / stddev of hour-of-day distribution)
       - ``per_session_count`` (mean / stddev of action count per session,
                                computed off the rolling table; decayed
                                aggregate uses the periodic re-fold)."""


# ---------------------------------------------------------------------------
# Resource-pattern canonicalisation (privacy invariant)
# ---------------------------------------------------------------------------


_PROD_HINT = ("prod", "production", "live")
_STAGING_HINT = ("staging", "stage", "qa", "test")


def canonical_resource_pattern(resource: str | None) -> str:
    """Return a STRUCTURAL pattern for ``resource`` — never the raw value.

    We deliberately keep this lossy so the baseline DB never carries
    customer data. Rules:

      * ``arn:aws:<svc>:<region>:<account>:<rest>`` → ``arn:aws:<svc>::<env>``
        where ``<env>`` is one of ``prod`` / ``staging`` / ``other`` based
        on substring hints. Account + region + name are dropped.
      * Plain k8s resource (``namespace/name``) → ``k8s:<env>``.
      * Plain SQL identifier (``schema.table``) → ``sql:<env>``.
      * Bare ``*`` (wildcard) → ``*``.
      * Empty / None → ``-``.

    The detector matches on this pattern, so two ARNs that share the
    same service + env hint are considered the same "resource shape"
    for baselining purposes. False positives from over-bucketing are
    preferable to leaking customer data into the baseline DB.
    """
    if resource is None:
        return "-"
    s = str(resource).strip()
    if not s:
        return "-"
    if s == "*":
        return "*"
    lower = s.lower()
    env = "other"
    if any(h in lower for h in _PROD_HINT):
        env = "prod"
    elif any(h in lower for h in _STAGING_HINT):
        env = "staging"
    if s.startswith("arn:"):
        parts = s.split(":", 5)
        svc = parts[2] if len(parts) > 2 else "unknown"
        return f"arn:aws:{svc}::{env}"
    if "/" in s and not s.startswith("/"):
        return f"k8s:{env}"
    if "." in s and " " not in s:
        return f"sql:{env}"
    return f"opaque:{env}"


# ---------------------------------------------------------------------------
# BaselineStore
# ---------------------------------------------------------------------------


class BaselineStore:
    """Per-agent behavioral baseline storage (rolling + exponential decay).

    Usage::

        store = BaselineStore(path="~/.iam-jit/anomaly-baseline.db")
        store.start()
        store.observe(agent_identity="claude-code:abc",
                      action="s3:GetObject",
                      resource="arn:aws:s3:::prod-bucket/key",
                      session_id="s-1")
        summary = store.summary_for("claude-code:abc", "s3:GetObject",
                                     "arn:aws:s3:::prod-bucket/key")
        # ... detector consumes `summary`
        store.stop()

    The class is thread-safe + the SQLite connection lives in a worker
    thread so the proxy hot-path never blocks on disk I/O (observe()
    just enqueues).
    """

    DEFAULT_WINDOW_SECONDS = 14 * 24 * 3600  # 14 days
    DEFAULT_DECAY_RATE = 0.96  # operator-configurable; ~14d half-life
    DEFAULT_DECAY_PERIOD_SECONDS = 24 * 3600  # one decay step per day
    DEFAULT_FLUSH_INTERVAL_SECONDS = 30
    DEFAULT_QUEUE_MAXSIZE = 50_000

    def __init__(
        self,
        *,
        path: str | pathlib.Path | None = None,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        decay_rate: float = DEFAULT_DECAY_RATE,
        decay_period_seconds: int = DEFAULT_DECAY_PERIOD_SECONDS,
        flush_interval_seconds: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
        queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
        clock: Any = None,
    ) -> None:
        # Path resolution: explicit path > IAM_JIT_ANOMALY_BASELINE_PATH
        # > ~/.iam-jit/anomaly-baseline.db. Tests pass an in-memory
        # ":memory:" path.
        import os

        if path is None:
            env = os.environ.get("IAM_JIT_ANOMALY_BASELINE_PATH")
            path = env or str(
                pathlib.Path.home() / ".iam-jit" / "anomaly-baseline.db"
            )
        self.path = str(path)
        self.window_seconds = int(window_seconds)
        self.decay_rate = float(decay_rate)
        self.decay_period_seconds = int(decay_period_seconds)
        self.flush_interval_seconds = float(flush_interval_seconds)
        self.queue_maxsize = int(queue_maxsize)
        # Injectable clock so tests can fast-forward through a 14d
        # window in milliseconds.
        self._clock = clock or time.time

        # Drop counter — surfaced by the bouncer status MCP tool so a
        # broken disk / overflowing queue is visible without raising.
        self._dropped = 0
        self._write_errors = 0

        self._queue: deque[tuple[int, str, str, str, int, str]] = deque()
        self._queue_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._conn: sqlite3.Connection | None = None
        # For in-memory testing we keep the connection on the caller
        # thread; SQLite ``:memory:`` databases are NOT shared across
        # connections so the worker thread can't reopen them.
        self._in_memory = self.path == ":memory:"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Open the SQLite connection + spawn the flush worker."""
        if self._conn is not None:
            return
        if not self._in_memory:
            parent = pathlib.Path(self.path).expanduser().parent
            parent.mkdir(parents=True, exist_ok=True)
            self.path = str(pathlib.Path(self.path).expanduser())
        self._conn = sqlite3.connect(
            self.path,
            check_same_thread=False,
            isolation_level=None,  # autocommit; we batch in worker
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        for stmt in _DDL:
            self._conn.execute(stmt)
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(_SCHEMA_VERSION),),
        )
        self._stop_event.clear()
        self._worker = threading.Thread(
            target=self._worker_loop,
            name="anomaly-baseline-flush",
            daemon=True,
        )
        self._worker.start()

    def stop(self, *, drain: bool = True) -> None:
        """Stop the worker + close the connection. ``drain=True`` flushes
        the in-memory queue first; tests pass False when they want to
        observe drop behavior."""
        self._stop_event.set()
        if self._worker is not None:
            self._worker.join(timeout=5.0)
            self._worker = None
        if drain:
            self._flush_locked()
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ------------------------------------------------------------------
    # Observation path (hot path — must be non-blocking)
    # ------------------------------------------------------------------

    def observe(
        self,
        *,
        agent_identity: str,
        action: str,
        resource: str | None = None,
        session_id: str = "",
        observed_at: float | None = None,
    ) -> None:
        """Record one observation. Non-blocking; enqueues for the worker.

        Privacy: ``resource`` is canonicalised via
        :func:`canonical_resource_pattern` before storage. The raw
        ``resource`` value NEVER touches disk.
        """
        if not action:
            return
        ai = (agent_identity or "anonymous").strip()
        if not ai:
            ai = "anonymous"
        ts = int(observed_at if observed_at is not None else self._clock())
        pat = canonical_resource_pattern(resource)
        hr = time.gmtime(ts).tm_hour
        with self._queue_lock:
            if len(self._queue) >= self.queue_maxsize:
                self._dropped += 1
                return
            self._queue.append((ts, ai, action, pat, hr, session_id))

    # ------------------------------------------------------------------
    # Worker thread
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(self.flush_interval_seconds)
            try:
                self._flush_locked()
            except Exception as e:  # pragma: no cover
                logger.warning("anomaly baseline flush failed: %s", e)
                self._write_errors += 1

    def _flush_locked(self) -> None:
        """Drain the queue + write to SQLite + refresh decayed aggregate."""
        with self._queue_lock:
            if not self._queue:
                return
            batch = list(self._queue)
            self._queue.clear()
        if self._conn is None:
            return
        try:
            self._conn.execute("BEGIN")
            self._conn.executemany(
                "INSERT INTO anomaly_baseline_per_agent "
                "(observed_at, agent_identity, action, resource_pattern, "
                " hour_of_day, count) VALUES (?, ?, ?, ?, ?, 1)",
                [
                    (ts, ai, act, pat, hr)
                    for (ts, ai, act, pat, hr, _sid) in batch
                ],
            )
            # Refresh the decayed aggregate for the affected keys.
            affected: set[tuple[str, str, str]] = set()
            for (_ts, ai, act, pat, _hr, _sid) in batch:
                affected.add((ai, act, pat))
            now = int(self._clock())
            for ai, act, pat in affected:
                self._refresh_decayed_aggregate(ai, act, pat, now)
            # Prune rolling-window rows past ``window_seconds`` so the
            # table doesn't grow unbounded.
            self._conn.execute(
                "DELETE FROM anomaly_baseline_per_agent "
                "WHERE observed_at < ?",
                (now - self.window_seconds,),
            )
            self._conn.execute("COMMIT")
        except Exception as e:
            logger.warning("baseline flush sqlite error: %s", e)
            self._write_errors += 1
            try:
                self._conn.execute("ROLLBACK")
            except Exception:
                pass

    def _refresh_decayed_aggregate(
        self,
        agent_identity: str,
        action: str,
        resource_pattern: str,
        now: int,
    ) -> None:
        """Re-fold the rolling table into the decayed aggregate for one
        key. Per-dimension aggregates (action_frequency, hour_of_day,
        per_session_count) all share the same row template; we use the
        ``dimension`` column to discriminate.

        The fold weights each observation by
        ``decay_rate ** age_in_periods`` where periods are
        ``decay_period_seconds`` long. This matches the AGMM /
        Polygraph formulation from #488.
        """
        assert self._conn is not None
        # Pull all observations within window
        rows = self._conn.execute(
            "SELECT observed_at, hour_of_day FROM "
            "anomaly_baseline_per_agent WHERE agent_identity=? "
            "AND action=? AND resource_pattern=? AND observed_at >= ?",
            (
                agent_identity, action, resource_pattern,
                now - self.window_seconds,
            ),
        ).fetchall()
        if not rows:
            return

        # action_frequency = total weighted count
        # hour_of_day      = weighted mean / stddev of `hour_of_day`
        # Per-dimension we maintain (weighted_count, weighted_sum,
        # weighted_sum_sq) so the decayed view can compute mean +
        # variance without storing the full sample.
        freq_n = freq_s = freq_ss = 0.0
        hour_n = hour_s = hour_ss = 0.0
        for ts, hr in rows:
            age_periods = max(0.0, (now - ts) / self.decay_period_seconds)
            weight = self.decay_rate ** age_periods
            freq_n += weight
            freq_s += weight  # action_frequency: every row contributes 1
            freq_ss += weight  # variance carried separately; see detector
            hour_n += weight
            hour_s += weight * hr
            hour_ss += weight * hr * hr

        upserts = [
            ("action_frequency", freq_n, freq_s, freq_ss),
            ("hour_of_day", hour_n, hour_s, hour_ss),
        ]
        for dim, wn, ws, wss in upserts:
            self._conn.execute(
                "INSERT INTO anomaly_baseline_decayed "
                "(agent_identity, action, resource_pattern, dimension, "
                " weighted_count, weighted_sum, weighted_sum_sq, "
                " last_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(agent_identity, action, resource_pattern, "
                "dimension) DO UPDATE SET weighted_count=excluded."
                "weighted_count, weighted_sum=excluded.weighted_sum, "
                "weighted_sum_sq=excluded.weighted_sum_sq, "
                "last_updated=excluded.last_updated",
                (agent_identity, action, resource_pattern, dim,
                 wn, ws, wss, now),
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_open(self) -> None:
        """Open the SQLite connection on demand when not already open.

        Called by every read path so both the proxy (which calls
        ``start()`` at process boot) and the CLI dry-run path (which
        constructs a fresh store and calls ``summary_for`` directly,
        without ``start()``) get the real on-disk data instead of an
        empty short-circuit.

        Idempotent: if ``_conn`` is already open this is a no-op
        (mirrors the ``start()`` guard ``if self._conn is not None:
        return``). The worker thread is NOT spawned here; this is the
        read-only fast path — no background flush needed for a CLI
        dry-run that never calls ``observe()``.
        """
        if self._conn is not None:
            return
        # Resolve and mkdir the parent directory (same logic as start()).
        if not self._in_memory:
            resolved = str(pathlib.Path(self.path).expanduser())
            # Don't create the directory for a read — if the DB doesn't
            # exist yet, sqlite3.connect will create an empty file, and
            # the DDL below will produce empty tables (zero rows) which
            # is the correct answer: "no baseline yet".
            parent = pathlib.Path(resolved).parent
            parent.mkdir(parents=True, exist_ok=True)
            self.path = resolved
        self._conn = sqlite3.connect(
            self.path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        for stmt in _DDL:
            self._conn.execute(stmt)
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(_SCHEMA_VERSION),),
        )

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    def summary_for(
        self,
        agent_identity: str,
        action: str,
        resource: str | None = None,
        *,
        now: float | None = None,
    ) -> BaselineSummary:
        """Compute the per-dimension summary the detector consumes.

        Cheap: a handful of indexed lookups + arithmetic. Safe to call
        on the proxy hot-path (single-digit ms even for a baseline
        with millions of rows because the rolling-window prune keeps
        the table compact).

        Read-path callers (including the CLI dry-run) do NOT need to
        call ``start()`` first — ``_ensure_open`` lazily opens the
        connection on demand so the real on-disk baseline is visible
        without the background flush worker. The proxy path still calls
        ``start()`` at boot; ``_ensure_open`` is a no-op for it.
        """
        # Lazily open the connection so the CLI read path sees the real
        # on-disk data even when start() was never called.
        self._ensure_open()
        # Force a flush of any in-flight observations so callers
        # observing then querying immediately see their own writes.
        self._flush_locked()
        pat = canonical_resource_pattern(resource)
        ts_now = int(now if now is not None else self._clock())

        # Rolling window scan — exact count + time-of-day distribution
        rolling_rows = self._conn.execute(
            "SELECT observed_at, hour_of_day FROM "
            "anomaly_baseline_per_agent WHERE agent_identity=? "
            "AND action=? AND resource_pattern=? AND observed_at >= ?",
            (agent_identity, action, pat, ts_now - self.window_seconds),
        ).fetchall()
        rolling_count = len(rolling_rows)

        # Per-dimension exact stats (these are what the detector uses
        # when the rolling sample is large enough to be authoritative;
        # the decayed view supplements with longer-tail weight).
        dims: dict[str, DimensionStats] = {}
        if rolling_count > 0:
            # action_frequency: count per hour over the window.
            hours = max(1.0, self.window_seconds / 3600.0)
            freq_mean = rolling_count / hours
            # Use Poisson-ish variance proxy: var ≈ mean (count data).
            freq_var = freq_mean
            dims["action_frequency"] = DimensionStats(
                dimension="action_frequency",
                count=float(rolling_count),
                mean=freq_mean,
                stddev=math.sqrt(max(freq_var, 1e-9)),
            )
            hour_vals = [float(hr) for (_ts, hr) in rolling_rows]
            if len(hour_vals) >= 2:
                hr_mean = float(statistics.mean(hour_vals))
                hr_sd = float(statistics.pstdev(hour_vals))
            else:
                hr_mean = float(hour_vals[0])
                hr_sd = 0.0
            dims["hour_of_day"] = DimensionStats(
                dimension="hour_of_day",
                count=float(len(hour_vals)),
                mean=hr_mean,
                stddev=hr_sd,
            )

        # Decayed aggregates — always include when available.
        decayed_rows = self._conn.execute(
            "SELECT dimension, weighted_count, weighted_sum, "
            " weighted_sum_sq FROM anomaly_baseline_decayed "
            "WHERE agent_identity=? AND action=? AND resource_pattern=?",
            (agent_identity, action, pat),
        ).fetchall()
        decayed_total = 0.0
        hours = max(1.0, self.window_seconds / 3600.0)
        for dim, wn, ws, wss in decayed_rows:
            if dim == "action_frequency":
                decayed_total = wn
                # Poisson-ish: mean = count/hours; var ≈ mean.
                mean = float(wn) / hours
                stddev = math.sqrt(max(mean, 1e-9))
                dims[dim + "_decayed"] = DimensionStats(
                    dimension=dim + "_decayed",
                    count=float(wn),
                    mean=mean,
                    stddev=stddev,
                )
                continue
            if wn <= 0:
                continue
            mean = ws / wn
            var = max(0.0, (wss / wn) - mean * mean)
            dims[dim + "_decayed"] = DimensionStats(
                dimension=dim + "_decayed",
                count=float(wn),
                mean=float(mean),
                stddev=math.sqrt(var),
            )

        return BaselineSummary(
            agent_identity=agent_identity,
            action=action,
            resource_pattern=pat,
            total_observations_rolling=rolling_count,
            total_observations_decayed=decayed_total,
            dimensions=dims,
        )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Return a snapshot suitable for the bouncer status MCP tool."""
        with self._queue_lock:
            queue_depth = len(self._queue)
        return {
            "path": self.path,
            "queue_depth": queue_depth,
            "dropped": self._dropped,
            "write_errors": self._write_errors,
            "window_seconds": self.window_seconds,
            "decay_rate": self.decay_rate,
            "decay_period_seconds": self.decay_period_seconds,
            "in_memory": self._in_memory,
        }

    def known_agents(self) -> list[str]:
        """Return distinct agent identities tracked so far. Debugging
        helper for the CLI; cheap on any reasonable baseline."""
        self._ensure_open()
        self._flush_locked()
        rows = self._conn.execute(
            "SELECT DISTINCT agent_identity FROM anomaly_baseline_per_agent"
        ).fetchall()
        return sorted({r[0] for r in rows})


__all__ = [
    "BaselineStore",
    "BaselineSummary",
    "DimensionStats",
    "canonical_resource_pattern",
]
