"""JSONL audit-log writer — Channel 1 of the audit-export transport.

Per `security-team-audit-export`:
- File mode: ``O_APPEND|O_CREAT|O_WRONLY`` (append-only; never
  truncates an existing file; survives concurrent appenders on
  POSIX so a sidecar shipper can rotate underneath without losing
  bytes mid-write).
- Buffered: events go to an asyncio.Queue; a worker task drains.
  Write to disk is OFF the proxy hot-path so a slow filesystem
  (NFS, busy SSD) never blocks request handling.
- Optional fsync per write via `--audit-log-fsync`. Default OFF
  for throughput; the compliance-grade trade-off is called out in
  the CLI --help text + docs.
- No rotation built in. Operators point logrotate / Fluent Bit /
  Vector at the path — that's the same shape every production app
  uses (nginx, postgres, kafka), and rolling our own would compete
  with those tools without offering anything they don't already do.

The writer is fail-soft: filesystem errors are logged + counted on
a counter the MCP `bouncer_audit_export_status` tool surfaces, but
they never raise into the proxy hot-path. A broken disk should not
turn the proxy into a 500-machine — the audit channel is a feature,
not a hard dependency of correctness.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pathlib
import threading
import time
from typing import Any, Callable

from . import rotation as _rotation

logger = logging.getLogger(__name__)

# Default queue size for the writer. Large enough that a 10k-RPS
# burst against a momentarily-slow disk doesn't lose anything; small
# enough that we OOM-protect a runaway producer. The webhook pusher
# uses a tighter bound (1000) because network round-trips are slower
# and the operator probably cares more about webhook freshness than
# log completeness.
_DEFAULT_LOG_QUEUE_MAXSIZE = 10_000


class AuditLogWriter:
    """Async JSONL audit-log writer.

    Lifecycle::

        writer = AuditLogWriter(path="/var/log/ibounce/audit.jsonl")
        await writer.start()  # opens fd + spawns worker
        await writer.write({"ts": "...", ...})  # never blocks
        await writer.stop()   # drains queue + closes fd

    The proxy hot-path calls `write()` which performs an
    ``asyncio.Queue.put_nowait`` (non-blocking). If the queue is full
    (shouldn't happen with the default 10k cap), the event is dropped
    + a counter is bumped; we DO NOT block the request to wait for
    queue capacity (a slow disk would otherwise stall the proxy).
    """

    def __init__(
        self,
        *,
        path: str | pathlib.Path,
        fsync: bool = False,
        queue_maxsize: int = _DEFAULT_LOG_QUEUE_MAXSIZE,
        max_size_mb: int = _rotation.DEFAULT_MAX_SIZE_MB,
        max_age_days: int = _rotation.DEFAULT_MAX_AGE_DAYS,
        on_rotation: Callable[[pathlib.Path], None] | None = None,
        on_rotation_failure: Callable[[str], None] | None = None,
        on_recovery: Callable[[int], None] | None = None,
    ) -> None:
        self.path = pathlib.Path(path)
        self.fsync = fsync
        self.queue_maxsize = queue_maxsize
        # #311 / §A10 rotation knobs. Zero disables the respective
        # trigger; the writer never destroys data on its own (rotated
        # files are always gzip'd into the same dir and kept until an
        # explicit `ibounce logs purge` reaps them).
        self.max_size_mb = max_size_mb
        self.max_age_days = max_age_days
        # Optional callbacks the proxy wires to emit admin-action
        # events on rotation success / failure / recovery. The
        # writer's worker can't synthesise audit events itself (would
        # create a recursion with the event channel it's draining);
        # the caller passes a recorder-bound emitter that converts
        # the call into an `audit.log.rotated` / `.rotation_failed` /
        # `.recovered_partial` admin-action.
        self._on_rotation = on_rotation
        self._on_rotation_failure = on_rotation_failure
        self._on_recovery = on_recovery
        self._queue: asyncio.Queue[dict[str, Any] | None] | None = None
        self._worker_task: asyncio.Task | None = None
        self._fd: int | None = None
        # Stats — read by the MCP `bouncer_audit_export_status` tool.
        # Protected by a plain lock since they're read off the event
        # loop by the MCP server (separate thread / sync call).
        self._stats_lock = threading.Lock()
        self._total_events = 0
        self._dropped_events = 0
        self._last_error: str | None = None
        # #267 — failure-visibility surface read by /healthz + the
        # audit_export_degraded alert rule. `_writes_ok` flips to False
        # on the first write error after a successful write (or on the
        # first error if no successful write has happened yet) and
        # flips back to True on the next successful write. The
        # timestamp companion makes "how long has this been broken?"
        # an O(1) check for the operator dashboard.
        self._writes_ok: bool = True
        self._last_error_at_unix: float | None = None
        # #311 / §A10 rotation telemetry. Counters are surfaced via
        # `status()` so operators can confirm rotation is firing
        # without grepping for the admin-action.
        self._rotations = 0
        self._last_rotation_at_unix: float | None = None
        self._last_rotation_path: str | None = None
        self._rotation_failures = 0
        self._partial_bytes_recovered = 0
        self._started = False

    async def start(self) -> None:
        """Open the log file + spawn the drain worker.

        Idempotent: calling twice is a no-op (returns immediately).
        Creates the parent directory if missing (matches the operator-
        convenience pattern other parts of the bouncer follow with
        the SQLite store).
        """
        if self._started:
            return
        # Create parent dir on demand; helpful for first-time setups
        # where the operator points `--audit-log-path` at a nested
        # path that doesn't exist yet. We don't refuse to create
        # parents — same posture as the SQLite store; the operator
        # asked us to write here.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            # Surface the error via the stats channel so the
            # MCP status tool / operator can see WHY the writer
            # isn't producing rows.
            self._record_error(f"mkdir parent {self.path.parent}: {e}")
            raise
        # #311 / §A10 — crash recovery: if the previous process died
        # mid-write, the final JSONL line may be partial. Truncate to
        # the previous newline before opening for append so the next
        # write doesn't produce a corrupt mixed line. The trimmed
        # byte count is surfaced as an admin-action so the operator
        # sees the partial-write happened (vital for compliance).
        try:
            recovered = _rotation.recover_partial_tail(self.path)
        except OSError as e:
            recovered = 0
            self._record_error(f"recover partial tail: {e}")
        if recovered > 0:
            with self._stats_lock:
                self._partial_bytes_recovered += recovered
            if self._on_recovery is not None:
                try:
                    self._on_recovery(recovered)
                except Exception as cb_err:
                    logger.warning(
                        "audit-log recovery callback raised: %s", cb_err
                    )
        # O_APPEND|O_CREAT|O_WRONLY — never truncate. 0o600 by default
        # because audit logs commonly contain sensitive metadata (the
        # operator can chmod it wider explicitly if their setup needs
        # group readability for a log shipper).
        try:
            self._fd = os.open(
                str(self.path),
                os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                0o600,
            )
        except OSError as e:
            self._record_error(f"open {self.path}: {e}")
            raise
        self._queue = asyncio.Queue(maxsize=self.queue_maxsize)
        self._worker_task = asyncio.create_task(
            self._worker(),
            name="ibounce-audit-log-writer",
        )
        self._started = True

    async def stop(self) -> None:
        """Signal the worker to drain + exit, close the fd."""
        if not self._started:
            return
        # Sentinel-on-queue is the cooperative-stop signal; the worker
        # exits its loop on receiving None.
        try:
            await self._queue.put(None)
        except Exception:
            pass
        if self._worker_task is not None:
            try:
                await self._worker_task
            except Exception as e:
                logger.warning("audit-log writer worker exited with %s", e)
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        self._started = False

    def write(self, event: dict[str, Any]) -> None:
        """Enqueue one event for the worker. NEVER blocks. NEVER raises.

        Returns immediately. The actual fd.write happens on the worker
        task. If the queue is full, the event is dropped + the dropped
        counter is bumped; the bouncer_audit_export_status MCP tool
        surfaces both totals.
        """
        if not self._started or self._queue is None:
            return  # caller didn't await start(); silently no-op
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            with self._stats_lock:
                self._dropped_events += 1
                self._last_error = (
                    f"log queue full at {self.queue_maxsize}; dropped event"
                )

    async def _worker(self) -> None:
        """Drain loop. Runs until it sees a `None` sentinel."""
        assert self._queue is not None
        assert self._fd is not None
        while True:
            event = await self._queue.get()
            if event is None:
                return
            try:
                line = json.dumps(event, ensure_ascii=False) + "\n"
                # Write encoded bytes via os.write (low-level fd path
                # we opened above). os.write is atomic per write call
                # for small buffers on POSIX (man 2 write, PIPE_BUF),
                # which keeps lines uncorrupted across concurrent
                # appenders — important when a log shipper is running
                # alongside.
                os.write(self._fd, line.encode("utf-8"))
                if self.fsync:
                    try:
                        os.fsync(self._fd)
                    except OSError as e:
                        # fsync failure does NOT lose the write — just
                        # the durability guarantee. Log + carry on.
                        self._record_error(f"fsync: {e}")
                with self._stats_lock:
                    self._total_events += 1
                    # #267 — a successful write clears the writes_ok
                    # alert flag. Previous transient errors (last_error
                    # / last_error_at) are retained for forensics; the
                    # bool reflects the CURRENT health of the channel.
                    self._writes_ok = True
                # #311 / §A10 — rotation guard runs after every
                # successful write. Cheap: a single stat() unless one
                # of the thresholds fires. We check on the worker
                # task (not the hot-path `write()`) so the actual
                # rename + gzip cost is paid off the request path.
                self._maybe_rotate()
            except Exception as e:
                # Any write failure (disk full, permission flipped at
                # runtime, fd closed underneath us) — record + carry
                # on. We do NOT raise into the worker's loop because
                # raising kills the task + every subsequent write()
                # would silently no-op without a counter.
                self._record_error(f"write: {e}")

    def _maybe_rotate(self) -> None:
        """#311 / §A10 — size + age rotation guard.

        Called by the worker after each successful write. Performs at
        most one stat() per call when no rotation is needed. On a
        rotation trigger we:
          1. fsync + close the current fd so the bytes are durable.
          2. Atomically rename + gzip via `rotation.rotate`.
          3. Re-open a fresh `audit.jsonl` at the same path with the
             same O_APPEND|O_CREAT|O_WRONLY mode + 0o600 perm.
          4. Fire the operator's `on_rotation` callback so an
             `audit.log.rotated` admin-action emits.

        Failures are recorded but do NOT raise into the worker loop
        (a rotation failure must not stop the audit channel — the
        active file keeps growing and the operator can act on the
        admin-action alert).
        """
        if self._fd is None:
            return
        if not (
            _rotation.should_rotate_by_size(self.path, self.max_size_mb)
            or _rotation.should_rotate_by_age(self.path, self.max_age_days)
        ):
            return
        # Best-effort fsync before rotating so the rotated archive
        # contains every byte the worker has accepted. A sync error
        # here is logged but doesn't block the rotation — the bytes
        # are at minimum in the OS page cache which is what `copy
        # fileobj` will read from anyway.
        try:
            os.fsync(self._fd)
        except OSError as e:
            logger.warning("audit-log fsync before rotate: %s", e)
        try:
            os.close(self._fd)
        finally:
            self._fd = None
        archive: pathlib.Path | None = None
        try:
            archive = _rotation.rotate(self.path)
        except OSError as e:
            with self._stats_lock:
                self._rotation_failures += 1
                self._last_error = f"rotate: {e}"
                self._writes_ok = False
                self._last_error_at_unix = time.time()
            if self._on_rotation_failure is not None:
                try:
                    self._on_rotation_failure(str(e))
                except Exception as cb_err:
                    logger.warning(
                        "audit-log rotation-failure callback raised: %s",
                        cb_err,
                    )
        # Re-open the active file regardless of rotation success — a
        # missing fd would silently drop every subsequent event.
        try:
            self._fd = os.open(
                str(self.path),
                os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                0o600,
            )
        except OSError as e:
            self._record_error(f"reopen after rotate: {e}")
            return
        if archive is not None:
            with self._stats_lock:
                self._rotations += 1
                self._last_rotation_at_unix = time.time()
                self._last_rotation_path = str(archive)
            if self._on_rotation is not None:
                try:
                    self._on_rotation(archive)
                except Exception as cb_err:
                    logger.warning(
                        "audit-log rotation callback raised: %s", cb_err
                    )

    def _record_error(self, msg: str) -> None:
        with self._stats_lock:
            self._last_error = msg
            # #267 — also flip writes_ok + capture wall-clock for the
            # failure-visibility surface. The companion timestamp lets
            # /healthz answer "how long has this been broken?" without
            # the operator having to grep logs for the first failure.
            self._writes_ok = False
            self._last_error_at_unix = time.time()
        logger.warning("audit-log writer error: %s", msg)

    def status(self) -> dict[str, Any]:
        """Snapshot for the MCP status tool. Safe to call from any
        thread; takes the stats lock."""
        with self._stats_lock:
            return {
                "configured": True,
                "path": str(self.path),
                "fsync": self.fsync,
                "queue_maxsize": self.queue_maxsize,
                "total_events": self._total_events,
                "dropped_events": self._dropped_events,
                "last_error": self._last_error,
                # #267 — failure-visibility surface fields. The bool
                # is the load-bearing one /healthz consults to flip
                # 503; the timestamp is for forensics.
                "writes_ok": self._writes_ok,
                "last_error_at_unix": self._last_error_at_unix,
                # #311 / §A10 rotation telemetry. Operators tail
                # `bouncer_audit_export_status` to confirm rotation
                # is firing on the cadence they expect.
                "max_size_mb": self.max_size_mb,
                "max_age_days": self.max_age_days,
                "rotations": self._rotations,
                "last_rotation_at_unix": self._last_rotation_at_unix,
                "last_rotation_path": self._last_rotation_path,
                "rotation_failures": self._rotation_failures,
                "partial_bytes_recovered": self._partial_bytes_recovered,
            }
