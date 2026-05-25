# #324a — watchdog-driven hot reload for the dynamic-deny YAML.
"""fsevents (macOS) / inotify (Linux) watcher around
``~/.iam-jit/dynamic-denies.yaml``.

Architecture mirrors the gbounce reference at
``gbounce: internal/dynamicdeny/watcher.go``:

  * Watch the PARENT DIRECTORY (not the file inode) so atomic-rename
    writes (write-tmp + rename) survive — fsnotify on a file inode
    loses the watch when the inode is replaced.
  * Debounce rapid sequential writes with a 100ms quiet period so a
    multi-event burst (the writer producing several Modify events in
    a row) collapses into one reload, not several.
  * On parse error: retain the previous snapshot + emit a
    ``dynamic_deny.parse_error`` admin-action event (fail-CLOSED per
    ``[[ibounce-honest-positioning]]``).
  * On startup, do a synchronous initial load so ``Snapshot()``
    returns real data before the proxy starts accepting traffic — no
    "first N requests see zero rules while we're still waking up"
    window.

Concurrent reads of the active snapshot are serialised through a
:py:class:`threading.RLock`. The proxy hot path holds a reference to
the *immutable* :class:`RuleSet` instance returned from
:py:meth:`snapshot`, so a mid-request reload never produces a torn
read.

Per ``[[creates-never-mutates]]`` the watcher is read-only — it never
modifies the on-disk file. The writer half (``iam-jit deny add``)
ships in #324e.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from .loader import (
    BOUNCER_NAME,
    DynamicDenyLoadError,
    load_file,
)
from .types import Rule, RuleSet

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reload reason enum
# ---------------------------------------------------------------------------


class ReloadReason(str):
    """Canonical reload-reason values surfaced on admin-action events.
    Operators query SIEMs for
    ``unmapped.iam_jit.admin_action.extra.reload_reason`` per the
    cross-product design doc.

    The values match gbounce's :go:type:`dynamicdeny.ReloadReason`
    string constants so a SIEM filter keyed on the value catches the
    same reload across both products.
    """


FILE_CREATED: ReloadReason = ReloadReason("file_created")
FILE_MODIFIED: ReloadReason = ReloadReason("file_modified")
FILE_REMOVED: ReloadReason = ReloadReason("file_removed")
PARSE_ERROR: ReloadReason = ReloadReason("parse_error")
RELOAD_REQUESTED: ReloadReason = ReloadReason("reload_requested")
INITIAL_LOAD: ReloadReason = ReloadReason("initial_load")


# ---------------------------------------------------------------------------
# Emit-callback type
# ---------------------------------------------------------------------------

# (reason, ruleset, parse_error or None) — the callback the watcher
# invokes whenever a reload (or reload attempt) lands. Implementations
# typically build an OCSF admin-action event + tee it into the
# audit-log sink + bump a /healthz counter. ``None`` means emissions
# are silently dropped (the reload still applies; the watcher just
# doesn't surface it through the admin-action channel).
EmitFunc = Callable[[ReloadReason, RuleSet, DynamicDenyLoadError | None], None]


# ---------------------------------------------------------------------------
# Watcher
# ---------------------------------------------------------------------------


_DEBOUNCE_QUIET_PERIOD_SEC = 0.10
"""Default debounce window. 100ms balances "react fast enough that an
operator sees the rule apply right after `iam-jit deny add`" against
"don't reload mid-write."""


class DynamicDenyWatcher:
    """Hot-reload :class:`RuleSet` on disk changes.

    Lifecycle:
      1. Construct with the file path + an optional :data:`EmitFunc`.
         The constructor performs a synchronous initial load so
         :py:meth:`snapshot` has real data immediately.
      2. :py:meth:`start` spins up the background watchdog observer.
      3. :py:meth:`snapshot` returns the current :class:`RuleSet`
         atomically.
      4. :py:meth:`reload_now` triggers an explicit reload (used by
         the ``/admin/dynamic-denies/reload`` endpoint).
      5. :py:meth:`stop` (or context-manager exit) tears down the
         observer cleanly.

    Thread-safety: :py:meth:`snapshot` + :py:meth:`reload_now` are
    safe to call from any thread. The watchdog observer runs its
    callbacks on a worker thread; the watcher's internal lock
    serialises mutation of the active snapshot.
    """

    def __init__(
        self,
        path: str | None,
        *,
        emit: EmitFunc | None = None,
        debounce_seconds: float | None = None,
    ) -> None:
        self.path = path or ""
        self._emit: EmitFunc | None = emit
        self._lock = threading.RLock()
        self._snapshot: RuleSet = RuleSet.empty(source_path=self.path)
        self._initial_load_error: DynamicDenyLoadError | None = None
        self._total_reloads = 0
        self._total_parse_errors = 0
        self._debounce_seconds = (
            debounce_seconds
            if debounce_seconds is not None
            else _DEBOUNCE_QUIET_PERIOD_SEC
        )

        # watchdog state — populated on start()
        self._observer: Any | None = None
        self._observer_lock = threading.Lock()
        self._stopped = False

        # Debounce machinery
        self._pending_timer: threading.Timer | None = None
        self._pending_reason: ReloadReason | None = None
        self._timer_lock = threading.Lock()

        # Perform the initial load synchronously so the startup banner
        # + first request both see the actual rule set.
        self._do_initial_load()

    # -- public API -------------------------------------------------------

    def snapshot(self) -> RuleSet:
        """Return the current :class:`RuleSet`. Safe for concurrent
        use; the returned instance is immutable so callers can read
        ``snapshot().rules`` without holding a lock.
        """
        with self._lock:
            return self._snapshot

    def total_reloads(self) -> int:
        """Successful reloads since construction (excludes initial
        load). Surfaced on ``/healthz`` so an operator can confirm
        the watcher is actually picking up file changes."""
        with self._lock:
            return self._total_reloads

    def total_parse_errors(self) -> int:
        """Failed reloads (parse / schema errors) since construction.
        Includes the initial load when it failed."""
        with self._lock:
            return self._total_parse_errors

    def initial_load_error(self) -> DynamicDenyLoadError | None:
        """Error from the constructor's synchronous initial load, or
        ``None`` when the load succeeded. The CLI surfaces this in the
        startup banner so an operator sees a parse error on their
        ``dynamic-denies.yaml`` BEFORE the proxy starts serving
        traffic (vs. a silent "0 rules loaded" — they'd think the
        file was empty)."""
        with self._lock:
            return self._initial_load_error

    def set_emit(self, emit: EmitFunc | None) -> None:
        """Install (or replace) the admin-action emit callback. Used
        by the CLI layer to wire the watcher's reload notifications
        into the audit-log sink AFTER ``__init__`` has already
        returned a snapshot the proxy can read."""
        with self._lock:
            self._emit = emit

    def start(self) -> None:
        """Spin up the watchdog observer. No-op when ``path`` is empty
        (the watcher acts as a frozen "always-empty" snapshot).
        """
        if not self.path:
            return
        with self._observer_lock:
            if self._observer is not None or self._stopped:
                return
            try:
                from watchdog.observers import Observer
            except ImportError as e:
                logger.warning(
                    "dynamic-deny watcher disabled: watchdog not installed: %s. "
                    "Hot reload will not fire; the initial-load snapshot "
                    "remains active until the next process restart.", e,
                )
                return
            import os
            import pathlib as _pl

            watched_dir = str(_pl.Path(self.path).parent or ".")
            # Walk up if the immediate parent doesn't yet exist (operator
            # may be about to create it). Find the nearest ancestor that
            # does exist + watch THAT.
            while watched_dir and not os.path.isdir(watched_dir):
                parent = os.path.dirname(watched_dir)
                if parent == watched_dir or not parent:
                    break
                watched_dir = parent
            if not watched_dir or not os.path.isdir(watched_dir):
                logger.warning(
                    "dynamic-deny watcher: no existing ancestor directory "
                    "to watch for %s; hot reload disabled.", self.path,
                )
                return

            handler = _make_event_handler(self)
            observer = Observer()
            observer.schedule(handler, watched_dir, recursive=False)
            observer.daemon = True
            observer.start()
            self._observer = observer

    def stop(self) -> None:
        """Shut down the observer. Safe to call multiple times."""
        with self._observer_lock:
            if self._stopped:
                return
            self._stopped = True
            obs = self._observer
            self._observer = None
        if obs is not None:
            try:
                obs.stop()
                obs.join(timeout=2.0)
            except Exception as e:
                logger.warning("dynamic-deny watcher: stop failed: %s", e)
        # Cancel any pending debounce timer.
        with self._timer_lock:
            t = self._pending_timer
            self._pending_timer = None
            self._pending_reason = None
        if t is not None:
            t.cancel()

    def __enter__(self) -> "DynamicDenyWatcher":
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    def reload_now(
        self, reason: ReloadReason = RELOAD_REQUESTED
    ) -> tuple[RuleSet, DynamicDenyLoadError | None]:
        """Trigger an immediate reload, skipping the debounce window.
        Used by the ``POST /admin/dynamic-denies/reload`` endpoint.

        Returns ``(ruleset, error_or_None)`` so the caller can build
        an HTTP response without re-querying state.
        """
        return self._do_reload(reason)

    # -- handler entry points -------------------------------------------

    def _on_fs_event(self, reason: ReloadReason) -> None:
        """Called by the watchdog event handler when a relevant file
        event fires. Debounces — every event resets the timer; only
        when the timer elapses without a new event do we actually
        reload (avoids reloading mid-write).
        """
        with self._timer_lock:
            self._pending_reason = reason
            if self._pending_timer is not None:
                self._pending_timer.cancel()
            t = threading.Timer(
                self._debounce_seconds, self._fire_debounced
            )
            t.daemon = True
            self._pending_timer = t
            t.start()

    def _fire_debounced(self) -> None:
        with self._timer_lock:
            reason = self._pending_reason or FILE_MODIFIED
            self._pending_timer = None
            self._pending_reason = None
        self._do_reload(reason)

    # -- internals --------------------------------------------------------

    def _do_initial_load(self) -> None:
        """Synchronous load called from ``__init__``."""
        try:
            rs = load_file(self.path)
        except DynamicDenyLoadError as e:
            with self._lock:
                self._initial_load_error = e
                self._total_parse_errors += 1
                # Keep the empty placeholder snapshot — fail-CLOSED
                # per [[ibounce-honest-positioning]].
                self._snapshot = RuleSet.empty(source_path=self.path)
            return
        with self._lock:
            self._snapshot = rs
            self._initial_load_error = None

    def _do_reload(
        self, reason: ReloadReason
    ) -> tuple[RuleSet, DynamicDenyLoadError | None]:
        """Shared reload implementation. Handles parse errors by
        retaining the previous snapshot + bumping the parse-error
        counter + firing the emit callback with ``parse_error``.
        """
        try:
            new_rs = load_file(self.path)
        except DynamicDenyLoadError as e:
            with self._lock:
                self._total_parse_errors += 1
                snap = self._snapshot
            self._fire_emit(PARSE_ERROR, snap, e)
            logger.warning(
                "dynamic-deny reload (%s) failed: %s; retaining previous "
                "%d rule(s)", reason, e, len(snap.rules),
            )
            return snap, e

        # Successful reload — commit + fire the emit callback with the
        # real reason (file_created / file_modified / etc.).
        with self._lock:
            self._snapshot = new_rs
            self._total_reloads += 1
        self._fire_emit(reason, new_rs, None)
        return new_rs, None

    def _fire_emit(
        self,
        reason: ReloadReason,
        rs: RuleSet,
        err: DynamicDenyLoadError | None,
    ) -> None:
        """Invoke the configured emit callback. Swallows callback
        errors so the watcher hot path never crashes on a broken
        audit-export sink (the reload itself has already landed)."""
        emit = self._emit
        if emit is None:
            return
        try:
            emit(reason, rs, err)
        except Exception as e:
            logger.warning(
                "dynamic-deny emit callback failed (%s): %s", reason, e,
            )


# ---------------------------------------------------------------------------
# watchdog event handler (factory builds a subclass of
# `watchdog.events.FileSystemEventHandler` at runtime so the import-
# failure branch in `DynamicDenyWatcher.start()` can degrade
# gracefully — without the import we never call _make_event_handler).
# ---------------------------------------------------------------------------


def _make_event_handler(watcher: DynamicDenyWatcher) -> Any:
    """Build a watchdog `FileSystemEventHandler` subclass bound to
    ``watcher``. Filters parent-directory events down to the single
    file the watcher cares about, then routes the event to the
    watcher's debouncer.
    """
    from watchdog.events import FileSystemEventHandler

    import pathlib

    target = str(pathlib.Path(watcher.path).resolve())

    def matches(event_path: str | bytes | None) -> bool:
        if not event_path:
            return False
        if isinstance(event_path, bytes):
            try:
                event_path = event_path.decode("utf-8", errors="replace")
            except Exception:
                return False
        try:
            return str(pathlib.Path(event_path).resolve()) == target
        except OSError:
            return False

    class _Handler(FileSystemEventHandler):
        def on_created(self, event: Any) -> None:
            if getattr(event, "is_directory", False):
                return
            if matches(getattr(event, "src_path", "")):
                watcher._on_fs_event(FILE_CREATED)

        def on_modified(self, event: Any) -> None:
            if getattr(event, "is_directory", False):
                return
            if matches(getattr(event, "src_path", "")):
                watcher._on_fs_event(FILE_MODIFIED)

        def on_deleted(self, event: Any) -> None:
            if getattr(event, "is_directory", False):
                return
            if matches(getattr(event, "src_path", "")):
                watcher._on_fs_event(FILE_REMOVED)

        def on_moved(self, event: Any) -> None:
            if getattr(event, "is_directory", False):
                return
            src = getattr(event, "src_path", "") or ""
            dst = getattr(event, "dest_path", "") or ""
            if matches(src) or matches(dst):
                watcher._on_fs_event(FILE_MODIFIED)

    return _Handler()


# ---------------------------------------------------------------------------
# Convenience: emit-callback factory bridging into ibounce's
# audit-export admin_action queue.
# ---------------------------------------------------------------------------


def make_admin_action_emitter(store: Any) -> EmitFunc:
    """Build an :data:`EmitFunc` that enqueues a
    ``dynamic_deny.reloaded`` / ``dynamic_deny.parse_error``
    admin-action event for every watcher notification.

    Used by the ibounce CLI to wire the watcher's reload stream into
    the existing OCSF admin-action pipeline. Per
    ``[[cross-product-agent-parity]]`` the wire shape here matches
    gbounce's #324d emit byte-for-byte.

    The emitter is best-effort — a queue error is logged but never
    crashes the watcher (the reload itself has already landed in
    memory).
    """
    from ..bouncer.audit_export.admin_action import (
        ADMIN_ACTION_SOURCE_API,
        enqueue_admin_action,
    )

    ADMIN_ACTION_DYNAMIC_DENY_RELOADED = "dynamic_deny.reloaded"
    ADMIN_ACTION_DYNAMIC_DENY_PARSE_ERROR = "dynamic_deny.parse_error"

    def _emit(
        reason: ReloadReason,
        rs: RuleSet,
        err: DynamicDenyLoadError | None,
    ) -> None:
        try:
            if err is not None or reason == PARSE_ERROR:
                err_msg = str(err) if err else "parse error (unknown)"
                stage = getattr(err, "stage", "unknown") if err else "unknown"
                enqueue_admin_action(
                    store,
                    kind=ADMIN_ACTION_DYNAMIC_DENY_PARSE_ERROR,
                    target_kind="dynamic_denies_file",
                    target_id=rs.source_path or "(unknown-path)",
                    source=ADMIN_ACTION_SOURCE_API,
                    extra={
                        "reload_reason": str(reason),
                        "error": err_msg,
                        "error_stage": stage,
                        "retained_rules_count": len(rs.rules),
                    },
                )
                return
            enqueue_admin_action(
                store,
                kind=ADMIN_ACTION_DYNAMIC_DENY_RELOADED,
                target_kind="dynamic_denies_file",
                target_id=rs.source_path or "(unknown-path)",
                source=ADMIN_ACTION_SOURCE_API,
                extra={
                    "reload_reason": str(reason),
                    "rules_applied_to_ibounce": len(rs.rules),
                    "total_rules_in_file": rs.total_rules_in_file,
                    "rule_ids": [r.id for r in rs.rules],
                },
            )
        except Exception as e:
            logger.warning(
                "dynamic-deny admin-action emit failed (%s): %s", reason, e,
            )

    return _emit


__all__ = [
    "DynamicDenyWatcher",
    "ReloadReason",
    "FILE_CREATED",
    "FILE_MODIFIED",
    "FILE_REMOVED",
    "PARSE_ERROR",
    "RELOAD_REQUESTED",
    "INITIAL_LOAD",
    "EmitFunc",
    "make_admin_action_emitter",
]


# Keep a small wait helper for tests so they don't have to import
# ``time`` themselves.
def _wait_for_predicate(
    predicate: Callable[[], bool], *, timeout: float = 2.0, poll: float = 0.02
) -> bool:
    """Test helper: spin-wait up to ``timeout`` seconds for
    ``predicate`` to return True. Returns whether it succeeded. Not
    exported in ``__all__`` — internal test-support."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(poll)
    return predicate()
