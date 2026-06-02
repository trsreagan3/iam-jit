"""Disk-pressure circuit-breaker policy layer — #424 / §A63.

Closes the LAUNCH-BLOCKER §A63 gap that until this slice landed, the
:func:`disk_status` primitive (rotation.py:381, shipped in #311) was
ONLY consulted by the ``*bounce doctor logs`` CLI. The proxy's
``/healthz`` handler ignored disk state, no periodic check fired
between operator-invoked CLI runs, and the documented
``--stop-on-disk-critical`` flag was a ghost reference. A bouncer
sitting on a 99 %-full disk would silently fail audit writes, losing
the compliance value the audit log is supposed to provide.

Three operator-selectable modes per the §A63 spec:

  * ``pause-requests`` (compliance-heavy default) — at ``critical``
    threshold the proxy REFUSES new agent requests with HTTP 503 +
    a structured ``bouncer paused: disk pressure`` body. Audit
    integrity prioritised over liveness. Per
    `[[creates-never-mutates]]` we don't drop archives or mutate
    existing state.

  * ``rotate-aggressively`` (dev default) — at ``critical`` threshold
    the policy drops the oldest rotated ``audit-*.jsonl.gz`` /
    ``audit-*.db.gz`` archives until disk usage falls back below the
    ``warn`` threshold. Liveness prioritised over historical retention.
    Calls :func:`_drop_oldest_archives` directly (additive — we
    never touch the active ``audit.jsonl`` / ``audit.db``).

  * ``archive-and-purge`` (hybrid) — at ``critical`` threshold the
    policy emits an admin-action event signaling oldest-archive
    candidates are eligible for upload by the operator's #317
    object-storage sink, THEN drops the oldest local archives to
    reclaim space. Operators wire ``--audit-object-storage-*`` flags
    independently; the modes don't double-couple to S3 SDK calls.

State transitions are recorded as OCSF v1.1.0 class 6003
admin-action events with kind ``disk_pressure.transition`` so the
SIEM dashboard answers "when did the bouncer cross into critical /
emergency / recover to ok?" from the same stream that carries
proxy decisions + admin actions.

Per [[ambient-value-prop-and-friction-framing]] the framing here is
"your bouncer is approaching disk threshold, consider archiving"
rather than "ERROR: disk pressure". Operator-facing message bodies
follow that pattern; refusal bodies (pause-requests mode) explain
WHY the refusal happened + what to configure to change behavior.

Per [[ibounce-honest-positioning]] every state transition surfaces
on /healthz audit_log.status + posture report + autopilot status
file. Don't hide disk state from operators.

Per [[v1-scope-bar]] this module reuses the existing
:func:`disk_status` primitive and :func:`purge_older_than` helper
from rotation.py — no rotation architecture redesign, no new
compression formats, no hash-chain coupling. The policy layer is
THIN: it sequences existing primitives based on the operator's
declared mode.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import pathlib
import time
from typing import Any, Callable

from .rotation import (
    DEFAULT_DISK_CRIT_FREE_BYTES,
    DEFAULT_DISK_CRIT_PCT,
    DEFAULT_DISK_WARN_FREE_BYTES,
    DEFAULT_DISK_WARN_PCT,
    DiskStatus,
    disk_status,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mode constants
# ---------------------------------------------------------------------------

# Operator-selectable disk-pressure response modes. Values match the
# YAML field `disk_pressure_mode:` documented in PRODUCTION-LOG-STORAGE.md.
# Per [[cross-product-agent-parity]] kbounce / dbounce / gbounce
# reimplement these in Go with the SAME string values so a single
# `disk_pressure_mode: pause-requests` row in apply-config YAML works
# across all four bouncers.
DISK_PRESSURE_MODE_PAUSE_REQUESTS = "pause-requests"
DISK_PRESSURE_MODE_ROTATE_AGGRESSIVELY = "rotate-aggressively"
DISK_PRESSURE_MODE_ARCHIVE_AND_PURGE = "archive-and-purge"

KNOWN_DISK_PRESSURE_MODES: frozenset[str] = frozenset({
    DISK_PRESSURE_MODE_PAUSE_REQUESTS,
    DISK_PRESSURE_MODE_ROTATE_AGGRESSIVELY,
    DISK_PRESSURE_MODE_ARCHIVE_AND_PURGE,
})

# Default mode when the operator hasn't picked one. Compliance-heavy
# default because the audit log IS the compliance value
# ([[self-host-zero-billing-dependency]]) — losing events to make room
# for new traffic inverts the whole point. Operators who prefer the
# liveness tradeoff opt in to rotate-aggressively.
DEFAULT_DISK_PRESSURE_MODE = DISK_PRESSURE_MODE_PAUSE_REQUESTS

# Periodic check interval (seconds). 60s matches the §A63 spec; small
# enough that a runaway-disk event hits the policy within one tick,
# large enough that the check isn't a meaningful load (one statvfs
# per minute).
DISK_PRESSURE_CHECK_INTERVAL_SECONDS = 60

# Emergency threshold — ABOVE crit. Operators see this as "disk is
# basically full; even rotate-aggressively can't keep up." Used by
# /healthz to surface a distinct status string + by the admin-action
# emit to escalate severity. ALL modes treat emergency the same way:
# log + emit + signal in /healthz; no mode is permitted to "ignore"
# emergency. Must be strictly greater than DEFAULT_DISK_CRIT_PCT so
# that 98.5% maps to "critical" not "emergency".
DEFAULT_DISK_EMERGENCY_PCT = 99

# Admin-action kind emitted on state transitions. Lands in
# unmapped.iam_jit.admin_action.kind + activity_name per
# [[ocsf-audit-schema]]. SIEM rules keyed on
# `action == "disk_pressure.transition"` catch every transition
# regardless of direction or mode.
ADMIN_ACTION_DISK_PRESSURE_TRANSITION = "disk_pressure.transition"

# Refusal body the proxy returns in pause-requests mode when
# critical/emergency. Framed per
# [[ambient-value-prop-and-friction-framing]] — explains what
# happened + how to change behavior, doesn't say "ERROR" or "BLOCKED".
PAUSE_REQUESTS_REFUSAL_REASON_TEMPLATE = (
    "bouncer paused — disk pressure at {used_pct:.1f}% used "
    "(threshold {crit_pct}%); audit-log writes would risk loss if "
    "we forwarded. Configure "
    "disk_pressure_mode=rotate-aggressively or "
    "archive-and-purge to change behavior, or clear space + restart."
)


# ---------------------------------------------------------------------------
# State container
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class DiskPressureState:
    """Live state for one bouncer's disk-pressure subsystem.

    Stored in-process; not persisted. On restart the periodic check
    re-detects state from the filesystem. Per [[ibounce-honest-
    positioning]] /healthz reads this directly so external monitoring
    sees the same view the proxy uses for refusal decisions.
    """

    mode: str = DEFAULT_DISK_PRESSURE_MODE
    """Operator-declared mode. One of KNOWN_DISK_PRESSURE_MODES."""

    current_status: str = "ok"
    """Last-observed DiskStatus.status — "ok", "degraded", "critical",
    "emergency". "emergency" is added by this layer (rotation.py's
    disk_status returns at most "critical"; emergency is computed
    from used_pct >= emergency_pct). "degraded" mirrors rotation.py's
    "degraded" (between warn and crit thresholds)."""

    last_observed: DiskStatus | None = None
    """Last DiskStatus snapshot from disk_status(). None until first
    check fires."""

    last_check_unix: float = 0.0
    """Unix time of the last periodic check. 0 before first check."""

    warn_pct: int = DEFAULT_DISK_WARN_PCT
    crit_pct: int = DEFAULT_DISK_CRIT_PCT
    emergency_pct: int = DEFAULT_DISK_EMERGENCY_PCT

    warn_free_bytes: int = DEFAULT_DISK_WARN_FREE_BYTES
    """Absolute-free-space floor for the warn threshold. Status transitions
    to "degraded" when free_bytes <= this value (and warn_free_bytes > 0).
    0 disables the absolute-free check for the warn tier."""

    crit_free_bytes: int = DEFAULT_DISK_CRIT_FREE_BYTES
    """Absolute-free-space floor for the critical threshold. Status
    transitions to "critical" when free_bytes <= this value (and
    crit_free_bytes > 0). 0 disables the absolute-free check for the
    critical tier."""

    ignore_disk_pressure: bool = False
    """When True, the disk-pressure check is disabled entirely.
    EvaluateAndReact always returns status="ignored" + refuse_requests=False.
    A startup warning is emitted when this flag is set. Surfaced on /healthz
    as status="ignored" so monitoring is never silently bypassed."""

    log_dir: str | None = None
    """Directory containing audit.jsonl + rotated archives. None when
    audit_log_path is unset; in that case the policy layer is a no-op
    (nothing to monitor)."""

    refuse_requests: bool = False
    """True when the proxy hot path should return 503 instead of
    forwarding. Computed from (mode, current_status). Read by
    _handle_request before forwarding."""

    transitions_count: int = 0
    """Total state transitions observed since startup. Surfaced on
    /healthz so monitoring can see "flapping" deployments."""

    last_action_taken: str | None = None
    """Short human-readable description of the most recent automated
    action ('refused N requests', 'dropped 3 archives', etc). Surfaced
    on /healthz for operator visibility."""

    archive_count: int = 0
    """Count of audit-*.jsonl.gz + audit-*.db.gz files in log_dir as
    of last check. 0 when log_dir is None."""

    archive_size_bytes: int = 0
    """Total bytes of archive files (rotated only; not the active
    log) as of last check."""

    object_storage_writer: Any | None = None
    """#501 fix: optional ObjectStorageWriter instance for the
    archive-and-purge mode. When set, archives are shipped to the
    configured object-storage sink BEFORE local drop. When None and
    mode is archive-and-purge, the mode refuses to drop + emits a
    CRIT log warning + falls back to pause-requests behavior (safer
    default — never silently delete data when no upload path exists)."""

    def status_label(self) -> str:
        """Human-readable status for /healthz + posture output.
        Adds the 'emergency' tier on top of rotation.py's ok/degraded/
        critical scale."""
        return self.current_status


def _resolve_log_dir(audit_log_path: str | None) -> str | None:
    """Map ProxyConfig.audit_log_path (file path) to the directory
    that holds it + the rotated archives. None when audit logging is
    disabled. Returns the parent dir even if the file doesn't yet
    exist (the first event creates it)."""
    if not audit_log_path:
        return None
    p = pathlib.Path(audit_log_path)
    parent = p.parent if p.suffix else p
    return str(parent)


def _count_archives(log_dir: str | None) -> tuple[int, int]:
    """Return (file_count, total_bytes) of rotated archives in
    log_dir. Skips the active audit.jsonl + audit.db. Returns (0, 0)
    when log_dir is None or unreadable."""
    if not log_dir:
        return 0, 0
    p = pathlib.Path(log_dir)
    if not p.is_dir():
        return 0, 0
    count = 0
    total = 0
    try:
        for child in p.iterdir():
            n = child.name
            if not (n.startswith("audit-") and (
                n.endswith(".jsonl.gz")
                or n.endswith(".db.gz")
                or n.endswith(".db")
            )):
                continue
            try:
                total += child.stat().st_size
                count += 1
            except OSError:
                continue
    except OSError:
        return 0, 0
    return count, total


def _drop_oldest_archives(
    log_dir: str,
    *,
    target_free_pct: int,
    statvfs: Any | None = None,
) -> list[pathlib.Path]:
    """Drop the oldest rotated archives until disk free pct >=
    target_free_pct OR no archives remain. Returns the list of paths
    removed.

    `statvfs` is an injection seam for tests (3-tuple of
    (total, used, free) bytes). Re-stats after each delete so the loop
    exits as soon as headroom returns. Per [[creates-never-mutates]]
    NEVER touches the active audit.jsonl / audit.db; only
    audit-*.jsonl.gz / audit-*.db.gz / audit-*.db.

    Used by rotate-aggressively + archive-and-purge modes; pause-requests
    does NOT call this (its whole point is to preserve audit data
    over liveness).
    """
    d = pathlib.Path(log_dir)
    if not d.is_dir():
        return []
    archives: list[pathlib.Path] = []
    try:
        for child in d.iterdir():
            n = child.name
            if n.startswith("audit-") and (
                n.endswith(".jsonl.gz")
                or n.endswith(".db.gz")
                or n.endswith(".db")
            ):
                archives.append(child)
    except OSError:
        return []
    # Oldest first by mtime.
    archives.sort(key=lambda c: c.stat().st_mtime if c.exists() else 0)
    removed: list[pathlib.Path] = []
    for child in archives:
        cur_status = disk_status(
            d, warn_pct=100 - target_free_pct, crit_pct=100,
            statvfs=statvfs,
        )
        if cur_status.used_pct < (100 - target_free_pct):
            break
        try:
            child.unlink()
            removed.append(child)
        except OSError:
            continue
    return removed


def _ship_archives_to_object_storage(
    archives: list[pathlib.Path],
    writer: Any,
) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    """Attempt to ship each archive in ``archives`` to the object-storage
    sink ``writer`` (an ObjectStorageWriter instance). Returns a 2-tuple of
    (shipped, failed) path lists.

    Each archive is read as raw bytes, wrapped in a single OCSF-envelope
    admin-action event, and flushed via writer.write() + writer.flush().
    This is the #501 fix: archive-and-purge mode calls this BEFORE
    _drop_oldest_archives so the operator's sink receives the data
    before local deletion.

    Fail-soft: a single archive upload failure doesn't abort the rest
    of the list — each archive is independent. The caller decides
    whether to drop archives that failed shipping (current policy: do
    NOT drop on upload failure to avoid silent data loss; the caller
    skips failed archives from the drop list).
    """
    shipped: list[pathlib.Path] = []
    failed: list[pathlib.Path] = []
    for archive in archives:
        try:
            # Read the archive as raw bytes and emit as a single
            # admin-action event carrying the archive content. This
            # preserves the full OCSF event stream in the object-storage
            # bucket at the cost of double-encoding the gzip payload as
            # a base64 string inside JSON. Operators who want the raw
            # NDJSON layout use the dedicated #317 S3 sink rotation path;
            # this path is specifically for the disk-pressure emergency
            # "get data off disk before drop" use case.
            import base64
            raw = archive.read_bytes()
            event = {
                "class_uid": 6003,
                "activity_name": "disk_pressure.archive_and_purge_ship",
                "unmapped": {
                    "iam_jit": {
                        "archive_filename": archive.name,
                        "archive_bytes_base64": base64.b64encode(raw).decode("ascii"),
                    },
                },
            }
            writer.write(event)
            writer.flush()
            shipped.append(archive)
        except Exception as e:  # pragma: no cover — fail-soft
            logger.warning(
                "archive-and-purge: failed to ship %s to object-storage: %s",
                archive.name, e,
            )
            failed.append(archive)
    return shipped, failed


def _compute_status(
    snap: DiskStatus,
    *,
    warn_pct: int,
    crit_pct: int,
    emergency_pct: int,
) -> str:
    """Map a DiskStatus snapshot to one of ok/degraded/critical/
    emergency. The rotation.py disk_status returns at most critical;
    we add the emergency tier on top so the proxy can surface a more
    severe state without changing the underlying primitive."""
    if snap.status == "ok":
        return "ok"
    if snap.used_pct >= emergency_pct:
        return "emergency"
    if snap.used_pct >= crit_pct:
        return "critical"
    if snap.used_pct >= warn_pct:
        return "degraded"
    return snap.status  # "degraded" fallback for non-numeric paths


def _compute_refuse_requests(mode: str, current_status: str) -> bool:
    """Single source of truth for "should the proxy refuse new
    requests now?" Used by both the periodic loop (when it updates
    state.refuse_requests) and the smoke tests (which assert the same
    mapping). pause-requests refuses at critical or emergency; the
    other two modes never refuse — they react via rotation."""
    if mode != DISK_PRESSURE_MODE_PAUSE_REQUESTS:
        return False
    return current_status in ("critical", "emergency")


def evaluate_and_react(
    state: DiskPressureState,
    *,
    emit: Callable[[dict], None] | None = None,
    statvfs: Any | None = None,
    now: float | None = None,
) -> DiskPressureState:
    """Run one tick of the disk-pressure check + reaction.

    1. statvfs the log directory (via disk_status).
    2. Compute current_status (adds emergency tier on top of
       rotation.py's ok/degraded/critical).
    3. If status transitioned vs state.current_status, emit an
       admin-action ``disk_pressure.transition`` OCSF event.
    4. Apply mode-specific behavior at critical/emergency:
        - pause-requests: flip state.refuse_requests = True
        - rotate-aggressively: drop oldest archives to recover
        - archive-and-purge: emit hint + drop oldest archives
    5. Re-stat archive_count + archive_size_bytes for /healthz.

    Returns the mutated state for chaining + test inspection.

    Per [[deliberate-feature-completion]] the function is the FULL
    reaction surface — the periodic loop calls this once per tick
    and the smoke tests invoke it directly. No half-reaction paths.
    """
    state.last_check_unix = now if now is not None else time.time()
    if state.ignore_disk_pressure:
        # Operator explicitly opted out of disk-pressure protection.
        # Always report "ignored" + never refuse requests. /healthz
        # exposes this status so monitoring is never silently bypassed.
        state.current_status = "ignored"
        state.refuse_requests = False
        return state
    if not state.log_dir:
        # Nothing to monitor. Leave state at ok + refuse_requests off.
        state.current_status = "ok"
        state.refuse_requests = False
        return state
    snap = disk_status(
        state.log_dir,
        warn_pct=state.warn_pct,
        crit_pct=state.crit_pct,
        warn_free_bytes=state.warn_free_bytes,
        crit_free_bytes=state.crit_free_bytes,
        statvfs=statvfs,
    )
    state.last_observed = snap
    new_status = _compute_status(
        snap,
        warn_pct=state.warn_pct,
        crit_pct=state.crit_pct,
        emergency_pct=state.emergency_pct,
    )
    # Refresh archive accounting (cheap; one iterdir).
    state.archive_count, state.archive_size_bytes = _count_archives(
        state.log_dir,
    )
    transitioned = new_status != state.current_status
    prior_status = state.current_status
    state.current_status = new_status
    if transitioned:
        state.transitions_count += 1
        _emit_transition_event(
            emit=emit,
            from_status=prior_status,
            to_status=new_status,
            snap=snap,
            mode=state.mode,
            log_dir=state.log_dir,
        )
    # Mode reactions only fire at critical / emergency. ok / degraded
    # do nothing automatic — degraded is the operator-action signal
    # (per the LOG-RETENTION.md runbook).
    state.refuse_requests = _compute_refuse_requests(
        state.mode, state.current_status,
    )
    if new_status in ("critical", "emergency"):
        if state.mode == DISK_PRESSURE_MODE_PAUSE_REQUESTS:
            state.last_action_taken = (
                f"refusing new agent requests at {snap.used_pct:.1f}% used"
            )
        elif state.mode == DISK_PRESSURE_MODE_ROTATE_AGGRESSIVELY:
            removed = _drop_oldest_archives(
                state.log_dir,
                target_free_pct=max(100 - state.warn_pct, 5),
                statvfs=statvfs,
            )
            state.last_action_taken = (
                f"dropped {len(removed)} oldest archive(s) to recover "
                f"space at {snap.used_pct:.1f}% used"
            )
            # Re-stat post-drop so /healthz shows the recovered shape.
            state.archive_count, state.archive_size_bytes = _count_archives(
                state.log_dir,
            )
        elif state.mode == DISK_PRESSURE_MODE_ARCHIVE_AND_PURGE:
            # #501 fix: archive-and-purge now ACTUALLY ships archives to
            # the object-storage sink before dropping locals. If no sink
            # is configured, refuse to drop + emit CRIT + fall back to
            # pause-requests behavior (safer — never silently delete data
            # when there is no upload path).
            if state.object_storage_writer is None:
                # No sink configured: refuse to drop. Flip refuse_requests
                # so the proxy surfaces a 503 with an explanatory body
                # telling the operator to configure a sink or switch modes.
                state.refuse_requests = True
                state.last_action_taken = (
                    f"archive-and-purge: CRIT — no object-storage sink "
                    f"configured; refusing to drop local archives. "
                    f"Configure --audit-object-storage-* flags to enable "
                    f"shipping, or switch to rotate-aggressively / "
                    f"pause-requests mode. Disk at {snap.used_pct:.1f}% used."
                )
                logger.critical(
                    "disk_pressure archive-and-purge: no object_storage_writer "
                    "configured; falling back to pause-requests behavior at "
                    "%.1f%% used. Configure an object-storage sink or change "
                    "disk_pressure_mode to rotate-aggressively or pause-requests.",
                    snap.used_pct,
                )
            else:
                # Collect the oldest archive candidates (same set that
                # _drop_oldest_archives would remove).
                d = pathlib.Path(state.log_dir)
                candidates: list[pathlib.Path] = []
                try:
                    for child in d.iterdir():
                        n_name = child.name
                        if n_name.startswith("audit-") and (
                            n_name.endswith(".jsonl.gz")
                            or n_name.endswith(".db.gz")
                            or n_name.endswith(".db")
                        ):
                            candidates.append(child)
                except OSError:
                    candidates = []
                candidates.sort(
                    key=lambda c: c.stat().st_mtime if c.exists() else 0,
                )
                # Ship BEFORE drop.
                shipped, failed = _ship_archives_to_object_storage(
                    candidates, state.object_storage_writer,
                )
                # Only drop archives that were successfully shipped.
                # Never drop archives that failed upload (avoid silent
                # data loss). Drop from oldest first.
                shipped_set = set(shipped)
                removed: list[pathlib.Path] = []
                for archive in candidates:
                    if archive not in shipped_set:
                        continue
                    try:
                        archive.unlink()
                        removed.append(archive)
                    except OSError as e:
                        logger.warning(
                            "archive-and-purge: drop failed for %s: %s",
                            archive.name, e,
                        )
                state.last_action_taken = (
                    f"archive-and-purge: shipped {len(shipped)} archive(s) "
                    f"to object-storage, dropped {len(removed)} locally "
                    f"({len(failed)} failed to ship + were kept) "
                    f"at {snap.used_pct:.1f}% used"
                )
                state.archive_count, state.archive_size_bytes = _count_archives(
                    state.log_dir,
                )
    else:
        state.last_action_taken = None
    return state


def _emit_transition_event(
    *,
    emit: Callable[[dict], None] | None,
    from_status: str,
    to_status: str,
    snap: DiskStatus,
    mode: str,
    log_dir: str,
) -> None:
    """Emit the admin-action disk_pressure.transition OCSF event.

    Fail-soft: if the audit-export channel isn't installed or the emit
    raises, we log + continue. Per [[deliberate-feature-completion]]
    + [[ibounce-honest-positioning]] the operator still sees the
    transition on /healthz even if the SIEM emit fails."""
    if emit is None:
        return
    try:
        from .admin_action import (
            ADMIN_ACTION_SOURCE_API,
            make_admin_action_event,
        )
        evt = make_admin_action_event(
            kind=ADMIN_ACTION_DISK_PRESSURE_TRANSITION,
            actor=None,
            actor_uid=None,
            target_kind="audit_log_directory",
            target_id=log_dir,
            target_extra={
                "from_status": from_status,
                "to_status": to_status,
                "used_pct": round(snap.used_pct, 2),
                "mode": mode,
            },
            before={"status": from_status},
            after={
                "status": to_status,
                "used_pct": round(snap.used_pct, 2),
            },
            source=ADMIN_ACTION_SOURCE_API,
            extra={
                "reason": snap.reason,
                "path": snap.path,
            },
        )
        emit(evt)
    except Exception as e:  # pragma: no cover — fail-soft path
        logger.warning(
            "disk_pressure transition emit failed (%s -> %s): %s",
            from_status, to_status, e,
        )


def healthz_audit_log_block(state: DiskPressureState) -> dict[str, Any]:
    """Build the /healthz `audit_log` block from a DiskPressureState
    snapshot. Surfaces per the §A63 spec + the LOG-RETENTION.md
    `/healthz` integration example.

    Per [[ibounce-honest-positioning]] when audit logging is disabled
    we still emit the block (with disk_free_pct=null + status="ok")
    so monitoring parsers can branch on a single field without
    checking "is the block present?" first. Matches the audit_export
    block shape (also always-present)."""
    if state.last_observed is None:
        disk_free_pct: float | None = None
        used_pct: float | None = None
        path: str | None = state.log_dir
    else:
        disk_free_pct = round(100.0 - state.last_observed.used_pct, 2)
        used_pct = round(state.last_observed.used_pct, 2)
        path = state.last_observed.path
    disk_free_bytes: int | None = (
        state.last_observed.free_bytes if state.last_observed else None
    )
    return {
        "status": state.status_label(),
        "disk_free_pct": disk_free_pct,
        "disk_free_bytes": disk_free_bytes,
        "used_pct": used_pct,
        "warn_pct": state.warn_pct,
        "crit_pct": state.crit_pct,
        "emergency_pct": state.emergency_pct,
        "warn_threshold_bytes": state.warn_free_bytes,
        "crit_threshold_bytes": state.crit_free_bytes,
        "ignore_disk_pressure": state.ignore_disk_pressure,
        "path": path,
        "disk_pressure_mode": state.mode,
        "refuse_requests": state.refuse_requests,
        "current_archive_count": state.archive_count,
        "current_archive_size_bytes": state.archive_size_bytes,
        "transitions_count": state.transitions_count,
        "last_check_unix": int(state.last_check_unix) if state.last_check_unix else None,
        "last_action_taken": state.last_action_taken,
        "reason": state.last_observed.reason if state.last_observed else None,
    }


def normalize_mode(value: str | None) -> str:
    """Validate + normalize the operator's mode input.

    Returns the canonical mode string. Raises ValueError on unknown
    values so the CLI / apply-config layer fails fast with a clear
    message. None or empty string returns the default (compliance-
    heavy pause-requests)."""
    if value is None or value == "":
        return DEFAULT_DISK_PRESSURE_MODE
    norm = value.strip().lower()
    if norm not in KNOWN_DISK_PRESSURE_MODES:
        raise ValueError(
            f"unknown disk_pressure_mode {value!r}; expected one of "
            f"{sorted(KNOWN_DISK_PRESSURE_MODES)}"
        )
    return norm


__all__ = [
    "ADMIN_ACTION_DISK_PRESSURE_TRANSITION",
    "DEFAULT_DISK_EMERGENCY_PCT",
    "DEFAULT_DISK_PRESSURE_MODE",
    "DISK_PRESSURE_CHECK_INTERVAL_SECONDS",
    "DISK_PRESSURE_MODE_ARCHIVE_AND_PURGE",
    "DISK_PRESSURE_MODE_PAUSE_REQUESTS",
    "DISK_PRESSURE_MODE_ROTATE_AGGRESSIVELY",
    "DiskPressureState",
    "KNOWN_DISK_PRESSURE_MODES",
    "PAUSE_REQUESTS_REFUSAL_REASON_TEMPLATE",
    "_compute_refuse_requests",
    "_compute_status",
    "_count_archives",
    "_drop_oldest_archives",
    "_resolve_log_dir",
    "_ship_archives_to_object_storage",
    "evaluate_and_react",
    "healthz_audit_log_block",
    "normalize_mode",
]
