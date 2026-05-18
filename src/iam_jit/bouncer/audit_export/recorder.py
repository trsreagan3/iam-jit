"""Per-session audit recording — #285 ("session recording / playback").

A `SessionRecorder` tees every audit event to a per-session NDJSON file at
`{dir}/{agent.session_id}.ndjson`. The file is the portable, complete unit
of replay: another operator (or a Claude analyst, or a compliance auditor)
can feed it to `iam-jit session replay <FILE>` and walk the entire session
the agent drove against the bouncer.

Design notes
------------

* DEFAULT OFF. The proxy never tees unless the operator passes
  `--record-sessions-dir PATH` (or invokes `ibounce session record --dir
  PATH`). Recording captures agent-identity + operation details so the
  operator opts in deliberately, matching the audit-webhook posture.
* Per-session file shape: first line is a `_meta` JSON header (recording
  schema version + agent identity + bouncer product + recording start
  timestamp), followed by one OCSF event per line, append-only. The
  `.partial` suffix marks an in-flight recording; on the heartbeat-timeout
  rename, it drops the suffix atomically. A clean shutdown drops the
  suffix the same way. A SIGKILL leaves a `.partial` which the NEXT
  `start()` finalises on detection (5-minute staleness window).
* Cross-product alignment per ``cross-product-agent-parity``: every
  Bounce product ships the same on-disk shape so `iam-jit session
  replay` consumes any of them uniformly. Each language's writer is
  thin — the schema is the contract.
* File mode 0o600 (owner-read-only) — these contain agent identity +
  operation detail.
* Recording is ADDITIVE per `creates-never-mutates`: it tees the existing
  event stream and writes a flat NDJSON file; no SQL, no network, no
  mutation of any external surface.
* No network calls per `self-host-zero-billing-dependency`: entirely
  local filesystem.

Fail-soft posture mirrors `AuditLogWriter`: a broken disk records the
error on the status counter, never raises into the proxy hot path.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import re
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)


# Recording-file schema version. Bump when the on-disk shape changes in a
# way that older replay CLIs can't consume. The `_meta` header records this
# so the replay CLI surfaces a clear error rather than silently ignoring
# unknown fields.
RECORDING_SCHEMA_VERSION = "1.0"

# Suffix used while a session is still receiving events. The recorder
# renames atomically (drops the suffix) on a clean stop OR on heartbeat-
# timeout finalisation.
PARTIAL_SUFFIX = ".partial"

# Heartbeat default — sessions idle longer than this are considered ended
# (no event in 5 minutes → finalise). Matches the spec.
DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 300

# File permissions — owner read+write only. Recording files carry agent
# identity + operation details; treat as sensitive by default.
RECORDING_FILE_MODE = 0o600

# Allowed session_id chars. The session_id is the file name; we refuse any
# value that would let a writer escape the recording dir or shadow an
# unrelated file. UUIDs + hex + dashes only.
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def is_valid_session_id(session_id: Any) -> bool:
    """Return True if `session_id` is a safe filename fragment.

    The session_id reaches the recorder from the agent_context module
    (UUIDv7 by default) but defence-in-depth: an event whose
    `agent.session_id` got mangled upstream must not let us write outside
    the recording dir.
    """
    return isinstance(session_id, str) and bool(_SESSION_ID_RE.match(session_id))


def extract_session_id(event: dict[str, Any]) -> str | None:
    """Pull `unmapped.iam_jit.agent.session_id` out of an OCSF event.

    Returns None when:
    - the event has no `agent` block (non-MCP path; raw boto3 from a
      cron — there's no session to record)
    - the session_id is missing / null
    - the session_id fails validation (defence in depth)
    """
    try:
        agent = event["unmapped"]["iam_jit"]["agent"]
    except (KeyError, TypeError):
        return None
    sid = agent.get("session_id") if isinstance(agent, dict) else None
    if not is_valid_session_id(sid):
        return None
    return sid


def _meta_header(
    *,
    session_id: str,
    agent_name: str,
    bouncer_product: str,
    recording_started_at: str,
) -> dict[str, Any]:
    """Build the first-line `_meta` header. Kept here (not in event.py)
    because it's recording-specific, not part of the OCSF wire shape."""
    return {
        "_meta": {
            "recording_schema_version": RECORDING_SCHEMA_VERSION,
            "session_id": session_id,
            "agent_name": agent_name,
            "bouncer_product": bouncer_product,
            "recording_started_at": recording_started_at,
        }
    }


def _now_iso_utc() -> str:
    """ISO-8601 UTC with second precision. Matches the audit-event
    timestamp style and is round-trippable on every platform."""
    import datetime as _dt

    return (
        _dt.datetime.now(tz=_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class SessionRecorder:
    """Tee every audit event to a per-session NDJSON file.

    Lifecycle::

        recorder = SessionRecorder(
            dir="~/.iam-jit/sessions/",
            bouncer_product="ibounce",
        )
        recorder.start()
        recorder.record(event)        # called from _emit_audit_event_raw
        recorder.finalise_idle()      # called periodically; renames .partial
        recorder.stop()               # final-renames all open files + closes

    The recorder is intentionally SYNCHRONOUS. The audit-event hot path
    already runs the JSONL writer + webhook pusher off-thread (async
    queues); the recorder appends one line + closes nothing per write.
    Synchronous keeps the implementation simple + the file fsync-able by
    operators who care. If a benchmark surfaces material overhead we'll
    move to an async-queue shape (see CHANGELOG note for #285).

    Failure handling mirrors `AuditLogWriter`: errors are counted on
    `status()` and never propagate.
    """

    def __init__(
        self,
        *,
        dir: str | pathlib.Path,
        bouncer_product: str,
        heartbeat_timeout_seconds: int = DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
    ) -> None:
        self.dir = pathlib.Path(dir).expanduser()
        self.bouncer_product = bouncer_product
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        # Per-session open-file state: session_id -> dict with `fd`,
        # `partial_path`, `final_path`, `last_event_at`, `event_count`.
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._started = False
        # Stats — mirrors AuditLogWriter.status() shape so the MCP status
        # tool can surface recorder health uniformly.
        self._total_events = 0
        self._dropped_events = 0
        self._last_error: str | None = None
        self._last_error_at_unix: float | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Create the sessions dir (if missing) + finalise any stale
        `.partial` files left by a previous SIGKILL.

        Idempotent. On error we record + raise — start failure is up
        front; mid-flight failures are fail-soft on `record()`.
        """
        if self._started:
            return
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self._record_error(f"mkdir {self.dir}: {e}")
            raise
        # Best-effort permission tightening on the dir. We accept failure
        # (an operator-chosen umask might prefer wider) but tightening
        # by default matches the file-permission stance.
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        # Recover from prior SIGKILLs: any .partial older than the
        # heartbeat threshold gets finalised on the spot. Younger
        # .partials are left alone — they MIGHT be from a sibling
        # process recording a live session.
        self._finalise_stale_partials_locked = False  # debug flag for tests
        self._finalise_stale_partials()
        self._started = True

    def stop(self) -> None:
        """Finalise every still-open session + close fds. Idempotent."""
        if not self._started:
            return
        with self._lock:
            session_ids = list(self._sessions.keys())
        for sid in session_ids:
            self._finalise_session(sid)
        self._started = False

    # ------------------------------------------------------------------
    # Event tee
    # ------------------------------------------------------------------

    def record(self, event: dict[str, Any]) -> None:
        """Append `event` to its session's recording file.

        Called from the proxy's `_emit_audit_event_raw`. The recorder is
        wired ONLY when the operator passed `--record-sessions-dir`; the
        emit path no-ops otherwise.

        Events without a resolvable session_id (raw boto3 / pre-#266
        events / mangled agent block) are dropped silently. The dropped
        counter is bumped so the operator can spot misconfiguration.
        """
        if not self._started:
            return
        sid = extract_session_id(event)
        if sid is None:
            self._dropped_events += 1
            return
        try:
            self._write_event(sid, event)
            self._total_events += 1
        except OSError as e:
            self._record_error(f"write {sid}: {e}")
        except Exception as e:  # noqa: BLE001 — fail-soft per design
            self._record_error(f"record {sid}: {e}")

    def finalise_idle(self, *, now: float | None = None) -> list[str]:
        """Finalise any session whose last event is older than the
        heartbeat threshold. Returns the list of finalised session_ids.

        The proxy should call this periodically (the heartbeat tick is
        a natural fit). Tests can pass an explicit `now` to bypass the
        wall clock.
        """
        now = now if now is not None else time.time()
        finalised: list[str] = []
        with self._lock:
            stale = [
                sid for sid, meta in self._sessions.items()
                if (now - meta["last_event_at"]) > self.heartbeat_timeout_seconds
            ]
        for sid in stale:
            self._finalise_session(sid)
            finalised.append(sid)
        return finalised

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Snapshot of recorder health. Safe to call from any thread."""
        with self._lock:
            return {
                "configured": True,
                "dir": str(self.dir),
                "bouncer_product": self.bouncer_product,
                "active_sessions": len(self._sessions),
                "total_events": self._total_events,
                "dropped_events": self._dropped_events,
                "last_error": self._last_error,
                "last_error_at_unix": self._last_error_at_unix,
            }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _write_event(self, sid: str, event: dict[str, Any]) -> None:
        """Append one event to the session's .partial file. Opens +
        writes the `_meta` header on first event."""
        line = (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock:
            meta = self._sessions.get(sid)
            if meta is None:
                meta = self._open_session_locked(sid, event)
            os.write(meta["fd"], line)
            meta["last_event_at"] = time.time()
            meta["event_count"] += 1

    def _open_session_locked(
        self, sid: str, first_event: dict[str, Any]
    ) -> dict[str, Any]:
        """Open the per-session .partial file + write the `_meta`
        header. Must be called with `self._lock` held."""
        # Defence in depth — validate again at filename time. If a bug
        # upstream produced a bad sid we'd have dropped it already in
        # `record()`; this is the belt-and-braces against future paths.
        if not is_valid_session_id(sid):
            raise ValueError(f"invalid session_id for filename: {sid!r}")
        final_path = self.dir / f"{sid}.ndjson"
        partial_path = self.dir / f"{sid}.ndjson{PARTIAL_SUFFIX}"
        fd = os.open(
            str(partial_path),
            os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            RECORDING_FILE_MODE,
        )
        # Best-effort permission tightening — if the file pre-existed
        # with wider perms (operator created it manually), tighten to
        # 0o600 so we never leak agent identity to other users on the
        # box. Fail-soft on chmod denial (test environments / containers
        # sometimes refuse).
        try:
            os.fchmod(fd, RECORDING_FILE_MODE)
        except OSError:
            pass
        # Resolve the agent name from the FIRST event so the header
        # carries something useful. Subsequent events should all carry
        # the same agent (one session = one agent) but we don't enforce
        # — the spec says one file per session_id, not "one file per
        # session_id + agent_name".
        agent_name = self._extract_agent_name(first_event) or "unknown"
        header = _meta_header(
            session_id=sid,
            agent_name=agent_name,
            bouncer_product=self.bouncer_product,
            recording_started_at=_now_iso_utc(),
        )
        os.write(
            fd,
            (json.dumps(header, ensure_ascii=False) + "\n").encode("utf-8"),
        )
        meta = {
            "fd": fd,
            "partial_path": partial_path,
            "final_path": final_path,
            "last_event_at": time.time(),
            "event_count": 0,
        }
        self._sessions[sid] = meta
        return meta

    @staticmethod
    def _extract_agent_name(event: dict[str, Any]) -> str | None:
        try:
            return str(event["unmapped"]["iam_jit"]["agent"].get("name") or "")
        except (KeyError, TypeError):
            return None

    def _finalise_session(self, sid: str) -> None:
        """Close the fd + atomic-rename .partial → .ndjson. Idempotent."""
        with self._lock:
            meta = self._sessions.pop(sid, None)
        if meta is None:
            return
        try:
            os.close(meta["fd"])
        except OSError:
            pass
        partial = meta["partial_path"]
        final = meta["final_path"]
        try:
            if partial.exists():
                # os.replace is atomic on POSIX; preserves the final
                # path even if a stale final from a prior run lingered.
                os.replace(str(partial), str(final))
        except OSError as e:
            self._record_error(f"finalise {sid}: {e}")

    def _finalise_stale_partials(self) -> None:
        """On startup, finalise any `.partial` file older than the
        heartbeat threshold. This catches SIGKILL'd processes.

        Younger `.partial` files are left alone — they might be from a
        sibling process or a session about to receive its next event.
        """
        threshold = time.time() - self.heartbeat_timeout_seconds
        try:
            for entry in self.dir.iterdir():
                if not entry.name.endswith(PARTIAL_SUFFIX):
                    continue
                try:
                    mtime = entry.stat().st_mtime
                except OSError:
                    continue
                if mtime > threshold:
                    continue
                # Drop the .partial suffix atomically.
                final_path = entry.with_suffix("")  # strips .partial
                # `.ndjson.partial` → `.ndjson` (with_suffix replaces the
                # last suffix only, which is `.partial` here).
                try:
                    os.replace(str(entry), str(final_path))
                except OSError as e:
                    self._record_error(
                        f"finalise stale {entry.name}: {e}"
                    )
        except OSError:
            # Directory disappeared between mkdir + iter — race-safe; we
            # surface no error because the next start() will recreate.
            pass

    def _record_error(self, msg: str) -> None:
        with self._lock:
            self._last_error = msg
            self._last_error_at_unix = time.time()
        logger.warning("session recorder error: %s", msg)


# ---------------------------------------------------------------------------
# Listing / reading helpers — power `ibounce session list / show / export`
# + the cross-product `iam-jit session replay`. Kept here so the on-disk
# shape stays in lockstep with the writer above.
# ---------------------------------------------------------------------------


def _safe_relative_resolve(base: pathlib.Path, candidate: pathlib.Path) -> pathlib.Path:
    """Resolve `candidate` and refuse traversal outside `base`.

    Defence against an operator passing `../../etc/passwd` as a session
    id to the `show` / `export` subcommands; we always restrict reads
    to within the recordings directory.
    """
    resolved = candidate.resolve()
    base_resolved = base.resolve()
    try:
        resolved.relative_to(base_resolved)
    except ValueError as e:
        raise ValueError(
            f"path {candidate} escapes recordings directory {base}"
        ) from e
    return resolved


def list_sessions(dir: str | pathlib.Path) -> list[dict[str, Any]]:
    """List recorded sessions in `dir`.

    Returns a list of dicts with `session_id`, `agent_name`,
    `bouncer_product`, `event_count`, `start`, `end`, `is_partial`,
    `path`. Robust against empty dirs (returns []) and unreadable files
    (silently skipped + logged at debug).
    """
    base = pathlib.Path(dir).expanduser()
    if not base.exists():
        return []
    rows: list[dict[str, Any]] = []
    for entry in sorted(base.iterdir()):
        name = entry.name
        if name.endswith(".ndjson"):
            is_partial = False
        elif name.endswith(".ndjson" + PARTIAL_SUFFIX):
            is_partial = True
        else:
            continue
        try:
            row = _summarise_recording(entry, is_partial=is_partial)
        except Exception as e:  # noqa: BLE001
            logger.debug("skipping unreadable recording %s: %s", entry, e)
            continue
        rows.append(row)
    return rows


def _summarise_recording(path: pathlib.Path, *, is_partial: bool) -> dict[str, Any]:
    """One-pass scan for header + counts + first/last timestamps."""
    meta: dict[str, Any] = {}
    event_count = 0
    start_ts: int | None = None
    end_ts: int | None = None
    with path.open("r", encoding="utf-8") as fh:
        for i, raw in enumerate(fh):
            line = raw.rstrip("\n")
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Tolerate the occasional truncated line at EOF of a
                # killed recorder; everything we successfully parsed
                # counts. List output is best-effort + advisory.
                continue
            if i == 0 and isinstance(obj, dict) and "_meta" in obj:
                meta = obj["_meta"]
                continue
            event_count += 1
            t = obj.get("time")
            if isinstance(t, (int, float)):
                t_int = int(t)
                if start_ts is None:
                    start_ts = t_int
                end_ts = t_int
    return {
        "session_id": meta.get("session_id") or path.stem.replace(".ndjson", ""),
        "agent_name": meta.get("agent_name", "unknown"),
        "bouncer_product": meta.get("bouncer_product", "unknown"),
        "recording_schema_version": meta.get(
            "recording_schema_version", "unknown",
        ),
        "recording_started_at": meta.get("recording_started_at"),
        "event_count": event_count,
        "start_ms": start_ts,
        "end_ms": end_ts,
        "is_partial": is_partial,
        "path": str(path),
    }


def read_session(
    dir: str | pathlib.Path, session_id: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load a single recording: returns `(meta, events)`.

    Used by `ibounce session show / export` and by the cross-product
    replay CLI. Raises `FileNotFoundError` if no matching file exists +
    `ValueError` if the path would escape the recordings dir.
    """
    base = pathlib.Path(dir).expanduser()
    if not is_valid_session_id(session_id):
        raise ValueError(f"invalid session_id: {session_id!r}")
    candidate_final = base / f"{session_id}.ndjson"
    candidate_partial = base / f"{session_id}.ndjson{PARTIAL_SUFFIX}"
    chosen: pathlib.Path | None = None
    for c in (candidate_final, candidate_partial):
        if c.exists():
            chosen = _safe_relative_resolve(base, c)
            break
    if chosen is None:
        raise FileNotFoundError(
            f"no recording for session {session_id} in {base}"
        )
    return read_session_file(chosen)


def read_session_file(
    path: str | pathlib.Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load a recording file by direct path. Returns `(meta, events)`.

    Used by `iam-jit session replay <FILE>` — the operator passes an
    explicit path, possibly shared from another box, so we DON'T require
    the file live inside a recordings dir.
    """
    p = pathlib.Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"recording file not found: {p}")
    meta: dict[str, Any] = {}
    events: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as fh:
        for i, raw in enumerate(fh):
            line = raw.rstrip("\n")
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"corrupt recording at line {i + 1}: {e}"
                ) from e
            if i == 0 and isinstance(obj, dict) and "_meta" in obj:
                meta = obj["_meta"]
                continue
            events.append(obj)
    return meta, events


def event_count_by_type(events: list[dict[str, Any]]) -> dict[str, int]:
    """Count events by `class_name` / `activity_name` for `session show`."""
    counts: dict[str, int] = {}
    for ev in events:
        key = (
            ev.get("activity_name")
            or ev.get("class_name")
            or ev.get("type_name")
            or "unknown"
        )
        counts[str(key)] = counts.get(str(key), 0) + 1
    return counts


def purge_older_than(
    dir: str | pathlib.Path, *, older_than_seconds: int, now: float | None = None
) -> list[str]:
    """Delete recordings whose mtime is older than `older_than_seconds`.

    Returns the list of removed paths (as strings). Skips `.partial`
    files — those represent active or recently-killed sessions and the
    `start()` recovery path is the right place to deal with them.
    """
    base = pathlib.Path(dir).expanduser()
    if not base.exists():
        return []
    threshold = (now if now is not None else time.time()) - older_than_seconds
    removed: list[str] = []
    for entry in base.iterdir():
        if not entry.name.endswith(".ndjson"):
            continue
        try:
            if entry.stat().st_mtime > threshold:
                continue
            entry.unlink()
            removed.append(str(entry))
        except OSError as e:
            logger.debug("purge skip %s: %s", entry, e)
    return removed


def detection_finding_from_session(
    meta: dict[str, Any], events: list[dict[str, Any]]
) -> dict[str, Any]:
    """Wrap a session recording into an OCSF Detection Finding envelope.

    Matches the #273 investigate-with-claude evidence shape so a session
    exported via `ibounce session export` is the same wire shape as the
    bundles cross-tool investigations produce. The recording events ride
    on the finding's `unmapped.iam_jit.session.events` array; the
    finding's own `time` / `start_time_dt` / `end_time_dt` bracket the
    session window.
    """
    start_ms = None
    end_ms = None
    for ev in events:
        t = ev.get("time")
        if isinstance(t, (int, float)):
            t_int = int(t)
            if start_ms is None:
                start_ms = t_int
            end_ms = t_int
    return {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": meta.get("bouncer_product", "ibounce"),
                "vendor_name": "iam-jit.com",
            },
        },
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
        "severity_id": 1,
        "severity": "Informational",
        "time": end_ms or start_ms or 0,
        "start_time": start_ms,
        "end_time": end_ms,
        "finding_info": {
            "title": (
                f"session recording: {meta.get('session_id', 'unknown')}"
            ),
            "uid": meta.get("session_id", "unknown"),
        },
        "unmapped": {
            "iam_jit": {
                "session": {
                    "session_id": meta.get("session_id"),
                    "agent_name": meta.get("agent_name"),
                    "bouncer_product": meta.get("bouncer_product"),
                    "recording_schema_version": meta.get(
                        "recording_schema_version"
                    ),
                    "recording_started_at": meta.get("recording_started_at"),
                    "event_count": len(events),
                    "events": events,
                }
            }
        },
    }


__all__ = [
    "DEFAULT_HEARTBEAT_TIMEOUT_SECONDS",
    "PARTIAL_SUFFIX",
    "RECORDING_FILE_MODE",
    "RECORDING_SCHEMA_VERSION",
    "SessionRecorder",
    "detection_finding_from_session",
    "event_count_by_type",
    "extract_session_id",
    "is_valid_session_id",
    "list_sessions",
    "purge_older_than",
    "read_session",
    "read_session_file",
]
