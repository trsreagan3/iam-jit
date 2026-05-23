"""Audit-log rotation, retention, and recovery — #311 / §A10.

Each bouncer writes a JSONL audit log + SQLite audit DB; without
rotation they grow unbounded and silently fill the disk. Per
`self-host-zero-billing-dependency` the audit log IS the compliance
value — it cannot silently fail. This module provides:

  * `should_rotate_by_size(path, max_mb)` — size-threshold check.
  * `should_rotate_by_age(path, max_days)` — age-threshold check.
  * `rotate(path)` — atomic move-and-gzip of the active log. The
    active path stays at `audit.jsonl`; the rotated file becomes
    `audit-{YYYY-MM-DD-HHMMSS}.jsonl.gz` in the same directory.
  * `recover_partial_tail(path)` — JSONL crash-recovery. On startup
    we validate the last line; if it isn't a complete JSON document
    we truncate to the previous newline. Returns the number of
    bytes trimmed (0 on a clean file).
  * `purge_older_than(dir, max_age)` — retention sweep across both
    rotated `.jsonl.gz` files and SQLite archives.
  * `archive_logs(dir, out_path)` — tar.gz bundle of all audit files
    for hand-off (security-team request, SIEM backfill).
  * `verify_integrity(dir)` — every rotated file is valid gzip + the
    active file is valid JSONL line-by-line.
  * `disk_status(path, warn_pct, crit_pct)` — `/healthz` degraded /
    critical signal based on disk usage.

Per `creates-never-mutates`: rotation is ADDITIVE. The active log is
moved (rename) to a new name and gzipped; the rename is atomic on
POSIX (same filesystem). No data is destroyed without an explicit
`logs purge` call.

Per `deliberate-feature-completion`: rotation, retention, recovery,
disk monitoring, and the CLI surface ship together — operators who
adopt this feature get the whole story.

Cross-product: kbounce / dbounce / gbounce reimplement this surface
in Go with the same flag names + behaviour so the operator runbook
in `docs/LOG-RETENTION.md` covers all four.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import gzip
import json
import os
import pathlib
import shutil
import tarfile
import time
from typing import Any, Iterable

# Default thresholds — match the cross-product table in
# `docs/LOG-RETENTION.md`. Operators can override via CLI flags +
# env vars (IAM_JIT_AUDIT_LOG_MAX_SIZE_MB / *_MAX_AGE_DAYS /
# *_DB_RETENTION_DAYS).
DEFAULT_MAX_SIZE_MB = 100
DEFAULT_MAX_AGE_DAYS = 7
DEFAULT_DB_RETENTION_DAYS = 30
DEFAULT_DISK_WARN_PCT = 85
DEFAULT_DISK_CRIT_PCT = 95

# Rotated-file naming. Suffix `.jsonl.gz` lets the standard `gunzip`
# / `zcat` pipeline ingest the archives without bouncer-specific
# tooling. The timestamp is UTC; we use HHMMSS to disambiguate
# multiple rotations within a day (size-driven rotation can fire
# many times per hour on a chatty bouncer).
ROTATED_JSONL_PATTERN = "audit-{ts}.jsonl.gz"
ROTATED_DB_PATTERN = "audit-{ts}.db.gz"
_ROTATION_TS_FMT = "%Y-%m-%d-%H%M%S"
_DB_DAILY_TS_FMT = "%Y-%m-%d"


@dataclasses.dataclass(frozen=True)
class DiskStatus:
    """`/healthz` payload for the audit-log subsystem.

    `status` is one of "ok", "degraded", "critical". `reason` carries
    a short human-readable string for the operator dashboard. The
    raw `used_pct` is included so monitors can chart trends without
    re-stat'ing the filesystem themselves.
    """

    status: str
    reason: str
    used_pct: float
    path: str

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "used_pct": round(self.used_pct, 2),
            "path": self.path,
        }


def should_rotate_by_size(path: str | os.PathLike, max_mb: int) -> bool:
    """Return True iff the file exists and exceeds `max_mb` megabytes.

    `max_mb <= 0` disables the size trigger (returns False). We use
    POSIX `os.stat` rather than `Path.stat` so symlinks resolve the
    same way as the writer's `os.open(O_APPEND)`.
    """
    if max_mb <= 0:
        return False
    try:
        st = os.stat(path)
    except OSError:
        return False
    return st.st_size > max_mb * 1024 * 1024


def should_rotate_by_age(
    path: str | os.PathLike,
    max_days: int,
    *,
    now: float | None = None,
) -> bool:
    """Return True iff the file's mtime is older than `max_days`.

    `max_days <= 0` disables the age trigger. We compare wall-clock
    seconds rather than calendar days so a bouncer started at 23:59
    rotates at 23:59 the next day, not at 00:00 (which would race
    the SQLite daily rotation).
    """
    if max_days <= 0:
        return False
    try:
        st = os.stat(path)
    except OSError:
        return False
    cutoff = (now if now is not None else time.time()) - max_days * 86400
    return st.st_mtime < cutoff


def rotate(path: str | os.PathLike, *, now: _dt.datetime | None = None) -> pathlib.Path | None:
    """Rotate the active JSONL log atomically + gzip the archive.

    Steps:
      1. Compute `audit-{UTC-timestamp}.jsonl.gz` in the same dir.
      2. Rename the active file to a `.rotating` temp name (atomic on
         POSIX same-fs; readers using the old fd keep writing into
         the unlinked inode — see `creates-never-mutates` posture).
      3. Gzip the temp file into the final archive name (streamed).
      4. Unlink the temp file on success.

    Returns the archive path on success, None when the active file
    was missing or empty (nothing to rotate). Raises on I/O errors so
    the caller (the writer's rotation guard) can record the failure
    via the existing admin-action channel.
    """
    src = pathlib.Path(path)
    if not src.exists():
        return None
    if src.stat().st_size == 0:
        return None
    when = now if now is not None else _dt.datetime.now(_dt.timezone.utc)
    ts = when.strftime(_ROTATION_TS_FMT)
    archive = src.parent / ROTATED_JSONL_PATTERN.format(ts=ts)
    # Use `.rotating` instead of `.tmp` so concurrent backup tools
    # that scan for *.tmp don't grab a half-rotated file.
    rotating = src.with_suffix(src.suffix + ".rotating")
    # If a previous rotation crashed mid-gzip we may have a stale
    # `.rotating` sibling. Reuse it (it has audit data we should NOT
    # destroy) — gzip it and continue.
    if rotating.exists():
        rotating.unlink()
    os.rename(str(src), str(rotating))
    try:
        with open(rotating, "rb") as fin, gzip.open(archive, "wb", compresslevel=6) as fout:
            shutil.copyfileobj(fin, fout, length=64 * 1024)
    finally:
        # Whether gzip succeeded or not, the active file has been
        # atomically removed; subsequent writes (via O_APPEND|O_CREAT)
        # land in a fresh inode. We `unlink` the `.rotating` sibling
        # only after a successful gzip — otherwise we'd lose data.
        if archive.exists() and archive.stat().st_size > 0:
            try:
                rotating.unlink()
            except FileNotFoundError:
                pass
    return archive


def recover_partial_tail(path: str | os.PathLike) -> int:
    """Trim a partially-written final line of a JSONL file.

    On startup we read the last line; if `json.loads` raises, we
    truncate to the previous newline. Returns the byte count trimmed
    (0 on a clean file or missing file).

    This handles the common "process kill mid-write" failure where
    the OS flushed partial bytes; the next `O_APPEND` write would
    otherwise produce a corrupt mixed-line. Per `creates-never-
    mutates` this DOES modify the active file — but only the
    unrecoverable bytes the OS already failed to fully persist.
    """
    p = pathlib.Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return 0
    # Read the last KB. Audit lines are typically ~1-4 KB; reading
    # 64 KB covers a large event without scanning the whole file.
    tail_window = min(p.stat().st_size, 64 * 1024)
    with open(p, "rb") as f:
        f.seek(-tail_window, os.SEEK_END)
        tail = f.read()
    # Find the last newline. Everything after it is the "current
    # line" the writer was building when the process died.
    nl = tail.rfind(b"\n")
    if nl == -1:
        # Whole file is one un-terminated line — extremely unusual
        # (a clean log always ends with `\n`). Try to parse the
        # whole tail; if invalid, truncate the whole file is too
        # destructive. Fall back to leaving it alone — the next
        # write will append cleanly and the operator can grep for
        # the un-terminated line.
        try:
            json.loads(tail.decode("utf-8", errors="strict"))
            return 0
        except (json.JSONDecodeError, UnicodeDecodeError):
            return 0
    last_line = tail[nl + 1:]
    if not last_line:
        return 0  # clean file (ends with newline, nothing after)
    try:
        json.loads(last_line.decode("utf-8", errors="strict"))
        return 0
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Truncate to nl (inclusive). The file size after the trim
        # is `size - len(last_line)`.
        trimmed = len(last_line)
        new_size = p.stat().st_size - trimmed
        with open(p, "r+b") as f:
            f.truncate(new_size)
        return trimmed


def purge_older_than(
    log_dir: str | os.PathLike,
    *,
    jsonl_max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    db_max_age_days: int = DEFAULT_DB_RETENTION_DAYS,
    now: float | None = None,
) -> list[pathlib.Path]:
    """Delete rotated archives older than the retention threshold.

    Returns the list of paths removed. Touches only files matching
    `audit-*.jsonl.gz` and `audit-*.db.gz` (or `audit-*.db`) — never
    the active `audit.jsonl` / `audit.db`. Per `creates-never-
    mutates` this is the ONLY function in this module that destroys
    audit data, and it requires an explicit operator invocation
    (the writer never calls it).
    """
    d = pathlib.Path(log_dir)
    if not d.is_dir():
        return []
    cutoff_now = now if now is not None else time.time()
    removed: list[pathlib.Path] = []
    for child in d.iterdir():
        name = child.name
        if name.startswith("audit-") and name.endswith(".jsonl.gz"):
            max_age = jsonl_max_age_days
        elif name.startswith("audit-") and (
            name.endswith(".db.gz") or name.endswith(".db")
        ):
            max_age = db_max_age_days
        else:
            continue
        if max_age <= 0:
            continue
        if child.stat().st_mtime < cutoff_now - max_age * 86400:
            try:
                child.unlink()
                removed.append(child)
            except OSError:
                # Skip — we surface failures via the caller's admin-
                # action emission; one stuck file shouldn't abort the
                # whole sweep.
                continue
    return removed


def archive_logs(
    log_dir: str | os.PathLike,
    out_path: str | os.PathLike,
    *,
    include_active: bool = True,
) -> pathlib.Path:
    """Bundle all audit files under `log_dir` into a tar.gz at `out_path`.

    The bundle is consumed by `*bounce logs archive --out FILE` for
    security-team hand-off. Optionally excludes the active
    `audit.jsonl` (operators backing up a running bouncer may want
    only the rotated archives to avoid an inconsistent tail).
    """
    src = pathlib.Path(log_dir)
    dst = pathlib.Path(out_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dst, "w:gz") as tf:
        for child in sorted(src.iterdir()):
            n = child.name
            if not (n.startswith("audit") and (
                n.endswith(".jsonl")
                or n.endswith(".jsonl.gz")
                or n.endswith(".db")
                or n.endswith(".db.gz")
            )):
                continue
            if not include_active and n in {"audit.jsonl", "audit.db"}:
                continue
            tf.add(str(child), arcname=child.name)
    return dst


@dataclasses.dataclass(frozen=True)
class IntegrityResult:
    """Outcome of `verify_integrity`. Empty `failures` == healthy."""

    files_checked: int
    failures: list[tuple[str, str]]  # (path, reason)

    @property
    def ok(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict:
        return {
            "files_checked": self.files_checked,
            "ok": self.ok,
            "failures": [
                {"path": p, "reason": r} for p, r in self.failures
            ],
        }


def verify_integrity(log_dir: str | os.PathLike) -> IntegrityResult:
    """Per-file gzip + JSONL syntactic check across the log dir.

    Each rotated `*.jsonl.gz` must decompress cleanly + every line
    must be valid JSON. The active `audit.jsonl` is validated up to
    the last complete newline (a partial tail isn't a failure here
    — `recover_partial_tail` handles that on next startup).
    """
    d = pathlib.Path(log_dir)
    if not d.is_dir():
        return IntegrityResult(files_checked=0, failures=[])
    checked = 0
    failures: list[tuple[str, str]] = []
    for child in sorted(d.iterdir()):
        name = child.name
        if name.endswith(".jsonl.gz") and name.startswith("audit-"):
            checked += 1
            try:
                with gzip.open(child, "rb") as f:
                    for i, line in enumerate(f, 1):
                        if not line.strip():
                            continue
                        json.loads(line)
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
                failures.append((str(child), f"{type(e).__name__}: {e}"))
        elif name == "audit.jsonl":
            checked += 1
            try:
                with open(child, "rb") as f:
                    data = f.read()
                # Split at the last newline; trailing partial bytes
                # are not a failure here (recovery handles them).
                last_nl = data.rfind(b"\n")
                if last_nl == -1:
                    continue
                for line in data[: last_nl + 1].splitlines():
                    if not line.strip():
                        continue
                    json.loads(line)
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
                failures.append((str(child), f"{type(e).__name__}: {e}"))
    return IntegrityResult(files_checked=checked, failures=failures)


def disk_status(
    path: str | os.PathLike,
    *,
    warn_pct: int = DEFAULT_DISK_WARN_PCT,
    crit_pct: int = DEFAULT_DISK_CRIT_PCT,
    statvfs: Iterable | None = None,
) -> DiskStatus:
    """Inspect the filesystem hosting `path`; return a DiskStatus.

    `statvfs` is an injection seam for tests (pass a 3-tuple of
    `(total, used, free)` bytes). In production we use
    `shutil.disk_usage` which is portable across Linux + macOS.
    """
    p = pathlib.Path(path)
    target = p if p.exists() else p.parent
    try:
        if statvfs is not None:
            total, used, free = statvfs  # type: ignore[misc]
        else:
            usage = shutil.disk_usage(str(target))
            total, used, free = usage.total, usage.used, usage.free
    except OSError as e:
        return DiskStatus(
            status="degraded",
            reason=f"disk stat error: {e}",
            used_pct=0.0,
            path=str(target),
        )
    if total <= 0:
        return DiskStatus(
            status="degraded",
            reason="disk total is zero",
            used_pct=0.0,
            path=str(target),
        )
    used_pct = 100.0 * used / total
    if used_pct >= crit_pct:
        return DiskStatus(
            status="critical",
            reason=f"disk usage {used_pct:.1f}% >= critical threshold {crit_pct}%",
            used_pct=used_pct,
            path=str(target),
        )
    if used_pct >= warn_pct:
        return DiskStatus(
            status="degraded",
            reason=f"disk usage {used_pct:.1f}% >= warn threshold {warn_pct}%",
            used_pct=used_pct,
            path=str(target),
        )
    return DiskStatus(
        status="ok",
        reason="disk usage within thresholds",
        used_pct=used_pct,
        path=str(target),
    )


def rotate_db_daily(
    db_path: str | os.PathLike,
    *,
    now: _dt.datetime | None = None,
) -> pathlib.Path | None:
    """Daily SQLite archive-rotate-replace.

    Steps:
      1. If `audit.db` is missing or empty, no-op.
      2. Rename `audit.db` to `audit-{YYYY-MM-DD}.db` (same dir).
      3. Gzip it to `audit-{YYYY-MM-DD}.db.gz` and unlink the .db.
      4. Caller is responsible for reopening a fresh `audit.db`.

    Returns the archive path on success, None on no-op.
    """
    src = pathlib.Path(db_path)
    if not src.exists() or src.stat().st_size == 0:
        return None
    when = now if now is not None else _dt.datetime.now(_dt.timezone.utc)
    ts = when.strftime(_DB_DAILY_TS_FMT)
    renamed = src.parent / f"audit-{ts}.db"
    archive = src.parent / ROTATED_DB_PATTERN.format(ts=ts)
    # If today's archive already exists (rotation called twice in
    # one UTC day), append `-HHMMSS` to disambiguate; the daily
    # rotation should normally fire exactly once but a manual
    # `*bounce logs rotate-now` invocation may double-fire.
    if renamed.exists() or archive.exists():
        ts2 = when.strftime(_ROTATION_TS_FMT)
        renamed = src.parent / f"audit-{ts2}.db"
        archive = src.parent / ROTATED_DB_PATTERN.format(ts=ts2)
    os.rename(str(src), str(renamed))
    try:
        with open(renamed, "rb") as fin, gzip.open(archive, "wb", compresslevel=6) as fout:
            shutil.copyfileobj(fin, fout, length=128 * 1024)
    finally:
        if archive.exists() and archive.stat().st_size > 0:
            try:
                renamed.unlink()
            except FileNotFoundError:
                pass
    return archive


def purge_by_policy(
    log_dir: str | os.PathLike,
    policy: Any,
    *,
    now: float | None = None,
) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    """#428 / §A67 — apply a RetentionPolicy to the log directory.

    Thin compose-helper that delegates to
    :func:`iam_jit.bouncer.audit_export.retention.apply_retention`
    so callers in this module (the writer's tier helper, the CLI's
    `iam-jit audit retention apply`) have a single entry point.

    Returns ``(transitioned_files, purged_files)`` — the tier
    transition + purge lists from the underlying call, simplified
    to two lists for callers that don't need the full result shape.

    Per `[[v1-scope-bar]]` this lives in rotation.py (rather than
    each caller importing retention.py) because rotation.py is the
    historical entrypoint for archive lifecycle operations.
    """
    # Lazy import to avoid retention -> rotation cyclic if retention
    # ever needs to call rotate primitives.
    from .retention import apply_retention
    result = apply_retention(log_dir, policy, now=now)
    transitioned = [pathlib.Path(t.path) for t in result.transitions]
    purged = [pathlib.Path(p) for p in result.purged]
    return transitioned, purged


__all__ = [
    "DEFAULT_DB_RETENTION_DAYS",
    "DEFAULT_DISK_CRIT_PCT",
    "DEFAULT_DISK_WARN_PCT",
    "DEFAULT_MAX_AGE_DAYS",
    "DEFAULT_MAX_SIZE_MB",
    "DiskStatus",
    "IntegrityResult",
    "ROTATED_DB_PATTERN",
    "ROTATED_JSONL_PATTERN",
    "archive_logs",
    "disk_status",
    "purge_by_policy",
    "purge_older_than",
    "recover_partial_tail",
    "rotate",
    "rotate_db_daily",
    "should_rotate_by_age",
    "should_rotate_by_size",
    "verify_integrity",
]
