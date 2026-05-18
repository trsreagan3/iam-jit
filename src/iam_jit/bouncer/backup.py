"""SQLite backup + restore for ibounce (#279).

Two top-level CLI subcommands (`ibounce backup` + `ibounce restore`)
let an operator move state across machines / preserve it across
upgrades / take a snapshot before a risky config change WITHOUT the
"stop the daemon and `cp state.db`" footgun (which silently
corrupts WAL-mode SQLite if anyone forgets the shutdown step).

Approach: SQLite's ``VACUUM INTO 'path'`` statement (3.27.0+, which
Python's stdlib ``sqlite3`` supports natively). VACUUM INTO produces
a consistent snapshot of the live database into a fresh single file
while holding only a brief read lock; the running proxy continues to
serve traffic during the backup. No extra dependency, no SQLAlchemy
ceremony, no sqlite3_backup_init plumbing.

After the VACUUM INTO step we open the output file as a separate
SQLite handle, DROP the audit / prompt tables (per opts), CREATE the
``ibounce_backup_metadata`` table, INSERT the provenance rows, and
re-VACUUM the destination so dropped pages don't bloat the on-disk
size. The on-disk file then matches the operator's intuition
("backup file is the size of the data it carries").

Cross-product alignment per [[cross-product-agent-parity]]: kbounce
ships `kbounce_backup_metadata`, dbounce ships
`dbounce_backup_metadata`, ibounce ships `ibounce_backup_metadata`.
The CLI flag names + refuse-without-force semantics + on-disk
metadata fields match across the three so one shared tooling layer
can target every Bounce.

Per [[creates-never-mutates]]: backup is strictly READ-ONLY against
the source store. The output file is a new DB file we wholly own.
Restore is the one CLI surface that DOES mutate an existing DB; the
destructive verb is gated by the explicit subcommand name + the
``--force`` semantics + the running-process probe.
Per [[self-host-zero-billing-dependency]]: no network calls.
Per [[security-team-positioning-safety-not-surveillance]]: every
operator-facing string is neutral — backup is a snapshotting
artifact, not a record of misbehavior.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import errno
import hashlib
import os
import pathlib
import socket
import sqlite3
import time
from typing import Any

from .. import __version__ as _ibounce_version
from .store import SCHEMA_VERSION

# ---------------------------------------------------------------------------
# Wire constants — cross-product aligned per
# [[cross-product-agent-parity]]
# ---------------------------------------------------------------------------

# Name of the metadata table embedded in every backup file. Reviewers
# grepping a backup-shaped DB for "ibounce_backup_metadata" can
# confirm it was produced by `ibounce backup` (vs a random SQLite
# file). kbounce uses `kbounce_backup_metadata`; dbounce uses
# `dbounce_backup_metadata`.
BACKUP_METADATA_TABLE = "ibounce_backup_metadata"

# Tables EXCLUDED from the default backup. These are the audit /
# decision-firehose surfaces: bulky + often-redundant after a
# rotation policy fires. `--include-audit` re-includes them.
BACKUP_EXCLUDED_AUDIT_TABLES: tuple[str, ...] = (
    "decisions",
    "config_events",
    "pending_audit_events",
)

# Tables EXCLUDED from the default backup unless `--include-prompts`
# is passed. Pending prompts are runtime state bound to in-flight
# proxy waiters; restoring them onto a fresh machine doesn't surface
# a live request to answer, so they're typically excluded.
BACKUP_EXCLUDED_PROMPT_TABLES: tuple[str, ...] = (
    "pending_prompts",
)

# Default loopback management port `ibounce run` binds. Matches
# `DEFAULT_HEALTHZ_URL` in diagnostics.py. The restore command's
# running-process probe dials this so a misconfigured restore can't
# clobber a live DB out from under the proxy.
DEFAULT_PROBE_PORT = 8767

# Probe timeout — short enough that the probe doesn't dominate
# restore latency; long enough that loopback connect-time noise
# doesn't false-negative. Matches the dbounce sibling default.
DEFAULT_PROBE_TIMEOUT_SECONDS = 0.2

# VACUUM INTO retry budget for the rare case where the source DB has
# a busy writer holding the write lock when the backup starts. Each
# retry doubles the wait up to the cap.
_VACUUM_INTO_MAX_RETRIES = 5
_VACUUM_INTO_INITIAL_BACKOFF_SECONDS = 0.05


# ---------------------------------------------------------------------------
# Public dataclasses — knobs + return shapes for the backup / restore
# worker functions
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class BackupOptions:
    """Knobs the CLI passes through to `write_backup`.

    Every field has a sensible default so a bare `ibounce backup`
    produces a useful artifact; tests pin paths under a tmpdir.
    """

    out_path: pathlib.Path
    include_audit: bool = False
    include_prompts: bool = False
    db_path: str | None = None
    # Override the wall-clock used to stamp `created_at`. Test hook;
    # production passes None and gets `datetime.now(UTC)`.
    now: _dt.datetime | None = None
    # Override the hostname source used to derive
    # `source_hostname_hash`. Test hook; production passes None and
    # gets `socket.gethostname()`.
    hostname: str | None = None


@dataclasses.dataclass
class BackupResult:
    """Returned by `write_backup` so the CLI can print a one-line
    summary + the admin-action audit row has stable fields to hash.
    """

    out_path: pathlib.Path
    size_bytes: int = 0
    schema_version: int = 0
    ibounce_version: str = ""
    created_at: str = ""
    source_hostname_hash: str = ""
    included_audit: bool = False
    included_prompts: bool = False
    sha256: str = ""
    # Per-table row counts inside the backup file. Useful in tests
    # and for the CLI summary.
    row_counts: dict[str, int] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class RestoreOptions:
    """Knobs the CLI passes through to `restore_from`. Defaults are
    STRICT — the caller must explicitly opt into each override."""

    in_path: pathlib.Path
    dest_db_path: str | None = None
    force: bool = False
    # Override the probe port the running-process check dials.
    # Defaults to DEFAULT_PROBE_PORT.
    probe_port: int = DEFAULT_PROBE_PORT
    # Skip the probe entirely. Use only when the probe port is held
    # by an unrelated process and the operator has manually verified
    # ibounce is down.
    probe_skip: bool = False
    probe_timeout_seconds: float = DEFAULT_PROBE_TIMEOUT_SECONDS


@dataclasses.dataclass
class RestoreResult:
    """Post-restore summary: row counts + sha256 of the resulting
    DB file. The CLI prints this; tests assert against it."""

    dest_path: pathlib.Path
    sha256: str = ""
    row_counts: dict[str, int] = dataclasses.field(default_factory=dict)
    backup_ibounce_version: str = ""
    backup_schema_version: int = 0
    version_mismatch: bool = False


# ---------------------------------------------------------------------------
# Error types — exported so the CLI layer can pattern-match without
# coupling to error messages
# ---------------------------------------------------------------------------


class BackupError(Exception):
    """Base class for backup / restore errors. Catchable separately
    from generic Click / sqlite3 exceptions."""


class NotABackupFileError(BackupError):
    """The source file opens as SQLite but does NOT carry the
    `ibounce_backup_metadata` table."""


class SchemaVersionMismatchError(BackupError):
    """The backup's `schema_version` does NOT match the running
    binary's SCHEMA_VERSION. NOT overridable by `--force` —
    cross-schema restore is the (future) `ibounce migrate` story."""


class IbounceVersionMismatchError(BackupError):
    """The backup's `ibounce_version` differs from the running
    binary's. Soft error — overridable with `--force`."""


class DestinationNotEmptyError(BackupError):
    """The destination DB exists and already has rows in
    user-config tables. Overridable with `--force`."""


class IbounceRunningError(BackupError):
    """A probe of the loopback management port succeeded; ibounce
    appears to be running. Stop it before restoring."""


# ---------------------------------------------------------------------------
# Filename + hash helpers
# ---------------------------------------------------------------------------


def default_backup_path(now: _dt.datetime | None = None) -> pathlib.Path:
    """`./ibounce-backup-<UTC-timestamp>.db` — the spec'd default.

    Timestamp format matches the kbounce + dbounce sibling default
    (`YYYYMMDDTHHMMSSZ`), keeping `ls` output sortable and
    cross-product diffs line-stable.
    """
    ts = (now or _dt.datetime.now(_dt.UTC)).strftime("%Y%m%dT%H%M%SZ")
    return pathlib.Path(f"./ibounce-backup-{ts}.db")


def _hostname_hash(hostname: str) -> str:
    """sha256(hostname)[:12] — same shape kbounce + dbounce use.

    Records source-host attribution without leaking the literal
    hostname into a backup file the operator may share for
    support purposes.
    """
    if not hostname:
        return ""
    return hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:12]


def _file_sha256(path: pathlib.Path) -> str:
    """Hex sha256 of a file's bytes. Streamed so a multi-GB backup
    doesn't pin the whole file in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------


def write_backup(opts: BackupOptions) -> BackupResult:
    """Write an online SQLite backup of the live store to
    `opts.out_path` + return the metadata embedded in the new file.

    Flow:

      1. ``VACUUM INTO '<tmp>'`` produces the consistent snapshot
         using a fresh sqlite3 connection (so we don't compete with
         the live store's connection pool / locks).
      2. Open `<tmp>` as a separate handle.
      3. DROP excluded tables (`decisions` + `config_events` +
         `pending_audit_events` unless `--include-audit`,
         `pending_prompts` unless `--include-prompts`).
      4. CREATE `ibounce_backup_metadata` + INSERT provenance rows.
      5. ``VACUUM`` the destination so dropped pages are reclaimed.
      6. Rename `<tmp>` to the final path + chmod 0o600.

    Returns the BackupResult so the CLI can print a one-line summary
    + the admin-action emit can stamp deterministic fields.

    Refuses to clobber an existing file at `opts.out_path` — explicit
    beats implicit for destructive ops. Operators who genuinely want
    to overwrite can `rm` first or pick a different `--out` path.
    """
    if not opts.db_path:
        from .store import default_db_path
        src_path = pathlib.Path(default_db_path())
    else:
        src_path = pathlib.Path(opts.db_path)
    if not src_path.exists():
        raise BackupError(
            f"ibounce: backup: source DB does not exist at {src_path!s}. "
            f"Did you `ibounce init` first?"
        )

    out_path = pathlib.Path(opts.out_path)
    if out_path.exists():
        raise BackupError(
            f"ibounce: backup: {out_path!s} already exists; remove it "
            f"first or pick a different --out path."
        )
    if out_path.parent and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)

    # Resolve metadata up-front so a clock drift during the VACUUM
    # doesn't desync the persisted timestamp.
    now = (opts.now or _dt.datetime.now(_dt.UTC)).astimezone(_dt.UTC)
    hostname = opts.hostname if opts.hostname is not None else socket.gethostname()

    # Step 1: VACUUM INTO a temp path in the destination directory so
    # the final rename is atomic on the same filesystem (cross-fs
    # rename falls back to copy+unlink and loses atomicity).
    tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")
    with contextlib.suppress(FileNotFoundError):
        tmp_path.unlink()

    src_conn = sqlite3.connect(str(src_path), isolation_level=None)
    try:
        # `VACUUM INTO` does not accept a bound parameter for the
        # destination path — SQLite requires a string literal. Quote
        # defensively (doubling embedded single quotes) so a path
        # with spaces or apostrophes is safe.
        escaped = str(tmp_path).replace("'", "''")
        _exec_with_busy_retry(src_conn, f"VACUUM INTO '{escaped}'")
    finally:
        src_conn.close()

    # Step 2-5: open the snapshot as a fresh handle so we can prune
    # excluded tables + stamp metadata without confusing any other
    # connection.
    dst = sqlite3.connect(str(tmp_path), isolation_level=None)
    try:
        excluded: list[str] = []
        if not opts.include_audit:
            excluded.extend(BACKUP_EXCLUDED_AUDIT_TABLES)
        if not opts.include_prompts:
            excluded.extend(BACKUP_EXCLUDED_PROMPT_TABLES)
        for tbl in excluded:
            # DROP rather than DELETE so the post-VACUUM file size
            # reflects "the data isn't there" (DELETE would leave
            # empty pages behind). DROP IF EXISTS so a schema-future
            # table that's not yet present doesn't fail the backup.
            try:
                dst.execute(f"DROP TABLE IF EXISTS {tbl}")
            except sqlite3.OperationalError as exc:
                # Defensive — modernc-style "no such table" can
                # occasionally raise even with IF EXISTS in older
                # SQLite builds. Swallow that specific shape.
                if "no such table" not in str(exc).lower():
                    raise BackupError(
                        f"ibounce: backup: drop {tbl}: {exc}"
                    ) from exc
            # sqlite_sequence carries an AUTOINCREMENT bookmark row
            # per table; clean ours up so a future migration doesn't
            # see a stale id pointer for a re-created table.
            with contextlib.suppress(sqlite3.OperationalError):
                dst.execute(
                    "DELETE FROM sqlite_sequence WHERE name = ?",
                    (tbl,),
                )

        # Step 3: read schema_version from the snapshot (source of
        # truth for the metadata we're embedding).
        try:
            row = dst.execute(
                "SELECT version FROM schema_version LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError as exc:
            raise BackupError(
                f"ibounce: backup: read schema_version: {exc}"
            ) from exc
        src_schema_version = int(row[0]) if row else SCHEMA_VERSION

        # Step 4: build + stamp metadata.
        host_hash = _hostname_hash(hostname)
        created_at_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        dst.execute(
            f"CREATE TABLE IF NOT EXISTS {BACKUP_METADATA_TABLE} ("
            f"  key TEXT PRIMARY KEY,"
            f"  value TEXT NOT NULL"
            f")"
        )
        meta_rows: dict[str, str] = {
            "ibounce_version": _ibounce_version,
            "created_at": created_at_str,
            "source_hostname_hash": host_hash,
            "schema_version": str(src_schema_version),
            "included_audit": "true" if opts.include_audit else "false",
            "included_prompts": "true" if opts.include_prompts else "false",
        }
        for k, v in meta_rows.items():
            dst.execute(
                f"INSERT OR REPLACE INTO {BACKUP_METADATA_TABLE}"
                f"(key, value) VALUES (?, ?)",
                (k, v),
            )

        # Step 5: VACUUM the destination so dropped pages are
        # reclaimed and the on-disk size matches operator intuition.
        dst.execute("VACUUM")

        row_counts = _count_rows_by_table(dst)
    finally:
        dst.close()

    # Step 6: atomic rename + chmod 0o600.
    os.replace(tmp_path, out_path)
    with contextlib.suppress(OSError):
        os.chmod(out_path, 0o600)

    size_bytes = out_path.stat().st_size
    sha = _file_sha256(out_path)

    return BackupResult(
        out_path=out_path,
        size_bytes=size_bytes,
        schema_version=src_schema_version,
        ibounce_version=_ibounce_version,
        created_at=created_at_str,
        source_hostname_hash=host_hash,
        included_audit=opts.include_audit,
        included_prompts=opts.include_prompts,
        sha256=sha,
        row_counts=row_counts,
    )


def _exec_with_busy_retry(conn: sqlite3.Connection, stmt: str) -> None:
    """Execute `stmt` with exponential-backoff retry on SQLITE_BUSY.

    The whole point of `ibounce backup` is to snapshot a RUNNING
    proxy; a writer holding the write lock briefly during VACUUM
    INTO should not fail the backup. Retry up to
    `_VACUUM_INTO_MAX_RETRIES` times then re-raise.
    """
    backoff = _VACUUM_INTO_INITIAL_BACKOFF_SECONDS
    last_exc: sqlite3.OperationalError | None = None
    for _ in range(_VACUUM_INTO_MAX_RETRIES + 1):
        try:
            conn.execute(stmt)
            return
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            if "database is locked" not in msg and "busy" not in msg:
                raise
            last_exc = exc
            time.sleep(backoff)
            backoff = min(backoff * 2, 1.0)
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def restore_from(opts: RestoreOptions) -> RestoreResult:
    """Replace the destination DB at `opts.dest_db_path` with the
    contents of the backup at `opts.in_path`.

    Validation gates (all checked BEFORE the destructive copy):

      1. Source file exists + opens as a SQLite DB.
      2. Source carries the `ibounce_backup_metadata` table (refuses
         a random SQLite file masquerading as a backup).
      3. Source's `schema_version` MUST equal the running binary's
         SCHEMA_VERSION (refused with `--force` too — cross-schema
         restore is a migration, not a restore).
      4. Source's `ibounce_version` SHOULD equal the running binary's
         version; mismatch is refused unless `opts.force` is True.
      5. Destination, if it exists + has rows in any user-config
         table, is refused unless `opts.force` is True.
      6. Loopback management port (default 8767) must not accept a
         TCP connection. The probe is presence-only (no HTTP); a
         successful connect raises IbounceRunningError.

    Then the destination file is REPLACED (os.replace; atomic on the
    same filesystem). Per [[creates-never-mutates]] the SOURCE backup
    file is preserved; only the destination is rewritten.
    """
    in_path = pathlib.Path(opts.in_path)
    if not in_path.exists():
        raise BackupError(
            f"ibounce: restore: backup file does not exist at {in_path!s}"
        )

    if opts.dest_db_path:
        dest_path = pathlib.Path(opts.dest_db_path)
    else:
        from .store import default_db_path
        dest_path = pathlib.Path(default_db_path())

    # Gate 1+2: open source + read metadata. Refuse any file that
    # doesn't carry the metadata table.
    src_conn = sqlite3.connect(str(in_path), isolation_level=None)
    try:
        try:
            present = src_conn.execute(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type='table' AND name = ?",
                (BACKUP_METADATA_TABLE,),
            ).fetchone()[0]
        except sqlite3.DatabaseError as exc:
            raise BackupError(
                f"ibounce: restore: {in_path!s} is not a SQLite database "
                f"({exc})"
            ) from exc
        if not present:
            raise NotABackupFileError(
                f"ibounce: restore: {in_path!s} is a SQLite database "
                f"but is missing the {BACKUP_METADATA_TABLE} table — "
                f"is this an ibounce backup file?"
            )
        meta = _read_backup_metadata(src_conn)
    finally:
        src_conn.close()

    backup_schema_version_raw = meta.get("schema_version", "")
    try:
        backup_schema_version = int(backup_schema_version_raw)
    except (TypeError, ValueError):
        raise BackupError(
            f"ibounce: restore: backup metadata has unparseable "
            f"schema_version={backup_schema_version_raw!r}"
        ) from None
    backup_ibounce_version = meta.get("ibounce_version", "")

    # Gate 3 (HARD): schema_version match. Not overridable.
    if backup_schema_version != SCHEMA_VERSION:
        raise SchemaVersionMismatchError(
            f"ibounce: restore: schema_version mismatch — backup is "
            f"schema_version={backup_schema_version}, running binary "
            f"expects schema_version={SCHEMA_VERSION}. Cross-schema "
            f"restore is the `ibounce migrate` story (out of scope "
            f"for #279); --force does NOT override this check."
        )

    # Gate 4 (soft): ibounce_version mismatch is overridable.
    version_mismatch = False
    if backup_ibounce_version and backup_ibounce_version != _ibounce_version:
        version_mismatch = True
        if not opts.force:
            raise IbounceVersionMismatchError(
                f"ibounce: restore: ibounce_version mismatch — backup "
                f"was created by ibounce {backup_ibounce_version!r}, "
                f"running binary is {_ibounce_version!r}. Pass --force "
                f"to proceed (cross-version restores are supported "
                f"within the same schema_version)."
            )

    # Gate 5: destination must be empty OR --force.
    if _destination_has_data(dest_path) and not opts.force:
        raise DestinationNotEmptyError(
            f"ibounce: restore: destination database at {dest_path!s} "
            f"already has user-config rows; pass --force to overwrite "
            f"(this REPLACES the destination wholesale)."
        )

    # Gate 6: running-process probe.
    if not opts.probe_skip and _ibounce_is_running(
        opts.probe_port, opts.probe_timeout_seconds,
    ):
        raise IbounceRunningError(
            f"ibounce: restore: ibounce appears to be running "
            f"(loopback port {opts.probe_port} accepted a TCP "
            f"connection). Stop ibounce first (e.g. `pkill -f "
            f"'ibounce run'` or your service manager's stop verb), "
            f"then retry. If the port is held by an unrelated "
            f"process, set probe_skip=True after manually verifying "
            f"ibounce is down."
        )

    # All gates pass — perform the destructive copy via a tmp file
    # on the destination's filesystem so the rename is atomic.
    if dest_path.parent and not dest_path.parent.exists():
        dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest_path.with_suffix(dest_path.suffix + ".restore.tmp")
    with contextlib.suppress(FileNotFoundError):
        tmp_path.unlink()
    _copy_file(in_path, tmp_path)
    with contextlib.suppress(OSError):
        os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, dest_path)

    # Sweep up the source-side WAL / SHM sidecars for the destination
    # path if they were present (the destination was an existing
    # WAL-mode store before restore). Best-effort: a stale -wal /
    # -shm file alongside the new state.db would confuse SQLite into
    # reading uncommitted pages from a different DB on next open.
    for suffix in ("-wal", "-shm"):
        sidecar = dest_path.with_name(dest_path.name + suffix)
        with contextlib.suppress(FileNotFoundError, OSError):
            sidecar.unlink()

    # Post-restore: open the destination + count rows for the
    # summary. Use a fresh connection so we don't conflict with any
    # other handle that might exist in this process.
    dst_conn = sqlite3.connect(str(dest_path), isolation_level=None)
    try:
        row_counts = _count_rows_by_table(dst_conn)
    finally:
        dst_conn.close()

    sha = _file_sha256(dest_path)

    return RestoreResult(
        dest_path=dest_path,
        sha256=sha,
        row_counts=row_counts,
        backup_ibounce_version=backup_ibounce_version,
        backup_schema_version=backup_schema_version,
        version_mismatch=version_mismatch,
    )


def _read_backup_metadata(conn: sqlite3.Connection) -> dict[str, str]:
    """Read every (key, value) row of the metadata table."""
    rows = conn.execute(
        f"SELECT key, value FROM {BACKUP_METADATA_TABLE}"
    ).fetchall()
    return {str(k): str(v) for k, v in rows}


def _destination_has_data(dest_path: pathlib.Path) -> bool:
    """True when `dest_path` exists + any user-config table has rows.

    "User-config tables" = the set ibounce considers carrying actual
    customer config: rules, tasks, profile_overrides (if any), and
    `pending_prompts`. The audit-firehose tables (decisions /
    config_events / pending_audit_events) are EXCLUDED from this
    check because a freshly-init'd ibounce can legitimately have
    config_events rows from the protective-default preset and we
    don't want that to force the operator to pass --force on a
    day-1 restore.

    A non-existent file is "not present" (empty). A zero-byte file
    is treated as empty too (sqlite would refuse it).
    """
    if not dest_path.exists():
        return False
    try:
        if dest_path.stat().st_size == 0:
            return False
    except OSError:
        return False

    conn = sqlite3.connect(str(dest_path), isolation_level=None)
    try:
        try:
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            ]
        except sqlite3.DatabaseError:
            # File exists but isn't a SQLite DB — treat as data-
            # present so --force is required (don't silently
            # overwrite some unrelated file at this path).
            return True
        # Tables to check for any non-empty content. Audit-firehose
        # tables are intentionally excluded per the docstring.
        config_tables = {
            "rules",
            "tasks",
            "plan_sessions",
            "plan_calls",
            "pause_events",
            "pending_prompts",
        }
        for tbl in tables:
            if tbl not in config_tables:
                continue
            try:
                count = conn.execute(
                    f"SELECT COUNT(*) FROM {tbl}"
                ).fetchone()[0]
            except sqlite3.OperationalError:
                # Schema mismatch (older DB without this table) —
                # tolerate.
                continue
            if count > 0:
                return True
        return False
    finally:
        conn.close()


def _ibounce_is_running(port: int, timeout_seconds: float) -> bool:
    """Best-effort TCP probe on `127.0.0.1:port`. Returns True iff
    something accepted the connection. The probe is presence-only;
    closes the socket immediately after connect so we never speak
    HTTP or SQL on the live management plane.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout_seconds)
        try:
            s.connect(("127.0.0.1", int(port)))
        except OSError as exc:
            # ECONNREFUSED is the expected "nothing listening" shape.
            # ETIMEDOUT / EHOSTUNREACH = also "nothing reachable."
            # Any other error is treated as "not running" so a
            # weird firewall doesn't block a legitimate restore.
            if exc.errno in (
                errno.ECONNREFUSED,
                errno.ETIMEDOUT,
                errno.EHOSTUNREACH,
                errno.ENETUNREACH,
            ):
                return False
            return False
        return True


def _copy_file(src: pathlib.Path, dst: pathlib.Path) -> None:
    """Byte-for-byte copy `src` → `dst`. We use a fresh file (not
    os.link) so a cross-filesystem restore works + so the dst is
    independent of the src (operator may want to delete the backup
    after a successful restore)."""
    with open(src, "rb") as in_f, open(dst, "wb") as out_f:
        for chunk in iter(lambda: in_f.read(65536), b""):
            out_f.write(chunk)
        out_f.flush()
        with contextlib.suppress(OSError):
            os.fsync(out_f.fileno())


def _count_rows_by_table(conn: sqlite3.Connection) -> dict[str, int]:
    """Return a map of table-name → row-count for every user-facing
    table in the database (excludes hidden `sqlite_*` tables).

    Includes the `ibounce_backup_metadata` table when present so a
    reviewer can see "yes, the file has its provenance row." Pulls
    table names from sqlite_master so a future schema-version bump
    doesn't require updating a hand-maintained allowlist.
    """
    out: dict[str, int] = {}
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    for (name,) in rows:
        try:
            count = conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        except sqlite3.OperationalError:
            count = 0
        out[str(name)] = int(count)
    return out


# ---------------------------------------------------------------------------
# Admin-action emit helpers — used by the CLI layer to enqueue
# `backup.create` / `backup.restore` OCSF rows
# ---------------------------------------------------------------------------


def emit_backup_create_admin_action(
    store: Any,
    *,
    result: BackupResult,
    actor: str | None = None,
) -> None:
    """Enqueue a `backup.create` ADMIN_ACTION OCSF row. Matches the
    kbounce + dbounce sibling shape so a SIEM rule keyed on
    `action="backup.create"` catches the snapshot lifecycle event
    regardless of which product fired it. Best-effort: a queue-write
    failure NEVER fails the user-facing backup (the file has
    already landed).
    """
    from .audit_export.admin_action import (
        ADMIN_ACTION_BACKUP_CREATE,
        ADMIN_ACTION_SOURCE_CLI,
        enqueue_admin_action,
        resolve_operator,
    )

    extra = {
        "out_path": str(result.out_path),
        "size_bytes": result.size_bytes,
        "sha256": result.sha256,
        "schema_version": result.schema_version,
        "ibounce_version": result.ibounce_version,
        "included_audit": result.included_audit,
        "included_prompts": result.included_prompts,
        "source_hostname_hash": result.source_hostname_hash,
    }
    enqueue_admin_action(
        store,
        kind=ADMIN_ACTION_BACKUP_CREATE,
        actor=actor or resolve_operator(),
        target_kind="backup",
        target_id=str(result.out_path),
        source=ADMIN_ACTION_SOURCE_CLI,
        extra=extra,
    )


def emit_backup_restore_admin_action(
    store: Any,
    *,
    in_path: pathlib.Path,
    result: RestoreResult,
    force: bool,
    probe_skip: bool,
    actor: str | None = None,
) -> None:
    """Enqueue a `backup.restore` ADMIN_ACTION OCSF row. See
    `emit_backup_create_admin_action`'s docstring for posture; this
    is the DR-lifecycle event a SIEM dashboard alerts on. The store
    used to enqueue is the freshly-restored destination DB (we want
    the row to land in the audit channel the operator is now
    looking at, not the previous DB which may have been replaced)."""
    from .audit_export.admin_action import (
        ADMIN_ACTION_BACKUP_RESTORE,
        ADMIN_ACTION_SOURCE_CLI,
        enqueue_admin_action,
        resolve_operator,
    )

    extra = {
        "source_path": str(in_path),
        "destination": str(result.dest_path),
        "sha256": result.sha256,
        "force": force,
        "probe_skipped": probe_skip,
        "row_count_total": sum(result.row_counts.values()),
        "version_mismatch": result.version_mismatch,
    }
    enqueue_admin_action(
        store,
        kind=ADMIN_ACTION_BACKUP_RESTORE,
        actor=actor or resolve_operator(),
        target_kind="backup",
        target_id=str(in_path),
        source=ADMIN_ACTION_SOURCE_CLI,
        extra=extra,
    )
