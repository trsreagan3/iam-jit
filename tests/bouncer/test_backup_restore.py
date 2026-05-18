"""Tests for #279 — `ibounce backup` + `ibounce restore` (SQLite
snapshot + DR replace).

Mirrors the kbounce + dbounce sibling test suites so a regression in
the shared cross-product contract surfaces in three places:

  * Backup file row counts match source minus excluded tables
  * Backup metadata fields populated correctly (each metadata
    key/value present)
  * Restore into empty DB succeeds + reproduces row counts
  * Restore into non-empty DB without `--force` fails with clear
    error
  * Restore with mismatched schema_version fails (even with `--force`)
  * Restore with mismatched ibounce_version warns but succeeds with
    `--force`
  * Backup works while a write-heavy concurrent task is running
    (online-backup property test)
  * Round-trip (backup -> restore -> backup again) produces
    metadata-equivalent second backup (timestamps + hash differ;
    row counts match)
  * Backup with --include-audit captures audit rows; round-trip
    preserves them
  * Admin-action OCSF events emitted on both backup + restore
  * Refuse-if-running: probe mock binds management port → restore
    fails with stop-first message

Per [[cross-product-agent-parity]]: every assertion mirrors the
sibling kbounce + dbounce tests so the cross-product contract is
enforced uniformly.
Per [[security-team-positioning-safety-not-surveillance]]: a
doc-surface lint sweep confirms every operator-facing string is
neutral.
"""

from __future__ import annotations

import json
import pathlib
import socket
import sqlite3
import threading
import time
from typing import Any

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.audit_export import (
    ADMIN_ACTION_BACKUP_CREATE,
    ADMIN_ACTION_BACKUP_RESTORE,
    EVENT_TYPE_ADMIN_ACTION,
)
from iam_jit.bouncer.backup import (
    BACKUP_EXCLUDED_AUDIT_TABLES,
    BACKUP_EXCLUDED_PROMPT_TABLES,
    BACKUP_METADATA_TABLE,
    BackupError,
    BackupOptions,
    DEFAULT_PROBE_PORT,
    DestinationNotEmptyError,
    IbounceRunningError,
    IbounceVersionMismatchError,
    NotABackupFileError,
    RestoreOptions,
    SchemaVersionMismatchError,
    default_backup_path,
    restore_from,
    write_backup,
)
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import SCHEMA_VERSION, BouncerStore
from iam_jit.bouncer_cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Isolated environment: every config path lives under tmp_path
    so a test never touches the operator's real ~/.iam-jit dir."""
    db = tmp_path / "state.db"
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))
    monkeypatch.setenv("IAM_JIT_BOUNCER_ACTOR", "frank@example.com")
    monkeypatch.setenv("HOME", str(home))
    return {
        "db": str(db),
        "tmp": str(tmp_path),
        "home": str(home),
    }


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _seed_store(db_path: str, *, rules: int = 3, decisions: int = 5) -> None:
    """Populate a fresh BouncerStore at db_path with synthetic rows
    so backup / restore have something to round-trip."""
    from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
    s = BouncerStore(db_path=db_path)
    try:
        for i in range(rules):
            s.add_rule(
                ProxyRule(
                    pattern=f"s3:GetObject{i}",
                    effect=Effect.ALLOW,
                    note=f"seed rule {i}",
                ),
                actor="seed",
            )
        # Synthetic decisions populate the audit table — these are
        # what `--include-audit` toggles.
        for i in range(decisions):
            s.record_decision(
                DecisionRecord(
                    decision=Decision.ALLOW,
                    mode=Mode.ENFORCE,
                    service="s3",
                    action=f"GetObject{i}",
                    arn=None,
                    region="us-east-1",
                    matched_rule=None,
                    reason="seed",
                ),
            )
    finally:
        s.close()


def _row_count(db_path: pathlib.Path, table: str) -> int:
    """Direct sqlite row count — used by tests to compare a backup
    file against its source without going through the store."""
    conn = sqlite3.connect(str(db_path))
    try:
        try:
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.OperationalError:
            return 0
    finally:
        conn.close()


def _read_metadata(backup_path: pathlib.Path) -> dict[str, str]:
    """Read the (key, value) rows out of the backup metadata table."""
    conn = sqlite3.connect(str(backup_path))
    try:
        rows = conn.execute(
            f"SELECT key, value FROM {BACKUP_METADATA_TABLE}"
        ).fetchall()
    finally:
        conn.close()
    return {str(k): str(v) for k, v in rows}


def _has_table(backup_path: pathlib.Path, table: str) -> bool:
    conn = sqlite3.connect(str(backup_path))
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
            (table,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------


def test_backup_writes_valid_sqlite_file(env, tmp_path) -> None:
    _seed_store(env["db"])
    out_path = tmp_path / "backup.db"
    result = write_backup(BackupOptions(out_path=out_path, db_path=env["db"]))
    assert out_path.exists()
    assert out_path.stat().st_size > 0
    assert result.size_bytes == out_path.stat().st_size
    # File opens as a SQLite DB.
    conn = sqlite3.connect(str(out_path))
    try:
        conn.execute("SELECT 1").fetchone()
    finally:
        conn.close()


def test_backup_default_excludes_audit_and_prompt_tables(env, tmp_path) -> None:
    """Default backup drops decisions + config_events +
    pending_audit_events + pending_prompts."""
    _seed_store(env["db"])
    out_path = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=out_path, db_path=env["db"]))
    for tbl in (
        *BACKUP_EXCLUDED_AUDIT_TABLES,
        *BACKUP_EXCLUDED_PROMPT_TABLES,
    ):
        assert not _has_table(out_path, tbl), (
            f"default backup should NOT contain {tbl}"
        )
    # Sanity: rules (kept) IS present.
    assert _has_table(out_path, "rules")


def test_backup_include_audit_keeps_audit_rows(env, tmp_path) -> None:
    _seed_store(env["db"], decisions=7)
    out_path = tmp_path / "backup.db"
    result = write_backup(BackupOptions(
        out_path=out_path, db_path=env["db"], include_audit=True,
    ))
    assert result.included_audit is True
    for tbl in BACKUP_EXCLUDED_AUDIT_TABLES:
        assert _has_table(out_path, tbl), (
            f"--include-audit should keep {tbl}"
        )
    assert _row_count(out_path, "decisions") == 7


def test_backup_include_prompts_keeps_prompts_table(env, tmp_path) -> None:
    _seed_store(env["db"])
    out_path = tmp_path / "backup.db"
    result = write_backup(BackupOptions(
        out_path=out_path, db_path=env["db"], include_prompts=True,
    ))
    assert result.included_prompts is True
    assert _has_table(out_path, "pending_prompts")


def test_backup_metadata_table_has_required_fields(env, tmp_path) -> None:
    _seed_store(env["db"])
    out_path = tmp_path / "backup.db"
    result = write_backup(BackupOptions(
        out_path=out_path,
        db_path=env["db"],
        hostname="prod-leader-02",
    ))
    meta = _read_metadata(out_path)
    # Every spec'd metadata key present.
    for key in (
        "ibounce_version",
        "created_at",
        "source_hostname_hash",
        "schema_version",
        "included_audit",
        "included_prompts",
    ):
        assert key in meta, f"metadata missing key {key}"
    assert meta["schema_version"] == str(SCHEMA_VERSION)
    assert meta["included_audit"] == "false"
    assert meta["included_prompts"] == "false"
    # source_hostname_hash is sha256[:12] of the hostname.
    assert len(meta["source_hostname_hash"]) == 12
    assert meta["source_hostname_hash"] != "prod-leader-02"
    # created_at is RFC3339 UTC with trailing Z.
    assert meta["created_at"].endswith("Z")
    # Result fields agree with the persisted row.
    assert result.schema_version == SCHEMA_VERSION
    assert result.source_hostname_hash == meta["source_hostname_hash"]


def test_backup_row_counts_match_source_minus_excluded(env, tmp_path) -> None:
    _seed_store(env["db"], rules=4, decisions=9)
    out_path = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=out_path, db_path=env["db"]))
    # rules kept: source count survives.
    assert _row_count(out_path, "rules") == _row_count(
        pathlib.Path(env["db"]), "rules"
    )
    # decisions excluded (default): 0 rows in the backup even though
    # the source has rows.
    assert _row_count(pathlib.Path(env["db"]), "decisions") == 9
    assert not _has_table(out_path, "decisions")


def test_backup_refuses_to_overwrite_existing(env, tmp_path) -> None:
    _seed_store(env["db"])
    out_path = tmp_path / "backup.db"
    out_path.write_bytes(b"existing")
    with pytest.raises(BackupError, match="already exists"):
        write_backup(BackupOptions(out_path=out_path, db_path=env["db"]))


def test_backup_creates_parent_dir(env, tmp_path) -> None:
    _seed_store(env["db"])
    out_path = tmp_path / "subdir" / "backup.db"
    write_backup(BackupOptions(out_path=out_path, db_path=env["db"]))
    assert out_path.exists()


def test_backup_file_perms_are_0600(env, tmp_path) -> None:
    _seed_store(env["db"])
    out_path = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=out_path, db_path=env["db"]))
    mode = out_path.stat().st_mode & 0o777
    assert mode == 0o600, f"backup perms {oct(mode)} must be 0o600"


def test_backup_works_during_concurrent_writes(env, tmp_path) -> None:
    """Online-backup property: a concurrent writer against the
    source DB doesn't break VACUUM INTO. We hammer the source with
    a background thread + assert the backup still succeeds."""
    _seed_store(env["db"])
    stop = threading.Event()

    def writer() -> None:
        from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
        s = BouncerStore(db_path=env["db"])
        try:
            i = 0
            while not stop.is_set():
                try:
                    s.record_decision(
                        DecisionRecord(
                            decision=Decision.ALLOW,
                            mode=Mode.ENFORCE,
                            service="s3",
                            action=f"Write{i}",
                            arn=None,
                            region="us-east-1",
                            matched_rule=None,
                            reason="concurrent",
                        ),
                    )
                except sqlite3.OperationalError:
                    pass
                i += 1
                time.sleep(0.001)
        finally:
            s.close()

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        time.sleep(0.05)  # let the writer get going
        out_path = tmp_path / "backup.db"
        result = write_backup(BackupOptions(
            out_path=out_path, db_path=env["db"],
        ))
        assert out_path.exists()
        assert result.size_bytes > 0
    finally:
        stop.set()
        t.join(timeout=2.0)


def test_backup_round_trip_preserves_row_counts(env, tmp_path) -> None:
    """Backup -> restore -> backup again: the two backups carry the
    same row counts (timestamps + sha256 will differ; row counts
    must match exactly)."""
    _seed_store(env["db"])
    first = tmp_path / "first.db"
    write_backup(BackupOptions(out_path=first, db_path=env["db"]))

    dest = tmp_path / "restored.db"
    restore_from(RestoreOptions(
        in_path=first, dest_db_path=str(dest), probe_skip=True,
    ))

    second = tmp_path / "second.db"
    write_backup(BackupOptions(out_path=second, db_path=str(dest)))

    counts_first = {
        t: _row_count(first, t)
        for t in ("rules", "tasks", "pause_events", BACKUP_METADATA_TABLE)
    }
    counts_second = {
        t: _row_count(second, t)
        for t in ("rules", "tasks", "pause_events", BACKUP_METADATA_TABLE)
    }
    assert counts_first == counts_second


def test_backup_round_trip_with_audit_preserves_audit_rows(env, tmp_path) -> None:
    _seed_store(env["db"], decisions=11)
    first = tmp_path / "first.db"
    write_backup(BackupOptions(
        out_path=first, db_path=env["db"], include_audit=True,
    ))
    assert _row_count(first, "decisions") == 11

    dest = tmp_path / "restored.db"
    restore_from(RestoreOptions(
        in_path=first, dest_db_path=str(dest), probe_skip=True,
    ))
    assert _row_count(dest, "decisions") == 11


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def test_restore_into_empty_db_succeeds(env, tmp_path) -> None:
    _seed_store(env["db"], rules=2)
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    dest = tmp_path / "new.db"
    result = restore_from(RestoreOptions(
        in_path=backup, dest_db_path=str(dest), probe_skip=True,
    ))
    assert dest.exists()
    assert result.sha256
    assert result.row_counts.get("rules") == 2


def test_restore_into_non_empty_db_refused_without_force(env, tmp_path) -> None:
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    # Build a separate populated destination DB.
    dest = tmp_path / "other.db"
    _seed_store(str(dest), rules=1)

    with pytest.raises(DestinationNotEmptyError, match="--force"):
        restore_from(RestoreOptions(
            in_path=backup, dest_db_path=str(dest), probe_skip=True,
        ))


def test_restore_into_non_empty_db_succeeds_with_force(env, tmp_path) -> None:
    _seed_store(env["db"], rules=4)
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    dest = tmp_path / "other.db"
    _seed_store(str(dest), rules=1)

    result = restore_from(RestoreOptions(
        in_path=backup, dest_db_path=str(dest),
        force=True, probe_skip=True,
    ))
    # Destination NOW has rules from the backup (4), not 1.
    assert result.row_counts.get("rules") == 4


def test_restore_refuses_non_backup_sqlite_file(env, tmp_path) -> None:
    # Build a SQLite file that doesn't carry the metadata table.
    bogus = tmp_path / "bogus.db"
    conn = sqlite3.connect(str(bogus))
    try:
        conn.execute("CREATE TABLE foo (id INTEGER)")
    finally:
        conn.close()

    dest = tmp_path / "dest.db"
    with pytest.raises(NotABackupFileError, match=BACKUP_METADATA_TABLE):
        restore_from(RestoreOptions(
            in_path=bogus, dest_db_path=str(dest), probe_skip=True,
        ))


def test_restore_refuses_missing_source_file(env, tmp_path) -> None:
    dest = tmp_path / "dest.db"
    with pytest.raises(BackupError, match="does not exist"):
        restore_from(RestoreOptions(
            in_path=tmp_path / "missing.db",
            dest_db_path=str(dest), probe_skip=True,
        ))


def test_restore_refuses_schema_version_mismatch_even_with_force(
    env, tmp_path,
) -> None:
    """schema_version is a HARD gate: --force does NOT override
    (cross-schema is `ibounce migrate` territory)."""
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    # Hand-poke a different schema_version into the metadata table.
    conn = sqlite3.connect(str(backup))
    try:
        conn.execute(
            f"UPDATE {BACKUP_METADATA_TABLE} SET value = ? WHERE key = ?",
            (str(SCHEMA_VERSION + 1), "schema_version"),
        )
        conn.commit()
    finally:
        conn.close()

    dest = tmp_path / "dest.db"
    with pytest.raises(SchemaVersionMismatchError):
        restore_from(RestoreOptions(
            in_path=backup, dest_db_path=str(dest),
            force=True, probe_skip=True,
        ))


def test_restore_version_mismatch_refused_without_force(env, tmp_path) -> None:
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    # Hand-poke a different ibounce_version.
    conn = sqlite3.connect(str(backup))
    try:
        conn.execute(
            f"UPDATE {BACKUP_METADATA_TABLE} SET value = ? WHERE key = ?",
            ("9.9.9-fake", "ibounce_version"),
        )
        conn.commit()
    finally:
        conn.close()

    dest = tmp_path / "dest.db"
    with pytest.raises(IbounceVersionMismatchError):
        restore_from(RestoreOptions(
            in_path=backup, dest_db_path=str(dest), probe_skip=True,
        ))


def test_restore_version_mismatch_succeeds_with_force(env, tmp_path) -> None:
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    conn = sqlite3.connect(str(backup))
    try:
        conn.execute(
            f"UPDATE {BACKUP_METADATA_TABLE} SET value = ? WHERE key = ?",
            ("9.9.9-fake", "ibounce_version"),
        )
        conn.commit()
    finally:
        conn.close()

    dest = tmp_path / "dest.db"
    result = restore_from(RestoreOptions(
        in_path=backup, dest_db_path=str(dest),
        force=True, probe_skip=True,
    ))
    assert result.version_mismatch is True
    assert result.backup_ibounce_version == "9.9.9-fake"


def test_restore_refuses_if_ibounce_appears_running(env, tmp_path) -> None:
    """Bind a TCP listener on a free loopback port + point the probe
    at it; the restore should refuse with a stop-first message."""
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    # Bind a fresh port so we don't conflict with a real ibounce
    # that might be running on the test machine.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        dest = tmp_path / "dest.db"
        with pytest.raises(IbounceRunningError, match="Stop ibounce first|ibounce appears to be running"):
            restore_from(RestoreOptions(
                in_path=backup, dest_db_path=str(dest),
                probe_port=port, probe_skip=False,
            ))
    finally:
        listener.close()


def test_restore_probe_skip_bypasses_running_check(env, tmp_path) -> None:
    """--probe-skip lets the restore proceed even when something is
    listening on the probe port."""
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        dest = tmp_path / "dest.db"
        result = restore_from(RestoreOptions(
            in_path=backup, dest_db_path=str(dest),
            probe_port=port, probe_skip=True,
        ))
        assert dest.exists()
        assert result.dest_path == dest
    finally:
        listener.close()


def test_restore_preserves_source_backup_file(env, tmp_path) -> None:
    """Per [[creates-never-mutates]]: restore reads the source; it
    never deletes or modifies it. The operator may want to keep
    the backup around after the restore lands."""
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))
    before_sha = backup.read_bytes()

    dest = tmp_path / "dest.db"
    restore_from(RestoreOptions(
        in_path=backup, dest_db_path=str(dest), probe_skip=True,
    ))
    assert backup.exists()
    assert backup.read_bytes() == before_sha


def test_restore_sweeps_destination_wal_sidecars(env, tmp_path) -> None:
    """If the destination DB had a stale -wal / -shm sidecar, the
    restore removes them so SQLite doesn't try to replay them
    against the new file."""
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    dest = tmp_path / "dest.db"
    _seed_store(str(dest))
    wal = pathlib.Path(str(dest) + "-wal")
    shm = pathlib.Path(str(dest) + "-shm")
    wal.write_bytes(b"stale")
    shm.write_bytes(b"stale")

    restore_from(RestoreOptions(
        in_path=backup, dest_db_path=str(dest),
        force=True, probe_skip=True,
    ))
    assert not wal.exists()
    assert not shm.exists()


# ---------------------------------------------------------------------------
# Admin-action OCSF emission
# ---------------------------------------------------------------------------


def _drain_admin_actions(db_path: str) -> list[dict[str, Any]]:
    s = BouncerStore(db_path=db_path)
    try:
        rows = s.drain_pending_audit_events(limit=1000)
    finally:
        s.close()
    out: list[dict[str, Any]] = []
    for row in rows:
        if row["event_type"] != EVENT_TYPE_ADMIN_ACTION:
            continue
        out.append(json.loads(row["payload_json"]))
    return out


def test_backup_cli_emits_admin_action(env, runner, tmp_path) -> None:
    _seed_store(env["db"])
    out_path = tmp_path / "backup.db"
    result = runner.invoke(main, [
        "backup",
        "--out", str(out_path),
        "--db", env["db"],
    ])
    assert result.exit_code == 0, result.output
    payloads = _drain_admin_actions(env["db"])
    kinds = [p["kind"] for p in payloads]
    assert ADMIN_ACTION_BACKUP_CREATE in kinds
    backup_payload = next(p for p in payloads if p["kind"] == ADMIN_ACTION_BACKUP_CREATE)
    extra = backup_payload["extra"]
    assert extra["out_path"] == str(out_path)
    assert extra["sha256"]
    assert extra["schema_version"] == SCHEMA_VERSION
    assert extra["included_audit"] is False
    assert extra["included_prompts"] is False


def test_restore_cli_emits_admin_action(env, runner, tmp_path) -> None:
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    # Drain so the backup-create row from the seed step doesn't
    # pollute the post-restore drain.
    s = BouncerStore(db_path=env["db"])
    try:
        s.drain_pending_audit_events(limit=1000)
    finally:
        s.close()

    dest_db = tmp_path / "restored.db"
    result = runner.invoke(main, [
        "restore",
        "--in", str(backup),
        "--db", str(dest_db),
        "--probe-skip",
    ])
    assert result.exit_code == 0, result.output
    # The admin-action row lands in the RESTORED destination DB
    # (where the operator is now looking), not the source.
    payloads = _drain_admin_actions(str(dest_db))
    kinds = [p["kind"] for p in payloads]
    assert ADMIN_ACTION_BACKUP_RESTORE in kinds
    restore_payload = next(p for p in payloads if p["kind"] == ADMIN_ACTION_BACKUP_RESTORE)
    extra = restore_payload["extra"]
    assert extra["source_path"] == str(backup)
    assert extra["destination"] == str(dest_db)
    assert extra["force"] is False
    assert extra["probe_skipped"] is True


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_backup_writes_file(env, runner, tmp_path) -> None:
    _seed_store(env["db"])
    out_path = tmp_path / "backup.db"
    result = runner.invoke(main, [
        "backup",
        "--out", str(out_path),
        "--db", env["db"],
    ])
    assert result.exit_code == 0, result.output
    assert out_path.exists()
    assert "wrote ibounce backup to" in result.output
    assert f"schema_version={SCHEMA_VERSION}" in result.output


def test_cli_backup_include_audit_flag(env, runner, tmp_path) -> None:
    _seed_store(env["db"], decisions=3)
    out_path = tmp_path / "backup.db"
    result = runner.invoke(main, [
        "backup",
        "--out", str(out_path),
        "--db", env["db"],
        "--include-audit",
    ])
    assert result.exit_code == 0, result.output
    assert _row_count(out_path, "decisions") == 3


def test_cli_backup_default_out_in_cwd(env, runner, tmp_path, monkeypatch) -> None:
    """No --out → default lands in CWD with the ibounce-backup-*.db
    naming."""
    _seed_store(env["db"])
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, ["backup", "--db", env["db"]])
    assert result.exit_code == 0, result.output
    matches = list(tmp_path.glob("ibounce-backup-*.db"))
    assert matches, "default --out must write ibounce-backup-*.db in CWD"


def test_default_backup_path_shape() -> None:
    import re
    p = default_backup_path()
    assert p.suffix == ".db"
    assert p.name.startswith("ibounce-backup-")
    ts = p.stem[len("ibounce-backup-"):]
    assert re.fullmatch(r"\d{8}T\d{6}Z", ts), ts


def test_cli_restore_requires_in_flag(env, runner) -> None:
    result = runner.invoke(main, ["restore", "--db", env["db"], "--probe-skip"])
    assert result.exit_code != 0
    assert "--in" in result.output.lower() or "missing" in result.output.lower()


def test_cli_restore_into_empty_db(env, runner, tmp_path) -> None:
    _seed_store(env["db"], rules=5)
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    dest = tmp_path / "restored.db"
    result = runner.invoke(main, [
        "restore",
        "--in", str(backup),
        "--db", str(dest),
        "--probe-skip",
    ])
    assert result.exit_code == 0, result.output
    assert "restored ibounce state.db" in result.output
    assert _row_count(dest, "rules") == 5


def test_cli_restore_non_empty_without_force_fails(env, runner, tmp_path) -> None:
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    dest = tmp_path / "other.db"
    _seed_store(str(dest))

    result = runner.invoke(main, [
        "restore",
        "--in", str(backup),
        "--db", str(dest),
        "--probe-skip",
    ])
    assert result.exit_code != 0
    assert "--force" in result.output


def test_cli_restore_running_proxy_message_is_actionable(
    env, runner, tmp_path,
) -> None:
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        dest = tmp_path / "dest.db"
        result = runner.invoke(main, [
            "restore",
            "--in", str(backup),
            "--db", str(dest),
            "--probe-port", str(port),
        ])
        assert result.exit_code != 0
        assert "Stop ibounce first" in result.output
    finally:
        listener.close()


def test_cli_restore_version_mismatch_with_force_warns(env, runner, tmp_path) -> None:
    _seed_store(env["db"])
    backup = tmp_path / "backup.db"
    write_backup(BackupOptions(out_path=backup, db_path=env["db"]))

    conn = sqlite3.connect(str(backup))
    try:
        conn.execute(
            f"UPDATE {BACKUP_METADATA_TABLE} SET value = ? WHERE key = ?",
            ("9.9.9-fake", "ibounce_version"),
        )
        conn.commit()
    finally:
        conn.close()

    dest = tmp_path / "restored.db"
    result = runner.invoke(main, [
        "restore",
        "--in", str(backup),
        "--db", str(dest),
        "--probe-skip",
        "--force",
    ])
    assert result.exit_code == 0, result.output
    assert "WARNING" in result.output
    assert "9.9.9-fake" in result.output


# ---------------------------------------------------------------------------
# Doc-surface linting — neutral language per
# [[security-team-positioning-safety-not-surveillance]]
# ---------------------------------------------------------------------------


_FORBIDDEN_WORDS = ("violation", "infraction", "unauthorized")


def test_backup_module_strings_are_neutral() -> None:
    """No operator-facing string in the backup module uses the
    accusatory words the security-team-positioning memo forbids."""
    src = pathlib.Path(
        "src/iam_jit/bouncer/backup.py"
    ).read_text(encoding="utf-8").lower()
    for w in _FORBIDDEN_WORDS:
        assert w not in src, (
            f"backup.py contains forbidden word {w!r} — use neutral language"
        )


def test_backup_restore_doc_is_neutral() -> None:
    doc = pathlib.Path("docs/BACKUP-RESTORE.md").read_text(encoding="utf-8").lower()
    for w in _FORBIDDEN_WORDS:
        assert w not in doc, (
            f"BACKUP-RESTORE.md contains forbidden word {w!r}"
        )


def test_backup_cli_help_is_neutral(runner) -> None:
    for sub in ("backup", "restore"):
        result = runner.invoke(main, [sub, "--help"])
        assert result.exit_code == 0
        for w in _FORBIDDEN_WORDS:
            assert w not in result.output.lower(), (
                f"{sub} --help contains forbidden word {w!r}"
            )


# ---------------------------------------------------------------------------
# Constants sanity — pinned by spec
# ---------------------------------------------------------------------------


def test_metadata_table_name_pinned() -> None:
    """Spec'd cross-product name; changing breaks kbounce / dbounce
    parity."""
    assert BACKUP_METADATA_TABLE == "ibounce_backup_metadata"


def test_default_probe_port_pinned() -> None:
    """Spec'd default management port. Changing requires updating
    the docs and the diagnostics module too."""
    assert DEFAULT_PROBE_PORT == 8767
