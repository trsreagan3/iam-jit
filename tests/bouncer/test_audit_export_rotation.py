"""Tests for #311 / §A10 audit-log rotation + retention + recovery.

Covers the cross-product invariants the runbook in
`docs/LOG-RETENTION.md` promises:

  * Size-driven rotation fires when the active file crosses the
    `--audit-log-max-size-mb` threshold.
  * Age-driven rotation fires when the active file's mtime is older
    than `--audit-log-max-age-days`.
  * Rotated archives are gzip-compressed + name-pattern matches.
  * `recover_partial_tail` truncates a corrupt JSONL tail (crash
    recovery) without touching valid prior lines.
  * `purge_older_than` reaps only archives past their retention
    threshold; the ACTIVE file is never touched.
  * `disk_status` returns degraded / critical at the configured
    thresholds via the injectable statvfs seam.
  * `verify_integrity` rejects a corrupted archive.
  * Admin-action callbacks fire on rotation success + recovery.

Per `[[deliberate-feature-completion]]`: every public function in
`audit_export.rotation` has at least one assertion below; new
behaviour requires a new assertion here before it ships.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import pathlib
import time
from typing import Any

import pytest

from iam_jit.bouncer.audit_export import (
    AuditLogWriter,
    DiskStatus,
    archive_logs,
    disk_status,
    recover_partial_tail,
    rotate_db_daily,
    rotate_log,
    rotation_purge_older_than,
    should_rotate_by_age,
    should_rotate_by_size,
    verify_integrity,
)


# ---------------------------------------------------------------------------
# rotate() / size + age triggers
# ---------------------------------------------------------------------------


def test_should_rotate_by_size_true_when_over_threshold(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    p.write_bytes(b"x" * (2 * 1024 * 1024))  # 2 MB
    assert should_rotate_by_size(p, max_mb=1)


def test_should_rotate_by_size_false_when_under(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    p.write_bytes(b"x" * 1024)
    assert not should_rotate_by_size(p, max_mb=1)


def test_should_rotate_by_size_disabled_when_zero(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    p.write_bytes(b"x" * (50 * 1024 * 1024))
    assert not should_rotate_by_size(p, max_mb=0)


def test_should_rotate_by_age_true_when_old(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    p.write_text("{}\n")
    old = time.time() - 86400 * 10
    import os
    os.utime(p, (old, old))
    assert should_rotate_by_age(p, max_days=7)


def test_should_rotate_by_age_false_when_fresh(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    p.write_text("{}\n")
    assert not should_rotate_by_age(p, max_days=7)


def test_rotate_moves_and_gzips(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    p.write_text('{"id":1}\n{"id":2}\n')
    archive = rotate_log(p)
    assert archive is not None
    assert archive.exists()
    assert archive.name.startswith("audit-") and archive.name.endswith(".jsonl.gz")
    # Active file is gone (caller re-opens fresh).
    assert not p.exists()
    # Archive is valid gzip + contains original lines.
    with gzip.open(archive, "rb") as f:
        body = f.read().decode("utf-8")
    assert body == '{"id":1}\n{"id":2}\n'


def test_rotate_noop_on_missing(tmp_path: pathlib.Path):
    assert rotate_log(tmp_path / "absent.jsonl") is None


def test_rotate_noop_on_empty(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    p.touch()
    assert rotate_log(p) is None
    # Empty active file remains.
    assert p.exists()


# ---------------------------------------------------------------------------
# recover_partial_tail() — crash recovery
# ---------------------------------------------------------------------------


def test_recover_partial_tail_clean_file_noop(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    p.write_text('{"id":1}\n{"id":2}\n')
    trimmed = recover_partial_tail(p)
    assert trimmed == 0
    assert p.read_text() == '{"id":1}\n{"id":2}\n'


def test_recover_partial_tail_truncates_corrupt_tail(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    # The last "line" is `{"id":3` — missing closing brace + newline.
    p.write_text('{"id":1}\n{"id":2}\n{"id":3')
    trimmed = recover_partial_tail(p)
    assert trimmed == len('{"id":3')
    # Valid lines preserved; corrupt tail gone.
    assert p.read_text() == '{"id":1}\n{"id":2}\n'


def test_recover_partial_tail_missing_file(tmp_path: pathlib.Path):
    assert recover_partial_tail(tmp_path / "absent.jsonl") == 0


def test_recover_partial_tail_after_recovery_writes_succeed(tmp_path: pathlib.Path):
    # After recovery the next O_APPEND write must land cleanly.
    p = tmp_path / "audit.jsonl"
    p.write_text('{"id":1}\n{"id":2}\n{"corrupt')
    recover_partial_tail(p)
    with open(p, "ab") as f:
        f.write(b'{"id":3}\n')
    lines = p.read_text().splitlines()
    assert lines == ['{"id":1}', '{"id":2}', '{"id":3}']
    for line in lines:
        json.loads(line)  # all valid


# ---------------------------------------------------------------------------
# purge_older_than() — retention
# ---------------------------------------------------------------------------


def test_purge_older_than_reaps_old_jsonl_gz(tmp_path: pathlib.Path):
    archive = tmp_path / "audit-2026-01-01-000000.jsonl.gz"
    archive.write_bytes(b"\x1f\x8bfake")
    old = time.time() - 86400 * 10
    import os
    os.utime(archive, (old, old))
    removed = rotation_purge_older_than(tmp_path, jsonl_max_age_days=7)
    assert removed == [archive]
    assert not archive.exists()


def test_purge_older_than_never_touches_active(tmp_path: pathlib.Path):
    active = tmp_path / "audit.jsonl"
    active.write_text("{}\n")
    import os
    old = time.time() - 86400 * 365
    os.utime(active, (old, old))
    removed = rotation_purge_older_than(tmp_path, jsonl_max_age_days=7)
    assert removed == []
    assert active.exists()


def test_purge_older_than_reaps_db_archives(tmp_path: pathlib.Path):
    db_archive = tmp_path / "audit-2026-01-01.db.gz"
    db_archive.write_bytes(b"\x1f\x8bfake")
    import os
    old = time.time() - 86400 * 60
    os.utime(db_archive, (old, old))
    removed = rotation_purge_older_than(tmp_path, db_max_age_days=30)
    assert removed == [db_archive]


def test_purge_older_than_skips_recent_archives(tmp_path: pathlib.Path):
    archive = tmp_path / "audit-2026-05-22-120000.jsonl.gz"
    archive.write_bytes(b"\x1f\x8bfake")
    # mtime is now (default) → within 7-day window.
    removed = rotation_purge_older_than(tmp_path, jsonl_max_age_days=7)
    assert removed == []
    assert archive.exists()


# ---------------------------------------------------------------------------
# disk_status() — /healthz signal
# ---------------------------------------------------------------------------


def test_disk_status_ok(tmp_path: pathlib.Path):
    # 50% used → ok at default thresholds (warn=85, crit=95).
    status = disk_status(tmp_path, statvfs=(100, 50, 50))
    assert status.status == "ok"
    assert status.used_pct == 50.0


def test_disk_status_degraded_at_warn(tmp_path: pathlib.Path):
    status = disk_status(tmp_path, statvfs=(100, 90, 10), warn_pct=85, crit_pct=95)
    assert status.status == "degraded"
    assert "85%" in status.reason or "warn" in status.reason


def test_disk_status_critical_at_crit(tmp_path: pathlib.Path):
    status = disk_status(tmp_path, statvfs=(100, 98, 2), warn_pct=85, crit_pct=95)
    assert status.status == "critical"
    assert "95%" in status.reason or "critical" in status.reason


def test_disk_status_to_dict_shape(tmp_path: pathlib.Path):
    status = disk_status(tmp_path, statvfs=(100, 50, 50))
    d = status.to_dict()
    assert set(d.keys()) == {"status", "reason", "used_pct", "path"}


# ---------------------------------------------------------------------------
# verify_integrity() — doctor logs check
# ---------------------------------------------------------------------------


def test_verify_integrity_clean_dir(tmp_path: pathlib.Path):
    active = tmp_path / "audit.jsonl"
    active.write_text('{"id":1}\n')
    archive = tmp_path / "audit-2026-01-01-000000.jsonl.gz"
    with gzip.open(archive, "wb") as f:
        f.write(b'{"id":2}\n')
    res = verify_integrity(tmp_path)
    assert res.ok
    assert res.files_checked == 2
    assert res.failures == []


def test_verify_integrity_detects_corrupt_gzip(tmp_path: pathlib.Path):
    archive = tmp_path / "audit-2026-01-01-000000.jsonl.gz"
    archive.write_bytes(b"not a gzip file at all")
    res = verify_integrity(tmp_path)
    assert not res.ok
    assert len(res.failures) == 1


def test_verify_integrity_active_partial_tail_not_a_failure(tmp_path: pathlib.Path):
    # Active file with partial tail is RECOVERABLE — not flagged as
    # a failure. The full-file scan stops at the last newline.
    active = tmp_path / "audit.jsonl"
    active.write_text('{"id":1}\n{"id":2}\n{"partial')
    res = verify_integrity(tmp_path)
    assert res.ok


# ---------------------------------------------------------------------------
# archive_logs() — *bounce logs archive
# ---------------------------------------------------------------------------


def test_archive_logs_bundles_all_audit_files(tmp_path: pathlib.Path):
    src = tmp_path / "logs"
    src.mkdir()
    (src / "audit.jsonl").write_text('{"id":1}\n')
    (src / "audit-2026-01-01-000000.jsonl.gz").write_bytes(b"\x1f\x8bfake")
    (src / "audit-2026-01-01.db.gz").write_bytes(b"\x1f\x8bfake")
    (src / "unrelated.txt").write_text("ignore me")
    out = tmp_path / "bundle.tar.gz"
    archive_logs(src, out)
    import tarfile
    with tarfile.open(out, "r:gz") as tf:
        names = sorted(m.name for m in tf.getmembers())
    assert "audit.jsonl" in names
    assert "audit-2026-01-01-000000.jsonl.gz" in names
    assert "audit-2026-01-01.db.gz" in names
    assert "unrelated.txt" not in names


def test_archive_logs_can_exclude_active(tmp_path: pathlib.Path):
    src = tmp_path / "logs"
    src.mkdir()
    (src / "audit.jsonl").write_text('{"id":1}\n')
    (src / "audit-2026-01-01-000000.jsonl.gz").write_bytes(b"\x1f\x8bfake")
    out = tmp_path / "bundle.tar.gz"
    archive_logs(src, out, include_active=False)
    import tarfile
    with tarfile.open(out, "r:gz") as tf:
        names = [m.name for m in tf.getmembers()]
    assert "audit.jsonl" not in names
    assert "audit-2026-01-01-000000.jsonl.gz" in names


# ---------------------------------------------------------------------------
# rotate_db_daily()
# ---------------------------------------------------------------------------


def test_rotate_db_daily_gzips_archive(tmp_path: pathlib.Path):
    db = tmp_path / "audit.db"
    db.write_bytes(b"fake sqlite data")
    archive = rotate_db_daily(db)
    assert archive is not None
    assert archive.name.startswith("audit-") and archive.name.endswith(".db.gz")
    assert not db.exists()
    with gzip.open(archive, "rb") as f:
        assert f.read() == b"fake sqlite data"


def test_rotate_db_daily_noop_on_missing(tmp_path: pathlib.Path):
    assert rotate_db_daily(tmp_path / "absent.db") is None


# ---------------------------------------------------------------------------
# AuditLogWriter integration — rotation guard fires on writes
# ---------------------------------------------------------------------------


async def _drain_until(writer: AuditLogWriter,
                       predicate, timeout_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate(writer.status()):
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"timeout; last status={writer.status()}")


@pytest.mark.asyncio
async def test_writer_rotates_when_size_exceeded(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    rotated: list[pathlib.Path] = []
    # 1MB threshold; we'll write enough chunky events to exceed it.
    w = AuditLogWriter(
        path=p,
        max_size_mb=1,
        max_age_days=0,  # disable age trigger
        on_rotation=lambda path: rotated.append(path),
    )
    await w.start()
    try:
        big = {"event": "x", "padding": "y" * 4096}
        for _ in range(400):  # ~1.6 MB raw
            w.write(big)
        await _drain_until(w, lambda s: s["rotations"] >= 1, timeout_s=5.0)
    finally:
        await w.stop()
    assert rotated, "rotation callback should fire"
    assert rotated[0].name.startswith("audit-")
    assert rotated[0].name.endswith(".jsonl.gz")
    # Active file exists and is small again (post-rotation).
    assert p.exists()


@pytest.mark.asyncio
async def test_writer_recovers_partial_tail_on_start(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    # Pre-seed a file with a corrupt tail.
    p.write_text('{"id":1}\n{"id":2}\n{"partial')
    recovered: list[int] = []
    w = AuditLogWriter(
        path=p,
        max_size_mb=0,
        max_age_days=0,
        on_recovery=lambda n: recovered.append(n),
    )
    await w.start()
    try:
        w.write({"id": 3})
        await _drain_until(w, lambda s: s["total_events"] >= 1, timeout_s=2.0)
    finally:
        await w.stop()
    assert recovered == [len('{"partial')]
    body = p.read_text()
    lines = [ln for ln in body.splitlines() if ln.strip()]
    assert lines[0] == '{"id":1}'
    assert lines[1] == '{"id":2}'
    # Final line is the new event (well-formed JSON).
    json.loads(lines[-1])


@pytest.mark.asyncio
async def test_writer_status_exposes_rotation_telemetry(tmp_path: pathlib.Path):
    p = tmp_path / "audit.jsonl"
    w = AuditLogWriter(path=p, max_size_mb=50, max_age_days=7)
    await w.start()
    try:
        w.write({"id": 1})
        await _drain_until(w, lambda s: s["total_events"] >= 1, timeout_s=2.0)
        status = w.status()
        assert status["max_size_mb"] == 50
        assert status["max_age_days"] == 7
        assert status["rotations"] == 0
        assert status["rotation_failures"] == 0
        assert status["partial_bytes_recovered"] == 0
        assert status["last_rotation_path"] is None
    finally:
        await w.stop()
