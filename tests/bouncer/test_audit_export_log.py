"""Tests for the JSONL audit-log writer (#252 Slice 1).

Per [[security-team-audit-export]] this is the FREE-tier channel:
- Append-only `O_APPEND|O_CREAT|O_WRONLY`
- Async-queued, never blocks the proxy hot-path
- Optional fsync for compliance-grade durability
- No rotation built-in (operators use logrotate / Fluent Bit / Vector)
- Fail-soft: filesystem errors are recorded on the status counter
  but never raise into the proxy
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import time

import pytest

from iam_jit.bouncer.audit_export import (
    AUDIT_EVENT_SCHEMA_VERSION,
    AuditLogWriter,
    audit_event_from_decision,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _drain_for(writer: AuditLogWriter, target_count: int,
                     timeout_s: float = 2.0) -> None:
    """Poll until the writer's status reports `target_count` events
    have been written, or `timeout_s` elapses. Used so tests don't
    race with the async worker."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if writer.status()["total_events"] >= target_count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(
        f"writer did not reach {target_count} events; "
        f"last status: {writer.status()}"
    )


# ---------------------------------------------------------------------------
# Basic writer lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_writer_creates_path_and_appends_jsonl(
    tmp_path: pathlib.Path,
) -> None:
    """The writer creates the file if missing + each event becomes
    one line of valid JSON."""
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path)
    await writer.start()
    try:
        for i in range(3):
            writer.write({"ts": "2026-05-18T00:00:00Z", "i": i})
        await _drain_for(writer, target_count=3)
    finally:
        await writer.stop()

    assert log_path.exists()
    lines = log_path.read_text().splitlines()
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    assert [p["i"] for p in parsed] == [0, 1, 2]


@pytest.mark.asyncio
async def test_writer_creates_parent_directory(
    tmp_path: pathlib.Path,
) -> None:
    """The writer creates a missing parent dir (operator-convenience
    parallel to the SQLite store)."""
    nested = tmp_path / "a" / "b" / "c" / "audit.jsonl"
    writer = AuditLogWriter(path=nested)
    await writer.start()
    try:
        writer.write({"event": "test"})
        await _drain_for(writer, target_count=1)
    finally:
        await writer.stop()
    assert nested.exists()


@pytest.mark.asyncio
async def test_writer_appends_does_not_truncate(
    tmp_path: pathlib.Path,
) -> None:
    """A second writer against the same path appends to the existing
    content rather than truncating — load-bearing for sidecar
    shippers that rotate underneath."""
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text('{"pre-existing": true}\n')

    writer = AuditLogWriter(path=log_path)
    await writer.start()
    try:
        writer.write({"event": "added"})
        await _drain_for(writer, target_count=1)
    finally:
        await writer.stop()

    lines = log_path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"pre-existing": True}
    assert json.loads(lines[1])["event"] == "added"


@pytest.mark.asyncio
async def test_writer_status_reports_counters(
    tmp_path: pathlib.Path,
) -> None:
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path)
    await writer.start()
    try:
        for i in range(5):
            writer.write({"i": i})
        await _drain_for(writer, target_count=5)
        status = writer.status()
        assert status["configured"] is True
        assert status["path"] == str(log_path)
        assert status["total_events"] == 5
        assert status["dropped_events"] == 0
        assert status["last_error"] is None
    finally:
        await writer.stop()


# ---------------------------------------------------------------------------
# Fsync flag
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_writer_fsync_flag_propagates(
    tmp_path: pathlib.Path,
) -> None:
    """The fsync flag is exposed on the status object so the operator
    + the MCP status tool can confirm the setting."""
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path, fsync=True)
    await writer.start()
    try:
        writer.write({"durability": "compliance-grade"})
        await _drain_for(writer, target_count=1)
        assert writer.status()["fsync"] is True
    finally:
        await writer.stop()


@pytest.mark.slow
@pytest.mark.asyncio
async def test_writer_fsync_does_not_explode(
    tmp_path: pathlib.Path,
) -> None:
    """Slow-marked smoke test: fsync mode handles 50 writes without
    errors. The perf trade-off is documented in the CLI help — this
    just confirms it doesn't blow up."""
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path, fsync=True)
    await writer.start()
    try:
        for i in range(50):
            writer.write({"i": i})
        await _drain_for(writer, target_count=50, timeout_s=5.0)
    finally:
        await writer.stop()
    assert len(log_path.read_text().splitlines()) == 50


# ---------------------------------------------------------------------------
# Backpressure behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_writer_drops_on_queue_overflow_without_blocking(
    tmp_path: pathlib.Path,
) -> None:
    """write() is non-blocking. With a tiny queue + the worker
    paused, additional writes are DROPPED + the counter is bumped
    rather than the caller blocking."""
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path, queue_maxsize=2)
    await writer.start()
    # Cancel the worker so the queue fills up without draining.
    if writer._worker_task is not None:
        writer._worker_task.cancel()
        try:
            await writer._worker_task
        except asyncio.CancelledError:
            pass
    try:
        # Fill + overflow.
        writer.write({"i": 0})
        writer.write({"i": 1})
        # Queue is full; subsequent writes should drop, not block.
        for i in range(5):
            writer.write({"i": 100 + i})
        status = writer.status()
        assert status["dropped_events"] == 5
        assert "queue full" in (status["last_error"] or "")
    finally:
        # Manually close fd because stop() expects a live worker.
        if writer._fd is not None:
            import os as _os
            _os.close(writer._fd)
            writer._fd = None
        writer._started = False


# ---------------------------------------------------------------------------
# Schema completeness — what the proxy actually emits
# ---------------------------------------------------------------------------


def test_audit_event_schema_has_required_top_level_fields() -> None:
    """The shared schema from [[security-team-audit-export]] requires
    a fixed set of top-level fields. Every consumer (Splunk, Datadog,
    a custom collector) expects them present."""
    event = audit_event_from_decision(
        decision_id=42,
        mode="transparent",
        profile="safe-default",
        verdict="deny",
        reason="explicit-deny rule",
        service="s3",
        action="DeleteBucket",
        arn="arn:aws:s3:::secret-bucket",
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
        upstream="s3.us-east-1.amazonaws.com",
        enforced=True,
        active_pause_id=None,
        principal="alice@example.com",
        request_id="req-uuid-1",
    )
    required = {
        "ts", "schema_version", "product", "version", "event_type",
        "decision_id", "mode", "profile", "verdict", "reason",
        "principal", "action", "service", "resource", "region",
        "request_id", "host", "upstream", "ext",
    }
    missing = required - set(event.keys())
    assert not missing, f"event missing required fields: {missing}"
    assert event["schema_version"] == AUDIT_EVENT_SCHEMA_VERSION
    assert event["product"] == "ibounce"
    assert event["event_type"] == "proxy.decision"
    assert event["decision_id"] == 42
    assert event["verdict"] == "deny"
    assert event["action"] == "s3:DeleteBucket"
    assert event["resource"] == "arn:aws:s3:::secret-bucket"
    assert event["ext"]["enforced"] is True


def test_audit_event_ts_is_z_suffixed_iso() -> None:
    """The timestamp uses the canonical Z suffix so the JSONL stream
    is parseable by tools that don't accept the explicit +00:00
    offset (some older Splunk versions)."""
    event = audit_event_from_decision(
        decision_id=0, mode="cooperative", profile=None, verdict="allow",
        reason="ok", service="s3", action="GetObject", arn=None,
        region=None, host="s3.amazonaws.com",
    )
    assert event["ts"].endswith("Z")


def test_audit_event_omits_active_pause_id_when_none() -> None:
    """When no pause is active the field is not present in `ext`
    (keeps the payload tidy)."""
    event = audit_event_from_decision(
        decision_id=0, mode="cooperative", profile=None, verdict="allow",
        reason="ok", service="s3", action="GetObject", arn=None,
        region=None, host="s3.amazonaws.com",
    )
    assert "active_pause_id" not in event["ext"]


def test_audit_event_extra_merges_into_ext_not_top_level() -> None:
    """Per-product extensions go in `ext`; the top-level keys are
    reserved for the shared cross-product schema."""
    event = audit_event_from_decision(
        decision_id=0, mode="cooperative", profile=None, verdict="allow",
        reason="ok", service="s3", action="GetObject", arn=None,
        region=None, host="s3.amazonaws.com",
        extra={"matched_rule_id": 7, "active_task_id": "task-1"},
    )
    assert event["ext"]["matched_rule_id"] == 7
    assert event["ext"]["active_task_id"] == "task-1"
    # Defensive: extra keys did not collide with top-level.
    assert "matched_rule_id" not in event
