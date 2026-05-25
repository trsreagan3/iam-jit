"""Tests for the cloud-neutral S3-compatible NDJSON object-storage
sink (#317).

S3 interactions are mocked via moto so the tests never touch real
AWS (matches the [[don't-tailor-to-lighthouse]] discipline + lets the
tests run in CI without credentials).

Per [[cross-product-agent-parity]]: kbouncer / dbounce / gbounce
ship the same shape. The wire-format invariants asserted here are
asserted byte-identically in those products' Go tests.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import io
import json
import os
import tempfile
import threading
import time
from typing import Any

import pytest

from iam_jit.bouncer.audit_export import (
    OBJECT_STORAGE_DEFAULT_MAX_SIZE_MB,
    OBJECT_STORAGE_DEFAULT_REGION,
    OBJECT_STORAGE_DEFAULT_ROTATION_MINUTES,
    ObjectStorageConfigError,
    ObjectStorageCredentials,
    ObjectStorageCredentialsError,
    ObjectStorageWriter,
    load_object_storage_credentials,
)
from iam_jit.bouncer.audit_export.object_storage import (
    _default_instance_id,
    _partition_path,
)


# ---------------------------------------------------------------------------
# Defaults sanity
# ---------------------------------------------------------------------------


def test_module_defaults_match_spec() -> None:
    """Spec-locked defaults. The integration test + docs reference
    these constants; an accidental drift here breaks docs + tests."""
    assert OBJECT_STORAGE_DEFAULT_ROTATION_MINUTES == 5
    assert OBJECT_STORAGE_DEFAULT_MAX_SIZE_MB == 16
    assert OBJECT_STORAGE_DEFAULT_REGION == "us-east-1"


# ---------------------------------------------------------------------------
# Credentials resolution
# ---------------------------------------------------------------------------


def test_load_credentials_from_env() -> None:
    env = {
        "AWS_ACCESS_KEY_ID": "AKIA-test",
        "AWS_SECRET_ACCESS_KEY": "secret-test",
    }
    c = load_object_storage_credentials(env=env)
    assert c.access_key_id == "AKIA-test"
    assert c.secret_access_key == "secret-test"
    assert c.session_token is None


def test_load_credentials_from_env_with_session_token() -> None:
    env = {
        "AWS_ACCESS_KEY_ID": "k",
        "AWS_SECRET_ACCESS_KEY": "s",
        "AWS_SESSION_TOKEN": "tok",
    }
    c = load_object_storage_credentials(env=env)
    assert c.session_token == "tok"


def test_load_credentials_missing_env_raises() -> None:
    with pytest.raises(ObjectStorageCredentialsError):
        load_object_storage_credentials(env={})


def test_load_credentials_yaml_file_overrides_env(tmp_path) -> None:
    """File precedence: file > env vars."""
    env = {
        "AWS_ACCESS_KEY_ID": "env-key",
        "AWS_SECRET_ACCESS_KEY": "env-secret",
    }
    creds_path = tmp_path / "creds.yaml"
    creds_path.write_text(
        "access_key_id: file-key\n"
        "secret_access_key: file-secret\n"
        "session_token: file-token\n",
        encoding="utf-8",
    )
    # #524 WB-5: creds file must be 0o600 or tighter for the loader to
    # accept it. Test-fixture write inherits the process umask (often
    # 0o022 -> 0o644 file mode) so we explicitly tighten here.
    os.chmod(creds_path, 0o600)
    c = load_object_storage_credentials(str(creds_path), env=env)
    # File wins.
    assert c.access_key_id == "file-key"
    assert c.secret_access_key == "file-secret"
    assert c.session_token == "file-token"


def test_load_credentials_ini_file(tmp_path) -> None:
    creds_path = tmp_path / "creds.ini"
    creds_path.write_text(
        "[default]\n"
        "access_key_id=ini-key\n"
        "secret_access_key=ini-secret\n",
        encoding="utf-8",
    )
    # #524 WB-5: creds file must be 0o600 or tighter — see the YAML
    # variant above for context.
    os.chmod(creds_path, 0o600)
    c = load_object_storage_credentials(str(creds_path), env={})
    assert c.access_key_id == "ini-key"
    assert c.secret_access_key == "ini-secret"


def test_load_credentials_file_missing_raises(tmp_path) -> None:
    with pytest.raises(ObjectStorageCredentialsError):
        load_object_storage_credentials(str(tmp_path / "nope.yaml"), env={})


def test_load_credentials_file_incomplete_raises(tmp_path) -> None:
    creds_path = tmp_path / "creds.yaml"
    creds_path.write_text("access_key_id: only-key\n", encoding="utf-8")
    # #524 WB-5: tighten perms so the incomplete-shape failure mode
    # (the thing this test actually verifies) is reached rather than
    # the perm-check refusal getting there first.
    os.chmod(creds_path, 0o600)
    with pytest.raises(ObjectStorageCredentialsError):
        load_object_storage_credentials(str(creds_path), env={})


# ---------------------------------------------------------------------------
# Partition path + instance id
# ---------------------------------------------------------------------------


def test_partition_path_format_locked() -> None:
    """Hive-style partition layout. Athena / BigQuery / Spark / Trino
    all auto-discover from this shape; the integration test + docs
    cite the exact string."""
    when = _dt.datetime(2026, 5, 22, 14, 7, 33, tzinfo=_dt.UTC)
    path = _partition_path(
        prefix="bounce-audit/prod",
        product="ibounce",
        instance_id="host42-12345",
        when=when,
        unix_ms=1747920453000,
    )
    assert path == (
        "bounce-audit/prod/year=2026/month=05/day=22/hour=14/"
        "ibounce-host42-12345-1747920453000.jsonl.gz"
    )


def test_partition_path_empty_prefix() -> None:
    when = _dt.datetime(2026, 5, 22, 0, 0, 0, tzinfo=_dt.UTC)
    path = _partition_path(
        prefix="", product="ibounce", instance_id="i-0",
        when=when, unix_ms=1,
    )
    assert path == "year=2026/month=05/day=22/hour=00/ibounce-i-0-1.jsonl.gz"


def test_default_instance_id_includes_product_and_pid() -> None:
    iid = _default_instance_id(product="ibounce")
    assert iid.startswith("ibounce-")
    # PID is the trailing dash-separated segment.
    assert iid.split("-")[-1] == str(os.getpid())


def test_default_instance_id_replaces_dots_in_hostname() -> None:
    iid = _default_instance_id(
        product="ibounce", hostname_factory=lambda: "node.example.com",
    )
    # Dots replaced with dashes so S3-compat layers don't misinterpret.
    assert "." not in iid
    assert "node-example-com" in iid


# ---------------------------------------------------------------------------
# Construction / refusal
# ---------------------------------------------------------------------------


def _make_creds() -> ObjectStorageCredentials:
    return ObjectStorageCredentials(
        access_key_id="k", secret_access_key="s",
    )


def test_writer_refuses_empty_endpoint() -> None:
    with pytest.raises(ObjectStorageConfigError):
        ObjectStorageWriter(
            endpoint_url="", bucket="b", prefix="p", region="r",
            credentials=_make_creds(), product="ibounce",
        )


def test_writer_refuses_empty_bucket() -> None:
    with pytest.raises(ObjectStorageConfigError):
        ObjectStorageWriter(
            endpoint_url="http://x", bucket="", prefix="p", region="r",
            credentials=_make_creds(), product="ibounce",
        )


def test_writer_refuses_non_positive_rotation() -> None:
    with pytest.raises(ObjectStorageConfigError):
        ObjectStorageWriter(
            endpoint_url="http://x", bucket="b", prefix="p", region="r",
            credentials=_make_creds(), product="ibounce",
            rotation_minutes=0,
        )


def test_writer_refuses_non_positive_max_size() -> None:
    with pytest.raises(ObjectStorageConfigError):
        ObjectStorageWriter(
            endpoint_url="http://x", bucket="b", prefix="p", region="r",
            credentials=_make_creds(), product="ibounce",
            max_size_mb=0,
        )


# ---------------------------------------------------------------------------
# Happy path via stub S3 client
# ---------------------------------------------------------------------------


class _StubS3:
    """Minimal in-memory S3 stub. Records every PutObject + DeleteObject
    so tests can assert against the recorded calls.

    Implemented as a duck-typed match for ObjectStorageS3Client (the
    writer takes any object exposing the four methods used)."""

    def __init__(self, *, head_raises: Exception | None = None) -> None:
        self.objects: dict[str, dict[str, Any]] = {}
        self.head_raises = head_raises
        self.put_calls: list[dict[str, Any]] = []
        self.delete_calls: list[dict[str, Any]] = []

    def head_bucket(self, *, bucket: str) -> None:
        if self.head_raises:
            raise self.head_raises

    def put_object(
        self, *, bucket: str, key: str, body: bytes,
        content_type: str, content_encoding: str | None = None,
    ) -> None:
        self.put_calls.append({
            "bucket": bucket, "key": key, "body": body,
            "content_type": content_type,
            "content_encoding": content_encoding,
        })
        self.objects[f"{bucket}/{key}"] = {
            "body": body, "content_type": content_type,
            "content_encoding": content_encoding,
        }

    def delete_object(self, *, bucket: str, key: str) -> None:
        self.delete_calls.append({"bucket": bucket, "key": key})
        self.objects.pop(f"{bucket}/{key}", None)


def _make_writer(
    stub: _StubS3,
    *,
    rotation_minutes: int = 5,
    max_size_mb: int = 16,
    now_value: _dt.datetime | None = None,
    instance_id: str = "test-host-1",
) -> ObjectStorageWriter:
    now_value = now_value or _dt.datetime(2026, 5, 22, 12, 0, 0, tzinfo=_dt.UTC)
    return ObjectStorageWriter(
        endpoint_url="https://s3.example.com",
        bucket="bounce-audit-test",
        prefix="test-suite",
        region="us-east-1",
        credentials=_make_creds(),
        product="ibounce",
        instance_id=instance_id,
        rotation_minutes=rotation_minutes,
        max_size_mb=max_size_mb,
        s3_client=stub,
        _now=lambda: now_value,
    )


def test_start_probes_bucket_via_head() -> None:
    """Bucket existence is verified via head_bucket so a typo'd
    bucket name surfaces immediately rather than at first flush."""
    stub = _StubS3()
    w = _make_writer(stub)
    w.start()
    try:
        # head_bucket succeeds (no raise) — writer is now running.
        assert w._started is True
    finally:
        w.stop()


def test_start_bucket_not_found_raises() -> None:
    """Bucket probe failure -> ObjectStorageCredentialsError so the
    operator sees the misconfiguration at startup, not silently."""
    stub = _StubS3(head_raises=RuntimeError("NoSuchBucket"))
    w = _make_writer(stub)
    with pytest.raises(ObjectStorageCredentialsError):
        w.start()


def test_write_buffers_events_until_flush() -> None:
    """Single event doesn't trigger a flush; explicit flush() uploads
    the NDJSON file."""
    stub = _StubS3()
    w = _make_writer(stub)
    w.start()
    try:
        w.write({"class_uid": 6003, "activity_id": 4, "decision_id": 1})
        # Nothing uploaded yet.
        assert len(stub.put_calls) == 0
        w.flush()
        # Flush pushed one finalized file to S3.
        assert len(stub.put_calls) == 1
        call = stub.put_calls[0]
        assert call["bucket"] == "bounce-audit-test"
        assert call["content_type"] == "application/x-ndjson"
        assert call["content_encoding"] == "gzip"
        # Key under the prefix + Hive partition layout.
        assert call["key"].startswith("test-suite/year=2026/month=05/")
        assert call["key"].endswith(".jsonl.gz")
        assert "ibounce-test-host-1-" in call["key"]
        # Body is gzipped NDJSON.
        decompressed = gzip.decompress(call["body"]).decode("utf-8")
        lines = [ln for ln in decompressed.splitlines() if ln]
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["class_uid"] == 6003
        assert event["decision_id"] == 1
    finally:
        w.stop()


def test_write_multiple_events_one_file_per_flush() -> None:
    stub = _StubS3()
    w = _make_writer(stub)
    w.start()
    try:
        for i in range(10):
            w.write({"class_uid": 6003, "decision_id": i})
        w.flush()
        assert len(stub.put_calls) == 1
        decompressed = gzip.decompress(stub.put_calls[0]["body"]).decode("utf-8")
        lines = [ln for ln in decompressed.splitlines() if ln]
        # 10 events -> 10 NDJSON lines.
        assert len(lines) == 10
        for i, line in enumerate(lines):
            event = json.loads(line)
            assert event["decision_id"] == i
    finally:
        w.stop()


def test_status_surfaces_counts_and_config() -> None:
    stub = _StubS3()
    w = _make_writer(stub)
    w.start()
    try:
        w.write({"class_uid": 6003, "decision_id": 1})
        w.write({"class_uid": 6003, "decision_id": 2})
        s = w.status()
        assert s["configured"] is True
        assert s["bucket"] == "bounce-audit-test"
        assert s["prefix"] == "test-suite"
        assert s["region"] == "us-east-1"
        assert s["product"] == "ibounce"
        assert s["instance_id"] == "test-host-1"
        assert s["rotation_minutes"] == 5
        assert s["max_size_mb"] == 16
        # Two events buffered, no flush yet.
        assert s["pending_rows"] == 2
        assert s["total_files_written"] == 0
        w.flush()
        s = w.status()
        # After flush: one file written, no pending.
        assert s["pending_rows"] == 0
        assert s["total_files_written"] == 1
        assert s["total_events"] == 2
        assert s["total_bytes_written"] > 0
        assert s["writes_ok"] is True
    finally:
        w.stop()


def test_size_cap_triggers_synchronous_flush() -> None:
    """Crossing --audit-object-storage-max-size-mb triggers a flush
    on the call that crosses the cap."""
    stub = _StubS3()
    # 1 MB cap so the test cheaply crosses it with a few writes.
    w = _make_writer(stub, max_size_mb=1)
    w.start()
    try:
        # Write events with ~200KB of padding each so 5 writes cross
        # the 1 MB cap (4 fit, the 5th triggers flush).
        big_payload = "x" * (200 * 1024)
        for i in range(6):
            w.write({"class_uid": 6003, "decision_id": i, "padding": big_payload})
        # At least one flush should have fired.
        assert len(stub.put_calls) >= 1
    finally:
        w.stop()


def test_writer_drops_when_pending_buffer_full() -> None:
    """When pending_rows crosses max_pending_rows the writer drops the
    incoming event + bumps dropped_events. The other rows are
    unaffected."""
    stub = _StubS3()
    # Cap at 3 pending rows so we cross it cheaply. The 1024MB
    # max_size_mb keeps size-cap flushes from masking the drop test.
    w = ObjectStorageWriter(
        endpoint_url="https://s3.example.com",
        bucket="bounce-audit-test", prefix="t", region="us-east-1",
        credentials=_make_creds(), product="ibounce",
        instance_id="i", rotation_minutes=60, max_size_mb=1024,
        max_pending_rows=3, s3_client=stub,
    )
    w.start()
    try:
        for i in range(5):
            w.write({"class_uid": 6003, "decision_id": i})
        s = w.status()
        # 3 buffered, 2 dropped.
        assert s["pending_rows"] == 3
        assert s["dropped_events"] == 2
        assert s["last_error"] is not None
        assert "buffer full" in s["last_error"]
    finally:
        w.stop()


def test_write_before_start_is_noop() -> None:
    """Per the spec: writes silently no-op until start() succeeds."""
    stub = _StubS3()
    w = _make_writer(stub)
    # No start() call.
    w.write({"class_uid": 6003})
    assert len(stub.put_calls) == 0


def test_stop_flushes_pending_synchronously() -> None:
    """On shutdown, anything still buffered is finalized BEFORE
    stop() returns (per the spec)."""
    stub = _StubS3()
    w = _make_writer(stub)
    w.start()
    try:
        for i in range(3):
            w.write({"class_uid": 6003, "decision_id": i})
        assert len(stub.put_calls) == 0
    finally:
        w.stop()
    # stop() drained the buffer.
    assert len(stub.put_calls) == 1
    decompressed = gzip.decompress(stub.put_calls[0]["body"]).decode("utf-8")
    lines = [ln for ln in decompressed.splitlines() if ln]
    assert len(lines) == 3


def test_put_failure_records_last_error_and_writes_ok_false() -> None:
    """A PutObject error feeds into status() so the operator sees
    the failure without grepping logs. Per [[audit-export-failure-
    visibility]] writes_ok flips false."""

    class _PutFailsStub(_StubS3):
        def put_object(self, **kwargs: Any) -> None:  # type: ignore[override]
            raise RuntimeError("upstream timeout")

    stub = _PutFailsStub()
    w = _make_writer(stub)
    w.start()
    try:
        w.write({"class_uid": 6003, "decision_id": 1})
        w.flush()
        s = w.status()
        assert s["writes_ok"] is False
        assert s["last_error"] is not None
        assert "put_object failed" in s["last_error"]
        # Counters reflect the failed upload: file count stays 0.
        assert s["total_files_written"] == 0
    finally:
        w.stop()


def test_rotation_timer_triggers_flush_in_background() -> None:
    """The rotator finalizes the active buffer when the rotation
    interval elapses, even without explicit flush()."""
    stub = _StubS3()
    # Use a wall-clock advancer so the rotator's overdue check fires.
    # rotation_minutes is in MINUTES; we simulate elapsed time by
    # injecting a clock that jumps forward after the first write.
    base_now = _dt.datetime(2026, 5, 22, 12, 0, 0, tzinfo=_dt.UTC)
    advanced_now = base_now + _dt.timedelta(minutes=6)
    now_calls = {"count": 0}

    def _clock() -> _dt.datetime:
        now_calls["count"] += 1
        # First few calls return base_now (so the buffer first_seen
        # is set); subsequent calls return advanced_now so the
        # rotator's overdue check triggers a flush.
        if now_calls["count"] <= 2:
            return base_now
        return advanced_now

    w = ObjectStorageWriter(
        endpoint_url="https://s3.example.com",
        bucket="bounce-audit-test", prefix="t", region="us-east-1",
        credentials=_make_creds(), product="ibounce",
        instance_id="i", rotation_minutes=5, max_size_mb=1024,
        s3_client=stub, _now=_clock,
    )
    w.start()
    try:
        w.write({"class_uid": 6003, "decision_id": 1})
        # Wait for the 1s-tick rotator to wake at least once.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if len(stub.put_calls) >= 1:
                break
            time.sleep(0.1)
        assert len(stub.put_calls) >= 1, (
            "rotation timer should have triggered a flush"
        )
    finally:
        w.stop()
