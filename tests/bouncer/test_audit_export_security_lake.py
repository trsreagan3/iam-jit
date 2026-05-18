"""Tests for the Security Lake audit-export adapter (#258).

Per [[security-team-audit-export]] this is Channel 4 of the audit-
export transport: OCSF events get serialised as parquet + written to
an S3 bucket in the Security-Lake-compatible partition layout.

S3 interactions are mocked via moto so the tests never touch real
AWS (matches the [[don't-tailor-to-lighthouse]] discipline + lets the
tests run in CI without credentials).

The cross-product schema contract (kbouncer + dbounce ship the same
column set) is asserted in `test_canonical_ocsf_columns_locked_in`.
"""

from __future__ import annotations

import datetime as _dt
import io
import json

import pytest

from iam_jit.bouncer.audit_export import (
    OCSF_PARQUET_COLUMNS,
    SECURITY_LAKE_DEFAULT_ROTATION_SECONDS,
    SecurityLakeConfigError,
    SecurityLakeCredentialsError,
    SecurityLakeWriter,
    audit_event_from_decision,
)
from iam_jit.bouncer.audit_export.security_lake import (
    _flatten_event_to_row,
    _partition_path,
    _rows_to_parquet_bytes,
)


# ---------------------------------------------------------------------------
# Moto fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set fake creds so boto3 inside moto's mock doesn't try to read
    the operator's real config."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture()
def s3_bucket(aws_credentials: None):
    """Stand up a moto S3 bucket the writer can target."""
    from moto import mock_aws
    import boto3

    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        bucket = "ibounce-security-lake-test"
        client.create_bucket(Bucket=bucket)
        yield bucket


# ---------------------------------------------------------------------------
# Schema + helpers
# ---------------------------------------------------------------------------


def test_canonical_ocsf_columns_locked_in() -> None:
    """Cross-product contract per [[cross-product-agent-parity]]: the
    column set + order are byte-stable. kbouncer + dbounce assert the
    same list in their own tests — changing this list requires
    changing all three products together."""
    names = [name for name, _ in OCSF_PARQUET_COLUMNS]
    # Spot-check the load-bearing fields.
    assert names[0] == "metadata.version"
    assert "class_uid" in names
    assert "activity_id" in names
    assert "unmapped.iam_jit.verdict" in names
    assert "unmapped.iam_jit.decision_id" in names
    assert "unmapped.iam_jit.ext_json" in names
    assert "resources_json" in names
    # The full count is locked so a stray addition fails the test
    # (forces the author to update kbouncer + dbounce in lockstep).
    assert len(OCSF_PARQUET_COLUMNS) == 39


def test_flatten_event_to_row_drops_into_columns() -> None:
    event = audit_event_from_decision(
        decision_id=7,
        mode="transparent",
        profile="safe-default",
        verdict="deny",
        reason="explicit-deny rule",
        service="s3",
        action="DeleteBucket",
        arn="arn:aws:s3:::secret-bucket",
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
        enforced=True,
        principal="alice@example.com",
        request_id="req-xyz",
    )
    row = _flatten_event_to_row(event)
    # Every canonical column is present (None is fine; presence is
    # the invariant).
    for name, _ in OCSF_PARQUET_COLUMNS:
        assert name in row, f"column {name} missing from flattened row"
    # Load-bearing fields land in the right cells.
    assert row["metadata.version"] == "1.1.0"
    assert row["metadata.product.name"] == "ibounce"
    assert row["metadata.product.vendor_name"] == "iam-jit"
    assert row["class_uid"] == 6003
    assert row["activity_id"] == 4  # Delete
    assert row["unmapped.iam_jit.verdict"] == "deny"
    assert row["unmapped.iam_jit.decision_id"] == 7
    assert row["unmapped.iam_jit.enforced"] is True
    assert row["actor.user.name"] == "alice@example.com"
    assert row["api.operation"] == "s3:DeleteBucket"
    # resources_json round-trips back to the ARN.
    resources = json.loads(row["resources_json"])
    assert resources[0]["uid"] == "arn:aws:s3:::secret-bucket"


def test_partition_path_format_matches_security_lake_layout() -> None:
    when = _dt.datetime(2026, 5, 19, 14, 7, 33, tzinfo=_dt.UTC)
    path = _partition_path(
        region="us-east-1", when=when, class_uid=6003, unix_ms=1747667253000,
    )
    # The Security-Lake-compatible partition layout, exact.
    assert path == (
        "region=us-east-1/eventday=20260519/eventhour=14/"
        "api_activity-1747667253000.parquet"
    )


def test_rows_to_parquet_round_trip() -> None:
    """Serialise rows, read them back via pyarrow, every column matches."""
    import pyarrow.parquet as pq

    event = audit_event_from_decision(
        decision_id=11, mode="cooperative", profile=None, verdict="allow",
        reason="rule#1", service="ec2", action="DescribeInstances",
        arn=None, region="us-west-2", host="ec2.us-west-2.amazonaws.com",
    )
    row = _flatten_event_to_row(event)
    parquet_bytes = _rows_to_parquet_bytes([row])
    assert parquet_bytes  # non-empty
    table = pq.read_table(io.BytesIO(parquet_bytes))
    # Schema preserved end-to-end.
    actual_columns = [f.name for f in table.schema]
    expected_columns = [name for name, _ in OCSF_PARQUET_COLUMNS]
    assert actual_columns == expected_columns
    # Spot-check a few cells.
    pdf = table.to_pylist()
    assert len(pdf) == 1
    assert pdf[0]["class_uid"] == 6003
    assert pdf[0]["api.operation"] == "ec2:DescribeInstances"
    assert pdf[0]["unmapped.iam_jit.verdict"] == "allow"


# ---------------------------------------------------------------------------
# Construction / refusal-to-start
# ---------------------------------------------------------------------------


def test_writer_refuses_empty_bucket() -> None:
    with pytest.raises(SecurityLakeConfigError):
        SecurityLakeWriter(bucket="", region="us-east-1")


def test_writer_refuses_empty_region() -> None:
    with pytest.raises(SecurityLakeConfigError):
        SecurityLakeWriter(bucket="b", region="")


def test_writer_refuses_non_positive_rotation() -> None:
    with pytest.raises(SecurityLakeConfigError):
        SecurityLakeWriter(bucket="b", region="r", rotation_seconds=0)


def test_writer_refuses_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """No credentials anywhere -> SecurityLakeCredentialsError at start()."""
    # Force every credential lookup path to fail.
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_SECURITY_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/iam-jit-test-config")
    monkeypatch.setenv(
        "AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/iam-jit-test-creds",
    )
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")

    writer = SecurityLakeWriter(bucket="b", region="us-east-1")
    with pytest.raises(SecurityLakeCredentialsError):
        writer.start()


# ---------------------------------------------------------------------------
# End-to-end via moto S3
# ---------------------------------------------------------------------------


def _drain_until(predicate, timeout_s: float = 5.0) -> None:
    """Poll-loop helper for the async ticker tests."""
    import time as _time

    deadline = _time.monotonic() + timeout_s
    while _time.monotonic() < deadline:
        if predicate():
            return
        _time.sleep(0.05)
    raise AssertionError("predicate never became true")


def test_writer_flushes_on_stop(s3_bucket: str) -> None:
    """The hard guarantee from the spec: stop() flushes pending."""
    writer = SecurityLakeWriter(
        bucket=s3_bucket, region="us-east-1",
        # 10 minutes — won't fire during the test; only stop() will.
        rotation_seconds=600,
    )
    writer.start()
    try:
        for i in range(3):
            writer.write(audit_event_from_decision(
                decision_id=i, mode="transparent", profile=None,
                verdict="allow", reason="", service="s3",
                action="GetObject", arn=None, region="us-east-1",
                host="s3.us-east-1.amazonaws.com",
            ))
        # Nothing should be in S3 yet.
        import boto3
        s3 = boto3.client("s3", region_name="us-east-1")
        listing = s3.list_objects_v2(Bucket=s3_bucket)
        assert listing.get("KeyCount", 0) == 0
    finally:
        writer.stop()
    # After stop() the file is there.
    s3 = boto3.client("s3", region_name="us-east-1")
    listing = s3.list_objects_v2(Bucket=s3_bucket)
    assert listing.get("KeyCount", 0) == 1
    key = listing["Contents"][0]["Key"]
    # Partition layout matches.
    assert key.startswith("region=us-east-1/eventday=")
    assert "/eventhour=" in key
    assert key.endswith(".parquet")
    assert "/api_activity-" in key
    # Status reports the flush.
    status = writer.status()
    assert status["total_events"] == 3
    assert status["total_files_written"] == 1
    assert status["total_bytes_written"] > 0


def test_writer_partitions_by_class_uid(s3_bucket: str) -> None:
    """Different OCSF classes land in separate files (per-class
    batching)."""
    writer = SecurityLakeWriter(
        bucket=s3_bucket, region="us-east-1", rotation_seconds=600,
    )
    writer.start()
    try:
        # One real OCSF 6003 decision event.
        writer.write(audit_event_from_decision(
            decision_id=1, mode="transparent", profile=None,
            verdict="allow", reason="", service="s3",
            action="GetObject", arn=None, region="us-east-1",
            host="s3.us-east-1.amazonaws.com",
        ))
        # One synthetic with a fake class_uid 7777 — exercises the
        # per-class bucketing path.
        writer.write({
            "metadata": {"version": "1.1.0",
                         "product": {"name": "ibounce",
                                     "vendor_name": "iam-jit",
                                     "version": "0.0.0"}},
            "time": 1, "class_uid": 7777, "class_name": "Synthetic",
            "category_uid": 6, "category_name": "Application Activity",
            "activity_id": 99, "activity_name": "synthetic",
            "type_uid": 777799, "type_name": "Synthetic: Other",
            "severity_id": 1, "severity": "Informational",
            "status_id": 1, "status": "Success", "status_detail": "",
            "actor": {"user": {"name": "", "uid": ""}},
            "api": {"operation": "", "service": {"name": ""},
                    "request": {"uid": ""}},
            "resources": [], "src_endpoint": {}, "dst_endpoint": {},
            "unmapped": {"iam_jit": {"event_type": "SYNTHETIC", "ext": {}}},
        })
    finally:
        writer.stop()
    import boto3
    s3 = boto3.client("s3", region_name="us-east-1")
    listing = s3.list_objects_v2(Bucket=s3_bucket)
    keys = [obj["Key"] for obj in listing.get("Contents", [])]
    assert len(keys) == 2, keys
    # One file under api_activity-, one under class-7777-.
    assert any("/api_activity-" in k for k in keys)
    assert any("/class-7777-" in k for k in keys)


def test_writer_flushes_on_size_cap(s3_bucket: str) -> None:
    """When in-memory estimate crosses the cap, flush fires for that
    class even though the rotation deadline hasn't hit."""
    writer = SecurityLakeWriter(
        bucket=s3_bucket, region="us-east-1",
        rotation_seconds=600,
        # 2KB cap so 2 rows (estimate 1024 each) trip the size flush.
        max_batch_bytes=2048,
    )
    writer.start()
    try:
        # 2 rows + a 3rd should already see at least one flushed file.
        for i in range(3):
            writer.write(audit_event_from_decision(
                decision_id=i, mode="transparent", profile=None,
                verdict="allow", reason="", service="s3",
                action="GetObject", arn=None, region="us-east-1",
                host="s3.us-east-1.amazonaws.com",
            ))
    finally:
        writer.stop()
    import boto3
    s3 = boto3.client("s3", region_name="us-east-1")
    listing = s3.list_objects_v2(Bucket=s3_bucket)
    # 2 files: one size-triggered (2 rows) + one stop-triggered (1 row).
    keys = [obj["Key"] for obj in listing.get("Contents", [])]
    assert len(keys) == 2, keys


def test_writer_flushes_on_rotation_timer(
    s3_bucket: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rotation deadline elapses → batch flushes without stop()."""
    # Mock clock so the ticker thinks rotation_seconds elapsed
    # immediately after the first write.
    fake_now = [_dt.datetime(2026, 5, 19, 14, 0, 0, tzinfo=_dt.UTC)]

    def _now() -> _dt.datetime:
        return fake_now[0]

    writer = SecurityLakeWriter(
        bucket=s3_bucket, region="us-east-1",
        rotation_seconds=1,
        _now=_now,
    )
    writer.start()
    try:
        writer.write(audit_event_from_decision(
            decision_id=1, mode="transparent", profile=None,
            verdict="allow", reason="", service="s3",
            action="GetObject", arn=None, region="us-east-1",
            host="s3.us-east-1.amazonaws.com",
        ))
        # Jump the fake clock past the deadline.
        fake_now[0] = fake_now[0] + _dt.timedelta(seconds=5)

        # Wait for the ticker to observe the deadline + flush.
        import boto3
        s3 = boto3.client("s3", region_name="us-east-1")

        def _flushed() -> bool:
            return s3.list_objects_v2(Bucket=s3_bucket).get("KeyCount", 0) >= 1

        _drain_until(_flushed, timeout_s=5.0)
    finally:
        writer.stop()


def test_writer_parquet_readable_after_flush(s3_bucket: str) -> None:
    """The bytes uploaded to S3 round-trip through pyarrow back to the
    original event payload."""
    import boto3
    import pyarrow.parquet as pq

    writer = SecurityLakeWriter(
        bucket=s3_bucket, region="us-east-1", rotation_seconds=600,
    )
    writer.start()
    try:
        ev = audit_event_from_decision(
            decision_id=42, mode="transparent", profile="safe-default",
            verdict="deny", reason="explicit-deny rule",
            service="iam", action="CreateAccessKey",
            arn="arn:aws:iam::111111111111:user/bot",
            region="us-east-1", host="iam.amazonaws.com",
            enforced=True, principal="bot@example.com", request_id="r-1",
        )
        writer.write(ev)
    finally:
        writer.stop()
    s3 = boto3.client("s3", region_name="us-east-1")
    listing = s3.list_objects_v2(Bucket=s3_bucket)
    key = listing["Contents"][0]["Key"]
    obj = s3.get_object(Bucket=s3_bucket, Key=key)
    body = obj["Body"].read()
    table = pq.read_table(io.BytesIO(body))
    row = table.to_pylist()[0]
    assert row["class_uid"] == 6003
    assert row["api.operation"] == "iam:CreateAccessKey"
    assert row["unmapped.iam_jit.verdict"] == "deny"
    assert row["unmapped.iam_jit.enforced"] is True
    assert row["actor.user.name"] == "bot@example.com"
    # resources_json contains the ARN.
    res = json.loads(row["resources_json"])
    assert res[0]["uid"] == "arn:aws:iam::111111111111:user/bot"


def test_writer_dropped_count_on_overflow(s3_bucket: str) -> None:
    """When in-memory pending rows exceed max_pending_rows, the writer
    drops + bumps the counter (status surfaces the drop)."""
    writer = SecurityLakeWriter(
        bucket=s3_bucket, region="us-east-1", rotation_seconds=600,
        max_pending_rows=2,
    )
    writer.start()
    try:
        for i in range(4):
            writer.write(audit_event_from_decision(
                decision_id=i, mode="transparent", profile=None,
                verdict="allow", reason="", service="s3",
                action="GetObject", arn=None, region="us-east-1",
                host="s3.us-east-1.amazonaws.com",
            ))
        assert writer.status()["dropped_events"] == 2
        assert writer.status()["pending_rows"] == 2
    finally:
        writer.stop()


def test_writer_status_shape_for_mcp(s3_bucket: str) -> None:
    """The MCP audit-export status tool expects a stable dict shape."""
    writer = SecurityLakeWriter(
        bucket=s3_bucket, region="us-east-1", rotation_seconds=600,
    )
    writer.start()
    try:
        st = writer.status()
        # The MCP tool branches on `configured`; everything else must
        # be readable without further KeyError protection.
        for key in (
            "configured", "bucket", "region", "role_arn", "account_id",
            "caller_arn", "rotation_seconds", "max_batch_bytes",
            "total_events", "total_files_written", "total_bytes_written",
            "dropped_events", "pending_rows", "last_error",
            "last_error_at_unix", "writes_ok",
        ):
            assert key in st, f"missing key {key} in status snapshot"
        assert st["configured"] is True
        assert st["bucket"] == s3_bucket
        assert st["region"] == "us-east-1"
        assert st["rotation_seconds"] == 600
        assert st["writes_ok"] is True
    finally:
        writer.stop()


def test_writer_defaults_match_spec() -> None:
    """The defaults the issue body locks in (300s rotation, 10 MiB cap)."""
    assert SECURITY_LAKE_DEFAULT_ROTATION_SECONDS == 300
    # The size cap default is 10 MiB.
    from iam_jit.bouncer.audit_export.security_lake import (
        DEFAULT_MAX_BATCH_BYTES,
    )
    assert DEFAULT_MAX_BATCH_BYTES == 10 * 1024 * 1024
