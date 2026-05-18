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
    OCSF_SCHEMA_VERSION,
    AuditLogWriter,
    audit_dropped_event,
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
# OCSF v1.1.0 class 6003 (API Activity) schema compliance — #255
# ---------------------------------------------------------------------------
#
# Per [[ocsf-audit-schema]] every event MUST conform to OCSF v1.1.0
# class 6003. The tests below cover:
#   - Required-field presence + types (validates against the OCSF
#     class 6003 minimum specification, hand-rolled per the memo)
#   - Verdict -> status_id honest-mapping table
#   - activity_id classifier (verb prefix + policy_sentry path)
#   - Cross-product shape (kbounce/dbounce produce the same structure
#     modulo `metadata.product.name`)
#   - AUDIT_DROPPED synthetic also conforms


# Minimum required fields per OCSF v1.1.0 class 6003 + the iam-jit-
# specific extension contract from [[ocsf-audit-schema]]. We hand-roll
# the validator (rather than fetching the full JSON Schema from the
# OCSF site at test time) because:
#   * The OCSF JSON Schema is ~thousands of lines + drags in object
#     subschemas we don't populate.
#   * Test runs MUST work offline (CI without internet, the founder's
#     train commute, etc.).
#   * Hand-rolled validation against the spec's REQUIRED fields covers
#     the contract that matters for ingestion — a SIEM that gets all
#     required fields with the right types ingests successfully.
# If the OCSF spec adds a required field we'll add it here.
_OCSF_API_ACTIVITY_REQUIRED: dict[str, type | tuple[type, ...]] = {
    "metadata": dict,
    "time": int,
    "class_uid": int,
    "class_name": str,
    "category_uid": int,
    "category_name": str,
    "activity_id": int,
    "activity_name": str,
    "type_uid": int,
    "type_name": str,
    "severity_id": int,
    "severity": str,
    "status_id": int,
    "status": str,
    "actor": dict,
    "api": dict,
}


def _validate_ocsf_api_activity(event: dict) -> None:
    """Hand-rolled OCSF v1.1.0 class 6003 validator.

    Fails loud (AssertionError) on the FIRST violation; the operator
    sees the actual missing field rather than a generic "schema
    invalid" message.
    """
    # Required top-level fields + types.
    for field, expected_type in _OCSF_API_ACTIVITY_REQUIRED.items():
        assert field in event, f"OCSF: missing required field {field!r}"
        assert isinstance(event[field], expected_type), (
            f"OCSF: field {field!r} should be {expected_type}, "
            f"got {type(event[field]).__name__}"
        )
    # Class + category constants must match the class 6003 spec.
    assert event["class_uid"] == 6003, "OCSF: class_uid for API Activity is 6003"
    assert event["category_uid"] == 6, "OCSF: category_uid is 6"
    # type_uid = class_uid * 100 + activity_id per the OCSF formula.
    assert event["type_uid"] == 6003 * 100 + event["activity_id"], (
        f"OCSF: type_uid {event['type_uid']} != 600300 + activity_id "
        f"({event['activity_id']})"
    )
    # activity_id is in the allowed set for class 6003.
    assert event["activity_id"] in {0, 1, 2, 3, 4, 99}, (
        f"OCSF: activity_id {event['activity_id']} not in {{0,1,2,3,4,99}}"
    )
    # status_id is in the allowed set for class 6003.
    assert event["status_id"] in {0, 1, 2, 99}, (
        f"OCSF: status_id {event['status_id']} not in {{0,1,2,99}}"
    )
    # severity_id range per OCSF base spec (0..6).
    assert 0 <= event["severity_id"] <= 6, (
        f"OCSF: severity_id {event['severity_id']} out of range 0..6"
    )
    # metadata.version + metadata.product structure per OCSF base.
    md = event["metadata"]
    assert md.get("version") == "1.1.0", "OCSF: metadata.version must be 1.1.0"
    prod = md.get("product", {})
    assert isinstance(prod, dict), "OCSF: metadata.product must be an object"
    assert prod.get("name"), "OCSF: metadata.product.name is required"
    assert prod.get("vendor_name"), "OCSF: metadata.product.vendor_name required"
    # api object structure.
    api = event["api"]
    assert "operation" in api, "OCSF: api.operation is required"
    assert "service" in api and isinstance(api["service"], dict), (
        "OCSF: api.service must be an object"
    )


def test_event_validates_against_ocsf_schema() -> None:
    """The decision event passes the OCSF v1.1.0 class 6003 validator."""
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
    _validate_ocsf_api_activity(event)
    assert event["class_uid"] == 6003
    assert event["class_name"] == "API Activity"
    assert event["metadata"]["version"] == OCSF_SCHEMA_VERSION
    assert OCSF_SCHEMA_VERSION == "1.1.0"
    assert AUDIT_EVENT_SCHEMA_VERSION == OCSF_SCHEMA_VERSION


def test_event_validates_audit_dropped_synthetic() -> None:
    """The AUDIT_DROPPED synthetic also conforms to OCSF class 6003
    (per [[ocsf-audit-schema]])."""
    event = audit_dropped_event(
        dropped_count=7,
        reason="webhook-queue-overflow",
        queue_size=1000,
    )
    _validate_ocsf_api_activity(event)
    # Per memo: activity_id=99 (Other), severity_id=3 (Medium),
    # status_id=99 (Other), event_type tag preserved for downstream
    # filters that already key on the legacy event_type string.
    assert event["activity_id"] == 99
    assert event["severity_id"] == 3
    assert event["status_id"] == 99
    assert event["unmapped"]["iam_jit"]["event_type"] == "AUDIT_DROPPED"
    assert event["unmapped"]["iam_jit"]["dropped_count"] == 7


def test_event_matches_cross_product_shape() -> None:
    """The cross-product contract from [[ocsf-audit-schema]]: every
    Bounce product's audit-export event must satisfy these invariants
    so a single SIEM dashboard scoped on
    `metadata.product.vendor_name == "iam-jit"` catches them all."""
    event = audit_event_from_decision(
        decision_id=99,
        mode="cooperative",
        profile=None,
        verdict="allow",
        reason="rule#3",
        service="ec2",
        action="DescribeInstances",
        arn=None,
        region="us-west-2",
        host="ec2.us-west-2.amazonaws.com",
    )
    # The five cross-product invariants from the memo.
    assert event["class_uid"] == 6003
    assert event["metadata"]["version"] == "1.1.0"
    assert event["metadata"]["product"]["vendor_name"] == "iam-jit"
    assert event["metadata"]["product"]["name"] in {
        "ibounce", "kbounce", "dbounce",
    }
    assert event["type_uid"] == 600300 + event["activity_id"]
    assert "verdict" in event["unmapped"]["iam_jit"]
    assert isinstance(event["unmapped"]["iam_jit"]["decision_id"], int)
    assert event["unmapped"]["iam_jit"]["decision_id"] == 99


def test_activity_id_maps_aws_verbs() -> None:
    """AWS verb -> OCSF activity_id mapping per [[ocsf-audit-schema]]
    + [[scorer-is-ground-truth]] (policy_sentry reused as the source).
    """
    def aid(service: str, action: str) -> int:
        ev = audit_event_from_decision(
            decision_id=0, mode="x", profile=None, verdict="allow",
            reason="", service=service, action=action, arn=None,
            region=None, host="example.com",
        )
        return ev["activity_id"]

    # Reads (policy_sentry hits + verb fallback both covered).
    assert aid("s3", "GetObject") == 2
    assert aid("s3", "ListObjects") == 2
    assert aid("ec2", "DescribeInstances") == 2
    assert aid("dynamodb", "BatchGetItem") == 2
    # Creates.
    assert aid("s3", "CreateBucket") == 1
    assert aid("ec2", "RunInstances") == 1
    assert aid("iam", "PutRolePolicy") == 1
    # Updates.
    assert aid("ec2", "ModifyInstanceAttribute") == 3
    assert aid("iam", "AttachRolePolicy") == 3
    # Tagging API: policy_sentry classifies as "Tagging" -> Update (3)
    # per [[ocsf-audit-schema]] memo. This is the [[scorer-is-ground-
    # truth]] path winning over the verb-prefix fallback.
    assert aid("s3", "PutBucketTagging") == 3
    # Deletes.
    assert aid("s3", "DeleteBucket") == 4
    assert aid("ec2", "TerminateInstances") == 4
    assert aid("iam", "RemoveRoleFromInstanceProfile") == 4
    # Unclassified -> Other (99).
    assert aid("custom", "FrobnicateWidget") == 99


def test_status_id_honest_verdict_mapping() -> None:
    """Per [[ibounce-honest-positioning]] + the memo's verdict table."""
    def status(verdict: str, *, enforced: bool, pause: int | None = None) -> int:
        return audit_event_from_decision(
            decision_id=1, mode="x", profile=None, verdict=verdict,
            reason="r", service="s3", action="GetObject", arn=None,
            region=None, host="example.com",
            enforced=enforced, active_pause_id=pause,
        )["status_id"]

    # ALLOW -> Success.
    assert status("allow", enforced=False) == 1
    assert status("allow", enforced=True) == 1
    # DENY enforced -> Failure.
    assert status("deny", enforced=True) == 2
    # DENY advisory (cooperative) -> Success-with-detail (the call
    # actually succeeded upstream).
    assert status("deny", enforced=False) == 1
    # BYPASS (pause active) -> Success regardless of enforced.
    assert status("deny", enforced=True, pause=42) == 1
    assert status("allow", enforced=False, pause=42) == 1


def test_status_detail_carries_reason() -> None:
    """The human-readable `reason` is preserved in `status_detail` so
    a SIEM cell that surfaces status_detail still shows the why."""
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="deny", reason="explicit-deny: s3:DeleteBucket",
        service="s3", action="DeleteBucket", arn=None,
        region=None, host="example.com", enforced=True,
    )
    assert "explicit-deny: s3:DeleteBucket" in event["status_detail"]


def test_status_detail_includes_advisory_marker_for_cooperative_deny() -> None:
    """Cooperative-mode deny appends an advisory marker so downstream
    consumers don't confuse it with an enforced failure."""
    event = audit_event_from_decision(
        decision_id=1, mode="cooperative", profile=None,
        verdict="deny", reason="explicit-deny: s3:DeleteBucket",
        service="s3", action="DeleteBucket", arn=None,
        region=None, host="example.com", enforced=False,
    )
    assert event["status_id"] == 1
    assert "advisory-deny" in event["status_detail"]


def test_status_detail_includes_pause_marker_for_bypass() -> None:
    """An active pause maps to BYPASS semantics; status_detail records
    the bypass so the SIEM sees the gap."""
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="deny", reason="explicit-deny", service="s3",
        action="DeleteBucket", arn=None, region=None,
        host="example.com", enforced=True, active_pause_id=99,
    )
    assert event["status_id"] == 1
    assert "pause-bypass" in event["status_detail"]


def test_resources_built_from_arn() -> None:
    """OCSF resources entry extracted from a well-formed ARN."""
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="allow", reason="ok", service="s3", action="GetObject",
        arn="arn:aws:s3:::my-bucket/some/key.txt", region=None,
        host="s3.amazonaws.com",
    )
    assert event["resources"] == [{
        "name": "key.txt",
        "uid": "arn:aws:s3:::my-bucket/some/key.txt",
        "type": "s3 resource",
    }]


def test_resources_empty_when_no_arn() -> None:
    """Per memo: emit an empty resources array when there's no ARN."""
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="allow", reason="ok", service="s3",
        action="ListBuckets", arn=None, region=None,
        host="s3.amazonaws.com",
    )
    assert event["resources"] == []


def test_unmapped_iam_jit_preserves_native_semantics() -> None:
    """The `unmapped.iam_jit` block lets downstream tools that care
    about iam-jit-native fields read mode/profile/verdict/decision_id/
    enforced + the per-product `ext` extension."""
    event = audit_event_from_decision(
        decision_id=42,
        mode="transparent",
        profile="safe-default",
        verdict="deny",
        reason="r",
        service="s3",
        action="DeleteBucket",
        arn=None,
        region="us-east-1",
        host="example.com",
        enforced=True,
        sigv4_credential_kid="AKIAEXAMPLE",
        extra={"matched_rule_id": 7, "active_task_id": "task-1"},
    )
    jit = event["unmapped"]["iam_jit"]
    assert jit["mode"] == "transparent"
    assert jit["profile"] == "safe-default"
    assert jit["verdict"] == "deny"
    assert jit["decision_id"] == 42
    assert jit["enforced"] is True
    # ext carries AWS-specific + caller-supplied fields.
    assert jit["ext"]["aws_region"] == "us-east-1"
    assert jit["ext"]["sigv4_credential_kid"] == "AKIAEXAMPLE"
    assert jit["ext"]["matched_rule_id"] == 7
    assert jit["ext"]["active_task_id"] == "task-1"


def test_time_is_unix_milliseconds() -> None:
    """OCSF spec uses Unix-ms for `time` (not RFC3339)."""
    event = audit_event_from_decision(
        decision_id=0, mode="cooperative", profile=None, verdict="allow",
        reason="ok", service="s3", action="GetObject", arn=None,
        region=None, host="s3.amazonaws.com",
    )
    # A 13-digit ms timestamp is bigger than 10^12 (year 2001) and
    # smaller than 10^14 (year 5138). Anything outside that window is
    # almost certainly seconds (10-digit) or microseconds (16-digit).
    assert isinstance(event["time"], int)
    assert 10**12 < event["time"] < 10**14


def test_severity_defaults_to_informational() -> None:
    """Per [[security-team-positioning-safety-not-surveillance]]:
    normal decisions are Informational so SIEMs don't surface them
    as warnings."""
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="deny", reason="r", service="s3", action="DeleteBucket",
        arn=None, region=None, host="example.com", enforced=True,
    )
    assert event["severity_id"] == 1
    assert event["severity"] == "Informational"


def test_api_operation_is_service_action() -> None:
    """OCSF api.operation = `service:Action` so a SIEM can group by it."""
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="allow", reason="ok", service="s3", action="GetObject",
        arn=None, region=None, host="example.com",
    )
    assert event["api"]["operation"] == "s3:GetObject"
    assert event["api"]["service"]["name"] == "s3"
    assert event["api"]["request"]["uid"] == "1"


def test_dst_endpoint_carries_upstream_host() -> None:
    """The proxy's view of "where this request was destined" is the
    AWS service host; that goes in dst_endpoint per OCSF base spec."""
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="allow", reason="ok", service="s3", action="GetObject",
        arn=None, region=None, host="s3.us-east-1.amazonaws.com",
    )
    assert event["dst_endpoint"]["hostname"] == "s3.us-east-1.amazonaws.com"
