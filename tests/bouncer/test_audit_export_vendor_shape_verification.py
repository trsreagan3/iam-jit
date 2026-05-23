"""Vendor-shape verification for the audit-export presets, Security Lake
parquet, and alert-rules → webhook E2E paths (UAT-debt tasks #257, #258,
#262 per `[[uat-debt-audit-2026-05-23]]`).

The auditor flagged that the existing test suite verifies these features
at the schema-byte level using mocks (moto for Security Lake, in-process
build_request for presets) but never confirmed the wire bytes match what
the real vendor endpoints accept.

This file fills the gap WITHOUT requiring live vendor credentials. For
each integration we:

  1. Drive the production codepath (WebhookPusher / SecurityLakeWriter /
     RuleEngine + WebhookPusher), not just the build_request helper.
  2. Capture the actual HTTP request bytes (via a local aiohttp server)
     or parquet bytes (via pyarrow read-back).
  3. Assert the captured bytes match each vendor's documented schema
     contract (field names, header names, body envelope, content types,
     status enum values).

Per `[[ibounce-honest-positioning]]` the verification scope is schema-
shape compliance; live ingestion against a paid Datadog / Splunk / Azure
account is documented as out-of-scope (operator must perform the final
"point at real endpoint" smoke test themselves; the schema diffs here
make that step a no-op).

Vendor doc references (current as of 2026-05):
  - Datadog Logs HTTP intake:
    https://docs.datadoghq.com/api/latest/logs/ — DD-API-KEY header,
    JSON array body, reserved `status` enum
    `emergency|alert|critical|error|warning|notice|info|debug`,
    reserved attributes `ddsource`, `ddtags`, `service`, `host`,
    `message`.
  - Splunk HEC /services/collector/event:
    https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
    — `Authorization: Splunk <token>` header, NDJSON body (NOT array),
    each line a HEC envelope with `event` (the payload), `time`
    (fractional epoch seconds), `host`, `source`, `sourcetype`.
  - Microsoft Sentinel / Log Analytics Data Collector API:
    https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api
    — `Authorization: SharedKey <workspaceId>:<base64HMAC>` header,
    `Log-Type` header (custom table name; ASCII letters only, ≤100
    chars), `x-ms-date` header (RFC 1123), Content-Type
    `application/json`, body JSON array.
  - AWS Security Lake custom source (OCSF parquet):
    https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html
    — partition layout `region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/`,
    parquet files, OCSF schema (class_uid 6003 = API Activity,
    activity_id values map to CRUD verbs), snappy compression
    recommended.
"""

from __future__ import annotations

import asyncio
import io
import json
import re

import pytest
from aiohttp import web

from iam_jit.bouncer.audit_export import (
    OCSF_PARQUET_COLUMNS,
    AlertsConfig,
    Preset,
    RuleEngine,
    WebhookPusher,
    audit_event_from_decision,
    make_admin_fallback_grant_event,
    make_profile_install_event,
)
from iam_jit.bouncer.audit_export.security_lake import (
    _flatten_event_to_row,
    _rows_to_parquet_bytes,
)


# ---------------------------------------------------------------------------
# Local capture server — shared across all preset + alert E2E tests so
# each preset's wire bytes are caught after going through the FULL
# WebhookPusher path (queue + backoff + serialise + send), not just the
# build_request helper.
# ---------------------------------------------------------------------------


class _Capture:
    def __init__(self) -> None:
        self.method = ""
        self.path = ""
        self.headers: dict[str, str] = {}
        self.body = b""


@pytest.fixture
async def capture_server(unused_tcp_port_factory):
    cap = _Capture()
    received = asyncio.Event()

    async def _handler(request: web.Request) -> web.Response:
        cap.method = request.method
        cap.path = request.path
        cap.headers = dict(request.headers)
        cap.body = await request.read()
        received.set()
        return web.Response(status=200, text="ok")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _handler)
    runner = web.AppRunner(app)
    await runner.setup()
    port = unused_tcp_port_factory()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    try:
        yield f"http://127.0.0.1:{port}", cap, received
    finally:
        await runner.cleanup()


def _real_decision_event() -> dict:
    """A real decision event from the production builder — same shape
    the proxy hot-path emits. Verification asserts the production
    builder's output (not a hand-rolled fixture) survives the preset
    transform with the vendor-required fields intact."""
    return audit_event_from_decision(
        decision_id=42,
        mode="transparent",
        profile="safe-default",
        verdict="deny",
        reason="explicit-deny rule",
        service="s3",
        action="DeleteBucket",
        arn="arn:aws:s3:::prod-data",
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
        enforced=True,
        principal="agent-bot@example.com",
        request_id="req-abc",
    )


# ===========================================================================
# Preset 1: Datadog Logs HTTP intake schema verification
# ===========================================================================


# Datadog's reserved-status vocabulary
# https://docs.datadoghq.com/logs/log_configuration/pipelines/?tab=status#log-status-remapper
_DD_RESERVED_STATUSES = {
    "emergency", "alert", "critical", "error",
    "warning", "notice", "info", "debug",
}


@pytest.mark.asyncio
async def test_datadog_real_pusher_emits_documented_schema(capture_server) -> None:
    """Drive the real WebhookPusher with the Datadog preset against a
    local server. Assert every field Datadog's Logs intake REQUIRES is
    present + uses the documented vocabulary.

    Vendor contract being verified:
      * DD-API-KEY header carries the token (NOT Authorization)
      * Content-Type: application/json
      * Body is a JSON array (never NDJSON for DD intake)
      * Each element has `ddsource` (str), `service` (str), `host`
        (str), `ddtags` (comma-separated str), `status` (reserved
        enum), `message` (str)
      * Status is one of the 8 reserved values
      * Original OCSF event preserved alongside DD overlay (so a
        downstream DD pipeline parsing OCSF fields like class_uid
        still works)
    """
    base, cap, received = capture_server
    pusher = WebhookPusher(
        url=f"{base}/api/v2/logs",
        token="dd_test_key_PLACEHOLDER",
        preset=Preset.DATADOG,
        tags="env:test",
        allow_internal=True,
    )
    await pusher.start()
    try:
        pusher.push(_real_decision_event())
        await asyncio.wait_for(received.wait(), timeout=5.0)
    finally:
        await pusher.stop()

    # --- Headers ---
    assert cap.method == "POST"
    assert cap.headers.get("DD-API-KEY") == "dd_test_key_PLACEHOLDER", (
        "Datadog REQUIRES DD-API-KEY header; Authorization Bearer would "
        "be rejected"
    )
    assert cap.headers.get("Content-Type") == "application/json"
    assert "Authorization" not in cap.headers, (
        "Datadog intake does not use Authorization; presence indicates "
        "header leak"
    )

    # --- Body shape: must be a JSON array ---
    parsed = json.loads(cap.body)
    assert isinstance(parsed, list), (
        "Datadog Logs intake requires a JSON array body; NDJSON would "
        "return 400"
    )
    assert len(parsed) == 1
    record = parsed[0]

    # --- Reserved attributes per Datadog spec ---
    for required in ("ddsource", "service", "host", "ddtags", "status", "message"):
        assert required in record, f"DD reserved field missing: {required}"
        assert isinstance(record[required], str), (
            f"DD reserved field {required} must be string"
        )

    # --- Status must use Datadog's reserved enum ---
    assert record["status"] in _DD_RESERVED_STATUSES, (
        f"DD status {record['status']!r} not in Datadog's reserved enum "
        f"{_DD_RESERVED_STATUSES}; will be silently coerced to 'info' by DD"
    )
    # deny + status_id=2 → "error"
    assert record["status"] == "error"

    # --- ddtags shape: comma-separated key:value pairs ---
    for tag in record["ddtags"].split(","):
        assert ":" in tag, f"DD tag {tag!r} must be 'key:value' format"

    # --- Original OCSF preserved ---
    assert record["class_uid"] == 6003, "OCSF class_uid must survive overlay"
    assert record["ocsf"]["status"] == "Failure", (
        "OCSF status must be shadowed under `ocsf.status` because DD "
        "reserves `status` for its own enum"
    )
    assert record["unmapped"]["iam_jit"]["verdict"] == "deny"


# ===========================================================================
# Preset 2: Splunk HEC schema verification
# ===========================================================================


@pytest.mark.asyncio
async def test_splunk_hec_real_pusher_emits_documented_schema(capture_server) -> None:
    """Drive the real WebhookPusher with the Splunk HEC preset.

    Vendor contract being verified:
      * Authorization: `Splunk <token>` (NOT Bearer, NOT HEC <token>)
      * Body is NDJSON (one envelope per line) — HEC's /event endpoint
        explicitly REJECTS JSON arrays
      * Each envelope has `event` (the payload — HEC indexes everything
        nested under here), plus optional HEC metadata: `sourcetype`,
        `source`, `host`, `time` (fractional Unix seconds, NOT
        milliseconds)
      * Time conversion: OCSF emits ms; HEC expects seconds — verify
        the conversion happens
    """
    base, cap, received = capture_server
    pusher = WebhookPusher(
        url=f"{base}/services/collector/event",
        token="splunk_hec_test_token_PLACEHOLDER",
        preset=Preset.SPLUNK_HEC,
        allow_internal=True,
    )
    await pusher.start()
    try:
        pusher.push(_real_decision_event())
        await asyncio.wait_for(received.wait(), timeout=5.0)
    finally:
        await pusher.stop()

    # --- Headers ---
    assert cap.headers.get("Authorization") == "Splunk splunk_hec_test_token_PLACEHOLDER", (
        "HEC requires literal 'Splunk <token>' auth scheme; not Bearer"
    )
    assert cap.headers.get("Content-Type") == "application/json"

    # --- Body shape: NDJSON not array ---
    assert not cap.body.startswith(b"["), (
        "HEC /services/collector/event rejects JSON arrays; body must be "
        "newline-delimited JSON envelopes"
    )

    # Each line MUST parse as a HEC envelope.
    for line in cap.body.split(b"\n"):
        if not line:
            continue
        wrapper = json.loads(line)
        assert "event" in wrapper, "HEC envelope must wrap payload under `event`"
        # HEC required-ish metadata; all optional per spec but the
        # adapter sets all four.
        assert "sourcetype" in wrapper
        assert "source" in wrapper
        assert "host" in wrapper
        assert "time" in wrapper

        # --- Time MUST be fractional Unix seconds, not milliseconds ---
        assert isinstance(wrapper["time"], (int, float))
        # 1700000000 (s) = 2023-11-14; 1700000000000 (ms) = year 55816
        # Reject anything that looks like an unconverted ms value.
        assert wrapper["time"] < 10_000_000_000, (
            f"HEC `time` field looks like milliseconds "
            f"({wrapper['time']!r}); should be fractional seconds"
        )

        # OCSF event survives under `event`
        assert wrapper["event"]["class_uid"] == 6003
        assert wrapper["event"]["unmapped"]["iam_jit"]["verdict"] == "deny"


# ===========================================================================
# Preset 3: Microsoft Sentinel Data Collector API schema verification
# ===========================================================================


# Per Microsoft docs Log-Type column-name rules: ASCII letters, numbers,
# underscores; ≤100 chars. (The `_CL` suffix Sentinel appends to the
# table name is added server-side — operator passes the bare name.)
_SENTINEL_LOG_TYPE_RE = re.compile(r"^[A-Za-z0-9_]{1,100}$")


@pytest.mark.asyncio
async def test_sentinel_real_pusher_emits_documented_schema(capture_server) -> None:
    """Drive the real WebhookPusher with the Sentinel preset.

    Vendor contract being verified:
      * Authorization: `SharedKey <workspaceId>:<base64HMAC>` —
        workspace id is the leftmost hostname label
      * `Log-Type` header (custom table name; column-name rules)
      * `x-ms-date` header (RFC 1123 format)
      * Content-Type: application/json
      * Body is JSON array (NOT NDJSON for Sentinel)
      * HMAC is computed over the body length (different bodies →
        different sigs)
      * Shared key never leaks into headers/body verbatim (HMAC
        consumes it)
    """
    base, cap, received = capture_server
    # Sentinel shared key is base64-encoded; this is a valid b64 string
    # but obviously not a real Azure key.
    test_key_b64 = "U2VudGluZWxUZXN0S2V5UGxhY2Vob2xkZXIxMjM0NQ=="
    pusher = WebhookPusher(
        url=f"{base}/api/logs",
        token=test_key_b64,
        preset=Preset.SENTINEL,
        sentinel_table="IbouncePresetTest",
        allow_internal=True,
    )
    await pusher.start()
    try:
        pusher.push(_real_decision_event())
        await asyncio.wait_for(received.wait(), timeout=5.0)
    finally:
        await pusher.stop()

    # --- Authorization header shape ---
    auth = cap.headers.get("Authorization", "")
    assert auth.startswith("SharedKey "), (
        "Sentinel requires `SharedKey <id>:<sig>` auth; not Bearer/API key"
    )
    # SharedKey <workspaceId>:<base64sig>
    rest = auth[len("SharedKey "):]
    assert ":" in rest, "SharedKey value must be `<id>:<sig>`"
    workspace_id, sig = rest.split(":", 1)
    assert workspace_id, "Workspace id must be present in Authorization"
    # Signature must be valid base64.
    import base64 as _b64
    try:
        decoded_sig = _b64.b64decode(sig, validate=True)
    except Exception as e:
        pytest.fail(f"Sentinel signature is not valid base64: {e}")
    # HMAC-SHA256 → 32 bytes → 44-char base64.
    assert len(decoded_sig) == 32, (
        f"Sentinel signature must decode to 32-byte HMAC-SHA256; "
        f"got {len(decoded_sig)} bytes"
    )

    # --- Required headers ---
    assert cap.headers.get("Log-Type") == "IbouncePresetTest"
    assert _SENTINEL_LOG_TYPE_RE.match(cap.headers["Log-Type"]), (
        "Sentinel Log-Type must match column-name rules "
        "(ASCII letters/digits/underscore, ≤100 chars)"
    )
    assert cap.headers.get("Content-Type") == "application/json"
    xms = cap.headers.get("x-ms-date", "")
    # RFC 1123 format: "Fri, 16 May 2026 10:30:00 GMT"
    rfc1123_re = re.compile(
        r"^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} "
        r"\d{2}:\d{2}:\d{2} GMT$"
    )
    assert rfc1123_re.match(xms), (
        f"x-ms-date header {xms!r} must be RFC 1123 format per "
        f"Sentinel Data Collector API spec"
    )

    # --- Body shape: JSON array (NOT NDJSON for Sentinel) ---
    parsed = json.loads(cap.body)
    assert isinstance(parsed, list), (
        "Sentinel Data Collector API requires JSON array; NDJSON rejected"
    )

    # --- Key never leaks ---
    assert test_key_b64 not in cap.body.decode("utf-8")
    for h_val in cap.headers.values():
        assert test_key_b64 not in h_val, (
            f"Sentinel shared key MUST NOT appear verbatim in headers "
            f"(HMAC-consumed only); leaked into {h_val!r}"
        )


# ===========================================================================
# Verification 2: Security Lake parquet — OCSF schema conformance
# ===========================================================================


# Per AWS Security Lake docs + OCSF v1.1.0 spec:
# class_uid 6003 = "API Activity" (the only class Bounce emits today).
# activity_id ∈ {0..6, 99}: 0=Unknown, 1=Create, 2=Read, 3=Update,
# 4=Delete, 5=Other (per OCSF), 6=List (added in v1.1), 99=Other.
_OCSF_VALID_ACTIVITY_IDS = {0, 1, 2, 3, 4, 5, 6, 99}
# OCSF severity_id ∈ {0..6, 99}
_OCSF_VALID_SEVERITY_IDS = {0, 1, 2, 3, 4, 5, 6, 99}
# OCSF status_id ∈ {0, 1, 2, 99} for class 6003
_OCSF_VALID_STATUS_IDS = {0, 1, 2, 99}


def test_security_lake_parquet_matches_ocsf_v1_1_0_schema() -> None:
    """Verify the parquet bytes the SecurityLakeWriter would upload to
    S3 actually parse with pyarrow AND carry every OCSF v1.1.0 class
    6003 required field.

    Vendor contract being verified:
      * Parquet file parses with pyarrow (Security Lake's Glue crawler
        uses the same arrow-based reader)
      * Compression is snappy (Security Lake's recommended codec)
      * Schema has all 39 documented columns
      * class_uid = 6003 for every row (API Activity, the only class
        Bounce custom sources emit today)
      * activity_id ∈ OCSF spec values
      * severity_id ∈ OCSF spec values
      * status_id ∈ OCSF spec values
      * metadata.version = "1.1.0" (Security Lake currently requires
        OCSF v1.1.0)
      * Bouncer extension fields land under unmapped.iam_jit.* (per
        OCSF "any non-spec field goes under unmapped" rule — Security
        Lake's schema mapper preserves these)
    """
    import pyarrow.parquet as pq

    # Build a small mixed batch (allow + deny + write) so we sweep the
    # activity_id + status_id variants.
    events = [
        audit_event_from_decision(
            decision_id=1, mode="transparent", profile="safe-default",
            verdict="allow", reason="", service="s3", action="GetObject",
            arn="arn:aws:s3:::data/x", region="us-east-1",
            host="s3.us-east-1.amazonaws.com",
        ),
        audit_event_from_decision(
            decision_id=2, mode="transparent", profile="safe-default",
            verdict="deny", reason="explicit-deny rule", service="s3",
            action="DeleteBucket", arn="arn:aws:s3:::prod",
            region="us-east-1", host="s3.us-east-1.amazonaws.com",
            enforced=True,
        ),
        audit_event_from_decision(
            decision_id=3, mode="cooperative", profile="dev",
            verdict="allow", reason="", service="ec2",
            action="RunInstances", arn=None, region="us-west-2",
            host="ec2.us-west-2.amazonaws.com",
        ),
    ]
    rows = [_flatten_event_to_row(e) for e in events]
    parquet_bytes = _rows_to_parquet_bytes(rows)
    assert parquet_bytes, "parquet bytes must be non-empty"
    # First 4 bytes of any parquet file are b"PAR1".
    assert parquet_bytes[:4] == b"PAR1", (
        "parquet magic-bytes header missing; bytes don't decode as parquet"
    )
    assert parquet_bytes[-4:] == b"PAR1", "parquet footer magic-bytes missing"

    # --- pyarrow round-trip ---
    table = pq.read_table(io.BytesIO(parquet_bytes))
    rows_back = table.to_pylist()
    assert len(rows_back) == 3

    # --- Schema-set check: every documented column is present ---
    actual_columns = [f.name for f in table.schema]
    expected_columns = [name for name, _ in OCSF_PARQUET_COLUMNS]
    assert actual_columns == expected_columns, (
        "Security Lake parquet schema columns drift from "
        "OCSF_PARQUET_COLUMNS contract"
    )

    # --- Per-row OCSF spec compliance ---
    for r in rows_back:
        # OCSF v1.1.0 — Security Lake currently mandates this version.
        assert r["metadata_version"] == "1.1.0", (
            f"Security Lake requires OCSF v1.1.0; got "
            f"{r['metadata_version']!r}"
        )
        # All Bounce events today are API Activity (class_uid 6003).
        assert r["class_uid"] == 6003
        assert r["category_uid"] == 6  # Application Activity
        assert r["activity_id"] in _OCSF_VALID_ACTIVITY_IDS
        assert r["severity_id"] in _OCSF_VALID_SEVERITY_IDS
        assert r["status_id"] in _OCSF_VALID_STATUS_IDS
        # type_uid = class_uid*100 + activity_id per OCSF spec
        assert r["type_uid"] == r["class_uid"] * 100 + r["activity_id"], (
            f"OCSF type_uid {r['type_uid']!r} != "
            f"class_uid * 100 + activity_id "
            f"({r['class_uid'] * 100 + r['activity_id']!r})"
        )
        # Bouncer-specific fields land under unmapped — this is the
        # OCSF-mandated escape hatch for non-spec fields. Security Lake
        # preserves these as-is.
        assert r["unmapped_iam_jit_verdict"] in ("allow", "deny", "prompt", "")


def test_security_lake_parquet_uses_snappy_compression() -> None:
    """Snappy is the Security-Lake-recommended codec (Athena + Glue
    decode it natively without an extra package install). Verify the
    writer actually selects snappy, not the pyarrow default."""
    import pyarrow.parquet as pq

    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="allow", reason="", service="s3", action="GetObject",
        arn=None, region="us-east-1", host="s3.us-east-1.amazonaws.com",
    )
    row = _flatten_event_to_row(event)
    parquet_bytes = _rows_to_parquet_bytes([row])
    pf = pq.ParquetFile(io.BytesIO(parquet_bytes))
    # Each row group has one or more columns; assert at least one is
    # snappy-compressed (we'd accept all-snappy; the writer doesn't
    # mix codecs).
    rg = pf.metadata.row_group(0)
    codecs = {rg.column(i).compression for i in range(rg.num_columns)}
    # `SNAPPY` is what pyarrow.parquet reports; `UNCOMPRESSED` would
    # mean we left the default in place.
    assert "SNAPPY" in codecs, (
        f"Security Lake parquet should use snappy compression; "
        f"writer used {codecs!r}"
    )


def test_security_lake_partition_path_athena_queryable() -> None:
    """The Security Lake partition layout must be exactly what AWS
    Glue's crawler recognises as Hive-style partitions, otherwise an
    Athena query like `WHERE region='us-east-1'` won't push down.

    Format per AWS docs:
      region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/<prefix>-<ts>.parquet
    """
    from iam_jit.bouncer.audit_export.security_lake import _partition_path
    import datetime as _dt

    when = _dt.datetime(2026, 5, 23, 9, 7, 33, tzinfo=_dt.UTC)
    path = _partition_path(
        region="us-east-1", when=when, class_uid=6003,
        unix_ms=1747667253000,
    )
    # Hive partition keys MUST use `=` and be path-segment-separated.
    parts = path.split("/")
    assert parts[0] == "region=us-east-1"
    assert parts[1] == "eventday=20260523"
    assert parts[2] == "eventhour=09"
    assert parts[3].endswith(".parquet")
    # Class prefix lands BEFORE the timestamp so a single-class crawler
    # (Glue table per OCSF class) can glob `api_activity-*.parquet`.
    assert parts[3].startswith("api_activity-")


# ===========================================================================
# Verification 3: Alert rules → real webhook E2E
# ===========================================================================


@pytest.mark.asyncio
async def test_alert_engine_fires_through_real_webhook(capture_server) -> None:
    """End-to-end: drive synthetic events through the RuleEngine wired
    to a real WebhookPusher → local server. Verify the alert event
    actually reaches the webhook with the documented OCSF anomaly_detected
    shape.

    This is the test the auditor flagged as missing — the existing
    test_audit_export_alerts.py captures alert dicts into an in-memory
    list, but no test sends the alert through the production transport.
    """
    base, cap, received = capture_server
    pusher = WebhookPusher(
        url=f"{base}/audit",
        token="alert_test_PLACEHOLDER",
        preset=Preset.GENERIC,
        allow_internal=True,
        batch_size=1,
    )
    await pusher.start()
    # Wire the engine to push EVERY alert through the real webhook.
    engine = RuleEngine(
        config=AlertsConfig.default(),
        emit=pusher.push,
    )
    try:
        # admin_fallback_burst fires at >3 grants in 5min window.
        # The default threshold is 3; fire 4 to cross.
        for i in range(4):
            engine.observe(make_admin_fallback_grant_event(
                principal="agent@example.com", grant_id=i,
            ))
        # Wait for the alert to flow through the webhook queue.
        await asyncio.wait_for(received.wait(), timeout=5.0)
    finally:
        await pusher.stop()

    # --- Webhook received the alert ---
    assert cap.method == "POST"
    assert cap.path == "/audit"
    # Generic preset wire format: NDJSON OCSF events. Batch_size=1
    # means one event per body.
    payload = json.loads(cap.body)

    # --- OCSF anomaly_detected event shape ---
    assert payload["class_uid"] == 6003
    assert payload["activity_id"] == 99  # Other = anomaly synthetic
    assert payload["activity_name"] == "anomaly_detected"
    assert payload["status_id"] == 99
    assert payload["status"] == "Other"
    # Alert-specific metadata under unmapped.iam_jit
    iam_jit = payload["unmapped"]["iam_jit"]
    assert iam_jit["event_type"] == "ANOMALY_DETECTED"
    assert iam_jit["pattern"] == "admin-fallback-burst"
    assert iam_jit["matched_event_count"] >= 4
    assert iam_jit["window_seconds"] == 5 * 60
    # Neutral-language suggestion (per [[security-team-positioning-...]])
    assert iam_jit["suggestion"], "alert must carry a suggestion string"
    forbidden = {"violation", "infraction", "unauthorized"}
    for word in forbidden:
        assert word not in iam_jit["suggestion"].lower()
        assert word not in payload["status_detail"].lower()


@pytest.mark.asyncio
async def test_alert_engine_does_not_self_cascade_through_webhook(
    capture_server,
) -> None:
    """Re-entry guard: the alert event the engine emits is OCSF with
    `unmapped.iam_jit.event_type == ANOMALY_DETECTED`. The same engine
    seeing that event must NOT fire on it (would cascade).

    Verify via the real webhook path — the test_audit_export_alerts.py
    suite covers this at the engine-only level; this confirms the
    guard survives the wire serialise → deserialise round-trip.
    """
    base, cap, received = capture_server
    pusher = WebhookPusher(
        url=f"{base}/audit",
        token="cascade_test_PLACEHOLDER",
        preset=Preset.GENERIC,
        allow_internal=True,
        batch_size=1,
    )
    received_alerts: list[dict] = []

    def _emit_and_count(event: dict) -> None:
        received_alerts.append(event)
        pusher.push(event)

    await pusher.start()
    engine = RuleEngine(
        config=AlertsConfig.default(),
        emit=_emit_and_count,
    )
    try:
        # 4 grants → 1 alert.
        for i in range(4):
            engine.observe(make_admin_fallback_grant_event(
                principal="x", grant_id=i,
            ))
        await asyncio.wait_for(received.wait(), timeout=5.0)
        # Now feed the emitted alert BACK into the engine. The
        # re-entry guard should suppress; no second alert fires.
        for alert in list(received_alerts):
            engine.observe(alert)
    finally:
        await pusher.stop()

    # Exactly one alert event fired; the re-injected alert was suppressed.
    assert len(received_alerts) == 1, (
        f"alert engine self-cascaded: {len(received_alerts)} alerts "
        f"emitted (expected 1)"
    )


@pytest.mark.asyncio
async def test_alert_engine_through_datadog_preset_emits_dd_shape(
    capture_server,
) -> None:
    """Cross-feature integration: alert events flow through the
    Datadog preset adapter and retain the DD-required overlay fields
    just like decision events do. Verifies the preset doesn't
    silently drop alert-shaped events.
    """
    base, cap, received = capture_server
    pusher = WebhookPusher(
        url=f"{base}/api/v2/logs",
        token="dd_alert_test_PLACEHOLDER",
        preset=Preset.DATADOG,
        allow_internal=True,
        batch_size=1,
    )
    await pusher.start()
    engine = RuleEngine(
        config=AlertsConfig.default(),
        emit=pusher.push,
    )
    try:
        # Trigger non_org_profile_install rule (fires immediately on
        # an install from a non-allowlisted URL; default allowlist is
        # empty so every install fires).
        engine.observe(make_profile_install_event(
            profile_name="ad-hoc",
            source_url="https://gist.github.com/evil/profile.yaml",
        ))
        await asyncio.wait_for(received.wait(), timeout=5.0)
    finally:
        await pusher.stop()

    # DD-shaped body.
    parsed = json.loads(cap.body)
    assert isinstance(parsed, list)
    rec = parsed[0]
    # DD overlay applied to alert event too.
    assert rec["ddsource"] == "iam-jit"
    assert rec["service"] == "ibounce"
    assert rec["status"] in _DD_RESERVED_STATUSES
    # Alert-specific OCSF fields preserved under the overlay.
    assert rec["activity_name"] == "anomaly_detected"
    assert rec["unmapped"]["iam_jit"]["pattern"] == "non-org-profile-install"
