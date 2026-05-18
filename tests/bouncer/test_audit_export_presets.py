"""Vendor-shape webhook preset tests (#257).

Per [[audit-webhook-presets]] this slice adds Datadog / Splunk HEC /
Microsoft Sentinel adapters in addition to the existing `generic`
preset. The canonical OCSF event (per [[ocsf-audit-schema]]) is
preserved verbatim; only the webhook body + headers get
vendor-shaped at send-time.

Coverage per preset:
- Adapter shape — returns (url, headers, body_bytes) with right types
- Token routed to the correct vendor header
- Body shape — array vs NDJSON
- Overlay fields present
- Token-leak — extends the load-bearing assertion to all 4 presets

Plus:
- Generic-preset byte-identical regression vs the pre-#257 wire format
- Sentinel HMAC signature matches a deterministic test vector computed
  via Microsoft's published algorithm
- End-to-end aiohttp server captures the actual request the
  WebhookPusher emits for each preset
"""

from __future__ import annotations

import asyncio
import json

import pytest
from aiohttp import web

from iam_jit.bouncer.audit_export import (
    Preset,
    WebhookPusher,
    build_request,
)
from iam_jit.bouncer.audit_export.presets import (
    sentinel_signature,
)


# Token we grep for to confirm it never leaks into the wrong header /
# body / log. Distinctive prefix + suffix so the grep is unambiguous.
TOKEN = "preset_test_secret_donotleak_zzz"

# OCSF v1.1.0 class-6003 sample event mirroring what
# `audit_event_from_decision` produces for an ALLOW (status_id=1) +
# DENY (status_id=2) + AUDIT_DROPPED (status_id=99). We hand-build
# them here so the test stays decoupled from the event builder.


def _sample_allow_event() -> dict:
    return {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "ibounce",
                "vendor_name": "iam-jit",
                "version": "1.0.0",
            },
        },
        "time": 1700000000000,
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 2,
        "activity_name": "GetObject",
        "type_uid": 600302,
        "type_name": "API Activity: Read",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "status_detail": "",
        "actor": {"user": {"name": "alice", "uid": "alice"}},
        "api": {
            "operation": "s3:GetObject",
            "service": {"name": "s3"},
            "request": {"uid": "42"},
        },
        "resources": [{
            "name": "config.json",
            "uid": "arn:aws:s3:::corp-data/config.json",
            "type": "s3 resource",
        }],
        "src_endpoint": {"ip": "10.42.0.7", "hostname": "agent-host-01"},
        "dst_endpoint": {"hostname": "s3.us-east-1.amazonaws.com"},
        "unmapped": {
            "iam_jit": {
                "mode": "cooperative",
                "profile": "safe-default",
                "verdict": "ALLOW",
                "decision_id": 42,
                "enforced": False,
                "ext": {"aws_region": "us-east-1"},
            },
        },
    }


def _sample_deny_event() -> dict:
    e = _sample_allow_event()
    e["activity_id"] = 4
    e["activity_name"] = "DeleteBucket"
    e["type_uid"] = 600304
    e["type_name"] = "API Activity: Delete"
    e["status_id"] = 2
    e["status"] = "Failure"
    e["status_detail"] = "profile-deny: writes not allowed"
    e["api"]["operation"] = "s3:DeleteBucket"
    e["resources"] = [{
        "name": "prod-data",
        "uid": "arn:aws:s3:::prod-data",
        "type": "s3 resource",
    }]
    e["unmapped"]["iam_jit"]["verdict"] = "DENY"
    e["unmapped"]["iam_jit"]["enforced"] = True
    e["unmapped"]["iam_jit"]["mode"] = "transparent"
    return e


def _sample_audit_dropped_event() -> dict:
    return {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "ibounce",
                "vendor_name": "iam-jit",
                "version": "1.0.0",
            },
        },
        "time": 1700000000000,
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 99,
        "activity_name": "audit_dropped",
        "type_uid": 600399,
        "type_name": "API Activity: Other",
        "severity_id": 3,
        "severity": "Medium",
        "status_id": 99,
        "status": "Other",
        "status_detail": "audit-export webhook dropped 7 event(s)",
        "actor": {"user": {"name": "", "uid": ""}},
        "api": {
            "operation": "audit_dropped",
            "service": {"name": "ibounce.audit_export"},
            "request": {"uid": ""},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": "AUDIT_DROPPED",
                "dropped_count": 7,
                "ext": {"reason": "webhook-queue-overflow"},
            },
        },
    }


# ---------------------------------------------------------------------------
# Generic preset — byte-identical regression
# ---------------------------------------------------------------------------


def _legacy_generic_wire_bytes(events: list[dict], token: str) -> tuple[dict, bytes]:
    """The wire format `WebhookPusher._send_once` produced
    BEFORE #257 introduced the preset adapter. Snapshotted here so
    the regression test can compare byte-for-byte against the new
    `build_request(Preset.GENERIC, ...)` output.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "ibounce-audit-export/1.0",
    }
    body = "\n".join(json.dumps(e, ensure_ascii=False) for e in events).encode("utf-8")
    return headers, body


def test_generic_preset_byte_identical_to_pre_slice_behavior() -> None:
    """The `generic` preset MUST be byte-identical to the pre-#257
    wire format. Existing operator webhook consumers configured with
    Bearer auth + NDJSON parsing must keep working without code
    changes. This is the load-bearing backward-compat assertion."""
    events_single = [_sample_allow_event()]
    events_batch = [_sample_allow_event(), _sample_deny_event()]
    for events in (events_single, events_batch):
        expected_headers, expected_body = _legacy_generic_wire_bytes(events, TOKEN)
        url, headers, body = build_request(
            Preset.GENERIC,
            "https://collector.example.com/audit",
            TOKEN,
            events,
        )
        assert url == "https://collector.example.com/audit"
        assert headers == expected_headers
        assert body == expected_body


def test_generic_adapter_shape() -> None:
    url, headers, body = build_request(
        Preset.GENERIC,
        "https://collector.example.com/audit",
        TOKEN,
        [_sample_allow_event()],
    )
    assert isinstance(url, str)
    assert isinstance(headers, dict)
    assert isinstance(body, bytes)


def test_generic_token_in_correct_header() -> None:
    _, headers, body = build_request(
        Preset.GENERIC,
        "https://collector.example.com/audit",
        TOKEN,
        [_sample_allow_event()],
    )
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    # No vendor headers leak in for generic.
    assert "DD-API-KEY" not in headers
    assert "Log-Type" not in headers
    assert "x-ms-date" not in headers


def test_generic_body_shape_is_ndjson() -> None:
    """Pre-slice generic body was NDJSON (one object per line); the
    regression contract preserves that. For batch_size=1 NDJSON is a
    single object with no trailing newline."""
    _, _, body_single = build_request(
        Preset.GENERIC, "https://x/", TOKEN, [_sample_allow_event()],
    )
    assert not body_single.startswith(b"["), "generic preset must NOT emit a JSON array"
    decoded_single = json.loads(body_single)
    assert decoded_single["activity_name"] == "GetObject"

    _, _, body_batch = build_request(
        Preset.GENERIC,
        "https://x/", TOKEN,
        [_sample_allow_event(), _sample_deny_event()],
    )
    lines = body_batch.split(b"\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["activity_name"] == "GetObject"
    assert json.loads(lines[1])["activity_name"] == "DeleteBucket"


def test_generic_token_never_appears_in_output() -> None:
    """The token appears in EXACTLY one place — the Authorization
    header. Body + URL never contain it."""
    url, headers, body = build_request(
        Preset.GENERIC, "https://collector.example.com/audit", TOKEN,
        [_sample_allow_event()],
    )
    assert TOKEN in headers["Authorization"]
    assert TOKEN not in body.decode("utf-8")
    assert TOKEN not in url


# ---------------------------------------------------------------------------
# Datadog preset
# ---------------------------------------------------------------------------


def test_datadog_adapter_shape() -> None:
    url, headers, body = build_request(
        Preset.DATADOG,
        "https://http-intake.logs.datadoghq.com/api/v2/logs",
        TOKEN,
        [_sample_allow_event()],
    )
    assert isinstance(url, str)
    assert isinstance(headers, dict)
    assert isinstance(body, bytes)


def test_datadog_token_in_correct_header() -> None:
    _, headers, _ = build_request(
        Preset.DATADOG, "https://x/", TOKEN, [_sample_allow_event()],
    )
    assert headers["DD-API-KEY"] == TOKEN
    # No legacy Bearer auth for DD.
    assert headers.get("Authorization", "") == ""
    assert "Authorization" not in headers


def test_datadog_body_shape_is_json_array() -> None:
    """DD expects an array even for a single event."""
    _, _, body = build_request(
        Preset.DATADOG, "https://x/", TOKEN, [_sample_allow_event()],
    )
    parsed = json.loads(body)
    assert isinstance(parsed, list)
    assert len(parsed) == 1


def test_datadog_overlay_fields_present_allow_event() -> None:
    """Every required DD overlay field is set with the right value
    derived from the OCSF event."""
    _, _, body = build_request(
        Preset.DATADOG, "https://x/", TOKEN,
        [_sample_allow_event()],
        tags="env:prod,team:platform",
    )
    obj = json.loads(body)[0]
    assert obj["service"] == "ibounce"
    assert obj["ddsource"] == "iam-jit"
    # Host falls back to hostname (src_endpoint.hostname set in fixture).
    assert obj["host"] == "agent-host-01"
    assert obj["ddtags"] == "product:iam-jit,bouncer:ibounce,env:prod,team:platform"
    # status_id=1 -> "info"
    assert obj["status"] == "info"
    # Original OCSF status preserved under `ocsf.status`.
    assert obj["ocsf"]["status"] == "Success"
    # message is human-readable + includes the verdict + operation.
    assert "ALLOW" in obj["message"]
    assert "s3:GetObject" in obj["message"]
    # OCSF fields preserved alongside.
    assert obj["class_uid"] == 6003
    assert obj["unmapped"]["iam_jit"]["verdict"] == "ALLOW"


def test_datadog_overlay_fields_deny_event() -> None:
    _, _, body = build_request(
        Preset.DATADOG, "https://x/", TOKEN,
        [_sample_deny_event()],
    )
    obj = json.loads(body)[0]
    assert obj["status"] == "error"  # status_id=2 -> error
    assert obj["ocsf"]["status"] == "Failure"
    assert "DENY" in obj["message"]
    assert "s3:DeleteBucket" in obj["message"]
    assert "prod-data" in obj["message"]
    assert "transparent" in obj["message"]


def test_datadog_overlay_fields_audit_dropped() -> None:
    _, _, body = build_request(
        Preset.DATADOG, "https://x/", TOKEN,
        [_sample_audit_dropped_event()],
    )
    obj = json.loads(body)[0]
    assert obj["status"] == "notice"  # status_id=99 -> notice
    assert obj["ocsf"]["status"] == "Other"
    # AUDIT_DROPPED gets a dedicated message shape.
    assert "AUDIT_DROPPED" in obj["message"]
    assert "7" in obj["message"]


def test_datadog_host_falls_back_to_ip_when_no_hostname() -> None:
    event = _sample_allow_event()
    event["src_endpoint"] = {"ip": "10.1.2.3"}  # no hostname
    _, _, body = build_request(
        Preset.DATADOG, "https://x/", TOKEN, [event],
    )
    obj = json.loads(body)[0]
    assert obj["host"] == "10.1.2.3"


def test_datadog_ddtags_without_extra_tags() -> None:
    _, _, body = build_request(
        Preset.DATADOG, "https://x/", TOKEN, [_sample_allow_event()],
    )
    obj = json.loads(body)[0]
    assert obj["ddtags"] == "product:iam-jit,bouncer:ibounce"


def test_datadog_token_never_appears_in_output() -> None:
    url, headers, body = build_request(
        Preset.DATADOG,
        "https://http-intake.logs.datadoghq.com/api/v2/logs",
        TOKEN,
        [_sample_allow_event(), _sample_deny_event(), _sample_audit_dropped_event()],
        tags="env:prod",
    )
    assert headers["DD-API-KEY"] == TOKEN
    assert TOKEN not in body.decode("utf-8")
    assert TOKEN not in url


def test_datadog_overlay_does_not_mutate_caller_event() -> None:
    """The OCSF event dict is also the one written to the JSONL log
    file; mutating it would corrupt the log. The adapter must
    shallow-copy before adding DD-specific fields."""
    e = _sample_allow_event()
    snapshot = json.dumps(e, sort_keys=True)
    build_request(Preset.DATADOG, "https://x/", TOKEN, [e])
    assert json.dumps(e, sort_keys=True) == snapshot, (
        "datadog overlay mutated the caller's OCSF event"
    )


# ---------------------------------------------------------------------------
# Splunk HEC preset
# ---------------------------------------------------------------------------


def test_splunk_hec_adapter_shape() -> None:
    url, headers, body = build_request(
        Preset.SPLUNK_HEC,
        "https://splunk.example.com:8088/services/collector/event",
        TOKEN,
        [_sample_allow_event()],
    )
    assert isinstance(url, str)
    assert isinstance(headers, dict)
    assert isinstance(body, bytes)


def test_splunk_hec_token_in_correct_header() -> None:
    _, headers, _ = build_request(
        Preset.SPLUNK_HEC, "https://x/", TOKEN, [_sample_allow_event()],
    )
    # HEC uses `Authorization: Splunk <token>` — NOT Bearer.
    assert headers["Authorization"] == f"Splunk {TOKEN}"
    # No DD header leak.
    assert "DD-API-KEY" not in headers


def test_splunk_hec_body_shape_is_ndjson_not_array() -> None:
    """HEC explicitly rejects JSON arrays at /services/collector/event;
    each event is its own JSON object on its own line."""
    _, _, body = build_request(
        Preset.SPLUNK_HEC, "https://x/", TOKEN,
        [_sample_allow_event(), _sample_deny_event()],
    )
    assert not body.startswith(b"[")
    lines = body.split(b"\n")
    assert len(lines) == 2
    for line in lines:
        wrapper = json.loads(line)
        assert "event" in wrapper
        assert "sourcetype" in wrapper


def test_splunk_hec_overlay_fields_present() -> None:
    _, _, body = build_request(
        Preset.SPLUNK_HEC, "https://x/", TOKEN, [_sample_allow_event()],
    )
    wrapper = json.loads(body)
    assert wrapper["sourcetype"] == "iam_jit:bouncer:ibounce"
    assert wrapper["source"] == "iam-jit"
    assert wrapper["host"] == "agent-host-01"
    # OCSF time (ms) -> HEC time (fractional seconds).
    assert wrapper["time"] == 1700000000.0
    # Full OCSF event preserved under `event`.
    assert wrapper["event"]["class_uid"] == 6003
    assert wrapper["event"]["unmapped"]["iam_jit"]["verdict"] == "ALLOW"


def test_splunk_hec_token_never_appears_in_output() -> None:
    url, headers, body = build_request(
        Preset.SPLUNK_HEC,
        "https://splunk.example.com:8088/services/collector/event",
        TOKEN,
        [_sample_allow_event(), _sample_deny_event()],
    )
    assert TOKEN in headers["Authorization"]
    assert TOKEN not in body.decode("utf-8")
    assert TOKEN not in url


# ---------------------------------------------------------------------------
# Microsoft Sentinel preset
# ---------------------------------------------------------------------------


# Deterministic test vector computed via Microsoft's documented
# algorithm (learn.microsoft.com/azure/azure-monitor/logs/data-collector-api).
# The shared key is a base64-encoded 32-byte test value (not a real key
# — chosen so the resulting signature is reproducible in any CI env
# without secret-management gymnastics). Algorithm:
#
#   string_to_sign = METHOD\n + content_length + \napplication/json
#                    \nx-ms-date:<date>\n/api/logs
#   signature = base64(HMAC-SHA256(b64decode(shared_key), string_to_sign))
#
# Anyone reproducing this with the same inputs gets the same output;
# that IS the contract. We computed the expected hash once via the
# same algorithm + freeze it here as the test vector.
SENTINEL_TEST_SHARED_KEY = (
    "SGVsbG9Xb3JsZFRoaXNJc0FUZXN0S2V5Rm9ySUFNSklUMTIzNDU2Nzg5MA=="
)
SENTINEL_TEST_DATE = "Fri, 16 May 2026 10:30:00 GMT"
SENTINEL_TEST_BODY_LEN = 100
SENTINEL_TEST_METHOD = "POST"
SENTINEL_TEST_CONTENT_TYPE = "application/json"
SENTINEL_TEST_RESOURCE = "/api/logs"
SENTINEL_TEST_EXPECTED_SIG = "sNrZsC5stS44EX10aN8Bwa9mziXcKegxkblKY86pSQY="


def test_sentinel_hmac_matches_documented_algorithm() -> None:
    """The Sentinel signature MUST match Microsoft's documented
    HMAC-SHA256 algorithm for Log Analytics Workspace Data Collector
    API. Source: learn.microsoft.com/azure/azure-monitor/logs/
    data-collector-api. The expected value is what Microsoft's
    own Python sample produces for these inputs."""
    sig = sentinel_signature(
        shared_key_b64=SENTINEL_TEST_SHARED_KEY,
        method=SENTINEL_TEST_METHOD,
        content_length=SENTINEL_TEST_BODY_LEN,
        content_type=SENTINEL_TEST_CONTENT_TYPE,
        date=SENTINEL_TEST_DATE,
        resource=SENTINEL_TEST_RESOURCE,
    )
    assert sig == SENTINEL_TEST_EXPECTED_SIG


def test_sentinel_adapter_shape() -> None:
    url, headers, body = build_request(
        Preset.SENTINEL,
        "https://b4b75d0b-c84c-4fb4-9adc-8f2c0a5d3cda.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
        SENTINEL_TEST_SHARED_KEY,
        [_sample_allow_event()],
    )
    assert isinstance(url, str)
    assert isinstance(headers, dict)
    assert isinstance(body, bytes)


def test_sentinel_token_in_correct_header() -> None:
    _, headers, _ = build_request(
        Preset.SENTINEL,
        "https://b4b75d0b-c84c-4fb4-9adc-8f2c0a5d3cda.ods.opinsights.azure.com/api/logs",
        SENTINEL_TEST_SHARED_KEY,
        [_sample_allow_event()],
    )
    assert headers["Authorization"].startswith(
        "SharedKey b4b75d0b-c84c-4fb4-9adc-8f2c0a5d3cda:",
    )
    # No Bearer / DD-API-KEY leak.
    assert "DD-API-KEY" not in headers
    assert "Bearer" not in headers["Authorization"]


def test_sentinel_body_shape_is_json_array() -> None:
    _, _, body = build_request(
        Preset.SENTINEL,
        "https://workspace.ods.opinsights.azure.com/api/logs",
        SENTINEL_TEST_SHARED_KEY,
        [_sample_allow_event(), _sample_deny_event()],
    )
    parsed = json.loads(body)
    assert isinstance(parsed, list)
    assert len(parsed) == 2


def test_sentinel_log_type_header_set() -> None:
    _, headers, _ = build_request(
        Preset.SENTINEL,
        "https://workspace.ods.opinsights.azure.com/api/logs",
        SENTINEL_TEST_SHARED_KEY,
        [_sample_allow_event()],
        sentinel_table="MyCustomTable",
    )
    assert headers["Log-Type"] == "MyCustomTable"
    assert "x-ms-date" in headers
    assert headers["Content-Type"] == "application/json"


def test_sentinel_signature_is_computed_over_body_length() -> None:
    """The signature depends on the body length; two payloads of
    different sizes must produce different signatures."""
    _, headers_small, _ = build_request(
        Preset.SENTINEL,
        "https://workspace.ods.opinsights.azure.com/api/logs",
        SENTINEL_TEST_SHARED_KEY,
        [_sample_allow_event()],
    )
    _, headers_big, _ = build_request(
        Preset.SENTINEL,
        "https://workspace.ods.opinsights.azure.com/api/logs",
        SENTINEL_TEST_SHARED_KEY,
        [_sample_allow_event(), _sample_deny_event(), _sample_audit_dropped_event()],
    )
    assert headers_small["Authorization"] != headers_big["Authorization"]


def test_sentinel_token_never_appears_in_output() -> None:
    """The shared key is HMAC-consumed; it's NEVER serialised into
    headers or body in any decodable form."""
    url, headers, body = build_request(
        Preset.SENTINEL,
        "https://workspace.ods.opinsights.azure.com/api/logs",
        SENTINEL_TEST_SHARED_KEY,
        [_sample_allow_event(), _sample_deny_event()],
        sentinel_table="IamJitBouncer",
    )
    assert SENTINEL_TEST_SHARED_KEY not in headers["Authorization"]
    for h_val in headers.values():
        assert SENTINEL_TEST_SHARED_KEY not in str(h_val)
    assert SENTINEL_TEST_SHARED_KEY not in body.decode("utf-8")
    assert SENTINEL_TEST_SHARED_KEY not in url


def test_sentinel_workspace_id_extracted_from_url() -> None:
    """The workspace-id comes from the leftmost hostname label and
    surfaces in the Authorization header."""
    _, headers, _ = build_request(
        Preset.SENTINEL,
        "https://my-workspace-xyz.ods.opinsights.azure.com/api/logs",
        SENTINEL_TEST_SHARED_KEY,
        [_sample_allow_event()],
    )
    assert "SharedKey my-workspace-xyz:" in headers["Authorization"]


# ---------------------------------------------------------------------------
# Unknown preset
# ---------------------------------------------------------------------------


def test_unknown_preset_raises() -> None:
    with pytest.raises(ValueError, match="unknown preset"):
        build_request("not-a-real-preset", "https://x/", TOKEN, [])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# End-to-end via aiohttp test server: drive a real WebhookPusher per
# preset against a localhost server + capture the request shape.
# ---------------------------------------------------------------------------


class _CapturedRequest:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.body: bytes = b""
        self.path: str = ""
        self.method: str = ""


@pytest.fixture
async def _capture_server(unused_tcp_port_factory):
    """aiohttp test server that captures the first request it
    receives. Returns (base_url, captured)."""
    captured = _CapturedRequest()
    event = asyncio.Event()

    async def _handler(request: web.Request) -> web.Response:
        captured.method = request.method
        captured.path = request.path
        captured.headers = dict(request.headers)
        captured.body = await request.read()
        event.set()
        return web.Response(status=200, text="ok")

    app = web.Application()
    # Accept any path so each preset can use its native URL shape.
    app.router.add_route("*", "/{tail:.*}", _handler)
    runner = web.AppRunner(app)
    await runner.setup()
    port = unused_tcp_port_factory()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    base = f"http://127.0.0.1:{port}"
    try:
        yield base, captured, event
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_e2e_generic_preset_against_real_server(_capture_server) -> None:
    base, captured, event = _capture_server
    pusher = WebhookPusher(
        url=f"{base}/audit",
        token=TOKEN,
        preset=Preset.GENERIC,
        allow_internal=True,  # localhost
    )
    await pusher.start()
    try:
        pusher.push(_sample_allow_event())
        await asyncio.wait_for(event.wait(), timeout=5.0)
    finally:
        await pusher.stop()
    assert captured.method == "POST"
    assert captured.path == "/audit"
    assert captured.headers["Authorization"] == f"Bearer {TOKEN}"
    assert captured.headers["Content-Type"] == "application/json"
    payload = json.loads(captured.body)
    assert payload["activity_name"] == "GetObject"


@pytest.mark.asyncio
async def test_e2e_datadog_preset_against_real_server(_capture_server) -> None:
    base, captured, event = _capture_server
    pusher = WebhookPusher(
        url=f"{base}/api/v2/logs",
        token=TOKEN,
        preset=Preset.DATADOG,
        tags="env:prod",
        allow_internal=True,
    )
    await pusher.start()
    try:
        pusher.push(_sample_allow_event())
        await asyncio.wait_for(event.wait(), timeout=5.0)
    finally:
        await pusher.stop()
    assert captured.headers["DD-API-KEY"] == TOKEN
    parsed = json.loads(captured.body)
    assert isinstance(parsed, list)
    assert parsed[0]["ddsource"] == "iam-jit"
    assert parsed[0]["status"] == "info"
    assert "env:prod" in parsed[0]["ddtags"]


@pytest.mark.asyncio
async def test_e2e_splunk_hec_preset_against_real_server(_capture_server) -> None:
    base, captured, event = _capture_server
    pusher = WebhookPusher(
        url=f"{base}/services/collector/event",
        token=TOKEN,
        preset=Preset.SPLUNK_HEC,
        allow_internal=True,
    )
    await pusher.start()
    try:
        pusher.push(_sample_deny_event())
        await asyncio.wait_for(event.wait(), timeout=5.0)
    finally:
        await pusher.stop()
    assert captured.headers["Authorization"] == f"Splunk {TOKEN}"
    wrapper = json.loads(captured.body)
    assert wrapper["sourcetype"] == "iam_jit:bouncer:ibounce"
    assert wrapper["event"]["unmapped"]["iam_jit"]["verdict"] == "DENY"


@pytest.mark.asyncio
async def test_e2e_sentinel_preset_against_real_server(_capture_server) -> None:
    base, captured, event = _capture_server
    pusher = WebhookPusher(
        # The hostname's leftmost label IS the workspace id; aiohttp
        # accepts loopback regardless, but we still need the URL
        # parser to extract a workspace id.
        url=f"{base}/api/logs",
        token=SENTINEL_TEST_SHARED_KEY,
        preset=Preset.SENTINEL,
        sentinel_table="MyTable",
        allow_internal=True,
    )
    await pusher.start()
    try:
        pusher.push(_sample_allow_event())
        await asyncio.wait_for(event.wait(), timeout=5.0)
    finally:
        await pusher.stop()
    assert captured.headers["Log-Type"] == "MyTable"
    assert captured.headers["Authorization"].startswith("SharedKey 127:")
    assert "x-ms-date" in captured.headers
    # Body is JSON array.
    parsed = json.loads(captured.body)
    assert isinstance(parsed, list)
    # The shared key is HMAC-consumed; never serialised verbatim.
    assert SENTINEL_TEST_SHARED_KEY not in captured.headers["Authorization"]
    assert SENTINEL_TEST_SHARED_KEY not in captured.body.decode("utf-8")
