"""Vendor-shaped webhook body/headers adapters (#257).

Per [[audit-webhook-presets]]: the canonical OCSF event (per
[[ocsf-audit-schema]]) is preserved unchanged in the JSONL log file +
in the webhook body. At webhook send-time we add a thin per-vendor
overlay (auth header + vendor-native overlay fields) so the customer's
existing SIEM auto-categorisation works without writing a custom
ingest mapping.

This module is pure transformation. No I/O, no scoring, no LLM (per
[[scorer-is-ground-truth]]). Each adapter takes an OCSF event list +
config and returns a (url, headers, body_bytes) tuple that the
webhook pusher POSTs as-is.

Per [[security-team-positioning-safety-not-surveillance]]: the
vendor overlay uses neutral language. Datadog `status` is one of
`info|error|notice` — no "violation"/"unauthorized" / "blocked"
framing in the overlay; the OCSF event's `status_detail` carries the
deny reason for operators who drill in.

Per [[deliberate-feature-completion]]: this module ships with full
unit tests + the regression assertion that the `generic` preset is
byte-identical to the pre-slice wire format.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import json
import urllib.parse
from enum import Enum
from typing import Any


class Preset(str, Enum):
    """Webhook body/headers preset selector.

    `GENERIC` (default) is byte-identical to the pre-#257 wire
    format: Bearer token in Authorization + NDJSON body. Existing
    operator webhook consumers keep working without code changes.

    The other three are vendor-shaped for one-click SIEM ingest:
    Datadog Logs HTTP intake, Splunk HEC, Microsoft Sentinel
    (Log Analytics Workspace).
    """

    GENERIC = "generic"
    DATADOG = "datadog"
    SPLUNK_HEC = "splunk-hec"
    SENTINEL = "sentinel"


# OCSF status_id -> Datadog `status` string. Datadog reserves a
# narrow vocabulary (`emergency|alert|critical|error|warning|notice|
# info|debug`); we map only the three values that the OCSF builder
# ever emits today + default to `info` for anything else (per
# [[security-team-positioning-safety-not-surveillance]] — neutral
# default, never escalate to `critical` automatically).
_OCSF_STATUS_TO_DD_STATUS = {
    1: "info",     # Success
    2: "error",    # Failure (e.g. enforced DENY)
    99: "notice",  # Other (e.g. AUDIT_DROPPED synthetic, non-binary verdict)
}


def build_request(
    preset: Preset,
    url: str,
    token: str,
    events: list[dict[str, Any]],
    *,
    tags: str = "",
    sentinel_table: str = "IamJitBouncer",
    product: str = "ibounce",
) -> tuple[str, dict[str, str], bytes]:
    """Return ``(url, headers, body_bytes)`` for the chosen preset.

    ``events`` is the list of OCSF v1.1.0 class-6003 dicts the pusher
    is about to POST. ``token`` is the operator's vendor secret (DD
    API key / Splunk HEC token / Sentinel shared key — base64-
    encoded for Sentinel).

    Per [[ocsf-audit-schema]] the OCSF event is preserved verbatim in
    the body. Vendor overlay fields sit ALONGSIDE the OCSF fields so
    a downstream tool reading the vendor pipeline can still find
    every OCSF field.
    """
    if preset == Preset.GENERIC:
        return _generic(url, token, events)
    if preset == Preset.DATADOG:
        return _datadog(url, token, events, tags=tags, product=product)
    if preset == Preset.SPLUNK_HEC:
        return _splunk_hec(url, token, events, product=product)
    if preset == Preset.SENTINEL:
        return _sentinel(url, token, events, sentinel_table=sentinel_table)
    raise ValueError(f"unknown preset: {preset!r}")


# ---------------------------------------------------------------------------
# generic — byte-identical to the pre-#257 wire format.
# ---------------------------------------------------------------------------


def _generic(
    url: str, token: str, events: list[dict[str, Any]],
) -> tuple[str, dict[str, str], bytes]:
    """Bearer token in Authorization + NDJSON body.

    REGRESSION CONTRACT: the wire bytes here MUST match
    `WebhookPusher._send_once` as it shipped pre-#257. The
    `test_generic_preset_byte_identical_to_pre_slice_behavior` test
    snapshots the expected format and asserts equality.

    NDJSON (newline-delimited JSON) — for ``batch_size=1`` this is a
    single JSON object with no trailing newline; for ``batch_size>1``
    it's one object per line. ``ensure_ascii=False`` matches the
    pre-slice serialiser so non-ASCII bytes in (e.g.) AWS resource
    names round-trip without `\\u` escapes.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "ibounce-audit-export/1.0",
    }
    body = "\n".join(json.dumps(e, ensure_ascii=False) for e in events).encode("utf-8")
    return url, headers, body


# ---------------------------------------------------------------------------
# datadog — Logs HTTP intake (https://docs.datadoghq.com/api/latest/logs/)
# ---------------------------------------------------------------------------


def _datadog(
    url: str, token: str, events: list[dict[str, Any]],
    *, tags: str, product: str,
) -> tuple[str, dict[str, str], bytes]:
    """Datadog Logs intake. Header `DD-API-KEY`; body is a JSON array
    of objects, each OCSF event OVERLAID with DD-native fields
    (`service`, `ddsource`, `host`, `ddtags`, `status`, `message`).

    Per [[ocsf-audit-schema]] field-overlap rule: the OCSF `status`
    field name collides with DD's reserved `status`; we preserve the
    original OCSF value under `ocsf.status` so both are queryable in
    the DD pipeline.
    """
    headers = {
        "DD-API-KEY": token,
        "Content-Type": "application/json",
        "User-Agent": "ibounce-audit-export/1.0",
    }
    overlayed: list[dict[str, Any]] = []
    for event in events:
        overlayed.append(_datadog_overlay(event, tags=tags, product=product))
    body = json.dumps(overlayed, ensure_ascii=False).encode("utf-8")
    return url, headers, body


def _datadog_overlay(
    event: dict[str, Any], *, tags: str, product: str,
) -> dict[str, Any]:
    """Build the Datadog-overlayed event. Original OCSF fields stay
    in place; vendor-reserved collisions (`status`) get the OCSF
    original preserved under `ocsf.<field>`."""
    # Shallow copy so we don't mutate the caller's dict (the JSONL
    # log writer is reading the SAME dict — mutating it would corrupt
    # the OCSF log file with DD-specific fields).
    enriched = dict(event)

    src_endpoint = event.get("src_endpoint") or {}
    metadata = event.get("metadata") or {}
    product_block = metadata.get("product") if isinstance(metadata, dict) else None
    service_name = ""
    if isinstance(product_block, dict):
        service_name = product_block.get("name") or ""

    # Preserve the OCSF status (the string "Success"/"Failure"/"Other")
    # under `ocsf.status` BEFORE we overwrite with DD's reserved
    # vocabulary. Keep the OCSF dict tight; only fields that collide
    # need shadowing.
    ocsf_shadow: dict[str, Any] = {}
    if "status" in event:
        ocsf_shadow["status"] = event["status"]
    if ocsf_shadow:
        enriched["ocsf"] = ocsf_shadow

    enriched["service"] = service_name
    enriched["ddsource"] = "iam-jit"
    enriched["host"] = (
        src_endpoint.get("hostname") or src_endpoint.get("ip") or ""
    )
    ddtags = f"product:iam-jit,bouncer:{product}"
    if tags:
        ddtags = f"{ddtags},{tags}"
    enriched["ddtags"] = ddtags
    enriched["status"] = _OCSF_STATUS_TO_DD_STATUS.get(
        event.get("status_id"), "info",
    )
    enriched["message"] = _datadog_message(event)

    return enriched


def _datadog_message(event: dict[str, Any]) -> str:
    """Human-readable single-line summary for the DD `message` field.

    DD uses this for full-text search + dashboard preview. Format:
    ``<verdict> <api_operation> on <first_resource_uid> (<mode>)``
    falling back gracefully when fields are missing.
    """
    unmapped = event.get("unmapped") or {}
    iam_jit = unmapped.get("iam_jit") if isinstance(unmapped, dict) else None
    verdict = ""
    mode = ""
    enforced = False
    if isinstance(iam_jit, dict):
        verdict = (iam_jit.get("verdict") or "").upper()
        mode = iam_jit.get("mode") or ""
        enforced = bool(iam_jit.get("enforced"))
        event_type = iam_jit.get("event_type")
        if event_type == "AUDIT_DROPPED":
            dropped = iam_jit.get("dropped_count", 0)
            return f"AUDIT_DROPPED {dropped} event(s)"

    api = event.get("api") or {}
    operation = api.get("operation") if isinstance(api, dict) else ""

    resources = event.get("resources") or []
    target = ""
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            target = first.get("uid") or first.get("name") or ""

    parts: list[str] = []
    if verdict:
        parts.append(verdict)
    if operation:
        parts.append(operation)
    if target:
        parts.append(f"on {target}")
    qualifier = mode
    if verdict == "DENY":
        qualifier = (
            f"{mode} enforced" if enforced else f"{mode} advisory"
        ).strip()
    if qualifier:
        parts.append(f"({qualifier})")
    if not parts:
        return "iam-jit audit event"
    return " ".join(parts)


# ---------------------------------------------------------------------------
# splunk-hec — HTTP Event Collector (event-wrapped NDJSON)
# https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
# ---------------------------------------------------------------------------


def _splunk_hec(
    url: str, token: str, events: list[dict[str, Any]],
    *, product: str,
) -> tuple[str, dict[str, str], bytes]:
    """Splunk HEC. Header `Authorization: Splunk <token>`; body is
    newline-delimited JSON (NOT a JSON array — HEC explicitly does
    NOT accept arrays at `/services/collector/event`).

    Each line wraps the full OCSF event under `event` + sets HEC's
    standard envelope fields (`sourcetype`, `source`, `host`,
    `time`). The OCSF `time` (Unix milliseconds) is converted to HEC's
    fractional Unix seconds.
    """
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json",
        "User-Agent": "ibounce-audit-export/1.0",
    }
    lines: list[str] = []
    for event in events:
        lines.append(json.dumps(
            _splunk_envelope(event, product=product),
            ensure_ascii=False,
        ))
    body = "\n".join(lines).encode("utf-8")
    return url, headers, body


def _splunk_envelope(
    event: dict[str, Any], *, product: str,
) -> dict[str, Any]:
    """Wrap one OCSF event in Splunk HEC's envelope. The OCSF event
    sits under ``event`` verbatim; HEC's auto-extraction will index
    every nested field as ``event.<path>``."""
    src_endpoint = event.get("src_endpoint") or {}
    host = src_endpoint.get("hostname") or src_endpoint.get("ip") or ""
    # OCSF `time` is unix-milliseconds (int). HEC wants fractional
    # unix-seconds. Fall back to current wall-clock when the event
    # didn't set one (shouldn't happen for events the builder
    # produces, but be defensive).
    time_ms = event.get("time")
    if isinstance(time_ms, (int, float)):
        time_seconds: float = float(time_ms) / 1000.0
    else:
        time_seconds = _dt.datetime.now(_dt.UTC).timestamp()
    return {
        "event": event,
        "sourcetype": f"iam_jit:bouncer:{product}",
        "source": "iam-jit",
        "host": host,
        "time": time_seconds,
    }


# ---------------------------------------------------------------------------
# sentinel — Microsoft Sentinel / Log Analytics Workspace ingest
# https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api
# ---------------------------------------------------------------------------


def _sentinel(
    url: str, token: str, events: list[dict[str, Any]],
    *, sentinel_table: str,
) -> tuple[str, dict[str, str], bytes]:
    """Microsoft Sentinel Data Collector API.

    Header `Authorization: SharedKey <workspace-id>:<HMAC-SHA256>`,
    where the HMAC is computed per Microsoft's documented algorithm
    over (METHOD, content-length, content-type, x-ms-date, resource).

    Body is a JSON array of OCSF events (one row per element in the
    resulting Log Analytics custom table named by ``sentinel_table``).
    """
    body = json.dumps(events, ensure_ascii=False).encode("utf-8")
    date = _sentinel_rfc1123_now()
    workspace_id = _extract_sentinel_workspace_id(url)
    signature = sentinel_signature(
        shared_key_b64=token,
        method="POST",
        content_length=len(body),
        content_type="application/json",
        date=date,
        resource="/api/logs",
    )
    headers = {
        "Authorization": f"SharedKey {workspace_id}:{signature}",
        "Log-Type": sentinel_table,
        "x-ms-date": date,
        "Content-Type": "application/json",
        "User-Agent": "ibounce-audit-export/1.0",
    }
    return url, headers, body


def sentinel_signature(
    *,
    shared_key_b64: str,
    method: str,
    content_length: int,
    content_type: str,
    date: str,
    resource: str,
) -> str:
    """Compute the Sentinel SharedKey HMAC-SHA256 signature.

    Exposed at module scope so the HMAC test-vector test can assert
    the calculation independently of the request-builder plumbing.

    Algorithm per Microsoft's Data Collector API doc:
        string_to_sign = METHOD\\n + content-length + \\napplication/json
                         \\nx-ms-date:<date>\\n/api/logs
        signature       = base64(HMAC-SHA256(b64decode(shared_key),
                                              string_to_sign))
    """
    string_to_sign = (
        f"{method}\n{content_length}\n{content_type}\nx-ms-date:{date}\n{resource}"
    )
    decoded_key = base64.b64decode(shared_key_b64)
    digest = hmac.new(
        decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def _sentinel_rfc1123_now() -> str:
    """Return the current UTC time formatted as RFC 1123 (which is
    what Sentinel's `x-ms-date` header expects)."""
    return _dt.datetime.now(_dt.UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")


def _extract_sentinel_workspace_id(url: str) -> str:
    """Parse the workspace-id out of the Sentinel ingest URL.

    Sentinel URLs are shaped like
    ``https://<workspace-id>.ods.opinsights.azure.com/api/logs?...``.
    We pull the leftmost label of the hostname; if the URL doesn't
    match the expected shape we return an empty string + let the
    vendor's endpoint surface the resulting 401 (per
    [[audit-webhook-presets]] "Don't validate the vendor's token
    format" — same principle for the workspace id).
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return ""
    host = parsed.hostname or ""
    if not host:
        return ""
    return host.split(".", 1)[0]
