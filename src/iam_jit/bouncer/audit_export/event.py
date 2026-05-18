"""Shared audit-event schema builder for the audit-export transport.

ONE helper builds the JSON payload that BOTH the log writer + the
webhook pusher serialize. This guarantees the two channels emit
identical bytes for the same decision, which is a load-bearing
property for security teams that consume both channels (e.g. webhook
to Splunk for alerting + JSONL to S3 for cold storage) and expect
them to reconcile.

Schema lives in the shared `security-team-audit-export` memo so the
sibling Bounce-suite agents (kbounce, dbounce) emit the same shape.
Keep this module dependency-light: no aiohttp, no SQLite — just
dict-shape plumbing so the helper is easy to call from the proxy
hot-path or from the upcoming Slice 2 alerting rule engine.

Per `scorer-is-ground-truth`: do NOT enrich the event with
LLM-derived risk scores. The scorer can flag separately; the audit
event records DETERMINISTIC decision data only. If a future caller
wants to add LLM-derived context, put it in a `scorer` event of its
own type — don't smuggle it into `proxy.decision` events.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

# Bump when the shape changes in a way consumers must adapt to
# (e.g. a renamed required field). Additive changes (new optional
# fields, new ext.* keys) do not require a bump. Consumers of the
# webhook / JSONL stream should branch on this when they have to.
AUDIT_EVENT_SCHEMA_VERSION = "1"

# Wire-version of the product itself. Read lazily so the import here
# doesn't pull the heavy mcp_server module just to build an event.
def _product_version() -> str:
    try:
        from ... import mcp_server as _mcp
        return getattr(_mcp, "SERVER_VERSION", "0.0.0")
    except Exception:
        return "0.0.0"


def _now_iso_z() -> str:
    """Wall-clock timestamp in the canonical Z-suffixed ISO-8601
    form the shared schema uses across all 3 Bounce products."""
    return _dt.datetime.now(_dt.UTC).isoformat().replace("+00:00", "Z")


def audit_event_from_decision(
    *,
    decision_id: int,
    mode: str,
    profile: str | None,
    verdict: str,
    reason: str,
    service: str,
    action: str,
    arn: str | None,
    region: str | None,
    host: str,
    upstream: str | None = None,
    enforced: bool = False,
    active_pause_id: int | None = None,
    principal: str | None = None,
    request_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical audit event for one proxy decision.

    Schema mirrors the shared spec in [[security-team-audit-export]].
    Per the memo, fields are stable across ibounce / kbounce /
    dbounce; the `ext` dict is the per-product expansion slot.

    `extra` arguments are merged INTO the `ext` namespace, not the
    top level — top-level keys are reserved for the shared schema.
    """
    ext: dict[str, Any] = {}
    if extra:
        ext.update(extra)
    if active_pause_id is not None:
        ext["active_pause_id"] = active_pause_id
    if enforced:
        ext["enforced"] = True

    return {
        "ts": _now_iso_z(),
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "product": "ibounce",
        "version": _product_version(),
        "event_type": "proxy.decision",
        "decision_id": decision_id,
        "mode": mode,
        "profile": profile,
        "verdict": verdict,
        "reason": reason,
        "principal": principal,
        "action": f"{service}:{action}" if service and action else action or service or "",
        "service": service,
        "resource": arn,
        "region": region,
        "request_id": request_id,
        "host": host,
        "upstream": upstream,
        "ext": ext,
    }


def audit_dropped_event(
    *,
    dropped_count: int,
    reason: str,
) -> dict[str, Any]:
    """Synthetic event emitted by the webhook pusher when its bounded
    queue overflows (or by the log writer if its queue ever does).
    Consumers can spot the data-loss window in their downstream
    aggregator (queryable: `event_type == "AUDIT_DROPPED"`).

    `dropped_count` resets each time this event is emitted so each
    AUDIT_DROPPED row represents the gap between this event and the
    previous one — consumers don't have to do delta math themselves.
    """
    return {
        "ts": _now_iso_z(),
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "product": "ibounce",
        "version": _product_version(),
        "event_type": "AUDIT_DROPPED",
        "dropped_count": dropped_count,
        "reason": reason,
    }
