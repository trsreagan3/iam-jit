"""#724 — OCSF synthetic for a chain-driven tightening.

When a chained signal from one bouncer TIGHTENS this bouncer's
decision, we emit a ``CHAIN_TIGHTENED`` OCSF v1.1.0 class-6003 event
that ATTRIBUTES the source bouncer (per the task spec: "audited ...
with the source bouncer attributed"). Language is neutral per
``[[ambient-value-prop-and-friction-framing]]`` /
``[[security-team-positioning-safety-not-surveillance]]`` — a
SAFETY action, never "violation"/"unauthorized".
"""

from __future__ import annotations

from typing import Any

from ..bouncer.audit_export.event import (
    OCSF_SCHEMA_VERSION,
    _now_unix_ms,
    _product_version,
)

_CLASS_UID = 6003
_CLASS_NAME = "API Activity"
_CATEGORY_UID = 6
_CATEGORY_NAME = "Application Activity"

_ACTIVITY_ID = 99  # Other — no CRUD verb for "a chain tightened posture"
_ACTIVITY_NAME = "chain_tightened"
_TYPE_UID = _CLASS_UID * 100 + _ACTIVITY_ID  # 600399

# High: a cross-protocol tightening means another bouncer saw something
# worth locking down (e.g. PII in a SQL result). Same severity as the
# cost breaker's "stop the bleeding" frame.
_SEVERITY_ID = 4
_SEVERITY = "High"

_STATUS_ID = 99
_STATUS = "Other"

_PRODUCT_NAME = "ibounce"
_PRODUCT_VENDOR_NAME = "iam-jit"

EVENT_TYPE_CHAIN_TIGHTENED = "CHAIN_TIGHTENED"


def make_chain_tightened_event(
    *,
    session_id: str,
    source_bouncer: str,
    trigger_kind: str,
    action_bouncer: str,
    action_verb: str,
    mode: str,                 # "block" | "alert"
    enforced: bool,
    ttl_seconds: int,
    service: str | None = None,
    action: str | None = None,
    host: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    """Build the OCSF CHAIN_TIGHTENED synthetic, attributing the source
    bouncer that raised the originating signal."""
    verb = (
        "tightened (egress for this session is now denied)"
        if mode == "block" and enforced
        else "flagged (alert mode; the request was still allowed)"
    )
    detail = (
        f"Cross-bouncer chain fired for session "
        f"{session_id or '(unattributed)'}: {source_bouncer} observed "
        f"'{trigger_kind}', so {action_bouncer} {verb}. The originating "
        f"signal is session-scoped (TTL {ttl_seconds}s) and only ever "
        f"tightens — it can never widen access."
    )
    return {
        "metadata": {
            "version": OCSF_SCHEMA_VERSION,
            "product": {
                "name": _PRODUCT_NAME,
                "vendor_name": _PRODUCT_VENDOR_NAME,
                "version": _product_version(),
            },
        },
        "time": _now_unix_ms(),
        "class_uid": _CLASS_UID,
        "class_name": _CLASS_NAME,
        "category_uid": _CATEGORY_UID,
        "category_name": _CATEGORY_NAME,
        "activity_id": _ACTIVITY_ID,
        "activity_name": _ACTIVITY_NAME,
        "type_uid": _TYPE_UID,
        "type_name": f"{_CLASS_NAME}: Other",
        "severity_id": _SEVERITY_ID,
        "severity": _SEVERITY,
        "status_id": _STATUS_ID,
        "status": _STATUS,
        "status_detail": detail,
        "actor": {"user": {"name": agent_name or "", "uid": session_id or ""}},
        "api": {
            "operation": "chain_tightened",
            "service": {"name": f"{action_bouncer}.bouncer_chaining"},
            "request": {"uid": session_id or ""},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {"hostname": host or ""},
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_CHAIN_TIGHTENED,
                "ext": {
                    "session_id": session_id or "",
                    # Source attribution — the bouncer whose observation
                    # tightened this one. This is what a reviewer filters
                    # on to trace a cross-protocol chain.
                    "chain_source_bouncer": source_bouncer,
                    "chain_trigger_kind": trigger_kind,
                    "chain_action_bouncer": action_bouncer,
                    "chain_action_verb": action_verb,
                    "chain_mode": mode,
                    "chain_enforced": bool(enforced),
                    "chain_signal_ttl_seconds": int(ttl_seconds),
                    "service": service or "",
                    "action": action or "",
                },
            },
        },
    }


__all__ = [
    "EVENT_TYPE_CHAIN_TIGHTENED",
    "make_chain_tightened_event",
]
