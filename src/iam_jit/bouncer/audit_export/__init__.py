"""Security-team audit-export transport (Slice 1 of #252).

Per the `security-team-audit-export` memo: each Bounce product
gains an audit-export layer that emits every proxy decision to one
or both of:

  Channel 1 — JSONL log file (FREE; all tiers)
    `AuditLogWriter` — append-only `O_APPEND|O_CREAT|O_WRONLY`,
    async-queued, optional fsync. No rotation built-in (operators
    point logrotate / Fluent Bit / Vector at the file).

  Channel 2 — HTTPS webhook push (ENTERPRISE; license-gated)
    `WebhookPusher` — bounded queue (default 1000), exponential
    backoff (1s -> 32s, max 5 attempts), drop + emit synthetic
    `AUDIT_DROPPED` event on overflow. SSRF gate via
    `socket.gethostbyname_ex()` + RFC1918/loopback/.internal
    denylist (mirrors dbounce MED-D8-06 closure). Bearer token
    auth via `Authorization: Bearer <token>`. The token NEVER
    appears in startup banner / /healthz / log file / error
    messages.

The two channels read from the SAME helper (`audit_event_from_decision`
in `event.py`) so the schema stays in lockstep across the products.

Slice 2 (alerting rules) rides on the same transport — alerts get
serialized as events with `event_type: SECURITY_ALERT` on the same
two channels.

Per `ibounce-honest-positioning`: this is operator-visibility for
security teams, not adversary-defense. An adversarial agent can
still bypass the bouncer entirely (per `bouncer-positioning-locked-
iam`); the audit catches the post-hoc + the BYPASS events.

Per `no-hosted-saas`: iam-jit-the-company NEVER receives the
webhook. The operator points the URL at their own collector
(Splunk / Datadog / S3 / a custom HTTP sink).

Per `self-host-zero-billing-dependency`: webhook adds no iam-jit
billing dependency; the customer owns the endpoint + the bandwidth.
"""

from __future__ import annotations

from .admin_action import (
    ADMIN_ACTION_ALERT_RULE_EDIT,
    ADMIN_ACTION_CONFIG_EXPORT,
    ADMIN_ACTION_CONFIG_IMPORT,
    ADMIN_ACTION_DIAGNOSTICS_BUNDLE,
    ADMIN_ACTION_LICENSE_INSTALL,
    ADMIN_ACTION_PAUSE_START,
    ADMIN_ACTION_PAUSE_STOP,
    ADMIN_ACTION_PRESET_APPLY,
    ADMIN_ACTION_PROFILE_ASSIGN,
    ADMIN_ACTION_PROFILE_DELETE,
    ADMIN_ACTION_PROFILE_INSTALL,
    ADMIN_ACTION_PROFILE_SWAP,
    ADMIN_ACTION_RULE_ADD,
    ADMIN_ACTION_RULE_REMOVE,
    ADMIN_ACTION_SESSION_KILL,
    ADMIN_ACTION_SOURCE_API,
    ADMIN_ACTION_SOURCE_CLI,
    ADMIN_ACTION_SOURCE_MCP,
    ADMIN_ACTION_SOURCE_UNKNOWN,
    DEFAULT_LOCAL_OPERATOR,
    EVENT_TYPE_ADMIN_ACTION,
    KNOWN_ADMIN_ACTION_KINDS,
    admin_action_event_from_payload,
    admin_action_payload,
    emit_admin_action_direct,
    enqueue_admin_action,
    hash_state,
    make_admin_action_event,
    resolve_operator,
)
from .agent_context import (
    AgentSession,
    active_agent_session,
    active_or_disk_agent_session,
    begin_mcp_session,
    detect_from_process_tree,
    detect_from_user_agent,
    end_mcp_session,
    reset_for_tests,
    resolve_agent_block,
    session_ended_event,
)
from .alerts import (
    BUILTIN_RULES,
    DEFAULT_AUDIT_EXPORT_DEGRADED_DROP_THRESHOLD,
    DEFAULT_AUDIT_EXPORT_DEGRADED_DROP_WINDOW_SECONDS,
    DEFAULT_AUDIT_EXPORT_DEGRADED_FAILURE_THRESHOLD,
    FORBIDDEN_ALERT_WORDS,
    AlertRule,
    AlertsConfig,
    AlertsLicenseError,
    RuleEngine,
    audit_export_degraded_stderr_message,
    gate_alerts_license,
    load_alerts_config,
    make_admin_fallback_grant_event,
    make_pause_end_event,
    make_profile_install_event,
    write_audit_export_degraded_stderr,
)
from .event import (
    AUDIT_EVENT_SCHEMA_VERSION,
    OCSF_SCHEMA_VERSION,
    audit_dropped_event,
    audit_event_from_decision,
)
from .heartbeat import (
    DEFAULT_HEARTBEAT_MISSING_COUNT,
    EVENT_TYPE_HEARTBEAT,
    HeartbeatEmitter,
    heartbeat_status,
    make_heartbeat_event,
)
from .log import AuditLogWriter
from .presets import Preset, build_request
from .webhook import (
    SSRFRejectedError,
    WebhookLicenseError,
    WebhookPusher,
    validate_webhook_url,
)

__all__ = [
    "ADMIN_ACTION_ALERT_RULE_EDIT",
    "ADMIN_ACTION_CONFIG_EXPORT",
    "ADMIN_ACTION_CONFIG_IMPORT",
    "ADMIN_ACTION_DIAGNOSTICS_BUNDLE",
    "ADMIN_ACTION_LICENSE_INSTALL",
    "ADMIN_ACTION_PAUSE_START",
    "ADMIN_ACTION_PAUSE_STOP",
    "ADMIN_ACTION_PRESET_APPLY",
    "ADMIN_ACTION_PROFILE_ASSIGN",
    "ADMIN_ACTION_PROFILE_DELETE",
    "ADMIN_ACTION_PROFILE_INSTALL",
    "ADMIN_ACTION_PROFILE_SWAP",
    "ADMIN_ACTION_RULE_ADD",
    "ADMIN_ACTION_RULE_REMOVE",
    "ADMIN_ACTION_SESSION_KILL",
    "ADMIN_ACTION_SOURCE_API",
    "ADMIN_ACTION_SOURCE_CLI",
    "ADMIN_ACTION_SOURCE_MCP",
    "ADMIN_ACTION_SOURCE_UNKNOWN",
    "AUDIT_EVENT_SCHEMA_VERSION",
    "AgentSession",
    "AlertRule",
    "AlertsConfig",
    "AlertsLicenseError",
    "AuditLogWriter",
    "BUILTIN_RULES",
    "DEFAULT_AUDIT_EXPORT_DEGRADED_DROP_THRESHOLD",
    "DEFAULT_AUDIT_EXPORT_DEGRADED_DROP_WINDOW_SECONDS",
    "DEFAULT_AUDIT_EXPORT_DEGRADED_FAILURE_THRESHOLD",
    "DEFAULT_HEARTBEAT_MISSING_COUNT",
    "DEFAULT_LOCAL_OPERATOR",
    "EVENT_TYPE_ADMIN_ACTION",
    "EVENT_TYPE_HEARTBEAT",
    "FORBIDDEN_ALERT_WORDS",
    "HeartbeatEmitter",
    "KNOWN_ADMIN_ACTION_KINDS",
    "OCSF_SCHEMA_VERSION",
    "Preset",
    "RuleEngine",
    "SSRFRejectedError",
    "WebhookLicenseError",
    "WebhookPusher",
    "active_agent_session",
    "active_or_disk_agent_session",
    "admin_action_event_from_payload",
    "admin_action_payload",
    "audit_dropped_event",
    "audit_event_from_decision",
    "audit_export_degraded_stderr_message",
    "begin_mcp_session",
    "build_request",
    "detect_from_process_tree",
    "detect_from_user_agent",
    "emit_admin_action_direct",
    "end_mcp_session",
    "enqueue_admin_action",
    "gate_alerts_license",
    "hash_state",
    "heartbeat_status",
    "load_alerts_config",
    "make_admin_action_event",
    "make_admin_fallback_grant_event",
    "make_heartbeat_event",
    "make_pause_end_event",
    "make_profile_install_event",
    "reset_for_tests",
    "resolve_agent_block",
    "resolve_operator",
    "session_ended_event",
    "validate_webhook_url",
    "write_audit_export_degraded_stderr",
]
