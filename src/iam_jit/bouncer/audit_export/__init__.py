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

  Channel 3 — per-session NDJSON recording (#285; FREE; opt-in)
    `SessionRecorder` — tees every event into
    `{dir}/{agent.session_id}.ndjson` so the full per-session
    transcript is portable + replayable via the cross-product
    `iam-jit session replay <FILE>` CLI. Files are 0o600;
    sessions older than the heartbeat threshold (default 5min)
    are finalised atomically (`.partial` -> `.ndjson`).

The two transport channels (1 + 2) read from the SAME helper
(`audit_event_from_decision` in `event.py`) so the schema stays in
lockstep across the products. The recorder consumes those same events
via the proxy's `_emit_audit_event_raw` tee.

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
The recorder is purely local filesystem; same posture.
"""

from __future__ import annotations

from .admin_action import (
    ADMIN_ACTION_ALERT_RULE_EDIT,
    ADMIN_ACTION_AUDIT_LOG_ARCHIVED,
    ADMIN_ACTION_AUDIT_LOG_PURGED,
    ADMIN_ACTION_AUDIT_LOG_RECOVERED_PARTIAL,
    ADMIN_ACTION_AUDIT_LOG_ROTATED,
    ADMIN_ACTION_AUDIT_LOG_ROTATION_FAILED,
    ADMIN_ACTION_BACKUP_CREATE,
    ADMIN_ACTION_BACKUP_RESTORE,
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
    extract_agent_headers,
    is_valid_agent_name,
    is_valid_agent_session_id,
    reset_agent_headers_rejected_for_tests,
    reset_for_tests,
    resolve_agent_block,
    session_ended_event,
    total_agent_headers_rejected,
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
from .rotation import (
    DEFAULT_DB_RETENTION_DAYS,
    DEFAULT_DISK_CRIT_PCT,
    DEFAULT_DISK_WARN_PCT,
    DEFAULT_MAX_AGE_DAYS,
    DEFAULT_MAX_SIZE_MB,
    DiskStatus,
    IntegrityResult,
    archive_logs,
    disk_status,
    purge_older_than as rotation_purge_older_than,
    recover_partial_tail,
    rotate as rotate_log,
    rotate_db_daily,
    should_rotate_by_age,
    should_rotate_by_size,
    verify_integrity,
)
from .presets import Preset, build_request
from .routes import (
    PagerDutyDestination,
    Route,
    RoutesConfig,
    RoutesConfigError,
    RoutesEngine,
    RoutesLicenseError,
    SlackDestination,
    WebhookDestination,
    evaluate_match,
    gate_routes_license,
    load_routes_config,
    select_routes,
)
from .recorder import (
    DEFAULT_HEARTBEAT_TIMEOUT_SECONDS as RECORDER_HEARTBEAT_TIMEOUT_SECONDS,
    PARTIAL_SUFFIX as RECORDING_PARTIAL_SUFFIX,
    RECORDING_FILE_MODE,
    RECORDING_SCHEMA_VERSION,
    SessionRecorder,
    detection_finding_from_session,
    event_count_by_type,
    extract_session_id,
    is_valid_session_id,
    list_sessions,
    purge_older_than,
    read_session,
    read_session_file,
)
from .object_storage import (
    DEFAULT_MAX_PENDING_ROWS as OBJECT_STORAGE_DEFAULT_MAX_PENDING_ROWS,
    DEFAULT_MAX_SIZE_MB as OBJECT_STORAGE_DEFAULT_MAX_SIZE_MB,
    DEFAULT_REGION as OBJECT_STORAGE_DEFAULT_REGION,
    DEFAULT_ROTATION_MINUTES as OBJECT_STORAGE_DEFAULT_ROTATION_MINUTES,
    IN_PROGRESS_SUFFIX as OBJECT_STORAGE_IN_PROGRESS_SUFFIX,
    ObjectStorageConfigError,
    ObjectStorageCredentials,
    ObjectStorageCredentialsError,
    ObjectStorageS3Client,
    ObjectStorageWriter,
    load_credentials as load_object_storage_credentials,
)
from .security_lake import (
    DEFAULT_MAX_BATCH_BYTES as SECURITY_LAKE_DEFAULT_MAX_BATCH_BYTES,
    DEFAULT_MAX_PENDING_ROWS as SECURITY_LAKE_DEFAULT_MAX_PENDING_ROWS,
    DEFAULT_ROTATION_SECONDS as SECURITY_LAKE_DEFAULT_ROTATION_SECONDS,
    OCSF_PARQUET_COLUMNS,
    SecurityLakeConfigError,
    SecurityLakeCredentialsError,
    SecurityLakeWriter,
)
from .webhook import (
    SSRFRejectedError,
    WebhookLicenseError,
    WebhookPusher,
    validate_webhook_url,
)

__all__ = [
    "ADMIN_ACTION_ALERT_RULE_EDIT",
    "ADMIN_ACTION_AUDIT_LOG_ARCHIVED",
    "ADMIN_ACTION_AUDIT_LOG_PURGED",
    "ADMIN_ACTION_AUDIT_LOG_RECOVERED_PARTIAL",
    "ADMIN_ACTION_AUDIT_LOG_ROTATED",
    "ADMIN_ACTION_AUDIT_LOG_ROTATION_FAILED",
    "ADMIN_ACTION_BACKUP_CREATE",
    "ADMIN_ACTION_BACKUP_RESTORE",
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
    "DEFAULT_DB_RETENTION_DAYS",
    "DEFAULT_DISK_CRIT_PCT",
    "DEFAULT_DISK_WARN_PCT",
    "DEFAULT_HEARTBEAT_MISSING_COUNT",
    "DEFAULT_MAX_AGE_DAYS",
    "DEFAULT_MAX_SIZE_MB",
    "DiskStatus",
    "IntegrityResult",
    "DEFAULT_LOCAL_OPERATOR",
    "EVENT_TYPE_ADMIN_ACTION",
    "EVENT_TYPE_HEARTBEAT",
    "FORBIDDEN_ALERT_WORDS",
    "HeartbeatEmitter",
    "KNOWN_ADMIN_ACTION_KINDS",
    "OBJECT_STORAGE_DEFAULT_MAX_PENDING_ROWS",
    "OBJECT_STORAGE_DEFAULT_MAX_SIZE_MB",
    "OBJECT_STORAGE_DEFAULT_REGION",
    "OBJECT_STORAGE_DEFAULT_ROTATION_MINUTES",
    "OBJECT_STORAGE_IN_PROGRESS_SUFFIX",
    "ObjectStorageConfigError",
    "ObjectStorageCredentials",
    "ObjectStorageCredentialsError",
    "ObjectStorageS3Client",
    "ObjectStorageWriter",
    "OCSF_SCHEMA_VERSION",
    "PagerDutyDestination",
    "Preset",
    "OCSF_PARQUET_COLUMNS",
    "Route",
    "RoutesConfig",
    "RoutesConfigError",
    "RoutesEngine",
    "RoutesLicenseError",
    "RECORDER_HEARTBEAT_TIMEOUT_SECONDS",
    "RECORDING_FILE_MODE",
    "RECORDING_PARTIAL_SUFFIX",
    "RECORDING_SCHEMA_VERSION",
    "RuleEngine",
    "SECURITY_LAKE_DEFAULT_MAX_BATCH_BYTES",
    "SECURITY_LAKE_DEFAULT_MAX_PENDING_ROWS",
    "SECURITY_LAKE_DEFAULT_ROTATION_SECONDS",
    "SSRFRejectedError",
    "SecurityLakeConfigError",
    "SecurityLakeCredentialsError",
    "SecurityLakeWriter",
    "SessionRecorder",
    "SlackDestination",
    "WebhookDestination",
    "WebhookLicenseError",
    "WebhookPusher",
    "active_agent_session",
    "archive_logs",
    "disk_status",
    "recover_partial_tail",
    "rotate_db_daily",
    "rotate_log",
    "rotation_purge_older_than",
    "should_rotate_by_age",
    "should_rotate_by_size",
    "verify_integrity",
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
    "detection_finding_from_session",
    "emit_admin_action_direct",
    "end_mcp_session",
    "enqueue_admin_action",
    "extract_agent_headers",
    "is_valid_agent_name",
    "is_valid_agent_session_id",
    "reset_agent_headers_rejected_for_tests",
    "total_agent_headers_rejected",
    "evaluate_match",
    "event_count_by_type",
    "extract_session_id",
    "gate_routes_license",
    "gate_alerts_license",
    "hash_state",
    "heartbeat_status",
    "is_valid_session_id",
    "list_sessions",
    "load_alerts_config",
    "load_object_storage_credentials",
    "load_routes_config",
    "make_admin_action_event",
    "make_admin_fallback_grant_event",
    "make_heartbeat_event",
    "make_pause_end_event",
    "make_profile_install_event",
    "purge_older_than",
    "read_session",
    "read_session_file",
    "reset_for_tests",
    "resolve_agent_block",
    "resolve_operator",
    "select_routes",
    "session_ended_event",
    "validate_webhook_url",
    "write_audit_export_degraded_stderr",
]
