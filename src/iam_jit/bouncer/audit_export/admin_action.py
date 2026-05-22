"""Admin-action OCSF audit-event layer (#278) for ibounce.

Closes the security-critical gap that until this slice landed, ONLY
proxy decisions and a small number of operator-side synthetics (admin-
fallback grant, pause end, profile install) rode the OCSF audit-export
channel. CONFIG CHANGES — rule add/remove, pause start/stop, preset
apply, profile hot-swap, session kill, config import/export, license
install — were silent on the export channel even when the operator
took the action. Security teams could not answer "who installed this
profile / paused enforcement / hot-swapped the active profile" purely
from the audit-export stream; they had to cross-reference the
`config_events` table which lives in the per-deployment SQLite store
and was never shipped over the JSONL log / webhook transports.

Per [[cross-product-agent-parity]] kbounce + dbounce ship the same
admin-action layer in parallel (commits 55e364d and 1200a8a
respectively). The wire shape here matches theirs:

  * OCSF v1.1.0 class 6003 (API Activity), product=ibounce,
    vendor_name=iam-jit (per [[ocsf-audit-schema]])
  * activity_id mapped to Create/Update/Delete/Other based on the
    nature of the admin action
  * Stable, deterministic before_hash + after_hash so a security team
    can compose with the tamper-detection rule from
    [[enterprise-admin-controls]]
  * unmapped.iam_jit.admin_action block carries kind + actor + target
    + source so SIEM dashboards can pivot on any axis

Per [[security-team-positioning-safety-not-surveillance]] every
user-facing string is NEUTRAL. The action `kind` values are factual
("profile.install", "rule.add", "pause.start") — never "injected",
"unauthorized", "violation", "infraction".

Per [[creates-never-mutates]] this is an additive feature; it changes
NO enforcement decision. The proxy ignores admin-action events on the
decision path; only the audit channels carry them.

Per [[self-host-zero-billing-dependency]] emission is local-only by
default (JSONL log file). An operator who points
--audit-export-webhook-url at their own collector picks up admin-action
events through the same Enterprise-gated channel as decision events;
iam-jit-the-company never receives them.

Per [[deliberate-feature-completion]] every touchpoint that mutates the
ibounce config surface gains an admin-action emit in this slice — no
half-finished surfaces, no future-PR "we'll add the emit later"
breadcrumbs. Stubbed-for-later emit helpers (config.import,
config.export, license.install) ship so the future PR is a one-line
call.

Token-leak invariant: keys named `license_content`, `license_bytes`,
`license_pem`, `license_private_key`, `license_token`, `secret`,
`bearer_token`, and `webhook_token` are silently stripped from the
`extra` dict before the event lands on the wire. A careless future
caller cannot leak signed material through the audit-export channel.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import os
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OCSF / cross-product constants
# ---------------------------------------------------------------------------

# Re-use the cross-product OCSF constants from event.py / alerts.py.
# Importing the names directly keeps this module honest about the fact
# that the wire shape is shared — bumping one constant bumps all sites.
from .alerts import (  # noqa: E402  (constants live below docstring)
    EVENT_TYPE_HEARTBEAT,  # re-exported for completeness; not used here
)
from .event import (  # noqa: E402
    OCSF_SCHEMA_VERSION,
    _now_unix_ms,
    _product_version,
)

_CLASS_UID = 6003
_CLASS_NAME = "API Activity"
_CATEGORY_UID = 6
_CATEGORY_NAME = "Application Activity"
_TYPE_UID_BASE = 600300  # class_uid * 100

# OCSF activity_id values for class 6003 (per the OCSF v1.1.0 spec).
ACTIVITY_UNKNOWN = 0
ACTIVITY_CREATE = 1
ACTIVITY_READ = 2
ACTIVITY_UPDATE = 3
ACTIVITY_DELETE = 4
ACTIVITY_OTHER = 99

_ACTIVITY_NAME_BY_ID: dict[int, str] = {
    ACTIVITY_UNKNOWN: "Unknown",
    ACTIVITY_CREATE: "Create",
    ACTIVITY_READ: "Read",
    ACTIVITY_UPDATE: "Update",
    ACTIVITY_DELETE: "Delete",
    ACTIVITY_OTHER: "Other",
}

# OCSF severity_id values. Most admin actions land at Informational —
# security teams want to SEE them, not be PAGED on every routine
# `rules add`. The two action kinds that change the enforcement floor
# (license.install, profile.assign) land at High per
# [[security-team-audit-export]].
SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5

_SEVERITY_NAME_BY_ID: dict[int, str] = {
    SEVERITY_INFORMATIONAL: "Informational",
    SEVERITY_LOW: "Low",
    SEVERITY_MEDIUM: "Medium",
    SEVERITY_HIGH: "High",
    SEVERITY_CRITICAL: "Critical",
}

# Product identity. Matches event.py + alerts.py exactly so a SIEM
# dashboard scoped to metadata.product.{name,vendor_name} catches the
# admin-action stream alongside decisions + anomaly alerts.
_PRODUCT_NAME = "ibounce"
_PRODUCT_VENDOR_NAME = "iam-jit"

# Event-type marker the alerts engine / SIEM dashboards key on. Lands
# at unmapped.iam_jit.event_type. Distinct from the existing
# EVENT_TYPE_{PROFILE_INSTALL,PAUSE_END,ADMIN_FALLBACK_GRANT,
# ANOMALY_DETECTED,HEARTBEAT} markers so a single field filter
# (`event_type == "ADMIN_ACTION"`) catches the whole admin-action
# stream regardless of the underlying kind.
EVENT_TYPE_ADMIN_ACTION = "ADMIN_ACTION"


# ---------------------------------------------------------------------------
# Admin-action kinds
# ---------------------------------------------------------------------------

# The canonical list. Each value lands in
# `unmapped.iam_jit.admin_action.kind` AND in OCSF `activity_name` so
# SIEM analysts can pivot on either field. Per
# [[security-team-positioning-safety-not-surveillance]] every kind name
# is NEUTRAL — "profile.install" (what happened), not "profile.injected"
# (accusation).

# Live (wired at one or more touchpoints in this slice):
ADMIN_ACTION_PROFILE_INSTALL = "profile.install"
ADMIN_ACTION_PROFILE_SWAP = "profile.swap"
ADMIN_ACTION_RULE_ADD = "rule.add"
ADMIN_ACTION_RULE_REMOVE = "rule.remove"
ADMIN_ACTION_PAUSE_START = "pause.start"
ADMIN_ACTION_PAUSE_STOP = "pause.stop"
ADMIN_ACTION_PRESET_APPLY = "preset.apply"
ADMIN_ACTION_SESSION_KILL = "session.kill"

# Stubbed for future PRs (the EmitAdminAction helpers are ready; the
# wiring lands when the calling surface ships):
ADMIN_ACTION_CONFIG_IMPORT = "config.import"
ADMIN_ACTION_CONFIG_EXPORT = "config.export"
ADMIN_ACTION_LICENSE_INSTALL = "license.install"
ADMIN_ACTION_PROFILE_ASSIGN = "profile.assign"
ADMIN_ACTION_PROFILE_DELETE = "profile.delete"
ADMIN_ACTION_ALERT_RULE_EDIT = "alert-rule.edit"

# Wired in #277 — `ibounce diagnostics bundle` emits this on every
# bundle creation so a security team can answer "who pulled
# diagnostics + when?" from the audit-export channel. Matches the
# kbounce + dbounce sibling action ids verbatim per
# [[cross-product-agent-parity]].
ADMIN_ACTION_DIAGNOSTICS_BUNDLE = "diagnostics.bundle"

# Wired in #279 — `ibounce backup` + `ibounce restore` emit these so
# a security team can answer "who snapshotted state + when, who
# restored a snapshot + which one?" from the audit-export channel.
# Cross-product-aligned with kbounce + dbounce per
# [[cross-product-agent-parity]]; the wire field values
# ("backup.create" / "backup.restore") match the sibling products
# verbatim so one SIEM rule keyed on `action == "backup.restore"`
# catches the DR-lifecycle event across the three.
ADMIN_ACTION_BACKUP_CREATE = "backup.create"
ADMIN_ACTION_BACKUP_RESTORE = "backup.restore"
# #311 / §A10 — audit-log lifecycle admin-actions. Fired by the
# writer / rotation guard so operators see WHY their log directory
# changed (rotation), WHEN data was reaped (purge), or WHETHER a
# crash left a partial line behind (recovery). Same wire-name
# convention as the sibling products (kbounce / dbounce / gbounce)
# so a SIEM rule keyed on `action == "audit.log.rotated"` catches
# the lifecycle event across all four.
ADMIN_ACTION_AUDIT_LOG_ROTATED = "audit.log.rotated"
ADMIN_ACTION_AUDIT_LOG_ROTATION_FAILED = "audit.log.rotation_failed"
ADMIN_ACTION_AUDIT_LOG_RECOVERED_PARTIAL = "audit.log.recovered_partial"
ADMIN_ACTION_AUDIT_LOG_PURGED = "audit.log.purged"
ADMIN_ACTION_AUDIT_LOG_ARCHIVED = "audit.log.archived"


# Set of every known kind. Used by the dispatch in the proxy's
# pending-audit-events drainer to route ADMIN_ACTION payloads back
# through `make_admin_action_event`.
KNOWN_ADMIN_ACTION_KINDS: frozenset[str] = frozenset({
    ADMIN_ACTION_PROFILE_INSTALL,
    ADMIN_ACTION_PROFILE_SWAP,
    ADMIN_ACTION_RULE_ADD,
    ADMIN_ACTION_RULE_REMOVE,
    ADMIN_ACTION_PAUSE_START,
    ADMIN_ACTION_PAUSE_STOP,
    ADMIN_ACTION_PRESET_APPLY,
    ADMIN_ACTION_SESSION_KILL,
    ADMIN_ACTION_CONFIG_IMPORT,
    ADMIN_ACTION_CONFIG_EXPORT,
    ADMIN_ACTION_LICENSE_INSTALL,
    ADMIN_ACTION_PROFILE_ASSIGN,
    ADMIN_ACTION_PROFILE_DELETE,
    ADMIN_ACTION_ALERT_RULE_EDIT,
    ADMIN_ACTION_DIAGNOSTICS_BUNDLE,
    ADMIN_ACTION_BACKUP_CREATE,
    ADMIN_ACTION_BACKUP_RESTORE,
    ADMIN_ACTION_AUDIT_LOG_ROTATED,
    ADMIN_ACTION_AUDIT_LOG_ROTATION_FAILED,
    ADMIN_ACTION_AUDIT_LOG_RECOVERED_PARTIAL,
    ADMIN_ACTION_AUDIT_LOG_PURGED,
    ADMIN_ACTION_AUDIT_LOG_ARCHIVED,
})


def admin_action_activity_id(kind: str) -> int:
    """Map an admin-action `kind` to its OCSF activity_id.

    Create/Update/Delete map to the canonical CRUD values; anything
    that's neither (config.export, license.install) maps to Other per
    the [[ocsf-audit-schema]] "honest about uncategorized" stance.
    """
    if kind in (
        ADMIN_ACTION_PROFILE_INSTALL,
        ADMIN_ACTION_RULE_ADD,
        ADMIN_ACTION_PRESET_APPLY,
        ADMIN_ACTION_CONFIG_IMPORT,
        ADMIN_ACTION_LICENSE_INSTALL,
        ADMIN_ACTION_BACKUP_CREATE,
    ):
        return ACTIVITY_CREATE
    if kind in (
        ADMIN_ACTION_PROFILE_SWAP,
        ADMIN_ACTION_PAUSE_START,
        ADMIN_ACTION_PAUSE_STOP,
        ADMIN_ACTION_ALERT_RULE_EDIT,
        ADMIN_ACTION_PROFILE_ASSIGN,
        ADMIN_ACTION_BACKUP_RESTORE,
    ):
        return ACTIVITY_UPDATE
    if kind in (
        ADMIN_ACTION_RULE_REMOVE,
        ADMIN_ACTION_SESSION_KILL,
        ADMIN_ACTION_PROFILE_DELETE,
    ):
        return ACTIVITY_DELETE
    return ACTIVITY_OTHER


def admin_action_severity(kind: str) -> tuple[int, str]:
    """Map an admin-action `kind` to its OCSF (severity_id, severity).

    Most admin actions are Informational — security teams want to SEE
    them, not be PAGED on every routine `rules add`. Two action kinds
    escalate to High per [[security-team-audit-export]]:

      * license.install — installing a new license changes the
        Enterprise enforcement surface; the security team should review.
      * profile.assign — per-user assignment binds an actor to a
        specific guardrail profile; misconfigured assignment can
        silently weaken the floor for a privileged user.
    """
    if kind in (ADMIN_ACTION_LICENSE_INSTALL, ADMIN_ACTION_PROFILE_ASSIGN):
        return SEVERITY_HIGH, _SEVERITY_NAME_BY_ID[SEVERITY_HIGH]
    return SEVERITY_INFORMATIONAL, _SEVERITY_NAME_BY_ID[SEVERITY_INFORMATIONAL]


# ---------------------------------------------------------------------------
# Admin-action sources
# ---------------------------------------------------------------------------

# Where the admin action originated. Lands in
# `unmapped.iam_jit.admin_action.source` so an analyst can answer "did
# this rule come from the CLI, an MCP-bridged agent, or the future
# import path?"

ADMIN_ACTION_SOURCE_CLI = "cli"
ADMIN_ACTION_SOURCE_MCP = "mcp"
ADMIN_ACTION_SOURCE_API = "api"  # reserved for the future control-plane
ADMIN_ACTION_SOURCE_UNKNOWN = "unknown"

_VALID_SOURCES: frozenset[str] = frozenset({
    ADMIN_ACTION_SOURCE_CLI,
    ADMIN_ACTION_SOURCE_MCP,
    ADMIN_ACTION_SOURCE_API,
    ADMIN_ACTION_SOURCE_UNKNOWN,
})


# ---------------------------------------------------------------------------
# Operator identity discovery
# ---------------------------------------------------------------------------

# Env var an operator can set to identify themselves explicitly. Same
# precedence as the CLI's existing `_current_actor()` helper but kept
# in this module so the audit_export package doesn't have to import
# bouncer_cli (which would be a circular dependency).
_OPERATOR_ENV_VAR = "IAM_JIT_BOUNCER_ACTOR"

# Fallback label used when no operator identity can be discovered (no
# env var, no readable OS user). Distinct from "unknown" — this is the
# honest "we know the action happened on this machine but we don't
# have a richer identity for it" answer.
DEFAULT_LOCAL_OPERATOR = "local-operator"


def resolve_operator() -> str:
    """Best-effort discovery of the operator who initiated an admin
    action. Returns a non-empty string; never raises.

    Precedence (matches `bouncer_cli._current_actor` for consistency
    across surfaces):

      1. `IAM_JIT_BOUNCER_ACTOR` env var — agents / CI / wrappers
         identify themselves explicitly.
      2. OS username via `getpass.getuser()`.
      3. `DEFAULT_LOCAL_OPERATOR` ("local-operator") — last-resort
         honest fallback. Used when getpass raises (e.g. a container
         with no /etc/passwd entry for the runtime UID).

    Per [[agent-friendly-not-bypassable]] Lens B there is NO admin-
    action emit with no actor — even unidentifiable callers get the
    `local-operator` label so SIEM dashboards can filter
    `actor.user.name = ""` and find zero rows.
    """
    import getpass

    explicit = os.environ.get(_OPERATOR_ENV_VAR, "").strip()
    if explicit:
        return explicit
    try:
        os_user = getpass.getuser()
    except Exception:
        os_user = ""
    return os_user or DEFAULT_LOCAL_OPERATOR


# ---------------------------------------------------------------------------
# State hashing (composes with tamper-detection per
# [[enterprise-admin-controls]])
# ---------------------------------------------------------------------------

# Keys silently stripped from `extra` dicts before the event lands on
# the wire. The license-content keys come from the future #235 license
# plumbing; the bearer/webhook tokens come from the existing audit-
# export-webhook gate. Mirrors kbounce's stripLicenseContent +
# extended with the webhook bearer.
_TOKEN_LEAK_KEYS: frozenset[str] = frozenset({
    "license_content",
    "license_bytes",
    "license_pem",
    "license_private_key",
    "license_token",
    "secret",
    "bearer_token",
    "webhook_token",
    "authorization",
})


def _strip_secret_keys(extra: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a shallow copy of `extra` with all token-leak keys
    silently removed. Empty input -> {}.

    The strip is silent because we DON'T want to surface a key name
    that might itself encode a secret in a misconfigured deployment
    (e.g. a caller that misnamed its variable). The wire shape is the
    contract; the strip is the defense.
    """
    if not extra:
        return {}
    out: dict[str, Any] = {}
    for k, v in extra.items():
        if k in _TOKEN_LEAK_KEYS:
            continue
        out[k] = v
    return out


def _canonical_json(value: Any) -> bytes:
    """Canonical JSON serialization for hashing. Stable key order +
    no insignificant whitespace so the same semantic input always
    produces the same bytes.

    Per [[cross-product-agent-parity]] kbounce + dbounce use Go's
    encoding/json which sorts map keys; Python's json.dumps with
    `sort_keys=True` matches that contract.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=False,
    ).encode("utf-8")


def hash_state(value: Any) -> str | None:
    """Hex-encoded SHA-256 of the canonical JSON serialisation of
    `value`. Returns None when `value` is None so the caller can omit
    the hash field — distinguishing "before-state not captured" from
    "before-state was the empty value".

    A non-None-but-empty value ({}, [], "") hashes to the SHA of its
    canonical JSON form ("{}", "[]", '""') — those ARE meaningful
    states.
    """
    if value is None:
        return None
    try:
        return hashlib.sha256(_canonical_json(value)).hexdigest()
    except Exception:
        # Don't surface a marshal error to the caller — admin-action
        # emission is best-effort; "no hash" is the honest answer when
        # serialization broke.
        return None


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------


def make_admin_action_event(
    *,
    kind: str,
    actor: str | None = None,
    actor_uid: str | None = None,
    target_kind: str = "",
    target_id: str = "",
    target_extra: Mapping[str, Any] | None = None,
    before: Any = None,
    after: Any = None,
    source: str = ADMIN_ACTION_SOURCE_CLI,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the OCSF v1.1.0 class 6003 event for one admin action.

    Returns a dict whose JSON serialisation is a valid OCSF API
    Activity event (validated against the schema in
    `tests/bouncer/test_audit_export_admin_action.py`).

    Parameters
    ----------
    kind
        One of the `ADMIN_ACTION_*` constants. Empty or unknown values
        are accepted (they land in `unmapped.iam_jit.admin_action.kind`
        as-is) so this builder never refuses a wire shape — the
        operator wants the audit row, not a crash.
    actor
        Operator identity (email, username, OIDC sub, ...). Empty ->
        resolved via `resolve_operator()` so every event carries an
        actor block per [[agent-friendly-not-bypassable]] Lens B.
    actor_uid
        Optional stable id for the operator (e.g. OIDC sub). Defaults
        to `actor` when not supplied.
    target_kind
        Human-readable label for the kind of entity affected
        ("profile", "rule", "pause_window", "preset", "task",
        "license"). Lands at
        `unmapped.iam_jit.admin_action.target.kind`.
    target_id
        Human-readable identifier of the affected entity (a profile
        name, a rule pattern + id, a pause id). Lands at
        `unmapped.iam_jit.admin_action.target.id`.
    target_extra
        Optional dict of per-target fields (profile source URL, rule
        effect, pause duration_seconds, ...). Token-leak keys are
        stripped before landing on the wire.
    before / after
        Optional state snapshots. SHA-256 hashes land at
        `unmapped.iam_jit.admin_action.before_hash` /
        `.after_hash`. The full snapshots NEVER land on the wire (a
        snapshot could be arbitrarily large and could contain
        secrets the caller hadn't thought to strip).
    source
        Where the action originated. Defaults to `cli`; the MCP tool
        passes `mcp`.
    extra
        Optional per-event context. Token-leak keys are stripped
        before landing on the wire.
    """
    activity_id = admin_action_activity_id(kind)
    severity_id, severity = admin_action_severity(kind)

    resolved_actor = (actor or "").strip() or resolve_operator()
    resolved_actor_uid = (actor_uid or "").strip() or resolved_actor

    if source not in _VALID_SOURCES:
        # Honest fallback for an unknown source string (defensive: an
        # MCP caller in the future could pass a typo). Better to land
        # the event with "unknown" than to drop it on the floor.
        source = ADMIN_ACTION_SOURCE_UNKNOWN

    activity_name = kind or "admin_action"
    type_uid = _TYPE_UID_BASE + activity_id
    type_name = f"{_CLASS_NAME}: {_ACTIVITY_NAME_BY_ID.get(activity_id, 'Other')}"

    admin_block: dict[str, Any] = {
        "kind": kind or "",
        "source": source,
        "actor": resolved_actor,
    }
    if target_kind or target_id or target_extra:
        target: dict[str, Any] = {}
        if target_kind:
            target["kind"] = target_kind
        if target_id:
            target["id"] = target_id
        if target_extra:
            target["extra"] = _strip_secret_keys(target_extra)
        admin_block["target"] = target
    before_hash = hash_state(before)
    after_hash = hash_state(after)
    if before_hash is not None:
        admin_block["before_hash"] = before_hash
    if after_hash is not None:
        admin_block["after_hash"] = after_hash
    if extra:
        admin_block["extra"] = _strip_secret_keys(extra)

    status_detail = _format_status_detail(
        kind=kind, actor=resolved_actor,
        target_kind=target_kind, target_id=target_id,
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
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": type_uid,
        "type_name": type_name,
        "severity_id": severity_id,
        "severity": severity,
        "status_id": 1,  # Success — the mutation has already landed
        "status": "Success",
        "status_detail": status_detail,
        "actor": {"user": {"name": resolved_actor, "uid": resolved_actor_uid}},
        "api": {
            "operation": activity_name,
            "service": {"name": f"ibounce.{(target_kind or 'admin')}"},
            "request": {"uid": target_id or ""},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_ADMIN_ACTION,
                "admin_action": admin_block,
                "ext": {},
            },
        },
    }


def _format_status_detail(
    *, kind: str, actor: str, target_kind: str, target_id: str,
) -> str:
    """Build a one-line human-readable summary for OCSF `status_detail`.

    Neutral language per [[security-team-positioning-safety-not-
    surveillance]]: "admin action X by Y on Z 'name'" — no
    "violation" / "unauthorized" / "infraction" framing.
    """
    actor_label = actor or DEFAULT_LOCAL_OPERATOR
    if target_kind and target_id:
        return (
            f"admin action {kind or 'admin_action'} on {target_kind} "
            f"{target_id!r} by {actor_label}"
        )
    if target_id:
        return (
            f"admin action {kind or 'admin_action'} on {target_id!r} "
            f"by {actor_label}"
        )
    return f"admin action {kind or 'admin_action'} by {actor_label}"


# ---------------------------------------------------------------------------
# Cross-process queue payload helpers
# ---------------------------------------------------------------------------

# CLI subcommands run in a SEPARATE process from `ibounce run`, so they
# can't push directly through the in-process audit channel. The
# existing pending_audit_events SQLite queue (used by the profile-
# install path) is the same emit channel — the serve process drains
# every ADMIN_ACTION row on its 1s tick and runs the payload through
# `make_admin_action_event` so the JSONL log + webhook + rule engine
# all see one canonical OCSF dict.
#
# The payload schema here is the wire contract between the CLI and the
# serve drainer. Bump it carefully; rolling-restart of long-lived
# deployments means a CLI of version N might enqueue payloads that a
# server of version N-1 has to drain.


def admin_action_payload(
    *,
    kind: str,
    actor: str | None = None,
    actor_uid: str | None = None,
    target_kind: str = "",
    target_id: str = "",
    target_extra: Mapping[str, Any] | None = None,
    before: Any = None,
    after: Any = None,
    source: str = ADMIN_ACTION_SOURCE_CLI,
    extra: Mapping[str, Any] | None = None,
) -> str:
    """Serialise an admin-action enqueue payload to JSON for the
    pending_audit_events queue. The drainer reverses this in
    `admin_action_event_from_payload`.

    Hashes for before/after are computed at enqueue time and stored in
    the payload — NOT the raw state — so the wire shape never carries
    a (potentially large, potentially secret-bearing) full snapshot
    even into the SQLite queue.
    """
    payload: dict[str, Any] = {
        "kind": kind,
        "actor": (actor or "").strip() or resolve_operator(),
        "actor_uid": (actor_uid or "").strip(),
        "target_kind": target_kind,
        "target_id": target_id,
        "source": source,
    }
    if target_extra:
        payload["target_extra"] = _strip_secret_keys(target_extra)
    bh = hash_state(before)
    ah = hash_state(after)
    if bh is not None:
        payload["before_hash"] = bh
    if ah is not None:
        payload["after_hash"] = ah
    if extra:
        payload["extra"] = _strip_secret_keys(extra)
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def admin_action_event_from_payload(payload_json: str) -> dict[str, Any]:
    """Reverse of `admin_action_payload`. Used by the serve process's
    pending_audit_events drainer to materialise the OCSF event from a
    queued row.

    Pre-computed hashes from the payload are stitched back into the
    admin_action block under the `before_hash` / `after_hash` keys; we
    do NOT re-derive them from the (absent) full state.
    """
    payload = json.loads(payload_json) if payload_json else {}
    kind = str(payload.get("kind") or "")
    actor = str(payload.get("actor") or "")
    actor_uid = str(payload.get("actor_uid") or "")
    target_kind = str(payload.get("target_kind") or "")
    target_id = str(payload.get("target_id") or "")
    source = str(payload.get("source") or ADMIN_ACTION_SOURCE_CLI)
    target_extra = payload.get("target_extra") or None
    extra = payload.get("extra") or None

    # Build the event without before/after so the builder doesn't
    # re-hash; then stitch the pre-computed hashes from the payload.
    evt = make_admin_action_event(
        kind=kind,
        actor=actor,
        actor_uid=actor_uid,
        target_kind=target_kind,
        target_id=target_id,
        target_extra=target_extra,
        before=None,
        after=None,
        source=source,
        extra=extra,
    )
    admin_block = evt["unmapped"]["iam_jit"]["admin_action"]
    if "before_hash" in payload:
        admin_block["before_hash"] = str(payload["before_hash"])
    if "after_hash" in payload:
        admin_block["after_hash"] = str(payload["after_hash"])
    return evt


# ---------------------------------------------------------------------------
# CLI-side enqueue helper
# ---------------------------------------------------------------------------


def enqueue_admin_action(
    store: Any,
    *,
    kind: str,
    actor: str | None = None,
    actor_uid: str | None = None,
    target_kind: str = "",
    target_id: str = "",
    target_extra: Mapping[str, Any] | None = None,
    before: Any = None,
    after: Any = None,
    source: str = ADMIN_ACTION_SOURCE_CLI,
    extra: Mapping[str, Any] | None = None,
) -> int | None:
    """Enqueue one admin-action row into the pending_audit_events
    queue. Best-effort: a store error is logged + swallowed so an
    admin-action emit failure NEVER fails the user-facing operation
    (the mutation has already landed; rolling it back for an audit-
    row failure would itself be an unaudited mutation).

    Returns the new row id on success, None on failure.
    """
    payload = admin_action_payload(
        kind=kind,
        actor=actor,
        actor_uid=actor_uid,
        target_kind=target_kind,
        target_id=target_id,
        target_extra=target_extra,
        before=before,
        after=after,
        source=source,
        extra=extra,
    )
    try:
        return store.enqueue_pending_audit_event(
            event_type=EVENT_TYPE_ADMIN_ACTION,
            payload_json=payload,
        )
    except Exception as e:
        logger.warning(
            "ibounce admin-action enqueue failed for kind=%s: %s",
            kind, e,
        )
        return None


# ---------------------------------------------------------------------------
# In-process direct emit (used by paths that ALREADY run inside the
# serve process — e.g. the MCP-tool-driven hot-swap that happens via
# `set_session_profile_override`).
# ---------------------------------------------------------------------------


def emit_admin_action_direct(
    emit: Any,
    *,
    kind: str,
    actor: str | None = None,
    actor_uid: str | None = None,
    target_kind: str = "",
    target_id: str = "",
    target_extra: Mapping[str, Any] | None = None,
    before: Any = None,
    after: Any = None,
    source: str = ADMIN_ACTION_SOURCE_MCP,
    extra: Mapping[str, Any] | None = None,
) -> None:
    """Push an admin-action event DIRECTLY through the in-process
    emit hook (the same closure the proxy hot-path uses for decision
    events). Used by MCP tools that mutate the gating surface from
    inside the serve process and don't need to round-trip through
    SQLite.

    `emit` may be None — the call is a no-op in that case so a
    deployment that hasn't configured the audit channel silently
    skips. Per the failure-soft posture of the audit channel,
    exceptions during emit are caught + logged.
    """
    if emit is None:
        return
    try:
        evt = make_admin_action_event(
            kind=kind,
            actor=actor,
            actor_uid=actor_uid,
            target_kind=target_kind,
            target_id=target_id,
            target_extra=target_extra,
            before=before,
            after=after,
            source=source,
            extra=extra,
        )
        emit(evt)
    except Exception as e:
        logger.warning(
            "ibounce admin-action direct emit failed for kind=%s: %s",
            kind, e,
        )


# Keep the heartbeat re-export reachable via `from .admin_action import
# *` so callers that already import via the alerts module don't have
# to reach further down the package tree. Not load-bearing for the
# admin-action feature itself.
_ = EVENT_TYPE_HEARTBEAT  # silence "imported but unused"


# Friendly module-level dt reference so a future builder needing UTC
# can grab it without re-importing. Not load-bearing.
_ = _dt


__all__ = [
    # OCSF constants
    "ACTIVITY_CREATE",
    "ACTIVITY_DELETE",
    "ACTIVITY_OTHER",
    "ACTIVITY_READ",
    "ACTIVITY_UNKNOWN",
    "ACTIVITY_UPDATE",
    "ADMIN_ACTION_ALERT_RULE_EDIT",
    "ADMIN_ACTION_BACKUP_CREATE",
    "ADMIN_ACTION_BACKUP_RESTORE",
    "ADMIN_ACTION_CONFIG_EXPORT",
    "ADMIN_ACTION_CONFIG_IMPORT",
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
    "DEFAULT_LOCAL_OPERATOR",
    "EVENT_TYPE_ADMIN_ACTION",
    "KNOWN_ADMIN_ACTION_KINDS",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_INFORMATIONAL",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    # Helpers
    "admin_action_activity_id",
    "admin_action_event_from_payload",
    "admin_action_payload",
    "admin_action_severity",
    "emit_admin_action_direct",
    "enqueue_admin_action",
    "hash_state",
    "make_admin_action_event",
    "resolve_operator",
]
