"""OCSF v1.1.0 class 6003 (API Activity) builder for audit-export.

Per [[ocsf-audit-schema]]: every audit-export event from ibounce
conforms to OCSF (Open Cybersecurity Schema Framework) v1.1.0 class
6003 "API Activity". This lets any consumer that already speaks OCSF
(AWS Security Lake, Splunk, Datadog, Cloudflare, IBM QRadar, ...)
ingest the JSONL log + webhook stream WITHOUT writing a custom
mapping layer.

Sibling Bounce products (kbounce, dbounce) emit the same OCSF shape
in parallel; the only fields that vary between products are:
  * `metadata.product.name`  ("ibounce" | "kbounce" | "dbounce")
  * `unmapped.iam_jit.ext`   (per-product extension dict)
  * `activity_id` mapping    (AWS verb prefix / K8s verb / SQL type)

Everything else — class_uid, category_uid, status_id semantics,
severity defaults, the `unmapped.iam_jit.{mode,profile,verdict,
decision_id,enforced}` block — is identical across products. The
cross-product fixture test (`test_event_matches_cross_product_shape`)
encodes that contract.

Why class 6003 (API Activity)? It's the closest OCSF class for
proxy decisions about service-API calls. AWS SDK requests, K8s API
requests, and SQL statements all fit. The alternative was 3005
(Authorize Session) but that's about session establishment, not
per-request auth.

Per [[ibounce-honest-positioning]] the status_id mapping is honest:
  * `ALLOW`                 -> 1 Success
  * `DENY` enforced=true    -> 2 Failure (the upstream call was blocked)
  * `DENY` enforced=false   -> 1 Success (cooperative-mode advisory;
                                 the upstream call DID succeed; we
                                 just flagged it); status_detail
                                 carries the deny reason
  * BYPASS (pause-active)   -> 1 Success with status_detail recording
                                 the pause-bypass

Per [[security-team-positioning-safety-not-surveillance]] severity
defaults to 1 Informational. Higher severities are reserved for
Slice 2 (anomaly_detected, prompt_burst_detected, ...) so a normal
decision never reads as "the proxy thinks something is wrong" in a
downstream SIEM.

Per [[scorer-is-ground-truth]]: the activity_id classifier reuses
the same policy_sentry source as `iam_jit.review._action_level`.
We do NOT keep an independent verb table — the scorer's view of
"is this a Read/Write/Tagging" is the one source of truth.

Per [[deliberate-feature-completion]]: this module is the ONLY
schema change in #255. The log writer / webhook pusher / CLI flags /
MCP status tool consume whatever dict shape this returns; they were
left untouched.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

# OCSF version this builder targets. Bump when (and only when) the
# OCSF spec itself moves; that's the schema_version downstream
# consumers branch on.
OCSF_SCHEMA_VERSION = "1.1.0"

# Shared product-level identity. `vendor_name` is "iam-jit" across
# all three Bounce products so a single SIEM dashboard scoped to
# `metadata.product.vendor_name == "iam-jit"` catches every event.
_PRODUCT_NAME = "ibounce"
_PRODUCT_VENDOR_NAME = "iam-jit"

# OCSF class 6003 = "API Activity" under category 6 "Application
# Activity". type_uid is the spec-defined class_uid * 100 + activity_id.
_CLASS_UID = 6003
_CLASS_NAME = "API Activity"
_CATEGORY_UID = 6
_CATEGORY_NAME = "Application Activity"
_TYPE_UID_BASE = 600300  # class_uid (6003) * 100

# Default severity for every audit-export event in Slice 1. Slice 2
# alerts (anomaly_detected etc.) override per the spec table.
_DEFAULT_SEVERITY_ID = 1
_DEFAULT_SEVERITY = "Informational"

# Back-compat re-export. Older callers (and our own external docs)
# referenced AUDIT_EVENT_SCHEMA_VERSION; keep the symbol so an import
# doesn't break, but point at the OCSF version since that IS the
# wire-format version now.
AUDIT_EVENT_SCHEMA_VERSION = OCSF_SCHEMA_VERSION

# ---------------------------------------------------------------------------
# OCSF activity_id mapping
# ---------------------------------------------------------------------------

# OCSF spec values for activity_id on class 6003. Documented at
# https://schema.ocsf.io/1.1.0/classes/api_activity
_ACTIVITY_UNKNOWN = 0
_ACTIVITY_CREATE = 1
_ACTIVITY_READ = 2
_ACTIVITY_UPDATE = 3
_ACTIVITY_DELETE = 4
_ACTIVITY_OTHER = 99

_ACTIVITY_NAME_BY_ID = {
    _ACTIVITY_UNKNOWN: "Unknown",
    _ACTIVITY_CREATE: "Create",
    _ACTIVITY_READ: "Read",
    _ACTIVITY_UPDATE: "Update",
    _ACTIVITY_DELETE: "Delete",
    _ACTIVITY_OTHER: "Other",
}

# Verb-prefix fallback used when policy_sentry returns no access
# level for an action (e.g. brand-new AWS APIs the local
# policy_sentry corpus hasn't picked up yet). Per [[ocsf-audit-schema]]
# memo, this is the documented fallback path.
#
# Order matters: longer prefixes first so e.g. `BatchGet*` resolves
# to Read before `Batch*` would resolve to Other. The tuples are
# evaluated in order; first hit wins.
_VERB_PREFIX_MAP: tuple[tuple[str, int], ...] = (
    # Read first — policy_sentry usually catches these, but the
    # fallback covers brand-new APIs not in the local corpus yet.
    ("BatchGet", _ACTIVITY_READ),
    ("Describe", _ACTIVITY_READ),
    ("Search", _ACTIVITY_READ),
    ("Query", _ACTIVITY_READ),
    ("Read", _ACTIVITY_READ),
    ("List", _ACTIVITY_READ),
    ("Get", _ACTIVITY_READ),
    ("Head", _ACTIVITY_READ),
    # Update before Create so `UpdateRole`/`Modify*` don't get caught
    # by the Create branch via a `Set*` collision.
    ("Update", _ACTIVITY_UPDATE),
    ("Modify", _ACTIVITY_UPDATE),
    ("Patch", _ACTIVITY_UPDATE),
    ("Attach", _ACTIVITY_UPDATE),
    ("Detach", _ACTIVITY_UPDATE),
    ("Set", _ACTIVITY_UPDATE),
    # Delete-ish.
    ("Delete", _ACTIVITY_DELETE),
    ("Remove", _ACTIVITY_DELETE),
    ("Terminate", _ACTIVITY_DELETE),
    ("Stop", _ACTIVITY_DELETE),
    ("Cancel", _ACTIVITY_DELETE),
    ("Disassociate", _ACTIVITY_DELETE),
    ("Revoke", _ACTIVITY_DELETE),
    # Create-ish (after Update to avoid `Update*` matching `Run*`).
    ("Create", _ACTIVITY_CREATE),
    ("Put", _ACTIVITY_CREATE),
    ("Add", _ACTIVITY_CREATE),
    ("Allocate", _ACTIVITY_CREATE),
    ("Register", _ACTIVITY_CREATE),
    ("Run", _ACTIVITY_CREATE),
)

# Mapping from the policy_sentry access-level vocabulary to OCSF
# activity_id. policy_sentry's vocabulary is well-defined (it's the
# AWS IAM access-level taxonomy from the AWS docs), so this table
# is exhaustive.
_POLICY_SENTRY_LEVEL_TO_ACTIVITY = {
    "Read": _ACTIVITY_READ,
    "List": _ACTIVITY_READ,
    # Per [[ocsf-audit-schema]] memo: Tagging maps to Update directly
    # (tag mutations are state changes that aren't CRUD-shaped).
    "Tagging": _ACTIVITY_UPDATE,
    # Write + "Permissions management" are intentionally absent from
    # this table: they're not 1:1 to CRUD (Write covers create/update/
    # delete; Permissions management covers Put/Attach/Detach/Delete).
    # We fall through to the verb-prefix fallback so the CRUD shape
    # comes from the action name itself — keeps `PutRolePolicy` as
    # Create-1 not Update-3 etc., matching the memo's spec table.
}


def _classify_activity(service: str, action: str) -> int:
    """Return the OCSF activity_id for an AWS (service, action) pair.

    Resolution order per [[ocsf-audit-schema]]:
      1. policy_sentry access-level lookup via
         `iam_jit.review._action_level` (the same source the scorer
         uses — [[scorer-is-ground-truth]]).
         Read/List           -> 2 Read
         Tagging             -> 3 Update
         Permissions mgmt    -> 3 Update
         Write               -> fall through (need CRUD-shape; verb
                                 prefix is the right tool)
      2. Verb-prefix heuristic (`_VERB_PREFIX_MAP`).
      3. 99 Other.

    Empty / synthetic events (unclassifiable-deny, profile-deny on a
    request that didn't parse) get 99 Other.
    """
    if not action:
        return _ACTIVITY_OTHER
    # 1. policy_sentry first. Lazy-import so the audit_export package
    # doesn't pull review.py at import time (review pulls policy_sentry,
    # which is heavier than we want to load just to format an event).
    if service:
        try:
            from ...review import _action_level
            level = _action_level(f"{service.lower()}:{action}")
        except Exception:
            level = None
        if level is not None:
            mapped = _POLICY_SENTRY_LEVEL_TO_ACTIVITY.get(level)
            if mapped is not None:
                return mapped
            # level == "Write" falls through to verb-prefix so the
            # CRUD subdivision survives.
    # 2. Verb-prefix fallback.
    for prefix, aid in _VERB_PREFIX_MAP:
        if action.startswith(prefix):
            return aid
    # 3. Unknown -> Other (NOT Unknown-0; OCSF reserves 0 for the
    # "we explicitly don't know" case which is genuinely rare for
    # us — we always know it's SOMETHING the proxy saw).
    return _ACTIVITY_OTHER


# ---------------------------------------------------------------------------
# OCSF status_id mapping
# ---------------------------------------------------------------------------

# OCSF status_id values for class 6003.
_STATUS_UNKNOWN = 0
_STATUS_SUCCESS = 1
_STATUS_FAILURE = 2
_STATUS_OTHER = 99

_STATUS_NAME_BY_ID = {
    _STATUS_UNKNOWN: "Unknown",
    _STATUS_SUCCESS: "Success",
    _STATUS_FAILURE: "Failure",
    _STATUS_OTHER: "Other",
}


def _map_verdict_to_status(
    verdict: str, *, enforced: bool, pause_active: bool,
) -> tuple[int, str, str | None]:
    """Map an iam-jit verdict to (status_id, status, status_detail).

    Per [[ocsf-audit-schema]] verdict-mapping table:

      ALLOW                     -> 1 Success (no detail beyond reason)
      DENY  enforced=True       -> 2 Failure (the call was blocked;
                                     this is what SIEM dashboards
                                     want to alert on)
      DENY  enforced=False      -> 1 Success with detail (cooperative-
                                     mode advisory; the upstream call
                                     succeeded; the bouncer flagged
                                     but did not block)
      BYPASS (pause-active)     -> 1 Success with detail recording
                                     the pause window
      anything else (PROMPT,
       unclassifiable, etc.)    -> 99 Other with detail

    Returns the tuple; the caller stitches the chosen status_detail
    into the event below (the deny `reason` is added separately so
    the OCSF event always carries the human-readable reason).
    """
    v = (verdict or "").strip().lower()
    if pause_active:
        # Pause demoted enforcement to advisory; the call DID succeed
        # upstream regardless of what the rule engine returned. We
        # honour that in status_id; status_detail records the bypass.
        return _STATUS_SUCCESS, _STATUS_NAME_BY_ID[_STATUS_SUCCESS], (
            "pause-bypass: enforcement suspended; decision recorded "
            "for audit reconciliation"
        )
    if v == "allow":
        return _STATUS_SUCCESS, _STATUS_NAME_BY_ID[_STATUS_SUCCESS], None
    if v == "deny":
        if enforced:
            return (
                _STATUS_FAILURE,
                _STATUS_NAME_BY_ID[_STATUS_FAILURE],
                None,
            )
        # Cooperative-mode advisory deny. The upstream call SUCCEEDED;
        # we just flagged it. Honest OCSF mapping records this as
        # Success-with-detail so SIEM "Failure" dashboards stay
        # accurate.
        return (
            _STATUS_SUCCESS,
            _STATUS_NAME_BY_ID[_STATUS_SUCCESS],
            "advisory-deny: cooperative mode flagged this call but did "
            "not block",
        )
    # PROMPT verdict (sync deny-prompt v1.1; #203) or anything we
    # don't recognise — emit as Other so the SIEM doesn't silently
    # bucket it as Success. status_detail names the verdict so a
    # human can trace.
    return (
        _STATUS_OTHER,
        _STATUS_NAME_BY_ID[_STATUS_OTHER],
        f"non-binary verdict: {verdict!r}",
    )


# ---------------------------------------------------------------------------
# ARN -> OCSF resource extraction
# ---------------------------------------------------------------------------


def _resource_from_arn(arn: str | None, service: str | None) -> list[dict[str, Any]]:
    """Extract an OCSF `resources` entry from an AWS ARN, if present.

    Returns a single-element list (one resource per request is the
    common case for AWS SDK calls) or an empty list when there's no
    ARN to attribute the call to (e.g. `ListBuckets`, which targets
    the account-level service, not a specific resource).

    We do not try to enrich beyond what the ARN tells us:
      * `name` is the relative resource portion (after the last `/` or
        `:`) which is what a human dashboard wants to see at a glance.
      * `uid` is the full ARN (the canonical unique-id).
      * `type` is `"<service> resource"` so a SIEM can filter by service.

    Per [[ocsf-audit-schema]]: prefer to emit an empty array over
    inventing names. SIEM dashboards that filter on resources.uid for
    correlation are better served by "no resource recorded" than by
    a synthesised string that doesn't match real ARNs.
    """
    if not arn:
        return []
    # AWS ARN structure: arn:partition:service:region:account-id:resource
    # The resource portion can contain colons (e.g. CloudWatch Logs)
    # or slashes (e.g. IAM); split on the 6th colon and keep the tail.
    parts = arn.split(":", 5)
    if len(parts) < 6:
        # Not a well-formed AWS ARN; record the raw value as both uid
        # and name so downstream tools at least have the original
        # string to grep on. Type falls back to whatever service the
        # caller supplied.
        return [{
            "name": arn,
            "uid": arn,
            "type": f"{service} resource" if service else "aws resource",
        }]
    arn_service = parts[2] or (service or "")
    resource_part = parts[5]
    # Common shapes: "type/name", "type:name", or just "name".
    name = resource_part
    for sep in ("/", ":"):
        if sep in resource_part:
            name = resource_part.rsplit(sep, 1)[-1]
            break
    return [{
        "name": name or resource_part,
        "uid": arn,
        "type": f"{arn_service} resource" if arn_service else "aws resource",
    }]


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def _product_version() -> str:
    """Read the bouncer's wire version from mcp_server lazily so this
    module doesn't pull the (heavy) mcp_server import path just to
    build an event. Fail-soft to "0.0.0" so a misconfigured import
    never crashes the audit channel."""
    try:
        from ... import mcp_server as _mcp
        return getattr(_mcp, "SERVER_VERSION", "0.0.0")
    except Exception:
        return "0.0.0"


def _now_unix_ms() -> int:
    """Wall-clock time in Unix milliseconds — the canonical OCSF
    `time` representation. We round down to ms; sub-ms precision is
    not part of the OCSF spec and varies across the JSON serialisers
    SIEM vendors use, so we don't try to preserve it."""
    return int(_dt.datetime.now(_dt.UTC).timestamp() * 1000)


def _principal_to_actor_user(
    principal: str | None,
) -> dict[str, str]:
    """Map a principal string to OCSF `actor.user.{name, uid}`.

    The principal we have at the proxy layer is best-effort (an email
    address, a "user/alice", or just "alice@example.com"). We don't
    try to resolve it against IAM — the proxy doesn't have the IAM
    read permission, and per [[recommender-context-boundary]] we
    don't reach out to do enrichment. Both `name` and `uid` get the
    same value when that's all we have; downstream tools that
    correlate against a directory can fan out from `name` themselves.
    """
    if not principal:
        return {"name": "", "uid": ""}
    return {"name": principal, "uid": principal}


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


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
    # Optional OCSF-shape fields. Call sites that don't know these
    # yet (which is all of Slice 1's plumbing) leave them None and we
    # omit them from the event. Slice 2's forwarding layer will start
    # passing src/dst endpoint info.
    src_ip: str | None = None,
    src_port: int | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    sigv4_credential_kid: str | None = None,
    extra: dict[str, Any] | None = None,
    # #266 — agent identity inputs. Defaults preserve the pre-#266
    # behaviour for callers (and tests) that don't supply any
    # agent-identity context — no agent block lands on the event in
    # that case. Per [[agent-identity-in-audit]] the resolver inside
    # agent_context handles the priority chain
    # (header > mcp_clientinfo > user_agent > process_tree).
    user_agent: str | None = None,
    peer_pid: int | None = None,
    include_process_tree: bool = True,
    # #318 / §A16 — explicit X-Agent-* headers, pre-validated by the
    # caller via agent_context.extract_agent_headers. Highest-precedence
    # detection source: when an agent declares itself via header, that
    # always wins over heuristic detection. Mirrors gbounce's pattern so
    # cross-bouncer queries on `unmapped.iam_jit.agent.session_id`
    # resolve across all four products.
    header_agent_name: str | None = None,
    header_agent_session_id: str | None = None,
    # #320 / §A18 — structured rejection breadcrumb list. Each entry
    # has {field, reason, value_redacted_length}. Lands at
    # `unmapped.iam_jit.ext.agent_header_rejection` (single dict when
    # one header failed, list when both failed). NEVER includes the
    # raw value — only its length, for safe forensics per
    # [[security-team-positioning-safety-not-surveillance]]. Caller
    # populates via agent_context.extract_agent_headers_with_rejections.
    agent_header_rejections: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the OCSF v1.1.0 class 6003 event for one proxy decision.

    Returns a dict whose JSON serialisation is a valid OCSF API
    Activity event (verified by `tests/bouncer/test_audit_export_log.py
    ::test_event_validates_against_ocsf_schema`). Both the JSONL log
    writer + the HTTPS webhook pusher consume this directly.

    Optional fields (`src_ip`, `sigv4_credential_kid`, ...) are
    omitted from the output when None so the resulting JSON stays
    tight; the validation test treats them as truly optional.

    Per [[deliberate-feature-completion]] this is the SINGLE place
    OCSF events are constructed. If a new piece of decision context
    needs to surface in the audit stream, add the parameter here
    rather than building the dict at the call site.
    """
    activity_id = _classify_activity(service, action)
    pause_active = active_pause_id is not None
    status_id, status, status_detail = _map_verdict_to_status(
        verdict, enforced=enforced, pause_active=pause_active,
    )
    # The deny `reason` is what humans actually want to read; prepend
    # it so a SIEM cell that shows `status_detail` shows the WHY.
    if reason:
        if status_detail:
            status_detail = f"{reason}; {status_detail}"
        else:
            status_detail = reason

    activity_name = action or _ACTIVITY_NAME_BY_ID[activity_id].lower()
    type_uid = _TYPE_UID_BASE + activity_id
    type_name = f"{_CLASS_NAME}: {_ACTIVITY_NAME_BY_ID[activity_id]}"

    api_operation = (
        f"{service}:{action}" if service and action else action or service or ""
    )

    # `unmapped.iam_jit.ext` carries product-specific fields that
    # don't have OCSF homes. Keep it small per the memo's "don't make
    # unmapped huge" guidance — these are the fields a kbounce/dbounce
    # event would never have (AWS region, SigV4 kid).
    ext: dict[str, Any] = {}
    if region:
        ext["aws_region"] = region
    if sigv4_credential_kid:
        ext["sigv4_credential_kid"] = sigv4_credential_kid
    # Caller-provided extras get merged in. These are the fields the
    # legacy schema kept under `ext` (matched_rule_id, active_task_id,
    # decision_source). They stay there for downstream consumers that
    # already grep on them, but they live under unmapped.iam_jit.ext
    # in OCSF terms.
    if extra:
        ext.update(extra)
    # Machine-readable pause linkage in the EXPORTED event (not just the SQLite
    # decisions.pause_id column). Without this a SIEM ingesting the JSONL could
    # only infer a pause from the status_detail text — it could not correlate
    # decisions to a specific pause window by id. (NUC-F UAT finding.)
    if active_pause_id is not None:
        ext["pause_id"] = active_pause_id

    # #320 / §A18: structured rejection breadcrumb. Single dict shape
    # when one header failed; list shape when both failed. Cross-
    # product invariant per [[cross-product-agent-parity]].
    if agent_header_rejections:
        if len(agent_header_rejections) == 1:
            ext["agent_header_rejection"] = agent_header_rejections[0]
        else:
            ext["agent_header_rejection"] = list(agent_header_rejections)

    # src_endpoint / dst_endpoint. We emit them only when we have at
    # least one populated field — an all-None endpoint is worse than
    # omitting it (SIEMs that index on `dst_endpoint.ip` see empty
    # buckets otherwise).
    src_endpoint: dict[str, Any] = {}
    if src_ip:
        src_endpoint["ip"] = src_ip
    if src_port:
        src_endpoint["port"] = src_port
    dst_endpoint: dict[str, Any] = {}
    # `host` (the upstream service host like "s3.us-east-1.amazonaws.com")
    # is always populated by the call sites; it goes in dst_endpoint
    # because the proxy considers AWS the destination of the request.
    if host:
        dst_endpoint["hostname"] = host
    if upstream and upstream != host:
        # If the proxy resolved a different host upstream (e.g. a
        # SigV4-rewrite case) record that too; otherwise omit to keep
        # the event small.
        dst_endpoint["hostname"] = upstream
    if dst_ip:
        dst_endpoint["ip"] = dst_ip
    if dst_port:
        dst_endpoint["port"] = dst_port

    actor: dict[str, Any] = {"user": _principal_to_actor_user(principal)}
    if request_id:
        # OCSF actor.session.uid is the place for an opaque session
        # identifier. We use the proxy's request_id (or the upstream
        # task_id when one is present) so a SIEM can collate every
        # event from one logical session.
        actor["session"] = {"uid": request_id}

    # #266 — agent identity block. Fail-soft so an agent_context
    # detection bug never breaks the audit channel. #318 / §A16 —
    # explicit X-Agent-* headers feed the resolver at highest
    # precedence so cross-bouncer correlation works.
    agent_block: dict[str, Any] | None = None
    try:
        from .agent_context import resolve_agent_block
        agent_block = resolve_agent_block(
            user_agent=user_agent,
            peer_pid=peer_pid,
            include_process_tree=include_process_tree,
            header_agent_name=header_agent_name,
            header_agent_session_id=header_agent_session_id,
        )
    except Exception:
        agent_block = None

    iam_jit_block: dict[str, Any] = {
        "mode": mode,
        "profile": profile,
        "verdict": verdict,
        "decision_id": decision_id,
        "enforced": bool(enforced),
        "ext": ext,
    }
    if agent_block is not None:
        iam_jit_block["agent"] = agent_block

    event: dict[str, Any] = {
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
        "severity_id": _DEFAULT_SEVERITY_ID,
        "severity": _DEFAULT_SEVERITY,
        "status_id": status_id,
        "status": status,
        "status_detail": status_detail or "",
        "actor": actor,
        "api": {
            "operation": api_operation,
            "service": {"name": service or ""},
            "request": {"uid": str(decision_id)},
        },
        "resources": _resource_from_arn(arn, service),
        "src_endpoint": src_endpoint,
        "dst_endpoint": dst_endpoint,
        "unmapped": {
            "iam_jit": iam_jit_block,
        },
    }
    return event


def audit_dropped_event(
    *,
    dropped_count: int,
    reason: str,
    queue_size: int | None = None,
) -> dict[str, Any]:
    """OCSF-shaped synthetic event emitted when the webhook pusher's
    bounded queue overflows.

    Per [[ocsf-audit-schema]]:
      * `activity_id = 99` (Other) — there's no CRUD verb for "we
        dropped some events," so Other is the honest mapping.
      * `severity_id = 3` (Medium) — data loss in the audit channel is
        worth waking a security team for, but it's not Critical (the
        proxy is still operating, just the export channel fell behind).
      * `status_id = 99` (Other) — the synthetic event isn't a
        Success/Failure of an upstream API call; it's a meta-event
        about the audit channel itself.

    `unmapped.iam_jit.event_type = "AUDIT_DROPPED"` lets downstream
    tools filter for these synthetics with a single field test
    (matches the legacy schema's `event_type == "AUDIT_DROPPED"`
    selector so existing alert rules still fire).
    """
    ext: dict[str, Any] = {"reason": reason}
    if queue_size is not None:
        ext["queue_size"] = queue_size

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
        "activity_id": _ACTIVITY_OTHER,
        "activity_name": "audit_dropped",
        "type_uid": _TYPE_UID_BASE + _ACTIVITY_OTHER,
        "type_name": f"{_CLASS_NAME}: {_ACTIVITY_NAME_BY_ID[_ACTIVITY_OTHER]}",
        "severity_id": 3,
        "severity": "Medium",
        "status_id": _STATUS_OTHER,
        "status": _STATUS_NAME_BY_ID[_STATUS_OTHER],
        "status_detail": (
            f"audit-export webhook dropped {dropped_count} event(s) due to "
            f"backpressure ({reason})"
        ),
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
                "dropped_count": dropped_count,
                "ext": ext,
            },
        },
    }
