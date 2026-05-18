"""Suspicious-activity rule engine — Slice 2 of #262.

Per [[security-team-audit-export]] Slice 2: the audit-export transport
gains a deterministic rule engine that observes the decision-event
stream + fires synthetic OCSF `anomaly_detected` events through the
SAME two channels (JSONL log + HTTPS webhook). Sibling agents land
parallel implementations on kbounce + dbounce; the cross-product
contract is one alert event-shape, one OCSF class, four built-in
patterns whose threshold defaults match.

Per [[scorer-is-ground-truth]]: every rule is DETERMINISTIC. No LLM
in Slice 2 (LLM-augmented patterns are explicitly post-launch). The
rules consume event dicts + bounded sliding-window state and return
a boolean fire/no-fire — same evaluation model as the bouncer's
decision rules.

Per [[security-team-positioning-safety-not-surveillance]]: every
user-facing string in this module uses NEUTRAL language. We say
"pattern fired" / "scope mismatch" / "consider distributing a broader
profile" — never "violation" / "infraction" / "unauthorized." A
security-team operator looking at a fired alert should read it as
"this needs a closer look," not "this person did something wrong."
The neutral-language scan test in `test_audit_export_alerts.py`
greps every alert string for the forbidden words.

Per [[enterprise-self-host-only]]: alerts ride the same Enterprise-
tier gate as the webhook. The license check fires at CLI parse time
AND at serve() start (defense in depth, same posture as the existing
webhook gate).

Per [[ocsf-audit-schema]]: anomaly events use OCSF class 6003 with
activity_id=99 (Other), activity_name="anomaly_detected", and a
severity_id that varies per rule (3 Medium for the routine patterns,
4 High for unusual high-risk action denies). The product-specific
fields ride under `unmapped.iam_jit.{event_type, pattern,
window_seconds, matched_event_count, suggestion}`.

Per [[deliberate-feature-completion]]: this module is the ONLY
schema change in #262. The transport, the webhook presets, the JSONL
log writer + the proxy decision path consume the alert event as just
another OCSF dict; no Slice 1 surface needs to know about the rule
engine.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from .event import (
    OCSF_SCHEMA_VERSION,
    _now_unix_ms,
    _product_version,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OCSF / cross-product constants
# ---------------------------------------------------------------------------

# Activity id 99 = Other (no CRUD verb maps to "we detected a
# pattern in our own audit stream"). Matches the AUDIT_DROPPED
# synthetic in event.py — same "meta-event about iam-jit itself"
# bucket.
_ANOMALY_ACTIVITY_ID = 99
_ANOMALY_ACTIVITY_NAME = "anomaly_detected"
_CLASS_UID = 6003
_CLASS_NAME = "API Activity"
_CATEGORY_UID = 6
_CATEGORY_NAME = "Application Activity"
_TYPE_UID = 600300 + _ANOMALY_ACTIVITY_ID  # 600399

# OCSF status_id = 99 (Other) — anomaly synthetics are not a
# success/failure of an upstream call. Matches the AUDIT_DROPPED
# convention.
_STATUS_OTHER_ID = 99
_STATUS_OTHER_NAME = "Other"

# Severity names per OCSF spec.
_SEVERITY_NAME_BY_ID = {
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}

# Product identity. Mirrors event.py exactly so a SIEM dashboard
# scoped to `metadata.product.name == "ibounce"` catches alerts too.
_PRODUCT_NAME = "ibounce"
_PRODUCT_VENDOR_NAME = "iam-jit"

# Event-type markers the rule engine recognises on incoming events.
# Each marker lives at unmapped.iam_jit.event_type. The Slice 1
# decision builder doesn't set this field (decision events identify
# themselves via verdict + class shape); these strings are the
# vocabulary the operator-side emitters (grant pipeline, pause
# tracker, profile installer) use when they push synthetic events
# through the SAME audit-export channel so the rule engine sees them.
EVENT_TYPE_ADMIN_FALLBACK_GRANT = "ADMIN_FALLBACK_GRANT"
EVENT_TYPE_PAUSE_END = "PAUSE_END"
EVENT_TYPE_PROFILE_INSTALL = "PROFILE_INSTALL"
EVENT_TYPE_ANOMALY_DETECTED = "ANOMALY_DETECTED"
# #264 — heartbeat event-type marker. The HeartbeatEmitter in
# heartbeat.py sets this on every tick; the heartbeat_gap rule
# below watches for the ABSENCE of these (per-rule tick scan, not
# per-event).
EVENT_TYPE_HEARTBEAT = "HEARTBEAT"


# ---------------------------------------------------------------------------
# Built-in rule defaults
# ---------------------------------------------------------------------------

# admin-fallback-burst defaults: >3 admin-fallback grants in a
# rolling 5-minute window. Threshold lives at the rule level so the
# YAML config can raise it for high-volume environments without
# touching code.
DEFAULT_ADMIN_FALLBACK_THRESHOLD = 3
DEFAULT_ADMIN_FALLBACK_WINDOW_SECONDS = 5 * 60  # 5 minutes

# long-pause defaults: a single pause window >30min. Pause length
# arrives on the PAUSE_END event (the pause tracker computes the
# actual duration when the window closes); we don't try to detect
# "pause is currently long" from a sliding window because that would
# fire repeatedly on a still-open pause.
DEFAULT_PAUSE_LONG_THRESHOLD_SECONDS = 30 * 60  # 30 minutes

# non-org-profile-install defaults: an empty allowlist means "alert
# on every profile install from a URL." Operators populate the YAML
# allowlist with their org's curated profile URLs.
DEFAULT_PROFILE_INSTALL_ALLOWLIST: tuple[str, ...] = ()

# heartbeat_gap defaults: alert after 2 consecutive missing heartbeats.
# Re-exported from heartbeat.py so config + CLI consumers have a
# single import path (this module is the public alerts surface).
from .heartbeat import (  # noqa: E402  — intentional mid-file import
    DEFAULT_HEARTBEAT_MISSING_COUNT,
    heartbeat_status as _heartbeat_status,
    mark_gap_detected as _mark_heartbeat_gap_detected,
    write_heartbeat_gap_stderr as _write_heartbeat_gap_stderr,
)


# unusual-high-risk-action defaults: the watchlist of action patterns
# that are sensitive enough to alert on every transparent-mode deny.
# Conservative starter set; operators extend via YAML.
#
# Format: `service:Action` glob with `*` permitted. Case-INSENSITIVE
# match on both service + action (AWS API verbs are PascalCase but
# operators almost always type lowercase service names in YAML).
#
# Per [[security-team-positioning-safety-not-surveillance]]: the
# watchlist focuses on actions that, if a write actually occurred,
# would have wide blast radius. A deny on these is a useful "here's
# something the agent tried that you should look at" signal even in
# benign sessions — not a "the agent did something bad" assertion.
DEFAULT_HIGH_RISK_ACTIONS: tuple[str, ...] = (
    # IAM creation primitives — full take-over surface.
    "iam:Create*",
    "iam:Put*",
    "iam:Attach*",
    "iam:Update*",
    "iam:Delete*",
    # Secrets / KMS reads — pre-exfiltration shape.
    "secretsmanager:GetSecretValue",
    "secretsmanager:ListSecrets",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    # Audit-infra destruction — visibility-blinding shape.
    "cloudtrail:Stop*",
    "cloudtrail:Delete*",
    "config:Delete*",
    "config:Stop*",
    "guardduty:Delete*",
    "guardduty:Disable*",
)


# ---------------------------------------------------------------------------
# Configuration shapes
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class AlertsConfig:
    """Parsed --alert-rules YAML. Frozen so a misbehaving rule can't
    mutate the operator's intent at runtime.

    `enabled_rules` is the set of built-in rule names the operator
    has opted into. `None` means "all four built-ins enabled" (the
    default when no YAML is supplied). An explicit empty set means
    "disable all built-ins" (legitimate when the operator wants the
    license gate + transport on but no actual patterns firing yet).
    """

    enabled_rules: frozenset[str] | None = None
    admin_fallback_threshold: int = DEFAULT_ADMIN_FALLBACK_THRESHOLD
    admin_fallback_window_seconds: int = DEFAULT_ADMIN_FALLBACK_WINDOW_SECONDS
    pause_long_threshold_seconds: int = DEFAULT_PAUSE_LONG_THRESHOLD_SECONDS
    profile_install_allowlist: tuple[str, ...] = DEFAULT_PROFILE_INSTALL_ALLOWLIST
    high_risk_actions: tuple[str, ...] = DEFAULT_HIGH_RISK_ACTIONS
    # #264 — heartbeat_gap rule: fire after this many consecutive
    # missed heartbeats. Default 2 catches one missed beat + the
    # detection scan that follows. Operators raise this for noisy
    # network paths where the occasional missed beat is normal.
    heartbeat_missing_count: int = DEFAULT_HEARTBEAT_MISSING_COUNT

    @classmethod
    def default(cls) -> "AlertsConfig":
        """Built-in defaults: all five rules enabled (admin_fallback_burst,
        pause_long, non_org_profile_install, unusual_high_risk_action,
        heartbeat_gap), conservative thresholds. This is what the engine
        uses when --alert-rules is absent (per spec)."""
        return cls(enabled_rules=None)


class AlertsLicenseError(Exception):
    """Raised when --alert-rules is passed without an Enterprise
    license file. Surfaced at CLI parse time so the operator gets a
    clear "this feature requires Enterprise" message + a pointer to
    docs/LICENSE.md, not a silent no-op.

    Mirrors the WebhookLicenseError shape so the CLI's error-handling
    branch can treat them uniformly.
    """


def gate_alerts_license(license_obj: Any) -> None:
    """Refuse if the operator passed --alert-rules without an active
    Enterprise license. Same load-license-via-iam_jit.license path
    the webhook gate uses (per [[enterprise-self-host-only]]).

    Raises `AlertsLicenseError` on a refusal; returns None on success.
    Defense in depth: the CLI fires this at parse time AND serve()
    fires it again at start so a license file that disappeared
    between parse + start doesn't quietly grant alert capability.
    """
    from ... import license as license_mod

    if license_obj is None:
        try:
            license_obj = license_mod.load_license()
        except license_mod.LicenseInvalidError as e:
            raise AlertsLicenseError(
                f"audit-export alerts require a valid Enterprise license. "
                f"The license file at the configured path failed "
                f"verification: {e}. See docs/LICENSE.md."
            ) from e
    if license_obj is None or license_obj.tier != "enterprise":
        tier = license_obj.tier if license_obj is not None else "free"
        raise AlertsLicenseError(
            f"audit-export alerts require an Enterprise license; current "
            f"tier is {tier!r}. The JSONL log channel (--audit-log-path) "
            f"and the deterministic decision events are available on all "
            f"tiers. See docs/LICENSE.md to obtain an Enterprise license."
        )


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


def load_alerts_config(path: str) -> AlertsConfig:
    """Parse the --alert-rules YAML file into an `AlertsConfig`.

    Expected schema (all top-level keys optional)::

        # built-in rule enable/disable. Default = all enabled.
        # An explicit empty list disables every built-in (the
        # license-gated transport + custom-rule hook still load).
        enabled_rules:
          - admin_fallback_burst
          - pause_long
          - non_org_profile_install
          - unusual_high_risk_action

        # per-rule threshold overrides (all optional).
        admin_fallback_threshold: 3
        admin_fallback_window_seconds: 300
        pause_long_threshold_seconds: 1800

        # org-approved profile-install allowlist. Profile installs
        # from URLs NOT on this list fire the non_org_profile_install
        # rule. Empty list (the default) = every install fires.
        profile_install_allowlist:
          - https://profiles.example.com/dev.yaml
          - https://profiles.example.com/prod-readonly.yaml

        # custom high-risk action watchlist. Format `service:Action`
        # with `*` glob permitted; case-insensitive.
        high_risk_actions:
          - iam:Create*
          - kms:Decrypt
          - secretsmanager:GetSecretValue

        # custom rule definitions (parsed but NOT instantiated in
        # Slice 2; future-proof key only). The loader records the
        # presence + warns so the operator knows the slot exists
        # but isn't wired yet.
        custom_rules: []

    Any unknown top-level key gets a warning + is dropped (per
    fail-soft posture; a YAML typo shouldn't refuse to start the
    proxy).
    """
    from ruamel.yaml import YAML

    yaml = YAML(typ="safe", pure=True)
    with open(path, encoding="utf-8") as f:
        raw = yaml.load(f) or {}
    if not isinstance(raw, dict):
        raise ValueError(
            f"alert-rules YAML at {path!r} must be a mapping at the top "
            f"level; got {type(raw).__name__}"
        )

    enabled_raw = raw.get("enabled_rules")
    enabled: frozenset[str] | None
    if enabled_raw is None:
        enabled = None  # absent = default = all built-ins
    elif isinstance(enabled_raw, list):
        # Empty list is a meaningful "disable all" signal — keep it
        # frozen-empty rather than falling through to None.
        enabled = frozenset(str(x) for x in enabled_raw)
    else:
        raise ValueError(
            f"enabled_rules must be a list (or absent for default); "
            f"got {type(enabled_raw).__name__}"
        )

    allowlist_raw = raw.get("profile_install_allowlist", [])
    if not isinstance(allowlist_raw, list):
        raise ValueError(
            f"profile_install_allowlist must be a list; "
            f"got {type(allowlist_raw).__name__}"
        )

    high_risk_raw = raw.get("high_risk_actions")
    if high_risk_raw is None:
        high_risk = DEFAULT_HIGH_RISK_ACTIONS
    elif isinstance(high_risk_raw, list):
        high_risk = tuple(str(x) for x in high_risk_raw)
    else:
        raise ValueError(
            f"high_risk_actions must be a list; got {type(high_risk_raw).__name__}"
        )

    # Warn for future-proof keys the operator put in but Slice 2
    # doesn't act on yet, so a typo doesn't silently disable a real
    # config they thought they wrote.
    known_keys = {
        "enabled_rules",
        "admin_fallback_threshold",
        "admin_fallback_window_seconds",
        "pause_long_threshold_seconds",
        "profile_install_allowlist",
        "high_risk_actions",
        # #264 — heartbeat_gap rule threshold.
        "heartbeat_missing_count",
        "custom_rules",
    }
    for k in raw:
        if k not in known_keys:
            logger.warning(
                "alert-rules YAML at %s: unknown key %r ignored; "
                "known keys are %s",
                path, k, sorted(known_keys),
            )
    if raw.get("custom_rules"):
        logger.warning(
            "alert-rules YAML at %s: 'custom_rules' parsed but "
            "Slice 2 ships built-in rules only; custom rule "
            "definitions will become active in a later slice.",
            path,
        )

    return AlertsConfig(
        enabled_rules=enabled,
        admin_fallback_threshold=int(
            raw.get("admin_fallback_threshold", DEFAULT_ADMIN_FALLBACK_THRESHOLD)
        ),
        admin_fallback_window_seconds=int(
            raw.get(
                "admin_fallback_window_seconds",
                DEFAULT_ADMIN_FALLBACK_WINDOW_SECONDS,
            )
        ),
        pause_long_threshold_seconds=int(
            raw.get(
                "pause_long_threshold_seconds",
                DEFAULT_PAUSE_LONG_THRESHOLD_SECONDS,
            )
        ),
        profile_install_allowlist=tuple(str(x) for x in allowlist_raw),
        high_risk_actions=high_risk,
        heartbeat_missing_count=int(
            raw.get(
                "heartbeat_missing_count",
                DEFAULT_HEARTBEAT_MISSING_COUNT,
            )
        ),
    )


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class AlertRule:
    """A single rule the engine evaluates on every incoming event.

    `pattern` is a callable that takes (event, window_state, config)
    and returns either None (no fire) or a dict carrying
    `{matched_event_count, window_seconds, suggestion, status_detail}`
    which the engine then folds into the OCSF anomaly event.

    `name` is the canonical identifier used both in YAML
    `enabled_rules` and in `unmapped.iam_jit.pattern` on the emitted
    alert — operators grep on this string in their SIEM.

    `severity` is the OCSF severity_id (1..5); spec table:
      - admin_fallback_burst        → 3 Medium
      - pause_long                  → 3 Medium
      - non_org_profile_install     → 3 Medium
      - unusual_high_risk_action    → 4 High
    """

    name: str
    pattern: Callable[[dict, deque, AlertsConfig], dict | None]
    severity: int
    description: str


# Each rule reads from + appends to its own bounded deque of
# (timestamp_seconds, event) tuples. Bounded by:
#   1. Time: events older than the rule's window are popped on each
#      observe() — see RuleEngine._prune_window.
#   2. Count: hard cap on `_MAX_WINDOW_EVENTS` per rule (defends
#      against a runaway producer that pushes more than `window`
#      events in one second).
_MAX_WINDOW_EVENTS = 10_000


def _event_type(event: dict) -> str:
    """Pull `unmapped.iam_jit.event_type` from an event, default empty."""
    unmapped = event.get("unmapped") or {}
    iam_jit = unmapped.get("iam_jit") if isinstance(unmapped, dict) else None
    if not isinstance(iam_jit, dict):
        return ""
    return str(iam_jit.get("event_type") or "")


def _event_ext(event: dict) -> dict:
    """Pull `unmapped.iam_jit.ext` from an event, default empty."""
    unmapped = event.get("unmapped") or {}
    iam_jit = unmapped.get("iam_jit") if isinstance(unmapped, dict) else None
    if not isinstance(iam_jit, dict):
        return {}
    ext = iam_jit.get("ext")
    return ext if isinstance(ext, dict) else {}


def _event_verdict(event: dict) -> str:
    """Pull the iam-jit verdict ('allow'/'deny'/'prompt') from event."""
    unmapped = event.get("unmapped") or {}
    iam_jit = unmapped.get("iam_jit") if isinstance(unmapped, dict) else None
    if not isinstance(iam_jit, dict):
        return ""
    return str(iam_jit.get("verdict") or "").lower()


def _event_mode(event: dict) -> str:
    """Pull the iam-jit mode ('cooperative'/'transparent'/...)."""
    unmapped = event.get("unmapped") or {}
    iam_jit = unmapped.get("iam_jit") if isinstance(unmapped, dict) else None
    if not isinstance(iam_jit, dict):
        return ""
    return str(iam_jit.get("mode") or "").lower()


def _event_enforced(event: dict) -> bool:
    """Pull `unmapped.iam_jit.enforced` (bool); default False."""
    unmapped = event.get("unmapped") or {}
    iam_jit = unmapped.get("iam_jit") if isinstance(unmapped, dict) else None
    if not isinstance(iam_jit, dict):
        return False
    return bool(iam_jit.get("enforced", False))


def _event_service_action(event: dict) -> tuple[str, str]:
    """Pull (service, action) from `api.operation` ('service:Action')."""
    api = event.get("api") or {}
    op = api.get("operation") if isinstance(api, dict) else ""
    if not isinstance(op, str) or ":" not in op:
        # Fall back to api.service.name when operation is malformed.
        svc = ""
        if isinstance(api, dict):
            service_block = api.get("service") or {}
            if isinstance(service_block, dict):
                svc = str(service_block.get("name") or "")
        return svc, ""
    svc, _, action = op.partition(":")
    return svc, action


def _glob_match(pattern: str, value: str) -> bool:
    """Case-insensitive glob match supporting `*` wildcards. Returns
    True if `pattern` matches `value` end-to-end.

    Pure-Python implementation (no `fnmatch`) so the behavior is
    deterministic across platforms — `fnmatch` consults the OS's
    locale on some build configurations which we don't want for a
    pattern-matching engine the operator's YAML reads from.
    """
    p = pattern.lower()
    v = value.lower()
    # Fast path: no wildcards = literal equality.
    if "*" not in p:
        return p == v
    # Split on `*` and match each segment in order with index-walk.
    parts = p.split("*")
    pos = 0
    # First segment must match the prefix (unless pattern starts with `*`).
    if parts[0]:
        if not v.startswith(parts[0]):
            return False
        pos = len(parts[0])
    for seg in parts[1:-1]:
        if not seg:
            continue
        idx = v.find(seg, pos)
        if idx == -1:
            return False
        pos = idx + len(seg)
    # Last segment must match the suffix (unless pattern ends with `*`).
    if parts[-1]:
        if not v.endswith(parts[-1]):
            return False
        if len(v) - len(parts[-1]) < pos:
            return False
    return True


# ---------------------------------------------------------------------------
# Built-in rule patterns
# ---------------------------------------------------------------------------


def _pattern_admin_fallback_burst(
    event: dict, window: deque, config: AlertsConfig,
) -> dict | None:
    """Fire when >`admin_fallback_threshold` admin-fallback grants
    appear in the rolling `admin_fallback_window_seconds` window.

    Per [[security-team-positioning-safety-not-surveillance]]: the
    suggestion frames this as a SCOPE-mismatch hint, not as an
    accusation. A burst of admin-fallback grants typically means the
    available profiles are too narrow for the work the team is
    actually doing — the right next step is usually to ship a broader
    profile, not to lecture the people requesting it.
    """
    if _event_type(event) != EVENT_TYPE_ADMIN_FALLBACK_GRANT:
        return None
    # The engine appends EVERY event to the per-rule window so the
    # window-pruner can do its job in one place — count only the
    # entries whose event_type matches this rule's interest. The
    # window's bounded length guarantees this loop is cheap (capped
    # at _MAX_WINDOW_EVENTS).
    count = sum(
        1 for _, e in window
        if _event_type(e) == EVENT_TYPE_ADMIN_FALLBACK_GRANT
    )
    if count <= config.admin_fallback_threshold:
        return None
    return {
        "matched_event_count": count,
        "window_seconds": config.admin_fallback_window_seconds,
        "status_detail": (
            f"Pattern admin-fallback-burst fired: {count} admin-fallback "
            f"grants in last {config.admin_fallback_window_seconds // 60}min"
        ),
        "suggestion": (
            "Recurring admin-fallback grants suggest the available profiles "
            "may be too narrow for the work being done; consider distributing "
            "a profile with broader scope to the affected team."
        ),
    }


def _pattern_pause_long(
    event: dict, window: deque, config: AlertsConfig,
) -> dict | None:
    """Fire when a PAUSE_END event reports a duration >
    `pause_long_threshold_seconds`.

    The pause tracker emits PAUSE_END synthetic events with
    `unmapped.iam_jit.ext.duration_seconds` set to the actual window
    length (operator-resumed or auto-expired). The rule reads that
    field; we don't try to detect "pause is currently long" because
    that would fire repeatedly on a still-open pause.
    """
    if _event_type(event) != EVENT_TYPE_PAUSE_END:
        return None
    ext = _event_ext(event)
    duration = ext.get("duration_seconds")
    try:
        duration = int(duration)
    except (TypeError, ValueError):
        return None
    if duration <= config.pause_long_threshold_seconds:
        return None
    minutes = duration // 60
    threshold_minutes = config.pause_long_threshold_seconds // 60
    return {
        "matched_event_count": 1,
        "window_seconds": duration,
        "status_detail": (
            f"Pattern long-pause fired: pause window of {minutes}min "
            f"exceeds threshold of {threshold_minutes}min"
        ),
        "suggestion": (
            "Extended pause windows reduce the enforcement surface; consider "
            "shorter targeted pauses scoped to the specific operation, or "
            "splitting the work across multiple shorter windows."
        ),
    }


def _pattern_non_org_profile_install(
    event: dict, window: deque, config: AlertsConfig,
) -> dict | None:
    """Fire when a PROFILE_INSTALL event reports a source_url NOT in
    the operator's allowlist.

    Empty allowlist = every install fires (the default; matches the
    "operator hasn't curated their profile catalog yet" baseline).
    """
    if _event_type(event) != EVENT_TYPE_PROFILE_INSTALL:
        return None
    ext = _event_ext(event)
    source_url = str(ext.get("source_url") or "")
    if not source_url:
        return None
    if source_url in config.profile_install_allowlist:
        return None
    return {
        "matched_event_count": 1,
        "window_seconds": 0,
        "status_detail": (
            f"Pattern non-org-profile-install fired: profile installed from "
            f"{source_url!r} which is not on the org allowlist"
        ),
        "suggestion": (
            "Profile installations from non-allowlisted sources are worth "
            "a closer look; if this is a legitimate source, add the URL to "
            "the org's profile_install_allowlist in --alert-rules."
        ),
    }


def _pattern_heartbeat_gap(
    event: dict, window: deque, config: AlertsConfig,
) -> dict | None:
    """#264 — fire when `heartbeat_missing_count` or more consecutive
    heartbeats have been missed.

    Evaluation:
      * Heartbeats are tracked via the heartbeat module's state
        (last_emit timestamp). When the elapsed time since the last
        heartbeat exceeds `interval * missing_count`, the rule fires.
      * The rule debounces by checking `heartbeat_gap_detected` —
        once it has fired, it does NOT fire again until a fresh
        heartbeat lands (the emitter calls `_record_emit` which clears
        the flag). This keeps a long outage from producing a fire-per-
        event storm in the audit channel.
      * When heartbeats are not enabled (the emitter never started),
        the rule is a no-op. Operators who haven't opted into
        heartbeats don't need the gap rule firing on the silence.
      * When the rule fires, it ALSO:
          - flips the module-level `heartbeat_gap_detected` flag the
            proxy's /healthz reads to return 503 (per spec)
          - writes a neutral-language message to stderr (per spec:
            the audit channel itself may be why heartbeats stopped,
            so alerting through the same channel isn't reliable —
            stderr is the supervisor-captured fallback)

    Per [[security-team-positioning-safety-not-surveillance]]: the
    suggestion frames this as "look at process status," not "someone
    killed your bouncer."
    """
    hb = _heartbeat_status()
    if not hb["heartbeat_enabled"]:
        # Operator hasn't opted into heartbeats; rule is dormant.
        return None
    if hb["heartbeat_gap_detected"]:
        # Already fired; wait for a fresh heartbeat to clear the
        # flag before considering a re-fire.
        return None
    interval = hb["heartbeat_interval_seconds"]
    if interval <= 0:
        # Defensive: a misconfigured emitter (interval=0) wouldn't
        # ever produce a meaningful gap calculation.
        return None
    last_seconds_ago = hb["heartbeat_last_emit_seconds_ago"]
    if last_seconds_ago is None:
        # No heartbeat has been recorded yet. The emitter writes its
        # first heartbeat on start(); a None here means start() hasn't
        # completed its first emit yet. Don't false-fire during the
        # brief boot window.
        return None
    threshold_seconds = interval * config.heartbeat_missing_count
    if last_seconds_ago < threshold_seconds:
        return None
    # Gap detected. Flip the /healthz flag + write to stderr, THEN
    # return the alert dict so the rule engine emits the OCSF event
    # through the normal alert path too.
    _mark_heartbeat_gap_detected()
    _write_heartbeat_gap_stderr(
        missing_count=config.heartbeat_missing_count,
        last_emit_seconds_ago=last_seconds_ago,
        interval_seconds=interval,
    )
    return {
        "matched_event_count": config.heartbeat_missing_count,
        "window_seconds": last_seconds_ago,
        "status_detail": (
            f"Pattern bouncer-uptime-gap fired: "
            f"{config.heartbeat_missing_count} consecutive heartbeats "
            f"missing (interval={interval}s, last emit "
            f"{last_seconds_ago}s ago)"
        ),
        "suggestion": (
            "bouncer may have been killed; investigate process status "
            "+ recent admin-action events. The audit-export channel "
            "may itself be the cause if the webhook collector is down "
            "or the JSONL path is unwritable; check stderr for a "
            "parallel notice the alert path did not depend on."
        ),
    }


def _pattern_unusual_high_risk_action(
    event: dict, window: deque, config: AlertsConfig,
) -> dict | None:
    """Fire when a transparent-mode DENY targets an action on the
    high-risk watchlist.

    Cooperative-mode denies do NOT fire this rule (the call still
    succeeded upstream; a deny was advisory only — that's a separate
    "your profile would have blocked this" preview, not an anomaly).
    Plan-capture mode also does not fire (the call was never sent
    upstream; deny in plan-capture is a normative preview).
    """
    if _event_verdict(event) != "deny":
        return None
    if _event_mode(event) != "transparent":
        return None
    if not _event_enforced(event):
        # Pause-demoted denies report enforced=False even in
        # transparent mode; we don't want to alert on those (the
        # operator explicitly opened the window).
        return None
    service, action = _event_service_action(event)
    if not service or not action:
        return None
    canonical = f"{service}:{action}"
    matched = None
    for pat in config.high_risk_actions:
        if _glob_match(pat, canonical):
            matched = pat
            break
    if matched is None:
        return None
    return {
        "matched_event_count": 1,
        "window_seconds": 0,
        "status_detail": (
            f"Pattern high-risk-action-denied fired: transparent-mode "
            f"deny on {canonical} (matched watchlist entry {matched!r})"
        ),
        "suggestion": (
            f"The agent attempted {canonical} and the proxy denied it. "
            "If this is expected for the workflow, add an allow rule scoped "
            "narrowly to the specific resource; if not, the deny was the "
            "right call and no action is needed."
        ),
    }


# Built-in rule registry. Order matters only for deterministic
# evaluation in tests; runtime correctness does not depend on it.
BUILTIN_RULES: tuple[AlertRule, ...] = (
    AlertRule(
        name="admin_fallback_burst",
        pattern=_pattern_admin_fallback_burst,
        severity=3,
        description=(
            "More than admin_fallback_threshold admin-fallback grants in "
            "admin_fallback_window_seconds. Indicates available profiles "
            "may be too narrow for the work being done."
        ),
    ),
    AlertRule(
        name="pause_long",
        pattern=_pattern_pause_long,
        severity=3,
        description=(
            "A single pause window exceeded pause_long_threshold_seconds. "
            "Indicates an extended reduction in enforcement surface."
        ),
    ),
    AlertRule(
        name="non_org_profile_install",
        pattern=_pattern_non_org_profile_install,
        severity=3,
        description=(
            "A profile was installed from a URL not on the org's "
            "profile_install_allowlist. Indicates a source worth reviewing."
        ),
    ),
    AlertRule(
        name="unusual_high_risk_action",
        pattern=_pattern_unusual_high_risk_action,
        severity=4,
        description=(
            "A transparent-mode deny targeted an action on the high-risk "
            "watchlist (iam:Create*, kms:Decrypt, secretsmanager:Get*, "
            "audit-infra destruction). Useful 'look at what was tried' "
            "signal."
        ),
    ),
    AlertRule(
        name="heartbeat_gap",
        pattern=_pattern_heartbeat_gap,
        severity=4,
        description=(
            "#264 — heartbeat_missing_count or more consecutive heartbeats "
            "missing from the audit stream. The bouncer may have been "
            "killed while a session was active; investigate process "
            "status + recent admin-action events. Also flips /healthz "
            "to 503 + writes to stderr for supervisor capture."
        ),
    ),
)


# Pattern names emitted on the OCSF event under `unmapped.iam_jit.pattern`.
# Matches the spec table; the keys are the rule `name` field.
_PATTERN_NAME_BY_RULE = {
    "admin_fallback_burst": "admin-fallback-burst",
    "pause_long": "long-pause",
    "non_org_profile_install": "non-org-profile-install",
    "unusual_high_risk_action": "high-risk-action-denied",
    "heartbeat_gap": "bouncer-uptime-gap",
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def _now_seconds() -> float:
    """Monotonic-friendly wall-clock seconds for window pruning.
    Wall-clock is fine here because the windows are short (minutes)
    and the rule's job is "the operator's clock view of these
    events"; a clock jump backwards just leaves more events in the
    window for one cycle. Tests inject a fake via the engine's
    `_now` hook."""
    return time.time()


class RuleEngine:
    """Deterministic alert rule engine.

    Lifecycle::

        engine = RuleEngine(config=AlertsConfig.default(), emit=channel_emit)
        engine.observe(event)        # called per audit event
        snapshot = engine.status()   # for the MCP status tool

    `emit` is the function that takes an alert event dict and pushes
    it through the audit-export transport (the same _emit_audit_event
    the proxy decision path uses). The engine NEVER does I/O itself;
    every side effect goes through `emit` so the same engine works in
    unit tests (`emit` captures into a list) and in production
    (`emit` is the proxy's transport).

    Thread-safe: a lock guards window state + counters because the
    proxy can call observe() from one event-loop thread while the
    MCP server reads status() from another.
    """

    def __init__(
        self,
        *,
        config: AlertsConfig | None = None,
        emit: Callable[[dict], None] | None = None,
        rules: tuple[AlertRule, ...] = BUILTIN_RULES,
        # Test hooks.
        _now: Callable[[], float] | None = None,
    ) -> None:
        self.config = config or AlertsConfig.default()
        self._emit = emit or (lambda _e: None)
        self._all_rules = rules
        self._now = _now or _now_seconds
        # Per-rule sliding window: deque of (timestamp_seconds, event).
        self._windows: dict[str, deque] = {
            r.name: deque() for r in self._all_rules
        }
        self._lock = threading.Lock()
        # Stats — surfaced by status() for the MCP tool.
        self._alerts_fired = 0
        self._last_alert_pattern: str | None = None
        self._last_alert_at: float | None = None

    @property
    def active_rules(self) -> tuple[AlertRule, ...]:
        """Filter to the rules the operator has actually enabled.
        `None` in `config.enabled_rules` = all enabled (the default);
        an empty frozenset = none enabled."""
        if self.config.enabled_rules is None:
            return self._all_rules
        return tuple(
            r for r in self._all_rules if r.name in self.config.enabled_rules
        )

    def observe(self, event: dict) -> list[dict]:
        """Feed one event to every active rule. Returns the list of
        alert events emitted (empty list = nothing fired).

        Per the spec: this is called for EVERY event the proxy emits
        through the audit-export transport, so it MUST be cheap. The
        per-rule deque-append + threshold-compare is O(1); the
        window-prune is O(expired) which amortises to O(1) over time.

        Fail-soft: any exception inside a rule pattern is logged +
        swallowed; we DO NOT let a buggy rule take down the proxy's
        audit channel.
        """
        if not isinstance(event, dict):
            return []
        # Suppress re-entry: an alert event we just emitted comes
        # back into observe() through the same transport. Without
        # this guard a rule could fire on its own output (infinite
        # cascade). Spec calls this out implicitly via the OCSF
        # `unmapped.iam_jit.event_type == ANOMALY_DETECTED` marker
        # the engine sets on every alert it emits.
        if _event_type(event) == EVENT_TYPE_ANOMALY_DETECTED:
            return []
        emitted: list[dict] = []
        now = self._now()
        with self._lock:
            for rule in self.active_rules:
                try:
                    window = self._windows[rule.name]
                    window.append((now, event))
                    self._prune_window(rule, window, now)
                    result = rule.pattern(event, window, self.config)
                except Exception as e:
                    logger.warning(
                        "alert rule %s raised %s on event; swallowing",
                        rule.name, e,
                    )
                    continue
                if result is None:
                    continue
                alert = self._build_alert_event(rule, event, result)
                emitted.append(alert)
                self._alerts_fired += 1
                self._last_alert_pattern = _PATTERN_NAME_BY_RULE.get(
                    rule.name, rule.name,
                )
                self._last_alert_at = now
        # Emit OUTSIDE the lock so the transport's enqueue can't
        # deadlock against another observe() on a different thread.
        for alert in emitted:
            try:
                self._emit(alert)
            except Exception as e:
                logger.warning("alert emit failed: %s", e)
        return emitted

    def _prune_window(
        self, rule: AlertRule, window: deque, now: float,
    ) -> None:
        """Drop window entries older than the rule's window OR past
        the hard `_MAX_WINDOW_EVENTS` cap (whichever bites first).

        We bound by BOTH so a producer that pushes 1M events per
        second into a 5-minute window can't OOM the proxy. The hard
        cap is set high enough (10k) that legitimate burst traffic
        through a single rule's window won't truncate.
        """
        # Pick the per-rule window-seconds based on rule name; rules
        # whose windows aren't time-bounded (pause_long, non_org_*,
        # unusual_high_risk) use 1 second so the deque doesn't grow
        # unbounded across the process lifetime.
        if rule.name == "admin_fallback_burst":
            window_seconds = self.config.admin_fallback_window_seconds
        else:
            window_seconds = 1
        cutoff = now - window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()
        while len(window) > _MAX_WINDOW_EVENTS:
            window.popleft()

    def _build_alert_event(
        self, rule: AlertRule, source_event: dict, result: dict,
    ) -> dict:
        """Assemble the OCSF v1.1.0 class-6003 anomaly_detected event
        the engine emits when `rule` fires on `source_event`.

        Per [[security-team-positioning-safety-not-surveillance]]:
        every string here is neutral. The status_detail + suggestion
        come from the rule pattern's return dict; the
        neutral-language scan test asserts both stay clean.
        """
        pattern = _PATTERN_NAME_BY_RULE.get(rule.name, rule.name)
        # Preserve a tiny reference to the source decision so the
        # operator can pivot from the alert back to the original
        # event in their SIEM. Only the decision_id + actor session
        # — never copy the full source event into the alert (size +
        # would force the alert through the same activity-id
        # classifier as the original).
        source_decision_id = ""
        source_unmapped = source_event.get("unmapped") or {}
        source_iam_jit = (
            source_unmapped.get("iam_jit")
            if isinstance(source_unmapped, dict)
            else None
        )
        if isinstance(source_iam_jit, dict):
            did = source_iam_jit.get("decision_id")
            if did is not None:
                source_decision_id = str(did)

        actor = source_event.get("actor") or {}
        if not isinstance(actor, dict):
            actor = {}
        actor = dict(actor)
        if "user" not in actor:
            actor["user"] = {"name": "", "uid": ""}

        severity_name = _SEVERITY_NAME_BY_ID.get(
            rule.severity, "Informational",
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
            "activity_id": _ANOMALY_ACTIVITY_ID,
            "activity_name": _ANOMALY_ACTIVITY_NAME,
            "type_uid": _TYPE_UID,
            "type_name": f"{_CLASS_NAME}: Other",
            "severity_id": rule.severity,
            "severity": severity_name,
            "status_id": _STATUS_OTHER_ID,
            "status": _STATUS_OTHER_NAME,
            "status_detail": result.get("status_detail", ""),
            "actor": actor,
            "api": {
                "operation": "anomaly_detected",
                "service": {"name": "ibounce.audit_export.alerts"},
                "request": {"uid": source_decision_id},
            },
            "resources": [],
            "src_endpoint": {},
            "dst_endpoint": {},
            "unmapped": {
                "iam_jit": {
                    "event_type": EVENT_TYPE_ANOMALY_DETECTED,
                    "pattern": pattern,
                    "window_seconds": int(result.get("window_seconds", 0)),
                    "matched_event_count": int(
                        result.get("matched_event_count", 0)
                    ),
                    "suggestion": result.get("suggestion", ""),
                    "source_decision_id": source_decision_id,
                    "rule_severity": rule.severity,
                },
            },
        }

    def status(self) -> dict[str, Any]:
        """Snapshot for the MCP `bouncer_audit_export_status` tool.

        Returns the three Slice 2 fields per the spec:
          - alerts_enabled (bool)
          - alerts_fired_count (int; since process start)
          - last_alert_pattern (str | None)

        Plus a small `active_rules` list so an agent can answer
        "which rules are currently configured to fire?" without a
        separate tool call. Safe to call from any thread.
        """
        with self._lock:
            active = self.active_rules
            return {
                "alerts_enabled": bool(active),
                "alerts_fired_count": self._alerts_fired,
                "last_alert_pattern": self._last_alert_pattern,
                "last_alert_at_unix": (
                    int(self._last_alert_at)
                    if self._last_alert_at is not None
                    else None
                ),
                "active_rules": [r.name for r in active],
            }


# ---------------------------------------------------------------------------
# Synthetic-event helpers (used by the operator-side emitters that
# push admin-fallback / pause-end / profile-install events through
# the same audit-export transport so the rule engine sees them).
# ---------------------------------------------------------------------------


def make_admin_fallback_grant_event(
    *,
    principal: str,
    grant_id: str | int,
    mode: str = "transparent",
) -> dict:
    """Build the OCSF synthetic the grant pipeline emits when it
    issues an admin-fallback (Action=`*`, Resource=`*`) grant.

    The rule engine watches for `unmapped.iam_jit.event_type ==
    ADMIN_FALLBACK_GRANT` and counts these against the rolling
    admin_fallback_window_seconds window.
    """
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
        "activity_id": _ANOMALY_ACTIVITY_ID,
        "activity_name": "admin_fallback_grant",
        "type_uid": _TYPE_UID,
        "type_name": f"{_CLASS_NAME}: Other",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": _STATUS_OTHER_ID,
        "status": _STATUS_OTHER_NAME,
        "status_detail": (
            f"admin-fallback grant issued: id={grant_id} principal={principal}"
        ),
        "actor": {"user": {"name": principal, "uid": principal}},
        "api": {
            "operation": "admin_fallback_grant",
            "service": {"name": "ibounce.grants"},
            "request": {"uid": str(grant_id)},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_ADMIN_FALLBACK_GRANT,
                "mode": mode,
                "grant_id": str(grant_id),
                "ext": {},
            },
        },
    }


def make_pause_end_event(
    *,
    pause_id: str | int,
    duration_seconds: int,
    end_kind: str = "resumed_early",
    started_by: str = "",
) -> dict:
    """Build the OCSF synthetic the pause tracker emits when a pause
    window closes (operator-resumed OR auto-expired).

    The rule engine watches for `unmapped.iam_jit.event_type ==
    PAUSE_END` and checks `ext.duration_seconds` against the
    pause_long_threshold_seconds.
    """
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
        "activity_id": _ANOMALY_ACTIVITY_ID,
        "activity_name": "pause_end",
        "type_uid": _TYPE_UID,
        "type_name": f"{_CLASS_NAME}: Other",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": _STATUS_OTHER_ID,
        "status": _STATUS_OTHER_NAME,
        "status_detail": (
            f"pause window closed: id={pause_id} "
            f"duration={duration_seconds}s end_kind={end_kind}"
        ),
        "actor": {"user": {"name": started_by, "uid": started_by}},
        "api": {
            "operation": "pause_end",
            "service": {"name": "ibounce.pauses"},
            "request": {"uid": str(pause_id)},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_PAUSE_END,
                "pause_id": str(pause_id),
                "ext": {
                    "duration_seconds": int(duration_seconds),
                    "end_kind": end_kind,
                },
            },
        },
    }


def make_profile_install_event(
    *,
    profile_name: str,
    source_url: str,
    installed_by: str = "",
) -> dict:
    """Build the OCSF synthetic `ibounce profile install --from URL`
    emits when it lands a new profile.

    The rule engine watches for `unmapped.iam_jit.event_type ==
    PROFILE_INSTALL` and compares `ext.source_url` against the
    profile_install_allowlist.
    """
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
        "activity_id": 1,  # Create — a new profile was created locally
        "activity_name": "profile_install",
        "type_uid": 600300 + 1,
        "type_name": f"{_CLASS_NAME}: Create",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "status_detail": (
            f"profile installed: name={profile_name} from={source_url}"
        ),
        "actor": {"user": {"name": installed_by, "uid": installed_by}},
        "api": {
            "operation": "profile_install",
            "service": {"name": "ibounce.profiles"},
            "request": {"uid": profile_name},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_PROFILE_INSTALL,
                "profile_name": profile_name,
                "ext": {
                    "source_url": source_url,
                },
            },
        },
    }


# Mostly for the neutral-language scan: the set of words that MUST
# NOT appear in any user-facing alert string. Exported so the test
# can import the canonical list rather than open-coding it.
FORBIDDEN_ALERT_WORDS: tuple[str, ...] = (
    "violation",
    "infraction",
    "unauthorized",
)


def _utc_now_iso() -> str:
    """ISO-8601 UTC timestamp for human-readable strings (NOT used
    in the OCSF event itself — that uses `_now_unix_ms`)."""
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
