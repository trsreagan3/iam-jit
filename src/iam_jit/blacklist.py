"""Per-deployment IAM action blacklist.

A configurable list of action patterns the deployment refuses to score
under any circumstances. Different from the risk scorer: scoring says
"how dangerous is this policy"; the blacklist says "we won't process
THIS at all."

Use cases:
- Hard organizational rules ("nobody ever requests iam:CreateAccessKey
  via JIT — those are minted by HR onboarding only").
- Catastrophic-action gates ("we never auto-process anything that
  could touch CloudTrail").
- Compliance-mandated denials (PCI scope, SOC 2 boundaries).

## Oracle-attack consideration

If the API tells anonymous callers exactly WHICH action triggered the
blacklist, an attacker can bisect their payload to map the rules.
That's a real concern but the mitigation is well-defined:

  - **Authenticated callers** (paid-tier API key holders): receive
    specific detail ("`iam:CreateAccessKey` is blacklisted: ..."),
    because they've already passed access control and we want them
    to fix their policy.
  - **Anonymous callers** (free tier / public): receive ONLY a
    generic "request rejected by deployment policy" with NO detail
    about which action or pattern matched. The bisection-attack path
    still exists but produces no usable signal — every probe gets
    the same generic response.
  - **Audit log**: every hit is recorded with rule_id + source IP +
    matched action + policy fingerprint, so the operator can review
    if traffic patterns suggest someone IS bisecting.
  - **Rate limit** (already in place): 30 req/min/IP makes bisection
    against a ~400-service IAM action space prohibitively slow.

## Pattern syntax

Glob-style on the `service:Action` form:
  - `iam:CreateAccessKey` — exact match
  - `iam:*AccessKey*` — substring on the action name
  - `cloudtrail:*` — every action in cloudtrail
  - `*:Delete*` — every Delete* action across all services
  - `*` alone is rejected (would block every request)

Pattern matching uses `fnmatch.fnmatchcase` semantics.

## Storage

`BlacklistStore` is a Protocol. Two implementations:
- `InMemoryBlacklistStore` — tests / dev
- `SettingsBlacklistStore` — production, persists in settings (which is
  DDB-backed in prod and YAML-backed in dev)
"""

from __future__ import annotations

import dataclasses
import fnmatch
import time
from typing import Any, Iterable, Protocol


@dataclasses.dataclass(frozen=True)
class BlacklistRule:
    """One blacklist entry."""

    rule_id: str          # short stable identifier, e.g. "ban-create-access-key"
    pattern: str          # fnmatch pattern on `service:Action`
    reason: str           # human-readable explanation surfaced in audit logs
    added_by: str         # the admin user id who installed it
    added_at: int         # epoch seconds


@dataclasses.dataclass(frozen=True)
class BlacklistHit:
    """One match between a policy and a blacklist rule."""

    rule_id: str
    pattern: str
    matched_action: str   # the actual action that matched
    reason: str           # copy from the rule (for audit-log convenience)


class BlacklistStore(Protocol):
    def list_rules(self) -> list[BlacklistRule]: ...

    def put_rule(self, rule: BlacklistRule) -> None: ...

    def delete_rule(self, rule_id: str) -> None: ...


class InMemoryBlacklistStore:
    """Thread-unsafe in-memory store. Tests and single-process dev only."""

    name = "memory"

    def __init__(self) -> None:
        self._rules: dict[str, BlacklistRule] = {}

    def list_rules(self) -> list[BlacklistRule]:
        return sorted(self._rules.values(), key=lambda r: r.rule_id)

    def put_rule(self, rule: BlacklistRule) -> None:
        if rule.pattern == "*":
            raise ValueError(
                "Pattern '*' alone is rejected — it would block every request. "
                "Use specific patterns like 'iam:*' or 'service:Action*'."
            )
        self._rules[rule.rule_id] = rule

    def delete_rule(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)


# ----------------------------------------------------------------------
# Matching
# ----------------------------------------------------------------------


def _iter_actions(policy: dict[str, Any]) -> Iterable[str]:
    """Walk every Action / NotAction string in the policy."""
    statements = policy.get("Statement") or []
    if not isinstance(statements, list):
        return
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        for key in ("Action", "NotAction"):
            actions = stmt.get(key)
            if actions is None:
                continue
            if isinstance(actions, str):
                yield actions
            elif isinstance(actions, list):
                for a in actions:
                    if isinstance(a, str):
                        yield a


def _has_iam_wildcard(s: str) -> bool:
    """True if `s` contains an IAM wildcard primitive (`*` or `?`).

    IAM treats both `*` (any string) and `?` (any single char) as
    wildcards in action/resource patterns. Round-4 white-box agent
    found that submitted-action `iam:?reateAccessKey` slipped past a
    blacklist rule `iam:CreateAccessKey` because fnmatch is asymmetric:
    `fnmatchcase(submitted, pattern)` only treats `pattern` as a glob,
    so a wildcard on the SUBMITTED side bypassed the literal rule.
    """
    return "*" in s or "?" in s


def _action_matches_rule(action: str, rule_pattern: str) -> bool:
    """Bidirectional wildcard-aware match between submitted action and
    blacklist rule pattern.

    The naïve approach (`fnmatch(action, rule)`) only works when the
    rule contains wildcards. If the attacker SUBMITS a wildcarded
    action like `iam:?reateAccessKey`, a literal rule
    `iam:CreateAccessKey` would never match. We fix this by trying
    both directions: rule-as-pattern AND submitted-action-as-pattern.
    """
    a_lc = action.lower()
    r_lc = rule_pattern.lower()
    # Direction 1 (the normal case): rule is the pattern.
    if fnmatch.fnmatchcase(a_lc, r_lc):
        return True
    # Direction 2: submitted action contains wildcards, so treat IT as
    # the pattern. The rule hits if its literal action is COVERED by
    # the submitted action's glob.
    if _has_iam_wildcard(a_lc) and not _has_iam_wildcard(r_lc):
        if fnmatch.fnmatchcase(r_lc, a_lc):
            return True
    return False


def check_policy(
    policy: dict[str, Any], store: BlacklistStore
) -> BlacklistHit | None:
    """Return the first blacklist rule that matches an action in the policy,
    or None if no rule matches.

    Matching is case-insensitive AND wildcard-aware in both directions
    (so `iam:?reateAccessKey` is caught by a literal `iam:CreateAccessKey`
    rule). See `_action_matches_rule`.
    """
    rules = store.list_rules()
    if not rules:
        return None
    for action in _iter_actions(policy):
        for rule in rules:
            if _action_matches_rule(action, rule.pattern):
                return BlacklistHit(
                    rule_id=rule.rule_id,
                    pattern=rule.pattern,
                    matched_action=action,
                    reason=rule.reason,
                )
    return None


# ----------------------------------------------------------------------
# Default templates (curated examples — operators can adopt or modify)
# ----------------------------------------------------------------------


def template_ban_catastrophic_actions() -> list[BlacklistRule]:
    """The 'we never want these via JIT' starter set.

    Every action here is one a JIT-IAM workflow has essentially zero
    legitimate need to grant on demand. They're explicit-admin-only
    operations — onboarding scripts, infrastructure-as-code, manual
    incident response.
    """
    now = int(time.time())
    return [
        BlacklistRule(
            rule_id="ban-close-account",
            pattern="account:CloseAccount",
            reason="Account closure is irreversible and never JIT-appropriate.",
            added_by="template:ban-catastrophic",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-leave-org",
            pattern="organizations:LeaveOrganization",
            reason="Leaving the AWS Org disconnects governance & billing; never JIT.",
            added_by="template:ban-catastrophic",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-cloudtrail-tampering",
            pattern="cloudtrail:DeleteTrail",
            reason="Deleting CloudTrail breaks audit evidence — incident-response only.",
            added_by="template:ban-catastrophic",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-cloudtrail-stop",
            pattern="cloudtrail:StopLogging",
            reason="Stopping audit logging is never JIT-appropriate.",
            added_by="template:ban-catastrophic",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-schedule-key-deletion",
            pattern="kms:ScheduleKeyDeletion",
            reason="Scheduled KMS deletion = irreversible data loss; never JIT.",
            added_by="template:ban-catastrophic",
            added_at=now,
        ),
    ]


def template_ban_credential_minting() -> list[BlacklistRule]:
    """Block credential-creation primitives — these should flow through
    onboarding tooling, not JIT requests.
    """
    now = int(time.time())
    return [
        BlacklistRule(
            rule_id="ban-create-access-key",
            pattern="iam:CreateAccessKey",
            reason="Long-lived programmatic credentials should be issued by onboarding, not JIT.",
            added_by="template:ban-credential-minting",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-update-login-profile",
            pattern="iam:UpdateLoginProfile",
            reason="Console password mutation should not be JIT.",
            added_by="template:ban-credential-minting",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-create-service-specific-cred",
            pattern="iam:CreateServiceSpecificCredential",
            reason="Service-specific credentials are persistent — issue via onboarding.",
            added_by="template:ban-credential-minting",
            added_at=now,
        ),
    ]


def template_ban_iam_escalation_primitives() -> list[BlacklistRule]:
    """Block the IAM mutations that compose into privilege escalation."""
    now = int(time.time())
    return [
        BlacklistRule(
            rule_id="ban-attach-role-policy",
            pattern="iam:AttachRolePolicy",
            reason="Attaching managed policies is the classic IAM escalation primitive.",
            added_by="template:ban-iam-escalation",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-put-role-policy",
            pattern="iam:PutRolePolicy",
            reason="Inline-policy puts on roles bypass policy-attachment review.",
            added_by="template:ban-iam-escalation",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-update-assume-role-policy",
            pattern="iam:UpdateAssumeRolePolicy",
            reason="Trust-policy rewrite lets any principal assume any role.",
            added_by="template:ban-iam-escalation",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-create-policy-version",
            pattern="iam:CreatePolicyVersion",
            reason="Silent-policy-swap escalation (combine with SetDefaultPolicyVersion).",
            added_by="template:ban-iam-escalation",
            added_at=now,
        ),
    ]


def template_ban_audit_evasion() -> list[BlacklistRule]:
    """Block actions that disable detection / response capabilities."""
    now = int(time.time())
    return [
        BlacklistRule(
            rule_id="ban-cloudwatch-disable-alarms",
            pattern="cloudwatch:DisableAlarmActions",
            reason="Disabling alarms suppresses detection — never JIT.",
            added_by="template:ban-audit-evasion",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-config-disable",
            pattern="config:StopConfigurationRecorder",
            reason="Stopping AWS Config drops compliance posture tracking.",
            added_by="template:ban-audit-evasion",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-config-delete",
            pattern="config:DeleteConfigurationRecorder",
            reason="Deleting Config configuration is destructive evidence handling.",
            added_by="template:ban-audit-evasion",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-guardduty-disable",
            pattern="guardduty:UpdateDetector",
            reason="Modifying GuardDuty can disable threat detection.",
            added_by="template:ban-audit-evasion",
            added_at=now,
        ),
        BlacklistRule(
            rule_id="ban-guardduty-delete",
            pattern="guardduty:DeleteDetector",
            reason="GuardDuty detector deletion is never operationally needed.",
            added_by="template:ban-audit-evasion",
            added_at=now,
        ),
    ]


# Convenience: name → callable for the template loader.
TEMPLATES: dict[str, Any] = {
    "ban-catastrophic-actions": template_ban_catastrophic_actions,
    "ban-credential-minting": template_ban_credential_minting,
    "ban-iam-escalation-primitives": template_ban_iam_escalation_primitives,
    "ban-audit-evasion": template_ban_audit_evasion,
}


# ---------------------------------------------------------------------
# Process-wide blacklist-store singleton.
#
# Pre-2026-05-24 this lived in `iam_jit.routes.score` next to the
# hosted /api/v1/score endpoint. When that endpoint was removed per
# [[no-hosted-saas]] restoration the singleton moved here so the
# self-host admin-blacklist routes (`routes/blacklist.py`) still have
# a process-wide handle to read + write.
#
# Default is the InMemoryBlacklistStore — no rules — so deployments
# without explicit blacklist config behave identically to the
# pre-blacklist scorer.
# ---------------------------------------------------------------------

_blacklist_store: BlacklistStore = InMemoryBlacklistStore()


def set_blacklist_store(store: BlacklistStore) -> None:
    """Wire in a different blacklist store. Called at app startup;
    also useful in tests to install rules for a specific assertion."""
    global _blacklist_store
    _blacklist_store = store


def get_blacklist_store() -> BlacklistStore:
    return _blacklist_store
