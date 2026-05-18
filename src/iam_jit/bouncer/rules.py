"""Bouncer rule data model + matcher.

A ProxyRule is a (pattern, effect, scope) triple:

- pattern: `service:action_glob` (e.g. `s3:GetObject`, `s3:Put*`, `*:Delete*`)
- effect: ALLOW or DENY (the decision when this rule matches)
- scope: optional ARN glob to narrow the match (e.g. `arn:aws:s3:::my-bucket/*`)
- region_scope: optional region glob (e.g. `us-east-1`, `us-*`)

Rule evaluation order (per blacklist module's battle-tested pattern):
explicit DENY beats explicit ALLOW; first matching rule wins WITHIN
each effect class. The decision module composes this with mode +
default-policy to reach a final Decision.

Per the user's UX guidance ([[safety-mode-lean-permissive]]): the
rule shape is intentionally minimal — service:action + ARN glob +
region. No condition keys, no IP CIDRs, no time-of-day. Users who
need that complexity can fall back to an IAM permissions boundary.
Bouncer is the "Little Snitch" layer, not a second IAM engine.

Per [[scorer-is-ground-truth]] precedent: rule matching is
deterministic. No LLM in this path. Predictable behavior is the
whole point of a gate.
"""

from __future__ import annotations

import dataclasses
import re
from enum import Enum
from typing import Any


class Effect(str, Enum):
    """A rule's effect when matched."""

    ALLOW = "allow"
    DENY = "deny"


@dataclasses.dataclass(frozen=True)
class ProxyRule:
    """One rule in the bouncer's RuleSet."""

    pattern: str  # `service:action_glob` (required)
    effect: Effect = Effect.ALLOW
    # Optional ARN-glob scope. If None or "*", matches any resource.
    # Examples: "arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*",
    #           "arn:aws:dynamodb:us-east-1:111111111111:table/Users".
    arn_scope: str | None = None
    # Optional region-glob scope. If None or "*", matches any region.
    region_scope: str | None = None
    # Optional human note (why this rule exists, who added it).
    note: str | None = None
    # Origin: "user" (added explicitly) / "learn" (auto-captured in
    # learn mode) / "default" (built-in baseline) / "bulk-allow-time-
    # bounded" (#253 — operator picked options 2/3/4 in `prompts
    # bulk-answer`) / "prompt" (#5 — answered a single deny-prompt).
    origin: str = "user"
    # #253 (bulk-prompt-answer-ux): optional wall-clock UTC expiry as
    # an ISO-8601 Z-suffixed string. None means the rule lives forever
    # (matches pre-#253 behavior; the vast majority of rules). When
    # set, the sweeper (`expire_rules_at`) filters this rule out of
    # the active RuleSet as soon as `now >= expires_at` — without
    # deleting the row, so the audit chain keeps a complete record of
    # what the rule WAS per [[creates-never-mutates]] spirit.
    #
    # Stored as a string (not datetime) because the store layer's
    # other timestamp columns (created_at, etc.) are also string-ISO;
    # keeps SQLite comparison + JSON serialisation uniform.
    expires_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "effect": self.effect.value,
            "arn_scope": self.arn_scope,
            "region_scope": self.region_scope,
            "note": self.note,
            "origin": self.origin,
            "expires_at": self.expires_at,
        }


def parse_pattern(pattern: str) -> tuple[str, str] | None:
    """Split a `service:action_glob` pattern. Returns (service, action)
    or None if malformed.

    Accepted shapes:
    - `service:action_glob`  e.g. `s3:GetObject`, `s3:Put*`, `iam:*`
    - `*:action_glob`        e.g. `*:Delete*` (cross-service deny pattern,
      essential for prod-deny-destructive presets)
    - `*`                    bare wildcard = match any service:any action
      (normalized to `*:*`)

    Action may include `*` and `?`. Service may be either a bare prefix
    (lowercased) or `*`. Empty parts and whitespace are rejected.

    Mirrors AWS IAM policy spec (where `*` is the legal "any" wildcard).
    """
    if not isinstance(pattern, str):
        return None
    token = pattern.strip()
    if not token or " " in token:
        return None
    # Bare `*` = any service, any action (the catch-all per AWS IAM spec)
    if token == "*":
        return "*", "*"
    parts = token.split(":")
    if len(parts) != 2:
        return None
    service, action = parts
    if not service or not action:
        return None
    # Service may be `*` (cross-service patterns) or a bare prefix.
    # If it has a `*` anywhere else (e.g. `s*` partial wildcard), reject
    # — AWS service prefixes are flat strings, not globs.
    if service != "*" and "*" in service:
        return None
    return service.lower(), action


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate an AWS-IAM-style glob (only `*` and `?` are meta;
    `*` matches any run of chars, `?` matches one char) into a
    compiled regex.

    WB23 LOW-23-02 closure: `fnmatch.fnmatchcase` admits `[abc]`
    character-class syntax that AWS IAM policy globs do NOT support.
    A user writing a literal `[` in an action / ARN pattern would
    get character-class semantics they didn't ask for. This helper
    matches AWS's documented glob spec exactly: `*` and `?` only.
    """
    out_chars: list[str] = []
    for ch in pattern:
        if ch == "*":
            out_chars.append(".*")
        elif ch == "?":
            out_chars.append(".")
        else:
            out_chars.append(re.escape(ch))
    return re.compile(r"\A" + "".join(out_chars) + r"\Z")


def _aws_glob_match(value: str, pattern: str) -> bool:
    """True iff `value` matches the AWS-IAM-style glob `pattern`."""
    return _glob_to_regex(pattern).match(value) is not None


def rule_matches(
    rule: ProxyRule,
    *,
    service: str,
    action: str,
    arn: str | None,
    region: str | None,
) -> bool:
    """Check whether `rule` matches a parsed request.

    All comparisons are case-sensitive on the AWS-canonical form
    EXCEPT service prefix, which is lowercased per AWS docs
    (service prefixes are always lowercase like "s3", "ec2", "iam").
    """
    parsed = parse_pattern(rule.pattern)
    if parsed is None:
        # Malformed rule — never matches. Caller should surface this
        # via list_rules() so the user can fix or remove.
        return False
    rule_service, rule_action = parsed

    # Service comparison: `*` in the rule matches any service.
    if rule_service != "*" and rule_service != service.lower():
        return False

    if not _aws_glob_match(action, rule_action):
        return False

    if rule.arn_scope and rule.arn_scope != "*":
        if arn is None:
            # Rule scopes by ARN but request has no resolvable ARN —
            # be conservative: don't match. Caller falls through to
            # default policy.
            return False
        if not _aws_glob_match(arn, rule.arn_scope):
            return False

    if rule.region_scope and rule.region_scope != "*":
        if region is None:
            return False
        if not _aws_glob_match(region, rule.region_scope):
            return False

    return True


@dataclasses.dataclass
class RuleSet:
    """Ordered collection of ProxyRules with deterministic evaluation.

    Evaluation order per [[safety-mode-lean-permissive]] + the
    blacklist-module precedent:
      1. Any matching DENY rule  → Effect.DENY (explicit deny beats allow)
      2. Else any matching ALLOW → Effect.ALLOW
      3. Else None (caller falls to mode default)

    This mirrors AWS IAM's policy evaluation but is implemented from
    scratch — bouncer rules are a separate language with simpler
    semantics, not a re-evaluation of IAM policy itself.
    """

    rules: list[ProxyRule] = dataclasses.field(default_factory=list)

    def add(self, rule: ProxyRule) -> None:
        self.rules.append(rule)

    def evaluate(
        self,
        *,
        service: str,
        action: str,
        arn: str | None = None,
        region: str | None = None,
    ) -> tuple[Effect, ProxyRule] | None:
        """Return the (effect, matched_rule) pair, or None if no rule
        matched. Caller (decisions module) decides what 'no match'
        means based on current mode."""
        matched_deny: ProxyRule | None = None
        matched_allow: ProxyRule | None = None
        for r in self.rules:
            if not rule_matches(
                r, service=service, action=action, arn=arn, region=region
            ):
                continue
            if r.effect == Effect.DENY and matched_deny is None:
                matched_deny = r
            elif r.effect == Effect.ALLOW and matched_allow is None:
                matched_allow = r
        if matched_deny is not None:
            return (Effect.DENY, matched_deny)
        if matched_allow is not None:
            return (Effect.ALLOW, matched_allow)
        return None
