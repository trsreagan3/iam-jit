# #324f — recommender Deny-injection from dynamic-deny rules.
"""Defense-in-depth half of the dynamic-deny model: embed an explicit
``Deny`` statement for every active dynamic-deny rule into any role
the iam-jit recommender issues.

The cross-product design lives at ``docs/DYNAMIC-DENY-RULES.md``
(section "Defense-in-depth model"). The bouncer path (#324a-e)
short-circuits AT REQUEST TIME — but agents can bypass the bouncer by
calling AWS directly with stolen creds, OR by using a role minted
BEFORE the deny landed. The recommender path (this module) closes
the second gap by embedding the deny into every NEW role's inline
policy. AWS evaluates explicit-Deny with absolute precedence over any
Allow — so even if the role is later used with the bouncer
sidestepped, the embedded Deny still fires inside AWS's own
evaluator.

Per ``[[creates-never-mutates]]`` we ONLY embed into newly-issued
roles. Existing roles minted before a deny lands keep the
bouncer-only enforcement path until they expire at their TTL.

Per ``[[ibounce-honest-positioning]]`` the embedding is honest about
its precondition: only rules where ``applied_to`` contains
``ibounce`` AND ``applies_to_recommender`` is true get embedded. A
rule routed to kbounce/dbounce/gbounce only does NOT bleed into the
IAM role policy — the design doc names that an honest separation
between protocol-level denies (k8s namespaces, hostnames, SQL
endpoints) and IAM-evaluator denies (AWS ARN patterns).

Per ``[[scorer-is-ground-truth]]`` the embedding is deterministic:
take the active ruleset (matcher's filter view), enumerate
ibounce-routed + recommender-eligible rules, emit one Deny statement
per rule with the rule's targets as Resource.

Module surface:

  * :func:`build_deny_statements(ruleset)` — pure function. Given a
    :class:`RuleSet`, return the list of policy Statement dicts to
    append. The caller decides where to put them in the final
    policy (provision.py appends to the inline policy's Statement
    list AFTER the time-condition augmentation).
  * :func:`inject_into_policy(policy, ruleset)` — convenience wrapper
    that takes a full policy + ruleset and returns the augmented
    policy with the Deny statements appended. Returns a new dict;
    does NOT mutate the input (per
    ``[[creates-never-mutates]]``).
  * :func:`embedded_rule_ids(ruleset)` — list of rule ids embedded.
    Surfaces in the audit event for operator verification.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from .types import Rule, RuleSet


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


def _eligible_rules(ruleset: RuleSet) -> list[Rule]:
    """Filter ``ruleset.rules`` down to the rules eligible for
    recommender embedding.

    Inclusion criteria (per the design doc + ``[[ibounce-honest-positioning]]``):
      1. ``applied_to`` contains ``"ibounce"`` — the loader already
         filters the ibounce snapshot down to this; defense-in-depth
         we re-check in case a caller passes an unfiltered ruleset.
      2. ``applies_to_recommender`` is true — operator opt-out for the
         per-rule "bouncer only" toggle.
      3. Not expired AT EMBED TIME — the loader drops rules expired
         at LOAD time, but a long-lived role-issuance session could
         see a rule expire mid-life. We re-check here against
         ``datetime.now(UTC)``.
      4. At least one target — the loader rejects rules with zero
         targets, but defensive.
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    out: list[Rule] = []
    for r in ruleset.rules:
        if "ibounce" not in r.applied_to:
            continue
        if not r.applies_to_recommender:
            continue
        if r.expires_at is not None and r.expires_at <= now:
            continue
        if not r.targets:
            continue
        out.append(r)
    return out


def build_deny_statements(ruleset: RuleSet) -> list[dict[str, Any]]:
    """Return the list of IAM policy Statement dicts to append to a
    newly-issued role's inline policy.

    Each statement carries:
      * ``Sid: "dynamic-deny-<id>"`` — operator reading the role policy
        in the AWS console / via CLI sees which rule contributed.
        The Sid format matches the design doc's contract (used by
        the role-policy review UI in v1.1).
      * ``Effect: "Deny"`` — explicit-Deny beats any Allow in IAM
        evaluation; this is what makes the defense-in-depth claim
        honest.
      * ``Action: "*"`` — broad action; the design doc specifies that
        dynamic-denies refuse THE RESOURCE entirely, regardless of
        action verb. An operator who wants action-narrowed denies
        uses static profile rules instead.
      * ``Resource: <rule.targets>`` — verbatim from the rule. The
        ``secret:NAME`` shorthand is NOT expanded here (an ARN is
        what the IAM evaluator expects); a future v1.1 can resolve
        the shorthand to a full Secrets Manager ARN at embed time.
        For v1.0 we filter out shorthand targets + log a hint via
        the caller's audit path (provision.py emits the verbatim
        Resource list so an operator can see the issue).

    Returns ``[]`` when no rules are eligible (empty ruleset OR all
    rules opt-out of recommender embedding OR all rules expired).
    """
    statements: list[dict[str, Any]] = []
    for r in _eligible_rules(ruleset):
        arn_targets = _arn_targets(r)
        if not arn_targets:
            # All of this rule's targets were the ``secret:NAME``
            # shorthand — IAM's evaluator can't take that resource
            # directly. Skip (the bouncer path still enforces; an
            # operator gets the message via the caller's audit
            # surface that names the rule id with zero
            # embedded_resource_count).
            continue
        statements.append({
            "Sid": _sid_for_rule(r.id),
            "Effect": "Deny",
            "Action": "*",
            "Resource": arn_targets if len(arn_targets) > 1 else arn_targets[0],
        })
    return statements


def embedded_rule_ids(ruleset: RuleSet) -> list[str]:
    """Return the list of rule ids that will be embedded by
    :func:`build_deny_statements`. Audit-side convenience for the
    ``unmapped.iam_jit.ext.embedded_dynamic_denies`` field on the
    provisioning event so an operator can verify which rules
    contributed without re-running the embed.
    """
    out: list[str] = []
    for r in _eligible_rules(ruleset):
        if not _arn_targets(r):
            continue
        out.append(r.id)
    return out


def inject_into_policy(
    policy: dict[str, Any], ruleset: RuleSet
) -> dict[str, Any]:
    """Return a NEW policy with dynamic-deny Statement(s) appended.

    Behaviour:
      * Empty ruleset / no eligible rules -> returns the input policy
        unchanged (a shallow copy so the caller can't observe a
        non-mutation contract violation).
      * Otherwise builds a copy of the policy whose ``Statement`` list
        contains the original statements followed by the dynamic-deny
        statements. Original statements are preserved verbatim
        (including any caller-side time-condition augmentation per
        ``provision._augment_policy_with_time_condition``).

    Per ``[[creates-never-mutates]]`` we never mutate the input dict
    in place.
    """
    extra = build_deny_statements(ruleset)
    if not extra:
        return {
            "Version": policy.get("Version", "2012-10-17"),
            "Statement": list(policy.get("Statement") or []),
        }
    return {
        "Version": policy.get("Version", "2012-10-17"),
        "Statement": list(policy.get("Statement") or []) + extra,
    }


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _arn_targets(rule: Rule) -> list[str]:
    """Return the rule's targets filtered to AWS ARN globs. The loader
    already filters the ibounce snapshot down to ARN + ``secret:``
    shorthand targets; here we drop the shorthand because the IAM
    evaluator wants a real ARN in ``Resource``.

    Future: a v1.1 enhancement could resolve ``secret:NAME`` to
    ``arn:aws:secretsmanager:*:*:secret:NAME*`` at embed time. Tracked
    via the design doc's "Honest caveats" section.
    """
    out: list[str] = []
    for t in rule.targets:
        if (
            t.startswith("arn:aws:")
            or t.startswith("arn:aws-cn:")
            or t.startswith("arn:aws-us-gov:")
        ):
            out.append(t)
    return out


def _sid_for_rule(rule_id: str) -> str:
    """Build the ``Sid`` value for a rule's embedded statement.

    IAM Sid grammar: ``[A-Za-z0-9]`` only (no underscores, no dashes,
    no spaces). The rule id is ``dd_<26-char ULID>`` — the underscore
    is illegal in Sid. We strip it + camel-case the rule id:
    ``dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C`` ->
    ``dynamicdenydd01HZ8VKJ6Y2BJTPVZ3PNX97A2C``.

    The prefix ``dynamicdeny`` is fixed so an operator reading a role
    policy can pattern-match all dynamic-deny statements (e.g.
    ``grep dynamicdeny role-policy.json``) without parsing JSON.
    """
    cleaned = rule_id.replace("_", "")
    return f"dynamicdeny{cleaned}"


__all__ = [
    "build_deny_statements",
    "embedded_rule_ids",
    "inject_into_policy",
]
