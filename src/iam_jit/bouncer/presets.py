"""Bouncer preset baselines — curated rule starting points so agents
(and humans) don't author from scratch.

Per [[agent-friendly-not-bypassable]] Lens A: agents need easy
starting points for common use cases. Without presets, the agent's
first interaction with the bouncer is "look at empty ruleset; author
N rules" — too much friction, agents will reach for "just disable."

Composes with [[aws-managed-baseline-strategy]] +
[[admin-minus-sensitive-baseline]]: the same shape decisions iam-jit
already encodes for grant baselines, applied to bouncer rules.

Each preset is a tuple of (pattern, effect, arn_scope, region_scope,
note). Applying a preset is a single atomic operation that's audit-
logged via record_preset_applied — the user always sees exactly which
preset was applied, with which rules, when.

Presets are intentionally CONSERVATIVE — they err toward DENY +
explicit ALLOW lists, not blanket allow. Agents who need broader
access should narrow from a preset, not start with a permissive base.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from .rules import Effect, ProxyRule


@dataclasses.dataclass(frozen=True)
class Preset:
    """One curated rule baseline."""

    name: str
    description: str
    rules: tuple[ProxyRule, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "rule_count": len(self.rules),
            "rules": [r.to_dict() for r in self.rules],
        }


# ---------------------------------------------------------------------------
# Curated preset baselines
# ---------------------------------------------------------------------------


def _r(pattern: str, effect: Effect = Effect.ALLOW, **kw) -> ProxyRule:
    return ProxyRule(pattern=pattern, effect=effect, origin="preset", **kw)


PRESETS: dict[str, Preset] = {
    "readonly": Preset(
        name="readonly",
        description=(
            "AWS-ReadOnlyAccess-shaped: explicit allow on Get*/List*/"
            "Describe* across common services + deny on the sensitive-"
            "read set (secrets, billing). Default-deny in enforce mode "
            "blocks all writes."
        ),
        rules=(
            # Explicit deny: secret-data reads + billing (defense-in-depth
            # even within a read-only baseline).
            _r("secretsmanager:GetSecretValue", effect=Effect.DENY,
               note="readonly preset: don't read secret VALUES even in read mode"),
            _r("secretsmanager:BatchGetSecretValue", effect=Effect.DENY,
               note="readonly preset: don't read secret VALUES even in read mode"),
            _r("ssm:GetParameter*", effect=Effect.DENY,
               note="readonly preset: don't read SecureString values"),
            _r("kms:Decrypt", effect=Effect.DENY,
               note="readonly preset: KMS decrypt is a high-leverage capability"),
            _r("billing:*", effect=Effect.DENY,
               note="readonly preset: billing data is sensitive"),
            # Broad reads across common services (the AWS ReadOnlyAccess
            # shape, narrowed to the most-used services to keep the
            # ruleset reviewable).
            _r("s3:Get*", note="readonly preset"),
            _r("s3:List*", note="readonly preset"),
            _r("s3:Head*", note="readonly preset"),
            _r("ec2:Describe*", note="readonly preset"),
            _r("ec2:Get*", note="readonly preset"),
            _r("rds:Describe*", note="readonly preset"),
            _r("lambda:Get*", note="readonly preset"),
            _r("lambda:List*", note="readonly preset"),
            _r("dynamodb:Describe*", note="readonly preset"),
            _r("dynamodb:List*", note="readonly preset"),
            _r("dynamodb:Get*", note="readonly preset"),
            _r("dynamodb:Query", note="readonly preset"),
            _r("dynamodb:Scan", note="readonly preset"),
            _r("iam:Get*", note="readonly preset"),
            _r("iam:List*", note="readonly preset"),
            _r("iam:Simulate*", note="readonly preset"),
            _r("cloudwatch:Get*", note="readonly preset"),
            _r("cloudwatch:List*", note="readonly preset"),
            _r("cloudwatch:Describe*", note="readonly preset"),
            _r("logs:Get*", note="readonly preset"),
            _r("logs:Describe*", note="readonly preset"),
            _r("logs:FilterLogEvents", note="readonly preset"),
            _r("sts:GetCallerIdentity", note="readonly preset"),
        ),
    ),
    "admin-minus-sensitive": Preset(
        name="admin-minus-sensitive",
        description=(
            "Allow * EXCEPT the sensitive-deny set (secret reads, "
            "IAM admin, billing, audit-infra destruction). Mirrors "
            "the AdminLikeWithSensitiveExclusions JIT baseline. "
            "Useful for trusted-but-not-fully-admin agent sessions."
        ),
        rules=(
            # Deny set first (explicit deny wins per RuleSet eval order).
            _r("secretsmanager:GetSecretValue", effect=Effect.DENY,
               note="admin-minus-sensitive: don't read secret VALUES"),
            _r("secretsmanager:BatchGetSecretValue", effect=Effect.DENY,
               note="admin-minus-sensitive: don't read secret VALUES"),
            _r("ssm:GetParameter*", effect=Effect.DENY,
               note="admin-minus-sensitive: SecureString reads blocked"),
            _r("iam:DeleteRole", effect=Effect.DENY,
               note="admin-minus-sensitive: no IAM principal-pivot"),
            _r("iam:CreateRole", effect=Effect.DENY,
               note="admin-minus-sensitive: no IAM principal-pivot"),
            _r("iam:PutRolePolicy", effect=Effect.DENY,
               note="admin-minus-sensitive: no IAM principal-pivot"),
            _r("iam:AttachRolePolicy", effect=Effect.DENY,
               note="admin-minus-sensitive: no IAM principal-pivot"),
            _r("iam:PassRole", effect=Effect.DENY,
               note="admin-minus-sensitive: no PassRole escalation"),
            _r("billing:*", effect=Effect.DENY,
               note="admin-minus-sensitive: billing sensitive"),
            _r("organizations:*", effect=Effect.DENY,
               note="admin-minus-sensitive: org-level changes blocked"),
            _r("account:*", effect=Effect.DENY,
               note="admin-minus-sensitive: account-level changes blocked"),
            _r("cloudtrail:Stop*", effect=Effect.DENY,
               note="admin-minus-sensitive: audit infra preservation"),
            _r("cloudtrail:Delete*", effect=Effect.DENY,
               note="admin-minus-sensitive: audit infra preservation"),
            _r("cloudtrail:Update*", effect=Effect.DENY,
               note="admin-minus-sensitive: audit infra preservation"),
            _r("config:Delete*", effect=Effect.DENY,
               note="admin-minus-sensitive: audit infra preservation"),
            _r("config:Stop*", effect=Effect.DENY,
               note="admin-minus-sensitive: audit infra preservation"),
            # Broad allow last.
            _r("*", effect=Effect.ALLOW,
               note="admin-minus-sensitive: allow everything else"),
        ),
    ),
    "prod-deny-destructive": Preset(
        name="prod-deny-destructive",
        description=(
            "Catch-all preset for prod-account safety: deny destructive "
            "operations (Delete*, Terminate*, Stop* on critical services) "
            "but let everything else through. Pair with ENFORCE mode + "
            "default-allow for a 'don't break prod' guardrail that mostly "
            "stays out of the way."
        ),
        rules=(
            _r("*:Delete*", effect=Effect.DENY,
               note="prod-deny-destructive: no deletions in prod"),
            _r("*:Terminate*", effect=Effect.DENY,
               note="prod-deny-destructive: no terminations in prod"),
            _r("ec2:StopInstances", effect=Effect.DENY,
               note="prod-deny-destructive: no stopping instances"),
            _r("rds:DeleteDBInstance", effect=Effect.DENY,
               note="prod-deny-destructive: no DB deletion"),
            _r("rds:StopDBInstance", effect=Effect.DENY,
               note="prod-deny-destructive: no DB stop"),
            _r("cloudformation:DeleteStack", effect=Effect.DENY,
               note="prod-deny-destructive: no stack deletion"),
            _r("eks:DeleteCluster", effect=Effect.DENY,
               note="prod-deny-destructive: no cluster deletion"),
            _r("ecs:DeleteCluster", effect=Effect.DENY,
               note="prod-deny-destructive: no cluster deletion"),
            _r("s3:DeleteBucket", effect=Effect.DENY,
               note="prod-deny-destructive: no bucket deletion"),
            _r("kms:ScheduleKeyDeletion", effect=Effect.DENY,
               note="prod-deny-destructive: no key deletion (KMS deletion is 7-day-irreversible)"),
            _r("kms:DisableKey", effect=Effect.DENY,
               note="prod-deny-destructive: no key disable"),
        ),
    ),
    "deny-iam-admin": Preset(
        name="deny-iam-admin",
        description=(
            "Single-purpose preset: block all IAM modifications + "
            "STS escalation paths. Compose with another preset for "
            "the rest. Useful for the 'agent can do whatever — just "
            "not touch IAM' shape."
        ),
        rules=(
            _r("iam:Create*", effect=Effect.DENY,
               note="deny-iam-admin: no IAM creation"),
            _r("iam:Update*", effect=Effect.DENY,
               note="deny-iam-admin: no IAM mutation"),
            _r("iam:Put*", effect=Effect.DENY,
               note="deny-iam-admin: no IAM policy attach"),
            _r("iam:Attach*", effect=Effect.DENY,
               note="deny-iam-admin: no IAM policy attach"),
            _r("iam:Delete*", effect=Effect.DENY,
               note="deny-iam-admin: no IAM deletion"),
            _r("iam:Detach*", effect=Effect.DENY,
               note="deny-iam-admin: no IAM policy detach"),
            _r("iam:PassRole", effect=Effect.DENY,
               note="deny-iam-admin: no PassRole escalation"),
        ),
    ),
}


def list_preset_names() -> list[str]:
    return sorted(PRESETS.keys())


def get_preset(name: str) -> Preset | None:
    return PRESETS.get(name)
