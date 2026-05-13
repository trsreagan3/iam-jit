"""Approver-side risk analysis.

Given a draft policy, produce a 1-10 risk score, list of risk factors, and
optionally an LLM-generated narrative. The score is fully deterministic; the
LLM can only ADD a narrative explanation — it cannot raise or lower the score.

Rubric (deterministic):
  10  literal Action: "*" anywhere; or *:* + Resource: "*"
   9  iam:* (any wildcard within iam); iam:PassRole + Resource: "*"
   8  service:* on a sensitive service (kms, secretsmanager, organizations)
   7  service:* on a normal service; or specific high-risk action with Resource: "*"
   6  any action in a sensitive service with Resource: "*"
   5  multiple wildcard-bearing actions across services
   4  Resource: "*" with non-sensitive services only
   3  scoped resources with broad action sets (read+list across multiple services)
   2  read/list on specific resources
   1  read on a single specific resource
"""

from __future__ import annotations

import datetime as _dt
import functools
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from policy_sentry.querying.actions import get_actions_with_access_level

from . import audit

if TYPE_CHECKING:
    from .llm import LLMBackend


def is_review_enabled() -> bool:
    """Return True if the deployment is configured to surface risk reviews.

    Risk scoring is part of the AI-feature surface — even though the score
    is deterministically computed from the policy, we treat it as part of
    the AI analysis layer. Deployments running in NoAI mode (`IAM_JIT_LLM=
    none` or no LLM env vars set) explicitly opted out of AI feedback,
    so the score is suppressed there. This keeps NoAI mode a clean
    "schema validation only" experience.
    """
    from .llm import NoOpBackend, get_backend

    return not isinstance(get_backend(), NoOpBackend)

_SENSITIVE_SERVICES = frozenset(
    {"secretsmanager", "kms", "ssm", "iam", "organizations", "sts"}
)

_HIGH_RISK_ACTIONS = frozenset(
    {
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "sts:AssumeRole",
    }
)

# Actions whose IAM access level is Write but which are commonly assumed to be
# read-only because they're often used for SELECT-style queries. The same API
# call can also DELETE/UPDATE depending on the SQL/query the caller passes —
# so they're a real outage risk and shouldn't be silently allowed in a
# read-only request without flagging.
_DECEPTIVE_WRITE_ACTIONS = frozenset(
    {
        "rds-data:ExecuteStatement",
        "rds-data:BatchExecuteStatement",
        "rds-data:ExecuteSql",
        "redshift-data:ExecuteStatement",
        "redshift-data:BatchExecuteStatement",
        "athena:StartQueryExecution",
        "athena:StopQueryExecution",
        "neptune-db:ReadDataViaQuery",
        "neptune-db:WriteDataViaQuery",
        "timestream:Select",
        "qldb:SendCommand",
    }
)


# Mutation actions whose IMPACT is high even when scoped to a single
# specific resource ARN. The default scorer treats single-resource
# scoped writes as low-risk; that's wrong for these — a single DNS
# record change or a single route-table modification can take down
# production. Each action here floors the request's risk score at
# 5 (medium) regardless of how narrow the resource scope is. Operators
# who want to auto-approve specific cases override via the planned
# admin risk-context input (see `docs/ROADMAP.md` § "Admin-
# configurable risk context").
_HIGH_IMPACT_MUTATION_ACTIONS = frozenset(
    {
        # DNS — affects all of production traffic routing
        "route53:ChangeResourceRecordSets",
        "route53:DeleteHostedZone",
        "route53:CreateHostedZone",
        # Network — single edit can isolate or open infra
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:ModifySecurityGroupRules",
        "ec2:ModifyVpcEndpoint",
        "ec2:CreateRoute",
        "ec2:DeleteRoute",
        "ec2:ReplaceRoute",
        # EC2 instance attribute changes — userData edits = arbitrary code exec
        "ec2:ModifyInstanceAttribute",
        # Load balancers — traffic-shifting
        "elasticloadbalancing:ModifyListener",
        "elasticloadbalancing:DeleteListener",
        "elasticloadbalancing:ModifyTargetGroupAttributes",
        # IAM — even single-policy changes are escalation surface
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        # S3 — bucket policy / public-access / object ACL changes
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl",
        "s3:PutObjectAcl",            # object-level public exposure
        "s3:PutPublicAccessBlock",
        "s3:DeletePublicAccessBlock",
        # KMS — key policy changes
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
        # CloudFront / WAF / SES — operational outage surface
        "cloudfront:DeleteDistribution",
        "cloudfront:UpdateDistribution",
        "wafv2:DeleteWebACL",
        # Lambda — code-execution swap + cross-account invoke grants
        "lambda:UpdateFunctionCode",
        "lambda:DeleteFunction",
        "lambda:AddPermission",       # grant cross-account/cross-service invoke
        "lambda:RemovePermission",
        # Secrets — credential rotation / theft surface
        "secretsmanager:UpdateSecret",
        "secretsmanager:PutSecretValue",
        "secretsmanager:RotateSecret",
        # SSM — RCE + secret rotation
        "ssm:SendCommand",            # RCE on EC2 fleet
        "ssm:StartSession",
        "ssm:PutParameter",           # secret rotation when SecureString
        # ECS — code deploy via task definition swap
        "ecs:UpdateService",
        "ecs:RegisterTaskDefinition",
        # CloudFormation — stack mutations = infra rewrites
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:UpdateStack",
        "cloudformation:CreateStack",
        # CodePipeline / CodeBuild — production deploy triggers
        "codepipeline:StartPipelineExecution",
        "codebuild:StartBuild",
    }
)


# Actions whose blast radius is severe enough that they should ALWAYS
# floor at 9 regardless of resource scope or conditions. These are the
# "this single API call can compromise the account / destroy evidence /
# remove governance" surface — auto-approve is never appropriate.
_CATASTROPHIC_ACTIONS = frozenset(
    {
        # Account governance — irreversible
        "account:CloseAccount",
        "organizations:LeaveOrganization",
        # Audit / evidence destruction
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
        # IAM total-compromise primitives — even a narrowly-resourced
        # AttachRolePolicy can swing in AdministratorAccess if the
        # attacker picks an admin-ish managed policy ARN.
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:CreateAccessKey",
        # KMS — schedule deletion of any key locks data forever
        "kms:ScheduleKeyDeletion",
    }
)


def _is_broad_resource(r: str) -> bool:
    """A resource string is 'broad' if it covers an unbounded set of items.

    Catches:
      - literal `*` (account-wide)
      - service-wide wildcards like `arn:aws:s3:::*`
      - bucket-level wildcards like `arn:aws:s3:::my-bucket/*` — every
        object in one bucket, which for a destructive action is still
        a wide blast radius (the whole bucket's contents).

    Path-narrowed wildcards like `arn:aws:s3:::bucket/prefix/*` or
    `arn:aws:s3:::bucket/team-a/files/*` are NOT broad — they're
    intentional scoping and shouldn't trip the wildcard rules.
    """
    if r == "*":
        return True
    if r.endswith(":*"):
        return True
    # Look at the resource-spec portion (everything after the ARN-prefix
    # colons). For `arn:aws:s3:::bucket/*`, the resource_spec is `bucket/*`.
    resource_spec = r.rsplit(":", 1)[-1] if r.startswith("arn:") else r
    if resource_spec == "*":
        return True
    if resource_spec.endswith("/*") and resource_spec.count("/") <= 1:
        # bucket/*   → 1 slash → broad
        # bucket/dir/* → 2 slashes → narrow (intentional path scoping)
        return True
    return False


def _resources_are_broad(resources: list[str]) -> bool:
    """True if any resource in the list is broad (see `_is_broad_resource`)."""
    return any(_is_broad_resource(r) for r in resources)


@functools.lru_cache(maxsize=None)
def _service_action_levels(service: str) -> dict[str, str]:
    """Return {action_name: access_level} for every action in `service`.

    Cached per-service so the policy_sentry lookups happen once per process.
    Returns an empty dict for unknown services.
    """
    levels: dict[str, str] = {}
    for level in ("Read", "List", "Write", "Tagging", "Permissions management"):
        try:
            for action_full in get_actions_with_access_level(service, level) or []:
                if ":" not in action_full:
                    continue
                _, name = action_full.split(":", 1)
                levels[name] = level
        except Exception:
            continue
    return levels


def _action_level(action: str) -> str | None:
    """Look up the IAM access level for a specific action.

    Returns one of "Read", "List", "Write", "Tagging", "Permissions management",
    or None if the action is wildcarded, malformed, or unknown to policy_sentry.
    """
    if not action or ":" not in action or "*" in action:
        return None
    service, name = action.split(":", 1)
    return _service_action_levels(service).get(name)


@dataclass
class ReviewAnalysis:
    risk_score: int
    risk_factors: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    deterministic_score: int = 1
    llm_narrative: str | None = None
    analyzed_at: str = ""
    analyzer: str = "deterministic"
    context_fingerprints: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_factors": list(self.risk_factors),
            "suggestions": list(self.suggestions),
            "deterministic_score": self.deterministic_score,
            "llm_narrative": self.llm_narrative,
            "analyzed_at": self.analyzed_at,
            "analyzer": self.analyzer,
            "context_fingerprints": dict(self.context_fingerprints),
        }


def analyze_policy(
    policy: dict[str, Any],
    request: dict[str, Any],
    *,
    backend: "LLMBackend | None" = None,
    extra_sensitive_services: tuple[str, ...] = (),
    extra_high_impact_actions: tuple[str, ...] = (),
) -> ReviewAnalysis:
    """Score the policy 1-10 deterministically; optionally annotate via LLM.

    When `backend` is provided, the LLM contributes a 2-3 sentence narrative
    summary AND a small set of additional risk-reduction suggestions that
    supplement the deterministic ones. The score itself is fully
    deterministic — the LLM cannot raise or lower it.

    `extra_sensitive_services` and `extra_high_impact_actions` extend
    the built-in calibration with admin-curated org-specific context.
    See docs/TUNING-RISK.md for the workflow (commit-or-UI).
    """
    score, factors, suggestions = _deterministic(
        policy, request,
        extra_sensitive_services=extra_sensitive_services,
        extra_high_impact_actions=extra_high_impact_actions,
    )
    analyzer = "deterministic"
    narrative: str | None = None

    if backend is not None:
        try:
            narrative = _narrate_with_llm(policy, request, backend, score, factors)
            analyzer = f"deterministic+{getattr(backend, 'name', 'llm')}"
        except Exception:
            narrative = None
        try:
            for s in _suggest_with_llm(policy, request, backend, factors):
                if s and s not in suggestions:
                    suggestions.append(s)
        except Exception:
            pass

    fingerprints = dict(audit._BOOT_FINGERPRINTS) if backend is not None else {}
    return ReviewAnalysis(
        risk_score=score,
        risk_factors=factors,
        suggestions=suggestions,
        deterministic_score=score,
        llm_narrative=narrative,
        analyzed_at=_dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        analyzer=analyzer,
        context_fingerprints=fingerprints,
    )


def _deterministic(
    policy: dict[str, Any],
    request: dict[str, Any],
    *,
    extra_sensitive_services: tuple[str, ...] = (),
    extra_high_impact_actions: tuple[str, ...] = (),
) -> tuple[int, list[str], list[str]]:
    # Effective sensitive-service set = built-in baseline + admin
    # additions. The admin context can EXPAND the set (mark more
    # services as sensitive) but not REMOVE built-ins.
    effective_sensitive = _SENSITIVE_SERVICES | set(extra_sensitive_services)
    effective_high_impact = _HIGH_IMPACT_MUTATION_ACTIONS | set(extra_high_impact_actions)
    if not policy or not isinstance(policy.get("Statement"), list):
        return 1, ["No statements in policy"], []

    score = 1
    factors: list[str] = []
    suggestions: list[str] = []

    spec = request.get("spec") or {}
    has_constraints = bool(spec.get("resource_constraints"))
    # If access_type is unset, don't impose a read-only constraint — only
    # apply the rule when the requester explicitly opted into read-only.
    access_type = (spec.get("access_type") or "").strip().lower()
    is_read_only = access_type == "read-only"
    duration_hours = _resolve_duration_hours(spec.get("duration") or {})

    # Read-only requests must contain only IAM-level Read or List actions.
    # Anything else gets flagged with a recommendation. Three classes of
    # mismatch, in increasing severity:
    #   - Wildcard mutation (e.g. s3:*)  → score 8, hard mismatch
    #   - Definite write action (e.g. s3:DeleteObject) → score 8, hard
    #   - "Deceptive write" (e.g. rds-data:ExecuteStatement) → score 6,
    #     softer because the action is often used for read-style queries
    #     but technically can mutate state.
    if is_read_only:
        for stmt in policy["Statement"]:
            if stmt.get("Effect") != "Allow":
                continue
            for action in _as_list(stmt.get("Action")):
                if ":" not in action:
                    continue

                # Wildcard handling first.
                if "*" in action:
                    if action == "*" or action.endswith(":*") or "*" in action.split(":", 1)[1][:3]:
                        score = max(score, 8)
                        factors.append(
                            f"Request marked read-only but policy includes wildcard `{action}`"
                        )
                        suggestions.append(
                            "Either flip access_type to read-write (and re-justify), or "
                            "narrow the action list to Get*/List*/Describe* only."
                        )
                    continue

                # Specific action: look up its IAM access level.
                level = _action_level(action)
                if level in ("Read", "List", None):
                    # Read/List are genuine reads. None means policy_sentry
                    # doesn't know the action — don't flag (could be a new
                    # service we haven't indexed yet).
                    continue

                if action in _DECEPTIVE_WRITE_ACTIONS:
                    score = max(score, 6)
                    factors.append(
                        f"`{action}` is IAM-classified as `{level}` despite being commonly used "
                        "for read-style queries. The same API call can DELETE/UPDATE with crafted input."
                    )
                    suggestions.append(
                        f"Either remove `{action}` (and use service-specific read-only APIs instead) "
                        "or flip access_type to read-write so the request is reviewed accordingly."
                    )
                else:
                    score = max(score, 8)
                    factors.append(
                        f"Request marked read-only but `{action}` is IAM-classified as `{level}` (mutates state)"
                    )
                    suggestions.append(
                        f"Remove `{action}` from the policy, or change access_type to read-write."
                    )

    for stmt in policy["Statement"]:
        if stmt.get("Effect") != "Allow":
            continue
        actions = _as_list(stmt.get("Action"))
        resources = _as_list(stmt.get("Resource"))

        # NotAction / NotResource handling. These keys are the inverse
        # form: "grant everything EXCEPT this set." A statement using
        # NotAction on Resource: `*` is effectively `*:*` minus the
        # explicit exclusions — i.e., near-total account access. AWS
        # itself flags `NotAction` as a footgun in the docs; we flag it
        # as a high-risk pattern unless the exclusion set is broad
        # enough that the residual surface is small. For now, any use
        # of NotAction with a wildcard resource floors the score at 9
        # (admin-minus-set is admin for practical purposes).
        not_actions = _as_list(stmt.get("NotAction"))
        not_resources = _as_list(stmt.get("NotResource"))
        if not_actions:
            resources_for_not = resources or ["*"]
            if any(r == "*" or r.endswith(":*") for r in resources_for_not):
                score = max(score, 9)
                excluded = ", ".join(not_actions[:3])
                factors.append(
                    f"`NotAction` with wildcard resource grants everything "
                    f"EXCEPT [{excluded}]. This is admin-minus-set, "
                    "treated as full account access for risk purposes."
                )
                suggestions.append(
                    "Replace `NotAction` with an explicit `Action` list of "
                    "the operations the role actually needs. NotAction is "
                    "almost always wider than the author intended."
                )
        if not_resources:
            if any(r == "*" or r.endswith(":*") for r in not_resources):
                # NotResource[*] is mathematically nothing (grants nothing),
                # so it's not actually a security risk — but it's a likely
                # mistake. Flag at low severity.
                score = max(score, 3)
                factors.append(
                    "`NotResource` containing `*` grants no access — "
                    "likely a misconfiguration."
                )
            else:
                # `NotResource: [<some-arns>]` means "every resource EXCEPT
                # these." With a wildcard action this is broad.
                if any("*" in a for a in actions):
                    score = max(score, 8)
                    factors.append(
                        f"`NotResource` with wildcard action grants the "
                        f"action on every resource EXCEPT {not_resources[:2]}. "
                        "This pattern is almost always broader than intended."
                    )
                    suggestions.append(
                        "Replace `NotResource` with an explicit `Resource` "
                        "list of the ARNs the role should reach."
                    )

        # Two senses of "wildcard" — kept distinct because they apply
        # to different rules:
        #
        # `wildcard_resource` (the strict sense): literal `*` or a
        # service-wide wildcard like `arn:aws:s3:::*`. Used by the
        # rules that flag *account-/service-wide* blast (e.g. the
        # "broad cross-resource read/access" suggestion) — the
        # standard idiom `["bucket", "bucket/*"]` for single-bucket
        # access should NOT trip these.
        #
        # `broad_blast_resource` (the inclusive sense): ALSO includes
        # bucket-level wildcards like `arn:aws:s3:::bucket/*`. Used by
        # the destructive-verb / high-impact-mutation rules — where
        # "I can wipe every object in this one bucket" is still a wide
        # enough blast to warrant flagging.
        wildcard_resource = any(r == "*" or r.endswith(":*") for r in resources)
        broad_blast_resource = _resources_are_broad(resources)

        if "*" in actions:
            return (
                10,
                ["Action `*` grants every AWS API call (full admin)"],
                ["Replace `*` with the specific API actions actually needed."],
            )

        for action in actions:
            if action == "*":
                continue
            service = action.split(":", 1)[0] if ":" in action else action

            if action.endswith(":*"):
                if service in effective_sensitive:
                    score = max(score, 9 if service in {"iam", "organizations"} else 8)
                    factors.append(
                        f"`{action}` grants every action in sensitive service `{service}`"
                    )
                    suggestions.append(
                        f"Replace `{action}` with the specific `{service}:` operations needed."
                    )
                else:
                    # Service-wildcard on broad resource (e.g. `ec2:*` on
                    # `Resource: *`) is near-admin within that service —
                    # every API, every resource. Floor at 8 to ensure it
                    # routes to human review even for non-sensitive
                    # services. Service-wildcard with narrow resource
                    # scoping (e.g. `s3:*` on a single bucket) still
                    # floors at 7 — the bucket is fully owned by this
                    # caller, but that's still "every action in s3".
                    score = max(score, 8 if wildcard_resource else 7)
                    factors.append(f"`{action}` grants every action in `{service}`")
                    suggestions.append(
                        f"Replace `{action}` with explicit `{service}:` actions."
                    )

            if "*" in action and not action.endswith(":*"):
                # e.g. iam:Create*
                if service in effective_sensitive:
                    score = max(score, 7)
                    factors.append(
                        f"Wildcard within sensitive service action: `{action}`"
                    )

            if action == "iam:PassRole":
                if wildcard_resource:
                    score = max(score, 9)
                    factors.append(
                        "`iam:PassRole` on Resource: `*` is a privilege-escalation path"
                    )
                    suggestions.append(
                        "Restrict iam:PassRole to specific role ARNs the requester needs to pass."
                    )
                else:
                    # Narrow PassRole still allows attaching ONE specific
                    # role to a service principal — if that role is more
                    # privileged than the caller, that's escalation. Always
                    # warrants a human glance; floor at 4 (medium tier).
                    score = max(score, 4)
                    factors.append(
                        "`iam:PassRole` is an escalation primitive — the "
                        "target role may have more privileges than the "
                        "caller. Even narrowly-scoped PassRole should be "
                        "reviewed against the role's actual policy."
                    )
                    suggestions.append(
                        "Confirm the target role's policy doesn't exceed "
                        "what the caller already has. Avoid auto-approve "
                        "even when PassRole is scoped to one role."
                    )
            elif action in _HIGH_RISK_ACTIONS and wildcard_resource:
                score = max(score, 7)
                factors.append(
                    f"`{action}` on Resource: `*` (broad access to "
                    f"{'secrets' if 'secret' in action.lower() else 'sensitive resource'})"
                )
                suggestions.append(
                    f"Scope `{action}` to specific ARNs (`{service}:` resources)."
                )
            elif (
                ":" in action
                and service in effective_sensitive
                and wildcard_resource
            ):
                score = max(score, 6)
                factors.append(
                    f"`{action}` on Resource: `*` touches sensitive service `{service}`"
                )

        # Destructive-action-on-wildcard check. Applies REGARDLESS of
        # access_type (the read-only mismatch path above only fires when
        # access_type=read-only, and a malicious or sloppy requester
        # marking a destructive request as read-write bypassed all the
        # other checks). For explicit specific actions like
        # `s3:DeleteObject` + `s3:DeleteBucket` on Resource: `*` — or on
        # `arn:aws:s3:::bucket/*` (every object in one bucket) — the
        # broad blast radius is the risk, not the service-sensitivity
        # classification. Uses `broad_blast_resource` so bucket-level
        # wildcards fire this rule too.
        for action in actions:
            if action == "*" or ":" not in action:
                continue
            if not broad_blast_resource:
                continue
            level = _action_level(action)
            # Explicitly destructive shapes regardless of IAM class —
            # the verb itself describes irreversibility. Floor at 7
            # so they ALWAYS route to human review (above threshold
            # 5 by default; admins can raise threshold up to floor 5).
            action_name = action.split(":", 1)[1] if ":" in action else action
            destructive_verbs = (
                "Delete", "Destroy", "Reset", "Terminate",
                "Disable", "Stop", "Revoke", "Cancel",
            )
            if action_name.startswith(destructive_verbs):
                # Floor at 8: a destructive verb on a broad resource is
                # always above the "auto-approve at threshold 5" line AND
                # above "medium" tier. The blast radius — every resource
                # in scope (literal `*`, service-wide, or one bucket) —
                # makes this categorically a human-review case.
                score = max(score, 8)
                factors.append(
                    f"Destructive action `{action}` on Resource: `*` "
                    f"(blast radius = every resource in this account)"
                )
                suggestions.append(
                    f"Scope `{action}` to specific resource ARNs (e.g., "
                    f"the one bucket/object/instance you actually need "
                    f"to operate on). Wildcard resource on a destructive "
                    "action is rarely intentional."
                )
            # Non-destructive but still IAM-class Write/Permissions/
            # Tagging actions on Resource: `*` are state-changing with
            # potentially broad reach. Floor at 6 (above default
            # threshold 5 but below the destructive floor).
            elif level in ("Write", "Permissions management", "Tagging"):
                score = max(score, 6)
                factors.append(
                    f"State-changing action `{action}` on Resource: `*` "
                    f"(IAM access level: {level})"
                )
                suggestions.append(
                    f"Scope `{action}` to specific resource ARNs so the "
                    "change can only affect the resources you've named."
                )

        if wildcard_resource and all(":" in a for a in actions):
            services_in_stmt = {a.split(":", 1)[0] for a in actions}
            if not (services_in_stmt & effective_sensitive):
                score = max(score, 4)
                services_label = ", ".join(sorted(services_in_stmt))
                factors.append(
                    f"Resource: `*` for {services_label} (broad cross-resource read/access)"
                )
                suggestions.append(
                    "Consider adding `resource_constraints` for "
                    f"{services_label} to scope to specific ARNs."
                )

        # High-impact mutation actions floor the score at 5 even
        # when the resource is a specific ARN. Single-resource scope
        # protects against scope creep but not against the action's
        # blast — a single DNS record change can move all of prod
        # traffic. See `_HIGH_IMPACT_MUTATION_ACTIONS` for the list.
        for action in actions:
            if action in effective_high_impact:
                score = max(score, 5)
                factors.append(
                    f"`{action}` is a high-impact mutation — a single "
                    "narrowly-scoped change can affect production "
                    "operations / security posture."
                )
                suggestions.append(
                    "High-impact mutations should not auto-approve "
                    "below medium-risk thresholds — set "
                    "IAM_JIT_AUTO_APPROVE_RISK_BELOW lower than 5 "
                    "to route this through human review."
                )

        # Catastrophic actions floor at 9 regardless of resource scope.
        # These are API calls where the blast radius is "the entire
        # account / its governance / its evidence trail" — auto-approve
        # is never appropriate even on a single narrowly-resourced ARN.
        # See `_CATASTROPHIC_ACTIONS`.
        for action in actions:
            if action in _CATASTROPHIC_ACTIONS:
                score = max(score, 9)
                factors.append(
                    f"`{action}` is catastrophic in blast radius "
                    "(account governance / IAM total compromise / "
                    "evidence destruction). Always route to human review."
                )
                suggestions.append(
                    f"Even with a specific resource ARN, `{action}` "
                    "should never auto-approve. If this is a legitimate "
                    "operational need, justify why a human shouldn't "
                    "approve it."
                )

    if not factors:
        # No flags fired — score depends on resource specificity.
        if has_constraints:
            score = max(score, 2)
            factors.append("Scoped to specific resources via resource_constraints")
        else:
            factors.append("All statements are scoped or limited; no broad patterns")

    if is_read_only and not any("read-only" in f.lower() for f in factors):
        # Surface the read-only marker as a positive signal for the approver.
        factors.append("Request explicitly marked read-only (cannot mutate state)")

    # Duration adjustment — longer grants are riskier for the same policy.
    # The adjustment scales with the base score so a low-risk policy for
    # a long time stays low-risk, but a medium/high-risk policy for an
    # extended window gets pushed up.
    if duration_hours is not None and duration_hours > 24:
        days = duration_hours / 24
        adj = 0
        if score >= 4 and duration_hours > 24 * 7:  # > 1 week + non-trivial baseline
            adj = 1
        if score >= 6 and duration_hours > 24 * 30:  # > 1 month + meaningful baseline
            adj = max(adj, 2)
        if score >= 8 and duration_hours > 24:  # > 1 day on already-high-risk
            adj = max(adj, 1)
        if adj > 0:
            score = min(10, score + adj)
            factors.append(
                f"Duration {days:.0f}+ days — extended grant raises risk on top "
                "of the base policy score."
            )
            suggestions.append(
                "Consider a shorter window (re-request when needed) to reduce blast radius."
            )

    # Deduplicate while preserving order.
    factors = _dedupe(factors)
    suggestions = _dedupe(suggestions)
    return score, factors, suggestions


def _resolve_duration_hours(duration: dict[str, Any]) -> int | None:
    """Return the grant duration in hours from a `spec.duration` block.

    The schema requires exactly one of `duration_hours` or `not_after`; we
    handle both. For `not_after` we compute hours from now() so the
    effective window — not the calendar size — drives the risk adjustment.
    """
    if "duration_hours" in duration:
        try:
            return int(duration["duration_hours"])
        except (TypeError, ValueError):
            return None
    not_after = duration.get("not_after")
    if not isinstance(not_after, str):
        return None
    try:
        deadline = _dt.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    except ValueError:
        return None
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=_dt.UTC)
    delta = deadline - _dt.datetime.now(_dt.UTC)
    if delta.total_seconds() <= 0:
        return None
    return max(1, int(delta.total_seconds() / 3600))


def _narrate_with_llm(
    policy: dict[str, Any],
    request: dict[str, Any],
    backend: "LLMBackend",
    deterministic_score: int,
    factors: list[str],
) -> str | None:
    """Ask the LLM for a 2-3 sentence approver-facing summary.

    The LLM is bounded to commentary only — it cannot change the score or
    the factor list. We forward the policy/context and ask for narrative.
    """
    description = (request.get("spec") or {}).get("description") or ""
    services, _ = backend.refine(
        description=(
            "You are reviewing an IAM policy on behalf of a security/infra approver. "
            "Below is the policy and the requester's task description. "
            "Return a JSON object with one key `services` containing 1-3 short bullet-style "
            "concerns the approver should weigh, drawn from the actual policy and description. "
            "Do not invent actions; do not output IAM action strings; "
            "do not produce free text outside the JSON. "
            "IMPORTANT: this iam-jit instance can only see what's in the policy/description "
            "and any admin-provided org-context — it has NO access to the user's application "
            "code, repositories, kubeconfigs, the internet, or AWS account contents. "
            "Frame concerns from that limited vantage; recommend the user supplement with "
            "local context (e.g., a local AI agent that can read their codebase) when needed. "
            f"Deterministic risk score: {deterministic_score}/10. "
            f"Deterministic factors: {factors!r}. "
            f"Policy: {policy!r}. "
            f"Description: {description!r}"
        ),
        initial_services=[],
        initial_actions=[],
    )
    if not services:
        return None
    bullets = [s for s in services if isinstance(s, str) and s.strip()]
    if not bullets:
        return None
    return " ".join(bullets[:3])


def _suggest_with_llm(
    policy: dict[str, Any],
    request: dict[str, Any],
    backend: "LLMBackend",
    factors: list[str],
) -> list[str]:
    """Ask the LLM for concrete risk-reduction suggestions.

    Supplements the deterministic suggestions with LLM-generated ones.
    The LLM is constrained to short, actionable strings — never raw IAM
    actions or policy JSON.
    """
    description = (request.get("spec") or {}).get("description") or ""
    services, _ = backend.refine(
        description=(
            "You help a developer reduce the risk of their IAM policy request. "
            "Below is the policy + task description + the deterministic risk "
            "factors that already fired. "
            "Return a JSON object with one key `services` containing 1-3 short, "
            "actionable suggestions the requester could take to lower the risk. "
            "Each suggestion is a single sentence. Do NOT output IAM action strings "
            "or policy JSON; do NOT repeat the deterministic suggestions verbatim. "
            "IMPORTANT: this iam-jit instance can only see what's in the policy/description "
            "and any admin-provided org-context — it has NO access to the user's application "
            "code, repositories, kubeconfigs, the internet, or AWS account contents. "
            "Where the right scoping requires more context than is available, recommend the "
            "requester regenerate their policy locally with a tool like Claude Code that can "
            "read their actual code/manifests. "
            f"Deterministic factors: {factors!r}. "
            f"Policy: {policy!r}. "
            f"Description: {description!r}"
        ),
        initial_services=[],
        initial_actions=[],
    )
    if not services:
        return []
    return [s for s in services if isinstance(s, str) and s.strip()][:3]


def _as_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out
