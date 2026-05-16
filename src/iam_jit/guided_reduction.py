"""Guided reduction walkthrough — agentless-user path for narrowing
a baseline policy via a curated checklist.

Per [[ui-guided-reduction-pro-tier]] (Enterprise plugin) — the OSS
foundation: a static checklist of ~10 high-impact reduction options
+ a function that maps user selections to `reductions.apply_reductions`
calls. The agentless UI user picks what they DON'T need; the result
is a reduced policy + recipe.

The Enterprise plugin (post-launch, proprietary) adds on top:
- Customer-configurable checklist via admin config
- LLM-driven branching ("you said no RDS — also no DynamoDB?")
- Web UI rendering with progressive disclosure

This module is OSS scaffolding — works fully without any LLM. An
agentless user can step through the checklist + get a reduced
policy via the MCP tools.

Per [[scorer-is-ground-truth]]: this module only TRANSFORMS the
policy. The scorer always evaluates the result; checklist selections
never bypass scoring.

Per the user's UX direction 2026-05-16: the checklist is ~10 items
curated by score-impact (the items whose presence/absence shifts
the scorer ≥1 point). NOT exhaustive — surfacing every AWS service
would be UI noise.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from .reductions import apply_reductions


@dataclasses.dataclass(frozen=True)
class ReductionChecklistItem:
    """One row in the reduction-walkthrough checklist."""

    id: str  # short stable identifier ("deny-secrets", "deny-rds", ...)
    label: str  # human-friendly checkbox label
    description: str  # why this matters; what gets denied
    reduction_axis: str  # "deny_services" | "deny_specific_services" | etc.
    reduction_values: tuple[str, ...]  # services / accounts / regions to apply
    default_checked: bool = False  # pre-checked when shown to the user

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "reduction_axis": self.reduction_axis,
            "reduction_values": list(self.reduction_values),
            "default_checked": self.default_checked,
        }


# ---------------------------------------------------------------------------
# The curated checklist (per user direction 2026-05-16: 8-12 items
# whose presence/absence shifts the scorer ≥1 point)
# ---------------------------------------------------------------------------


DEFAULT_CHECKLIST: tuple[ReductionChecklistItem, ...] = (
    # Pre-checked-by-default sensitive denies (the "you almost certainly
    # don't need these" set; mirrors AdminLikeWithSensitiveExclusions's
    # DenySecretData behavior)
    ReductionChecklistItem(
        id="deny-secrets",
        label="I don't need to READ secrets",
        description=(
            "Block secretsmanager:GetSecretValue + "
            "secretsmanager:BatchGetSecretValue + ssm:GetParameter* "
            "(covers SecureString reads). Almost every admin task can "
            "be done without touching secret VALUES. Note: KMS Decrypt "
            "is NOT blocked here — it would break too much legitimate "
            "use (every KMS-encrypted blob in S3/RDS/EBS). For a KMS "
            "Decrypt block, use a dedicated policy."
        ),
        reduction_axis="deny_actions",
        reduction_values=(
            "secretsmanager:GetSecretValue",
            "secretsmanager:BatchGetSecretValue",
            "ssm:GetParameter*",
        ),
        default_checked=True,
    ),
    ReductionChecklistItem(
        id="deny-iam-admin",
        label="I don't need to modify IAM roles / policies",
        description=(
            "Block iam:* operations. Closes the CreateRole + "
            "PutRolePolicy + AssumeRole principal-pivot path. Does "
            "NOT block other pivots (sts:AssumeRole into pre-existing "
            "roles that trust this principal, kms:CreateGrant, "
            "s3:PutBucketPolicy, lambda:AddPermission) — use a "
            "Permissions Boundary on the issued role for hardest "
            "containment."
        ),
        reduction_axis="deny_services",
        reduction_values=("iam",),
        default_checked=True,
    ),
    ReductionChecklistItem(
        id="deny-org-billing",
        label="I don't need org-level / billing operations",
        description=(
            "Block organizations:*, account:*, billing:*. Almost no "
            "task needs these; common attacker target."
        ),
        reduction_axis="deny_services",
        reduction_values=("organizations", "account", "billing"),
        default_checked=True,
    ),
    # Uncheckable-by-default service categories (user opts in to deny)
    ReductionChecklistItem(
        id="deny-rds",
        label="I don't need RDS (databases)",
        description="Block rds:*. Tick if your task doesn't touch RDS instances or Aurora.",
        reduction_axis="deny_services",
        reduction_values=("rds",),
    ),
    ReductionChecklistItem(
        id="deny-dynamodb",
        label="I don't need DynamoDB",
        description="Block dynamodb:*. Tick if your task doesn't touch DynamoDB tables.",
        reduction_axis="deny_services",
        reduction_values=("dynamodb",),
    ),
    ReductionChecklistItem(
        id="deny-s3-writes",
        label="I don't need to WRITE to S3",
        description=(
            "Block s3:Put*, s3:Delete*, s3:Create*, s3:Restore*, "
            "s3:Replicate*. Keeps read access; blocks modifications. "
            "Useful for read-only investigation grants."
        ),
        reduction_axis="deny_actions",
        reduction_values=(
            "s3:Put*",
            "s3:Delete*",
            "s3:Create*",
            "s3:Restore*",
            "s3:Replicate*",
        ),
    ),
    ReductionChecklistItem(
        id="deny-cloudformation",
        label="I don't need CloudFormation / SAM",
        description="Block cloudformation:*. Tick if your task doesn't deploy via CFN/SAM.",
        reduction_axis="deny_services",
        reduction_values=("cloudformation",),
    ),
    ReductionChecklistItem(
        id="deny-ecs-eks",
        label="I don't need container orchestration (ECS / EKS)",
        description="Block ecs:* + eks:*. Tick if your task is non-container.",
        reduction_axis="deny_services",
        reduction_values=("ecs", "eks"),
    ),
    ReductionChecklistItem(
        id="deny-lambda-deploy",
        label="I don't need to deploy Lambda functions",
        description=(
            "Block lambda:* operations. Tick if you're investigating "
            "rather than deploying."
        ),
        reduction_axis="deny_services",
        reduction_values=("lambda",),
    ),
)


# ---------------------------------------------------------------------------
# Apply selections to a policy
# ---------------------------------------------------------------------------


def apply_selections(
    policy: dict[str, Any],
    *,
    selected_item_ids: list[str],
    narrow_to_accounts: list[str] | None = None,
    narrow_to_regions: list[str] | None = None,
) -> dict[str, Any]:
    """Map user's checklist selections + optional account/region
    narrowing into a single reduce_policy call. Returns the same
    shape as reduce_policy: {policy, recipe, summary, ...}.

    Unknown item IDs are silently ignored (forward-compatible with
    future Enterprise-plugin checklist customizations that may add
    items the OSS core doesn't know about).

    Unknown reduction_axis values on a known item are also silently
    ignored (WB21 LOW-21-01 closure: forward-compat covers axes the
    OSS core doesn't know about, but the item ID is still reported
    as "selected but not applied" for audit honesty).

    Returns these keys:
    - policy: the reduced policy (or original if no axis fired)
    - recipe: list of recipe entries the reductions actually applied
    - summary: human-readable summary
    - selected_item_ids: IDs the user picked AND we recognize (sorted)
    - applied_item_ids: subset of selected_item_ids whose axis produced
      a recipe entry (WB21 LOW-21-02 closure: split "user picked" from
      "actually changed policy" so the audit chain stops conflating them)
    """
    # WB21 LOW-21-03 closure: defensive guard against None / non-dict policy
    # so Enterprise-plugin callers that bypass MCP validator don't crash
    # with opaque AttributeError. Return the same null-policy shape MCP uses.
    if not isinstance(policy, dict):
        return {
            "policy": None,
            "recipe": [],
            "summary": "no reductions applied (invalid policy)",
            "selected_item_ids": [],
            "applied_item_ids": [],
            "error": "policy must be a dict",
        }

    if not isinstance(selected_item_ids, list):
        selected_item_ids = []
    selected_set = {str(i) for i in selected_item_ids if isinstance(i, str)}
    by_id = {item.id: item for item in DEFAULT_CHECKLIST}

    # Aggregate values by axis. Each selected item contributes to the
    # axis it declares. Unknown axes are skipped (item still reported
    # as selected but not applied).
    deny_services_acc: list[str] = []
    deny_actions_acc: list[str] = []
    contributing_ids_by_axis: dict[str, list[str]] = {
        "deny_services": [],
        "deny_actions": [],
    }
    for item_id in selected_set:
        item = by_id.get(item_id)
        if item is None:
            continue
        if not item.reduction_values:
            # Empty values means the item is a no-op even if known —
            # don't count it as applied even if its axis fires elsewhere.
            continue
        if item.reduction_axis == "deny_services":
            deny_services_acc.extend(item.reduction_values)
            contributing_ids_by_axis["deny_services"].append(item_id)
        elif item.reduction_axis == "deny_actions":
            deny_actions_acc.extend(item.reduction_values)
            contributing_ids_by_axis["deny_actions"].append(item_id)
        # else: unknown axis → skip (forward-compat for Enterprise plugin)

    # Dedupe while preserving deterministic order
    deny_services_unique = sorted(set(deny_services_acc))
    deny_actions_unique = sorted(set(deny_actions_acc))

    result = apply_reductions(
        policy,
        deny_services_list=deny_services_unique,
        deny_actions_list=deny_actions_unique,
        narrow_to_accounts_list=narrow_to_accounts or [],
        narrow_to_regions_list=narrow_to_regions or [],
    )

    out = result.to_dict()
    # Determine which axes actually fired (produced a recipe entry)
    fired_axes = {e["axis"] for e in out["recipe"]}
    applied_ids: list[str] = []
    for axis, ids in contributing_ids_by_axis.items():
        if axis in fired_axes:
            applied_ids.extend(ids)
    out["selected_item_ids"] = sorted(selected_set & set(by_id.keys()))
    out["applied_item_ids"] = sorted(set(applied_ids))
    return out


def get_checklist() -> list[dict[str, Any]]:
    """Return the default checklist as a list of dicts ready for
    MCP / web-UI rendering."""
    return [item.to_dict() for item in DEFAULT_CHECKLIST]
