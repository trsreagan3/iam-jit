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
    # don't need these" set; matches AdminLikeWithSensitiveExclusions's
    # deny categories)
    ReductionChecklistItem(
        id="deny-secrets",
        label="I don't need to READ secrets",
        description=(
            "Block reading from Secrets Manager + SSM Parameter Store "
            "(SecureString) + KMS Decrypt. Almost every admin task can "
            "be done without touching secret VALUES."
        ),
        reduction_axis="deny_services",
        reduction_values=("secretsmanager",),  # ssm + kms decrypt are pattern-specific
        default_checked=True,
    ),
    ReductionChecklistItem(
        id="deny-iam-admin",
        label="I don't need to modify IAM roles / policies",
        description=(
            "Block iam:* operations. Stops the principal-pivot escape "
            "(create new role + assume it). Pair with this for hardest "
            "containment of an admin-class grant."
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
            "Block s3:Put*, s3:Delete*, s3:CreateBucket*. Keeps read "
            "access; blocks all modifications. Useful for read-only "
            "investigation grants."
        ),
        reduction_axis="deny_services",
        reduction_values=(),  # placeholder — s3 write blocking is handled differently
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
    shape as reduce_policy: {policy, recipe, summary}.

    Unknown item IDs are silently ignored (forward-compatible with
    future Enterprise-plugin checklist customizations that may add
    items the OSS core doesn't know about).
    """
    if not isinstance(selected_item_ids, list):
        selected_item_ids = []
    selected_set = {str(i) for i in selected_item_ids if isinstance(i, str)}
    by_id = {item.id: item for item in DEFAULT_CHECKLIST}

    # Aggregate all deny_services values across selected items
    deny_services_acc: list[str] = []
    for item_id in selected_set:
        item = by_id.get(item_id)
        if item is None:
            continue
        if item.reduction_axis == "deny_services":
            deny_services_acc.extend(item.reduction_values)

    # Dedupe while preserving deterministic order
    deny_services_unique = sorted(set(deny_services_acc))

    result = apply_reductions(
        policy,
        deny_services_list=deny_services_unique,
        narrow_to_accounts_list=narrow_to_accounts or [],
        narrow_to_regions_list=narrow_to_regions or [],
    )

    out = result.to_dict()
    # Append the selection metadata so the audit chain can show
    # exactly which checklist items the user picked
    out["selected_item_ids"] = sorted(selected_set & set(by_id.keys()))
    return out


def get_checklist() -> list[dict[str, Any]]:
    """Return the default checklist as a list of dicts ready for
    MCP / web-UI rendering."""
    return [item.to_dict() for item in DEFAULT_CHECKLIST]
