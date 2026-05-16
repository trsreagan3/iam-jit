"""Deterministic policy reductions per [[aws-managed-baseline-strategy]].

Per the agent-driven reduction loop ([[agent-driven-reduction-loop]]),
agents pick a baseline + use these reductions to narrow it before
submitting. Each reduction is a pure function: takes a policy +
parameters, returns a reduced policy + a recipe entry describing
what was reduced.

The reduction recipe is the AUDIT-CHAIN ARTIFACT:
"AdminLikeWithSensitiveExclusions minus [rds, secretsmanager],
scoped to account 111... + region us-east-1"
— much more reviewable than an opaque 47-action custom policy.

Three reduction axes ship pre-launch (#155):
- deny_services: append Deny statements for entire services
- narrow_to_accounts: add aws:RequestedAccount StringEquals condition
- narrow_to_regions: add aws:RequestedRegion StringEquals condition

Deferred to follow-up:
- strip_action_classes (writes / destructive / destructive_no_recovery)
- narrow_resources (per-action ARN narrowing — needs service-aware ARN format)

Per [[scorer-is-ground-truth]]: reductions are transparent — every
modification is recorded in the recipe; the final policy goes through
the unchanged scorer.
"""

from __future__ import annotations

import copy
import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True)
class ReductionEntry:
    """One axis of the reduction recipe."""

    axis: str  # "deny_services" / "narrow_to_accounts" / "narrow_to_regions"
    values: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"axis": self.axis, "values": list(self.values)}


@dataclasses.dataclass(frozen=True)
class ReductionResult:
    """A reduced policy + the recipe of what was reduced."""

    policy: dict[str, Any]
    recipe: tuple[ReductionEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "recipe": [e.to_dict() for e in self.recipe],
            "summary": self._summary(),
        }

    def _summary(self) -> str:
        if not self.recipe:
            return "no reductions applied"
        parts = []
        for e in self.recipe:
            if e.axis == "deny_services":
                parts.append(f"minus [{', '.join(e.values)}]")
            elif e.axis == "narrow_to_accounts":
                parts.append(f"scoped to account(s) {', '.join(e.values)}")
            elif e.axis == "narrow_to_regions":
                parts.append(f"scoped to region(s) {', '.join(e.values)}")
            else:
                parts.append(f"{e.axis}={list(e.values)}")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Reduction axis #1: append Deny statements for services
# ---------------------------------------------------------------------------


def deny_services(
    policy: dict[str, Any], services: list[str]
) -> tuple[dict[str, Any], ReductionEntry | None]:
    """Append a Deny statement that blocks `service:*` for each
    service in the list. Pure: returns a new policy; doesn't mutate.

    Empty / missing services list → policy unchanged + None recipe entry.
    """
    if not services:
        return policy, None
    valid = [s.strip() for s in services if isinstance(s, str) and s.strip()]
    if not valid:
        return policy, None
    new_policy = copy.deepcopy(policy)
    stmts = new_policy.setdefault("Statement", [])
    if isinstance(stmts, dict):
        # Normalize single-dict Statement to a list (AWS permits both forms)
        stmts = [stmts]
        new_policy["Statement"] = stmts
    deny_stmt = {
        "Sid": "ReductionDenyServices",
        "Effect": "Deny",
        "Action": [f"{s}:*" for s in valid],
        "Resource": "*",
    }
    stmts.append(deny_stmt)
    return new_policy, ReductionEntry(axis="deny_services", values=tuple(valid))


# ---------------------------------------------------------------------------
# Reduction axis #2: narrow to specific accounts
# ---------------------------------------------------------------------------


def narrow_to_accounts(
    policy: dict[str, Any], accounts: list[str]
) -> tuple[dict[str, Any], ReductionEntry | None]:
    """Add aws:RequestedAccount StringEquals condition to every Allow
    statement. Forces all granted operations to target one of the
    listed account IDs.

    Empty / missing accounts list → policy unchanged.
    Account-id format: 12-digit string. Non-conforming entries are
    rejected silently (return policy unchanged).
    """
    if not accounts:
        return policy, None
    valid = [a.strip() for a in accounts if isinstance(a, str) and a.strip().isdigit() and len(a.strip()) == 12]
    if not valid:
        return policy, None
    return _add_condition_to_allow_statements(
        policy,
        condition_key="aws:RequestedAccount",
        condition_values=valid,
        recipe_axis="narrow_to_accounts",
    )


# ---------------------------------------------------------------------------
# Reduction axis #3: narrow to specific regions
# ---------------------------------------------------------------------------


def narrow_to_regions(
    policy: dict[str, Any], regions: list[str]
) -> tuple[dict[str, Any], ReductionEntry | None]:
    """Add aws:RequestedRegion StringEquals condition to every Allow
    statement. Forces all granted operations to target one of the
    listed regions.

    Empty / missing regions list → policy unchanged.
    Note: some AWS services (IAM, STS, organizations, billing) are
    GLOBAL and ignore aws:RequestedRegion. This narrowing is
    incremental defense, not absolute.
    """
    if not regions:
        return policy, None
    valid = [r.strip() for r in regions if isinstance(r, str) and r.strip()]
    if not valid:
        return policy, None
    return _add_condition_to_allow_statements(
        policy,
        condition_key="aws:RequestedRegion",
        condition_values=valid,
        recipe_axis="narrow_to_regions",
    )


# ---------------------------------------------------------------------------
# Shared helper for condition-based narrowing
# ---------------------------------------------------------------------------


def _add_condition_to_allow_statements(
    policy: dict[str, Any],
    *,
    condition_key: str,
    condition_values: list[str],
    recipe_axis: str,
) -> tuple[dict[str, Any], ReductionEntry]:
    """Add a StringEquals condition with the given key=values to every
    Allow statement in the policy. Deny statements are left untouched
    (they should still fire regardless of region/account scope).
    """
    new_policy = copy.deepcopy(policy)
    stmts = new_policy.setdefault("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
        new_policy["Statement"] = stmts
    for s in stmts:
        if not isinstance(s, dict):
            continue
        if s.get("Effect") != "Allow":
            continue
        cond = s.setdefault("Condition", {})
        if not isinstance(cond, dict):
            # Existing condition is malformed; skip rather than corrupt
            continue
        string_equals = cond.setdefault("StringEquals", {})
        if not isinstance(string_equals, dict):
            cond["StringEquals"] = {}
            string_equals = cond["StringEquals"]
        # Merge values if the key already exists; otherwise set
        existing = string_equals.get(condition_key)
        if isinstance(existing, list):
            merged = sorted(set(existing) | set(condition_values))
            string_equals[condition_key] = merged
        elif isinstance(existing, str):
            merged = sorted({existing} | set(condition_values))
            string_equals[condition_key] = merged
        else:
            string_equals[condition_key] = sorted(set(condition_values))
    return new_policy, ReductionEntry(
        axis=recipe_axis, values=tuple(sorted(set(condition_values)))
    )


# ---------------------------------------------------------------------------
# Compose multiple reductions in one call
# ---------------------------------------------------------------------------


def apply_reductions(
    policy: dict[str, Any],
    *,
    deny_services_list: list[str] | None = None,
    narrow_to_accounts_list: list[str] | None = None,
    narrow_to_regions_list: list[str] | None = None,
) -> ReductionResult:
    """Apply multiple reductions in a deterministic order.

    Order matters for predictable output:
    1. Deny statements (additive — no merge complexity)
    2. Account narrowing (conditions on every Allow)
    3. Region narrowing (conditions on every Allow)

    Each step that produces a recipe entry contributes to the final
    recipe; steps with empty inputs are no-ops and don't appear.
    """
    current = policy
    recipe: list[ReductionEntry] = []

    if deny_services_list:
        current, entry = deny_services(current, deny_services_list)
        if entry is not None:
            recipe.append(entry)
    if narrow_to_accounts_list:
        current, entry = narrow_to_accounts(current, narrow_to_accounts_list)
        if entry is not None:
            recipe.append(entry)
    if narrow_to_regions_list:
        current, entry = narrow_to_regions(current, narrow_to_regions_list)
        if entry is not None:
            recipe.append(entry)

    return ReductionResult(policy=current, recipe=tuple(recipe))
