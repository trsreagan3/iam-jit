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
- narrow_to_accounts: add aws:ResourceAccount StringEquals condition
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

    Service prefixes must be bare (e.g. `rds`, `secretsmanager`),
    NOT include `:` or wildcards (LOW-20-LOW1 closure: input like
    `rds:*` would produce a malformed `rds:*:*` action). Non-
    conforming entries silently dropped.

    Sid is suffixed with a hash of the deny set so multiple
    deny_services calls on the same policy don't produce duplicate
    Sids (LOW-20-LOW2 closure: AWS rejects PUT-IAM-policy on
    duplicate Sids within a policy).

    Empty / missing services list → policy unchanged + None recipe entry.
    """
    if not services:
        return policy, None
    # LOW-20-LOW1: reject anything containing ':' (would produce service:*:*)
    # or '*' (already a wildcard) or whitespace inside the token
    valid: list[str] = []
    for s in services:
        if not isinstance(s, str):
            continue
        token = s.strip()
        if not token:
            continue
        if ":" in token or "*" in token or " " in token:
            continue
        valid.append(token)
    if not valid:
        return policy, None

    new_policy = copy.deepcopy(policy)
    stmts = new_policy.setdefault("Statement", [])
    if isinstance(stmts, dict):
        # Normalize single-dict Statement to a list (AWS permits both forms)
        stmts = [stmts]
        new_policy["Statement"] = stmts

    # LOW-20-LOW2: deterministic but unique Sid per deny set, so
    # multiple deny_services calls on the same policy don't collide.
    import hashlib
    sid_hash = hashlib.sha256(",".join(sorted(valid)).encode()).hexdigest()[:8]
    deny_stmt = {
        "Sid": f"ReductionDenyServices{sid_hash}",
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
    """Add aws:ResourceAccount StringEquals condition to every Allow
    statement. Forces all granted operations to target resources in
    one of the listed account IDs.

    CRIT-20-01 closure: this uses `aws:ResourceAccount` — the real
    AWS global condition key for "the account hosting the resource."
    A previous draft used `aws:RequestedAccount` which is NOT a real
    AWS key; AWS evaluates unknown keys on StringEquals as false,
    silently dead-locking the Allow. (Other related real keys:
    aws:PrincipalAccount = the requester's account;
    aws:SourceAccount = legacy S3 confused-deputy mitigation. Use
    aws:ResourceAccount for the general "scope to account X" intent.)

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
        condition_key="aws:ResourceAccount",
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
    Region values are lowercased (LOW-20-LOW3 closure: AWS regions
    are canonically lowercase; `us-EAST-1` is StringEquals-different
    from `us-east-1`, which would silently dead-lock the Allow).

    Note: some AWS services (IAM, STS, organizations, billing) are
    GLOBAL and ignore aws:RequestedRegion. This narrowing is
    incremental defense, not absolute.
    """
    if not regions:
        return policy, None
    valid = [r.strip().lower() for r in regions if isinstance(r, str) and r.strip()]
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
) -> tuple[dict[str, Any], ReductionEntry | None]:
    """Add a StringEquals condition with the given key=values to every
    Allow statement in the policy. Deny statements are left untouched
    (they should still fire regardless of region/account scope).

    Returns recipe entry ONLY if at least one Allow statement was
    actually modified (MED-20-01 closure: don't lie in the recipe
    about applying a reduction that no-op'd). If policy has zero
    Allows, or every Allow had malformed Condition / conflicting
    pre-existing operator on the same key (MED-20-02 closure), the
    returned recipe entry is None.

    Effect comparison is case-insensitive per AWS spec (LOW-20-LOW4
    closure: AWS IAM treats `Allow` / `allow` / `ALLOW` identically;
    we must too, otherwise lowercase `effect: allow` statements
    silently fall through unscoped).
    """
    new_policy = copy.deepcopy(policy)
    stmts = new_policy.setdefault("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
        new_policy["Statement"] = stmts

    statements_modified = 0
    for s in stmts:
        if not isinstance(s, dict):
            continue
        # LOW-20-LOW4: case-insensitive Effect comparison (AWS spec)
        effect = s.get("Effect", "")
        if not isinstance(effect, str) or effect.strip().lower() != "allow":
            continue
        cond = s.get("Condition")
        if cond is None:
            s["Condition"] = {}
            cond = s["Condition"]
        if not isinstance(cond, dict):
            # MED-20-01: existing Condition is malformed; skip rather
            # than corrupt. Do NOT count this statement as modified.
            continue
        # MED-20-02: if another operator (StringLike, StringNotEquals,
        # etc.) already references this key, AWS evaluates conditions
        # as AND across operators — adding StringEquals on the same
        # key produces a contradictory expression (unsatisfiable),
        # silently dead-locking the Allow. Skip with no modification.
        if _other_operators_reference_key(cond, condition_key):
            continue
        string_equals = cond.get("StringEquals")
        if string_equals is None:
            cond["StringEquals"] = {}
            string_equals = cond["StringEquals"]
        if not isinstance(string_equals, dict):
            # StringEquals is malformed (e.g. a string); skip this statement
            continue
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
        statements_modified += 1

    if statements_modified == 0:
        # No Allow statement was actually narrowed — don't lie in the
        # recipe. Caller sees None → recipe entry omitted.
        return new_policy, None
    return new_policy, ReductionEntry(
        axis=recipe_axis, values=tuple(sorted(set(condition_values)))
    )


def _other_operators_reference_key(condition: dict[str, Any], key: str) -> bool:
    """MED-20-02 helper: check if the existing Condition block has
    any operator OTHER than StringEquals that references the given
    key. If so, adding StringEquals creates an unsatisfiable AND.

    Returns True if a conflicting operator exists; False otherwise.
    """
    for op, op_block in condition.items():
        if op == "StringEquals":
            continue
        if not isinstance(op_block, dict):
            continue
        if key in op_block:
            return True
    return False


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
