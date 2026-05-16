"""Per-user template storage — the personal-tier of the
evolving preset library ([[evolving-preset-library]]).

When a user has a policy that worked well, they can save it as a
named template. The next time they need similar access, they pick
from their personal library instead of re-typing JSON or re-running
the agent's reduction loop.

Pre-launch slice (per #150): personal-tier templates only.
Org-curated tier (admin promotes a personal template to be
org-wide) ships post-launch.

The library NEVER bypasses the scorer per [[scorer-is-ground-truth]].
A saved template is just a policy starting point — the scorer
re-evaluates every submission. Past approval of a template does
NOT lower current risk. Same gates as raw-JSON submit.

Two implementations:
  - InMemoryUserTemplateStore: tests, local dev, iam-jit serve --local
  - (DynamoDBUserTemplateStore: post-launch when hosted-tier ships)
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any, Protocol


@dataclasses.dataclass(frozen=True)
class UserTemplate:
    """One saved template in a user's personal library."""

    template_id: str
    user_id: str
    name: str  # human-friendly identifier ("payment-incident-read", "rotate-staging-secret")
    policy: dict[str, Any]  # the IAM policy document
    created_at: int  # epoch seconds
    # Optional provenance — which grant this was saved from, what the
    # task was. Surfaces in the audit log as "based on saved template X
    # originally from grant Y".
    source_grant_id: str | None = None
    source_description: str | None = None
    # Hash of canonicalized actions + resources for similarity match.
    # Computed at save time; used by find_similar() to compare policies
    # without re-canonicalizing on every search.
    shape_hash: str = ""
    # Use counter — incremented each time this template is re-used as
    # the starting point for a new request. Drives "auto-suggest as
    # recurring template after N reuses" (post-launch).
    reuse_count: int = 0


class UserTemplateNotFound(Exception):
    pass


class UserTemplateNameTaken(Exception):
    """Per-user names must be unique."""


class UserTemplateStore(Protocol):
    def put(self, record: UserTemplate) -> None: ...
    def get(self, template_id: str) -> UserTemplate: ...
    def get_by_name(self, user_id: str, name: str) -> UserTemplate: ...
    def list_for_user(self, user_id: str) -> list[UserTemplate]: ...
    def delete(self, template_id: str) -> None: ...
    def increment_reuse(self, template_id: str) -> None: ...


# ---------------------------------------------------------------------------
# Similarity helpers
# ---------------------------------------------------------------------------


def compute_shape_hash(policy: dict[str, Any]) -> str:
    """Canonical hash of the policy's action+resource shape.

    Two policies with the same actions on the same (or wildcard)
    resources collide — that's the intent: detect "I already have
    a template for this shape." Effect (Allow/Deny) is included so
    deny-listing variants are distinguished. NotAction/NotResource
    are included; Condition is included but order-insensitive.

    Returns a 16-hex prefix of SHA-256 over the canonical JSON.
    """
    canon = _canonicalize_shape(policy)
    return hashlib.sha256(
        json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]


def _canonicalize_shape(policy: dict[str, Any]) -> Any:
    """Reduce a policy to its 'shape' for similarity comparison.

    Sort actions + resources lists. Drop Sid (cosmetic-only). Keep
    Effect, Action/NotAction, Resource/NotResource, Condition. Order
    statements by (effect, first action) for deterministic compare.
    """
    if not isinstance(policy, dict):
        return policy
    stmts = policy.get("Statement") or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    canon_stmts: list[Any] = []
    for s in stmts:
        if not isinstance(s, dict):
            continue
        out: dict[str, Any] = {"Effect": s.get("Effect", "Allow")}
        for field in ("Action", "NotAction", "Resource", "NotResource"):
            if field in s:
                val = s[field]
                if isinstance(val, list):
                    out[field] = sorted(val)
                else:
                    out[field] = val
        if "Condition" in s:
            # Condition values can themselves be lists — sort inner lists too
            cond = s["Condition"]
            if isinstance(cond, dict):
                out["Condition"] = {
                    op: {k: sorted(v) if isinstance(v, list) else v for k, v in v_inner.items()}
                    for op, v_inner in cond.items()
                    if isinstance(v_inner, dict)
                }
            else:
                out["Condition"] = cond
        canon_stmts.append(out)
    canon_stmts.sort(
        key=lambda s: (
            s.get("Effect", ""),
            json.dumps(s.get("Action") or s.get("NotAction") or "", sort_keys=True),
        )
    )
    return {"Version": policy.get("Version", "2012-10-17"), "Statement": canon_stmts}


def action_overlap_similarity(
    policy_a: dict[str, Any], policy_b: dict[str, Any]
) -> float:
    """Jaccard similarity of the two policies' action sets.

    Returns a float in [0.0, 1.0]. 1.0 means identical action sets;
    0.0 means no overlap. Resources + conditions are ignored for this
    metric — we want "is this the same KIND of access" matching.
    """
    actions_a = _extract_actions(policy_a)
    actions_b = _extract_actions(policy_b)
    if not actions_a and not actions_b:
        return 1.0
    if not actions_a or not actions_b:
        return 0.0
    intersection = len(actions_a & actions_b)
    union = len(actions_a | actions_b)
    return intersection / union if union > 0 else 0.0


def _extract_actions(policy: dict[str, Any]) -> set[str]:
    """All Allow-statement actions, flattened to a set."""
    out: set[str] = set()
    if not isinstance(policy, dict):
        return out
    for s in policy.get("Statement") or []:
        if not isinstance(s, dict):
            continue
        if s.get("Effect") != "Allow":
            continue
        actions = s.get("Action")
        if isinstance(actions, list):
            out.update(str(a) for a in actions)
        elif isinstance(actions, str):
            out.add(actions)
    return out


# ---------------------------------------------------------------------------
# InMemory implementation
# ---------------------------------------------------------------------------


class InMemoryUserTemplateStore:
    name = "memory"

    def __init__(self) -> None:
        # template_id → UserTemplate
        self._items: dict[str, UserTemplate] = {}

    def put(self, record: UserTemplate) -> None:
        # Enforce per-user name uniqueness on insert (not on update)
        existing = self._items.get(record.template_id)
        for r in self._items.values():
            if (
                r.user_id == record.user_id
                and r.name == record.name
                and r.template_id != record.template_id
            ):
                raise UserTemplateNameTaken(
                    f"user {record.user_id!r} already has a template named {record.name!r}"
                )
        self._items[record.template_id] = record

    def get(self, template_id: str) -> UserTemplate:
        if template_id not in self._items:
            raise UserTemplateNotFound(template_id)
        return self._items[template_id]

    def get_by_name(self, user_id: str, name: str) -> UserTemplate:
        for r in self._items.values():
            if r.user_id == user_id and r.name == name:
                return r
        raise UserTemplateNotFound(f"user {user_id!r} template {name!r}")

    def list_for_user(self, user_id: str) -> list[UserTemplate]:
        return sorted(
            (r for r in self._items.values() if r.user_id == user_id),
            key=lambda r: r.created_at,
            reverse=True,  # newest first
        )

    def delete(self, template_id: str) -> None:
        self._items.pop(template_id, None)

    def increment_reuse(self, template_id: str) -> None:
        existing = self._items.get(template_id)
        if existing is None:
            return
        self._items[template_id] = dataclasses.replace(
            existing, reuse_count=existing.reuse_count + 1
        )


# ---------------------------------------------------------------------------
# Module-level default store for InMemory path (used by tests + local-mode)
# ---------------------------------------------------------------------------


_default_store: UserTemplateStore | None = None


def get_default_store() -> UserTemplateStore:
    global _default_store
    if _default_store is None:
        _default_store = InMemoryUserTemplateStore()
    return _default_store


def reset_default_store_for_tests() -> None:
    """Reset between tests — same pattern as other singleton stores."""
    global _default_store
    _default_store = None


# ---------------------------------------------------------------------------
# Pure-function search helpers (work on any UserTemplateStore via list_for_user)
# ---------------------------------------------------------------------------


def find_similar(
    store: UserTemplateStore,
    user_id: str,
    policy: dict[str, Any],
    *,
    top_k: int = 5,
    min_similarity: float = 0.3,
) -> list[tuple[UserTemplate, float]]:
    """Return up to top_k templates ranked by action-overlap similarity.

    Pre-launch metric: action-overlap Jaccard. Post-launch can add
    resource-ARN overlap, condition-match scoring, etc. — kept simple
    for the first slice.
    """
    candidates = store.list_for_user(user_id)
    if not candidates:
        return []
    scored: list[tuple[UserTemplate, float]] = []
    for t in candidates:
        sim = action_overlap_similarity(policy, t.policy)
        if sim >= min_similarity:
            scored.append((t, sim))
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:top_k]


def find_by_shape_hash(
    store: UserTemplateStore, user_id: str, policy: dict[str, Any]
) -> UserTemplate | None:
    """Exact shape-hash match — for 'this is the same template I saved before' detection."""
    target = compute_shape_hash(policy)
    for t in store.list_for_user(user_id):
        if t.shape_hash == target:
            return t
    return None
