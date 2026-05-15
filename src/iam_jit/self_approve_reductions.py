"""Self-approve reductions — admins auto-approve their OWN narrower grants.

Per [[self-approve-reductions]] memo. The use case:

  A solo dev (running `iam-jit serve --local`) is the admin of
  their own laptop process. They have full AWS access via their
  local `~/.aws/credentials`. When they submit a request through
  iam-jit, that request is necessarily a *reduction* of authority
  they already hold — they could have used their admin keys
  directly. Asking them to "approve" their own scoped request is
  pure friction.

This gate runs BEFORE the auto-approve scoring gate. When it
fires, the request transitions pending → approved with actor
`self_approve_reduction:<user.id>` (distinguishable from
`system:auto-approver` in the audit log) and skips human review
entirely.

What's still enforced:
  - Audit chain (full record of who/what/when/why)
  - Time-bounds (the grant's `duration_hours` still applies)
  - Scoring (the deterministic + LLM score still runs and is
    recorded; the gate just doesn't BLOCK on it)
  - Service / account blocklists (admin-curated denylists still apply)
  - MFA freshness (Layer C of [[mfa-compliance-strategy]] —
    high-risk grants still need recent MFA even for self-approve)

What's NOT enforced:
  - The score threshold (admins have already shown they have the
    authority; reducing to a narrower scope is by definition lower
    risk than the alternative they could've taken)

When the gate FIRES:
  1. User is_admin == True (has full authority)
  2. deployment_mode == "solo" OR user.self_approve_reductions == True
  3. Request owner == requesting user (you can self-approve only
     your OWN requests; you cannot self-approve a request you
     made on behalf of someone else)
  4. No service-blocklist hits (still hard floor)

The blocklist check stays as a hard floor because the platform
team (via deploy-time Floors) gets to say "even an admin self-
approving cannot touch these services without human review."
That's the iam-jit-equivalent of a refuse-to-process SCP.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Any


@dataclasses.dataclass(frozen=True)
class SelfApproveDecision:
    """Outcome of the self-approve-reduction gate."""

    self_approved: bool
    reason: str
    """One of:
      'self_approved'       — admin reduction; auto-approve
      'not_admin'           — user lacks admin role; skip gate
      'not_owner'           — request belongs to someone else
      'mode_not_enabled'    — deployment mode != solo and user not opted in
      'service_blocked'     — blocked by service blocklist (hard floor)
      'no_policy'           — request has no policy (shouldn't reach here)
    """
    details: dict[str, Any] = dataclasses.field(default_factory=dict)


def _deployment_mode() -> str:
    return (os.environ.get("IAM_JIT_DEPLOYMENT_MODE") or "").strip().lower()


def is_enabled_for(user_self_approve_flag: bool) -> bool:
    """The gate is enabled for a user when EITHER the deployment-wide
    mode is `solo` OR the user has explicitly opted in.

    Both paths still subject the request to the gate's full
    eligibility chain (admin + owner + not-blocklisted).
    """
    return _deployment_mode() == "solo" or bool(user_self_approve_flag)


def evaluate(
    *,
    request: dict[str, Any],
    user_id: str,
    user_is_admin: bool,
    user_self_approve_flag: bool = False,
    blocked_services: tuple[str, ...] = (),
) -> SelfApproveDecision:
    """Decide whether this request self-approves under the reductions gate.

    Caller responsibilities:
      - Pass the AUTHENTICATED user_id (from middleware)
      - Pass `user_is_admin` from `user.is_admin`
      - Pass `user_self_approve_flag` from the user's profile
        (defaults to False; only the user's explicit opt-in toggles
        it on outside solo mode)
      - Pass `blocked_services` from `settings.never_auto_approve_services`
        so the platform-team floor is honored
    """
    if not is_enabled_for(user_self_approve_flag):
        return SelfApproveDecision(
            self_approved=False, reason="mode_not_enabled",
            details={"deployment_mode": _deployment_mode()},
        )

    if not user_is_admin:
        return SelfApproveDecision(
            self_approved=False, reason="not_admin",
        )

    # Owner check: only self-approve requests you own. Requests
    # submitted on behalf of another user still flow through normal
    # approval (a real human approval signal is still required for
    # someone else's grant).
    metadata = request.get("metadata") or {}
    owner = metadata.get("owner") or ""
    if owner != user_id:
        return SelfApproveDecision(
            self_approved=False, reason="not_owner",
            details={"owner": owner, "requesting_user": user_id},
        )

    # Hard-floor blocklist: even self-approving admin cannot route
    # around the platform-team service blocklist.
    spec = request.get("spec") or {}
    policy = spec.get("policy") or {}
    statements = policy.get("Statement") or []
    if not statements:
        return SelfApproveDecision(
            self_approved=False, reason="no_policy",
        )
    block_set = set(blocked_services)
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if not isinstance(action, str) or ":" not in action:
                continue
            service = action.split(":", 1)[0]
            if service in block_set:
                return SelfApproveDecision(
                    self_approved=False,
                    reason="service_blocked",
                    details={"service": service, "action": action},
                )

    return SelfApproveDecision(
        self_approved=True, reason="self_approved",
        details={
            "user_id": user_id,
            "deployment_mode": _deployment_mode() or "(implicit per-user flag)",
        },
    )


def audit_actor_for(user_id: str) -> str:
    """The actor string written to the audit log on a self-approved
    transition. Intentionally distinct from `system:auto-approver`
    so a compliance auditor can grep for either independently."""
    return f"self_approve_reduction:{user_id}"
