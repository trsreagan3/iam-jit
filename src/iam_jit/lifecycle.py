"""Request state machine and helpers for the API routes.

States:
  draft → pending → provisioning → active → expired
                 │
                 ├─ rejected
                 ├─ cancelled
                 └─ needs_changes ─resubmit→ pending
                                  │
                                  └─ cancelled

`apply_transition` is the single place that mutates `request["status"]`.
It enforces:
  - state-machine legality (which transitions are allowed)
  - actor authorization (owner-only vs approver-only vs admin)
  - records the transition in `status.history`

Routes call into this module instead of editing the dict themselves.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any

from .users_store import User


VALID_STATES = frozenset(
    {
        "pending",
        "provisioning",
        "provisioning_failed",
        "active",
        "rejected",
        "cancelled",
        "needs_changes",
        "expired",
        "revoked",
    }
)


_TRANSITIONS: dict[tuple[str, str], dict[str, Any]] = {
    # (from_state, action) → metadata about who can do it
    ("pending", "approve"): {"to": "provisioning", "actor": "approver"},
    ("pending", "reject"): {"to": "rejected", "actor": "approver"},
    ("pending", "request_changes"): {"to": "needs_changes", "actor": "approver"},
    ("pending", "cancel"): {"to": "cancelled", "actor": "owner"},
    ("pending", "edit"): {"to": "pending", "actor": "owner"},
    ("needs_changes", "edit"): {"to": "pending", "actor": "owner"},
    ("needs_changes", "resubmit"): {"to": "pending", "actor": "owner"},
    ("needs_changes", "cancel"): {"to": "cancelled", "actor": "owner"},
    ("provisioning", "active"): {"to": "active", "actor": "system"},
    ("provisioning", "provisioning_failed"): {"to": "provisioning_failed", "actor": "system"},
    # #610 — `cancel` allowed from `provisioning` is a recovery surface.
    # Pre-fix the web admin approve flow could leave a request stuck in
    # `provisioning` indefinitely (Gap UAT-WEB-ADMIN-01, 2026-05-25);
    # even with that race closed via the synchronous provisioning call,
    # operator may still want to abandon a request that gets wedged
    # mid-flight (network blip, watchdog hasn't fired yet). Per
    # [[ibounce-honest-positioning]] "no silent zombie" — give the
    # owner a way out without admin intervention.
    ("provisioning", "cancel"): {"to": "cancelled", "actor": "owner"},
    ("provisioning_failed", "retry"): {"to": "provisioning", "actor": "approver"},
    ("provisioning_failed", "cancel"): {"to": "cancelled", "actor": "owner"},
    ("active", "expire"): {"to": "expired", "actor": "system"},
    ("active", "revoke"): {"to": "revoked", "actor": "admin"},
    # Admin force-cancel — allowed from any non-terminal state. Special-cased below.
}


@dataclass(frozen=True)
class TransitionResult:
    new_state: str
    history_event: dict[str, Any]


class IllegalTransition(Exception):
    pass


class NotAuthorized(Exception):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_state(request: dict[str, Any]) -> str:
    return ((request.get("status") or {}).get("state")) or "pending"


def get_owner(request: dict[str, Any]) -> str | None:
    return (request.get("status") or {}).get("owner")


def is_owner(request: dict[str, Any], user: User) -> bool:
    return get_owner(request) == user.id


def init_status(request: dict[str, Any], *, owner: User) -> None:
    """Stamp the initial status fields on a freshly-submitted request."""
    request.setdefault("status", {})
    request["status"]["state"] = "pending"
    request["status"]["owner"] = owner.id
    request["status"]["submitted_at"] = _now()
    request["status"]["last_updated_at"] = request["status"]["submitted_at"]
    request["status"].setdefault("comments", [])
    request["status"].setdefault("history", [])
    request["status"]["history"].append(
        {"action": "submit", "by": owner.id, "at": request["status"]["submitted_at"]}
    )


def apply_transition(
    request: dict[str, Any],
    *,
    action: str,
    actor: User,
    reason: str | None = None,
    extra: dict[str, Any] | None = None,
) -> TransitionResult:
    """Mutate `request['status']` to apply a state transition.

    Raises IllegalTransition if the action isn't allowed from the current
    state. Raises NotAuthorized if `actor` lacks the role/ownership.
    """
    state = get_state(request)
    key = (state, action)

    # Admin force-cancel: allowed from any non-terminal state.
    if action == "force_cancel":
        if not actor.is_admin:
            raise NotAuthorized("force_cancel requires admin role")
        if state in {"active", "expired", "rejected", "cancelled"}:
            raise IllegalTransition(f"cannot force_cancel from {state}")
        return _commit(request, action, actor, "cancelled", reason, extra)

    if key not in _TRANSITIONS:
        raise IllegalTransition(f"action {action!r} not allowed from state {state!r}")

    rule = _TRANSITIONS[key]
    actor_class = rule["actor"]
    if actor_class == "owner":
        if not is_owner(request, actor):
            raise NotAuthorized(f"{action} requires being the request owner")
    elif actor_class == "approver":
        if not actor.is_approver:
            raise NotAuthorized(f"{action} requires the approver role")
        # Self-approval is forbidden even for approvers.
        if action == "approve" and is_owner(request, actor):
            raise NotAuthorized("approvers cannot approve their own requests")
    elif actor_class == "admin":
        if not actor.is_admin:
            raise NotAuthorized(f"{action} requires admin role")
    elif actor_class == "system":
        # System-driven transitions (provisioning completion, expiry sweep) —
        # only callable from inside the Lambda's own code path, never via API.
        raise NotAuthorized(f"{action} is system-only")

    return _commit(request, action, actor, rule["to"], reason, extra)


def _commit(
    request: dict[str, Any],
    action: str,
    actor: User,
    new_state: str,
    reason: str | None,
    extra: dict[str, Any] | None,
) -> TransitionResult:
    now = _now()
    request.setdefault("status", {})
    prior_state = get_state(request)
    request["status"]["state"] = new_state
    request["status"]["last_updated_at"] = now
    request["status"].setdefault("history", [])
    event: dict[str, Any] = {
        "action": action,
        "from": prior_state,
        "to": new_state,
        "by": actor.id,
        "at": now,
    }
    if reason:
        event["reason"] = reason
    if extra:
        event.update(extra)
    request["status"]["history"].append(event)
    try:
        from . import audit

        audit.emit(
            actor=actor.id,
            kind="request.transition",
            summary=f"{action}: {prior_state} -> {new_state}",
            details={
                "request_id": (request.get("metadata") or {}).get("id"),
                "action": action,
                "from": prior_state,
                "to": new_state,
                "reason": reason,
            },
        )
    except Exception:
        pass
    return TransitionResult(new_state=new_state, history_event=event)


def mark_provisioned(
    request: dict[str, Any],
    *,
    provisioned: dict[str, Any],
) -> TransitionResult:
    """System-driven transition: provisioning → active.

    Stores `provisioned` (the ProvisioningResult plus assume_instructions)
    under status.provisioned, then advances state. Bypasses actor
    authorization because this is called from server-internal code, never
    from the API.

    On success, ALSO appends a sanitized snapshot to the approved-request
    memory store (when enabled) so future intake conversations can use
    this shape as grounding.
    """
    state = get_state(request)
    if state != "provisioning":
        raise IllegalTransition(
            f"mark_provisioned requires state=provisioning, got {state}"
        )
    request.setdefault("status", {})
    request["status"]["provisioned"] = provisioned
    result = _commit_system(request, "active", "active")
    _maybe_record_memory(request)
    return result


def _maybe_record_memory(request: dict[str, Any]) -> None:
    """Best-effort sanitized snapshot to the memory store. Never raises
    — recording failures must never block the lifecycle transition."""
    try:
        from . import memory

        store = memory.get_store()
        if store is None:
            return
        store.append(memory.sanitize(request))
    except Exception:
        pass


def mark_revoked(
    request: dict[str, Any],
    *,
    revoked_by: str,
    revocation: dict[str, Any],
) -> TransitionResult:
    """Record the outcome of an admin-driven revoke and advance state.

    Stores the revocation envelope (which IAM role was deleted, when, by
    whom, and the aws-cli replay of the deletion) under
    `status.revocation` so the request detail page can render the audit
    trail. The state machine transition itself is admin-authored — this
    helper exists so the route handler can attach the revocation data
    *atomically* with the transition: same `status.last_updated_at` /
    `status.history` entry.
    """
    state = get_state(request)
    if state not in {"active", "provisioning_failed"}:
        raise IllegalTransition(
            f"mark_revoked requires state=active or provisioning_failed, got {state}"
        )
    request.setdefault("status", {})
    request["status"]["revocation"] = revocation
    return _commit_system(request, "revoke", "revoked")


def mark_provisioning_failed(
    request: dict[str, Any],
    *,
    error: str,
) -> TransitionResult:
    """System-driven transition: provisioning → provisioning_failed.

    Stores the error message so the approver UI can surface it. The
    request stays out of the active flow until an approver retries or
    the owner cancels.
    """
    state = get_state(request)
    if state != "provisioning":
        raise IllegalTransition(
            f"mark_provisioning_failed requires state=provisioning, got {state}"
        )
    request.setdefault("status", {})
    request["status"]["provisioning_error"] = error
    return _commit_system(request, "provisioning_failed", "provisioning_failed")


def _commit_system(
    request: dict[str, Any],
    action: str,
    new_state: str,
) -> TransitionResult:
    """System transition without an authenticated actor."""
    now = _now()
    prior_state = get_state(request)
    request.setdefault("status", {})
    request["status"]["state"] = new_state
    request["status"]["last_updated_at"] = now
    request["status"].setdefault("history", [])
    event: dict[str, Any] = {
        "action": action,
        "from": prior_state,
        "to": new_state,
        "by": "system",
        "at": now,
    }
    request["status"]["history"].append(event)
    try:
        from . import audit

        audit.emit(
            actor="system",
            kind="request.transition",
            summary=f"{action}: {prior_state} -> {new_state}",
            details={
                "request_id": (request.get("metadata") or {}).get("id"),
                "action": action,
                "from": prior_state,
                "to": new_state,
            },
        )
    except Exception:
        pass
    return TransitionResult(new_state=new_state, history_event=event)


def add_comment(
    request: dict[str, Any],
    *,
    author: User,
    message: str,
    suggested_constraints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Append a comment to the request's thread. Always allowed for any
    authenticated user who can already view the request — view-authz is
    enforced upstream in the route."""
    now = _now()
    comment = {
        "author": author.id,
        "message": message,
        "posted_at": now,
    }
    if suggested_constraints:
        comment["suggested_constraints"] = suggested_constraints
    request.setdefault("status", {})
    request["status"].setdefault("comments", []).append(comment)
    request["status"]["last_updated_at"] = now
    return comment


_FADED_TERMINAL_STATES = frozenset({"cancelled", "revoked", "expired"})
_DASHBOARD_TTL_HOURS = 24


def _dashboard_state(r: dict[str, Any]) -> str:
    """Read state from either a full request dict or a summary dict."""
    if isinstance(r.get("status"), dict):
        return (r["status"].get("state")) or "pending"
    return r.get("state") or "pending"


def _dashboard_last_updated(r: dict[str, Any]) -> str | None:
    if isinstance(r.get("status"), dict):
        return r["status"].get("last_updated_at")
    return r.get("last_updated_at")


def _dashboard_submitted(r: dict[str, Any]) -> str:
    if isinstance(r.get("status"), dict):
        return r["status"].get("submitted_at") or ""
    return r.get("submitted_at") or ""


def _parse_iso_z(value: str | None) -> _dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return _dt.datetime.strptime(value.rstrip("Z"), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=_dt.UTC
        )
    except ValueError:
        return None


def is_visible_on_dashboard(
    request: dict[str, Any], *, now: _dt.datetime | None = None
) -> bool:
    """Decide whether a request should appear in the user's dashboard list.

    Rules, in order:
      1. Active grants stay visible as long as they're still valid
         (status.provisioned.expires_at in the future, or no expiry set).
         An active-but-already-past-expiry request is treated like
         expired — visible until 24h after expiry, then hidden.
      2. Terminal "faded" states — `cancelled`, `revoked`, `expired` —
         stay visible for 24h after they entered that state, then hide.
      3. `rejected` stays visible indefinitely (compliance signal).
      4. Everything else (pending, provisioning, needs_changes,
         provisioning_failed) stays visible.

    Hidden requests are still reachable by direct URL and via the API —
    this only filters the list view.

    Accepts either a full request dict (state under .status) or a summary
    dict (state at the top level).
    """
    if now is None:
        now = _dt.datetime.now(_dt.UTC)
    state = _dashboard_state(request)

    if state == "active":
        # Active but its grant has expired in AWS land — fade it like
        # the system-driven expiry would.
        provisioned = (request.get("status") or {}).get("provisioned") or {}
        expires_at = _parse_iso_z(provisioned.get("expires_at"))
        if expires_at is None:
            return True
        if now < expires_at:
            return True
        return (now - expires_at) < _dt.timedelta(hours=_DASHBOARD_TTL_HOURS)

    if state in _FADED_TERMINAL_STATES:
        ts = _parse_iso_z(_dashboard_last_updated(request))
        if ts is None:
            return True
        return (now - ts) < _dt.timedelta(hours=_DASHBOARD_TTL_HOURS)

    return True


def sort_for_dashboard(
    requests: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Order for the user's dashboard:
      - faded terminal states (cancelled, revoked, expired) sink to bottom
      - within each group, newest submitted_at first

    Accepts either full request dicts or summary dicts; reads state /
    submitted_at from whichever shape is supplied.
    """
    active = sorted(
        (r for r in requests if _dashboard_state(r) not in _FADED_TERMINAL_STATES),
        key=_dashboard_submitted,
        reverse=True,
    )
    faded = sorted(
        (r for r in requests if _dashboard_state(r) in _FADED_TERMINAL_STATES),
        key=_dashboard_submitted,
        reverse=True,
    )
    return active + faded


def can_view(request: dict[str, Any], user: User) -> bool:
    """Owner-based view authz: requesters see only their own; approvers
    and admins see all."""
    if user.is_approver:  # includes admin
        return True
    return is_owner(request, user)


def to_template(request: dict[str, Any]) -> dict[str, Any]:
    """Return a re-submittable projection of a request.

    Strips status, history, comments, server-set ids — keeps the parts a
    requester (or their agent) would want to reuse: description, intent,
    accounts, duration, policy, provisioning mode. The result validates
    against the request schema (after the server stamps a fresh id and
    status on submission).
    """
    spec = request.get("spec") or {}
    metadata = request.get("metadata") or {}
    requester = (metadata.get("requester") or {}).copy()
    requester.pop("principal_arn", None)
    template_spec: dict[str, Any] = {}
    for key in (
        "description",
        "access_type",
        "task_intent",
        "accounts",
        "duration",
        "policy",
        "resource_constraints",
        "provisioning",
    ):
        if key in spec and spec[key] is not None:
            template_spec[key] = spec[key]
    return {
        "apiVersion": request.get("apiVersion", "iam-jit.dev/v1alpha1"),
        "kind": request.get("kind", "RoleRequest"),
        "metadata": {"requester": requester} if requester else {},
        "spec": template_spec,
    }


def summarize(request: dict[str, Any]) -> dict[str, Any]:
    """Return a small projection of the request for list views."""
    spec = request.get("spec") or {}
    metadata = request.get("metadata") or {}
    status = request.get("status") or {}
    review = status.get("review") or {}
    return {
        "id": metadata.get("id"),
        "name": metadata.get("name"),
        "owner": status.get("owner"),
        "state": status.get("state") or "pending",
        "access_type": spec.get("access_type"),
        "description_preview": (spec.get("description") or "")[:140],
        "accounts": [a.get("account_id") for a in (spec.get("accounts") or [])],
        "duration_hours": (spec.get("duration") or {}).get("duration_hours"),
        "not_after": (spec.get("duration") or {}).get("not_after"),
        "submitted_at": status.get("submitted_at"),
        "last_updated_at": status.get("last_updated_at"),
        "risk_score": review.get("risk_score"),
        "risk_factors_summary": (review.get("risk_factors") or [])[:2],
    }
