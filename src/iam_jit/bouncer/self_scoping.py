"""Self-scoping orchestrator (#174 / Slice E).

Per [[self-scoping-without-interaction]] + user direction 2026-05-17:
agents (and humans about to run something locally) should be able to
declare "scope me to ONLY what I need for this task" in one shot,
WITHOUT user interaction when the declared scope is narrow enough.

This module is the orchestrator. It composes three existing systems
that were independently shipped:

1. Compatibility check ([[iam-jit-inapplicable-cases]]) — answers
   "can iam-jit-the-issuer help here, or only iam-jit-the-bouncer?"
2. Bouncer task scope ([[proxy-smart-defaults-and-task-scope]]) —
   creates an ephemeral scope (allow + deny rules) that narrows the
   bouncer's behavior for the task's duration.
3. iam-jit JIT role submission (optional) — issues a short-lived
   IAM role with the implied policy. Auto-approves below threshold.

The composer returns ONE unified status so the agent doesn't have
to compose three separate calls and reason about the cartesian
product of outcomes:

- `SCOPED` — both bouncer task active AND JIT role issued. Agent can
  proceed with the JIT role's creds; bouncer enforces additional
  scope per the agent's task declaration.
- `SCOPED_BOUNCER_ONLY` — bouncer task active; no JIT role (either
  compatibility said USE_EXISTING / USE_BOUNCER, OR the agent
  chose `submit_jit_role=False`). Agent uses whatever creds are
  available; bouncer gates them.
- `NEEDS_HUMAN` — bouncer task active, but JIT role submission
  returned a score above the auto-approval threshold. Agent must
  wait for human approval OR end the task and re-declare with
  narrower scope.
- `CANNOT_HELP` — neither product applies (allowlist override said
  CANNOT_HELP). Agent must escalate to a human; iam-jit isn't the
  right tool here.
- `FAILED` — bouncer task creation failed (typically: concurrent
  active task for the same owner; agent should end it first).

Per [[agent-friendly-not-bypassable]]:
- Lens A: ONE call replaces a sequence the agent could get wrong.
  Returns a self-describing terminal state + next_action_hint.
- Lens B: never adds anything to the GLOBAL ruleset. All narrowing
  is ephemeral (task scope + JIT role with expiry). Task end →
  baseline restored automatically per user clarification.

Per [[creates-never-mutates]]: only the ephemeral task scope is
created; nothing about persistent admin state changes. The JIT role
(if issued) is a fresh role bounded by its own TTL.
"""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any


class SelfScopeStatus(str, Enum):
    SCOPED = "scoped"
    SCOPED_BOUNCER_ONLY = "scoped_bouncer_only"
    NEEDS_HUMAN = "needs_human"
    CANNOT_HELP = "cannot_help"
    FAILED = "failed"


@dataclasses.dataclass(frozen=True)
class SelfScopeResult:
    """One unified status from the self-scoping composer.

    Per [[agent-friendly-not-bypassable]] Lens A: every terminal
    state carries `next_action_hint` so the agent has a concrete
    path forward — proceed with the JIT creds, proceed with
    existing creds + bouncer, wait for human, end-and-retry, etc.
    """

    status: SelfScopeStatus
    next_action_hint: str

    # Bouncer-task piece
    task_id: str | None = None
    task_expires_at: str | None = None

    # Compatibility piece
    compatibility_verdict: str | None = None
    compatibility_reasoning: str | None = None
    compatibility_matched_pattern: str | None = None

    # JIT-role piece (None for SCOPED_BOUNCER_ONLY / CANNOT_HELP)
    jit_request_id: str | None = None
    jit_role_arn: str | None = None
    jit_score: int | None = None
    jit_auto_approved: bool = False
    review_url: str | None = None  # NEEDS_HUMAN

    # Failure detail
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "next_action_hint": self.next_action_hint,
            "task_id": self.task_id,
            "task_expires_at": self.task_expires_at,
            "compatibility_verdict": self.compatibility_verdict,
            "compatibility_reasoning": self.compatibility_reasoning,
            "compatibility_matched_pattern": self.compatibility_matched_pattern,
            "jit_request_id": self.jit_request_id,
            "jit_role_arn": self.jit_role_arn,
            "jit_score": self.jit_score,
            "jit_auto_approved": self.jit_auto_approved,
            "review_url": self.review_url,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Composer
# ---------------------------------------------------------------------------


def scope_self_for_task(
    *,
    description: str,
    allow_rules: list[dict[str, Any]],
    deny_rules: list[dict[str, Any]] | None = None,
    duration_minutes: int = 30,
    workload: str | None = None,
    target_account_id: str | None = None,
    target_services: list[str] | None = None,
    owner: str | None = None,
    submit_jit_role: bool = True,
    actor: str = "agent",
) -> SelfScopeResult:
    """One-shot 'scope me for this task' composer.

    Steps (in order):

    1. Compatibility check (if `workload` is provided): consults the
       admin allowlist + curated catalog. Determines whether to also
       attempt JIT role issuance OR fall through to bouncer-only.

    2. Bouncer task creation: builds a TaskScope from the agent's
       declared allow/deny rules + duration + owner; persists it.
       Atomic per-owner single-active check enforced at the store
       layer (Slice C / WB26-HIGH-26-02 closure).

    3. JIT role submission (only if compatibility = PROCEED and
       `submit_jit_role=True`): builds an implied policy from the
       task's allow rules, calls submit_policy, returns the result.
       Auto-approves below threshold; returns NEEDS_HUMAN above.

    On any failure during steps 2-3, the bouncer task (if created
    in step 2) STAYS active — the agent gets partial scope (bouncer
    only) rather than nothing. This matches the user's "use proxy
    when iam-role isn't available" pattern.

    No user interaction required when:
    - All declared rules pass validation
    - Bouncer has no concurrent active task for `owner`
    - JIT role auto-approves (or submit_jit_role=False)
    """
    # Step 1: compatibility check (advisory; doesn't block bouncer)
    compat_verdict, compat_reasoning, compat_matched = _check_compatibility(
        workload=workload,
        target_account_id=target_account_id,
        target_services=target_services,
        actor=actor,
    )

    # If allowlist explicitly says CANNOT_HELP → respect it; don't
    # even create a bouncer task. Agent has to escalate.
    if compat_verdict == "cannot_help":
        return SelfScopeResult(
            status=SelfScopeStatus.CANNOT_HELP,
            next_action_hint=(
                "iam-jit is explicitly out-of-scope for this case per the "
                "admin allowlist. Escalate to a human; do not attempt to "
                "use iam-jit or bypass."
            ),
            compatibility_verdict=compat_verdict,
            compatibility_reasoning=compat_reasoning,
            compatibility_matched_pattern=compat_matched,
        )

    # Step 2: bouncer task scope (always attempted)
    task_id, task_expires, task_error = _create_bouncer_task(
        description=description,
        allow_rules=allow_rules,
        deny_rules=deny_rules or [],
        duration_minutes=duration_minutes,
        owner=owner,
        actor=actor,
    )
    if task_id is None:
        return SelfScopeResult(
            status=SelfScopeStatus.FAILED,
            next_action_hint=(
                f"Bouncer task creation failed: {task_error}. "
                "End any concurrent active task with `bouncer_end_task` "
                "or choose a different owner identifier, then retry."
            ),
            compatibility_verdict=compat_verdict,
            compatibility_reasoning=compat_reasoning,
            compatibility_matched_pattern=compat_matched,
            error=task_error,
        )

    # Step 3: JIT role submission (only if compatibility allows it)
    should_try_jit = (
        submit_jit_role
        and compat_verdict in (None, "proceed")  # None = no compat check; PROCEED = compat ok
    )
    if not should_try_jit:
        # Bouncer-only path. Per user direction 2026-05-17: "use the
        # proxy when you can't use an iam-role."
        return SelfScopeResult(
            status=SelfScopeStatus.SCOPED_BOUNCER_ONLY,
            next_action_hint=(
                "Bouncer task active for the duration. Proceed with "
                "whatever AWS credentials your workload already has; "
                "bouncer will gate calls against your declared task "
                "scope. Task scope expires automatically + baseline "
                "is restored."
            ),
            task_id=task_id,
            task_expires_at=task_expires,
            compatibility_verdict=compat_verdict,
            compatibility_reasoning=compat_reasoning,
            compatibility_matched_pattern=compat_matched,
        )

    jit_result = _submit_jit_role(
        description=description,
        allow_rules=allow_rules,
        target_account_id=target_account_id,
        duration_minutes=duration_minutes,
        actor=actor,
    )

    if jit_result.get("auto_approved") and jit_result.get("role_arn"):
        return SelfScopeResult(
            status=SelfScopeStatus.SCOPED,
            next_action_hint=(
                "Both bouncer task and JIT role are active. Assume "
                "the issued role; bouncer narrows to your declared "
                "task scope on top. Task + role both expire on TTL; "
                "baseline restored automatically."
            ),
            task_id=task_id,
            task_expires_at=task_expires,
            compatibility_verdict=compat_verdict,
            compatibility_reasoning=compat_reasoning,
            compatibility_matched_pattern=compat_matched,
            jit_request_id=jit_result.get("request_id"),
            jit_role_arn=jit_result.get("role_arn"),
            jit_score=jit_result.get("score"),
            jit_auto_approved=True,
        )

    # JIT role didn't auto-approve → either pending human approval,
    # or submission encountered an error. Bouncer task is still
    # active, so the agent has SOMETHING. Surface NEEDS_HUMAN.
    return SelfScopeResult(
        status=SelfScopeStatus.NEEDS_HUMAN,
        next_action_hint=(
            "Bouncer task active, but the implied JIT role didn't "
            "auto-approve (score too high OR submission error). "
            "Options: (1) wait for human approval at the review_url; "
            "(2) proceed bouncer-only without a JIT role using your "
            "existing creds; (3) end the bouncer task and re-declare "
            "with narrower scope."
        ),
        task_id=task_id,
        task_expires_at=task_expires,
        compatibility_verdict=compat_verdict,
        compatibility_reasoning=compat_reasoning,
        compatibility_matched_pattern=compat_matched,
        jit_request_id=jit_result.get("request_id"),
        jit_score=jit_result.get("score"),
        jit_auto_approved=False,
        review_url=jit_result.get("review_url"),
        error=jit_result.get("error"),
    )


# ---------------------------------------------------------------------------
# Helpers (sub-call orchestration)
# ---------------------------------------------------------------------------


def _check_compatibility(
    *,
    workload: str | None,
    target_account_id: str | None,
    target_services: list[str] | None,
    actor: str,
) -> tuple[str | None, str | None, str | None]:
    """Returns (verdict, reasoning, matched_pattern). All None if
    workload wasn't supplied (compatibility check is opt-in via the
    workload field)."""
    if workload is None:
        return None, None, None
    try:
        from ..compatibility import (
            CompatibilityIntent,
            WorkloadType,
            check_compatibility,
        )
    except Exception:
        return None, None, None
    try:
        workload_enum = WorkloadType(workload)
    except ValueError:
        return None, f"unknown workload {workload!r}", None
    try:
        from ..compatibility_allowlist import build_default_store
        allowlist = build_default_store()
    except Exception:
        allowlist = None
    intent = CompatibilityIntent(
        workload=workload_enum,
        target_account_id=target_account_id,
        target_services=tuple(target_services or ()),
    )
    result = check_compatibility(intent, allowlist=allowlist, actor=actor)
    return (
        result.verdict.value,
        result.reasoning,
        result.matched_pattern,
    )


def _create_bouncer_task(
    *,
    description: str,
    allow_rules: list[dict[str, Any]],
    deny_rules: list[dict[str, Any]],
    duration_minutes: int,
    owner: str | None,
    actor: str,
) -> tuple[str | None, str | None, str | None]:
    """Returns (task_id, expires_at, error_message). task_id is None
    on failure; error_message describes what went wrong."""
    from .store import ActiveTaskExistsError, BouncerStore
    from .tasks import TaskValidationError, build_task_scope

    try:
        scope = build_task_scope(
            description=description,
            allow_rules=allow_rules,
            deny_rules=deny_rules,
            duration_minutes=duration_minutes,
            started_by=actor,
            owner=owner,
        )
    except TaskValidationError as e:
        return None, None, f"task validation failed: {e}"

    store = BouncerStore()
    try:
        try:
            store.add_task(scope, actor=actor)
        except ActiveTaskExistsError as e:
            return None, None, str(e)
    finally:
        store.close()
    return scope.task_id, scope.expires_at, None


def _submit_jit_role(
    *,
    description: str,
    allow_rules: list[dict[str, Any]],
    target_account_id: str | None,
    duration_minutes: int,
    actor: str,
) -> dict[str, Any]:
    """Build an implied IAM policy from the task's allow rules + ask
    iam-jit to issue a JIT role. Returns a dict with keys
    {auto_approved, role_arn, request_id, score, review_url, error}.

    Slice E ships a SIMPLE policy implication: each allow rule
    becomes one Allow statement with the action pattern + Resource
    set to arn_scope (or "*" if unset). Slice F+ could refine
    (e.g. consolidate same-resource patterns, add Condition keys
    from region_scope).
    """
    statements: list[dict[str, Any]] = []
    for r in allow_rules:
        if not isinstance(r, dict):
            continue
        pattern = r.get("pattern")
        if not pattern:
            continue
        statements.append({
            "Effect": "Allow",
            "Action": pattern,
            "Resource": r.get("arn_scope") or "*",
        })
    if not statements:
        return {
            "auto_approved": False,
            "error": "no valid allow rules to derive a JIT policy",
        }

    policy = {"Version": "2012-10-17", "Statement": statements}
    accounts = [target_account_id] if target_account_id else []
    if not accounts:
        # iam-jit submit_policy requires at least one account
        return {
            "auto_approved": False,
            "error": (
                "target_account_id is required to submit a JIT role; "
                "bouncer task scope still active for the duration"
            ),
        }

    duration_hours = max(1, duration_minutes // 60)
    # Lazy import the MCP-layer submit so we don't depend on it at
    # module load (keeps the composer dependency-free for tests).
    try:
        from ..mcp_server import _submit_policy_for_mcp
    except Exception as e:
        return {"auto_approved": False, "error": f"submit unavailable: {e}"}

    submit_args = {
        "policy": policy,
        "description": description,
        "accounts": accounts,
        "duration_hours": duration_hours,
    }
    try:
        out = _submit_policy_for_mcp(submit_args)
    except Exception as e:
        return {"auto_approved": False, "error": f"submit raised: {e}"}

    if out.get("error"):
        return {
            "auto_approved": False,
            "error": out["error"],
            "request_id": out.get("request_id"),
        }

    return {
        "auto_approved": bool(out.get("auto_approved")),
        "role_arn": (out.get("server_response") or {}).get("role_arn"),
        "request_id": out.get("request_id"),
        "score": out.get("score"),
        "review_url": out.get("review_url"),
    }


# ---------------------------------------------------------------------------
# Effective-scope query (what's gating me RIGHT NOW)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class EffectiveScope:
    """Composed view of the bouncer's current decision shape — what
    rules + task + default would apply to a hypothetical call right
    now. Read-only; for visibility.
    """

    has_active_task: bool
    active_task_id: str | None
    active_task_description: str | None
    active_task_expires_at: str | None
    active_task_owner: str | None
    active_task_allow_rule_count: int
    active_task_deny_rule_count: int
    global_rule_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_active_task": self.has_active_task,
            "active_task_id": self.active_task_id,
            "active_task_description": self.active_task_description,
            "active_task_expires_at": self.active_task_expires_at,
            "active_task_owner": self.active_task_owner,
            "active_task_allow_rule_count": self.active_task_allow_rule_count,
            "active_task_deny_rule_count": self.active_task_deny_rule_count,
            "global_rule_count": self.global_rule_count,
        }


def get_effective_scope(*, owner: str | None = None) -> EffectiveScope:
    """Return a composed snapshot of "what's gating you right now."

    Per the user's "return to baseline" clarification (2026-05-17):
    when no task is active, has_active_task=False and the global
    rules ARE the effective scope. When a task ends, this method's
    next call shows the post-baseline state.
    """
    from .store import BouncerStore

    store = BouncerStore()
    try:
        active = store.get_active_task(owner=owner)
        global_rules = store.list_rules()
    finally:
        store.close()
    if active is None:
        return EffectiveScope(
            has_active_task=False,
            active_task_id=None,
            active_task_description=None,
            active_task_expires_at=None,
            active_task_owner=None,
            active_task_allow_rule_count=0,
            active_task_deny_rule_count=0,
            global_rule_count=len(global_rules),
        )
    return EffectiveScope(
        has_active_task=True,
        active_task_id=active.task_id,
        active_task_description=active.description,
        active_task_expires_at=active.expires_at,
        active_task_owner=active.owner,
        active_task_allow_rule_count=len(active.allow_rules),
        active_task_deny_rule_count=len(active.deny_rules),
        global_rule_count=len(global_rules),
    )
