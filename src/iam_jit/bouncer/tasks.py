"""Bouncer task scope — agent-declared per-task rule overlays.

Per [[proxy-smart-defaults-and-task-scope]]: an agent doing a
discrete task (the canonical example: "upgrade EKS staging cluster
control plane to 1.30") declares a TASK SCOPE at task start. The
bouncer enforces that scope for the task's duration; the audit
chain captures the task lifecycle. When the task ends (explicit end
OR time-based expiry), the scope drops and the bouncer returns to
its baseline behavior.

The composition model with global rules ([[safety-mode-lean-permissive]]
+ admin-minus-sensitive default):

  ALLOW = (no global-explicit-deny matches)
          AND (no task-explicit-deny matches)
          AND (
              task-allow-rule matches
              OR (no task allow rules apply AND global rules allow)
          )

In plain English:
- Global explicit deny ALWAYS wins (the admin's baseline can't be
  overridden by a task scope).
- Task explicit deny ALSO wins (the agent saying "no prod" enforces
  even if global rules would have allowed).
- Task allow takes precedence when it matches (the agent's positive
  declaration is what the task is for).
- Unmatched-by-task-allow falls through to global rules (so
  infrastructure calls like `sts:GetCallerIdentity` that the agent
  didn't think to declare still work if global rules allow them).

The agent decides how strict to be by what task allows + denies they
declare. The recommended pattern for the staging-EKS case: declare
allow rules for the EKS + EC2-describe calls the upgrade needs,
declare a deny rule for the prod account ARN pattern, let global
rules handle the housekeeping.

Per [[agent-friendly-not-bypassable]]:
- Lens A: agent declares the task at start; the bouncer enforces
  during the duration; agents get a clear answer for every call.
- Lens B: every task lifecycle event is audit-logged via
  `config_events` (`task_started` / `task_ended`); decisions during
  the task reference the active `task_id` so post-incident review
  can answer "what was this agent authorized to do, and did
  anything escape that scope?"
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import uuid
from enum import Enum
from typing import Any

from .rules import Effect, ProxyRule, RuleSet


class TaskStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"  # explicitly ended via bouncer_end_task
    EXPIRED = "expired"      # auto-ended on duration expiry
    REPLACED = "replaced"    # superseded by a newer task (Slice C may
                             # add concurrent tasks; today: one at a time)


@dataclasses.dataclass(frozen=True)
class TaskScope:
    """An agent's declared task scope.

    `allow_rules` is the positive declaration: "these are the calls
    the task needs." `deny_rules` is the explicit narrowing: "these
    calls MUST be denied even if global rules would allow them"
    (e.g. "no prod account").

    `expires_at` is absolute time, not duration — `start_task`
    computes it from `duration_minutes` so storage / read paths
    don't have to worry about clock drift.
    """

    task_id: str
    description: str
    allow_rules: tuple[ProxyRule, ...]
    deny_rules: tuple[ProxyRule, ...]
    started_at: str  # ISO-8601 UTC
    expires_at: str  # ISO-8601 UTC
    started_by: str
    status: TaskStatus = TaskStatus.ACTIVE
    ended_at: str | None = None
    ended_by: str | None = None
    end_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "description": self.description,
            "allow_rules": [r.to_dict() for r in self.allow_rules],
            "deny_rules": [r.to_dict() for r in self.deny_rules],
            "started_at": self.started_at,
            "expires_at": self.expires_at,
            "started_by": self.started_by,
            "status": self.status.value,
            "ended_at": self.ended_at,
            "ended_by": self.ended_by,
            "end_reason": self.end_reason,
        }

    def is_expired(self, now: _dt.datetime | None = None) -> bool:
        """True if the task's wall-clock expiry has passed."""
        if self.status != TaskStatus.ACTIVE:
            return False
        cur = now or _dt.datetime.now(_dt.UTC)
        try:
            expires = _dt.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return False
        return cur >= expires

    def allow_ruleset(self) -> RuleSet:
        return RuleSet(rules=list(self.allow_rules))

    def deny_ruleset(self) -> RuleSet:
        return RuleSet(rules=list(self.deny_rules))


class TaskValidationError(ValueError):
    """Raised when an agent's start_task input is malformed."""


def _isoformat_z(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_task_scope(
    *,
    description: str,
    allow_rules: list[dict[str, Any]] | list[ProxyRule] | None = None,
    deny_rules: list[dict[str, Any]] | list[ProxyRule] | None = None,
    duration_minutes: int = 30,
    started_by: str,
    task_id: str | None = None,
    started_at: str | None = None,
) -> TaskScope:
    """Validating constructor used by the MCP tool + CLI + tests.

    Rules can be supplied as ProxyRule instances OR as dict shapes
    (`{pattern, effect?, arn_scope?, region_scope?, note?}`) — the
    MCP path passes dicts; tests pass either. Effect is forced:
    allow_rules always get ALLOW, deny_rules always get DENY (the
    distinction is which list they're in, not a per-rule field).
    """
    if not description or not description.strip():
        raise TaskValidationError("description is required and must be non-empty")
    if not isinstance(duration_minutes, int) or duration_minutes < 1:
        raise TaskValidationError("duration_minutes must be a positive integer")
    if duration_minutes > 24 * 60:
        raise TaskValidationError(
            "duration_minutes max is 1440 (24h); use multiple tasks for longer work"
        )

    allow_clean = _coerce_rules(allow_rules or [], default_effect=Effect.ALLOW)
    deny_clean = _coerce_rules(deny_rules or [], default_effect=Effect.DENY)

    if not allow_clean and not deny_clean:
        raise TaskValidationError(
            "at least one allow_rule or deny_rule is required — a task scope "
            "with no rules has no effect"
        )

    now = _dt.datetime.now(_dt.UTC)
    started = started_at or _isoformat_z(now)
    expires = _isoformat_z(now + _dt.timedelta(minutes=duration_minutes))

    return TaskScope(
        task_id=task_id or uuid.uuid4().hex[:12],
        description=description.strip(),
        allow_rules=tuple(allow_clean),
        deny_rules=tuple(deny_clean),
        started_at=started,
        expires_at=expires,
        started_by=started_by,
    )


def _coerce_rules(
    rules: list[Any], *, default_effect: Effect
) -> list[ProxyRule]:
    """Accept dicts or ProxyRules; force effect to default; validate
    each via the same parse_pattern checks the store uses for
    persistent rules."""
    from .rules import parse_pattern

    out: list[ProxyRule] = []
    for r in rules:
        if isinstance(r, ProxyRule):
            # Force effect to match the list it's in
            rule = dataclasses.replace(r, effect=default_effect, origin="task")
        elif isinstance(r, dict):
            pattern = r.get("pattern")
            if not isinstance(pattern, str) or not pattern.strip():
                raise TaskValidationError(
                    f"rule entry missing 'pattern' or pattern is empty: {r!r}"
                )
            rule = ProxyRule(
                pattern=pattern.strip(),
                effect=default_effect,
                arn_scope=r.get("arn_scope"),
                region_scope=r.get("region_scope"),
                note=r.get("note"),
                origin="task",
            )
        else:
            raise TaskValidationError(
                f"rule entry must be a dict or ProxyRule, got {type(r).__name__}"
            )
        if parse_pattern(rule.pattern) is None:
            raise TaskValidationError(
                f"rule pattern {rule.pattern!r} is malformed; "
                "must be `service:action_glob` (e.g. `eks:*`, `iam:PassRole`, or `*:Delete*`)"
            )
        out.append(rule)
    return out
