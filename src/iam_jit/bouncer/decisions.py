"""Bouncer decision logic — combines RuleSet evaluation with the
current mode and default policy to reach a final Decision.

Three modes, per [[safety-mode-lean-permissive]] + [[safety-mode-two-modes]]
shape:

- LEARN  — observe everything; always ALLOW; record the call so the
           user can convert it into rules later. The default; safer
           for adoption since the bouncer can't break a workflow on
           first install. Captured calls don't show in `rules list`
           — they live in the audit log + a separate `learned/`
           inbox the user reviews with `rules learn-review`.
- ENFORCE — apply rules. Unmatched calls follow `default_policy`
            (ALLOW or DENY). This is the production mode.
- PROMPT  — apply rules. Unmatched calls return PROMPT so the proxy
            server can interrupt the user / agent. Pre-launch we
            ship the Decision type; the actual prompt UX comes in
            Stage 2.

Why three not two: LEARN exists because adoption fails when the
first action a tool takes is to block. ENFORCE is the steady-state.
PROMPT is the high-touch developer mode for handling the long tail
of one-off calls without writing rules upfront.
"""

from __future__ import annotations

import dataclasses
from enum import Enum

from .rules import Effect, ProxyRule, RuleSet


class Mode(str, Enum):
    LEARN = "learn"
    ENFORCE = "enforce"
    PROMPT = "prompt"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    PROMPT = "prompt"  # caller (proxy server) must interactively ask


class DefaultPolicy(str, Enum):
    """What ENFORCE mode does when no rule matches."""

    ALLOW = "allow"
    DENY = "deny"


@dataclasses.dataclass(frozen=True)
class DecisionRecord:
    """The full decision context — what was decided and why.

    Logged to the audit-log SQLite table so the user can review
    every gate the bouncer made. Includes the matched rule (if any)
    so review can spot over-broad rules quickly.
    """

    decision: Decision
    mode: Mode
    service: str
    action: str
    arn: str | None
    region: str | None
    matched_rule: ProxyRule | None
    reason: str  # short human label for "why"

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "mode": self.mode.value,
            "service": self.service,
            "action": self.action,
            "arn": self.arn,
            "region": self.region,
            "matched_rule": self.matched_rule.to_dict() if self.matched_rule else None,
            "reason": self.reason,
        }


def decide(
    ruleset: RuleSet,
    *,
    mode: Mode,
    default_policy: DefaultPolicy,
    service: str,
    action: str,
    arn: str | None = None,
    region: str | None = None,
    active_task: Any | None = None,  # TaskScope; lazy-typed to avoid circ import
) -> DecisionRecord:
    """Combine rule evaluation + mode + default-policy into a final
    DecisionRecord. Pure: no I/O, no side effects.

    The caller (proxy server or `iam-jit-bouncer decide` CLI) takes
    the result and either forwards the request (ALLOW), returns an
    error to the client (DENY), or invokes the interactive prompt
    UX (PROMPT).

    LEARN-mode invariant: NEVER returns DENY. The matched_rule field
    still records what WOULD have matched in ENFORCE mode, so the
    user can preview "what would my current rules do?" without
    actually breaking anything.

    Slice B of [[proxy-smart-defaults-and-task-scope]]: if an
    `active_task` is provided, its allow + deny rules layer onto the
    decision per the composition documented in `tasks.py`:
    - task-deny match → DENY (the agent's "no prod" wins even if
      global rules would allow)
    - task-allow match → ALLOW (with global-deny still able to block)
    - unmatched-by-task → fall through to global rules

    The result's `reason` includes the active task_id so the audit
    chain captures task-scope effect.
    """
    matched = ruleset.evaluate(
        service=service, action=action, arn=arn, region=region
    )

    # Slice B: task-deny wins over everything (including LEARN's
    # no-deny invariant — the agent's explicit "no prod" must hold
    # even when the operator is in learn mode; otherwise the learn-
    # mode contract would have agents accidentally write to prod
    # during a "narrow this task" workflow).
    if active_task is not None:
        task_deny = active_task.deny_ruleset().evaluate(
            service=service, action=action, arn=arn, region=region
        )
        if task_deny is not None:
            _, task_rule = task_deny
            return DecisionRecord(
                decision=Decision.DENY,
                mode=mode,
                service=service,
                action=action,
                arn=arn,
                region=region,
                matched_rule=task_rule,
                reason=(
                    f"task-explicit-deny rule (task {active_task.task_id})"
                ),
            )

    if mode == Mode.LEARN:
        # Always allow; preserve the matched rule for review purposes.
        if matched is not None:
            effect, rule = matched
            return DecisionRecord(
                decision=Decision.ALLOW,
                mode=mode,
                service=service,
                action=action,
                arn=arn,
                region=region,
                matched_rule=rule,
                reason=f"learn-mode (would-{effect.value} per rule)",
            )
        return DecisionRecord(
            decision=Decision.ALLOW,
            mode=mode,
            service=service,
            action=action,
            arn=arn,
            region=region,
            matched_rule=None,
            reason="learn-mode (unmatched; recording for later review)",
        )

    # Global explicit-rule decisions come BEFORE task-allow because
    # the global ruleset can include an explicit DENY (e.g. the
    # admin-minus-sensitive baseline denies secret reads) and that
    # must win even if the agent's task-allow says otherwise. Task
    # scope NARROWS within global guardrails; it doesn't lift them.
    if matched is not None:
        effect, rule = matched
        if effect == Effect.DENY:
            return DecisionRecord(
                decision=Decision.DENY,
                mode=mode,
                service=service,
                action=action,
                arn=arn,
                region=region,
                matched_rule=rule,
                reason="explicit-deny rule",
            )
        # Global explicit ALLOW; task-allow can still narrow further
        # below, but if no task is active, this allows.
        if active_task is None:
            return DecisionRecord(
                decision=Decision.ALLOW,
                mode=mode,
                service=service,
                action=action,
                arn=arn,
                region=region,
                matched_rule=rule,
                reason="explicit-allow rule",
            )

    # Slice B: with an active task, the task-allow ruleset acts as
    # a NARROWED positive declaration. If task-allow matches → ALLOW
    # (no further check needed; global deny was already handled
    # above). If task-allow does NOT match → fall through to the
    # next layer (global allow if matched + no task allows declared
    # cover this; else default).
    if active_task is not None:
        task_allow = active_task.allow_ruleset().evaluate(
            service=service, action=action, arn=arn, region=region
        )
        if task_allow is not None:
            _, task_rule = task_allow
            return DecisionRecord(
                decision=Decision.ALLOW,
                mode=mode,
                service=service,
                action=action,
                arn=arn,
                region=region,
                matched_rule=task_rule,
                reason=(
                    f"task-allow rule (task {active_task.task_id})"
                ),
            )
        # No task-allow rule matched. Two sub-cases:
        # (a) Global ALLOW already matched → ALLOW (the global rule's
        #     decision still holds; task scope didn't add a NEW
        #     positive rule for this call, but the call was already
        #     blessed by the operator's global baseline).
        # (b) Global didn't match either → DENY (task is active; the
        #     agent's positive declaration is the allowlist for this
        #     task; unmatched-by-task = "not part of the task; deny").
        if matched is not None:
            effect, rule = matched
            return DecisionRecord(
                decision=Decision.ALLOW,
                mode=mode,
                service=service,
                action=action,
                arn=arn,
                region=region,
                matched_rule=rule,
                reason=(
                    f"explicit-allow rule (global; not declared in task "
                    f"{active_task.task_id})"
                ),
            )
        return DecisionRecord(
            decision=Decision.DENY,
            mode=mode,
            service=service,
            action=action,
            arn=arn,
            region=region,
            matched_rule=None,
            reason=(
                f"out-of-task-scope (task {active_task.task_id} active; "
                "unmatched by task allow rules)"
            ),
        )

    # No active task; matched is None here (handled above when present).

    # No rule matched.
    if mode == Mode.PROMPT:
        return DecisionRecord(
            decision=Decision.PROMPT,
            mode=mode,
            service=service,
            action=action,
            arn=arn,
            region=region,
            matched_rule=None,
            reason="prompt-mode unmatched (awaiting user input)",
        )

    # ENFORCE mode + no matching rule → default policy.
    fallback = (
        Decision.ALLOW if default_policy == DefaultPolicy.ALLOW else Decision.DENY
    )
    return DecisionRecord(
        decision=fallback,
        mode=mode,
        service=service,
        action=action,
        arn=arn,
        region=region,
        matched_rule=None,
        reason=f"enforce-mode unmatched (default-{default_policy.value})",
    )
