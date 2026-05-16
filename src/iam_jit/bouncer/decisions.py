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
    """
    matched = ruleset.evaluate(
        service=service, action=action, arn=arn, region=region
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

    if matched is not None:
        effect, rule = matched
        # Explicit-rule decisions are the same in ENFORCE and PROMPT.
        return DecisionRecord(
            decision=Decision.DENY if effect == Effect.DENY else Decision.ALLOW,
            mode=mode,
            service=service,
            action=action,
            arn=arn,
            region=region,
            matched_rule=rule,
            reason=f"explicit-{effect.value} rule",
        )

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
