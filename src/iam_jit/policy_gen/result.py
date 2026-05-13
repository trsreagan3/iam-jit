"""Data types for policy generation.

These types are intentionally simple — no validation magic, no
inheritance. The generator pipeline reads `GenerationRequest`, mutates
a working `GenerationResult`, and returns it. The caller (CLI or API
handler) is responsible for turning the result into a JIT-request
payload or rejecting it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# Bias values — passed to the generator to control how it resolves
# ambiguity in the task description.
#
# `allow`: when uncertain whether an action is needed, INCLUDE it.
#   Produces broader (more permissive) policies. Better UX for
#   legitimate users; the scorer still floors at high scores for
#   genuinely dangerous combinations.
#
# `deny`: when uncertain, EXCLUDE the action. Produces narrower
#   policies. Better for strict-compliance environments and fully-
#   automated agent loops where over-grant is more costly than
#   re-asking the user for detail.
BIAS_ALLOW: Literal["allow"] = "allow"
BIAS_DENY: Literal["deny"] = "deny"

Bias = Literal["allow", "deny"]


@dataclass
class GenerationContext:
    """Optional context the caller passes to bias generation.

    Most fields are advisory. The generator uses them to fill resource
    templates and select between AWS partitions / regions when the
    user description is ambiguous.
    """

    # AWS account ID the requester is operating in. Used to construct
    # ARN account segments when the user doesn't supply explicit
    # ARNs. Wildcards in if unset.
    account_id: str | None = None

    # Preferred AWS region. Used for region segment in constructed
    # ARNs. Wildcards in if unset.
    region: str | None = None

    # AWS partition (`aws`, `aws-cn`, `aws-us-gov`). Default `aws`.
    partition: str = "aws"

    # Caller-supplied explicit resource ARNs that should appear in the
    # generated policy. Use this when the task description references
    # resources by name and the caller has already resolved the names
    # to ARNs (e.g. via a wrapper agent).
    resources: list[str] = field(default_factory=list)


@dataclass
class Refinement:
    """Caller-supplied refinement applied AFTER pattern matching.

    Used when the user reviewed a previous `GenerationResult` and wants
    to iterate ("too strict — also add s3:DeleteObject" or "too broad
    — remove iam:PassRole"). The generator applies the refinement to
    the heuristic output before scoring, so the final result reflects
    both the original task description AND the user's edits.
    """
    # Action names (or `service:*` wildcards) to remove from the
    # generated policy. Useful when the user thinks the generator
    # over-included.
    exclude_actions: list[str] = field(default_factory=list)

    # Action names to add to the generated policy. Each must be in
    # `service:Action` form. Useful when the user knows a specific
    # action the pattern didn't include.
    include_actions: list[str] = field(default_factory=list)

    # Resource ARNs to add. The generator places these on the
    # statement(s) whose actions target the same service-kind.
    include_resources: list[str] = field(default_factory=list)

    # Resource ARNs to remove (e.g. drop the wildcard fallback).
    exclude_resources: list[str] = field(default_factory=list)

    # Free-text rationale the caller is supplying for audit. Surfaces
    # in `GenerationResult.reasons`. Optional but recommended — a
    # one-line "why I refined this way" makes audit logs much more
    # useful.
    rationale: str = ""


@dataclass
class GenerationRequest:
    """A request to generate a policy for a task description."""

    # The natural-language task description. The heuristic pattern
    # matcher reads this directly.
    task_description: str

    # Bias setting — see BIAS_ALLOW / BIAS_DENY.
    bias: Bias = BIAS_ALLOW

    # Optional context (account, region, explicit resources).
    context: GenerationContext = field(default_factory=GenerationContext)

    # Hint about the expected access type (mirrors the scoring
    # request's access_type). The generator uses this to bias
    # toward Read/List vs Write actions when ambiguous.
    access_type: Literal["read", "read-only", "read-write"] = "read-write"

    # Duration hours — passed through to the scoring step.
    duration_hours: int = 1

    # Iterative refinement applied AFTER pattern matching. Set this
    # when the caller is re-generating in response to a previous
    # result that was too strict, too broad, or otherwise wrong.
    # None = first-pass generation, no edits applied.
    refinement: Refinement | None = None


@dataclass
class GenerationResult:
    """The generator's verdict on a request.

    Always returned by `generate_policy()` — even when the generator
    couldn't match the description to a pattern (in that case
    `policy` is None and `unmatched_reason` explains why).
    """

    # The generated IAM policy, ready to attach to a role. None if
    # the generator couldn't produce a policy.
    policy: dict[str, Any] | None

    # Patterns that matched the description, in match order.
    # Documents what the generator inferred from the task wording.
    matched_patterns: list[str] = field(default_factory=list)

    # Per-decision reasons — actions added, resources filled,
    # ambiguity resolutions, bias choices. Surfaces in audit logs.
    reasons: list[str] = field(default_factory=list)

    # Confidence in the generation (1-10).
    #   1 = "matched a known pattern with full resource detail; high
    #        confidence the policy reflects the user's intent"
    #   10 = "no pattern matched; output is a hand-coded fallback or
    #        the description was too ambiguous"
    # Note: higher = LESS confident. Mirrors the risk-score direction
    # (higher = more concerning).
    confidence: int = 5

    # The deterministic risk score from running the generated policy
    # through `analyze_policy()`. None if generation didn't produce
    # a policy.
    scored_risk: int | None = None

    # Risk factors from the scorer — verbatim list returned by
    # analyze_policy. Useful when the generator's output scored
    # higher than the caller expected.
    risk_factors: list[str] = field(default_factory=list)

    # Suggestions the scorer returned alongside the score (e.g.
    # "scope this S3 read to a specific bucket ARN").
    risk_suggestions: list[str] = field(default_factory=list)

    # When `policy is None`, this explains why no policy was
    # produced. Empty otherwise.
    unmatched_reason: str = ""

    # When the generator wanted to include an action but the bias
    # said no, those actions are listed here. Lets the caller
    # surface "you might also need: ..." to the user.
    suppressed_actions: list[str] = field(default_factory=list)

    # Refinement hints — suggestions the caller can use to iterate
    # if the result was too strict or too broad. Each hint is a
    # short human-readable string with an embedded refinement
    # template the UI/agent can apply directly. Populated by the
    # generator based on the matched patterns and the scored risk.
    refinement_hints: list[str] = field(default_factory=list)
