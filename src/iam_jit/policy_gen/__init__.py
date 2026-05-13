"""Policy generation — natural-language task description → scoped IAM policy.

The generator is intentionally LAYERED so the deterministic safety floor
from `iam_jit.review.analyze_policy` is always the final arbiter of
whether a generated policy is safe to use:

  1. Heuristic pattern library matches the task description against
     known shapes (S3 read, Lambda deploy, DynamoDB query, etc.) and
     proposes a draft policy.
  2. Resource extraction pulls explicit ARNs from the description and
     fills the pattern's resource template; missing info → wildcards.
  3. Bias logic decides which actions go into the draft when intent
     is ambiguous:
       - `allow` bias: include more actions (better UX, scorer catches
         anything genuinely dangerous).
       - `deny` bias: include only actions explicitly required.
  4. The draft policy is scored by `analyze_policy()`. The risk score
     and the generator's own confidence are both returned to the
     caller so the request workflow can decide whether to auto-approve.

The generator does NOT make safety decisions on its own. It proposes;
the scorer disposes. This separation is what makes the feature safe
to ship without the same multi-round adversarial discipline the
scorer itself went through (the scorer's discipline transitively
protects every generator output).

Public API:
  - `generate_policy(request) -> GenerationResult`
  - `GenerationRequest`, `GenerationContext`, `GenerationResult` dataclasses
  - `BIAS_ALLOW`, `BIAS_DENY` constants

See `docs/agent-access.md` for the workflow and CLI usage.
"""

from __future__ import annotations

from .result import (
    BIAS_ALLOW,
    BIAS_DENY,
    GenerationContext,
    GenerationRequest,
    GenerationResult,
    Refinement,
)
from .generate import generate_policy

__all__ = [
    "BIAS_ALLOW",
    "BIAS_DENY",
    "GenerationContext",
    "GenerationRequest",
    "GenerationResult",
    "Refinement",
    "generate_policy",
]
