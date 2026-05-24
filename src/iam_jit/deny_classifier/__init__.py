"""§A50 / #404 — LLM-classifier for deny-reason.

When a deny occurs (after the deterministic profile/scope/floor said NO),
this module's `classify_deny()` looks at the deny event + recent operator
context + the agent's prompt context and tags the deny as one of:

  * `appears_legitimate` — fits the operator's observed pattern; agent
    can suggest an easy-allow flow with confidence
  * `ambiguous`          — plausible but novel; operator should decide
  * `appears_adversarial`— matches a known-adversarial pattern (e.g.
    `iam:CreateAccessKey` from a data-reporting agent); agent must
    halt + escalate regardless of any operator auto-allow config

The classifier is ADVISORY only — per `[[scorer-is-ground-truth]]`, it
NEVER replaces the deterministic deny floor. If the deterministic
scorer/profile denies, the deny happens; the classifier just helps the
agent + operator decide what to do AFTER the deny.

Public API:

  >>> from iam_jit.deny_classifier import classify_deny
  >>> result = classify_deny(
  ...     deny_event={
  ...         "action": "iam:CreateAccessKey",
  ...         "resource": "*",
  ...         "agent_prompt_context": "...",
  ...         "operator_recent_pattern": "...",
  ...     },
  ...     backend="anthropic",
  ...     budget_usd=0.001,
  ... )
  >>> result["classification"]
  'appears_adversarial'
  >>> result["advisory_action"]
  'escalate'

Phase B (#402 structured deny response + #401 improve + #403 autopilot)
consumes this module via the public `classify_deny()` function.

Safety rails (encoded as invariants in `classifier.py`):
  1. High-confidence-adversarial (confidence > 0.85) → `escalate`,
     ALWAYS, even when operator config says auto-allow.
  2. Budget exceeded → fallback `ambiguous` / `hold` (never crash the
     deny path; just decline to classify).
  3. LLM unavailable → same fallback.
  4. Free tier → classifier disabled with clear upgrade message.
"""

from __future__ import annotations

from .classifier import (
    ClassifierResult,
    DenyEvent,
    classify_deny,
    is_known_adversarial,
)

__all__ = [
    "ClassifierResult",
    "DenyEvent",
    "classify_deny",
    "is_known_adversarial",
]
