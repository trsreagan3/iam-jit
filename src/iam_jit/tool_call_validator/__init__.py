"""Hallucinated-tool-call validator (task #729 / BUILD-8).

Inspects OUTBOUND agent tool-call request bodies (MCP / OpenAI / Anthropic
shapes) and reports calls whose `name` + `arguments` don't match any
schema in the corpus. Per the competitive-firewall landscape PDF this is
the single highest individual catch-rate of the differentiators
(~95% — claim INTENTIONALLY NOT in code/docs until calibrated against
a real corpus).

Structurally pairs with `iam_jit.injection_scanner` (BUILD-9, #730):
- BUILD-9 inspects RESPONSE bodies for indirect prompt-injection
- BUILD-8 inspects REQUEST bodies for hallucinated tool-call shapes

Public API:

  - `validate(body, *, schema_corpus=None, allowlist_patterns=(),
      max_body_bytes=64*1024)` -> `ValidationResult`
  - `ValidationResult` (frozen dataclass)
  - `Indicator` (frozen dataclass)
  - `Action` (Literal: warn | strip | deny | allow)
  - `ProfileConfig` (frozen dataclass)
  - `SchemaCorpus` (frozen dataclass)
  - `default_corpus()` -> `SchemaCorpus`
  - `decide_action(result, profile)` -> `Action`
  - `apply_strip(body, result)` -> str

Per [[ibounce-honest-positioning]] + [[scorer-is-ground-truth]]:
- Every indicator carries `rule`, `shape`, `tool_name`, `severity`,
  `source`, `reason`.
- Confidence weighting is documented (see `_compute_confidence`) and
  MUST NOT be tuned post-hoc.
- Low-confidence detections populate `low_confidence_explanation` so
  callers always have a reason string to log.
"""

from __future__ import annotations

from .config import ProfileConfig
from .corpus import SchemaCorpus, ToolSchema, default_corpus
from .validator import (
    Action,
    Indicator,
    ValidationResult,
    apply_strip,
    decide_action,
    validate,
)

__all__ = [
    "Action",
    "Indicator",
    "ProfileConfig",
    "SchemaCorpus",
    "ToolSchema",
    "ValidationResult",
    "apply_strip",
    "decide_action",
    "default_corpus",
    "validate",
]
