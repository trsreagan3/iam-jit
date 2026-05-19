"""Per-provider `score_policy` wrappers.

Each module here adapts the corresponding backend in
`iam_jit.llm._core` (which exposes `refine()` + `chat()`) to the
`score_policy(policy, context) -> ScoreResponse` shape consumed by
the pluggable scorer abstraction.

Adding a new provider is a 4-step recipe:

  1. Implement `BackendImpl` (subclass `_core` if it adds a third
     provider; otherwise just wrap the SDK call here).
  2. Implement `score_policy(policy, context) -> ScoreResponse`.
  3. Implement `is_available() -> bool` (checks env / SDK install).
  4. Implement `estimate_cost_per_1k(input_tokens, output_tokens) -> float`.

Then register the name in `iam_jit.llm.registry._BACKENDS`.
"""

from __future__ import annotations
