"""Pluggable LLM backends for iam-jit.

This module was historically a single `iam_jit/llm.py` file. As of the
pluggable-backend slice (2026-05-19) it is a package so we can host
the per-provider `score_policy()` wrappers in `backends/` and the
selection logic in `registry.py` — without breaking any existing
`from iam_jit.llm import X` consumer.

PUBLIC API (preserved verbatim from the old single-file module):
  - `NoOpBackend`, `OllamaBackend`, `AnthropicBackend`, `BedrockBackend`
  - `RecordingBackend`, `CassetteMiss`, `wrap_with_cassette`
  - `_parse`, `_cassette_key` (test-suite consumers)
  - `get_backend`, `get_backend_for_tier`
  - `LLMBackend` (Protocol)
  - `SYSTEM_PROMPT`

PUBLIC API (added by the pluggable slice):
  - `score_policy(policy, context, *, preferred_backend=None)` — convenience
    entry point that picks a backend and calls it.
  - `default_score_backend(preferred=None)` — backend selection.
  - `get_score_backend(name)` — fetch a specific backend module.
  - `available_backends()` — list of registered backend names.
  - `ScoreContext`, `ScoreResponse` — the per-call envelope.
"""

from __future__ import annotations

from typing import Any

# Back-compat re-exports — every symbol that any caller in the codebase
# (or the test suite) imported from `iam_jit.llm` BEFORE the package
# conversion. DO NOT remove any of these without a deprecation cycle.
from ._core import (  # noqa: F401
    SYSTEM_PROMPT,
    AnthropicBackend,
    BedrockBackend,
    CassetteMiss,
    LLMBackend,
    NoOpBackend,
    OllamaBackend,
    RecordingBackend,
    _cassette_key,
    _parse,
    get_backend,
    get_backend_for_tier,
    wrap_with_cassette,
)

# New pluggable-backend API surface.
from .registry import (  # noqa: F401
    available_backends,
    default_score_backend,
    get_score_backend,
)
from .report_skip import (  # noqa: F401
    REASON_BACKEND_UNAVAILABLE,
    REASON_BUDGET_EXCEEDED,
    REASON_NO_LLM_BACKEND,
    REASON_NO_SIDE_LLM_ENABLED,
    REASON_RESPONSE_INVALID,
    report_skip,
    reset_skip_counter,
    skip_counter_snapshot,
)
from .types import ScoreContext, ScoreResponse  # noqa: F401


def score_policy(
    policy: dict[str, Any],
    context: ScoreContext,
    *,
    preferred_backend: str | None = None,
) -> ScoreResponse:
    """Convenience: pick a backend and call `score_policy` on it.

    Returns an empty `ScoreResponse` (caller falls back to
    deterministic-only) when no backend is available or the backend
    fails internally.
    """
    backend = default_score_backend(preferred=preferred_backend)
    if backend is None:
        return ScoreResponse(backend_name="")
    return backend.score_policy(policy, context)


__all__ = [
    # Back-compat
    "SYSTEM_PROMPT",
    "AnthropicBackend",
    "BedrockBackend",
    "CassetteMiss",
    "LLMBackend",
    "NoOpBackend",
    "OllamaBackend",
    "RecordingBackend",
    "_cassette_key",
    "_parse",
    "get_backend",
    "get_backend_for_tier",
    "wrap_with_cassette",
    # New
    "ScoreContext",
    "ScoreResponse",
    "available_backends",
    "default_score_backend",
    "get_score_backend",
    "score_policy",
    # #509 Phase 2 — silent-degradation tracker
    "REASON_BACKEND_UNAVAILABLE",
    "REASON_BUDGET_EXCEEDED",
    "REASON_NO_LLM_BACKEND",
    "REASON_NO_SIDE_LLM_ENABLED",
    "REASON_RESPONSE_INVALID",
    "report_skip",
    "reset_skip_counter",
    "skip_counter_snapshot",
]
