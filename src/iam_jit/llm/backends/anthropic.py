"""Anthropic API backend (api.anthropic.com)."""

from __future__ import annotations

import logging
import os
from typing import Any

from .._core import AnthropicBackend as _CoreAnthropicBackend
from ..types import ScoreContext, ScoreResponse
from ._score_prompt import SCORE_SYSTEM_PROMPT, build_user_message, parse_score_response

logger = logging.getLogger("iam_jit.llm.backends.anthropic")

name = "anthropic"


# Sonnet-class default pricing. Operators on Opus pay more; this is
# a rough order-of-magnitude estimate, not a billing source of truth.
_ANTHROPIC_DEFAULT_INPUT_USD = 0.003
_ANTHROPIC_DEFAULT_OUTPUT_USD = 0.015


def is_available() -> bool:
    """`ANTHROPIC_API_KEY` set AND `anthropic` SDK importable."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def estimate_cost_per_1k(input_tokens: int, output_tokens: int) -> float:
    return (
        (input_tokens / 1000.0) * _ANTHROPIC_DEFAULT_INPUT_USD
        + (output_tokens / 1000.0) * _ANTHROPIC_DEFAULT_OUTPUT_USD
    )


def _build_backend() -> _CoreAnthropicBackend:
    model = (
        os.environ.get("IAM_JIT_LLM_MODEL")
        or "claude-sonnet-4-6"
    )
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "Anthropic backend selected but ANTHROPIC_API_KEY is not set."
        )
    return _CoreAnthropicBackend(model=model)


def score_policy(policy: dict[str, Any], context: ScoreContext) -> ScoreResponse:
    """Ask Anthropic to score `policy`. Returns empty response on failure."""
    try:
        backend = _build_backend()
    except RuntimeError as e:
        logger.info("anthropic backend unavailable: %s", e)
        return ScoreResponse(backend_name=name)

    user = build_user_message(policy, context)
    text = backend.chat(
        system_prompt=SCORE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user}],
    )
    return parse_score_response(text, backend_name=name)
