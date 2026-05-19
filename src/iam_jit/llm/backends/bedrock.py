"""AWS Bedrock backend (Converse API)."""

from __future__ import annotations

import logging
import os
from typing import Any

from .._core import BedrockBackend as _CoreBedrockBackend
from ..types import ScoreContext, ScoreResponse
from ._score_prompt import SCORE_SYSTEM_PROMPT, build_user_message, parse_score_response

logger = logging.getLogger("iam_jit.llm.backends.bedrock")

name = "bedrock"


# Conservative per-1k-tokens price points used only for the
# `estimate_cost_per_1k` helper surfaced in docs + CLI. Operators
# pay the price their AWS contract gives them; this is just a
# sane default for "rough magnitude" sizing.
_BEDROCK_DEFAULT_INPUT_USD = 0.003
_BEDROCK_DEFAULT_OUTPUT_USD = 0.015


def is_available() -> bool:
    """A Bedrock model ID must be configured AND boto3 importable."""
    if not (
        os.environ.get("IAM_JIT_BEDROCK_MODEL")
        or os.environ.get("IAM_JIT_LLM_MODEL")
    ):
        return False
    try:
        import boto3  # noqa: F401
    except ImportError:
        return False
    return True


def estimate_cost_per_1k(input_tokens: int, output_tokens: int) -> float:
    """Rough USD cost for `input_tokens` input + `output_tokens` output."""
    return (
        (input_tokens / 1000.0) * _BEDROCK_DEFAULT_INPUT_USD
        + (output_tokens / 1000.0) * _BEDROCK_DEFAULT_OUTPUT_USD
    )


def _build_backend() -> _CoreBedrockBackend:
    model_id = (
        os.environ.get("IAM_JIT_BEDROCK_MODEL")
        or os.environ.get("IAM_JIT_LLM_MODEL")
    )
    if not model_id:
        raise RuntimeError(
            "Bedrock backend selected but no model id configured. "
            "Set IAM_JIT_BEDROCK_MODEL (or IAM_JIT_LLM_MODEL) to a "
            "model id your AWS account has enabled."
        )
    region = (
        os.environ.get("IAM_JIT_BEDROCK_REGION")
        or os.environ.get("AWS_REGION")
    )
    return _CoreBedrockBackend(model_id=model_id, region=region)


def score_policy(policy: dict[str, Any], context: ScoreContext) -> ScoreResponse:
    """Ask Bedrock to score `policy`. Returns empty `ScoreResponse` on failure."""
    try:
        backend = _build_backend()
    except RuntimeError as e:
        logger.info("bedrock backend unavailable: %s", e)
        return ScoreResponse(backend_name=name)

    user = build_user_message(policy, context)
    text = backend.chat(
        system_prompt=SCORE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user}],
    )
    return parse_score_response(text, backend_name=name)
