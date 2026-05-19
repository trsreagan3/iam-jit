"""OpenAI API backend (api.openai.com).

NEW for the pluggable-backend slice: there is no `OpenAIBackend` in
`_core` because the original three-backend rotation did not include
OpenAI. We talk to the SDK directly via the Chat Completions API.

Why Chat Completions (not Responses): coverage. As of the Pro-tier
launch window, Chat Completions is the broadest, most stable surface
across organization-owned org keys, OpenRouter-proxied keys, and
Azure-OpenAI deployments. Switching to Responses is a transparent
swap when a customer asks for it.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ..types import ScoreContext, ScoreResponse
from ._score_prompt import SCORE_SYSTEM_PROMPT, build_user_message, parse_score_response

logger = logging.getLogger("iam_jit.llm.backends.openai")

name = "openai"


# GPT-4o-mini-class default pricing — operators on GPT-4o or o1 pay
# more. Documented as approximate in docs/LLM-BACKENDS.md.
_OPENAI_DEFAULT_INPUT_USD = 0.00015
_OPENAI_DEFAULT_OUTPUT_USD = 0.0006

_DEFAULT_MODEL = "gpt-4o-mini"


def is_available() -> bool:
    """`OPENAI_API_KEY` set AND `openai` SDK importable."""
    if not os.environ.get("OPENAI_API_KEY"):
        return False
    try:
        import openai  # noqa: F401
    except ImportError:
        return False
    return True


def estimate_cost_per_1k(input_tokens: int, output_tokens: int) -> float:
    return (
        (input_tokens / 1000.0) * _OPENAI_DEFAULT_INPUT_USD
        + (output_tokens / 1000.0) * _OPENAI_DEFAULT_OUTPUT_USD
    )


def _max_output_tokens(default: int) -> int:
    raw = os.environ.get("IAM_JIT_LLM_MAX_OUTPUT_TOKENS")
    if not raw:
        return default
    try:
        return max(64, int(raw))
    except ValueError:
        return default


def _chat(system_prompt: str, user_message: str) -> str:
    """Call OpenAI Chat Completions. Returns "" on any failure."""
    try:
        import openai
    except ImportError:
        logger.warning("openai SDK not installed; install with `pip install openai`")
        return ""

    if not os.environ.get("OPENAI_API_KEY"):
        logger.info("openai backend selected but OPENAI_API_KEY is not set")
        return ""

    model = (
        os.environ.get("IAM_JIT_LLM_MODEL")
        or _DEFAULT_MODEL
    )
    base_url = os.environ.get("OPENAI_BASE_URL")  # supports OpenRouter / Azure
    client_kwargs: dict[str, Any] = {}
    if base_url:
        client_kwargs["base_url"] = base_url

    try:
        client = openai.OpenAI(**client_kwargs)
        resp = client.chat.completions.create(
            model=model,
            max_tokens=_max_output_tokens(512),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            response_format={"type": "json_object"},
        )
    except Exception as e:  # noqa: BLE001 — defensive: never crash the score path
        logger.warning("openai backend call failed: %s: %s", type(e).__name__, e)
        return ""

    try:
        return resp.choices[0].message.content or ""
    except (AttributeError, IndexError):
        return ""


def score_policy(policy: dict[str, Any], context: ScoreContext) -> ScoreResponse:
    """Ask OpenAI to score `policy`. Returns empty response on failure."""
    user = build_user_message(policy, context)
    text = _chat(SCORE_SYSTEM_PROMPT, user)
    return parse_score_response(text, backend_name=name)
