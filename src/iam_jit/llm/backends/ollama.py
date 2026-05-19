"""Local Ollama backend (http://localhost:11434 by default)."""

from __future__ import annotations

import logging
import os
from typing import Any

from .._core import OllamaBackend as _CoreOllamaBackend
from ..types import ScoreContext, ScoreResponse
from ._score_prompt import SCORE_SYSTEM_PROMPT, build_user_message, parse_score_response

logger = logging.getLogger("iam_jit.llm.backends.ollama")

name = "ollama"


# Ollama is local; no per-token cost. We return 0.0 so the cost-
# comparison tooling treats Ollama as the floor.
def estimate_cost_per_1k(input_tokens: int, output_tokens: int) -> float:
    return 0.0


def is_available() -> bool:
    """Treat Ollama as available iff `OLLAMA_HOST` is set.

    We intentionally do NOT attempt a live `GET /api/tags` probe at
    import time — a slow / unreachable Ollama would block every
    scoring call. Live failures degrade to empty `ScoreResponse`
    via the `chat()` wrapper.
    """
    return bool(os.environ.get("OLLAMA_HOST"))


def _build_backend() -> _CoreOllamaBackend:
    host = os.environ.get("OLLAMA_HOST") or "http://localhost:11434"
    model = os.environ.get("IAM_JIT_LLM_MODEL") or "llama3.2:3b"
    return _CoreOllamaBackend(host=host, model=model)


def score_policy(policy: dict[str, Any], context: ScoreContext) -> ScoreResponse:
    """Ask local Ollama to score `policy`. Returns empty response on failure."""
    backend = _build_backend()
    user = build_user_message(policy, context)
    text = backend.chat(
        system_prompt=SCORE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user}],
    )
    return parse_score_response(text, backend_name=name)
