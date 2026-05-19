"""Per-backend test fixtures.

Auto-cleans every backend-selection env var so tests start from a
known-clean state. Mirrors the autouse fixture in
`tests/test_llm_backend.py` so the two suites can run interleaved.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "IAM_JIT_LLM",
        "IAM_JIT_LLM_BACKEND",
        "IAM_JIT_LLM_MODEL",
        "OLLAMA_HOST",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "IAM_JIT_BEDROCK_MODEL",
        "IAM_JIT_BEDROCK_REGION",
        "AWS_REGION",
    ):
        monkeypatch.delenv(var, raising=False)
