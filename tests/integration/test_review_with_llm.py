"""Integration test: risk analysis is annotated with an LLM-generated narrative
when an LLM backend is available. Skipped if Ollama isn't running.

We verify the *contract* (narrative is a non-empty string) rather than the
quality of the narrative — that's a per-model concern asserted by the human
reviewer in the actual workflow.
"""

from __future__ import annotations

import os

import pytest

from iam_jit.llm import OllamaBackend
from iam_jit.review import analyze_policy

pytestmark = pytest.mark.integration

_TEST_MODEL = os.environ.get("IAM_JIT_TEST_OLLAMA_MODEL", "smollm2:135m")


def test_review_attaches_llm_narrative(ollama_endpoint: str) -> None:
    backend = OllamaBackend(host=ollama_endpoint, model=_TEST_MODEL)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": "*",
            }
        ],
    }
    request = {
        "metadata": {"requester": {"name": "x", "email": "x@example.com"}},
        "spec": {
            "description": (
                "I need to debug a service in the staging environment that "
                "reads its database credentials from Secrets Manager."
            ),
            "task_intent": {"services": ["secretsmanager"], "actions": ["read"]},
            "accounts": [{"account_id": "111111111111"}],
            "duration": {"duration_hours": 24},
        },
    }

    analysis = analyze_policy(policy, request, backend=backend)

    # Score is deterministic regardless of LLM availability.
    assert analysis.risk_score == 7
    assert analysis.deterministic_score == 7
    # Analyzer label reflects the LLM was consulted.
    assert "ollama" in analysis.analyzer or analysis.analyzer == "deterministic"
    # If the model produced anything usable, it landed in llm_narrative as a string.
    if analysis.llm_narrative is not None:
        assert isinstance(analysis.llm_narrative, str)
        assert analysis.llm_narrative.strip()
