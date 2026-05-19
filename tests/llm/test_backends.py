"""Per-backend `score_policy` shape tests.

These exercise EVERY backend through its `score_policy(policy, context)`
entry point. SDK calls / HTTP calls are mocked at the boundary so no
network, no API keys, no boto3 region needed.

Cross-backend property test at the bottom asserts that, given a fixed
mock response, every backend returns the SAME `ScoreResponse` field
set — the contract is the same across providers.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from iam_jit.llm import ScoreContext, ScoreResponse
from iam_jit.llm.backends import anthropic as b_anthropic
from iam_jit.llm.backends import bedrock as b_bedrock
from iam_jit.llm.backends import ollama as b_ollama
from iam_jit.llm.backends import openai as b_openai


_VALID_LLM_REPLY = json.dumps(
    {
        "narrative": "Broad S3 access without resource scoping.",
        "suggestions": [
            "Scope to a specific bucket ARN.",
            "Drop write actions if read suffices.",
        ],
        "risk_signal": 6,
    }
)


def _ctx() -> ScoreContext:
    return ScoreContext(
        request_shape={"spec": {"description": "read app logs"}},
        deterministic_score=7,
        deterministic_factors=("wildcard-resource", "broad-services"),
        description="read app logs",
    )


# -----------------------------------------------------------------------------
# Bedrock
# -----------------------------------------------------------------------------


def test_bedrock_score_policy_returns_response_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_BEDROCK_MODEL", "anthropic.claude-sonnet-4-6-v1:0")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    class _FakeClient:
        def converse(self, **kwargs: Any) -> dict:
            return {
                "output": {
                    "message": {"content": [{"text": _VALID_LLM_REPLY}]}
                }
            }

    import boto3

    monkeypatch.setattr(
        boto3, "client", lambda *a, **kw: _FakeClient()
    )
    out = b_bedrock.score_policy({"Statement": []}, _ctx())
    assert isinstance(out, ScoreResponse)
    assert out.backend_name == "bedrock"
    assert "S3" in out.narrative
    assert len(out.suggestions) == 2
    assert out.risk_signal == 6


def test_bedrock_is_available_requires_model_and_boto3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("IAM_JIT_BEDROCK_MODEL", raising=False)
    monkeypatch.delenv("IAM_JIT_LLM_MODEL", raising=False)
    assert b_bedrock.is_available() is False
    monkeypatch.setenv("IAM_JIT_BEDROCK_MODEL", "x")
    assert b_bedrock.is_available() is True


def test_bedrock_auth_error_returns_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_BEDROCK_MODEL", "x")

    class _FakeClient:
        def converse(self, **kwargs: Any) -> dict:
            raise RuntimeError("UnauthorizedException: AWS credentials missing")

    import boto3

    monkeypatch.setattr(
        boto3, "client", lambda *a, **kw: _FakeClient()
    )
    out = b_bedrock.score_policy({"Statement": []}, _ctx())
    assert out.narrative == ""
    assert out.suggestions == ()


def test_bedrock_cost_estimate_is_finite() -> None:
    assert b_bedrock.estimate_cost_per_1k(2000, 500) > 0.0


# -----------------------------------------------------------------------------
# Anthropic
# -----------------------------------------------------------------------------


def test_anthropic_score_policy_returns_response_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    class _FakeBlock:
        def __init__(self, text: str) -> None:
            self.text = text

    class _FakeResp:
        content = [_FakeBlock(_VALID_LLM_REPLY)]

    class _FakeMessages:
        def create(self, **kwargs: Any) -> _FakeResp:
            return _FakeResp()

    class _FakeClient:
        messages = _FakeMessages()

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", lambda *a, **kw: _FakeClient())
    out = b_anthropic.score_policy({"Statement": []}, _ctx())
    assert out.backend_name == "anthropic"
    assert "S3" in out.narrative


def test_anthropic_is_available_requires_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert b_anthropic.is_available() is False
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert b_anthropic.is_available() is True


def test_anthropic_no_key_returns_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = b_anthropic.score_policy({"Statement": []}, _ctx())
    assert out.narrative == ""
    assert out.backend_name == "anthropic"


def test_anthropic_cost_estimate_is_finite() -> None:
    assert b_anthropic.estimate_cost_per_1k(2000, 500) > 0.0


# -----------------------------------------------------------------------------
# OpenAI
# -----------------------------------------------------------------------------


def test_openai_score_policy_returns_response_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    class _Msg:
        content = _VALID_LLM_REPLY

    class _Choice:
        message = _Msg()

    class _Resp:
        choices = [_Choice()]

    class _Completions:
        def create(self, **kwargs: Any) -> _Resp:
            assert kwargs["response_format"] == {"type": "json_object"}
            return _Resp()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    import openai

    monkeypatch.setattr(openai, "OpenAI", lambda *a, **kw: _Client())
    out = b_openai.score_policy({"Statement": []}, _ctx())
    assert out.backend_name == "openai"
    assert "S3" in out.narrative


def test_openai_is_available_requires_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert b_openai.is_available() is False
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert b_openai.is_available() is True


def test_openai_auth_error_returns_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    class _Completions:
        def create(self, **kwargs: Any) -> Any:
            raise RuntimeError("AuthenticationError: bad OPENAI_API_KEY")

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    import openai

    monkeypatch.setattr(openai, "OpenAI", lambda *a, **kw: _Client())
    out = b_openai.score_policy({"Statement": []}, _ctx())
    assert out.narrative == ""
    assert out.backend_name == "openai"


def test_openai_no_key_returns_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    out = b_openai.score_policy({"Statement": []}, _ctx())
    assert out.narrative == ""


def test_openai_cost_estimate_is_finite() -> None:
    assert b_openai.estimate_cost_per_1k(2000, 500) > 0.0


def test_openai_honors_openai_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """OpenRouter / Azure-OpenAI users set OPENAI_BASE_URL."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://openrouter.example/v1")

    captured: dict[str, Any] = {}

    class _Completions:
        def create(self, **kwargs: Any) -> Any:
            class _Resp:
                class _C:
                    class _M:
                        content = _VALID_LLM_REPLY

                    message = _M()

                choices = [_C()]

            return _Resp()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    def _factory(**kw: Any) -> _Client:
        captured.update(kw)
        return _Client()

    import openai

    monkeypatch.setattr(openai, "OpenAI", _factory)
    b_openai.score_policy({}, _ctx())
    assert captured["base_url"] == "https://openrouter.example/v1"


# -----------------------------------------------------------------------------
# Ollama
# -----------------------------------------------------------------------------


def test_ollama_score_policy_returns_response_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")

    import respx
    from httpx import Response

    with respx.mock(assert_all_called=True) as r:
        r.post("http://localhost:11434/api/chat").mock(
            return_value=Response(
                200,
                json={"message": {"content": _VALID_LLM_REPLY}},
            )
        )
        out = b_ollama.score_policy({"Statement": []}, _ctx())

    assert out.backend_name == "ollama"
    assert "S3" in out.narrative


def test_ollama_is_available_requires_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert b_ollama.is_available() is False
    monkeypatch.setenv("OLLAMA_HOST", "http://x:1")
    assert b_ollama.is_available() is True


def test_ollama_connection_error_returns_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")

    import respx
    from httpx import ConnectError

    with respx.mock() as r:
        r.post("http://localhost:11434/api/chat").mock(
            side_effect=ConnectError("Connection refused")
        )
        out = b_ollama.score_policy({"Statement": []}, _ctx())

    assert out.narrative == ""
    assert out.backend_name == "ollama"


def test_ollama_cost_estimate_is_zero() -> None:
    # Local model — no per-token API cost.
    assert b_ollama.estimate_cost_per_1k(2000, 500) == 0.0


# -----------------------------------------------------------------------------
# Cross-backend property
# -----------------------------------------------------------------------------


def test_all_backends_produce_same_response_field_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Property: given a valid mock response, every backend returns a
    ScoreResponse with the same field set populated. Guards against
    drift where one backend silently drops `risk_signal` or `suggestions`.
    """
    # Make all backends "succeed" with the canned reply.
    monkeypatch.setenv("IAM_JIT_BEDROCK_MODEL", "x")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")

    class _BedrockClient:
        def converse(self, **kw: Any) -> dict:
            return {"output": {"message": {"content": [{"text": _VALID_LLM_REPLY}]}}}

    import boto3

    monkeypatch.setattr(boto3, "client", lambda *a, **kw: _BedrockClient())

    class _Block:
        def __init__(self, t: str) -> None:
            self.text = t

    class _AResp:
        content = [_Block(_VALID_LLM_REPLY)]

    class _AMessages:
        def create(self, **kw: Any) -> _AResp:
            return _AResp()

    class _AClient:
        messages = _AMessages()

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", lambda *a, **kw: _AClient())

    class _OMsg:
        content = _VALID_LLM_REPLY

    class _OChoice:
        message = _OMsg()

    class _OResp:
        choices = [_OChoice()]

    class _OComp:
        def create(self, **kw: Any) -> _OResp:
            return _OResp()

    class _OChat:
        completions = _OComp()

    class _OClient:
        chat = _OChat()

    import openai

    monkeypatch.setattr(openai, "OpenAI", lambda *a, **kw: _OClient())

    import respx
    from httpx import Response

    with respx.mock(assert_all_called=False) as r:
        r.post("http://localhost:11434/api/chat").mock(
            return_value=Response(200, json={"message": {"content": _VALID_LLM_REPLY}})
        )
        responses = {
            "bedrock": b_bedrock.score_policy({}, _ctx()),
            "anthropic": b_anthropic.score_policy({}, _ctx()),
            "openai": b_openai.score_policy({}, _ctx()),
            "ollama": b_ollama.score_policy({}, _ctx()),
        }

    fields = {
        name: (
            bool(resp.narrative),
            bool(resp.suggestions),
            resp.risk_signal,
        )
        for name, resp in responses.items()
    }
    # Every backend should populate the same fields.
    distinct = set(fields.values())
    assert len(distinct) == 1, f"backends produced different shapes: {fields}"


# -----------------------------------------------------------------------------
# Safety-language check (no "violation"/"infraction"/"unauthorized" in prompts)
# -----------------------------------------------------------------------------


def test_score_system_prompt_avoids_security_team_language() -> None:
    from iam_jit.llm.backends._score_prompt import SCORE_SYSTEM_PROMPT

    lowered = SCORE_SYSTEM_PROMPT.lower()
    # Per [[security-team-positioning-safety-not-surveillance]] — keep
    # user-facing language collaborative, not enforcement-flavored.
    for bad in ("violation", "infraction", "unauthorized"):
        assert bad not in lowered, f"score prompt contains banned word: {bad!r}"
