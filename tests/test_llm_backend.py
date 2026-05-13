import os
from unittest import mock

import pytest

from iam_jit.llm import (
    AnthropicBackend,
    BedrockBackend,
    NoOpBackend,
    OllamaBackend,
    _parse,
    get_backend,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "IAM_JIT_LLM",
        "IAM_JIT_LLM_MODEL",
        "OLLAMA_HOST",
        "ANTHROPIC_API_KEY",
        "IAM_JIT_BEDROCK_MODEL",
        "IAM_JIT_BEDROCK_REGION",
        "AWS_REGION",
    ):
        monkeypatch.delenv(var, raising=False)


def test_default_is_noop() -> None:
    assert isinstance(get_backend(), NoOpBackend)


def test_explicit_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_LLM", "none")
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert isinstance(get_backend(), NoOpBackend)


def test_ollama_host_autoselect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    backend = get_backend()
    assert isinstance(backend, OllamaBackend)
    assert backend.host == "http://localhost:11434"


def test_anthropic_key_autoselect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    backend = get_backend()
    assert isinstance(backend, AnthropicBackend)


def test_explicit_overrides_autoselect(monkeypatch: pytest.MonkeyPatch) -> None:
    # Both Ollama and Anthropic available, but explicit takes precedence.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    monkeypatch.setenv("IAM_JIT_LLM", "anthropic")
    assert isinstance(get_backend(), AnthropicBackend)


def test_explicit_unknown_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_LLM", "magic-cloud")
    with pytest.raises(ValueError):
        get_backend()


def test_noop_passes_through() -> None:
    services, actions = NoOpBackend().refine(
        description="anything", initial_services=["s3"], initial_actions=["read"]
    )
    assert services == ["s3"]
    assert actions == ["read"]


def test_parse_valid_response() -> None:
    services, actions = _parse(
        '{"services": ["s3", "eks"], "actions": ["read", "list"]}',
        ["fallback_svc"],
        ["fallback_action"],
    )
    assert services == ["s3", "eks"]
    assert actions == ["read", "list"]


def test_parse_invalid_json_falls_back() -> None:
    services, actions = _parse("not json at all", ["s3"], ["read"])
    assert services == ["s3"]
    assert actions == ["read"]


def test_parse_drops_unknown_action_levels() -> None:
    services, actions = _parse(
        '{"services": ["s3"], "actions": ["read", "iam:CreateUser", "permissions-management"]}',
        [],
        [],
    )
    assert "iam:CreateUser" not in actions
    assert "read" in actions
    assert "permissions-management" in actions


def test_parse_non_string_services_dropped() -> None:
    services, actions = _parse(
        '{"services": ["s3", 123, null, "eks"], "actions": ["read"]}',
        [],
        [],
    )
    assert services == ["s3", "eks"]


def test_ollama_backend_calls_chat_endpoint() -> None:
    import respx
    from httpx import Response

    backend = OllamaBackend(host="http://x:1", model="llama3.2:3b")

    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("http://x:1/api/chat").mock(
            return_value=Response(
                200,
                json={
                    "message": {"content": '{"services": ["s3"], "actions": ["read"]}'}
                },
            )
        )
        services, actions = backend.refine(
            description="task", initial_services=[], initial_actions=[]
        )

    assert services == ["s3"]
    assert actions == ["read"]
    assert route.called
    request = route.calls[0].request
    body = request.read()
    import json as _json

    body_obj = _json.loads(body)
    assert body_obj["model"] == "llama3.2:3b"
    assert body_obj["format"] == "json"


def test_bedrock_explicit_requires_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_LLM", "bedrock")
    with pytest.raises(ValueError):
        get_backend()


def test_bedrock_explicit_with_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_LLM", "bedrock")
    monkeypatch.setenv("IAM_JIT_BEDROCK_MODEL", "meta.llama3-3-70b-instruct-v1:0")
    backend = get_backend()
    assert isinstance(backend, BedrockBackend)
    assert backend.model_id == "meta.llama3-3-70b-instruct-v1:0"


def test_bedrock_autoselect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_BEDROCK_MODEL", "meta.llama3-3-70b-instruct-v1:0")
    backend = get_backend()
    assert isinstance(backend, BedrockBackend)


def test_anthropic_wins_over_bedrock_in_autoselect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("IAM_JIT_BEDROCK_MODEL", "meta.llama3-3-70b-instruct-v1:0")
    assert isinstance(get_backend(), AnthropicBackend)


def test_bedrock_backend_invokes_converse(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = BedrockBackend(model_id="meta.llama3-3-70b-instruct-v1:0", region="us-east-1")
    captured: dict[str, object] = {}

    class _FakeBedrockClient:
        def converse(self, **kwargs: object) -> dict:
            captured["call"] = kwargs
            return {
                "output": {
                    "message": {
                        "content": [
                            {"text": '{"services": ["s3"], "actions": ["read"]}'}
                        ]
                    }
                }
            }

    def _fake_client(name: str, region_name: str | None = None) -> _FakeBedrockClient:
        captured["client_name"] = name
        captured["region"] = region_name
        return _FakeBedrockClient()

    import boto3

    monkeypatch.setattr(boto3, "client", _fake_client)
    services, actions = backend.refine(
        description="task", initial_services=[], initial_actions=[]
    )
    assert services == ["s3"]
    assert actions == ["read"]
    assert captured["client_name"] == "bedrock-runtime"
    assert captured["region"] == "us-east-1"
    call = captured["call"]
    assert isinstance(call, dict)
    assert call["modelId"] == "meta.llama3-3-70b-instruct-v1:0"
