"""Backend-registry selection tests.

Exercises:
  - `default_score_backend()` precedence (preferred → env → legacy → autoselect)
  - `get_score_backend(name)` validation
  - Unavailable preferred backend falls back rather than crashing
  - `available_backends()` lists every registered name
"""

from __future__ import annotations

import pytest

from iam_jit.llm import (
    ScoreContext,
    ScoreResponse,
    available_backends,
    default_score_backend,
    get_score_backend,
    score_policy,
)


# -----------------------------------------------------------------------------
# Registration
# -----------------------------------------------------------------------------


def test_available_backends_lists_all_four() -> None:
    names = available_backends()
    assert set(names) == {"bedrock", "anthropic", "openai", "ollama"}


def test_get_score_backend_unknown_lists_available() -> None:
    with pytest.raises(ValueError) as exc:
        get_score_backend("magic-cloud")
    msg = str(exc.value)
    assert "magic-cloud" in msg
    assert "bedrock" in msg
    assert "anthropic" in msg
    assert "openai" in msg
    assert "ollama" in msg


def test_get_score_backend_returns_module() -> None:
    backend = get_score_backend("anthropic")
    assert backend.name == "anthropic"
    assert callable(backend.score_policy)
    assert callable(backend.is_available)


def test_get_score_backend_case_insensitive() -> None:
    assert get_score_backend("ANTHROPIC").name == "anthropic"
    assert get_score_backend(" Bedrock ").name == "bedrock"


# -----------------------------------------------------------------------------
# default_score_backend() precedence
# -----------------------------------------------------------------------------


def test_default_no_creds_returns_none() -> None:
    assert default_score_backend() is None


def test_default_explicit_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_LLM_BACKEND", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    backend = default_score_backend()
    assert backend is not None
    assert backend.name == "anthropic"


def test_default_preferred_kwarg_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-account override (preferred=) beats deployment env."""
    monkeypatch.setenv("IAM_JIT_LLM_BACKEND", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    backend = default_score_backend(preferred="openai")
    assert backend is not None
    assert backend.name == "openai"


def test_default_unavailable_preferred_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preferred backend without creds → falls back to deployment default,
    rather than failing the whole scoring call."""
    # Caller asks for openai but didn't set OPENAI_API_KEY.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    backend = default_score_backend(preferred="openai")
    assert backend is not None
    assert backend.name == "anthropic"  # autoselect fallback


def test_default_unknown_preferred_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bad name → logged + fallback, not raised. The score call must not
    crash because an admin typo'd the backend name."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    backend = default_score_backend(preferred="not-a-real-backend")
    assert backend is not None
    assert backend.name == "anthropic"


def test_default_legacy_iam_jit_llm_honored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_LLM", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    backend = default_score_backend()
    assert backend is not None
    assert backend.name == "anthropic"


def test_default_autoselect_prefers_anthropic_over_bedrock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per registry docstring: anthropic > openai > bedrock > ollama
    when no explicit env is set. Captures the Bedrock-lead-time
    reality (see [[aws-account-verification]])."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("IAM_JIT_BEDROCK_MODEL", "x")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    backend = default_score_backend()
    assert backend is not None
    assert backend.name == "anthropic"


def test_default_autoselect_picks_ollama_when_only_one_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    backend = default_score_backend()
    assert backend is not None
    assert backend.name == "ollama"


# -----------------------------------------------------------------------------
# score_policy convenience entry point
# -----------------------------------------------------------------------------


def test_score_policy_no_backend_returns_empty_response() -> None:
    out = score_policy(
        {"Statement": []},
        ScoreContext(
            request_shape={},
            deterministic_score=5,
            deterministic_factors=(),
            description="",
        ),
    )
    assert isinstance(out, ScoreResponse)
    assert out.narrative == ""
    assert out.backend_name == ""


def test_score_policy_routes_to_preferred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    class _Msg:
        content = json.dumps(
            {"narrative": "ok", "suggestions": ["tighten arn"], "risk_signal": 4}
        )

    class _Choice:
        message = _Msg()

    class _Resp:
        choices = [_Choice()]

    class _Comp:
        def create(self, **kw):  # type: ignore[no-untyped-def]
            return _Resp()

    class _Chat:
        completions = _Comp()

    class _Client:
        chat = _Chat()

    import openai

    monkeypatch.setattr(openai, "OpenAI", lambda *a, **kw: _Client())

    out = score_policy(
        {"Statement": []},
        ScoreContext(
            request_shape={},
            deterministic_score=5,
            deterministic_factors=(),
            description="x",
        ),
        preferred_backend="openai",
    )
    assert out.backend_name == "openai"
    assert out.narrative == "ok"
    assert out.suggestions == ("tighten arn",)
    assert out.risk_signal == 4


# -----------------------------------------------------------------------------
# Selection-log line (caller asked for a sample log line in the report)
# -----------------------------------------------------------------------------


def test_default_logs_selection_source(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The registry MUST log which selection branch was taken so
    operators can debug 'why did we route to X today'."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with caplog.at_level("INFO", logger="iam_jit.llm.registry"):
        default_score_backend()
    selection = [
        rec.getMessage()
        for rec in caplog.records
        if "llm.backend.select" in rec.getMessage()
    ]
    assert selection, "no selection log line emitted"
    # Sample line shape: "llm.backend.select source=autoselect name=anthropic"
    assert "source=" in selection[-1]
    assert "name=" in selection[-1]
