"""Tests for the per-account `preferred_backend` extension to LLMDecision.

The pluggable-backend slice (2026-05-19) added a `preferred_backend`
field to `LLMDecision`. When the account record carries
`llm_preferred_backend`, the decide() function MUST surface it so the
caller can route the score through that backend.
"""

from __future__ import annotations

import dataclasses

import pytest

from iam_jit import llm_account_policy


@dataclasses.dataclass(frozen=True)
class _FakeAccount:
    account_id: str
    llm_policy: str | None = None
    llm_policy_reason: str | None = None
    llm_preferred_backend: str | None = None


class _FakeStore:
    def __init__(self, accounts: list[_FakeAccount]) -> None:
        self._accounts = {a.account_id: a for a in accounts}

    def get(self, account_id: str) -> _FakeAccount:
        return self._accounts[account_id]


def test_preferred_backend_surfaces_when_use_llm() -> None:
    store = _FakeStore(
        [
            _FakeAccount(
                account_id="111111111111",
                llm_policy="use_llm",
                llm_preferred_backend="openai",
            )
        ]
    )
    decision = llm_account_policy.decide(
        account_id="111111111111", accounts_store=store
    )
    assert decision.use_llm is True
    assert decision.preferred_backend == "openai"
    assert decision.source == "account_policy"


def test_preferred_backend_none_when_unset() -> None:
    store = _FakeStore(
        [_FakeAccount(account_id="111111111111", llm_policy="use_llm")]
    )
    decision = llm_account_policy.decide(
        account_id="111111111111", accounts_store=store
    )
    assert decision.preferred_backend is None


def test_preferred_backend_dropped_when_deterministic_only() -> None:
    """Defense-in-depth: if the admin set both deterministic_only AND a
    preferred backend, we DO NOT want to route through the backend by
    mistake. The policy gate's primary contract is to skip the LLM."""
    store = _FakeStore(
        [
            _FakeAccount(
                account_id="111111111111",
                llm_policy="deterministic_only",
                llm_preferred_backend="openai",
            )
        ]
    )
    decision = llm_account_policy.decide(
        account_id="111111111111", accounts_store=store
    )
    assert decision.use_llm is False
    assert decision.preferred_backend is None


def test_preferred_backend_none_for_no_account_context() -> None:
    decision = llm_account_policy.decide(account_id=None)
    assert decision.preferred_backend is None
    assert decision.use_llm is True


def test_preferred_backend_none_for_deployment_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No account match → deployment default; preferred_backend stays None."""
    monkeypatch.setenv("IAM_JIT_LLM_DEFAULT_POLICY", "use_llm")
    decision = llm_account_policy.decide(account_id="222222222222")
    assert decision.preferred_backend is None
    assert decision.use_llm is True


def test_get_backend_for_tier_honors_preferred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: when llm_account_policy hands a `preferred_backend`
    to `get_backend_for_tier`, the returned backend matches."""
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    # Set Anthropic key — without preferred we'd autoselect anthropic.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    from iam_jit.llm import OllamaBackend, get_backend_for_tier

    backend = get_backend_for_tier("pro", preferred_backend="ollama")
    assert isinstance(backend, OllamaBackend)


def test_get_backend_for_tier_preferred_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`preferred_backend='noop'` short-circuits even when an LLM env is set."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    from iam_jit.llm import NoOpBackend, get_backend_for_tier

    backend = get_backend_for_tier("pro", preferred_backend="noop")
    assert isinstance(backend, NoOpBackend)
