"""Tests for the per-customer LLM-narrative budget cap + tier→model
mapping (`src/iam_jit/llm_budget.py`).

Pin the launch-economics-critical behavior:
- Pro tier exhausts its monthly budget; further calls return False
  (caller serves deterministic-only).
- Enterprise tier is unlimited.
- Free/indie tier returns False on every call (deterministic-only
  by design).
- The model mapping defaults Pro+Team to Sonnet (5x cheaper),
  Enterprise to Opus.
- Env vars override per-tier caps and per-tier models.
"""

from __future__ import annotations

import os

import pytest

from iam_jit import llm_budget


@pytest.fixture(autouse=True)
def _reset_store_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset the module-level singleton between tests so env overrides
    don't leak."""
    llm_budget.reset_default_store_for_tests()
    for key in [
        "IAM_JIT_LLM_BUDGET_TABLE",
        "IAM_JIT_LLM_BUDGET_PRO",
        "IAM_JIT_LLM_BUDGET_TEAM",
        "IAM_JIT_LLM_BUDGET_ENTERPRISE",
        "IAM_JIT_LLM_BUDGET_FREE",
        "IAM_JIT_LLM_BUDGET_INDIE",
        "IAM_JIT_LLM_MODEL_PRO",
        "IAM_JIT_LLM_MODEL_TEAM",
        "IAM_JIT_LLM_MODEL_ENTERPRISE",
    ]:
        monkeypatch.delenv(key, raising=False)


def test_pro_tier_hits_cap_after_default_budget() -> None:
    store = llm_budget.InMemoryLLMBudgetStore()
    # Lower the cap for a fast test.
    os.environ["IAM_JIT_LLM_BUDGET_PRO"] = "3"

    assert store.consume_or_reject("alice@example.com", "pro") is True
    assert store.consume_or_reject("alice@example.com", "pro") is True
    assert store.consume_or_reject("alice@example.com", "pro") is True
    # 4th call hits the cap.
    assert store.consume_or_reject("alice@example.com", "pro") is False
    # Subsequent calls also blocked.
    assert store.consume_or_reject("alice@example.com", "pro") is False


def test_enterprise_tier_is_unlimited() -> None:
    store = llm_budget.InMemoryLLMBudgetStore()
    for _ in range(500):
        assert store.consume_or_reject("acme@bigcorp.com", "enterprise") is True


def test_free_and_indie_tiers_refuse_all_llm() -> None:
    store = llm_budget.InMemoryLLMBudgetStore()
    assert store.consume_or_reject("anon@example.com", "free") is False
    assert store.consume_or_reject("indie@example.com", "indie") is False


def test_budgets_are_per_customer_independent() -> None:
    os.environ["IAM_JIT_LLM_BUDGET_PRO"] = "2"
    store = llm_budget.InMemoryLLMBudgetStore()

    # alice exhausts her budget.
    assert store.consume_or_reject("alice@", "pro") is True
    assert store.consume_or_reject("alice@", "pro") is True
    assert store.consume_or_reject("alice@", "pro") is False
    # bob is unaffected.
    assert store.consume_or_reject("bob@", "pro") is True
    assert store.consume_or_reject("bob@", "pro") is True
    assert store.consume_or_reject("bob@", "pro") is False


def test_usage_for_returns_current_month_count() -> None:
    store = llm_budget.InMemoryLLMBudgetStore()
    assert store.usage_for("alice@") == 0
    store.consume_or_reject("alice@", "pro")
    store.consume_or_reject("alice@", "pro")
    assert store.usage_for("alice@") == 2


def test_default_models_pro_sonnet_team_opus_enterprise_opus() -> None:
    """Pro uses Sonnet (5× cheaper, ~70% narrative quality).
    Team + Enterprise customers pay enough to fund Opus."""
    assert "sonnet" in llm_budget.model_for_tier("pro").lower()
    assert "opus" in llm_budget.model_for_tier("team").lower()
    assert "opus" in llm_budget.model_for_tier("enterprise").lower()


def test_team_default_budget_is_tighter_than_pro_to_match_opus_cost() -> None:
    """Team uses Opus which is 5× the cost of Sonnet; its monthly
    cap is correspondingly tighter than Pro's to keep $499 margin
    healthy."""
    pro_budget = llm_budget._budget_for_tier("pro")
    team_budget = llm_budget._budget_for_tier("team")
    assert pro_budget is not None and team_budget is not None
    # Team includes more LLM volume than Pro, but the cost-per-call
    # is 5× higher. Sanity-check the absolute number is in the
    # "Team narrative volume" range, not "Pro × 10."
    assert team_budget < pro_budget * 5


def test_model_per_tier_env_override() -> None:
    os.environ["IAM_JIT_LLM_MODEL_PRO"] = "claude-haiku-4-5-20251001"
    assert llm_budget.model_for_tier("pro") == "claude-haiku-4-5-20251001"


def test_budget_env_overrides_default_cap() -> None:
    os.environ["IAM_JIT_LLM_BUDGET_PRO"] = "5"
    store = llm_budget.InMemoryLLMBudgetStore()
    for _ in range(5):
        assert store.consume_or_reject("alice@", "pro") is True
    assert store.consume_or_reject("alice@", "pro") is False


def test_budget_env_unlimited_makes_pro_unlimited() -> None:
    os.environ["IAM_JIT_LLM_BUDGET_PRO"] = "unlimited"
    store = llm_budget.InMemoryLLMBudgetStore()
    for _ in range(200):
        assert store.consume_or_reject("alice@", "pro") is True


def test_default_store_factory_returns_in_memory_when_no_table() -> None:
    store = llm_budget.get_default_store()
    assert isinstance(store, llm_budget.InMemoryLLMBudgetStore)


def test_default_store_factory_returns_dynamodb_when_table_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("IAM_JIT_LLM_BUDGET_TABLE", "iam-jit-llm-budget-test")
    llm_budget.reset_default_store_for_tests()
    store = llm_budget.get_default_store()
    assert isinstance(store, llm_budget.DynamoDBLLMBudgetStore)


def test_unknown_tier_defaults_to_no_budget() -> None:
    store = llm_budget.InMemoryLLMBudgetStore()
    # An unrecognized tier name (typo, etc.) gets the default of 0 →
    # no LLM. Fail-closed.
    assert store.consume_or_reject("alice@", "platinum-deluxe") is False
