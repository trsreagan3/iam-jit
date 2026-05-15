"""Tests for `iam_jit.llm_account_policy.decide`.

Decision flow (per [[per-account-llm-policy]] design memo):

  1. account.llm_policy set?      → honor it
  2. deployment default            → IAM_JIT_LLM_DEFAULT_POLICY
  3. (caller continues with budget + confidence gates downstream)

Tests pin each branch + the corner cases.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from iam_jit import llm_account_policy


@dataclasses.dataclass(frozen=True)
class _FakeAccount:
    """Minimal Account stand-in. Only carries the fields the gate reads."""

    account_id: str
    llm_policy: str | None = None
    llm_policy_reason: str | None = None


class _FakeStore:
    def __init__(self, accounts: list[_FakeAccount]) -> None:
        self._accounts = {a.account_id: a for a in accounts}

    def get(self, account_id: str) -> _FakeAccount:
        return self._accounts[account_id]


# ---------------------------------------------------------------------------
# 1. account.llm_policy is the FIRST gate.
# ---------------------------------------------------------------------------


def test_account_use_llm_overrides_deployment_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Account says use_llm even when deployment default is deterministic_only."""
    monkeypatch.setenv("IAM_JIT_LLM_DEFAULT_POLICY", "deterministic_only")
    store = _FakeStore([_FakeAccount(account_id="111111111111", llm_policy="use_llm")])
    decision = llm_account_policy.decide(
        account_id="111111111111", accounts_store=store,
    )
    assert decision.use_llm is True
    assert decision.source == "account_policy"
    assert decision.skip_reason is None


def test_account_deterministic_only_overrides_deployment_use_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Account says deterministic_only even when deployment default is use_llm."""
    monkeypatch.setenv("IAM_JIT_LLM_DEFAULT_POLICY", "use_llm")
    store = _FakeStore([
        _FakeAccount(
            account_id="222222222222",
            llm_policy="deterministic_only",
            llm_policy_reason="high volume dev account, LLM wasted spend",
        )
    ])
    decision = llm_account_policy.decide(
        account_id="222222222222", accounts_store=store,
    )
    assert decision.use_llm is False
    assert decision.source == "account_policy"
    assert decision.skip_reason == "account_policy:deterministic_only"
    assert decision.skip_detail == "high volume dev account, LLM wasted spend"


def test_account_skip_detail_when_no_reason_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If admin didn't supply llm_policy_reason, skip_detail is None."""
    monkeypatch.delenv("IAM_JIT_LLM_DEFAULT_POLICY", raising=False)
    store = _FakeStore([_FakeAccount(
        account_id="333333333333", llm_policy="deterministic_only",
    )])
    decision = llm_account_policy.decide(
        account_id="333333333333", accounts_store=store,
    )
    assert decision.use_llm is False
    assert decision.skip_detail is None


# ---------------------------------------------------------------------------
# 2. Deployment default applies when account.llm_policy is unset.
# ---------------------------------------------------------------------------


def test_deployment_default_use_llm_when_account_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_LLM_DEFAULT_POLICY", "use_llm")
    store = _FakeStore([_FakeAccount(account_id="444444444444")])
    decision = llm_account_policy.decide(
        account_id="444444444444", accounts_store=store,
    )
    assert decision.use_llm is True
    assert decision.source == "deployment_default"


def test_deployment_default_deterministic_only_when_account_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_LLM_DEFAULT_POLICY", "deterministic_only")
    store = _FakeStore([_FakeAccount(account_id="555555555555")])
    decision = llm_account_policy.decide(
        account_id="555555555555", accounts_store=store,
    )
    assert decision.use_llm is False
    assert decision.source == "deployment_default"
    assert decision.skip_reason == "deployment_default:deterministic_only"
    assert "IAM_JIT_LLM_DEFAULT_POLICY" in decision.skip_detail


def test_deployment_default_unset_defaults_to_use_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When neither account nor deployment policy is set, default is
    use_llm (preserves prior behavior; per-account is an opt-IN cap)."""
    monkeypatch.delenv("IAM_JIT_LLM_DEFAULT_POLICY", raising=False)
    store = _FakeStore([_FakeAccount(account_id="666666666666")])
    decision = llm_account_policy.decide(
        account_id="666666666666", accounts_store=store,
    )
    assert decision.use_llm is True


# ---------------------------------------------------------------------------
# 3. Edge: no account context, missing account, store errors.
# ---------------------------------------------------------------------------


def test_no_account_id_returns_use_llm() -> None:
    """The standalone /score endpoint without an account_id continues
    to allow LLM (subject to downstream budget gating)."""
    decision = llm_account_policy.decide(account_id=None)
    assert decision.use_llm is True
    assert decision.source == "no_account_context"


def test_unknown_account_falls_through_to_deployment_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_LLM_DEFAULT_POLICY", "deterministic_only")
    store = _FakeStore([])  # empty
    decision = llm_account_policy.decide(
        account_id="777777777777", accounts_store=store,
    )
    assert decision.use_llm is False  # deployment default applied
    assert decision.source == "deployment_default"


def test_no_store_falls_through_to_deployment_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caller passes account_id but no store — only the deployment
    default applies. Useful when the score endpoint has an
    account_id but doesn't want to take a hard dependency on the
    accounts store (e.g., agent-supplied account)."""
    monkeypatch.setenv("IAM_JIT_LLM_DEFAULT_POLICY", "deterministic_only")
    decision = llm_account_policy.decide(
        account_id="888888888888", accounts_store=None,
    )
    assert decision.use_llm is False


def test_store_get_exception_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    """A store that raises on `get` doesn't crash the gate — falls
    through to deployment default. This is defensive: the LLM
    decision is not security-critical (it only affects whether the
    LLM is consulted; deterministic floor still applies)."""

    class _CrashStore:
        def get(self, account_id: str):
            raise RuntimeError("boom")

    monkeypatch.delenv("IAM_JIT_LLM_DEFAULT_POLICY", raising=False)
    decision = llm_account_policy.decide(
        account_id="999999999999", accounts_store=_CrashStore(),
    )
    # Falls through to deployment-default (which defaults to use_llm).
    assert decision.use_llm is True


# ---------------------------------------------------------------------------
# 4. Invalid policy values are ignored.
# ---------------------------------------------------------------------------


def test_invalid_llm_policy_value_falls_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If somehow an account record has llm_policy='garbage' (DDB
    drift, schema-bypass write), don't crash and don't honor it.
    Fall through to deployment default."""
    monkeypatch.setenv("IAM_JIT_LLM_DEFAULT_POLICY", "use_llm")
    store = _FakeStore([_FakeAccount(account_id="000000000000", llm_policy="garbage")])
    decision = llm_account_policy.decide(
        account_id="000000000000", accounts_store=store,
    )
    # Deployment default applies — invalid value treated as unset.
    assert decision.use_llm is True
    assert decision.source == "deployment_default"


# ---------------------------------------------------------------------------
# 5. Cost-control demo case: many dev accounts, few prod.
# ---------------------------------------------------------------------------


def test_realistic_enterprise_topology(monkeypatch: pytest.MonkeyPatch) -> None:
    """Customer with 5 dev accounts (deterministic_only) + 2 prod
    (use_llm) gets LLM only where it matters."""
    monkeypatch.setenv("IAM_JIT_LLM_DEFAULT_POLICY", "deterministic_only")
    store = _FakeStore([
        _FakeAccount("100000000001", llm_policy="deterministic_only"),
        _FakeAccount("100000000002", llm_policy="deterministic_only"),
        _FakeAccount("100000000003", llm_policy="deterministic_only"),
        _FakeAccount("100000000004", llm_policy="deterministic_only"),
        _FakeAccount("100000000005", llm_policy="deterministic_only"),
        _FakeAccount("200000000001", llm_policy="use_llm"),
        _FakeAccount("200000000002", llm_policy="use_llm"),
    ])
    # All five dev accounts skip the LLM.
    for dev in ("100000000001", "100000000002", "100000000003",
                "100000000004", "100000000005"):
        assert llm_account_policy.decide(
            account_id=dev, accounts_store=store,
        ).use_llm is False
    # Both prod accounts call the LLM.
    for prod in ("200000000001", "200000000002"):
        assert llm_account_policy.decide(
            account_id=prod, accounts_store=store,
        ).use_llm is True
