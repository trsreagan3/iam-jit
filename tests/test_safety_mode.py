"""Tests for `iam_jit.safety_mode.resolve_mode + thresholds`.

Per [[safety-mode-two-modes]] memo.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from iam_jit import safety_mode


@dataclasses.dataclass(frozen=True)
class _FakeAccount:
    account_id: str
    safety_mode_override: str | None = None


class _FakeStore:
    def __init__(self, accounts: list[_FakeAccount]) -> None:
        self._d = {a.account_id: a for a in accounts}

    def get(self, account_id: str) -> _FakeAccount:
        return self._d[account_id]


# ---------------------------------------------------------------------------
# resolve_mode priority
# ---------------------------------------------------------------------------


def test_session_override_wins_over_account(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "read_write_swap")
    store = _FakeStore([_FakeAccount("111", safety_mode_override="read_write_swap")])
    mode = safety_mode.resolve_mode(
        session_override="strict",
        account_id="111",
        accounts_store=store,
    )
    assert mode == "strict"


def test_account_override_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "read_write_swap")
    store = _FakeStore([_FakeAccount("222", safety_mode_override="strict")])
    mode = safety_mode.resolve_mode(
        account_id="222", accounts_store=store,
    )
    assert mode == "strict"


def test_env_default_when_no_account_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "strict")
    store = _FakeStore([_FakeAccount("333")])
    mode = safety_mode.resolve_mode(
        account_id="333", accounts_store=store,
    )
    assert mode == "strict"


def test_fallback_default_read_write_swap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_SAFETY_MODE", raising=False)
    mode = safety_mode.resolve_mode()
    assert mode == "read_write_swap"


def test_invalid_session_override_falls_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "strict")
    mode = safety_mode.resolve_mode(session_override="garbage")
    assert mode == "strict"


def test_invalid_env_falls_through_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "garbage-value")
    mode = safety_mode.resolve_mode()
    assert mode == "read_write_swap"


def test_account_store_exception_falls_through_gracefully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A store that raises on `get` doesn't break mode resolution."""

    class _CrashStore:
        def get(self, account_id: str):
            raise RuntimeError("boom")

    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "strict")
    mode = safety_mode.resolve_mode(
        account_id="999", accounts_store=_CrashStore(),
    )
    assert mode == "strict"


# ---------------------------------------------------------------------------
# thresholds_for + auto_approve_threshold_for
# ---------------------------------------------------------------------------


def test_read_write_swap_thresholds() -> None:
    t = safety_mode.thresholds_for("read_write_swap")
    assert t.auto_approve_read_below == 9  # very permissive
    assert t.auto_approve_write_below == 4  # standard
    assert t.allow_action_wildcards is True
    assert t.allow_admin_fallback is True
    assert t.is_strict is False


def test_strict_thresholds() -> None:
    t = safety_mode.thresholds_for("strict")
    assert t.auto_approve_read_below == 5  # tighter than swap
    assert t.auto_approve_write_below == 2  # very tight
    assert t.allow_action_wildcards is False
    assert t.allow_admin_fallback is False
    assert t.extended_audit_retention is True
    assert t.is_strict is True


def test_unknown_mode_falls_back_to_default() -> None:
    t = safety_mode.thresholds_for("nonexistent-mode")
    # Should return the read_write_swap thresholds.
    assert t.auto_approve_read_below == 9


def test_auto_approve_threshold_for_read() -> None:
    assert safety_mode.auto_approve_threshold_for("strict", access_type="read") == 5
    assert safety_mode.auto_approve_threshold_for("strict", access_type="read-only") == 5
    assert safety_mode.auto_approve_threshold_for("read_write_swap", access_type="read-only") == 9


def test_auto_approve_threshold_for_write() -> None:
    assert safety_mode.auto_approve_threshold_for("strict", access_type="read-write") == 2
    assert safety_mode.auto_approve_threshold_for("read_write_swap", access_type="read-write") == 4


# ---------------------------------------------------------------------------
# Realistic scenarios
# ---------------------------------------------------------------------------


def test_realistic_pilot_topology(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deployment default read_write_swap; prod accounts strict;
    dev inherits."""
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "read_write_swap")
    store = _FakeStore([
        _FakeAccount("100000000001"),  # dev — no override
        _FakeAccount("100000000002"),  # staging — no override
        _FakeAccount("200000000001", safety_mode_override="strict"),  # prod
        _FakeAccount("200000000002", safety_mode_override="strict"),  # pci-prod
    ])
    # Dev / staging inherit deployment default.
    for dev in ("100000000001", "100000000002"):
        assert safety_mode.resolve_mode(
            account_id=dev, accounts_store=store,
        ) == "read_write_swap"
    # Prod accounts opt-up to strict.
    for prod in ("200000000001", "200000000002"):
        assert safety_mode.resolve_mode(
            account_id=prod, accounts_store=store,
        ) == "strict"


def test_session_can_opt_up_to_strict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Engineer working on a dev account but wants strict mode for
    a high-stakes session. The session override wins."""
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "read_write_swap")
    store = _FakeStore([_FakeAccount("dev-acct")])
    mode = safety_mode.resolve_mode(
        session_override="strict",
        account_id="dev-acct",
        accounts_store=store,
    )
    assert mode == "strict"
