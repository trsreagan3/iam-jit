"""Tests for self_approve_reductions: admin auto-approves their own narrower grants."""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit import self_approve_reductions as sar


USER_ID = "email:alice@example.com"


def _request(
    *,
    owner: str = USER_ID,
    actions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "metadata": {"id": "req-1", "owner": owner},
        "spec": {
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": actions or ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::x/*",
                }],
            },
        },
    }


# ---------------------------------------------------------------------------
# Mode + opt-in.
# ---------------------------------------------------------------------------


def test_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without solo mode or per-user flag, the gate is closed."""
    monkeypatch.delenv("IAM_JIT_DEPLOYMENT_MODE", raising=False)
    decision = sar.evaluate(
        request=_request(),
        user_id=USER_ID,
        user_is_admin=True,
        user_self_approve_flag=False,
    )
    assert decision.self_approved is False
    assert decision.reason == "mode_not_enabled"


def test_enabled_in_solo_deployment_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    decision = sar.evaluate(
        request=_request(),
        user_id=USER_ID,
        user_is_admin=True,
    )
    assert decision.self_approved is True
    assert decision.reason == "self_approved"


def test_enabled_via_per_user_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-solo deployment + user opted in → gate is open."""
    monkeypatch.delenv("IAM_JIT_DEPLOYMENT_MODE", raising=False)
    decision = sar.evaluate(
        request=_request(),
        user_id=USER_ID,
        user_is_admin=True,
        user_self_approve_flag=True,
    )
    assert decision.self_approved is True


# ---------------------------------------------------------------------------
# Eligibility chain.
# ---------------------------------------------------------------------------


def test_non_admin_cannot_self_approve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    decision = sar.evaluate(
        request=_request(),
        user_id=USER_ID,
        user_is_admin=False,
    )
    assert decision.self_approved is False
    assert decision.reason == "not_admin"


def test_cannot_self_approve_someone_elses_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A request submitted on behalf of another user still needs review."""
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    decision = sar.evaluate(
        request=_request(owner="email:bob@example.com"),
        user_id=USER_ID,
        user_is_admin=True,
    )
    assert decision.self_approved is False
    assert decision.reason == "not_owner"


def test_service_blocklist_overrides_self_approve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The platform-team service blocklist is a hard floor — even
    admin self-approve cannot route around it."""
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    decision = sar.evaluate(
        request=_request(actions=["iam:PassRole"]),
        user_id=USER_ID,
        user_is_admin=True,
        blocked_services=("iam", "organizations"),
    )
    assert decision.self_approved is False
    assert decision.reason == "service_blocked"
    assert decision.details["service"] == "iam"


def test_no_policy_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    decision = sar.evaluate(
        request={"metadata": {"owner": USER_ID}, "spec": {}},
        user_id=USER_ID,
        user_is_admin=True,
    )
    assert decision.self_approved is False
    assert decision.reason == "no_policy"


# ---------------------------------------------------------------------------
# Audit-actor naming.
# ---------------------------------------------------------------------------


def test_audit_actor_is_distinguishable_from_auto_approver() -> None:
    actor = sar.audit_actor_for(USER_ID)
    assert actor.startswith("self_approve_reduction:")
    assert actor != "system:auto-approver"


# ---------------------------------------------------------------------------
# is_enabled_for() helper.
# ---------------------------------------------------------------------------


def test_is_enabled_for_solo_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    assert sar.is_enabled_for(False) is True


def test_is_enabled_for_user_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_DEPLOYMENT_MODE", raising=False)
    assert sar.is_enabled_for(True) is True


def test_is_enabled_for_neither(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_DEPLOYMENT_MODE", raising=False)
    assert sar.is_enabled_for(False) is False
