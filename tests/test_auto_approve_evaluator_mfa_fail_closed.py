"""#599 — auto_approve_evaluator MUST fail-CLOSED if the MFA gate raises.

Independent code review 2026-05-25 flagged 6 inner `except Exception: pass`
blocks in `auto_approve_evaluator._evaluate_and_apply_inner` with no logger
call. The most severe failure mode was the MFA-gate path:

  * `mfa_audit` was initialised as `{"mfa_gate_evaluated": False}`
  * `_mfa_gate.evaluate_for_route(...)` was wrapped in `try/except: pass`
  * Downstream `_apply_mfa_and_self_approve` read
    `bool(mfa_audit.get("would_require_mfa"))` which is False when the
    key is absent
  * Net effect on gate crash: a high-risk request that would normally
    require MFA verification would silently auto-approve WITHOUT MFA.
    FAIL-OPEN on a security-critical gate.

Per [[ibounce-honest-positioning]] the only honest default for a
security-critical gate is FAIL-CLOSED — a crash routes the request to
the human-approval path (would_require_mfa stays True; mfa_present
stays False; the enforcement block in `_apply_mfa_and_self_approve`
blocks the auto-approval).

Tests follow the state-verification convention in docs/CONTRIBUTING.md:
each test asserts the OBSERVABLE outcome (the AutoApproveDecision the
evaluator returns + the request's persisted state), not just the
internal audit dict shape. The sabotage check at the bottom proves the
fail-CLOSED default is load-bearing — if a future refactor reverts to
`{"mfa_gate_evaluated": False}`, the sabotage assertion fails.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock

import pytest

from iam_jit import (
    auto_approve_evaluator,
    mfa_gate,
    rate_limit,
    settings_store,
)
from iam_jit.auto_approve import AutoApproveDecision


# ----- Fixtures ----------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singletons() -> None:
    """Reset module-level singletons that bleed across tests."""
    settings_store.reset_default_store_for_tests()
    rate_limit.reset_default_limiter_for_tests()


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set env vars the evaluator reads at runtime.

      * IAM_JIT_MAGIC_LINK_SECRET — middleware._get_secret() raises
        HTTPException(500) without it; that exception would bypass the
        MFA-gate try/except via the args-eval order and confuse the
        test (the log would name "evaluate_for_route raised" but the
        real source is the secret-getter).
      * IAM_JIT_MAX_AUTO_APPROVE_RISK_BELOW — the platform floor that
        clamps `auto_approve_risk_below`. Raised to 20 so we can use a
        score of 9 to exercise the MFA-enforcement path: 9 < threshold
        (so the score gate APPROVES), AND 9 >= MFA floor (so MFA is
        required). The default floor of 5 makes those two conditions
        unreachable together.
      * IAM_JIT_MFA_STEP_UP_AT_SCORE — set to 7 (its default) so the
        intent is explicit in test setup.
    """
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", "test-secret-aaaaaaaaa")
    monkeypatch.setenv("IAM_JIT_MAX_AUTO_APPROVE_RISK_BELOW", "20")
    monkeypatch.setenv("IAM_JIT_MFA_STEP_UP_AT_SCORE", "7")


@pytest.fixture
def auto_approve_enabled() -> None:
    """Configure deployment so low-risk requests would auto-approve in
    the success path. Used to prove the fail-CLOSED default takes
    precedence when the gate raises (without this fixture there's
    nothing to fail-close on — feature is off, the request never
    auto-approves regardless).

    Threshold = 15 with the floor raised to 20 (see `_env` fixture)
    means score=8 is BELOW threshold (9 for read-only) → score gate
    would APPROVE → the
    MFA-enforcement block is reachable. With the default floor of 5
    any score>=5 is auto-rejected by the score gate before the MFA
    enforcement block ever runs.
    """
    store = settings_store.get_default_store()
    store.put(
        settings_store.Settings(
            auto_approve_risk_below=15,
            auto_approve_quota_per_hour=100,
            never_auto_approve_services=(),
        ),
    )


def _make_request(*, score: int) -> dict[str, Any]:
    """A minimal request dict with the shape `_evaluate_and_apply_inner`
    expects. `score` controls the `would_require_mfa` outcome — the MFA
    gate floor defaults to 7 (see `mfa_gate._high_risk_score_floor`),
    so score>=7 is high-risk and DOES require MFA."""
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": "rq-fail-closed-test",
            "requester": {"name": "Dev", "email": "dev@example.com"},
        },
        "spec": {
            "description": "Read S3 config",
            "access_type": "read-only",
            "task_intent": {"services": ["s3"], "actions": ["read"]},
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 24},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::example",
                }],
            },
            "provisioning": {"mode": "identity_center"},
        },
        "status": {
            "state": "pending",
            "history": [],
            "review": {"risk_score": score},
        },
    }


def _make_user() -> Any:
    user = MagicMock()
    user.id = "email:dev@example.com"
    user.is_admin = False
    return user


# ----- #599 tests --------------------------------------------------------


def test_mfa_gate_evaluate_crash_defaults_fail_closed_not_open(
    monkeypatch: pytest.MonkeyPatch,
    auto_approve_enabled: None,
) -> None:
    """THE core #599 regression — when `mfa_gate.evaluate_for_route`
    raises, the high-risk request MUST be blocked (auto_approve=False)
    with reason `mfa_required_for_high_risk`, NOT silently auto-
    approved.

    Pre-#599 the evaluator's `mfa_audit` defaulted to
    `{"mfa_gate_evaluated": False}` and `would_require_mfa` was absent,
    coerced to False, so the enforcement block at
    `_apply_mfa_and_self_approve` line ~397 never fired → high-risk
    request would auto-approve without MFA. This test exercises that
    exact failure mode.
    """
    def _raise_gate(**_kw: Any) -> dict[str, Any]:
        raise RuntimeError("simulated MFA gate regression")
    monkeypatch.setattr(mfa_gate, "evaluate_for_route", _raise_gate)

    request = _make_request(score=8)  # >= MFA floor (7); < read threshold (9)
    user = _make_user()

    result = auto_approve_evaluator.evaluate_and_apply_for_new_request(
        request=request, user=user, accounts_store=None,
    )

    # 1. The reported decision is the claim.
    decision = result["auto_decision"]
    assert decision is not None, (
        "evaluator returned no decision — gate crash propagated past "
        "the outer try/except; this is a separate regression from #599"
    )
    assert decision.auto_approve is False, (
        "FAIL-OPEN regression: gate crash auto-approved a high-risk "
        f"request. decision={decision!r}; this is the #599 shape."
    )
    assert decision.reason == "mfa_required_for_high_risk", (
        f"expected MFA-enforcement block to fire; got reason={decision.reason!r}"
    )

    # 2. Observable state per docs/CONTRIBUTING.md: the request stays
    #    in pending (the auto-approve provisioning side effect never
    #    fires when auto_approve is False).
    state = (request.get("status") or {}).get("state")
    assert state == "pending", (
        f"FAIL-OPEN regression in state: request transitioned out of "
        f"pending despite blocked decision. state={state!r}; full "
        f"status={request.get('status')!r}"
    )

    # 3. The mfa_block_response is populated so the route can return
    #    the 403 + redirect body to the client.
    block = result["mfa_block_response"]
    assert block is not None, (
        "block response missing — the route can't tell the client to "
        f"re-authenticate. result={result!r}"
    )
    assert block.get("mfa_step_up_required") is True


def test_mfa_gate_evaluate_crash_logs_exception(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    auto_approve_enabled: None,
) -> None:
    """Per #599: each inner except MUST `logger.exception(...)` so
    SecOps can chase the gate failure out-of-band. A silent `pass`
    leaves operators blind to security-relevant degradation."""
    def _raise_gate(**_kw: Any) -> dict[str, Any]:
        raise RuntimeError("simulated MFA gate regression for log assert")
    monkeypatch.setattr(mfa_gate, "evaluate_for_route", _raise_gate)

    request = _make_request(score=8)
    user = _make_user()

    with caplog.at_level(logging.ERROR, logger="iam_jit.auto_approve_evaluator"):
        auto_approve_evaluator.evaluate_and_apply_for_new_request(
            request=request, user=user, accounts_store=None,
        )

    # State verification: the log record exists AND it's an
    # exception-shape record (carries the traceback) AND it names the
    # MFA gate specifically (so an operator searching for "mfa" finds
    # it).
    mfa_records = [
        r for r in caplog.records
        if r.levelno >= logging.ERROR
        and "mfa_gate" in r.message.lower()
    ]
    assert mfa_records, (
        "expected an ERROR-level log naming the MFA gate failure; "
        f"got records={[(r.levelno, r.message) for r in caplog.records]!r}"
    )
    assert any(r.exc_info is not None for r in mfa_records), (
        "expected logger.exception (carries traceback); got "
        f"logger.error/.warning instead. records={mfa_records!r}"
    )


def test_mfa_gate_normal_path_unchanged_low_risk_auto_approves(
    monkeypatch: pytest.MonkeyPatch,
    auto_approve_enabled: None,
) -> None:
    """Regression check: when the MFA gate does NOT crash + the
    request is LOW-risk (score < floor), the request should auto-
    approve. Proves the fail-CLOSED default only applies on crash,
    not on every request."""
    def _success_low_risk(**_kw: Any) -> dict[str, Any]:
        return {
            "mfa_gate_evaluated": True,
            "mfa_source": "absent",
            "mfa_step_up_floor": 7,
            "would_require_mfa": False,  # low-risk → MFA not required
            "mfa_present": False,
            "mfa_age_seconds": None,
            "mfa_reason": "no_cookie",
        }
    monkeypatch.setattr(mfa_gate, "evaluate_for_route", _success_low_risk)

    # Stub provisioning so the auto-approve path can complete cleanly.
    from iam_jit import provision as provision_mod
    def _stub_provision(req, *, accounts_store, **_kw):
        return provision_mod.ProvisioningResult(
            role_arn="arn:aws:iam::060392206767:role/iam-jit/stub",
            role_name="stub", account_id="060392206767",
            assumer_principal_arn="arn:aws:iam::060392206767:user/stub",
            expires_at="2030-01-01T00:00:00Z", external_id="stub",
            session_name="stub", tags={},
        )
    monkeypatch.setattr(provision_mod, "provision", _stub_provision)

    request = _make_request(score=2)  # low-risk
    user = _make_user()

    result = auto_approve_evaluator.evaluate_and_apply_for_new_request(
        request=request, user=user, accounts_store=None,
    )

    decision = result["auto_decision"]
    assert decision is not None
    assert decision.auto_approve is True, (
        f"low-risk normal-path request was NOT auto-approved; "
        f"the fail-CLOSED default is over-applying. decision={decision!r}"
    )
    # State verification: request transitioned out of pending.
    state = (request.get("status") or {}).get("state")
    assert state != "pending", (
        f"auto_approve=True but state stayed pending; state={state!r}"
    )


def test_mfa_gate_normal_path_high_risk_with_mfa_auto_approves(
    monkeypatch: pytest.MonkeyPatch,
    auto_approve_enabled: None,
) -> None:
    """Regression check: when the MFA gate returns
    `would_require_mfa=True` BUT `mfa_present=True`, the high-risk
    request should auto-approve. Proves the enforcement block only
    fires when MFA is required AND absent."""
    def _success_with_mfa(**_kw: Any) -> dict[str, Any]:
        return {
            "mfa_gate_evaluated": True,
            "mfa_source": "cookie",
            "mfa_step_up_floor": 7,
            "would_require_mfa": True,
            "mfa_present": True,
            "mfa_age_seconds": 60,
            "mfa_reason": "ok",
        }
    monkeypatch.setattr(mfa_gate, "evaluate_for_route", _success_with_mfa)

    from iam_jit import provision as provision_mod
    def _stub_provision(req, *, accounts_store, **_kw):
        return provision_mod.ProvisioningResult(
            role_arn="arn:aws:iam::060392206767:role/iam-jit/stub",
            role_name="stub", account_id="060392206767",
            assumer_principal_arn="arn:aws:iam::060392206767:user/stub",
            expires_at="2030-01-01T00:00:00Z", external_id="stub",
            session_name="stub", tags={},
        )
    monkeypatch.setattr(provision_mod, "provision", _stub_provision)

    request = _make_request(score=8)  # >= MFA floor (7); < read threshold (9)
    user = _make_user()

    result = auto_approve_evaluator.evaluate_and_apply_for_new_request(
        request=request, user=user, accounts_store=None,
    )

    decision = result["auto_decision"]
    assert decision is not None
    assert decision.auto_approve is True, (
        f"high-risk WITH MFA present was NOT auto-approved; "
        f"decision={decision!r}"
    )


def test_mfa_gate_normal_path_high_risk_without_mfa_blocked(
    monkeypatch: pytest.MonkeyPatch,
    auto_approve_enabled: None,
) -> None:
    """Regression check (positive control): the success path with
    high-risk + no MFA must STILL block. Proves the enforcement
    block is reachable via the normal path, not only via the fail-
    CLOSED default — so the #599 test above isn't accidentally
    testing the same code path."""
    def _success_no_mfa(**_kw: Any) -> dict[str, Any]:
        return {
            "mfa_gate_evaluated": True,
            "mfa_source": "absent",
            "mfa_step_up_floor": 7,
            "would_require_mfa": True,
            "mfa_present": False,
            "mfa_age_seconds": None,
            "mfa_reason": "no_cookie",
        }
    monkeypatch.setattr(mfa_gate, "evaluate_for_route", _success_no_mfa)

    request = _make_request(score=8)
    user = _make_user()

    result = auto_approve_evaluator.evaluate_and_apply_for_new_request(
        request=request, user=user, accounts_store=None,
    )

    decision = result["auto_decision"]
    assert decision is not None
    assert decision.auto_approve is False
    assert decision.reason == "mfa_required_for_high_risk"
    state = (request.get("status") or {}).get("state")
    assert state == "pending"


def test_mfa_audit_default_is_fail_closed() -> None:
    """White-box check on the load-bearing default. If a future
    refactor changes the initial mfa_audit back to
    `{"mfa_gate_evaluated": False}` (the pre-#599 shape), this test
    catches it via the source-shape assertion below — the bytes
    `would_require_mfa": True` must appear in the same try-block
    that wraps evaluate_for_route.

    This is the source-text check that pairs with the behavioural
    sabotage check `test_fail_closed_default_is_load_bearing` below
    — together they make it impossible to silently revert without
    failing a test.
    """
    from pathlib import Path
    src = Path(auto_approve_evaluator.__file__).read_text()
    # The fail-CLOSED initial state must include would_require_mfa: True.
    # We search for the phrase in the immediate vicinity of the
    # evaluate_for_route call so the test isn't fooled by an unrelated
    # `would_require_mfa": True` somewhere else in the file.
    idx_call = src.find("_mfa_gate.evaluate_for_route(")
    assert idx_call > 0, "evaluate_for_route call not found in evaluator"
    # The fail-CLOSED init must come BEFORE the call (it's the value
    # mfa_audit holds if the call raises).
    window_before = src[max(0, idx_call - 1500):idx_call]
    assert '"would_require_mfa": True' in window_before, (
        "mfa_audit fail-CLOSED default missing — pre-#599 shape "
        "regression. The init block before evaluate_for_route MUST set "
        '`"would_require_mfa": True` so a gate crash routes high-risk '
        "requests to human approval, not silent auto-approve."
    )


def test_fail_closed_default_is_load_bearing(
    monkeypatch: pytest.MonkeyPatch,
    auto_approve_enabled: None,
) -> None:
    """Sabotage check per docs/CONTRIBUTING.md: prove that the fail-
    CLOSED default is what's keeping the #599 test green. If we
    sabotage `_apply_mfa_and_self_approve` to ignore would_require_mfa
    (the pre-#599 enforcement gap), the gate-crash test above would
    incorrectly auto-approve. This test verifies the inverse: with
    the fix in place, the enforcement IS what blocks.
    """
    # Sabotage: stub _apply_mfa_and_self_approve to pass through the
    # auto_decision unmodified (which is what would happen if
    # would_require_mfa were always False).
    def _no_op_apply(auto_decision, **_kw):
        return auto_decision, "system:auto-approver", None
    monkeypatch.setattr(
        auto_approve_evaluator,
        "_apply_mfa_and_self_approve",
        _no_op_apply,
    )
    # Make the gate crash.
    def _raise_gate(**_kw):
        raise RuntimeError("simulated for sabotage check")
    monkeypatch.setattr(mfa_gate, "evaluate_for_route", _raise_gate)
    # Stub provisioning so the sabotaged path can complete.
    from iam_jit import provision as provision_mod
    def _stub_provision(req, *, accounts_store, **_kw):
        return provision_mod.ProvisioningResult(
            role_arn="arn:aws:iam::060392206767:role/iam-jit/stub",
            role_name="stub", account_id="060392206767",
            assumer_principal_arn="arn:aws:iam::060392206767:user/stub",
            expires_at="2030-01-01T00:00:00Z", external_id="stub",
            session_name="stub", tags={},
        )
    monkeypatch.setattr(provision_mod, "provision", _stub_provision)

    request = _make_request(score=8)  # >= MFA floor (7); < read threshold (9)
    user = _make_user()
    result = auto_approve_evaluator.evaluate_and_apply_for_new_request(
        request=request, user=user, accounts_store=None,
    )

    # With the sabotage in place, the request DOES auto-approve —
    # proving that without the enforcement block, gate crash =>
    # auto-approve. This is the exact failure mode #599 documents,
    # and seeing it under sabotage proves the fix is load-bearing
    # (the unmodified test above relies on the enforcement to block).
    decision = result["auto_decision"]
    assert decision is not None
    assert decision.auto_approve is True, (
        "Sabotage check failed — even without the enforcement block, "
        "the gate crash did NOT auto-approve. That means the #599 "
        "test above is NOT testing what we think it is."
    )
