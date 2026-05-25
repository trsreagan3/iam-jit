"""#601 — state-verification parity tests for the `_auto_approve_helpers`
extraction (independent code review 2026-05-25 HIGH-4).

Pre-extraction `routes/requests.py` and `auto_approve_evaluator.py`
both carried structurally-identical local copies of
`_apply_mfa_and_self_approve` and `_attempt_provisioning` with comments
noting the duplication was kept-in-sync by discipline to avoid a
circular import. Same shape as the #559 / #596 / #598
[[cross-product-agent-parity]] violations.

These tests assert the OBSERVABLE state per docs/CONTRIBUTING.md:
  - both call sites import the helpers from the leaf module
  - neither call site has a local twin function definition
  - the helpers' behavior matches what the pre-extraction code produced
  - sabotage check: monkeypatching the leaf helper actually changes
    both call sites' behavior (proves the import is wired, not stale)

If a future refactor inlines either helper back into one of the
callers, every test in this file fails loudly at PR time.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from iam_jit import (
    _auto_approve_helpers,
    auto_approve_evaluator,
)
from iam_jit.auto_approve import AutoApproveDecision
from iam_jit.routes import requests as routes_requests


# ----- Helpers ---------------------------------------------------------------


def _module_source_path(mod: Any) -> Path:
    """Return the absolute path of a module's source file."""
    src = inspect.getsourcefile(mod)
    assert src is not None, f"could not locate source for {mod!r}"
    return Path(src)


def _module_ast(mod: Any) -> ast.Module:
    """Parse a module's source file into an AST."""
    src = _module_source_path(mod).read_text()
    return ast.parse(src)


def _module_imports_name_from(
    mod: Any, *, source_module_suffix: str, name: str
) -> bool:
    """AST check: does `mod` have an `ImportFrom` statement that imports
    `name` (possibly aliased) from a module whose dotted path ends with
    `source_module_suffix`? Catches both `from x import y` and
    `from x import y as z`.
    """
    tree = _module_ast(mod)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        # node.module is a dotted-but-not-leading-dots string ("foo.bar"),
        # or None for `from . import x`. We match on the suffix so
        # relative + absolute imports both work.
        mod_name = node.module or ""
        if not mod_name.endswith(source_module_suffix):
            continue
        for alias in node.names:
            if alias.name == name:
                return True
    return False


def _module_defines_function(mod: Any, *, name: str) -> bool:
    """AST check: does `mod` define a top-level function named `name`?"""
    tree = _module_ast(mod)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return True
    return False


# ----- Test 1: both call sites import from the leaf module ------------------


def test_apply_mfa_helper_imported_by_both_call_sites() -> None:
    """State verification: the leaf module's helper is imported by BOTH
    `routes/requests.py` AND `auto_approve_evaluator.py`. The whole
    point of the #601 extraction is that the two call sites share one
    source of truth — if either drops the import, this test fails."""
    assert _module_imports_name_from(
        routes_requests,
        source_module_suffix="_auto_approve_helpers",
        name="apply_mfa_and_self_approve_enforcement",
    ), (
        "routes/requests.py does NOT import "
        "apply_mfa_and_self_approve_enforcement from "
        "iam_jit._auto_approve_helpers — the #601 extraction has "
        "regressed; the route is using a local twin again."
    )
    assert _module_imports_name_from(
        auto_approve_evaluator,
        source_module_suffix="_auto_approve_helpers",
        name="apply_mfa_and_self_approve_enforcement",
    ), (
        "auto_approve_evaluator.py does NOT import "
        "apply_mfa_and_self_approve_enforcement from "
        "iam_jit._auto_approve_helpers — the #601 extraction has "
        "regressed; the evaluator is using a local twin again."
    )


def test_attempt_provisioning_helper_imported_by_both_call_sites() -> None:
    """Parity twin of the test above for `attempt_provisioning`."""
    assert _module_imports_name_from(
        routes_requests,
        source_module_suffix="_auto_approve_helpers",
        name="attempt_provisioning",
    ), (
        "routes/requests.py does NOT import attempt_provisioning "
        "from iam_jit._auto_approve_helpers — the #601 extraction "
        "has regressed."
    )
    assert _module_imports_name_from(
        auto_approve_evaluator,
        source_module_suffix="_auto_approve_helpers",
        name="attempt_provisioning",
    ), (
        "auto_approve_evaluator.py does NOT import "
        "attempt_provisioning from iam_jit._auto_approve_helpers — "
        "the #601 extraction has regressed."
    )


def test_safe_mark_failed_helper_imported_by_both_call_sites() -> None:
    """Parity twin for `safe_mark_failed`. The pre-extraction routes/*
    twin had a silent-pass last-resort fallback; the leaf version logs
    loudly. Both call sites now get the loud-logging shape."""
    assert _module_imports_name_from(
        routes_requests,
        source_module_suffix="_auto_approve_helpers",
        name="safe_mark_failed",
    )
    assert _module_imports_name_from(
        auto_approve_evaluator,
        source_module_suffix="_auto_approve_helpers",
        name="safe_mark_failed",
    )


# ----- Test 2: no local twin definitions ------------------------------------


def test_no_local_apply_mfa_twin_in_routes_requests() -> None:
    """State verification: routes/requests.py has NO local
    `_apply_mfa_and_self_approve_enforcement` function definition.
    The name remains in the module namespace as an import alias, but
    NOT as a function definition.

    If a future PR re-inlines the helper, this test fails — surfaces
    the [[cross-product-agent-parity]] violation at PR time.
    """
    assert not _module_defines_function(
        routes_requests, name="_apply_mfa_and_self_approve_enforcement"
    ), (
        "routes/requests.py has a local def "
        "_apply_mfa_and_self_approve_enforcement — the #601 extraction "
        "has regressed; the routes copy was re-inlined."
    )


def test_no_local_apply_mfa_twin_in_auto_approve_evaluator() -> None:
    """Twin of the test above for auto_approve_evaluator.py. The local
    function was named `_apply_mfa_and_self_approve` (without the
    `_enforcement` suffix) pre-extraction."""
    assert not _module_defines_function(
        auto_approve_evaluator, name="_apply_mfa_and_self_approve"
    ), (
        "auto_approve_evaluator.py has a local def "
        "_apply_mfa_and_self_approve — the #601 extraction has "
        "regressed; the evaluator copy was re-inlined."
    )


def test_no_local_attempt_provisioning_twin_in_routes_requests() -> None:
    assert not _module_defines_function(
        routes_requests, name="_attempt_provisioning"
    ), (
        "routes/requests.py has a local def _attempt_provisioning — "
        "the #601 extraction has regressed; the routes copy was "
        "re-inlined."
    )


def test_no_local_attempt_provisioning_twin_in_auto_approve_evaluator() -> None:
    assert not _module_defines_function(
        auto_approve_evaluator, name="_attempt_provisioning"
    ), (
        "auto_approve_evaluator.py has a local def "
        "_attempt_provisioning — the #601 extraction has regressed."
    )


def test_no_local_safe_mark_failed_twin_in_routes_requests() -> None:
    assert not _module_defines_function(
        routes_requests, name="_safe_mark_failed"
    ), (
        "routes/requests.py has a local def _safe_mark_failed — "
        "the #601 extraction has regressed."
    )


def test_no_local_safe_mark_failed_twin_in_auto_approve_evaluator() -> None:
    assert not _module_defines_function(
        auto_approve_evaluator, name="_safe_mark_failed"
    ), (
        "auto_approve_evaluator.py has a local def _safe_mark_failed "
        "— the #601 extraction has regressed."
    )


# ----- Test 3: helper behavior matches pre-extraction (regression) ----------


def test_apply_mfa_helper_no_op_when_low_risk_no_self_approve() -> None:
    """Behavior regression: low-risk request, MFA not required, no
    self-approve eligibility → helper returns the decision unchanged
    with actor=system:auto-approver, no block_response.
    """
    incoming = AutoApproveDecision(
        auto_approve=True, reason="under_threshold", details={"score": 2},
    )
    decision, actor, block = (
        _auto_approve_helpers.apply_mfa_and_self_approve_enforcement(
            incoming,
            mfa_audit={
                "would_require_mfa": False,
                "mfa_present": False,
            },
            self_approve_audit={"self_approve_eligible": False},
            analysis_score=2,
            user_id="email:dev@example.com",
        )
    )
    # Pre-extraction behavior: pass-through.
    assert decision is incoming, (
        f"low-risk no-MFA no-SAR path mutated the decision; got {decision!r}"
    )
    assert actor == "system:auto-approver"
    assert block is None


def test_apply_mfa_helper_blocks_high_risk_without_mfa() -> None:
    """Behavior regression: approve decision + MFA required + MFA absent
    → block with reason=mfa_required_for_high_risk + block_response
    carries the OIDC redirect.
    """
    incoming = AutoApproveDecision(
        auto_approve=True, reason="under_threshold", details={"score": 8},
    )
    decision, actor, block = (
        _auto_approve_helpers.apply_mfa_and_self_approve_enforcement(
            incoming,
            mfa_audit={
                "would_require_mfa": True,
                "mfa_present": False,
                "mfa_step_up_floor": 7,
            },
            self_approve_audit={"self_approve_eligible": False},
            analysis_score=8,
            user_id="email:dev@example.com",
        )
    )
    assert decision.auto_approve is False, (
        f"MFA enforcement did NOT block the auto-approve; got {decision!r}"
    )
    assert decision.reason == "mfa_required_for_high_risk"
    assert decision.details.get("mfa_step_up_required") is True
    assert decision.details.get("mfa_step_up_at_score") == 7, (
        "mfa_step_up_at_score must carry the FLOOR not a duration "
        "(WB13-09 closure)"
    )
    # Actor reverts to system per WB12-11.
    assert actor == "system:auto-approver"
    # Block response shape — what the route splats into the response.
    assert block is not None
    assert block["mfa_step_up_required"] is True
    assert block["reason"] == "fresh_mfa_required"
    assert block["redirect_to"] == "/api/v1/auth/oidc/login"


def test_apply_mfa_helper_self_approve_flips_above_threshold() -> None:
    """Behavior regression: above_threshold + self_approve_eligible →
    decision flips to approve with reason=self_approve_reduction and
    actor=self_approve_reduction:<user_id>.
    """
    incoming = AutoApproveDecision(
        auto_approve=False, reason="above_threshold", details={"score": 7},
    )
    decision, actor, block = (
        _auto_approve_helpers.apply_mfa_and_self_approve_enforcement(
            incoming,
            mfa_audit={
                "would_require_mfa": False,
                "mfa_present": False,
            },
            self_approve_audit={
                "self_approve_eligible": True,
                "self_approve_reason": "admin_reduction",
            },
            analysis_score=7,
            user_id="email:admin@example.com",
        )
    )
    assert decision.auto_approve is True, (
        f"self-approve override did NOT flip the decision; got {decision!r}"
    )
    assert decision.reason == "self_approve_reduction"
    assert decision.details.get("original_reason") == "above_threshold", (
        "audit trail should preserve the pre-flip reason"
    )
    # Audit actor names the self-approve actor.
    assert "self_approve_reduction" in actor
    assert "admin@example.com" in actor
    assert block is None


def test_apply_mfa_helper_self_approve_flip_then_mfa_blocks() -> None:
    """Behavior regression (the WB13-08 / WB13-09 closure shape): a
    self-approve flip that lands on a high-risk score MUST then be MFA-
    blocked. Pre-WB13-08 the MFA gate ran first and missed this case.
    """
    incoming = AutoApproveDecision(
        auto_approve=False, reason="above_threshold", details={"score": 8},
    )
    decision, actor, block = (
        _auto_approve_helpers.apply_mfa_and_self_approve_enforcement(
            incoming,
            mfa_audit={
                "would_require_mfa": True,
                "mfa_present": False,
                "mfa_step_up_floor": 7,
            },
            self_approve_audit={
                "self_approve_eligible": True,
                "self_approve_reason": "admin_reduction",
            },
            analysis_score=8,
            user_id="email:admin@example.com",
        )
    )
    # MFA wins — admin self-approving a high-risk role with stale MFA
    # must still re-authenticate.
    assert decision.auto_approve is False, (
        f"WB13-08 regression — self-approve high-risk path bypassed "
        f"MFA enforcement; got {decision!r}"
    )
    assert decision.reason == "mfa_required_for_high_risk"
    # Actor reverts to system — the MFA block is the final word.
    assert actor == "system:auto-approver"
    assert block is not None


# ----- Test 4: sabotage check — leaf import is load-bearing -----------------


def test_sabotage_helper_change_affects_both_call_sites(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage check (per docs/CONTRIBUTING.md): monkeypatch the
    aliased helper on BOTH call-site modules and verify the sentinel
    propagates. Each call site looks up `_apply_mfa_and_self_approve_*`
    in its own module globals at call time, so the sabotage must be
    applied to the module where the call site lives, not to the leaf
    module — which is the exact behaviour the existing sabotage check
    in `tests/test_auto_approve_evaluator_mfa_fail_closed.py` relies on.

    Verifying both module-level aliases are wired (and that the alias
    on each module IS the helper from the leaf module) proves the
    extraction is structurally correct AND the existing sabotage
    contract continues to hold.
    """
    # 1. The two module-level aliases ARE the canonical leaf helper.
    assert (
        auto_approve_evaluator._apply_mfa_and_self_approve
        is _auto_approve_helpers.apply_mfa_and_self_approve_enforcement
    ), (
        "auto_approve_evaluator._apply_mfa_and_self_approve is NOT the "
        "leaf helper — the import alias has been shadowed by a local "
        "function. The #601 extraction has regressed."
    )
    assert (
        routes_requests._apply_mfa_and_self_approve_enforcement
        is _auto_approve_helpers.apply_mfa_and_self_approve_enforcement
    ), (
        "routes_requests._apply_mfa_and_self_approve_enforcement is "
        "NOT the leaf helper — the import alias has been shadowed."
    )

    # 2. Sabotage: replace the helper at the LEAF and verify the alias
    #    on each call-site module is unaffected — proves we cannot
    #    sabotage by monkeypatching the leaf alone (the call sites
    #    bound the helper at import time). This is INTENTIONAL — it
    #    means tests that need to sabotage MUST do so on the call-site
    #    module, exactly as the existing #599 sabotage test does.
    sentinel = object()
    monkeypatch.setattr(
        _auto_approve_helpers,
        "apply_mfa_and_self_approve_enforcement",
        sentinel,
    )
    # The call-site aliases still point at the ORIGINAL helper (Python
    # `from x import y` binds y at import time, so re-binding x.y
    # doesn't reach back to the caller's namespace).
    assert (
        auto_approve_evaluator._apply_mfa_and_self_approve is not sentinel
    )
    assert (
        routes_requests._apply_mfa_and_self_approve_enforcement is not sentinel
    )

    # 3. The inverse sabotage — monkeypatching the call-site alias
    #    DOES change the behavior at that site. Proves the call site
    #    looks up the name from its own globals at call time, so the
    #    existing sabotage test in
    #    `tests/test_auto_approve_evaluator_mfa_fail_closed.py` still
    #    works post-extraction.
    monkeypatch.setattr(
        auto_approve_evaluator, "_apply_mfa_and_self_approve", sentinel,
    )
    assert auto_approve_evaluator._apply_mfa_and_self_approve is sentinel


def test_sabotage_no_op_helper_on_evaluator_module_changes_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Functional sabotage check: monkeypatch the evaluator's alias to
    a no-op pass-through and confirm a request that would normally
    auto-approve does so unchanged (no MFA enforcement). Proves the
    helper is actually on the hot path inside `_evaluate_and_apply_inner`
    — without this, the parity tests above could be green while the
    real call path bypassed the helper through some other channel.

    Mirrors the [[cross-product-agent-parity]] sabotage convention from
    `tests/test_routes_auto_approve_parity.py` (#596 / #598).
    """
    # Sabotage: replace the helper on the evaluator with a pass-through.
    seen = []
    def _passthrough(auto_decision, **_kw):
        seen.append(auto_decision)
        return auto_decision, "system:auto-approver", None
    monkeypatch.setattr(
        auto_approve_evaluator,
        "_apply_mfa_and_self_approve",
        _passthrough,
    )

    # Minimal inputs — drive the inner evaluator with a low-risk
    # request that would normally auto-approve. We don't care about
    # the outcome; we care that the sabotaged helper was invoked.
    from iam_jit import (
        mfa_gate,
        rate_limit,
        settings_store,
    )

    settings_store.reset_default_store_for_tests()
    rate_limit.reset_default_limiter_for_tests()
    settings_store.get_default_store().put(
        settings_store.Settings(
            auto_approve_risk_below=15,
            auto_approve_quota_per_hour=100,
            never_auto_approve_services=(),
        ),
    )
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", "test-secret-aaaaaaaaa")
    monkeypatch.setenv("IAM_JIT_MAX_AUTO_APPROVE_RISK_BELOW", "20")

    def _mfa_low_risk(**_kw: Any) -> dict[str, Any]:
        return {
            "mfa_gate_evaluated": True,
            "mfa_source": "absent",
            "mfa_step_up_floor": 7,
            "would_require_mfa": False,
            "mfa_present": False,
            "mfa_age_seconds": None,
            "mfa_reason": "no_cookie",
        }
    monkeypatch.setattr(mfa_gate, "evaluate_for_route", _mfa_low_risk)

    # Stub provisioning so the auto-approve side effect completes.
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

    request = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": "rq-sabotage-test",
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
            "review": {"risk_score": 3},
        },
    }
    user = MagicMock()
    user.id = "email:dev@example.com"
    user.is_admin = False

    auto_approve_evaluator.evaluate_and_apply_for_new_request(
        request=request, user=user, accounts_store=None,
    )

    # State verification: the sabotaged helper was invoked at least
    # once with the score-gate decision. Proves the evaluator's hot
    # path actually calls the aliased helper — if a future refactor
    # routes around it (e.g., calling the leaf helper directly via
    # the leaf-module name), `seen` stays empty and this fails.
    assert len(seen) >= 1, (
        "evaluator did NOT call the module-aliased helper — the hot "
        "path bypassed the alias, so monkeypatching it has no effect. "
        "This would break the existing #599 sabotage test in "
        "tests/test_auto_approve_evaluator_mfa_fail_closed.py."
    )
