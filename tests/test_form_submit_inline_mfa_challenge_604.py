"""Inline MFA gate at form-submit — #604 HIGH.

Founder Q 2026-05-25: "if I use iam-jit to request a role and haven't
2FA'd already, what happens? do I automatically get prompted for 2FA?"

Pre-fix shape: the web paste-form submit handler ran the auto-approve
evaluator (which evaluates the MFA gate), then unconditionally
`store.put`-ed the request and redirected to the request detail page.
A user whose effective decision would have been auto-approve-but-MFA-
blocked saw their request silently land in `pending` with no inline
signal that MFA was the blocker; they had to chase the audit log to
find out why nothing happened.

Post-fix shape: when the evaluator returns a non-None
`mfa_block_response`, the form-submit handler renders the form back
with HTTP 403, the user's typed input preserved, and a structured
errors list naming the score, the threshold, the OIDC re-auth link,
and the admin-fallback hint. The request is NOT persisted (no queue
clutter for a submission the user must re-trigger after stepping up
MFA).

The MFA gate inside `_apply_mfa_and_self_approve_enforcement` only
short-circuits to `mfa_required_for_high_risk` when the effective
auto-approve decision is True AND MFA is missing. For a NON-admin
user, the score gate denies a high-risk request as `above_threshold`
first (before MFA matters) — that user gets the normal human-review
fallback, not an inline MFA challenge. So the gate is observable in
the founder's exact scenario when:

    admin + solo deployment + high-risk own-request + no MFA

Stage 1 of the enforcement helper flips the score-gate denial to
`self_approve_reduction`; Stage 2 then fires the MFA block on the
flipped-to-approve decision. That yields a non-None
`mfa_block_response` for our inline-gate to catch — which is exactly
the founder's UX gap from 2026-05-25.

These tests follow the state-verification convention in
`docs/CONTRIBUTING.md`: every assertion about the reported status
ALSO asserts the observable side effect — most notably that the
high-risk no-MFA path leaves the request store EMPTY (the user has
to resubmit after MFA), not "in pending and waiting for an approver."

The final sabotage test proves the MFA gate is load-bearing: with
the inline-gate stripped via a monkeypatch on
`evaluate_and_apply_for_new_request`, the same high-risk submission
that was rejected is now accepted (303 + persisted) — i.e., the
production guard is the only thing keeping the request out of the
store.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


# -----------------------------------------------------------------------------
# Test fixtures — high vs low risk policies.
# -----------------------------------------------------------------------------


def _high_risk_policy() -> str:
    """Serialised policy that scores >= 7 — `iam:PassRole on *` is
    the canonical privilege-escalation primitive that the
    deterministic scorer rates highly (verified score=9). Same shape
    used in tests/test_mfa_enforcement_e2e.py.
    """
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                }
            ],
        }
    )


def _low_risk_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::artifacts/release-notes.pdf",
                }
            ],
        }
    )


def _form_body(*, policy: str, access_type: str = "read-write") -> dict[str, str]:
    return {
        "description": "MFA inline-gate test — needs a fresh-MFA submission",
        "policy": policy,
        "access_type": access_type,
        "accounts": "060392206767",
        "duration_hours": "1",
    }


def _store_request_count(app: Any) -> int:
    """State-verification helper: how many requests are persisted?
    The fix MUST leave the store empty after a blocked submission."""
    store = app.state.request_store
    return len(store.list_ids())


def _solo_admin_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable the deployment shape where MFA inline-rejection actually
    fires for an authenticated user.

    See module docstring for why this combination — admin + solo +
    high-risk + no MFA — is the one that yields a non-None
    `mfa_block_response` from the shared evaluator. Concretely:

      - IAM_JIT_DEPLOYMENT_MODE=solo enables the self-approve
        override path for admins (see
        `src/iam_jit/self_approve_reductions.py`).
      - IAM_JIT_MFA_STEP_UP_AT_SCORE=7 puts the MFA-required floor
        at the score we use for the high-risk policy (which scores 9).
      - We force the settings store to a state where the score-gate
        WOULD have approved if not for the MFA block: a high
        auto_approve_risk_below + an empty `never_auto_approve_services`
        list (default blocks the `iam` service entirely, which would
        deny our test policy via `service_blocked` before the MFA
        gate could ever fire).
      - Floor env raised in lockstep so the threshold isn't clamped
        back below our test score.
    """
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    monkeypatch.setenv("IAM_JIT_MFA_STEP_UP_AT_SCORE", "7")
    monkeypatch.setenv("IAM_JIT_MAX_AUTO_APPROVE_RISK_BELOW", "20")
    from iam_jit import settings_store

    # Note: the conftest's autouse `_reset_global_singletons` fixture
    # already resets the settings store before each test (we run AFTER
    # that), so the put below is the only state we're injecting.
    settings_store.get_default_store().put(
        settings_store.Settings(
            auto_approve_risk_below=15,  # high enough to qualify our score-9 policy
            auto_approve_quota_per_hour=100,
            # Default `never_auto_approve_services` includes "iam",
            # which would short-circuit our iam:PassRole test policy
            # with `service_blocked` BEFORE the MFA gate could fire.
            # Empty tuple removes that floor for this test only.
            never_auto_approve_services=(),
        ),
    )


# -----------------------------------------------------------------------------
# Tests.
# -----------------------------------------------------------------------------


def test_low_risk_submit_proceeds_normally_no_mfa_needed(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Baseline: low-risk submission (no high-risk MFA trigger) by an
    admin in solo mode must NOT trip the inline gate. The handler
    redirects to the request detail page (303) and the request IS
    persisted.

    State-verification: store gains exactly one request after the
    submit. (Distinguishes a real success from a silent failure that
    just happens to return 303.)
    """
    _solo_admin_env(monkeypatch)

    before = _store_request_count(as_admin.app)
    resp = as_admin.post(
        "/requests/new/paste",
        data=_form_body(policy=_low_risk_policy(), access_type="read-only"),
        follow_redirects=False,
    )

    # Claim: 303 redirect to a /requests/<id> detail page.
    assert resp.status_code == 303, (
        f"low-risk submit must redirect; got {resp.status_code}: {resp.text[:400]}"
    )
    location = resp.headers["location"]
    assert location.startswith("/requests/"), location

    # Observable state: one new request landed in the store. Without
    # this assertion the test would still pass if the redirect fired
    # while the store.put silently failed.
    after = _store_request_count(as_admin.app)
    assert after == before + 1, (
        f"low-risk submit must persist a request; before={before} after={after}"
    )


def test_high_risk_submit_no_mfa_cookie_renders_inline_challenge(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The user's question: 'if I haven't 2FA'd, what happens?'

    A high-risk policy submitted without a fresh iam_jit_session_mfa
    cookie MUST be rejected inline at form-submit with a 403 response
    that names the score, the threshold, and the OIDC re-auth link.

    State-verification (THIS is what makes the test catch the
    regression): the response body literally contains the words
    'MFA', 'step-up', and 'score:' followed by the numeric score.
    Without the inline-gate fix, the response would either be a 303
    redirect (pre-fix shape) or a 403 without the structured error
    payload (different bug).
    """
    _solo_admin_env(monkeypatch)

    resp = as_admin.post(
        "/requests/new/paste",
        data=_form_body(policy=_high_risk_policy()),
        follow_redirects=False,
    )

    # Claim: 403, NOT 303. (303 would mean the request landed in the
    # store and the user is being redirected to the detail page —
    # exactly the pre-fix UX the founder asked about.)
    assert resp.status_code == 403, (
        f"high-risk no-MFA submit must be rejected at the form; "
        f"got status {resp.status_code}; body[:400]={resp.text[:400]}"
    )

    # Observable state: the response body carries the structured
    # error block that names the gate (so the user can act on it).
    body = resp.text
    assert "MFA" in body, "response must mention MFA so user knows the gate"
    assert "step-up" in body, (
        "response must mention step-up so user knows the action"
    )
    assert "score:" in body, (
        "response must surface the score so user can compare against threshold"
    )
    # The redirect_to link MUST be present so a user clicking 'sign in'
    # lands on OIDC, which mints a fresh iam_jit_session_mfa cookie.
    assert "/api/v1/auth/oidc/login" in body, (
        "response must include the OIDC re-auth link"
    )


def test_high_risk_submit_no_mfa_does_not_persist_request(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State-verification of the inline-gate's other guarantee: a
    blocked submission MUST NOT pollute the request store.

    Pre-fix: the request was always `store.put`-ed after evaluator
    return (the evaluator left the state at `pending` when MFA
    blocked, but the request still landed on disk). The user's queue
    filled up with rejected-pending submissions they couldn't tell
    apart from real pending ones.

    Post-fix: store.put is skipped when mfa_block_response is set.
    """
    _solo_admin_env(monkeypatch)

    before = _store_request_count(as_admin.app)
    resp = as_admin.post(
        "/requests/new/paste",
        data=_form_body(policy=_high_risk_policy()),
        follow_redirects=False,
    )
    assert resp.status_code == 403

    after = _store_request_count(as_admin.app)
    assert after == before, (
        f"blocked submission must NOT persist a request; "
        f"before={before} after={after}"
    )


def test_high_risk_block_response_names_admin_fallback(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the inline gate fires, the response MUST tell the user
    BOTH the user-side action (OIDC re-auth) AND the admin-side
    fallback (operator can approve via human-review path / enroll
    OIDC MFA if not yet configured).

    Per [[ibounce-honest-positioning]] the rejection must be
    actionable on its own — a user without an OIDC provider must not
    be locked out with no recourse.
    """
    _solo_admin_env(monkeypatch)

    resp = as_admin.post(
        "/requests/new/paste",
        data=_form_body(policy=_high_risk_policy()),
        follow_redirects=False,
    )
    assert resp.status_code == 403
    body = resp.text

    # User-side action: re-auth via OIDC.
    assert "re-authenticate" in body or "re-auth" in body, (
        "response must tell the user to re-authenticate"
    )
    # Admin-side fallback: human-review path / enroll OIDC.
    assert "Admin" in body or "admin" in body, (
        "response must mention the admin-side fallback (human review / "
        "OIDC enrollment) so a user without an OIDC provider isn't "
        "locked out with no recourse"
    )


def test_sabotage_check_mfa_gate_is_load_bearing(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage check (per [[deliberate-feature-completion]] +
    docs/CONTRIBUTING.md state-verification convention): if we
    monkeypatch the auto-approve evaluator to never return an
    `mfa_block_response`, the same high-risk submission that
    test_high_risk_submit_no_mfa_cookie_renders_inline_challenge
    rejected MUST now be accepted (303 + stored).

    This proves the inline-gate fix is the only thing keeping the
    blocked submission out of the store — a future refactor that
    silently bypasses the mfa_block_response check would fail this
    test loudly, not silently regress.
    """
    _solo_admin_env(monkeypatch)

    from iam_jit import auto_approve_evaluator
    from iam_jit.routes import web as web_routes

    real_eval = auto_approve_evaluator.evaluate_and_apply_for_new_request

    def _eval_without_mfa_block(*args: Any, **kwargs: Any) -> dict[str, Any]:
        """Wrap the real evaluator but strip mfa_block_response so
        the form-submit gate cannot fire."""
        result = real_eval(*args, **kwargs)
        if isinstance(result, dict):
            result = dict(result)
            result["mfa_block_response"] = None
        return result

    # Patch the attribute the route handler actually reaches for.
    # `from .. import auto_approve_evaluator` inside web.py rebinds
    # the lookup against the module object, so monkeypatching the
    # module-level attribute (rather than the imported name) is the
    # right surface.
    monkeypatch.setattr(
        auto_approve_evaluator,
        "evaluate_and_apply_for_new_request",
        _eval_without_mfa_block,
    )
    # Defense-in-depth: also patch the attribute on the route module
    # in case a future refactor caches the lookup.
    if hasattr(web_routes, "auto_approve_evaluator"):
        monkeypatch.setattr(
            web_routes.auto_approve_evaluator,
            "evaluate_and_apply_for_new_request",
            _eval_without_mfa_block,
        )

    before = _store_request_count(as_admin.app)
    resp = as_admin.post(
        "/requests/new/paste",
        data=_form_body(policy=_high_risk_policy()),
        follow_redirects=False,
    )

    # With the gate sabotaged, the form-submit no longer detects
    # mfa_block_response and falls through to store.put + redirect.
    # The presence of this redirect proves the inline-gate check at
    # the form-submit handler is the load-bearing piece — not the
    # evaluator alone, not the OIDC layer, not the score calculation.
    assert resp.status_code == 303, (
        f"sabotage check: with mfa_block_response stripped, the same "
        f"submission that the production gate rejected MUST now "
        f"succeed (303 + persisted). Instead got status "
        f"{resp.status_code}; body[:400]={resp.text[:400]}. If this "
        f"test fails as 403 even with the sabotage, the form-submit "
        f"handler has a SECOND MFA check that the inline-gate fix is "
        f"not the only thing keeping the request out of the store."
    )
    after = _store_request_count(as_admin.app)
    assert after == before + 1, (
        f"sabotage check: store.put must run when the gate is removed; "
        f"before={before} after={after}"
    )
