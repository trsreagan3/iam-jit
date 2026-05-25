"""#598 — web /requests/new/paste must evaluate the auto-approve gate
identically to the API submit path.

PDF v3 build agent finding 2026-05-25: web paste-form submission saved
the request to pending but did NOT invoke the auto-approve evaluator
that the API submit path invokes. Operators submitting via the web UI
got every request as pending, even ones the deterministic scorer
would have auto-approved. Same silent-degradation pattern as #596
(web→Slack notification gap, just fixed in 1ee7aa6).

These tests assert OBSERVABLE state per docs/CONTRIBUTING.md — every
test inspects what actually landed in the request store (state,
history actor, history action) rather than just whether the form
POST returned 303. A status-only assertion is exactly the kind of
test that lets a silent-degradation bug ship; the table in
CONTRIBUTING.md lists seven prior incidents of that shape.

Tests:
  1. Web paste-form low-risk submit auto-approves (the #598 core fix).
  2. API submit low-risk auto-approves (regression check — pre-#598
     behaviour must stay working).
  3. Both paths produce identical auto-approve trajectories — same
     actor on the history entry, same `auto_approve` action, same
     post-evaluation state ([[cross-product-agent-parity]]).
  4. Web paste high-risk stays pending (no auto-approve, request
     waits for human approver).
  5. API submit high-risk stays pending (regression).
  6. Web paste with no auto-approve threshold configured stays
     pending (no-op gate is correct for "feature off" deployments
     per [[ibounce-honest-positioning]]).
  7. Web paste evaluator failure doesn't fail request creation
     (honest degradation per [[ibounce-honest-positioning]]).
  8. Sabotage check — monkeypatching the helper to a no-op makes
     test #1 fail. Proves the test is load-bearing on the real
     call path, not spuriously green from some other code path.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit import auto_approve_evaluator, settings_store

pytest_plugins = ["tests.conftest_routes"]


# ----- Settings fixtures -------------------------------------------------


@pytest.fixture
def auto_approve_enabled() -> None:
    """Configure deployment so low-risk requests auto-approve.

    `auto_approve_risk_below=5` is the platform floor (the deploy-time
    `max_auto_approve_risk_below`). Empty service blocklist so an s3
    read can clear all four gates. Quota of 100 so a multi-test run
    in the same process doesn't trip the per-hour cap.
    """
    settings_store.reset_default_store_for_tests()
    store = settings_store.get_default_store()
    store.put(
        settings_store.Settings(
            auto_approve_risk_below=5,
            auto_approve_quota_per_hour=100,
            never_auto_approve_services=(),
        ),
    )


@pytest.fixture
def auto_approve_disabled() -> None:
    """Configure deployment with auto-approve OFF — every request
    lands in pending regardless of score (the conservative default)."""
    settings_store.reset_default_store_for_tests()
    store = settings_store.get_default_store()
    store.put(
        settings_store.Settings(
            auto_approve_risk_below=None,
            never_auto_approve_services=(),
        ),
    )


# ----- Payload helpers ---------------------------------------------------


_LOW_RISK_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::example-config",
            }
        ],
    }
)


_HIGH_RISK_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*"],
                "Resource": "*",
            }
        ],
    }
)


def _paste_form_fields(*, policy_json: str) -> dict[str, str]:
    """Form fields for POST /requests/new/paste — mirrors the real
    HTML form. principal_arn is blank: handler infers from session
    per #594."""
    return {
        "description": "Read S3 config files for service X (web paste).",
        "policy": policy_json,
        "accounts": "060392206767",
        "duration_hours": "24",
        "access_type": "read-only",
        "assume_principal_arn": "",
        "assume_session_name": "",
        "ticket": "",
    }


def _api_submit_payload(*, policy_json: str) -> dict[str, Any]:
    """JSON body for POST /api/v1/requests — semantically equivalent
    to the web paste form so the two paths produce identical auto-
    approve trajectories (parity assertion)."""
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                "principal_arn": "arn:aws:iam::060392206767:user/dev@example.com",
            },
        },
        "spec": {
            "description": "Read S3 config files for service X.",
            "access_type": "read-only",
            "task_intent": {"services": ["s3"], "actions": ["read", "list"]},
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 24},
            "policy": json.loads(policy_json),
            "provisioning": {"mode": "identity_center"},
            "assume_by": {
                "principal_arn": "arn:aws:iam::060392206767:user/dev@example.com",
            },
        },
    }


def _fetch_request_via_api(client: TestClient, request_id: str) -> dict[str, Any]:
    """Pull the persisted request by id. Authenticated under the
    same fixture user (as_dev). Returns the stored dict."""
    r = client.get(f"/api/v1/requests/{request_id}")
    assert r.status_code == 200, (
        f"could not fetch persisted request {request_id}: {r.text}"
    )
    return r.json()


def _extract_request_id_from_paste_redirect(resp: Any) -> str:
    """The paste form's 303 redirects to /requests/<id> on success.
    Pull <id> from the Location header."""
    location = resp.headers.get("location", "")
    assert location.startswith("/requests/"), (
        f"expected /requests/<id> redirect; got {location!r}"
    )
    return location[len("/requests/"):]


# ----- Tests -------------------------------------------------------------


def test_web_paste_low_risk_auto_approves(
    as_dev: TestClient,
    auto_approve_enabled: None,
) -> None:
    """#598 core fix — POSTing the web paste form with a low-risk
    policy must transition the request out of `pending` via the
    auto-approve gate. The history entry MUST carry the
    `system:auto-approver` actor + the `auto_approve` action so the
    audit trail proves the gate fired.
    """
    resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(policy_json=_LOW_RISK_POLICY),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    request_id = _extract_request_id_from_paste_redirect(resp)

    # State verification: NOT pending. The auto-approve gate fires
    # synchronous provisioning, so the post-evaluator state is
    # `active` (stub-provisioning succeeded) — anything other than
    # `pending` proves the gate ran. Pre-#598 every web submit
    # landed at exactly `pending` regardless of score.
    req = _fetch_request_via_api(as_dev, request_id)
    state = (req.get("status") or {}).get("state")
    assert state != "pending", (
        "web paste submit landed in pending with low-risk policy + "
        f"auto-approve configured (this is the #598 silent gap); state={state!r}; "
        f"full status={req.get('status')!r}"
    )
    # History trail verification: an auto-approve history entry
    # exists with the system actor.
    history = (req.get("status") or {}).get("history") or []
    auto_entries = [h for h in history if h.get("action") == "auto_approve"]
    assert auto_entries, (
        "no auto_approve history entry — the gate didn't run or didn't "
        f"record. history={history!r}"
    )
    assert auto_entries[0].get("actor") == "system:auto-approver", (
        f"unexpected actor on auto_approve entry: {auto_entries[0]!r}"
    )


def test_api_submit_low_risk_auto_approves(
    as_dev: TestClient,
    auto_approve_enabled: None,
) -> None:
    """Regression check — the pre-existing API submit path must
    still auto-approve low-risk requests after #598 routed both
    paths through the shared helper."""
    resp = as_dev.post(
        "/api/v1/requests",
        json=_api_submit_payload(policy_json=_LOW_RISK_POLICY),
    )
    assert resp.status_code in (200, 201), resp.text
    body = resp.json()
    # The API returns the structured auto_approve_decision in the
    # response body — assert it fired.
    decision = body.get("auto_approve_decision")
    assert decision is not None, (
        f"API submit returned no auto_approve_decision; body={body!r}"
    )
    assert decision["auto_approve"] is True, (
        f"API submit didn't auto-approve a low-risk policy; decision={decision!r}"
    )
    # State verification: the persisted request is NOT in pending.
    req = body["request"]
    state = (req.get("status") or {}).get("state")
    assert state != "pending", (
        f"API auto-approve fired but state stayed pending; state={state!r}"
    )


def test_web_paste_and_api_post_identical_auto_approve_outcome(
    as_dev: TestClient,
    auto_approve_enabled: None,
) -> None:
    """Parity assertion — both paths produce identical auto-approve
    trajectories per [[cross-product-agent-parity]]. The history
    entry's actor + action must match exactly, and the post-
    evaluation state must match. This is the test that would have
    caught #598 at write-time: a difference between the two paths'
    history entries would surface immediately.
    """
    # API path first.
    api_resp = as_dev.post(
        "/api/v1/requests",
        json=_api_submit_payload(policy_json=_LOW_RISK_POLICY),
    )
    assert api_resp.status_code in (200, 201), api_resp.text
    api_body = api_resp.json()
    api_req = api_body["request"]
    api_state = (api_req.get("status") or {}).get("state")
    api_history = (api_req.get("status") or {}).get("history") or []
    api_auto = [h for h in api_history if h.get("action") == "auto_approve"]

    # Web paste second.
    web_resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(policy_json=_LOW_RISK_POLICY),
        follow_redirects=False,
    )
    assert web_resp.status_code == 303, web_resp.text
    web_request_id = _extract_request_id_from_paste_redirect(web_resp)
    web_req = _fetch_request_via_api(as_dev, web_request_id)
    web_state = (web_req.get("status") or {}).get("state")
    web_history = (web_req.get("status") or {}).get("history") or []
    web_auto = [h for h in web_history if h.get("action") == "auto_approve"]

    # Same post-evaluation state.
    assert api_state == web_state, (
        "API and web paths produced different post-auto-approve states — "
        f"[[cross-product-agent-parity]] violation. api={api_state!r} "
        f"web={web_state!r}"
    )
    # Each path produced exactly one auto_approve entry.
    assert len(api_auto) == 1 and len(web_auto) == 1, (
        f"unexpected auto_approve entry count; api={api_auto!r} web={web_auto!r}"
    )
    # Same actor (the audit trail proves the gate fired with the
    # same actor identity on both surfaces).
    assert api_auto[0].get("actor") == web_auto[0].get("actor"), (
        "auto_approve actor diverges between API and web paths — "
        f"[[cross-product-agent-parity]] violation. "
        f"api_actor={api_auto[0].get('actor')!r} web_actor={web_auto[0].get('actor')!r}"
    )
    # Same to_state on the transition entry.
    assert api_auto[0].get("to_state") == web_auto[0].get("to_state"), (
        f"to_state diverges; api={api_auto[0].get('to_state')!r} "
        f"web={web_auto[0].get('to_state')!r}"
    )


def test_web_paste_high_risk_stays_pending(
    as_dev: TestClient,
    auto_approve_enabled: None,
) -> None:
    """High-risk policy (s3:* on *) scores above the threshold; the
    request must land in pending awaiting a human approver. Verifies
    the evaluator runs but correctly DOESN'T fire for above-threshold
    requests."""
    resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(policy_json=_HIGH_RISK_POLICY),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    request_id = _extract_request_id_from_paste_redirect(resp)

    req = _fetch_request_via_api(as_dev, request_id)
    state = (req.get("status") or {}).get("state")
    assert state == "pending", (
        f"high-risk web paste should stay pending; state={state!r}"
    )
    history = (req.get("status") or {}).get("history") or []
    auto_entries = [h for h in history if h.get("action") == "auto_approve"]
    assert auto_entries == [], (
        f"high-risk request should NOT have auto_approve history entry; got {auto_entries!r}"
    )


def test_api_submit_high_risk_stays_pending(
    as_dev: TestClient,
    auto_approve_enabled: None,
) -> None:
    """Regression — API path also correctly stays pending on high-risk."""
    resp = as_dev.post(
        "/api/v1/requests",
        json=_api_submit_payload(policy_json=_HIGH_RISK_POLICY),
    )
    assert resp.status_code in (200, 201), resp.text
    body = resp.json()
    decision = body.get("auto_approve_decision")
    assert decision is not None
    assert decision["auto_approve"] is False, (
        f"API submit auto-approved a high-risk policy; decision={decision!r}"
    )
    req = body["request"]
    state = (req.get("status") or {}).get("state")
    assert state == "pending", f"high-risk API submit should stay pending; state={state!r}"


def test_web_paste_no_threshold_configured_stays_pending(
    as_dev: TestClient,
    auto_approve_disabled: None,
) -> None:
    """When auto-approve isn't configured (the conservative default),
    the gate is a no-op and every request lands in pending. This is
    the [[ibounce-honest-positioning]] discipline: a deployment that
    didn't ask for auto-approve must not get it implicitly."""
    resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(policy_json=_LOW_RISK_POLICY),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    request_id = _extract_request_id_from_paste_redirect(resp)
    req = _fetch_request_via_api(as_dev, request_id)
    state = (req.get("status") or {}).get("state")
    assert state == "pending", (
        f"no-threshold deployment should leave all requests pending; state={state!r}"
    )


def test_web_paste_evaluator_failure_doesnt_fail_request_creation(
    as_dev: TestClient,
    auto_approve_enabled: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Honest degradation per [[ibounce-honest-positioning]] — if the
    auto-approve evaluator raises for any reason, the request must
    still be created and persisted in pending. The operator's
    human-approval path is the fallback; iam-jit does NOT block
    request creation on an evaluator bug.
    """
    def _boom(**kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("simulated evaluator crash for honest-degradation test")

    monkeypatch.setattr(
        auto_approve_evaluator,
        "_evaluate_and_apply_inner",
        _boom,
    )

    resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(policy_json=_LOW_RISK_POLICY),
        follow_redirects=False,
    )
    # 303 redirect = request was successfully persisted despite the
    # evaluator crashing.
    assert resp.status_code == 303, resp.text
    request_id = _extract_request_id_from_paste_redirect(resp)
    # Verify the request actually landed in the store.
    req = _fetch_request_via_api(as_dev, request_id)
    state = (req.get("status") or {}).get("state")
    assert state == "pending", (
        "evaluator crash should leave request in pending (the human-"
        f"approval fallback); state={state!r}"
    )


# ----- Sabotage check ----------------------------------------------------


def test_sabotage_disabling_helper_makes_parity_test_fail(
    as_dev: TestClient,
    auto_approve_enabled: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage check — if we no-op the shared helper, the web
    paste-form path must NOT auto-approve a low-risk request. Proves
    `test_web_paste_low_risk_auto_approves` above is load-bearing on
    the real call path; without this sabotage, the test could be
    spuriously green if the helper were wired through some other
    channel we didn't realise.
    """
    monkeypatch.setattr(
        auto_approve_evaluator,
        "evaluate_and_apply_for_new_request",
        lambda **kwargs: {"auto_decision": None, "mfa_block_response": None},
    )
    resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(policy_json=_LOW_RISK_POLICY),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    request_id = _extract_request_id_from_paste_redirect(resp)
    req = _fetch_request_via_api(as_dev, request_id)
    state = (req.get("status") or {}).get("state")
    # The helper is no-op'd → the gate cannot fire → the request
    # MUST stay in pending. If state is anything else, the route
    # handler is reaching the auto-approve transition through some
    # path OTHER than the shared helper, and the parity test above
    # isn't actually load-bearing.
    assert state == "pending", (
        "the route handler is auto-approving through some path OTHER "
        "than auto_approve_evaluator.evaluate_and_apply_for_new_request "
        f"— the parity test above isn't actually load-bearing. state={state!r}"
    )
    history = (req.get("status") or {}).get("history") or []
    auto_entries = [h for h in history if h.get("action") == "auto_approve"]
    assert auto_entries == [], (
        f"sabotaged helper still produced auto_approve history entry: {auto_entries!r}"
    )
