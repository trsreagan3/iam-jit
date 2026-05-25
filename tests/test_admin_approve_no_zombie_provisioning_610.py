"""#610 CRIT — admin web approve must not leave a request in zombie
`provisioning` state.

Per UAT-Admin-Web 2026-05-25 (Gap UAT-WEB-ADMIN-01): admin approving
ANOTHER user's request via the web form whose `assume_principal_arn`
isn't an ARN (e.g. ``email:dev@example.com``) silently transitioned to
``provisioning`` and stayed there forever. The API approve path and the
admin-self-approve path both correctly transitioned to
``provisioning_failed`` — only the admin-approving-other-user web path
was the divergent twin.

State-verification tests per ``docs/CONTRIBUTING.md``: assert observable
state (request.status.state, status.provisioning_error, history
entries, audit log events) — never just the HTTP redirect status.

Sabotage-check: monkeypatch ``_attempt_provisioning_helper`` to be a
no-op and verify the primary test fails — proving the wired-in
provisioning call is load-bearing for the state transition.
"""

from __future__ import annotations

import datetime as _dt
import pathlib
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_jit import auth as auth_mod, lifecycle as lifecycle_mod
from iam_jit.accounts_store import Account, InMemoryAccountStore
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore


_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin
    roles: [admin]
  - id: email:approver@example.com
    display_name: Approver
    roles: [approver]
  - id: email:dev@example.com
    display_name: Dev
    roles: [requester]
"""

_DEV_SECRET = "test-secret-for-610-zombie-aaaaaaaaa"


@pytest.fixture
def env_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)
    # Reset module-level singletons that leak between tests.
    from iam_jit import (
        bans as _bans,
        cidr_store as _cidrs,
        llm_budget as _llmb,
        magic_link_nonces as _nonces,
        rate_limit as _rl,
        scoring_feedback as _fb,
        session_revocation as _sr,
        settings_store as _settings,
    )
    _rl.reset_default_limiter_for_tests()
    _bans.reset_default_store_for_tests()
    _nonces.reset_default_store_for_tests()
    _cidrs.reset_default_store_for_tests()
    _settings.reset_default_store_for_tests()
    _sr.reset_default_store_for_tests()
    _fb.reset_default_store_for_tests()
    _llmb.reset_default_store_for_tests()


@pytest.fixture
def app_with_registered_account(
    env_setup: None, tmp_path: pathlib.Path,
) -> Iterator[FastAPI]:
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    accounts = InMemoryAccountStore()
    accounts.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-060392206767",
            provisioning_mode="classic_iam",
            alias="dev-account",
        )
    )
    app = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
        accounts_store=accounts,
    )
    yield app


def _client(app: FastAPI, user_id: str | None = None) -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    if user_id:
        c.cookies.set("iam_jit_session", auth_mod.sign_session(_DEV_SECRET, user_id))
    return c


def _bad_principal_payload() -> dict:
    """Request whose assume_by.principal_arn fails ARN validation.

    `email:dev@example.com` is the canonical bug-trigger from the UAT
    report: it passes schema validation as a string but provisioning
    refuses it because it doesn't start with `arn:aws`.
    """
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                "principal_arn": "arn:aws:iam::060392206767:user/dev",
            }
        },
        "spec": {
            "description": "read s3 config (admin approve other user bug repro)",
            "access_type": "read-only",
            "task_intent": {"services": ["s3"], "actions": ["read"]},
            "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
            "duration": {"duration_hours": 24},
            "assume_by": {
                # The wedge: this is NOT an ARN. provision._validate_assumer_arn
                # raises AssumerPrincipalMissing on it.
                "principal_arn": "email:dev@example.com",
            },
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "arn:aws:s3:::example-config",
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
    }


# ---------------------------------------------------------------------
# Step 5 test 1: PRIMARY repro — admin approves OTHER user's request
# ---------------------------------------------------------------------

def test_admin_approve_other_user_with_blocking_issue_transitions_to_failed(
    app_with_registered_account: FastAPI,
) -> None:
    """Admin clicks Approve (with override) on dev's request whose
    assume_principal_arn isn't an ARN. Pre-fix the state silently became
    `provisioning` and stayed there. Post-fix it must transition to
    `provisioning_failed` synchronously."""
    app = app_with_registered_account
    dev = _client(app, "email:dev@example.com")
    admin = _client(app, "email:admin@example.com")

    rid = dev.post(
        "/api/v1/requests", json=_bad_principal_payload()
    ).json()["request"]["metadata"]["id"]

    # Admin posts via the WEB form (cookie session). The override
    # checkbox is set because the UAT scenario explicitly approves
    # despite the red warning.
    resp = admin.post(
        f"/requests/{rid}/approve",
        data={"override_blocking_issues": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    assert resp.headers["location"] == f"/requests/{rid}"

    # STATE VERIFICATION (per CONTRIBUTING.md): the request must NOT
    # be in zombie `provisioning`. The honest end-state is either
    # `provisioning_failed` (the AssumerPrincipalMissing error) or
    # `active` — never `provisioning`.
    store = app.state.request_store
    req = store.get(rid)
    final_state = req["status"]["state"]
    assert final_state == "provisioning_failed", (
        f"#610 regression: expected provisioning_failed, got "
        f"{final_state!r}. status={req['status']!r}"
    )
    # The error message must mention the bad ARN.
    err = req["status"].get("provisioning_error", "")
    assert err, "provisioning_error must be populated"
    # Match either the ARN validation message or the principal-missing
    # message — both are valid AssumerPrincipalMissing shapes.
    assert (
        "email:dev@example.com" in err
        or "principal" in err.lower()
        or "arn" in err.lower()
    ), f"unexpected provisioning_error: {err!r}"

    # History should contain BOTH the approve transition AND the
    # provisioning_failed transition.
    history = req["status"]["history"]
    actions = [ev.get("action") for ev in history if isinstance(ev, dict)]
    assert "approve" in actions, f"approve missing from history: {actions}"
    assert "provisioning_failed" in actions, (
        f"provisioning_failed missing from history (request stuck in "
        f"provisioning?): {actions}"
    )


# ---------------------------------------------------------------------
# Step 5 test 2: REGRESSION — admin-self-approve path still works
# ---------------------------------------------------------------------

def test_admin_self_approve_with_blocking_issue_still_transitions_to_failed(
    app_with_registered_account: FastAPI,
) -> None:
    """The API path was working before #610; make sure the fix didn't
    regress it. Admin submits own request via API, then API approves.

    Admin-self-approve isn't allowed at the lifecycle level (approvers
    can't approve their own), so we use the approver persona to approve
    admin's own submitted request via the API to verify the API path
    transitions correctly.
    """
    app = app_with_registered_account
    admin = _client(app, "email:admin@example.com")
    approver = _client(app, "email:approver@example.com")

    rid = admin.post(
        "/api/v1/requests", json=_bad_principal_payload()
    ).json()["request"]["metadata"]["id"]
    resp = approver.post(f"/api/v1/requests/{rid}/approve")
    assert resp.status_code == 200, resp.text
    body = resp.json()["request"]
    assert body["status"]["state"] == "provisioning_failed", body["status"]


# ---------------------------------------------------------------------
# Step 5 test 3: BLOCKING-ISSUE without override → form error
# ---------------------------------------------------------------------

def test_admin_approve_blocking_issue_without_override_returns_form_error(
    app_with_registered_account: FastAPI,
) -> None:
    """Admin clicks Approve WITHOUT checking the override box. The
    pre-approve gate refuses, the redirect carries the structured
    `approve_blocked` reason, and state stays `pending`."""
    app = app_with_registered_account
    dev = _client(app, "email:dev@example.com")
    admin = _client(app, "email:admin@example.com")

    rid = dev.post(
        "/api/v1/requests", json=_bad_principal_payload()
    ).json()["request"]["metadata"]["id"]

    resp = admin.post(
        f"/requests/{rid}/approve",
        data={},  # NO override
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    loc = resp.headers["location"]
    assert loc.startswith(f"/requests/{rid}"), loc
    assert "approve_blocked=would_fail_at_provisioning" in loc, (
        f"expected structured approve_blocked reason in redirect: {loc!r}"
    )
    assert "issues=" in loc, f"expected issues querystring: {loc!r}"

    # STATE VERIFICATION: still pending — the silent advance is the
    # exact bug shape we're closing.
    store = app.state.request_store
    req = store.get(rid)
    assert req["status"]["state"] == "pending", (
        f"approve without override must NOT advance state; got "
        f"{req['status']['state']!r}"
    )

    # Follow the redirect and verify the flash is rendered.
    detail = admin.get(loc)
    assert detail.status_code == 200
    assert "Approval blocked" in detail.text
    assert "Override blocking issues" in detail.text


# ---------------------------------------------------------------------
# Step 5 test 4: BLOCKING-ISSUE with override → proceeds to failed
# ---------------------------------------------------------------------

def test_admin_approve_blocking_issue_with_override_proceeds_to_failed(
    app_with_registered_account: FastAPI,
) -> None:
    """Same as test 1 but explicitly asserts that the override checkbox
    is what authorizes the proceed-to-provisioning_failed path."""
    app = app_with_registered_account
    dev = _client(app, "email:dev@example.com")
    admin = _client(app, "email:admin@example.com")

    rid = dev.post(
        "/api/v1/requests", json=_bad_principal_payload()
    ).json()["request"]["metadata"]["id"]

    resp = admin.post(
        f"/requests/{rid}/approve",
        data={"override_blocking_issues": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    store = app.state.request_store
    req = store.get(rid)
    # Operator explicitly opted in → state advances + lands honestly
    # in provisioning_failed.
    assert req["status"]["state"] == "provisioning_failed"


# ---------------------------------------------------------------------
# Step 5 test 5: Cancel allowed from `provisioning` state
# ---------------------------------------------------------------------

def test_cancel_allowed_from_provisioning_state(
    app_with_registered_account: FastAPI, tmp_path: pathlib.Path,
) -> None:
    """Recovery surface: owner can cancel a request stuck in
    `provisioning`. Pre-fix this raised IllegalTransition (action not
    allowed from state)."""
    app = app_with_registered_account
    dev = _client(app, "email:dev@example.com")

    rid = dev.post(
        "/api/v1/requests", json=_bad_principal_payload()
    ).json()["request"]["metadata"]["id"]

    # Directly wedge the state to `provisioning` (simulates a process
    # crash mid-flight between approve and the provisioning call).
    store = app.state.request_store
    req = store.get(rid)
    req["status"]["state"] = "provisioning"
    req["status"]["history"].append(
        {
            "action": "approve",
            "from": "pending",
            "to": "provisioning",
            "by": "email:approver@example.com",
            "at": "2026-05-25T00:00:00Z",
        }
    )
    store.put(rid, req)

    # Owner cancels.
    resp = dev.post(f"/api/v1/requests/{rid}/cancel")
    assert resp.status_code == 200, resp.text
    body = resp.json()["request"]
    assert body["status"]["state"] == "cancelled"


# ---------------------------------------------------------------------
# Step 5 test 6: provisioning_timeout watchdog
# ---------------------------------------------------------------------

def test_provisioning_timeout_watchdog_transitions_to_failed(
    app_with_registered_account: FastAPI,
) -> None:
    """Request stuck in `provisioning` for > 15 minutes is auto-
    transitioned to `provisioning_failed` by the sweep helper. Audit
    event ``request.provisioning_timeout`` is emitted."""
    from iam_jit._auto_approve_helpers import sweep_stuck_provisioning

    app = app_with_registered_account
    dev = _client(app, "email:dev@example.com")

    rid = dev.post(
        "/api/v1/requests", json=_bad_principal_payload()
    ).json()["request"]["metadata"]["id"]

    store = app.state.request_store
    req = store.get(rid)
    # Wedge to `provisioning` with an entry 30 minutes ago.
    stale_at = (
        _dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=30)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    req["status"]["state"] = "provisioning"
    req["status"]["last_updated_at"] = stale_at
    req["status"]["history"].append(
        {
            "action": "approve",
            "from": "pending",
            "to": "provisioning",
            "by": "email:approver@example.com",
            "at": stale_at,
        }
    )
    store.put(rid, req)

    swept = sweep_stuck_provisioning(
        store, lifecycle=lifecycle_mod, timeout_minutes=15,
    )
    assert len(swept) == 1
    assert swept[0]["request_id"] == rid
    assert swept[0]["new_state"] == "provisioning_failed"

    # STATE VERIFICATION: re-read from store, confirm transition.
    req_after = store.get(rid)
    assert req_after["status"]["state"] == "provisioning_failed"
    err = req_after["status"].get("provisioning_error", "")
    assert "provisioning_timeout" in err, (
        f"watchdog must record provisioning_timeout reason; got {err!r}"
    )


def test_provisioning_timeout_watchdog_leaves_fresh_provisioning_alone(
    app_with_registered_account: FastAPI,
) -> None:
    """Watchdog must NOT sweep requests that recently entered
    `provisioning` (the normal hot path). Otherwise it would race the
    synchronous provisioning call."""
    from iam_jit._auto_approve_helpers import sweep_stuck_provisioning

    app = app_with_registered_account
    dev = _client(app, "email:dev@example.com")

    rid = dev.post(
        "/api/v1/requests", json=_bad_principal_payload()
    ).json()["request"]["metadata"]["id"]

    store = app.state.request_store
    req = store.get(rid)
    fresh_at = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    req["status"]["state"] = "provisioning"
    req["status"]["last_updated_at"] = fresh_at
    req["status"]["history"].append(
        {
            "action": "approve",
            "from": "pending",
            "to": "provisioning",
            "by": "email:approver@example.com",
            "at": fresh_at,
        }
    )
    store.put(rid, req)

    swept = sweep_stuck_provisioning(
        store, lifecycle=lifecycle_mod, timeout_minutes=15,
    )
    assert swept == [], (
        f"watchdog must leave fresh provisioning requests alone; got {swept}"
    )
    req_after = store.get(rid)
    assert req_after["status"]["state"] == "provisioning"


# ---------------------------------------------------------------------
# Step 5 test 7: SABOTAGE CHECK
# ---------------------------------------------------------------------

def test_sabotage_check_attempt_provisioning_is_load_bearing(
    app_with_registered_account: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage: replace ``_attempt_provisioning_helper`` with a no-op
    that doesn't transition state. The primary test
    (`test_admin_approve_other_user_with_blocking_issue_transitions_to_failed`)
    must fail under this monkeypatch — proving the wired-in helper
    call is what makes the state transition honest.

    Per CONTRIBUTING.md (state-verification): tests should fail
    loudly if the load-bearing wire is severed.
    """
    app = app_with_registered_account
    dev = _client(app, "email:dev@example.com")
    admin = _client(app, "email:admin@example.com")

    # Replace the imported helper inside routes.web with a no-op.
    from iam_jit import _auto_approve_helpers as helpers_mod

    def _noop(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(
        helpers_mod, "attempt_provisioning", _noop,
    )
    monkeypatch.setattr(
        helpers_mod, "safe_mark_failed", _noop,
    )

    rid = dev.post(
        "/api/v1/requests", json=_bad_principal_payload()
    ).json()["request"]["metadata"]["id"]

    admin.post(
        f"/requests/{rid}/approve",
        data={"override_blocking_issues": "1"},
        follow_redirects=False,
    )

    store = app.state.request_store
    req = store.get(rid)
    # Under sabotage the state stays in `provisioning` — exactly the
    # zombie shape #610 closes. The primary test asserts
    # `provisioning_failed`; here we assert the negative to prove the
    # wire is load-bearing.
    assert req["status"]["state"] == "provisioning", (
        f"sabotage check: expected the no-op helper to leave state in "
        f"zombie 'provisioning' (proving the real helper is load-"
        f"bearing); got {req['status']['state']!r}"
    )
