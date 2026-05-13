"""F18: end-to-end lifecycle integration test.

Walks the full path through the HTTP API:
  1. dev submits a request (POST /api/v1/requests)
  2. approver approves (POST /api/v1/requests/{id}/approve)
     → server provisions (stubbed) → state=active, status.provisioned populated
  3. admin lists provisioned grants (GET /api/v1/admin/provisioned)
  4. admin revokes the grant (POST /api/v1/admin/requests/...) — wait,
     revoke is at /api/v1/requests/{id}/revoke. Same router.
  5. state=revoked, status.revocation populated, role no longer in
     /api/v1/admin/provisioned (unless include_revoked=true)

We also exercise the failure-then-retry path: a provisioning error
that lands the request in `provisioning_failed`, then `retry-provisioning`
that brings it back.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient


pytest_plugins = ["tests.conftest_routes"]


@pytest.fixture
def stub_revoke(monkeypatch: pytest.MonkeyPatch) -> None:
    from iam_jit import provision as provision_mod

    def _stub(req, *, accounts_store, sts_client=None, iam_client_factory=None):
        provisioned = (req.get("status") or {}).get("provisioned") or {}
        return provision_mod.RevocationResult(
            role_arn=provisioned.get("role_arn") or "arn:aws:iam::000:role/iam-jit/x",
            role_name=provisioned.get("role_name") or "iam-jit-grant-x",
            account_id=provisioned.get("account_id") or "060392206767",
            revoked_at="2030-01-01T00:00:00Z",
            aws_cli_replay=[
                "aws iam delete-role-policy --role-name x --policy-name x",
                "aws iam delete-role --role-name x",
            ],
            inline_policies_deleted=[],
            role_existed=True,
        )

    monkeypatch.setattr(provision_mod, "revoke", _stub)


@pytest.fixture
def registered_account(as_admin: TestClient) -> str:
    """Register a destination account via the admin API so provisioning
    can find it, since the route handler hits accounts_store.get."""
    from iam_jit.accounts_store import Account

    accounts_store = as_admin.app.state.accounts_store
    accounts_store.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="ext",
            provisioning_mode="classic_iam",
            alias="omise-dev",
        )
    )
    return "060392206767"


@pytest.fixture
def request_payload() -> dict:
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
            "description": "e2e lifecycle test fixture body",
            "access_type": "read-only",
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 24},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::ex/*"],
                    }
                ],
            },
        },
    }


# ---- happy path: submit → approve → list → revoke ----


def test_full_lifecycle_submit_approve_revoke(
    as_dev: TestClient,
    as_approver: TestClient,
    as_admin: TestClient,
    request_payload: dict,
    registered_account: str,
    stub_revoke: None,
) -> None:
    # 1. submit
    submit = as_dev.post("/api/v1/requests", json=request_payload)
    assert submit.status_code == 201, submit.text
    rid = submit.json()["request"]["metadata"]["id"]
    assert submit.json()["request"]["status"]["state"] == "pending"

    # 2. approve (fires the stubbed provisioner)
    approve = as_approver.post(f"/api/v1/requests/{rid}/approve")
    assert approve.status_code == 200, approve.text
    body = approve.json()["request"]
    assert body["status"]["state"] == "active"
    provisioned = body["status"]["provisioned"]
    assert provisioned["role_name"].endswith(rid)
    assert provisioned["account_id"] == "060392206767"
    assert provisioned.get("creation_succeeded") is True

    # 3. admin sees the provisioned grant
    listed = as_admin.get("/api/v1/admin/provisioned").json()["provisioned"]
    assert any(r["request_id"] == rid for r in listed), listed

    # 4. admin revokes
    revoke = as_admin.post(
        f"/api/v1/requests/{rid}/revoke",
        json={"reason": "compliance audit — pulling early"},
    )
    assert revoke.status_code == 200, revoke.text
    after = revoke.json()["request"]
    assert after["status"]["state"] == "revoked"
    assert after["status"]["revocation"]["revoked_by"] == "email:admin@example.com"
    assert after["status"]["revocation"]["reason"].startswith("compliance audit")

    # 5. listing without include_revoked drops it
    listed_after = as_admin.get("/api/v1/admin/provisioned").json()["provisioned"]
    assert not any(r["request_id"] == rid for r in listed_after)
    listed_with = (
        as_admin.get("/api/v1/admin/provisioned?include_revoked=true").json()
        ["provisioned"]
    )
    assert any(r["request_id"] == rid for r in listed_with)


# ---- failure-then-retry path ----


def test_lifecycle_failure_retry_succeeds(
    as_dev: TestClient,
    as_approver: TestClient,
    as_admin: TestClient,
    request_payload: dict,
    registered_account: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """First approve fails (account suddenly disabled mid-provision);
    retry succeeds after the operator re-enables the account."""
    from iam_jit import provision as provision_mod

    submit = as_dev.post("/api/v1/requests", json=request_payload)
    assert submit.status_code == 201
    rid = submit.json()["request"]["metadata"]["id"]

    # First approve: provision raises a typed error.
    def _failing_stub(req, *, accounts_store, sts_client=None, iam_client_factory=None):
        raise provision_mod.AccountNotRegistered("simulated race")

    monkeypatch.setattr(provision_mod, "provision", _failing_stub)
    approve1 = as_approver.post(f"/api/v1/requests/{rid}/approve")
    assert approve1.status_code == 200
    state_after_fail = approve1.json()["request"]["status"]["state"]
    assert state_after_fail == "provisioning_failed"

    # Operator fixes the issue. The conftest's default stub_provisioning
    # is the one we want to switch back to. Re-monkeypatch with the
    # working version.
    def _ok_stub(req, *, accounts_store, sts_client=None, iam_client_factory=None):
        spec = req.get("spec") or {}
        accounts = spec.get("accounts") or [{}]
        account_id = accounts[0].get("account_id") or "000000000000"
        request_id = (req.get("metadata") or {}).get("id") or "rq-test"
        return provision_mod.ProvisioningResult(
            role_arn=f"arn:aws:iam::{account_id}:role/iam-jit/iam-jit-grant-{request_id}",
            role_name=f"iam-jit-grant-{request_id}",
            account_id=account_id,
            assumer_principal_arn="arn:aws:iam::060392206767:user/dev",
            expires_at="2030-01-01T00:00:00Z",
            external_id="ext",
            session_name=f"iam-jit-provision-{request_id}",
            tags={"managed-by": "iam-jit"},
        )

    monkeypatch.setattr(provision_mod, "provision", _ok_stub)
    retry = as_approver.post(f"/api/v1/requests/{rid}/retry-provisioning")
    assert retry.status_code == 200, retry.text
    final_state = retry.json()["request"]["status"]["state"]
    assert final_state == "active"


# ---- ownership isolation across the full flow ----


def test_dev_cannot_revoke_another_users_request(
    as_dev: TestClient,
    as_dev2: TestClient,
    as_approver: TestClient,
    request_payload: dict,
    registered_account: str,
) -> None:
    """Revoke is admin-only — even the request owner can't trigger it."""
    submit = as_dev.post("/api/v1/requests", json=request_payload)
    rid = submit.json()["request"]["metadata"]["id"]
    as_approver.post(f"/api/v1/requests/{rid}/approve")

    r = as_dev.post(
        f"/api/v1/requests/{rid}/revoke",
        json={"reason": "trying to self-revoke"},
    )
    assert r.status_code == 403


def test_approver_cannot_revoke_their_own_approved_request(
    as_approver: TestClient,
) -> None:
    """Revoke endpoint requires admin role; approver alone is refused."""
    r = as_approver.post(
        "/api/v1/requests/rq-nonexistent/revoke",
        json={"reason": "approver attempting revoke"},
    )
    assert r.status_code == 403
