"""Admin endpoints: /api/v1/admin/rediscover, /provisioned, /force-delete-role.

We mock out the rediscover module's reconcile() and force_delete_stale_role()
so these tests stay focused on the route layer (auth, payload validation,
audit emission, response shape). The rediscover module's internals are
covered in test_rediscover.py.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


# ---- /rediscover ----


def test_rediscover_requires_admin(
    as_dev: TestClient,
    as_approver: TestClient,
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iam_jit import rediscover

    def _stub(*args: Any, **kwargs: Any) -> rediscover.ReconciliationReport:
        return rediscover.ReconciliationReport(
            generated_at="2026-05-08T12:00:00Z", accounts=[]
        )

    monkeypatch.setattr(rediscover, "reconcile", _stub)

    assert as_dev.post("/api/v1/admin/rediscover").status_code == 403
    assert as_approver.post("/api/v1/admin/rediscover").status_code == 403
    assert as_admin.post("/api/v1/admin/rediscover").status_code == 200


def test_rediscover_returns_full_report_shape(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All buckets and the summary block must round-trip."""
    from iam_jit import rediscover

    def _stub(*args: Any, **kwargs: Any) -> rediscover.ReconciliationReport:
        return rediscover.ReconciliationReport(
            generated_at="2026-05-08T12:00:00Z",
            accounts=[
                rediscover.AccountReconciliation(
                    account_id="111111111111",
                    alias="acct-a",
                    success=True,
                    roles=[],
                ),
                rediscover.AccountReconciliation(
                    account_id="222222222222",
                    alias="acct-b",
                    success=False,
                    error="DestinationAccessDenied: iam:ListRoles",
                ),
            ],
            known=[{"request_id": "rq-1"}],
            stale=[{"request_id": "rq-2"}],
            orphans=[{"role_arn": "arn:aws:iam::333:role/x"}],
            zombies=[{"request_id": "rq-3"}],
            errors=[
                {
                    "account_id": "222222222222",
                    "error": "DestinationAccessDenied: iam:ListRoles",
                }
            ],
            inaccessible_accounts=[
                {
                    "account_id": "222222222222",
                    "error": "DestinationAccessDenied",
                    "remediation": "re-run /api/v1/admin/rediscover after access is restored",
                }
            ],
        )

    monkeypatch.setattr(rediscover, "reconcile", _stub)
    body = as_admin.post("/api/v1/admin/rediscover").json()

    assert body["summary"]["accounts_scanned"] == 2
    assert body["summary"]["accounts_failed"] == 1
    assert body["summary"]["incomplete"] is True
    assert "re-run" in body["summary"]["incomplete_reason"].lower()
    assert body["summary"]["known"] == 1
    assert body["summary"]["stale"] == 1
    assert body["summary"]["orphans"] == 1
    assert body["summary"]["zombies"] == 1
    # Inaccessible accounts surfaced for the admin notification UX.
    assert body["inaccessible_accounts"][0]["account_id"] == "222222222222"
    assert "remediation" in body["inaccessible_accounts"][0]


def test_rediscover_passes_deployment_filter(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ?deployment_filter=foo is set, the value reaches reconcile()."""
    from iam_jit import rediscover

    captured: dict[str, Any] = {}

    def _stub(*args: Any, **kwargs: Any) -> rediscover.ReconciliationReport:
        captured["deployment_filter"] = kwargs.get("deployment_filter")
        return rediscover.ReconciliationReport(
            generated_at="2026-05-08T12:00:00Z", accounts=[]
        )

    monkeypatch.setattr(rediscover, "reconcile", _stub)
    as_admin.post("/api/v1/admin/rediscover?deployment_filter=team-platform")
    assert captured["deployment_filter"] == "team-platform"


# ---- /provisioned ----


def test_provisioned_lists_roles_from_request_store(
    as_admin: TestClient, as_dev: TestClient, request_payload: dict
) -> None:
    """List shows requests that have status.provisioned populated."""
    rid = (
        as_dev.post("/api/v1/requests", json=request_payload)
        .json()["request"]["metadata"]["id"]
    )
    # Hand-edit the request to look provisioned (simulate post-approve state).
    store = as_admin.app.state.request_store
    req = store.get(rid)
    req["status"]["state"] = "active"
    req["status"]["provisioned"] = {
        "role_arn": "arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-" + rid,
        "role_name": "iam-jit-grant-" + rid,
        "account_id": "060392206767",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    store.put(rid, req)

    body = as_admin.get("/api/v1/admin/provisioned").json()
    rids = {r["request_id"] for r in body["provisioned"]}
    assert rid in rids


def test_provisioned_excludes_revoked_by_default(
    as_admin: TestClient, as_dev: TestClient, request_payload: dict
) -> None:
    rid = (
        as_dev.post("/api/v1/requests", json=request_payload)
        .json()["request"]["metadata"]["id"]
    )
    store = as_admin.app.state.request_store
    req = store.get(rid)
    req["status"]["state"] = "revoked"
    req["status"]["provisioned"] = {
        "role_arn": "arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-" + rid,
        "role_name": "iam-jit-grant-" + rid,
        "account_id": "060392206767",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    store.put(rid, req)

    body = as_admin.get("/api/v1/admin/provisioned").json()
    rids = {r["request_id"] for r in body["provisioned"]}
    assert rid not in rids

    # ?include_revoked=true brings them back.
    body2 = as_admin.get("/api/v1/admin/provisioned?include_revoked=true").json()
    rids2 = {r["request_id"] for r in body2["provisioned"]}
    assert rid in rids2


def test_provisioned_requires_admin(
    as_dev: TestClient, as_approver: TestClient
) -> None:
    assert as_dev.get("/api/v1/admin/provisioned").status_code == 403
    assert as_approver.get("/api/v1/admin/provisioned").status_code == 403


# ---- /force-delete-role ----


def _force_delete_payload(reason: str = "stuck cleanup sweep — testing") -> dict:
    return {
        "account_id": "060392206767",
        "role_name": "iam-jit-grant-rq-test",
        "role_arn": "arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-rq-test",
        "tags": {"managed-by": "iam-jit", "request-id": "rq-test"},
        "reason": reason,
    }


def test_force_delete_requires_admin(
    as_dev: TestClient, as_approver: TestClient
) -> None:
    pl = _force_delete_payload()
    assert as_dev.post("/api/v1/admin/force-delete-role", json=pl).status_code == 403
    assert (
        as_approver.post("/api/v1/admin/force-delete-role", json=pl).status_code == 403
    )


def test_force_delete_requires_reason(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    pl = _force_delete_payload()
    pl["reason"] = ""
    resp = as_admin.post("/api/v1/admin/force-delete-role", json=pl)
    assert resp.status_code == 400
    assert "reason" in resp.json()["detail"].lower()


def test_force_delete_requires_known_account(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    pl = _force_delete_payload()
    pl["account_id"] = "999999999999"  # not registered
    resp = as_admin.post("/api/v1/admin/force-delete-role", json=pl)
    assert resp.status_code == 404


def test_force_delete_safety_gate_returns_422(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A role with an iam-jit name but no managed-by tag → 422."""
    # Register the account so we get past the lookup.
    accounts_store = as_admin.app.state.accounts_store
    from iam_jit.accounts_store import Account

    accounts_store.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="ext",
            provisioning_mode="classic_iam",
            alias="omise-dev",
        )
    )
    pl = _force_delete_payload()
    pl["tags"] = {}  # missing managed-by tag
    resp = as_admin.post("/api/v1/admin/force-delete-role", json=pl)
    assert resp.status_code == 422
    assert "managed-by=iam-jit" in resp.json()["detail"]


def test_force_delete_safety_gate_rejects_wrong_arn_pattern(
    as_admin: TestClient,
) -> None:
    accounts_store = as_admin.app.state.accounts_store
    from iam_jit.accounts_store import Account

    accounts_store.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="ext",
            provisioning_mode="classic_iam",
            alias="omise-dev",
        )
    )
    pl = _force_delete_payload()
    pl["role_arn"] = "arn:aws:iam::060392206767:role/some-other-role"
    pl["role_name"] = "some-other-role"
    pl["tags"] = {"managed-by": "iam-jit"}  # tag right but name wrong
    resp = as_admin.post("/api/v1/admin/force-delete-role", json=pl)
    assert resp.status_code == 422


def test_force_delete_invokes_provision_revoke_when_safety_passes(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    accounts_store = as_admin.app.state.accounts_store
    from iam_jit.accounts_store import Account

    accounts_store.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="ext",
            provisioning_mode="classic_iam",
            alias="omise-dev",
        )
    )

    captured: dict[str, Any] = {}
    from iam_jit import rediscover

    def _stub(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {
            "role_arn": kwargs["role_arn"],
            "role_name": kwargs["role_name"],
            "deleted": True,
            "inline_deleted": ["iam-jit-grant-rq-test"],
            "aws_cli_replay": [
                "aws iam delete-role-policy --role-name iam-jit-grant-rq-test --policy-name iam-jit-grant-rq-test",
                "aws iam delete-role --role-name iam-jit-grant-rq-test",
            ],
        }

    monkeypatch.setattr(rediscover, "force_delete_stale_role", _stub)

    pl = _force_delete_payload()
    resp = as_admin.post("/api/v1/admin/force-delete-role", json=pl)
    assert resp.status_code == 200, resp.json()
    body = resp.json()
    assert body["result"]["deleted"] is True
    assert body["actor"] == "email:admin@example.com"
    assert body["reason"] == pl["reason"]
    # Audit invariant: the rediscover layer received the gate-validated payload.
    assert captured["role_arn"] == pl["role_arn"]


# ---- Test fixtures ----


@pytest.fixture
def request_payload() -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
        "spec": {
            "description": "rediscovery fixture request for testing",
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
