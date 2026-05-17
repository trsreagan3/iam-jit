"""F17: admin web views for /provisioned and /rediscover."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient


pytest_plugins = ["tests.conftest_routes"]


def test_admin_provisioned_page_lists_active_grants(
    as_admin: TestClient, as_dev: TestClient, request_payload: dict
) -> None:
    rid = (
        as_dev.post("/api/v1/requests", json=request_payload)
        .json()["request"]["metadata"]["id"]
    )
    store = as_admin.app.state.request_store
    req = store.get(rid)
    req["status"]["state"] = "active"
    req["status"]["provisioned"] = {
        "role_arn": f"arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-{rid}",
        "role_name": f"iam-jit-grant-{rid}",
        "account_id": "060392206767",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    store.put(rid, req)

    body = as_admin.get("/admin/provisioned").text
    assert rid in body
    assert "iam-jit-grant-" in body


def test_admin_provisioned_excludes_revoked_by_default(
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
        "role_arn": f"arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-{rid}",
        "role_name": f"iam-jit-grant-{rid}",
        "account_id": "060392206767",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    store.put(rid, req)
    body = as_admin.get("/admin/provisioned").text
    assert rid not in body
    body_with = as_admin.get("/admin/provisioned?include_revoked=1").text
    assert rid in body_with


def test_admin_provisioned_requires_admin(
    as_dev: TestClient, as_approver: TestClient
) -> None:
    assert as_dev.get("/admin/provisioned").status_code == 403
    assert as_approver.get("/admin/provisioned").status_code == 403


def test_admin_rediscover_get_renders_form(as_admin: TestClient) -> None:
    body = as_admin.get("/admin/rediscover").text
    assert "Cross-account rediscover" in body
    assert "<form" in body


def test_admin_rediscover_post_renders_report(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from iam_jit import rediscover

    def _stub(**kwargs: Any) -> rediscover.ReconciliationReport:
        return rediscover.ReconciliationReport(
            generated_at="2026-05-08T12:00:00Z",
            accounts=[
                rediscover.AccountReconciliation(
                    account_id="060392206767",
                    alias="dev-account",
                    success=True,
                )
            ],
            known=[{"request_id": "rq-known-1"}],
            stale=[],
            orphans=[],
            zombies=[],
            errors=[],
            inaccessible_accounts=[],
        )

    monkeypatch.setattr(rediscover, "reconcile", _stub)
    body = as_admin.post(
        "/admin/rediscover", data={"deployment_filter": "default"}
    ).text
    assert "rq-known-1" in body
    assert "Generated at" in body


def test_admin_rediscover_requires_admin(
    as_dev: TestClient, as_approver: TestClient
) -> None:
    assert as_dev.get("/admin/rediscover").status_code == 403
    assert as_approver.get("/admin/rediscover").status_code == 403


@pytest.fixture
def request_payload() -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
        "spec": {
            "description": "admin web view fixture body",
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
