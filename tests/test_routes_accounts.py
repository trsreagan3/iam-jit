"""Account routes — onboarding preview, register, list, deregister."""

from __future__ import annotations

from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


# ---- Onboarding preview ----


def test_preview_requires_admin(as_dev: TestClient) -> None:
    r = as_dev.post(
        "/api/v1/accounts/onboarding/preview",
        json={"account_id": "123456789012"},
    )
    assert r.status_code == 403


def test_preview_returns_full_plan(as_admin: TestClient) -> None:
    r = as_admin.post(
        "/api/v1/accounts/onboarding/preview",
        json={
            "account_id": "123456789012",
            "hub_account_id": "999988887777",
            "region": "us-east-1",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["account_id"] == "123456789012"
    assert body["expected"]["provisioner_role_arn"].startswith("arn:aws:iam::")
    assert "AWSTemplateFormatVersion" in body["artifacts"]["cloudformation_template"]
    assert "aws cloudformation deploy" in body["artifacts"]["cli_commands"]


def test_preview_validates_account_id(as_admin: TestClient) -> None:
    r = as_admin.post(
        "/api/v1/accounts/onboarding/preview",
        json={"account_id": "abc", "hub_account_id": "999988887777"},
    )
    assert r.status_code == 422  # pydantic regex


# ---- Register / list / get / delete ----


def _payload(account_id: str = "123456789012", **overrides) -> dict:
    base = {
        "account_id": account_id,
        "provisioner_role_arn": f"arn:aws:iam::{account_id}:role/iam-jit-provisioner",
        "provisioner_external_id": f"iam-jit-{account_id}",
        "provisioning_mode": "classic_iam",
        "alias": "alpha",
        "regions": ["us-east-1"],
    }
    base.update(overrides)
    return base


def test_register_requires_admin(as_dev: TestClient) -> None:
    r = as_dev.post("/api/v1/accounts", json=_payload())
    assert r.status_code == 403


def test_register_then_list(as_admin: TestClient) -> None:
    r = as_admin.post("/api/v1/accounts", json=_payload())
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["account_id"] == "123456789012"
    assert body["registered_by"] == "email:admin@example.com"
    listed = as_admin.get("/api/v1/accounts").json()
    assert listed["count"] == 1
    assert listed["accounts"][0]["account_id"] == "123456789012"


def test_register_duplicate_returns_409(as_admin: TestClient) -> None:
    as_admin.post("/api/v1/accounts", json=_payload())
    r = as_admin.post("/api/v1/accounts", json=_payload())
    assert r.status_code == 409


def test_get_account_404_when_unknown(as_admin: TestClient) -> None:
    r = as_admin.get("/api/v1/accounts/000000000000")
    assert r.status_code == 404


def test_deregister(as_admin: TestClient) -> None:
    as_admin.post("/api/v1/accounts", json=_payload())
    r = as_admin.delete("/api/v1/accounts/123456789012")
    assert r.status_code == 200
    assert r.json()["deregistered"] is True
    assert as_admin.get("/api/v1/accounts").json()["count"] == 0


def test_deregister_unknown_404(as_admin: TestClient) -> None:
    r = as_admin.delete("/api/v1/accounts/000000000000")
    assert r.status_code == 404


def test_list_requires_admin(as_dev: TestClient) -> None:
    r = as_dev.get("/api/v1/accounts")
    assert r.status_code == 403


# ---- Web UI ----


def test_web_accounts_page_requires_admin(as_dev: TestClient) -> None:
    r = as_dev.get("/accounts", follow_redirects=False)
    assert r.status_code == 403


def test_web_accounts_page_renders_for_admin(as_admin: TestClient) -> None:
    r = as_admin.get("/accounts")
    assert r.status_code == 200
    assert "Destination accounts" in r.text


def test_web_new_account_form_renders(as_admin: TestClient) -> None:
    r = as_admin.get("/accounts/new")
    assert r.status_code == 200
    assert "Add a destination account" in r.text


def test_web_new_account_post_renders_plan(as_admin: TestClient) -> None:
    r = as_admin.post(
        "/accounts/new",
        data={
            "account_id": "123456789012",
            "region": "us-east-1",
            "account_alias": "alpha",
            "hub_account_id": "999988887777",
            "provisioning_mode": "classic_iam",
            "enable_discovery": "1",
        },
    )
    assert r.status_code == 200
    assert "Onboarding plan for account 123456789012" in r.text
    assert "aws cloudformation deploy" in r.text


def test_web_register_then_redirects_to_detail(as_admin: TestClient) -> None:
    r = as_admin.post(
        "/accounts/register",
        data={
            "account_id": "123456789012",
            "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
            "provisioner_external_id": "iam-jit-123456789012",
            "provisioning_mode": "classic_iam",
            "region": "us-east-1",
            "alias": "alpha",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/accounts/123456789012"
    detail = as_admin.get("/accounts/123456789012")
    assert detail.status_code == 200
    assert "Account 123456789012" in detail.text
