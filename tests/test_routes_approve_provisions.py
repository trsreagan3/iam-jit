"""End-to-end approve→provision→active route test against moto.

The other route tests stub provision.provision() to keep things fast.
This test exercises the real wiring with moto-backed STS + IAM so we
catch any breakage in the integration path between the lifecycle
machinery and the provision module.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_jit import auth as auth_mod
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

_DEV_SECRET = "test-secret-for-route-tests-aaaaaaaaa"


@pytest.fixture
def real_provision_env(
    monkeypatch: pytest.MonkeyPatch, mock_aws_env: None
) -> Iterator[None]:
    """Set up env so the iam-jit app uses real (moto-backed) provisioning.

    This fixture deliberately does NOT stub provision.provision — we
    want the actual code path. moto provides STS + IAM emulation.
    """
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)
    yield


@pytest.fixture
def app_with_registered_account(
    real_provision_env: None,
    tmp_path: pathlib.Path,
) -> Iterator[FastAPI]:
    from moto import mock_aws

    with mock_aws():
        users_yaml = tmp_path / "users.yaml"
        users_yaml.write_text(_USERS_YAML)
        accounts = InMemoryAccountStore()
        accounts.put(
            Account(
                account_id="060392206767",
                provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
                provisioner_external_id="iam-jit-060392206767",
                provisioning_mode="classic_iam",
                alias="omise-dev",
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
    c = TestClient(app)
    if user_id:
        c.cookies.set("iam_jit_session", auth_mod.sign_session(_DEV_SECRET, user_id))
    return c


def _payload() -> dict:
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
            "description": "read s3 config files in account 060392206767",
            "access_type": "read-only",
            "task_intent": {"services": ["s3"], "actions": ["read", "list"]},
            "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
            "duration": {"duration_hours": 24},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": "arn:aws:s3:::example-config",
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
    }


def test_approve_runs_real_provision_against_moto(
    app_with_registered_account: FastAPI,
) -> None:
    app = app_with_registered_account
    dev = _client(app, "email:dev@example.com")
    approver = _client(app, "email:approver@example.com")

    rid = dev.post("/api/v1/requests", json=_payload()).json()["request"]["metadata"]["id"]
    resp = approver.post(f"/api/v1/requests/{rid}/approve")
    assert resp.status_code == 200, resp.text
    body = resp.json()["request"]
    assert body["status"]["state"] == "active", body["status"]
    p = body["status"]["provisioned"]
    assert p["role_arn"].endswith(f"/iam-jit-grant-{rid}")
    assert p["account_id"] == "060392206767"
    assert p["external_id"] == "iam-jit-060392206767"
    assert "assume_instructions" in p
    assert "aws sts assume-role" in p["assume_instructions"]["cli_assume_role"]
    assert "agent_usage_hints" in p["assume_instructions"]


def test_retry_provisioning_after_account_gets_registered(
    real_provision_env: None,
    tmp_path: pathlib.Path,
) -> None:
    """Realistic recovery path: approver hits approve, provisioning
    fails because the destination account isn't registered yet, admin
    registers it, approver clicks 'Retry provisioning' → role gets
    created."""
    from moto import mock_aws

    with mock_aws():
        users_yaml = tmp_path / "users.yaml"
        users_yaml.write_text(_USERS_YAML)
        # Start with an empty account registry — the first approve will fail.
        accounts = InMemoryAccountStore()
        app = create_app(
            request_store=FilesystemStore(tmp_path / "requests"),
            user_store=FileUserStore(str(users_yaml)),
            api_tokens_store=InMemoryAPITokenStore(),
            accounts_store=accounts,
        )
        dev = _client(app, "email:dev@example.com")
        approver = _client(app, "email:approver@example.com")

        rid = dev.post("/api/v1/requests", json=_payload()).json()["request"]["metadata"]["id"]
        first = approver.post(f"/api/v1/requests/{rid}/approve")
        assert first.status_code == 200, first.text
        assert first.json()["request"]["status"]["state"] == "provisioning_failed"

        # Admin registers the account.
        accounts.put(
            Account(
                account_id="060392206767",
                provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
                provisioner_external_id="iam-jit-060392206767",
                provisioning_mode="classic_iam",
            )
        )

        # Approver retries.
        retry = approver.post(f"/api/v1/requests/{rid}/retry-provisioning")
        assert retry.status_code == 200, retry.text
        body = retry.json()["request"]
        assert body["status"]["state"] == "active"
        assert body["status"]["provisioned"]["role_arn"].endswith(f"/iam-jit-grant-{rid}")


def test_approve_with_unregistered_account_lands_in_provisioning_failed(
    real_provision_env: None,
    tmp_path: pathlib.Path,
) -> None:
    """If the spec's account isn't in the registry, provisioning fails
    cleanly and the request is flagged for retry — the API doesn't 500."""
    from moto import mock_aws

    with mock_aws():
        users_yaml = tmp_path / "users.yaml"
        users_yaml.write_text(_USERS_YAML)
        # Empty accounts store — no destination is registered.
        app = create_app(
            request_store=FilesystemStore(tmp_path / "requests"),
            user_store=FileUserStore(str(users_yaml)),
            api_tokens_store=InMemoryAPITokenStore(),
            accounts_store=InMemoryAccountStore(),
        )
        dev = _client(app, "email:dev@example.com")
        approver = _client(app, "email:approver@example.com")

        rid = dev.post("/api/v1/requests", json=_payload()).json()["request"]["metadata"]["id"]
        resp = approver.post(f"/api/v1/requests/{rid}/approve")
        assert resp.status_code == 200, resp.text
        body = resp.json()["request"]
        assert body["status"]["state"] == "provisioning_failed"
        err = body["status"].get("provisioning_error", "")
        assert "060392206767" in err
        assert "not registered" in err.lower()
