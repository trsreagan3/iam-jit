"""Tests for `provision.revoke()` — admin-driven role teardown.

The revoke path mirrors provision(): assume the destination's
ProvisionerRole, then issue IAM API calls. We exercise it against moto
so the boto3 surface (paginators, exception classes) is real.

Coverage:
- happy path: role + inline policy actually disappear from moto
- idempotency: calling revoke twice is fine, second call reports
  role_existed=False
- already-deleted: external manual delete races us — same idempotency
- account-no-longer-registered: surfaces as AccountNotRegistered
- request-was-never-provisioned: ProvisioningError instead of crash
- aws_cli_replay matches what we executed
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

from iam_jit import provision
from iam_jit.accounts_store import (
    Account,
    InMemoryAccountStore,
)


@pytest.fixture
def moto_sts_iam(mock_aws_env: None) -> Iterator[Any]:
    from moto import mock_aws

    with mock_aws():
        import boto3

        sts = boto3.client("sts", region_name="us-east-1")

        def factory(creds: dict[str, str]) -> Any:
            return boto3.client("iam", region_name="us-east-1")

        yield sts, factory


@pytest.fixture
def store() -> InMemoryAccountStore:
    s = InMemoryAccountStore()
    s.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-060392206767",
            provisioning_mode="classic_iam",
            alias="dev-account",
        )
    )
    return s


def _request_with_provisioned(rid: str) -> dict[str, Any]:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": rid,
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                "principal_arn": "arn:aws:iam::060392206767:user/dev",
            },
        },
        "spec": {
            "description": "read s3 config files",
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
            "provisioning": {"mode": "classic_iam"},
        },
        "status": {
            "state": "active",
            "history": [],
        },
    }


def _provision_then_attach_to_request(
    req: dict[str, Any], moto_pair, account_store
) -> provision.ProvisioningResult:
    sts, factory = moto_pair
    result = provision.provision(
        req, accounts_store=account_store, sts_client=sts, iam_client_factory=factory
    )
    req["status"]["provisioned"] = {
        "role_arn": result.role_arn,
        "role_name": result.role_name,
        "account_id": result.account_id,
    }
    return result


# ---- happy path ----


def test_revoke_deletes_role_and_inline_policies(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    req = _request_with_provisioned("rq-rev-001")
    result = _provision_then_attach_to_request(req, moto_sts_iam, store)

    sts, factory = moto_sts_iam
    iam = factory({})
    # Sanity: role exists before revoke.
    iam.get_role(RoleName=result.role_name)

    rev = provision.revoke(
        req, accounts_store=store, sts_client=sts, iam_client_factory=factory
    )
    assert rev.role_name == result.role_name
    assert rev.account_id == "060392206767"
    assert rev.role_existed is True
    assert "iam-jit-grant-rq-rev-001" in rev.inline_policies_deleted

    # Role no longer exists.
    from botocore.exceptions import ClientError

    with pytest.raises(ClientError) as excinfo:
        iam.get_role(RoleName=result.role_name)
    assert "NoSuchEntity" in str(excinfo.value)


def test_revoke_aws_cli_replay_describes_what_we_did(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    req = _request_with_provisioned("rq-rev-cli")
    _provision_then_attach_to_request(req, moto_sts_iam, store)

    sts, factory = moto_sts_iam
    rev = provision.revoke(
        req, accounts_store=store, sts_client=sts, iam_client_factory=factory
    )
    # First the inline policies, then the role itself.
    assert any("delete-role-policy" in cmd for cmd in rev.aws_cli_replay)
    assert any(
        "delete-role" in cmd and "delete-role-policy" not in cmd
        for cmd in rev.aws_cli_replay
    )
    # delete-role must come last (otherwise IAM would refuse — role still
    # has attached policies).
    assert "delete-role" in rev.aws_cli_replay[-1]
    assert "delete-role-policy" not in rev.aws_cli_replay[-1]


# ---- idempotency / race conditions ----


def test_revoke_twice_is_idempotent(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    req = _request_with_provisioned("rq-rev-idem")
    _provision_then_attach_to_request(req, moto_sts_iam, store)

    sts, factory = moto_sts_iam
    first = provision.revoke(
        req, accounts_store=store, sts_client=sts, iam_client_factory=factory
    )
    assert first.role_existed is True

    # Second call: role is already gone, must not raise.
    second = provision.revoke(
        req, accounts_store=store, sts_client=sts, iam_client_factory=factory
    )
    assert second.role_existed is False
    assert second.inline_policies_deleted == []


def test_revoke_after_external_manual_delete(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    """If an admin nukes the role manually in the AWS console, our
    revoke path must still succeed gracefully — we report
    role_existed=False and don't blow up."""
    req = _request_with_provisioned("rq-rev-ext")
    result = _provision_then_attach_to_request(req, moto_sts_iam, store)

    sts, factory = moto_sts_iam
    iam = factory({})
    # Manually delete: simulate AWS console action.
    iam.delete_role_policy(
        RoleName=result.role_name, PolicyName=f"iam-jit-grant-rq-rev-ext"
    )
    iam.delete_role(RoleName=result.role_name)

    rev = provision.revoke(
        req, accounts_store=store, sts_client=sts, iam_client_factory=factory
    )
    assert rev.role_existed is False


# ---- error paths ----


def test_revoke_request_with_no_provisioned_block_raises(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    req = _request_with_provisioned("rq-rev-noprov")
    req["status"].pop("provisioned", None)

    sts, factory = moto_sts_iam
    with pytest.raises(provision.ProvisioningError):
        provision.revoke(
            req, accounts_store=store, sts_client=sts, iam_client_factory=factory
        )


def test_revoke_for_unregistered_account_raises_account_not_registered(
    moto_sts_iam,
) -> None:
    """If an admin de-registered the destination account between
    provisioning and revocation, we surface AccountNotRegistered so the
    caller can present a useful error rather than 'STS denied'."""
    empty_store = InMemoryAccountStore()
    req = _request_with_provisioned("rq-rev-noacc")
    req["status"]["provisioned"] = {
        "role_arn": "arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-rq-rev-noacc",
        "role_name": "iam-jit-grant-rq-rev-noacc",
        "account_id": "060392206767",
    }

    sts, factory = moto_sts_iam
    with pytest.raises(provision.AccountNotRegistered):
        provision.revoke(
            req, accounts_store=empty_store, sts_client=sts, iam_client_factory=factory
        )


def test_revoke_request_with_missing_id_raises(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    req = _request_with_provisioned("rq-rev-x")
    req["metadata"].pop("id")
    sts, factory = moto_sts_iam
    with pytest.raises(provision.ProvisioningError):
        provision.revoke(
            req, accounts_store=store, sts_client=sts, iam_client_factory=factory
        )
