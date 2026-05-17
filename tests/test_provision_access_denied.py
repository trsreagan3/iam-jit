"""Permission-loss handling: when the destination ProvisionerRole
no longer has the IAM permissions it needs, we surface a typed
`DestinationAccessDenied` error with the failing operation and
remediation pointer.

Moto doesn't enforce IAM authorization, so we simulate access-denial
with a fake IAM client that raises ClientError(AccessDenied)."""

from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from iam_jit import provision
from iam_jit.accounts_store import Account, InMemoryAccountStore


def _access_denied(op: str) -> ClientError:
    return ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": (
                    f"User: arn:aws:sts::060392206767:assumed-role/iam-jit-provisioner/x "
                    f"is not authorized to perform: {op} on resource: ..."
                ),
            }
        },
        op,
    )


class _FakeIAM:
    """Configurable IAM mock that raises AccessDenied on the operations
    we tell it to."""

    def __init__(self, *, deny: set[str]) -> None:
        self.deny = deny
        self.created_roles: dict[str, dict[str, Any]] = {}
        self.inline_policies: dict[str, dict[str, dict[str, Any]]] = {}

    def create_role(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:CreateRole" in self.deny or "CreateRole" in self.deny:
            raise _access_denied("iam:CreateRole")
        rn = kwargs["RoleName"]
        self.created_roles[rn] = kwargs
        return {"Role": {"RoleName": rn, "Arn": f"arn:aws:iam::060392206767:role/{rn}"}}

    def put_role_policy(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:PutRolePolicy" in self.deny or "PutRolePolicy" in self.deny:
            raise _access_denied("iam:PutRolePolicy")
        rn = kwargs["RoleName"]
        self.inline_policies.setdefault(rn, {})[kwargs["PolicyName"]] = kwargs
        return {}

    def list_role_policies(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:ListRolePolicies" in self.deny or "ListRolePolicies" in self.deny:
            raise _access_denied("iam:ListRolePolicies")
        rn = kwargs["RoleName"]
        return {"PolicyNames": list(self.inline_policies.get(rn, {}).keys())}

    def delete_role_policy(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:DeleteRolePolicy" in self.deny or "DeleteRolePolicy" in self.deny:
            raise _access_denied("iam:DeleteRolePolicy")
        rn = kwargs["RoleName"]
        self.inline_policies.setdefault(rn, {}).pop(kwargs["PolicyName"], None)
        return {}

    def delete_role(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:DeleteRole" in self.deny or "DeleteRole" in self.deny:
            raise _access_denied("iam:DeleteRole")
        self.created_roles.pop(kwargs["RoleName"], None)
        return {}


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


@pytest.fixture
def fake_sts() -> Any:
    class _STS:
        def assume_role(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Credentials": {
                    "AccessKeyId": "AK",
                    "SecretAccessKey": "SK",
                    "SessionToken": "ST",
                    "Expiration": "2099-01-01T00:00:00Z",
                }
            }

    return _STS()


def _request() -> dict[str, Any]:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": "rq-acc-001",
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                "principal_arn": "arn:aws:iam::060392206767:user/dev",
            },
        },
        "spec": {
            "description": "policy",
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
    }


def test_create_role_access_denied_raises_typed_error(
    store: InMemoryAccountStore, fake_sts: Any
) -> None:
    iam = _FakeIAM(deny={"iam:CreateRole"})
    with pytest.raises(provision.DestinationAccessDenied) as excinfo:
        provision.provision(
            _request(),
            accounts_store=store,
            sts_client=fake_sts,
            iam_client_factory=lambda creds: iam,
        )
    err = excinfo.value
    assert "iam:CreateRole" in err.operation or "CreateRole" in err.operation
    assert "redeploy" in str(err).lower() or "cloudformation" in str(err).lower()


def test_put_role_policy_access_denied_raises_typed_error(
    store: InMemoryAccountStore, fake_sts: Any
) -> None:
    iam = _FakeIAM(deny={"iam:PutRolePolicy"})
    with pytest.raises(provision.DestinationAccessDenied):
        provision.provision(
            _request(),
            accounts_store=store,
            sts_client=fake_sts,
            iam_client_factory=lambda creds: iam,
        )


def test_revoke_delete_role_access_denied_raises_typed_error(
    store: InMemoryAccountStore, fake_sts: Any
) -> None:
    # First create the role with full access.
    full = _FakeIAM(deny=set())
    req = _request()
    provision.provision(
        req,
        accounts_store=store,
        sts_client=fake_sts,
        iam_client_factory=lambda c: full,
    )
    # Mark as provisioned in the request envelope so revoke() finds it.
    req["status"] = {
        "state": "active",
        "provisioned": {
            "role_name": f"iam-jit-grant-{req['metadata']['id']}",
            "account_id": "060392206767",
            "role_arn": (
                f"arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-{req['metadata']['id']}"
            ),
        },
    }

    # Now flip the IAM client into "permission was revoked" mode for delete.
    denied = _FakeIAM(deny={"iam:DeleteRole"})
    # Pre-populate so list_role_policies and delete_role_policy succeed
    denied.created_roles[req["status"]["provisioned"]["role_name"]] = {}
    denied.inline_policies[req["status"]["provisioned"]["role_name"]] = {
        f"iam-jit-grant-{req['metadata']['id']}": {}
    }

    with pytest.raises(provision.DestinationAccessDenied) as excinfo:
        provision.revoke(
            req,
            accounts_store=store,
            sts_client=fake_sts,
            iam_client_factory=lambda c: denied,
        )
    assert "DeleteRole" in excinfo.value.operation


def test_revoke_list_policies_access_denied_raises_typed_error(
    store: InMemoryAccountStore, fake_sts: Any
) -> None:
    req = _request()
    req["status"] = {
        "state": "active",
        "provisioned": {
            "role_name": "iam-jit-grant-rq-acc-001",
            "account_id": "060392206767",
            "role_arn": "arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-rq-acc-001",
        },
    }
    denied = _FakeIAM(deny={"iam:ListRolePolicies"})
    with pytest.raises(provision.DestinationAccessDenied) as excinfo:
        provision.revoke(
            req,
            accounts_store=store,
            sts_client=fake_sts,
            iam_client_factory=lambda c: denied,
        )
    assert "ListRolePolicies" in excinfo.value.operation


def test_is_access_denied_detection_helpers() -> None:
    """`_is_access_denied` must recognize the common shapes."""
    assert provision._is_access_denied(_access_denied("iam:DeleteRole"))
    assert provision._is_access_denied(Exception("AccessDeniedException"))
    assert provision._is_access_denied(
        Exception("User: x is not authorized to perform: iam:CreateRole")
    )
    # Non-AccessDenied errors should NOT match.
    assert not provision._is_access_denied(Exception("NoSuchEntity"))
    assert not provision._is_access_denied(Exception("Throttling"))
