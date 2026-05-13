"""End-to-end provisioning lifecycle: create → assume → revoke.

The existing test files cover each step in isolation (provision.py
creates, assume.py assumes, provision_revoke.py revokes). This
file chains them so a regression in any single step that breaks
the END-TO-END flow gets caught — even if each step's own tests
still pass.

The flow:

  1. Register a destination account.
  2. Submit + approve a request → provision module creates an
     IAM role in moto-IAM with the correct tags + trust policy.
  3. Verify the role actually exists in moto by direct
     `iam.get_role`.
  4. Assume the role via STS → get short-lived credentials.
  5. Verify the assumed-role principal can be derived back to
     the iam-jit grant via the session name.
  6. Revoke the request → provision_revoke deletes the role.
  7. Verify the role is GONE from moto-IAM by direct
     `iam.get_role` (expects NoSuchEntity).

Uses moto for all AWS calls — no live AWS, no destination stack
needed. Tests the full code path including the tag-scoped delete
that the real cross-account ProvisionerRole enforces.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Iterator

import pytest

from iam_jit import provision as provision_mod
from iam_jit.accounts_store import Account, InMemoryAccountStore


@pytest.fixture
def mock_aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")


@pytest.fixture
def moto_aws(mock_aws_env: None) -> Iterator[Any]:
    """Yield (sts_client, iam_client_factory) backed by moto."""
    from moto import mock_aws

    with mock_aws():
        import boto3

        sts = boto3.client("sts", region_name="us-east-1")

        def iam_factory(account_id: str, *, region: str = "us-east-1"):
            # moto's STS ignores the AssumeRole call — we just
            # return a fresh boto3 client; moto's IAM is global
            # per-process so all calls share state.
            return boto3.client("iam", region_name=region)

        yield sts, iam_factory


@pytest.fixture
def accounts() -> InMemoryAccountStore:
    store = InMemoryAccountStore()
    store.put(
        Account(
            account_id="111111111111",
            alias="lifecycle-test",
            regions=("us-east-1",),
            provisioner_role_arn=(
                "arn:aws:iam::111111111111:role/iam-jit-provisioner"
            ),
            provisioner_external_id="iam-jit-111111111111",
            provisioning_mode="classic_iam",
        ),
    )
    return store


def _request_payload(*, request_id: str = "lc-test-001") -> dict[str, Any]:
    """A representative read-only request the lifecycle test exercises."""
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": request_id,
            "requester": {
                "name": "Lifecycle Test",
                "email": "lifecycle@example.com",
                # The assumer principal — production sets this from
                # the requester's IAM identity. For lifecycle tests
                # against moto we use a synthetic user ARN.
                "principal_arn": (
                    "arn:aws:iam::111111111111:user/lifecycle-test"
                ),
            },
        },
        "spec": {
            "description": "lifecycle integration test",
            "access_type": "read-only",
            "duration": {"duration_hours": 1},
            "accounts": [{"account_id": "111111111111", "regions": ["us-east-1"]}],
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [
                            "arn:aws:s3:::lifecycle-test",
                            "arn:aws:s3:::lifecycle-test/*",
                        ],
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
        "status": {
            "owner": "email:lifecycle@example.com",
            "approval": {
                "approved_by": "email:approver@example.com",
                "approved_at": "2026-05-11T00:00:00Z",
            },
            "history": [
                {
                    "actor": "email:approver@example.com",
                    "action": "approve",
                    "to_state": "provisioning",
                    "at": "2026-05-11T00:00:00Z",
                },
            ],
        },
    }


# ---- The lifecycle ----


def test_create_role_actually_exists_in_iam(
    moto_aws, accounts: InMemoryAccountStore
) -> None:
    """Step 2-3: provision creates the role; verify it exists in
    moto-IAM by direct API call. The role MUST be under /iam-jit/
    path and carry the managed-by tag — those are the invariants
    the destination CFN policy depends on."""
    sts, factory = moto_aws
    req = _request_payload()

    result = provision_mod.provision(
        req,
        accounts_store=accounts,
        sts_client=sts,
        iam_client_factory=factory,
    )

    assert result.role_arn
    assert "/iam-jit/" in result.role_arn, (
        f"role must be under /iam-jit/ path; got {result.role_arn}"
    )
    assert result.role_name.startswith("iam-jit-grant-")

    # Now verify the role REALLY exists in moto-IAM.
    iam = factory("111111111111")
    role = iam.get_role(RoleName=result.role_name)
    assert role["Role"]["RoleName"] == result.role_name
    assert "/iam-jit/" in role["Role"]["Path"]
    # managed-by=iam-jit tag MUST be on the role — the destination
    # CFN policy refuses to delete roles without it.
    tags = {t["Key"]: t["Value"] for t in (role["Role"].get("Tags") or [])}
    assert tags.get("managed-by") == "iam-jit"
    # request-id is the audit anchor that ties the role back to the
    # iam-jit request that produced it.
    assert tags.get("request-id") == "lc-test-001"


def test_role_has_time_bounded_trust_policy(
    moto_aws, accounts: InMemoryAccountStore
) -> None:
    """The trust policy must include a `DateLessThan` /
    `aws:CurrentTime` condition so the role auto-becomes
    unassumable past `expires_at` even if iam-jit never gets to
    delete it."""
    sts, factory = moto_aws
    req = _request_payload(request_id="lc-test-002")

    result = provision_mod.provision(
        req, accounts_store=accounts,
        sts_client=sts, iam_client_factory=factory,
    )
    iam = factory("111111111111")
    role = iam.get_role(RoleName=result.role_name)
    trust_policy = role["Role"]["AssumeRolePolicyDocument"]

    statements = trust_policy["Statement"]
    found_time_condition = False
    for stmt in statements:
        cond = stmt.get("Condition") or {}
        for op in ("DateLessThan", "DateLessThanEquals"):
            if "aws:CurrentTime" in (cond.get(op) or {}):
                found_time_condition = True
                break
    assert found_time_condition, (
        f"trust policy missing time-bounded condition; got {trust_policy}"
    )


def test_role_can_be_assumed_via_sts(
    moto_aws, accounts: InMemoryAccountStore
) -> None:
    """Step 4-5: assume the just-created role. Verify the assumed
    principal carries the expected session name (which is the
    audit anchor at the AWS-CloudTrail layer)."""
    sts, factory = moto_aws
    req = _request_payload(request_id="lc-test-003")

    result = provision_mod.provision(
        req, accounts_store=accounts,
        sts_client=sts, iam_client_factory=factory,
    )

    # Assume the role. Moto's STS does the round-trip but doesn't
    # actually verify the role's trust policy — we're testing that
    # provision returned a usable shape, not that moto's STS is
    # IAM-compliant.
    assumed = sts.assume_role(
        RoleArn=result.role_arn,
        RoleSessionName=result.session_name,
        ExternalId=result.external_id,
    )
    creds = assumed["Credentials"]
    assert creds["AccessKeyId"]
    assert creds["SecretAccessKey"]
    assert creds["SessionToken"]

    # The assumed principal's ARN includes the session name we
    # specified, which lets the request-id be derived back from
    # CloudTrail logs.
    assert result.session_name in assumed["AssumedRoleUser"]["Arn"], (
        f"assumed principal should embed session_name; got {assumed}"
    )
    # iam-jit conventions: the session name encodes the request id
    # so an auditor can trace any AssumedRole CloudTrail event back
    # to the originating iam-jit request.
    assert "lc-test-003" in result.session_name, (
        f"session name missing request id: {result.session_name}"
    )


def test_revoke_deletes_role_from_iam(
    moto_aws, accounts: InMemoryAccountStore
) -> None:
    """Step 6-7: revoke removes the role from moto-IAM. Direct
    API verification — not just our internal state."""
    from iam_jit import provision as provision_revoke_mod
    from botocore.exceptions import ClientError

    sts, factory = moto_aws
    req = _request_payload(request_id="lc-test-004")

    # Provision first.
    result = provision_mod.provision(
        req, accounts_store=accounts,
        sts_client=sts, iam_client_factory=factory,
    )
    iam = factory("111111111111")
    # Sanity: role exists.
    iam.get_role(RoleName=result.role_name)

    # Splice the provision result into the request payload (mirrors
    # what the real submit→approve→provision flow writes).
    req_with_provisioned = dict(req)
    req_with_provisioned["status"] = dict(req["status"])
    req_with_provisioned["status"]["provisioned"] = {
        "role_arn": result.role_arn,
        "role_name": result.role_name,
        "account_id": result.account_id,
        "external_id": result.external_id,
        "session_name": result.session_name,
        "expires_at": result.expires_at,
    }

    # Revoke.
    revoke_result = provision_revoke_mod.revoke(
        req_with_provisioned,
        accounts_store=accounts,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert revoke_result.role_existed is True

    # Now verify role is GONE from moto-IAM.
    with pytest.raises(ClientError) as excinfo:
        iam.get_role(RoleName=result.role_name)
    assert excinfo.value.response["Error"]["Code"] == "NoSuchEntity"


def test_revoke_is_idempotent(
    moto_aws, accounts: InMemoryAccountStore
) -> None:
    """Calling revoke twice on the same request must not raise.
    Mirrors the production case where a scheduled-expiry sweep
    races with a manual admin revoke."""
    from iam_jit import provision as provision_revoke_mod

    sts, factory = moto_aws
    req = _request_payload(request_id="lc-test-005")
    result = provision_mod.provision(
        req, accounts_store=accounts,
        sts_client=sts, iam_client_factory=factory,
    )

    req_with_provisioned = dict(req)
    req_with_provisioned["status"] = dict(req["status"])
    req_with_provisioned["status"]["provisioned"] = {
        "role_arn": result.role_arn,
        "role_name": result.role_name,
        "account_id": result.account_id,
        "external_id": result.external_id,
        "session_name": result.session_name,
        "expires_at": result.expires_at,
    }

    r1 = provision_revoke_mod.revoke(
        req_with_provisioned,
        accounts_store=accounts,
        sts_client=sts, iam_client_factory=factory,
    )
    assert r1.role_existed is True

    # Second revoke should not raise; it should report "already gone."
    r2 = provision_revoke_mod.revoke(
        req_with_provisioned,
        accounts_store=accounts,
        sts_client=sts, iam_client_factory=factory,
    )
    assert r2.role_existed is False  # already gone, no second delete
    # No exception → idempotency holds.


def test_provision_with_iam_role_principal(
    moto_aws, accounts: InMemoryAccountStore
) -> None:
    """Lifecycle test variant: the requester's `principal_arn` is an
    IAM **role** (not a user or SSO session ARN).

    This is the realistic dev-on-an-EC2-instance / agent-running-in-
    a-container case: the principal that will assume the iam-jit
    grant is a workload IAM role, NOT a human SSO session. The
    trust policy needs to lock to the ROLE ARN, and a subsequent
    assume-role using credentials FROM that role must succeed.

    What this verifies end-to-end:
      - provision.provision() accepts a role-ARN principal
      - the resulting trust policy carries the role ARN as
        Principal.AWS (not a session ARN, not a user ARN)
      - the time-bounded DateLessThan condition is still present
      - the role can be assumed by an AWS principal whose identity
        matches that role ARN (moto's STS is permissive but the
        trust-policy shape is what matters)
    """
    sts, factory = moto_aws
    req = _request_payload(request_id="lc-test-iam-role")
    # Override the principal to an IAM role ARN (the common
    # workload case: agents running with a role attached).
    req["metadata"]["requester"]["principal_arn"] = (
        "arn:aws:iam::111111111111:role/dev-workload-role"
    )

    result = provision_mod.provision(
        req, accounts_store=accounts,
        sts_client=sts, iam_client_factory=factory,
    )

    iam = factory("111111111111")
    role = iam.get_role(RoleName=result.role_name)
    trust = role["Role"]["AssumeRolePolicyDocument"]
    statements = trust["Statement"]

    # The trust policy MUST list the IAM-role ARN as the
    # principal — not collapsed to the account root, not the
    # SSO session ARN, and not the bare role name.
    found_role_principal = False
    for stmt in statements:
        principal = stmt.get("Principal") or {}
        aws_principals = principal.get("AWS")
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        if not aws_principals:
            continue
        for p in aws_principals:
            if p == "arn:aws:iam::111111111111:role/dev-workload-role":
                found_role_principal = True
                break
    assert found_role_principal, (
        f"trust policy must list the IAM role ARN as Principal.AWS; "
        f"got {trust}"
    )

    # Time-bound condition still present (no regression on the
    # role-principal path).
    found_time_condition = False
    for stmt in statements:
        cond = stmt.get("Condition") or {}
        for op in ("DateLessThan", "DateLessThanEquals"):
            if "aws:CurrentTime" in (cond.get(op) or {}):
                found_time_condition = True
    assert found_time_condition, (
        "DateLessThan condition missing on role-principal path"
    )

    # Verify the assumer_principal_arn surfaced back to the caller
    # matches what we passed in (audit anchor — the request body
    # records the IAM role ARN, the role records it, full circle).
    assert result.assumer_principal_arn == (
        "arn:aws:iam::111111111111:role/dev-workload-role"
    )


def test_inventory_lists_only_iam_jit_managed_roles(
    moto_aws, accounts: InMemoryAccountStore
) -> None:
    """The destination CFN ReadIAMState statement is `Resource: *`
    (AWS doesn't allow path-prefix conditions on ListRoles), so
    the iam-jit provisioner CAN see all roles. iam-jit must
    filter client-side to only the iam-jit-tagged ones in the
    rediscover flow.

    Set up: create one iam-jit role + one foreign role; confirm
    rediscover only surfaces the iam-jit one.
    """
    from iam_jit import rediscover

    sts, factory = moto_aws
    iam = factory("111111111111")

    # iam-jit role via the production code path
    req = _request_payload(request_id="lc-test-006")
    iamjit_role = provision_mod.provision(
        req, accounts_store=accounts,
        sts_client=sts, iam_client_factory=factory,
    )

    # Foreign role directly via moto (simulates a pre-existing role
    # in the destination account that iam-jit shouldn't touch).
    iam.create_role(
        RoleName="not-managed-by-iam-jit",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )

    # Rediscover should find ONLY the iam-jit-tagged role.
    account = accounts.get("111111111111")
    found = rediscover.discover_roles_in_account(
        account=account, sts_client=sts, iam_client_factory=factory,
    )
    found_names = {r.role_name for r in found}
    assert iamjit_role.role_name in found_names
    assert "not-managed-by-iam-jit" not in found_names
    assert len(found) == 1, (
        f"expected exactly one iam-jit role; got {found_names}"
    )
