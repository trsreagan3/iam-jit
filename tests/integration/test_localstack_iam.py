"""Integration tests proving the IAM provisioning code path can talk to a
LocalStack-emulated AWS exactly as it would talk to real AWS — no AWS account
required. These tests document the contract Phase 2's `provision.py` must
satisfy: create role, attach inline policy, assume-role principal, tag.

Skipped automatically if LocalStack isn't running.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.integration


def test_create_and_describe_role(localstack_iam: object) -> None:
    role_name = "iam-jit-integration-test-role"
    assume = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::000000000000:user/example"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    localstack_iam.create_role(  # type: ignore[attr-defined]
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume),
        Description="iam-jit integration test",
        MaxSessionDuration=3600,
        Tags=[
            {"Key": "managed-by", "Value": "iam-jit"},
            {"Key": "request-id", "Value": "integration-test"},
        ],
    )
    described = localstack_iam.get_role(RoleName=role_name)  # type: ignore[attr-defined]
    assert described["Role"]["RoleName"] == role_name
    assert described["Role"]["MaxSessionDuration"] == 3600
    localstack_iam.delete_role(RoleName=role_name)  # type: ignore[attr-defined]


def test_attach_inline_policy(localstack_iam: object) -> None:
    role_name = "iam-jit-integration-inline-role"
    assume = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    localstack_iam.create_role(  # type: ignore[attr-defined]
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume)
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*",
            }
        ],
    }
    localstack_iam.put_role_policy(  # type: ignore[attr-defined]
        RoleName=role_name,
        PolicyName="iam-jit-grant",
        PolicyDocument=json.dumps(policy),
    )
    fetched = localstack_iam.get_role_policy(RoleName=role_name, PolicyName="iam-jit-grant")  # type: ignore[attr-defined]
    assert fetched["PolicyName"] == "iam-jit-grant"
    body = fetched["PolicyDocument"]
    if isinstance(body, str):
        body = json.loads(body)
    assert body["Statement"][0]["Action"] == ["s3:GetObject", "s3:ListBucket"]
    localstack_iam.delete_role_policy(RoleName=role_name, PolicyName="iam-jit-grant")  # type: ignore[attr-defined]
    localstack_iam.delete_role(RoleName=role_name)  # type: ignore[attr-defined]


def test_role_lifecycle_round_trip(localstack_iam: object) -> None:
    """Mirrors the create-then-revoke flow Phase 3's expiry handler will run."""
    role_name = "iam-jit-integration-expiry-role"
    assume = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    localstack_iam.create_role(  # type: ignore[attr-defined]
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume)
    )
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    localstack_iam.put_role_policy(  # type: ignore[attr-defined]
        RoleName=role_name, PolicyName="grant", PolicyDocument=json.dumps(policy_doc)
    )
    # Revoke: delete inline policies, then delete the role.
    inline = localstack_iam.list_role_policies(RoleName=role_name)  # type: ignore[attr-defined]
    for pname in inline.get("PolicyNames", []):
        localstack_iam.delete_role_policy(RoleName=role_name, PolicyName=pname)  # type: ignore[attr-defined]
    localstack_iam.delete_role(RoleName=role_name)  # type: ignore[attr-defined]
    with pytest.raises(Exception):
        localstack_iam.get_role(RoleName=role_name)  # type: ignore[attr-defined]
