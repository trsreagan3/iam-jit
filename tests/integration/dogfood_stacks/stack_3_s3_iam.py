"""Stack 3 — S3 + IAM.

Exercises HIGH-5 (token API admin-on-behalf-of) by minting a
short-lived token AS the admin and confirming a non-admin token
gets 403 on the same admin endpoint.

Also covers LOW-2 (reconciler) — after the role is provisioned,
the dogfood script raw-deletes the IAM role out from under
iam-jit and waits for the reconciler to mark the request
`revoked` with `reason="RECONCILED..."`.

Stack 3 keeps the AWS surface minimal — S3 bucket + IAM role —
because the real assertions here are control-plane (token API +
reconciler), not data-plane (bucket lifecycle).
"""

from __future__ import annotations

STACK_NAME = "stack_3_s3_iam"
STACK_TAG = "s3-iam"

INTENDED_ACTIONS: list[dict] = [
    {
        "service": "s3",
        "operation_name": "CreateBucket",
        "params": {"Bucket": "dogfood-stack3-plan-only"},
        "iam_action": "s3:CreateBucket",
    },
    {
        "service": "s3",
        "operation_name": "PutBucketPolicy",
        "params": {"Bucket": "dogfood-stack3-plan-only",
                   "Policy": '{"Version":"2012-10-17","Statement":[]}'},
        "iam_action": "s3:PutBucketPolicy",
    },
    {
        "service": "s3",
        "operation_name": "PutBucketVersioning",
        "params": {"Bucket": "dogfood-stack3-plan-only",
                   "VersioningConfiguration": {"Status": "Enabled"}},
        "iam_action": "s3:PutBucketVersioning",
    },
    {
        "service": "s3",
        "operation_name": "PutBucketEncryption",
        "params": {
            "Bucket": "dogfood-stack3-plan-only",
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault":
                           {"SSEAlgorithm": "AES256"}}]
            },
        },
        "iam_action": "s3:PutBucketEncryption",
    },
    {
        "service": "iam",
        "operation_name": "CreateRole",
        "params": {
            "RoleName": "dogfood-stack3-app-role",
            "AssumeRolePolicyDocument": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Principal":'
                '{"Service":"ec2.amazonaws.com"},'
                '"Action":"sts:AssumeRole"}]}'
            ),
        },
        "iam_action": "iam:CreateRole",
    },
    {
        "service": "iam",
        "operation_name": "PutRolePolicy",
        "params": {
            "RoleName": "dogfood-stack3-app-role",
            "PolicyName": "s3-access",
            "PolicyDocument": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Action":'
                '["s3:GetObject","s3:ListBucket"],'
                '"Resource":"arn:aws:s3:::dogfood-stack3-*"}]}'
            ),
        },
        "iam_action": "iam:PutRolePolicy",
    },
    {
        "service": "iam",
        "operation_name": "AttachRolePolicy",
        "params": {
            "RoleName": "dogfood-stack3-app-role",
            "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
        },
        "iam_action": "iam:AttachRolePolicy",
    },
]

ACCURACY_PROBES: list[dict] = [
    # ListAllMyBuckets — cheap, read-only; ReadOnlyAccess covers
    # it. (Stack 3 grants s3 + iam reads via AttachRolePolicy.)
    {
        "service": "s3",
        "operation_name": "ListBuckets",
        "params": {},
        "iam_action": "s3:ListAllMyBuckets",
    },
]

NEGATIVE_PROBES: list[str] = [
    "iam:CreateUser",
    "ec2:RunInstances",
]
