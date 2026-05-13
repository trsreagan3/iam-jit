"""Tests for the service-specific debug-bundle augmentation."""

from __future__ import annotations

from iam_jit import debug_bundles


def test_lambda_bundle_adds_logs_metrics_xray() -> None:
    """The bare LLM draft for lambda is missing CloudWatch Logs, Metrics,
    and X-Ray. The bundle augmentation must add them so the role is
    actually useful for debugging."""
    draft = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["lambda:GetFunction"],
                "Resource": "arn:aws:lambda:us-east-1:060392206767:function:my-fn",
            }
        ],
    }
    out = debug_bundles.augment_for_debug(
        draft, fields={"account_id": "060392206767"}
    )
    actions = []
    for s in out["Statement"]:
        a = s.get("Action") or []
        actions.extend(a if isinstance(a, list) else [a])

    # Lambda's own actions augmented
    assert "lambda:GetFunction" in actions
    assert "lambda:GetFunctionConfiguration" in actions
    assert "lambda:GetPolicy" in actions
    assert "lambda:ListEventSourceMappings" in actions
    # Logs (the most important debug surface)
    assert any(a.startswith("logs:") for a in actions)
    assert "logs:FilterLogEvents" in actions
    assert "logs:GetLogEvents" in actions
    # Metrics
    assert "cloudwatch:GetMetricData" in actions
    # X-Ray
    assert "xray:GetTraceSummaries" in actions


def test_lambda_logs_resource_is_scoped_to_function_log_group() -> None:
    """The Logs Resource should be scoped to /aws/lambda/<function>* —
    not '*' (over-broad) and not just the function ARN (Logs ARNs are
    different shape)."""
    draft = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["lambda:GetFunction"],
                "Resource": "arn:aws:lambda:us-east-1:060392206767:function:my-payment-fn",
            }
        ],
    }
    out = debug_bundles.augment_for_debug(
        draft, fields={"account_id": "060392206767"}
    )
    logs_stmt = next(
        s for s in out["Statement"]
        if s.get("Sid") == "iamJitLambdaLogs"
    )
    resources = logs_stmt["Resource"]
    if isinstance(resources, str):
        resources = [resources]
    assert any("/aws/lambda/my-payment-fn" in r for r in resources)
    assert all("060392206767" in r for r in resources)


def test_s3_bundle_adds_metrics_keeps_resource_scope() -> None:
    """Bundle augmentation must NOT broaden the user's Resource scoping.
    The bucket the user named should remain the bucket the policy targets."""
    draft = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::my-bucket",
                    "arn:aws:s3:::my-bucket/*",
                ],
            }
        ],
    }
    out = debug_bundles.augment_for_debug(draft, fields={"account_id": "060392206767"})
    s3_stmt = out["Statement"][0]
    assert s3_stmt["Resource"] == [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*",
    ]
    # Bundle expanded the Action set but kept the Resource.
    assert "s3:GetBucketPolicy" in s3_stmt["Action"]
    assert "s3:GetBucketEncryption" in s3_stmt["Action"]


def test_unknown_service_passes_through_unchanged() -> None:
    """A service with no bundle entry leaves the policy alone."""
    draft = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["someweirdservice:GetFoo"],
                "Resource": "arn:aws:someweirdservice:::foo",
            }
        ],
    }
    out = debug_bundles.augment_for_debug(draft, fields={"account_id": "060392206767"})
    assert out["Statement"] == draft["Statement"]


def test_idempotent_double_augment() -> None:
    """Running augment twice produces the same policy (no duplicate
    statements, no expanding action lists)."""
    draft = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["lambda:GetFunction"],
                "Resource": "arn:aws:lambda:us-east-1:1:function:f",
            }
        ],
    }
    once = debug_bundles.augment_for_debug(draft, fields={"account_id": "1"})
    twice = debug_bundles.augment_for_debug(once, fields={"account_id": "1"})
    assert once == twice


def test_service_wildcard_action_skips_bundle_action_merge() -> None:
    """If the existing Statement already grants `<service>:*`, don't
    bother adding individual actions — they're already covered."""
    draft = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:*"],  # already wide-open on dynamodb
                "Resource": "arn:aws:dynamodb:us-east-1:1:table/x",
            }
        ],
    }
    out = debug_bundles.augment_for_debug(draft, fields={"account_id": "1"})
    # First statement keeps the wildcard untouched.
    assert out["Statement"][0]["Action"] == ["dynamodb:*"]


def test_bundles_have_aws_managed_reference() -> None:
    """Every bundle should record the closest AWS-maintained managed
    policy as a reference for reviewers."""
    for service, bundle in debug_bundles.BUNDLES.items():
        assert "aws_managed_reference" in bundle, service
        assert bundle["aws_managed_reference"].startswith("arn:aws:iam::aws:policy/")


def test_rds_bundle_adds_log_download_when_db_known() -> None:
    """RDS-specific extra: db log file download is only added when the
    db_instance is known (extracted from the ARN). Without a known DB,
    the global metrics are still added but log-download isn't."""
    draft = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["rds:DescribeDBInstances"],
                "Resource": "arn:aws:rds:us-east-1:060392206767:db:prod-payments",
            }
        ],
    }
    out = debug_bundles.augment_for_debug(draft, fields={"account_id": "060392206767"})
    sids = [s.get("Sid") for s in out["Statement"]]
    assert "iamJitRdsLogs" in sids


def test_eks_bundle_includes_kubernetes_api_access() -> None:
    """Without eks:AccessKubernetesApi, you can DescribeCluster but not
    actually run kubectl. That defeats the purpose of EKS debug access."""
    draft = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["eks:DescribeCluster"],
                "Resource": "arn:aws:eks:us-east-1:1:cluster/prod",
            }
        ],
    }
    out = debug_bundles.augment_for_debug(draft, fields={"account_id": "1"})
    actions = []
    for s in out["Statement"]:
        actions.extend(s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
    assert "eks:AccessKubernetesApi" in actions
