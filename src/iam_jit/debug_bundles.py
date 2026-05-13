"""Service-specific read-only debug bundles.

When a user requests read-only access for debugging or investigating
something, the bare service-prefix actions (e.g. just `lambda:GetFunction`)
are usually insufficient. To actually debug a Lambda you also need
CloudWatch Logs for the function's log group, CloudWatch Metrics for
errors/duration/throttles, X-Ray traces if instrumented, plus the
function's configuration, aliases, event sources, and resource policy.

This module is a curated, auditable knowledge base mapping each AWS
service to a "debug bundle" — the additional actions and cross-service
permissions someone investigating that service typically needs.

Bundles are applied as a code-level augmentation in `intake.take_turn`
when `access_type=read-only`, after the LLM has produced its draft. The
LLM doesn't need to know about bundles — that keeps the prompt small
and the augmentation deterministic and easy to audit.

Each bundle has:
  - `actions`:   list of action prefixes for the service itself
  - `extras`:    list of full Statement blocks granting cross-service
                 permissions (Logs, Metrics, X-Ray) with resource
                 templates that get filled in based on the request

Resource templates use these placeholders:
  {function_name}    — extracted from the lambda function ARN if present
  {cluster_name}     — extracted from EKS/ECS cluster ARN if present
  {db_instance}      — extracted from RDS DB ARN if present
  {account}          — request's target account_id (always available)
  {region}           — request's region or '*'
"""

from __future__ import annotations

import re
from typing import Any


_ARN_LAMBDA = re.compile(
    r"^arn:aws[a-z-]*:lambda:([^:]*):([0-9]{12}):function:([^:/]+)"
)
_ARN_EKS = re.compile(r"^arn:aws[a-z-]*:eks:([^:]*):([0-9]{12}):cluster/(.+)$")
_ARN_ECS_CLUSTER = re.compile(
    r"^arn:aws[a-z-]*:ecs:([^:]*):([0-9]{12}):cluster/(.+)$"
)
_ARN_RDS = re.compile(
    r"^arn:aws[a-z-]*:rds:([^:]*):([0-9]{12}):db:(.+)$"
)
_ARN_S3 = re.compile(r"^arn:aws[a-z-]*:s3:::([^/]+)")
_ARN_DYNAMODB = re.compile(
    r"^arn:aws[a-z-]*:dynamodb:([^:]*):([0-9]{12}):table/([^/]+)"
)
_ARN_SECRET = re.compile(
    r"^arn:aws[a-z-]*:secretsmanager:([^:]*):([0-9]{12}):secret:([^:]+)"
)


# ---- Bundle definitions ----
#
# Keep these tight: each entry should be a real, useful debug surface.
# Adding random "while we're at it" actions defeats the purpose. Every
# extra action is one more thing the human reviewer has to understand
# before approving.


"""Each bundle may include an `aws_managed_reference` field — the
closest AWS-maintained managed policy. Reviewers can use it as a
sanity check ("does this draft cover roughly the same scope?"); admins
who don't want curated inline policies can attach the managed policy
directly instead of using the bundle. AWS-maintained policies update
automatically when new APIs are added, so they're a useful baseline
but typically less tightly resource-scoped than what we produce.

The bundles are deliberately a SUBSET (resource-scoped where possible)
plus some ADDITIONS (cross-service observability) compared to the
managed reference. Don't expect 1:1 equivalence."""


BUNDLES: dict[str, dict[str, Any]] = {
    "lambda": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AWSLambda_ReadOnlyAccess",
        "aws_managed_notes": (
            "AWSLambda_ReadOnlyAccess covers all lambda:Get*/List* actions on "
            "all functions. Our bundle scopes to a specific function ARN when "
            "known, plus adds CloudWatch Logs/Metrics + X-Ray for actual "
            "debugging."
        ),
        "actions": [
            "lambda:GetFunction",
            "lambda:GetFunctionConfiguration",
            "lambda:GetFunctionConcurrency",
            "lambda:GetFunctionEventInvokeConfig",
            "lambda:GetPolicy",
            "lambda:ListAliases",
            "lambda:GetAlias",
            "lambda:ListVersionsByFunction",
            "lambda:ListEventSourceMappings",
            "lambda:GetEventSourceMapping",
            "lambda:ListTags",
            "lambda:GetLayerVersion",
        ],
        "extras_when_function_known": [
            {
                "Sid": "iamJitLambdaLogs",
                "Effect": "Allow",
                "Action": [
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:GetLogEvents",
                    "logs:FilterLogEvents",
                    "logs:StartQuery",
                    "logs:StopQuery",
                    "logs:GetQueryResults",
                    "logs:GetLogGroupFields",
                ],
                "Resource": [
                    "arn:aws:logs:*:{account}:log-group:/aws/lambda/{function_name}",
                    "arn:aws:logs:*:{account}:log-group:/aws/lambda/{function_name}:*",
                    "arn:aws:logs:*:{account}:log-group:/aws/lambda/{function_name}:log-stream:*",
                ],
            },
        ],
        "extras_global": [
            {
                "Sid": "iamJitLambdaMetrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                ],
                "Resource": "*",
            },
            {
                "Sid": "iamJitLambdaXray",
                "Effect": "Allow",
                "Action": [
                    "xray:GetTraceSummaries",
                    "xray:BatchGetTraces",
                    "xray:GetServiceGraph",
                    "xray:GetGroups",
                    "xray:GetSamplingRules",
                ],
                "Resource": "*",
            },
        ],
    },
    "ec2": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
        "aws_managed_notes": (
            "AmazonEC2ReadOnlyAccess covers ec2:Describe*/Get* + "
            "elasticloadbalancing:Describe*/cloudwatch:Describe*/autoscaling:Describe*. "
            "Our bundle is tighter on the EC2 side and adds metrics."
        ),
        "actions": [
            "ec2:DescribeInstances",
            "ec2:DescribeInstanceStatus",
            "ec2:DescribeInstanceAttribute",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeSubnets",
            "ec2:DescribeVpcs",
            "ec2:DescribeRouteTables",
            "ec2:DescribeNatGateways",
            "ec2:DescribeInternetGateways",
            "ec2:GetConsoleOutput",
            "ec2:GetConsoleScreenshot",
            "ec2:DescribeTags",
        ],
        "extras_global": [
            {
                "Sid": "iamJitEc2Metrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                    "cloudwatch:DescribeAlarms",
                ],
                "Resource": "*",
            },
        ],
    },
    "rds": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess",
        "actions": [
            "rds:DescribeDBInstances",
            "rds:DescribeDBClusters",
            "rds:DescribeDBSnapshots",
            "rds:DescribeDBClusterSnapshots",
            "rds:DescribeDBLogFiles",
            "rds:DescribeDBSubnetGroups",
            "rds:DescribeDBParameterGroups",
            "rds:DescribeDBClusterParameters",
            "rds:DescribeEvents",
            "rds:DescribePendingMaintenanceActions",
            "rds:DescribeOptionGroups",
            "rds:ListTagsForResource",
        ],
        "extras_when_db_known": [
            {
                "Sid": "iamJitRdsLogs",
                "Effect": "Allow",
                "Action": [
                    "rds:DownloadDBLogFilePortion",
                    "rds:DownloadCompleteDBLogFile",
                ],
                "Resource": "arn:aws:rds:*:{account}:db:{db_instance}",
            },
        ],
        "extras_global": [
            {
                "Sid": "iamJitRdsMetrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                    "cloudwatch:DescribeAlarms",
                ],
                "Resource": "*",
            },
        ],
    },
    "eks": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
        "aws_managed_notes": (
            "No first-party AWSEKSReadOnly. Closest AWS-managed pattern is "
            "the SSO/IDC permission set 'EKSReadOnly' (community example). "
            "Our bundle is the curated debug surface for EKS."
        ),
        "actions": [
            "eks:DescribeCluster",
            "eks:DescribeNodegroup",
            "eks:DescribeFargateProfile",
            "eks:DescribeUpdate",
            "eks:DescribeAddon",
            "eks:DescribeAddonVersions",
            "eks:DescribeIdentityProviderConfig",
            "eks:ListClusters",
            "eks:ListNodegroups",
            "eks:ListAddons",
            "eks:ListUpdates",
            "eks:AccessKubernetesApi",  # required to actually use kubectl
        ],
        "extras_global": [
            {
                "Sid": "iamJitEksMetrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                    "logs:DescribeLogGroups",
                    "logs:GetLogEvents",
                    "logs:FilterLogEvents",
                ],
                "Resource": "*",
            },
        ],
    },
    "ecs": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonECS_FullAccess",
        "aws_managed_notes": (
            "ECS doesn't ship a first-party read-only managed policy. Our "
            "bundle is hand-curated for read-only debug."
        ),
        "actions": [
            "ecs:DescribeClusters",
            "ecs:DescribeServices",
            "ecs:DescribeTasks",
            "ecs:DescribeTaskDefinition",
            "ecs:DescribeContainerInstances",
            "ecs:ListClusters",
            "ecs:ListServices",
            "ecs:ListTasks",
            "ecs:ListContainerInstances",
            "ecs:ListTaskDefinitions",
            "ecs:ListTagsForResource",
        ],
        "extras_global": [
            {
                "Sid": "iamJitEcsLogs",
                "Effect": "Allow",
                "Action": [
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:GetLogEvents",
                    "logs:FilterLogEvents",
                ],
                "Resource": "arn:aws:logs:*:{account}:log-group:/ecs/*",
            },
            {
                "Sid": "iamJitEcsMetrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                ],
                "Resource": "*",
            },
        ],
    },
    "dynamodb": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess",
        "actions": [
            "dynamodb:DescribeTable",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeStream",
            "dynamodb:ListStreams",
            "dynamodb:DescribeBackup",
            "dynamodb:ListBackups",
            "dynamodb:GetItem",
            "dynamodb:Scan",
            "dynamodb:Query",
            "dynamodb:BatchGetItem",
            "dynamodb:ListTagsOfResource",
        ],
        "extras_global": [
            {
                "Sid": "iamJitDynamoMetrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                ],
                "Resource": "*",
            },
        ],
    },
    "s3": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        "actions": [
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:GetObjectAcl",
            "s3:GetObjectTagging",
            "s3:ListBucket",
            "s3:ListBucketVersions",
            "s3:GetBucketLocation",
            "s3:GetBucketAcl",
            "s3:GetBucketPolicy",
            "s3:GetBucketTagging",
            "s3:GetBucketVersioning",
            "s3:GetBucketLogging",
            "s3:GetBucketCors",
            "s3:GetBucketNotification",
            "s3:GetBucketEncryption",
            "s3:GetLifecycleConfiguration",
            "s3:GetReplicationConfiguration",
            "s3:GetInventoryConfiguration",
        ],
        "extras_global": [
            {
                "Sid": "iamJitS3Metrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                ],
                "Resource": "*",
            },
        ],
    },
    "secretsmanager": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
        "aws_managed_notes": (
            "AWS doesn't ship a SecretsManagerReadOnly managed policy — only "
            "SecretsManagerReadWrite. Our bundle is the read-only subset."
        ),
        "actions": [
            "secretsmanager:DescribeSecret",
            "secretsmanager:GetSecretValue",
            "secretsmanager:ListSecretVersionIds",
            "secretsmanager:GetResourcePolicy",
            "secretsmanager:ListTagsForResource",
        ],
    },
    "kms": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/aws-service-role/AWSKeyManagementServiceMultiRegionKeysServiceRolePolicy",
        "aws_managed_notes": (
            "No first-party KMS read-only managed policy. Our bundle is the "
            "metadata-read surface (not key usage — that requires explicit "
            "kms:Decrypt grants on each key)."
        ),
        "actions": [
            "kms:DescribeKey",
            "kms:GetKeyPolicy",
            "kms:GetKeyRotationStatus",
            "kms:ListAliases",
            "kms:ListKeyPolicies",
            "kms:ListResourceTags",
        ],
    },
    "sns": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonSNSReadOnlyAccess",
        "actions": [
            "sns:GetTopicAttributes",
            "sns:GetSubscriptionAttributes",
            "sns:ListSubscriptionsByTopic",
            "sns:ListTagsForResource",
        ],
        "extras_global": [
            {
                "Sid": "iamJitSnsMetrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                ],
                "Resource": "*",
            },
        ],
    },
    "sqs": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonSQSReadOnlyAccess",
        "actions": [
            "sqs:GetQueueAttributes",
            "sqs:GetQueueUrl",
            "sqs:ListDeadLetterSourceQueues",
            "sqs:ListQueueTags",
            "sqs:ReceiveMessage",  # peek for debugging — non-destructive
        ],
        "extras_global": [
            {
                "Sid": "iamJitSqsMetrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                ],
                "Resource": "*",
            },
        ],
    },
    "route53": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonRoute53ReadOnlyAccess",
        "actions": [
            "route53:GetHostedZone",
            "route53:ListHostedZones",
            "route53:ListResourceRecordSets",
            "route53:GetChange",
            "route53:ListTagsForResource",
            "route53:GetHealthCheck",
            "route53:GetHealthCheckStatus",
            "route53:ListHealthChecks",
        ],
    },
    "elasticloadbalancing": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AWSElasticLoadBalancingFullAccess",
        "aws_managed_notes": (
            "No first-party ELB read-only managed policy. Our bundle is the "
            "Describe* subset only."
        ),
        "actions": [
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeListeners",
            "elasticloadbalancing:DescribeRules",
            "elasticloadbalancing:DescribeTargetGroups",
            "elasticloadbalancing:DescribeTargetHealth",
            "elasticloadbalancing:DescribeLoadBalancerAttributes",
            "elasticloadbalancing:DescribeTargetGroupAttributes",
            "elasticloadbalancing:DescribeTags",
        ],
        "extras_global": [
            {
                "Sid": "iamJitElbMetrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                ],
                "Resource": "*",
            },
        ],
    },
    "apigateway": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AmazonAPIGatewayInvokeFullAccess",
        "actions": [
            "apigateway:GET",
        ],
        "extras_global": [
            {
                "Sid": "iamJitApigwMetrics",
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                    "logs:DescribeLogGroups",
                    "logs:GetLogEvents",
                    "logs:FilterLogEvents",
                ],
                "Resource": "*",
            },
        ],
    },
    "stepfunctions": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/AWSStepFunctionsReadOnlyAccess",
        "actions": [
            "states:DescribeStateMachine",
            "states:DescribeExecution",
            "states:GetExecutionHistory",
            "states:ListExecutions",
            "states:ListStateMachines",
            "states:ListTagsForResource",
        ],
    },
    "cloudfront": {
        "aws_managed_reference": "arn:aws:iam::aws:policy/CloudFrontReadOnlyAccess",
        "actions": [
            "cloudfront:GetDistribution",
            "cloudfront:GetDistributionConfig",
            "cloudfront:ListDistributions",
            "cloudfront:GetInvalidation",
            "cloudfront:ListInvalidations",
            "cloudfront:GetCachePolicy",
            "cloudfront:ListTagsForResource",
        ],
    },
}


def _extract_resource_hints(fields: dict[str, Any], policy: dict[str, Any]) -> dict[str, str]:
    """Pull resource identifiers out of the policy's existing Resource
    fields and the user's gathered fields.

    Returns a dict suitable for str.format() placeholder expansion in
    bundle resource templates.
    """
    hints: dict[str, str] = {
        "account": str(fields.get("account_id") or "*"),
        "region": "*",
    }
    arns: list[str] = []
    for s in policy.get("Statement") or []:
        r = s.get("Resource")
        if isinstance(r, str):
            arns.append(r)
        elif isinstance(r, list):
            arns.extend(x for x in r if isinstance(x, str))

    for arn in arns:
        m = _ARN_LAMBDA.match(arn)
        if m:
            hints["function_name"] = m.group(3)
            if m.group(1):
                hints["region"] = m.group(1)
        m = _ARN_EKS.match(arn) or _ARN_ECS_CLUSTER.match(arn)
        if m:
            hints["cluster_name"] = m.group(3)
        m = _ARN_RDS.match(arn)
        if m:
            hints["db_instance"] = m.group(3)
    return hints


def _expand_resource(template: Any, hints: dict[str, str]) -> Any:
    """str.format() the template with hints. Tolerates missing hints
    by leaving placeholders unfilled (the deploy will still work — IAM
    just won't match)."""
    if isinstance(template, str):
        try:
            return template.format(**hints)
        except (KeyError, IndexError):
            return template
    if isinstance(template, list):
        return [_expand_resource(x, hints) for x in template]
    return template


def augment_for_debug(
    policy: dict[str, Any], fields: dict[str, Any]
) -> dict[str, Any]:
    """Augment a read-only draft policy with the debug bundles for each
    service it covers.

    Idempotent: running this twice produces the same policy. Statements
    are deduplicated by Sid where present and by (action_set, resource)
    where not.

    Only services with bundles are augmented; unknown services pass
    through unchanged. Caller decides when to invoke this — typically
    only for `access_type=read-only` completions.
    """
    if not isinstance(policy, dict):
        return policy
    statements_in = list(policy.get("Statement") or [])
    services = _services_in_statements(statements_in)
    if not services:
        return policy

    hints = _extract_resource_hints(fields, policy)

    # Augment each existing statement that targets a known service by
    # adding the bundle's actions to it (so the resource scoping the
    # user already provided is preserved).
    statements_out: list[dict[str, Any]] = []
    for s in statements_in:
        statements_out.append(_augment_statement_actions(s))

    # Append cross-service extras (logs/metrics/xray) for each service
    # that has them. Sid-dedupe so re-running is idempotent.
    existing_sids = {s.get("Sid") for s in statements_out if s.get("Sid")}
    for svc in services:
        bundle = BUNDLES.get(svc)
        if not bundle:
            continue
        if "extras_global" in bundle:
            for extra in bundle["extras_global"]:
                if extra.get("Sid") and extra["Sid"] in existing_sids:
                    continue
                expanded = {
                    k: (_expand_resource(v, hints) if k == "Resource" else v)
                    for k, v in extra.items()
                }
                statements_out.append(expanded)
                if expanded.get("Sid"):
                    existing_sids.add(expanded["Sid"])
        if (
            svc == "lambda"
            and "function_name" in hints
            and "extras_when_function_known" in bundle
        ):
            for extra in bundle["extras_when_function_known"]:
                if extra.get("Sid") and extra["Sid"] in existing_sids:
                    continue
                expanded = {
                    k: (_expand_resource(v, hints) if k == "Resource" else v)
                    for k, v in extra.items()
                }
                statements_out.append(expanded)
                if expanded.get("Sid"):
                    existing_sids.add(expanded["Sid"])
        if (
            svc == "rds"
            and "db_instance" in hints
            and "extras_when_db_known" in bundle
        ):
            for extra in bundle["extras_when_db_known"]:
                if extra.get("Sid") and extra["Sid"] in existing_sids:
                    continue
                expanded = {
                    k: (_expand_resource(v, hints) if k == "Resource" else v)
                    for k, v in extra.items()
                }
                statements_out.append(expanded)
                if expanded.get("Sid"):
                    existing_sids.add(expanded["Sid"])

    return {"Version": policy.get("Version", "2012-10-17"), "Statement": statements_out}


def _services_in_statements(statements: list[dict[str, Any]]) -> set[str]:
    services: set[str] = set()
    for s in statements:
        actions = s.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if isinstance(a, str) and ":" in a:
                services.add(a.split(":", 1)[0])
    return services


def _augment_statement_actions(stmt: dict[str, Any]) -> dict[str, Any]:
    """Add a bundle's service-scoped actions to a statement, preserving
    the existing Resource.

    If the statement already grants `<service>:*`, leave it — adding
    individual actions wouldn't tighten anything. Otherwise dedupe and
    sort the action list so output is deterministic.
    """
    actions = stmt.get("Action") or []
    if isinstance(actions, str):
        actions = [actions]
    actions = list(actions)

    services = _services_in_statements([stmt])
    new_actions = set(actions)
    for svc in services:
        bundle = BUNDLES.get(svc)
        if not bundle:
            continue
        # If the statement is already fully open on this service, skip.
        if f"{svc}:*" in actions:
            continue
        for a in bundle.get("actions", []):
            new_actions.add(a)

    if new_actions == set(actions):
        return stmt
    out = dict(stmt)
    out["Action"] = sorted(new_actions)
    return out
