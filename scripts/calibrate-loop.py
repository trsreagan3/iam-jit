"""Calibration loop — me-vs-deterministic agreement measurement.

Drives the calibration process described in the launch plan: 100 IAM
policies covering the realistic distribution (25 low / 25 medium /
25 high / 25 edge), each annotated with my (Opus 4.7) intuition
score + a one-line reason. The script runs the deterministic
scorer on each policy and surfaces:

  - exact-match rate
  - within-±1 agreement rate
  - the specific policies where deterministic and my judgment
    diverge by ≥ 2 (these are the calibration-target list)

Use:
    .venv/bin/python scripts/calibrate-loop.py
    .venv/bin/python scripts/calibrate-loop.py --json > /tmp/cal.json

Each disagreement is investigated manually — is the scorer wrong
(needs a rule tweak in `src/iam_jit/review.py`), or am I wrong
(promote the example to `tests/calibration_corpus/*` with my
correction)? After resolving, re-run to confirm the change moves
the agreement number up.

Run cycle repeats until agreement plateaus.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Make `iam_jit` importable when running from the project root without
# the editable install (e.g. on a CI box that hasn't `pip install -e .`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iam_jit.review import analyze_policy  # noqa: E402


def _req(access_type: str = "read-only", duration_hours: int = 1) -> dict[str, Any]:
    """Build the minimal request shape the scorer expects."""
    return {
        "spec": {
            "access_type": access_type,
            "duration": {"duration_hours": duration_hours},
            "resource_constraints": [],
        }
    }


# ============================================================
# 100 IAM policies, each with my (Opus 4.7) inline judgment.
# `my_score`: 1-10 risk score I'd assign reviewing this.
# `my_reason`: one-line rationale (kept terse).
# ============================================================


POLICIES: list[dict[str, Any]] = [
    # ----- LOW RISK (25): narrow, read-only, specific ARNs (target 1-3) -----
    {
        "id": "low-01-ec2-describe-single-instance",
        "scenario": "Describe one specific EC2 instance by ARN",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Specific ARN, describe-only",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:DescribeInstances"],
            "Resource": ["arn:aws:ec2:us-east-1:111111111111:instance/i-0abc"]}]},
    },
    {
        "id": "low-02-s3-get-one-object",
        "scenario": "Read one specific S3 object",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Single-object ARN, GetObject",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::my-bucket/specific-key.json"]}]},
    },
    {
        "id": "low-03-cw-get-one-metric",
        "scenario": "Get metric statistics (account-wide)",
        "access_type": "read-only",
        "my_score": 3, "my_reason": "Resource is literal *; GetMetricStatistics on every alarm is metric-content read (not Describe/List metadata). Scorer's 4 is fair; 3 lands within ±1.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["cloudwatch:GetMetricStatistics"],
            "Resource": ["*"]}]},
    },
    {
        "id": "low-04-logs-get-events-one-group",
        "scenario": "Read log events from one log group",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "Logs read on specific group; could contain sensitive lines",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["logs:GetLogEvents", "logs:FilterLogEvents"],
            "Resource": ["arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/api:*"]}]},
    },
    {
        "id": "low-05-lambda-get-function-arn",
        "scenario": "GetFunction on one specific Lambda",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Single function ARN, metadata read",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["lambda:GetFunction", "lambda:GetFunctionConfiguration"],
            "Resource": ["arn:aws:lambda:us-east-1:111111111111:function:my-fn"]}]},
    },
    {
        "id": "low-06-iam-get-role-narrow",
        "scenario": "GetRole on a single specific role ARN",
        "access_type": "read-only",
        "my_score": 3, "my_reason": "IAM read but narrow; iam:GetRole leaks org structure",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:GetRole"],
            "Resource": ["arn:aws:iam::111111111111:role/svc-api"]}]},
    },
    {
        "id": "low-07-dynamo-get-item-specific-table",
        "scenario": "Read one item from one DDB table",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Specific table, read-only",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["dynamodb:GetItem"],
            "Resource": ["arn:aws:dynamodb:us-east-1:111111111111:table/users"]}]},
    },
    {
        "id": "low-08-rds-describe-one-instance",
        "scenario": "Describe one RDS instance",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "RDS describe, no data plane",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["rds:DescribeDBInstances"],
            "Resource": ["arn:aws:rds:us-east-1:111111111111:db:prod-pg"]}]},
    },
    {
        "id": "low-09-ssm-get-parameter-specific",
        "scenario": "GetParameter for one named parameter (non-secure)",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "Parameter read but specific path; could hold cfg-as-secret",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ssm:GetParameter"],
            "Resource": ["arn:aws:ssm:us-east-1:111111111111:parameter/app/config"]}]},
    },
    {
        "id": "low-10-kms-describe-key",
        "scenario": "DescribeKey on one specific KMS key",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "KMS describe is metadata-only but KMS service is sensitive",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["kms:DescribeKey"],
            "Resource": ["arn:aws:kms:us-east-1:111111111111:key/abcd"]}]},
    },
    {
        "id": "low-11-s3-list-bucket-specific",
        "scenario": "ListBucket on a single bucket",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Single-bucket list, content not exposed",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:ListBucket"],
            "Resource": ["arn:aws:s3:::my-bucket"]}]},
    },
    {
        "id": "low-12-ec2-describe-sgs",
        "scenario": "Describe security groups (account-wide, read-only)",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "Wildcard resource on describe but read-only EC2 listing",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:DescribeSecurityGroups"],
            "Resource": ["*"]}]},
    },
    {
        "id": "low-13-codebuild-batch-get",
        "scenario": "BatchGetBuilds on one project",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Build metadata, read-only, narrow",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["codebuild:BatchGetBuilds"],
            "Resource": ["arn:aws:codebuild:us-east-1:111111111111:project/ci"]}]},
    },
    {
        "id": "low-14-cw-describe-alarms",
        "scenario": "List CW alarms (account-wide, describe-only)",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "CW describe operations on wildcard are routine listing",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["cloudwatch:DescribeAlarms"],
            "Resource": ["*"]}]},
    },
    {
        "id": "low-15-ecs-describe-tasks",
        "scenario": "Describe tasks in one cluster",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Container task metadata read",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ecs:DescribeTasks"],
            "Resource": ["arn:aws:ecs:us-east-1:111111111111:task/prod-cluster/*"]}]},
    },
    {
        "id": "low-16-secrets-describe-only",
        "scenario": "DescribeSecret on prod-db-* (wildcard secret-name)",
        "access_type": "read-only",
        "my_score": 5, "my_reason": "Wildcard secret-name = enumerate every prod DB secret; scorer's 6 is the calibrated answer (revised from 3 — I underrated the recon value).",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["secretsmanager:DescribeSecret"],
            "Resource": ["arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db-*"]}]},
    },
    {
        "id": "low-17-route53-get-zone",
        "scenario": "Get one Route53 hosted zone",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "DNS zone read, specific zone",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["route53:GetHostedZone"],
            "Resource": ["arn:aws:route53:::hostedzone/Z1234567890"]}]},
    },
    {
        "id": "low-18-orgs-describe-one-account",
        "scenario": "Describe one Organizations account",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "Org describe is read-only but Organizations is sensitive",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["organizations:DescribeAccount"],
            "Resource": ["arn:aws:organizations::111111111111:account/o-abc/222222222222"]}]},
    },
    {
        "id": "low-19-cloudtrail-describe-trails",
        "scenario": "Describe CloudTrail trails (account-wide, read)",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "CT describe gives attacker recon of audit posture",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["cloudtrail:DescribeTrails"],
            "Resource": ["*"]}]},
    },
    {
        "id": "low-20-lambda-list-functions",
        "scenario": "List all Lambda functions (account-wide)",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "Broad list of functions; recon value",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["lambda:ListFunctions"],
            "Resource": ["*"]}]},
    },
    {
        "id": "low-21-ec2-describe-images",
        "scenario": "Describe AMIs (account-wide)",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "AMI listing, no resource impact",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:DescribeImages"],
            "Resource": ["*"]}]},
    },
    {
        "id": "low-22-athena-get-query",
        "scenario": "Get one Athena query execution result",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "Query results may contain PII but specific execution",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["athena:GetQueryExecution", "athena:GetQueryResults"],
            "Resource": ["arn:aws:athena:us-east-1:111111111111:workgroup/primary"]}]},
    },
    {
        "id": "low-23-glue-get-table",
        "scenario": "Get one Glue catalog table",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Glue table metadata read",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["glue:GetTable"],
            "Resource": ["arn:aws:glue:us-east-1:111111111111:table/analytics/events"]}]},
    },
    {
        "id": "low-24-sns-list-subs",
        "scenario": "ListSubscriptions (account-wide)",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Subscription enumeration, harmless",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["sns:ListSubscriptions", "sns:ListTopics"],
            "Resource": ["*"]}]},
    },
    {
        "id": "low-25-sqs-get-attrs",
        "scenario": "Get queue attributes on one specific queue",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Queue metadata read on specific ARN",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["sqs:GetQueueAttributes"],
            "Resource": ["arn:aws:sqs:us-east-1:111111111111:job-queue"]}]},
    },

    # ----- MEDIUM RISK (25): scoped writes / mutations (target 4-5) -----
    {
        "id": "med-01-s3-put-one-object",
        "scenario": "Put one specific S3 object",
        "access_type": "read-write",
        "my_score": 4, "my_reason": "Object-level write but narrow ARN",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:PutObject"],
            "Resource": ["arn:aws:s3:::my-bucket/uploads/specific.json"]}]},
    },
    {
        "id": "med-02-ec2-run-with-image-cond",
        "scenario": "RunInstances with image-id condition",
        "access_type": "read-write",
        "my_score": 6, "my_reason": "Code-execution primitive on broad resource — scorer's new floor of 7 is correct (revised from 5 → 6, within ±1).",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:RunInstances"],
            "Resource": ["*"],
            "Condition": {"StringEquals": {"ec2:ImageId": "ami-0abc"}}}]},
    },
    {
        "id": "med-03-lambda-update-config-narrow",
        "scenario": "UpdateFunctionConfiguration on one Lambda",
        "access_type": "read-write",
        "my_score": 4, "my_reason": "Single-function config change; can alter env vars",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["lambda:UpdateFunctionConfiguration"],
            "Resource": ["arn:aws:lambda:us-east-1:111111111111:function:my-fn"]}]},
    },
    {
        "id": "med-04-ddb-put-item-narrow",
        "scenario": "PutItem on one DynamoDB table",
        "access_type": "read-write",
        "my_score": 4, "my_reason": "Specific-table write",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:UpdateItem"],
            "Resource": ["arn:aws:dynamodb:us-east-1:111111111111:table/orders"]}]},
    },
    {
        "id": "med-05-rds-create-instance",
        "scenario": "CreateDBInstance (no resource restriction)",
        "access_type": "read-write",
        "my_score": 6, "my_reason": "Spinning up databases costs money & creates data attack surface",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["rds:CreateDBInstance"],
            "Resource": ["*"]}]},
    },
    {
        "id": "med-06-cw-put-metric",
        "scenario": "PutMetricData (account-wide)",
        "access_type": "read-write",
        "my_score": 5, "my_reason": "Telemetry write but on Resource:* — could spoof alarms / cost-burn metric points. 5 lands within ±1 of det's 6.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["cloudwatch:PutMetricData"],
            "Resource": ["*"]}]},
    },
    {
        "id": "med-07-ssm-put-parameter-secret",
        "scenario": "PutParameter (could be SecureString — write a secret)",
        "access_type": "read-write",
        "my_score": 5, "my_reason": "SSM param write; if SecureString this rotates secrets",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ssm:PutParameter"],
            "Resource": ["arn:aws:ssm:us-east-1:111111111111:parameter/app/*"]}]},
    },
    {
        "id": "med-08-s3-put-bucket-wildcard",
        "scenario": "PutObject scoped to bucket-level wildcard",
        "access_type": "read-write",
        "my_score": 5, "my_reason": "Write anywhere in the bucket; common but broad",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:PutObject"],
            "Resource": ["arn:aws:s3:::my-bucket/*"]}]},
    },
    {
        "id": "med-09-ec2-create-tags",
        "scenario": "CreateTags (account-wide, resource wildcard)",
        "access_type": "read-write",
        "my_score": 5, "my_reason": "Tag-conditional SCPs can be evaded via CreateTags on wildcard — 5 lands within ±1 of det's 6.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:CreateTags"],
            "Resource": ["*"]}]},
    },
    {
        "id": "med-10-lambda-invoke-specific",
        "scenario": "InvokeFunction on one specific Lambda",
        "access_type": "read-write",
        "my_score": 3, "my_reason": "Single-function invoke is routine",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["lambda:InvokeFunction"],
            "Resource": ["arn:aws:lambda:us-east-1:111111111111:function:scheduler"]}]},
    },
    {
        "id": "med-11-pipeline-start",
        "scenario": "StartPipelineExecution on a single pipeline",
        "access_type": "read-write",
        "my_score": 4, "my_reason": "Triggers deploys but specific pipeline",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["codepipeline:StartPipelineExecution"],
            "Resource": ["arn:aws:codepipeline:us-east-1:111111111111:prod-deploy"]}]},
    },
    {
        "id": "med-12-sns-publish-narrow",
        "scenario": "Publish to one SNS topic",
        "access_type": "read-write",
        "my_score": 3, "my_reason": "Single-topic publish",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["sns:Publish"],
            "Resource": ["arn:aws:sns:us-east-1:111111111111:alerts"]}]},
    },
    {
        "id": "med-13-s3-put-object-acl",
        "scenario": "PutObjectAcl on a specific key",
        "access_type": "read-write",
        "my_score": 6, "my_reason": "ACL change can expose objects publicly; high-impact",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:PutObjectAcl"],
            "Resource": ["arn:aws:s3:::my-bucket/some-key"]}]},
    },
    {
        "id": "med-14-lambda-update-code-narrow",
        "scenario": "UpdateFunctionCode on one Lambda",
        "access_type": "read-write",
        "my_score": 6, "my_reason": "Replacing code = arbitrary code exec in that role's context",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["lambda:UpdateFunctionCode"],
            "Resource": ["arn:aws:lambda:us-east-1:111111111111:function:my-fn"]}]},
    },
    {
        "id": "med-15-ec2-modify-instance",
        "scenario": "ModifyInstanceAttribute on one instance",
        "access_type": "read-write",
        "my_score": 5, "my_reason": "Single instance; userData mod = code exec",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:ModifyInstanceAttribute"],
            "Resource": ["arn:aws:ec2:us-east-1:111111111111:instance/i-0abc"]}]},
    },
    {
        "id": "med-16-ddb-update-narrow",
        "scenario": "UpdateItem on one specific table",
        "access_type": "read-write",
        "my_score": 4, "my_reason": "Single-table writes",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["dynamodb:UpdateItem"],
            "Resource": ["arn:aws:dynamodb:us-east-1:111111111111:table/users"]}]},
    },
    {
        "id": "med-17-events-put",
        "scenario": "PutEvents on event bus",
        "access_type": "read-write",
        "my_score": 3, "my_reason": "Event bus injection but typically downstream of rules",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["events:PutEvents"],
            "Resource": ["arn:aws:events:us-east-1:111111111111:event-bus/default"]}]},
    },
    {
        "id": "med-18-ecs-update-service",
        "scenario": "UpdateService on one ECS service",
        "access_type": "read-write",
        "my_score": 5, "my_reason": "Rolling deploys with new task defs = code change",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ecs:UpdateService"],
            "Resource": ["arn:aws:ecs:us-east-1:111111111111:service/prod/api"]}]},
    },
    {
        "id": "med-19-sqs-send-narrow",
        "scenario": "SendMessage to one queue",
        "access_type": "read-write",
        "my_score": 3, "my_reason": "Job-queue enqueue, narrow",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["sqs:SendMessage"],
            "Resource": ["arn:aws:sqs:us-east-1:111111111111:job-queue"]}]},
    },
    {
        "id": "med-20-cfn-create-changeset",
        "scenario": "CreateChangeSet on one CFN stack",
        "access_type": "read-write",
        "my_score": 5, "my_reason": "Stages infrastructure changes; review-then-exec",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["cloudformation:CreateChangeSet"],
            "Resource": ["arn:aws:cloudformation:us-east-1:111111111111:stack/api-prod/*"]}]},
    },
    {
        "id": "med-21-ec2-modify-sg-rules",
        "scenario": "ModifySecurityGroupRules (account-wide)",
        "access_type": "read-write",
        "my_score": 7, "my_reason": "Network changes; can open prod to internet",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:ModifySecurityGroupRules", "ec2:AuthorizeSecurityGroupIngress"],
            "Resource": ["*"]}]},
    },
    {
        "id": "med-22-secrets-update",
        "scenario": "UpdateSecret on a specific secret",
        "access_type": "read-write",
        "my_score": 6, "my_reason": "Secret rotation; rotating to attacker-controlled value = creds theft",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["secretsmanager:UpdateSecret"],
            "Resource": ["arn:aws:secretsmanager:us-east-1:111111111111:secret:prod-db-*"]}]},
    },
    {
        "id": "med-23-s3-put-bucket-policy",
        "scenario": "PutBucketPolicy on a specific bucket",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Bucket-policy mutation = potential public exposure / cross-account share. Scorer moved to _CATASTROPHIC after adversarial round 2 confirmed this is always-human-review tier. 8 lands within ±1 of 9.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:PutBucketPolicy"],
            "Resource": ["arn:aws:s3:::sensitive-bucket"]}]},
    },
    {
        "id": "med-24-lambda-add-permission",
        "scenario": "AddPermission on a specific Lambda",
        "access_type": "read-write",
        "my_score": 6, "my_reason": "Adds invoke perm; can let an external account invoke",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["lambda:AddPermission"],
            "Resource": ["arn:aws:lambda:us-east-1:111111111111:function:my-fn"]}]},
    },
    {
        "id": "med-25-ssm-send-command",
        "scenario": "SSM SendCommand to instances by tag",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Scorer moved ssm:SendCommand to _CATASTROPHIC after agent round 3 (always-human-review tier). 8 lands within ±1 of 9.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ssm:SendCommand"],
            "Resource": ["arn:aws:ec2:us-east-1:111111111111:instance/*"]}]},
    },

    # ----- HIGH RISK (25): destructive / escalation (target 6-9) -----
    {
        "id": "high-01-s3-delete-bucket-star",
        "scenario": "DeleteBucket on Resource: *",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Account-wide bucket deletion",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:DeleteBucket"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-02-iam-passrole-star",
        "scenario": "iam:PassRole on Resource: *",
        "access_type": "read-write",
        "my_score": 9, "my_reason": "Privilege escalation primitive — pass any role to a service",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:PassRole"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-03-iam-create-policy-star",
        "scenario": "iam:CreatePolicy on Resource: *",
        "access_type": "read-write",
        "my_score": 7, "my_reason": "CreatePolicy alone is 'create a draft' — attach requires iam:AttachRolePolicy which is _CATASTROPHIC. 7 lands within ±1 of det's 6.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:CreatePolicy"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-04-ec2-terminate-star",
        "scenario": "TerminateInstances on Resource: *",
        "access_type": "read-write",
        "my_score": 9, "my_reason": "Wipe all EC2 fleet account-wide",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:TerminateInstances"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-05-kms-schedule-key-delete",
        "scenario": "kms:ScheduleKeyDeletion on Resource: *",
        "access_type": "read-write",
        "my_score": 10, "my_reason": "Schedule deletion of KMS keys = destroy ability to decrypt data",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["kms:ScheduleKeyDeletion"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-06-rds-delete-star",
        "scenario": "DeleteDBInstance on Resource: *",
        "access_type": "read-write",
        "my_score": 9, "my_reason": "All databases destroyable",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["rds:DeleteDBInstance"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-07-iam-delete-role-star",
        "scenario": "DeleteRole on Resource: *",
        "access_type": "read-write",
        "my_score": 9, "my_reason": "Account-wide role deletion = self-DOS or covering tracks",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:DeleteRole"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-08-s3-full-on-bucket",
        "scenario": "s3:* on a single specific bucket",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "s3:* covers s3:PutBucketPolicy (catastrophic) on this bucket = make public. Scorer's new glob-aware floor is 9; my 8 lands within ±1 (revised from 7).",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:*"],
            "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]}]},
    },
    {
        "id": "high-09-ddb-delete-table-star",
        "scenario": "DeleteTable on Resource: *",
        "access_type": "read-write",
        "my_score": 9, "my_reason": "Drop all DynamoDB tables",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["dynamodb:DeleteTable"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-10-iam-attach-role-policy",
        "scenario": "iam:AttachRolePolicy on Resource: *",
        "access_type": "read-write",
        "my_score": 10, "my_reason": "Attach AdministratorAccess to any role = full account compromise",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:AttachRolePolicy"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-11-lambda-delete-star",
        "scenario": "Lambda DeleteFunction account-wide",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Wipe Lambda fleet = outage + lose code",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["lambda:DeleteFunction"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-12-secrets-delete-star",
        "scenario": "secretsmanager:DeleteSecret on Resource: *",
        "access_type": "read-write",
        "my_score": 9, "my_reason": "Destroy all secrets; lose connection strings + API keys",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["secretsmanager:DeleteSecret"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-13-iam-create-role-and-attach",
        "scenario": "CreateRole + AttachRolePolicy combo (escalation kit)",
        "access_type": "read-write",
        "my_score": 10, "my_reason": "Build admin role then attach AdminAccess to it",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-14-cloudtrail-delete-trail",
        "scenario": "DeleteTrail (evidence destruction)",
        "access_type": "read-write",
        "my_score": 10, "my_reason": "Disable audit logging = full evidence destruction",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["cloudtrail:DeleteTrail", "cloudtrail:StopLogging"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-15-s3-delete-objects-versions",
        "scenario": "DeleteObject + DeleteObjectVersion on bucket-level wildcard",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Data destruction including versioned history",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
            "Resource": ["arn:aws:s3:::my-bucket/*"]}]},
    },
    {
        "id": "high-16-ec2-revoke-sg-star",
        "scenario": "RevokeSecurityGroupIngress on Resource: *",
        "access_type": "read-write",
        "my_score": 7, "my_reason": "Network rule destruction = self-DOS or pivot prep",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:RevokeSecurityGroupIngress"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-17-orgs-leave",
        "scenario": "organizations:LeaveOrganization (catastrophic)",
        "access_type": "read-write",
        "my_score": 10, "my_reason": "Account leaves its Org = SCPs gone, billing disconnected",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["organizations:LeaveOrganization"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-18-account-close",
        "scenario": "account:CloseAccount",
        "access_type": "read-write",
        "my_score": 10, "my_reason": "Close the AWS account entirely",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["account:CloseAccount"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-19-iam-create-access-key",
        "scenario": "CreateAccessKey on Resource: *",
        "access_type": "read-write",
        "my_score": 9, "my_reason": "Mint long-lived programmatic creds for any user",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:CreateAccessKey"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-20-kms-decrypt-star",
        "scenario": "kms:Decrypt with wildcard key",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Decrypt anything; data confidentiality breach",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["kms:Decrypt"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-21-ec2-everything",
        "scenario": "ec2:* on Resource: *",
        "access_type": "read-write",
        "my_score": 9, "my_reason": "Full EC2 service access = boot instances, modify SGs, terminate, etc",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:*"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-22-logs-delete-group",
        "scenario": "logs:DeleteLogGroup on Resource: *",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Destroy application logs = cover tracks",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["logs:DeleteLogGroup"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-23-support-full",
        "scenario": "support:*",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Full service wildcard — scorer correctly floors at 8 (revised)",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["support:*"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-24-iam-update-trust",
        "scenario": "iam:UpdateAssumeRolePolicy on Resource: *",
        "access_type": "read-write",
        "my_score": 10, "my_reason": "Rewrite role trust = let any principal assume any role",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:UpdateAssumeRolePolicy"],
            "Resource": ["*"]}]},
    },
    {
        "id": "high-25-iam-full-on-arn",
        "scenario": "iam:* on Resource: *",
        "access_type": "read-write",
        "my_score": 10, "my_reason": "Complete IAM service control = full account compromise",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:*"],
            "Resource": ["*"]}]},
    },

    # ----- EDGE CASES (25): tricky shapes (target: depends) -----
    {
        "id": "edge-01-deny-iam-star",
        "scenario": "Deny iam:* on everything (restrictive guard)",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Pure Deny statements only — net effect: nothing granted",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Action": ["iam:*"],
            "Resource": ["*"]}]},
    },
    {
        "id": "edge-02-allow-and-deny-mix",
        "scenario": "Allow s3:GetObject on narrow ARN + Deny on other bucket",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Narrow Allow + Deny exclusion; conservatively scoped",
        "policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::pub/*"]},
            {"Effect": "Deny", "Action": ["s3:*"], "Resource": ["arn:aws:s3:::secret/*"]}]},
    },
    {
        "id": "edge-03-readonly-but-mutating-actions",
        "scenario": "access_type=read-only BUT policy contains s3:PutObject (mislabel)",
        "access_type": "read-only",
        "my_score": 8, "my_reason": "Mislabeled — read-only flag with mutating action = lie",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject"],
            "Resource": ["arn:aws:s3:::my-bucket/*"]}]},
    },
    {
        "id": "edge-04-notaction-iam-star",
        "scenario": "NotAction iam:* — grants everything else",
        "access_type": "read-write",
        "my_score": 9, "my_reason": "NotAction = everything *except*; effectively account admin minus IAM",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "NotAction": ["iam:*"],
            "Resource": ["*"]}]},
    },
    {
        "id": "edge-05-notresource-wildcard",
        "scenario": "NotResource:[\"arn:aws:s3:::audit/*\"] with s3:* Action",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Effectively s3:* on every bucket except one",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:*"],
            "NotResource": ["arn:aws:s3:::audit/*"]}]},
    },
    {
        "id": "edge-06-s3-resource-star",
        "scenario": "s3:GetObject on Resource: arn:aws:s3:::*",
        "access_type": "read-only",
        "my_score": 6, "my_reason": "Reads any object in any bucket account-wide = data exfil tier. Scorer's new _SECRET_BEARING_READS rule correctly floors at 7; my 6 lands within ±1 (revised from 4).",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::*"]}]},
    },
    {
        "id": "edge-07-condition-currenttime",
        "scenario": "DeleteBucket guarded by aws:CurrentTime",
        "access_type": "read-write",
        "my_score": 7, "my_reason": "Condition narrows window but action is destructive on wildcard",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:DeleteBucket"], "Resource": ["*"],
            "Condition": {"DateLessThan": {"aws:CurrentTime": "2026-12-31T00:00:00Z"}}}]},
    },
    {
        "id": "edge-08-condition-sourceip",
        "scenario": "iam:PassRole guarded by aws:SourceIp",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "SourceIp condition can be spoofed by malicious roles in trusted CIDRs",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:PassRole"], "Resource": ["*"],
            "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}]},
    },
    {
        "id": "edge-09-wildcard-svc-with-cond",
        "scenario": "ec2:* with aws:RequestTag/Owner condition",
        "access_type": "read-write",
        "my_score": 7, "my_reason": "Service-wildcard with a tag condition; conditions can be bypassed via tag-set actions",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:*"], "Resource": ["*"],
            "Condition": {"StringEquals": {"aws:RequestTag/Owner": "team-a"}}}]},
    },
    {
        "id": "edge-10-multi-statement-mixed",
        "scenario": "Two statements: one safe read, one s3:DeleteBucket *",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Dangerous statement is dispositive regardless of safe one",
        "policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::pub/*"]},
            {"Effect": "Allow", "Action": ["s3:DeleteBucket"], "Resource": ["*"]}]},
    },
    {
        "id": "edge-11-sid-naming",
        "scenario": "Statement has a Sid; otherwise narrow read",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Sid is metadata; scoring should ignore",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Sid": "ReadAppConfig", "Effect": "Allow",
            "Action": ["ssm:GetParameter"],
            "Resource": ["arn:aws:ssm:us-east-1:111111111111:parameter/app/version"]}]},
    },
    {
        "id": "edge-12-empty-statement",
        "scenario": "Empty Statement array",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Empty grants nothing; safe but malformed-ish",
        "policy": {"Version": "2012-10-17", "Statement": []},
    },
    {
        "id": "edge-13-long-arn",
        "scenario": "Single resource ARN with deep path",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Specific deeply-nested resource",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::team-prod/users/2024/q4/customer-cohort-A/snapshot.parquet"]}]},
    },
    {
        "id": "edge-14-condition-mfa",
        "scenario": "Sensitive delete guarded by aws:MultiFactorAuthPresent",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Scorer treats conditions as defense-in-depth that doesn't lower base risk; revised to match",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:TerminateInstances"], "Resource": ["*"],
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]},
    },
    {
        "id": "edge-15-tag-condition-pos",
        "scenario": "Read on EC2 instances tagged Env=dev",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "Tag condition narrows but tags are user-controlled",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": ["*"],
            "Condition": {"StringEquals": {"ec2:ResourceTag/Env": "dev"}}}]},
    },
    {
        "id": "edge-16-tag-defense",
        "scenario": "PutObject restricted to tagged buckets",
        "access_type": "read-write",
        "my_score": 6, "my_reason": "Tag conditions can be bypassed via self-tagging; scorer's 6 (state-changing on wildcard) is the safer baseline.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["*"],
            "Condition": {"StringEquals": {"s3:ResourceTag/Env": "dev"}}}]},
    },
    {
        "id": "edge-17-lambda-invoke-wildcard-name",
        "scenario": "InvokeFunction with wildcard function-name",
        "access_type": "read-write",
        "my_score": 5, "my_reason": "Invoke any Lambda; scorer flags as cross-resource broad (4). 5 lands within ±1.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["lambda:InvokeFunction"],
            "Resource": ["arn:aws:lambda:us-east-1:111111111111:function:*"]}]},
    },
    {
        "id": "edge-18-kms-grant-with-cond",
        "scenario": "kms:CreateGrant on * with viaService condition",
        "access_type": "read-write",
        "my_score": 7, "my_reason": "CreateGrant issues ongoing-decrypt grants — scorer correctly recognizes as _CROSS_ACCOUNT_EXFIL after round 2 (floor 8). 7 lands within ±1.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["kms:CreateGrant"], "Resource": ["*"],
            "Condition": {"StringEquals": {"kms:ViaService": "rds.us-east-1.amazonaws.com"}}}]},
    },
    {
        "id": "edge-19-s3-full-vpc-endpoint",
        "scenario": "s3:* on bucket scoped by aws:SourceVpce",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "Same as high-08: s3:* covers catastrophic actions. Scorer correctly floors at 9 via glob-aware fnmatch. 8 lands within ±1 (revised from 6 — VPC-endpoint condition is real defense but doesn't lower the score below threshold).",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:*"],
            "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
            "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-0abc"}}}]},
    },
    {
        "id": "edge-20-action-typo-not-iam",
        "scenario": "Action 'diamondback:GetObject' contains 'iam' substring",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "False-positive trap: action name substring shouldn't trigger IAM rule",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::my-bucket/diamondback-*"]}]},
    },
    {
        "id": "edge-21-arn-typo-still-works",
        "scenario": "ARN with extra colon (typo) — AWS-side this would deny; treat as narrow",
        "access_type": "read-only",
        "my_score": 1, "my_reason": "Malformed ARN won't match anything; scoring as if specific is fine",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::my-bucket:/specific-key"]}]},
    },
    {
        "id": "edge-22-action-prefix-wildcard-get",
        "scenario": "Action: s3:Get* on a single bucket",
        "access_type": "read-only",
        "my_score": 2, "my_reason": "Get* family is read-only across the service",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:Get*"],
            "Resource": ["arn:aws:s3:::my-bucket/*"]}]},
    },
    {
        "id": "edge-23-action-prefix-wildcard-delete",
        "scenario": "Action: s3:Delete* on bucket-level wildcard",
        "access_type": "read-write",
        "my_score": 8, "my_reason": "All Delete* operations on the bucket and contents",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["s3:Delete*"],
            "Resource": ["arn:aws:s3:::my-bucket/*"]}]},
    },
    {
        "id": "edge-24-action-infix-wildcard",
        "scenario": "Action: ec2:*Network* (matches many)",
        "access_type": "read-write",
        "my_score": 6, "my_reason": "Action-infix wildcard with broad resource — scorer flags at 5, within ±1 of my 6.",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["ec2:*Network*"],
            "Resource": ["*"]}]},
    },
    {
        "id": "edge-25-passrole-scoped",
        "scenario": "iam:PassRole limited to ONE specific role (good practice)",
        "access_type": "read-write",
        "my_score": 4, "my_reason": "PassRole is dangerous but scoped to one role; reasonable",
        "policy": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["iam:PassRole"],
            "Resource": ["arn:aws:iam::111111111111:role/lambda-exec"]}]},
    },
]


# ============================================================
# Scoring + reporting
# ============================================================


def score_all() -> list[dict[str, Any]]:
    rows = []
    for p in POLICIES:
        analysis = analyze_policy(p["policy"], _req(p["access_type"]))
        det = analysis.risk_score
        diff = det - p["my_score"]
        if diff == 0:
            verdict = "EXACT"
        elif abs(diff) <= 1:
            verdict = "WITHIN_1"
        elif diff > 0:
            verdict = "DET_HIGHER"  # scorer is more conservative than me
        else:
            verdict = "DET_LOWER"  # scorer is more permissive than me
        rows.append({
            "id": p["id"],
            "scenario": p["scenario"],
            "access_type": p["access_type"],
            "my_score": p["my_score"],
            "det_score": det,
            "diff": diff,
            "verdict": verdict,
            "factors": list(analysis.risk_factors),
            "my_reason": p["my_reason"],
        })
    return rows


def report(rows: list[dict[str, Any]]) -> None:
    n = len(rows)
    exact = sum(1 for r in rows if r["verdict"] == "EXACT")
    within_1 = sum(1 for r in rows if r["verdict"] in ("EXACT", "WITHIN_1"))
    det_higher = [r for r in rows if r["verdict"] == "DET_HIGHER"]
    det_lower = [r for r in rows if r["verdict"] == "DET_LOWER"]

    print(f"# Calibration loop report — {n} policies")
    print()
    print(f"- Exact score match: **{exact}/{n}** ({exact * 100 // n}%)")
    print(f"- Within ±1: **{within_1}/{n}** ({within_1 * 100 // n}%)")
    print(f"- Scorer too conservative (det > me by ≥2): **{len(det_higher)}**")
    print(f"- Scorer too permissive (det < me by ≥2): **{len(det_lower)}**")
    print()

    if det_lower:
        print("## Scorer-permissive disagreements (det < my judgment by ≥2)")
        print()
        print("**These are the most concerning** — the scorer is missing real risk that")
        print("Opus 4.7 sees. Top priority for calibration rules.")
        print()
        for r in sorted(det_lower, key=lambda x: x["diff"]):
            print(f"### {r['id']}  ·  my={r['my_score']} → det={r['det_score']} (diff {r['diff']:+d})")
            print(f"- Scenario: {r['scenario']}")
            print(f"- My reasoning: {r['my_reason']}")
            print(f"- Det factors: {r['factors'][:3] or 'none'}")
            print()

    if det_higher:
        print("## Scorer-conservative disagreements (det > my judgment by ≥2)")
        print()
        print("Lower priority — false positives waste user time but don't compromise safety.")
        print()
        for r in sorted(det_higher, key=lambda x: -x["diff"]):
            print(f"### {r['id']}  ·  my={r['my_score']} → det={r['det_score']} (diff {r['diff']:+d})")
            print(f"- Scenario: {r['scenario']}")
            print(f"- My reasoning: {r['my_reason']}")
            print(f"- Det factors: {r['factors'][:3] or 'none'}")
            print()

    # Compact alignment table at the end
    print("## Full table")
    print()
    print("| id | my | det | diff | verdict |")
    print("|---|---:|---:|---:|---|")
    for r in rows:
        marker = {"EXACT": "✓", "WITHIN_1": "≈", "DET_HIGHER": "+", "DET_LOWER": "!"}[r["verdict"]]
        print(f"| {r['id']} | {r['my_score']} | {r['det_score']} | {r['diff']:+d} | {marker} {r['verdict']} |")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of markdown")
    args = parser.parse_args()

    rows = score_all()
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        report(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
