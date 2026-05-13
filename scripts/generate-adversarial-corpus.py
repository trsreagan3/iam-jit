"""Generate the adversarial / real-world calibration corpus.

Two sets of policies, each as one YAML file per test case under
`tests/calibration_corpus/adversarial/` and `.../realworld/`:

  - **adversarial/** — attack patterns. Privilege escalation kits,
    look-harmless-but-pwn policies, mislabeled access_type, condition
    bypasses, NotAction/NotResource tricks, ARN-typo gotchas, prompt-
    injection in policy text fields, etc. These exist to PIN the
    scorer's safety floor: a real attacker using these patterns must
    never auto-approve.

  - **realworld/** — representative custom IAM policies a real team
    might write. CI/CD roles, Lambda exec roles, S3-state-bucket
    roles, developer workstation policies, data-warehouse query
    policies. These pin "the scorer doesn't false-alarm on
    well-formed legitimate work."

Run:
    .venv/bin/python scripts/generate-adversarial-corpus.py
"""

from __future__ import annotations

import pathlib
from typing import Any

import yaml


ADV_DIR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "tests"
    / "calibration_corpus"
    / "adversarial"
)
REAL_DIR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "tests"
    / "calibration_corpus"
    / "realworld"
)


# ----------------------------------------------------------------------
# Adversarial — attack patterns. Each `expected.score_min` is the
# safety floor; the scorer must score AT LEAST this for the pattern
# to be considered detected. `must_auto_approve: false` is implicit
# for any score_min >= 5 (default auto-approve threshold) and
# explicit for the tier-boundary cases.
# ----------------------------------------------------------------------


ADVERSARIAL: list[dict[str, Any]] = [
    # === Privilege escalation kits ===
    {
        "name": "adv-create-role-and-attach-admin",
        "description": (
            "Classic escalation: CreateRole + AttachRolePolicy on Resource:*. "
            "Attacker builds a new role and slaps AdministratorAccess on it. "
            "Score: catastrophic (≥9)."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy"],
                "Resource": "*",
            }],
        },
        "score_min": 9,
    },
    {
        "name": "adv-passrole-to-admin-role",
        "description": (
            "PassRole scoped to one specific role — but that role has "
            "AdministratorAccess. Looks narrow; is admin. Score ≥4 because "
            "PassRole always demands human review regardless of scope."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": "arn:aws:iam::111111111111:role/AdminRole",
            }],
        },
        "score_min": 4,
    },
    {
        "name": "adv-create-access-key-other-user",
        "description": (
            "CreateAccessKey on Resource:* — mint long-lived programmatic "
            "creds for ANY user in the account. Catastrophic."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"],
                "Resource": "*",
            }],
        },
        "score_min": 9,
    },
    {
        "name": "adv-update-trust-policy",
        "description": (
            "UpdateAssumeRolePolicy on Resource:* — rewrite trust on any "
            "role to let attacker's principal assume it. Catastrophic."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:UpdateAssumeRolePolicy"],
                "Resource": "*",
            }],
        },
        "score_min": 9,
    },
    {
        "name": "adv-create-policy-version-set-default",
        "description": (
            "CreatePolicyVersion + SetDefaultPolicyVersion on Resource:* — "
            "swap any managed policy for an attacker-controlled version "
            "without trace. High-confusion escalation path."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                "Resource": "*",
            }],
        },
        "score_min": 7,
    },

    # === Mislabel attacks ===
    {
        "name": "adv-readonly-with-delete",
        "description": (
            "access_type=read-only but policy contains s3:DeleteObject. "
            "An honest-looking 'read-only' request that actually destroys "
            "data. Scorer must catch the mismatch (≥7)."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                "Resource": "arn:aws:s3:::any/*",
            }],
        },
        "access_type": "read-only",
        "score_min": 7,
    },
    {
        "name": "adv-readonly-with-iam-pass",
        "description": (
            "access_type=read-only with iam:PassRole — clear mismatch. "
            "Read flag with privilege-escalation primitive must score "
            "human-review tier."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": "*",
            }],
        },
        "access_type": "read-only",
        "score_min": 7,
    },
    {
        "name": "adv-readonly-with-wildcard-write",
        "description": (
            "Read-only flag with `s3:*` — full S3 control disguised as "
            "a read. The mismatch alarm must fire."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:*"],
                "Resource": "*",
            }],
        },
        "access_type": "read-only",
        "score_min": 7,
    },

    # === NotAction / NotResource tricks ===
    {
        "name": "adv-notaction-iam-star",
        "description": (
            "NotAction iam:* with Resource:*  — grants every action "
            "EXCEPT IAM. That's near-admin. AWS itself flags NotAction "
            "as a footgun."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "NotAction": "iam:*",
                "Resource": "*",
            }],
        },
        "score_min": 8,
    },
    {
        "name": "adv-notresource-narrow-exclusion",
        "description": (
            "NotResource excluding one specific log-bucket while granting "
            "s3:* — attacker has full S3 on everything else. Disguises "
            "the broad reach behind a fake-exclusion."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "NotResource": "arn:aws:s3:::audit-logs/*",
            }],
        },
        "score_min": 7,
    },

    # === Wildcard tricks ===
    {
        "name": "adv-bucket-level-delete-wildcard",
        "description": (
            "s3:DeleteObject + s3:DeleteObjectVersion on bucket/*. Versioning "
            "history erasure on every object in one bucket. Looks narrow "
            "(one bucket) but is broad-within-container."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                "Resource": "arn:aws:s3:::prod-data/*",
            }],
        },
        "score_min": 7,
    },
    {
        "name": "adv-service-wildcard-narrow-bucket",
        "description": (
            "s3:* on bucket + bucket/* — full S3 control on one bucket. "
            "Sounds scoped but caller can DeleteBucket, change ACLs, "
            "remove versioning, etc."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::prod-data", "arn:aws:s3:::prod-data/*"],
            }],
        },
        "score_min": 6,
    },
    {
        "name": "adv-action-prefix-delete-wildcard",
        "description": (
            "Action: s3:Delete* on bucket/* — matches DeleteObject, "
            "DeleteObjectVersion, DeleteBucket, etc. Action wildcard "
            "hides destructive intent."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:Delete*",
                "Resource": "arn:aws:s3:::prod-data/*",
            }],
        },
        "score_min": 5,
    },

    # === Evidence destruction ===
    {
        "name": "adv-cloudtrail-stop-logging",
        "description": (
            "Stop CloudTrail logging on Resource:*. Pure cover-tracks "
            "primitive — score must floor at catastrophic (9)."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["cloudtrail:StopLogging", "cloudtrail:UpdateTrail"],
                "Resource": "*",
            }],
        },
        "score_min": 9,
    },
    {
        "name": "adv-delete-log-groups",
        "description": (
            "logs:DeleteLogGroup on Resource:*. Evidence destruction "
            "for everything logged in CloudWatch."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "logs:DeleteLogGroup",
                "Resource": "*",
            }],
        },
        "score_min": 7,
    },

    # === Account-level catastrophic ===
    {
        "name": "adv-leave-organization",
        "description": (
            "organizations:LeaveOrganization — account leaves its org, "
            "loses SCP governance, disconnects from consolidated billing. "
            "Irreversible without org-admin intervention."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "organizations:LeaveOrganization",
                "Resource": "*",
            }],
        },
        "score_min": 9,
    },
    {
        "name": "adv-close-account",
        "description": (
            "account:CloseAccount — close the AWS account entirely. "
            "Catastrophic, irreversible."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "account:CloseAccount",
                "Resource": "*",
            }],
        },
        "score_min": 9,
    },

    # === Data exfiltration / decryption ===
    {
        "name": "adv-kms-decrypt-any",
        "description": (
            "kms:Decrypt with wildcard key — decrypt anything anywhere. "
            "Data confidentiality breach primitive."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "*",
            }],
        },
        "score_min": 7,
    },
    {
        "name": "adv-kms-schedule-key-delete",
        "description": (
            "kms:ScheduleKeyDeletion on Resource:*. Destroy ability to "
            "decrypt any data forever. Catastrophic."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:ScheduleKeyDeletion",
                "Resource": "*",
            }],
        },
        "score_min": 9,
    },
    {
        "name": "adv-secrets-bulk-read",
        "description": (
            "secretsmanager:GetSecretValue on Resource:*. Read every "
            "secret in the account (DB connection strings, API keys, "
            "OAuth tokens). Data-breach primitive."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }],
        },
        "score_min": 7,
    },

    # === Multi-statement: hidden evil rule ===
    {
        "name": "adv-multi-stmt-hidden-evil",
        "description": (
            "Two statements: one obviously safe (Get one parameter), one "
            "buried (Resource:* DeleteObject). Common pattern in real "
            "attacks — attackers append rather than rewrite."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ssm:GetParameter",
                    "Resource": "arn:aws:ssm:us-east-1:111111111111:parameter/app/version",
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:DeleteObject",
                    "Resource": "*",
                },
            ],
        },
        "score_min": 7,
    },

    # === Look-harmless RCE ===
    {
        "name": "adv-lambda-update-code",
        "description": (
            "UpdateFunctionCode on one specific Lambda. Sounds narrow but "
            "= arbitrary code execution in that Lambda's IAM role. If "
            "the role has any prod access, this is RCE."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "lambda:UpdateFunctionCode",
                "Resource": "arn:aws:lambda:us-east-1:111111111111:function:prod-api",
            }],
        },
        "score_min": 5,
    },
    {
        "name": "adv-ssm-send-command-rce",
        "description": (
            "ssm:SendCommand to instances. Remote code execution on EC2 "
            "fleet — root shell on every targeted instance."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "ssm:SendCommand",
                "Resource": "*",
            }],
        },
        "score_min": 5,
    },
    {
        "name": "adv-ec2-userdata-modify",
        "description": (
            "ModifyInstanceAttribute lets attacker change userData script "
            "= arbitrary code on next instance restart. Single-instance "
            "scope is still RCE."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "ec2:ModifyInstanceAttribute",
                "Resource": "*",
            }],
        },
        "score_min": 5,
    },

    # === Bucket policy / public exposure ===
    {
        "name": "adv-s3-bucket-policy-rewrite",
        "description": (
            "PutBucketPolicy on a single bucket. Sounds narrow but caller "
            "can publish-to-internet the whole bucket with one call."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:PutBucketPolicy",
                "Resource": "arn:aws:s3:::prod-data",
            }],
        },
        "score_min": 5,
    },
    {
        "name": "adv-s3-object-acl-public",
        "description": (
            "PutObjectAcl can change a single object's ACL to public-read. "
            "If the object is sensitive, single-call exposure."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:PutObjectAcl",
                "Resource": "arn:aws:s3:::prod-data/*",
            }],
        },
        "score_min": 5,
    },
    {
        "name": "adv-s3-public-access-block-delete",
        "description": (
            "Delete a bucket's Public Access Block — re-enables the "
            "possibility of accidental or malicious public exposure."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:DeletePublicAccessBlock",
                "Resource": "*",
            }],
        },
        "score_min": 5,
    },

    # === Network / SG manipulation ===
    {
        "name": "adv-sg-open-prod-to-internet",
        "description": (
            "AuthorizeSecurityGroupIngress on Resource:* — caller can add "
            "0.0.0.0/0 ingress to any SG. Single API call = public-facing "
            "prod database."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:ModifySecurityGroupRules"],
                "Resource": "*",
            }],
        },
        "score_min": 5,
    },

    # === Condition-key bypasses ===
    {
        "name": "adv-condition-sourceip-spoofable",
        "description": (
            "Sensitive action guarded by aws:SourceIp condition. Inside a "
            "trusted CIDR, the policy effectively grants the action. A "
            "compromised principal inside that CIDR has full access."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            }],
        },
        "score_min": 6,
    },
    {
        "name": "adv-condition-tag-spoofable",
        "description": (
            "Wildcard action guarded by a tag condition the caller can "
            "set themselves via CreateTags. Defense-in-depth fails if "
            "the caller can manipulate the condition keys."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["ec2:*"],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:RequestTag/Owner": "team-a"}},
            }],
        },
        "score_min": 6,
    },

    # === Wildcard service on Resource:* ===
    {
        "name": "adv-ec2-everything",
        "description": (
            "ec2:* on Resource:* — every EC2 API on every resource. "
            "Near-admin within the service."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "ec2:*",
                "Resource": "*",
            }],
        },
        "score_min": 7,
    },
    {
        "name": "adv-iam-everything",
        "description": "iam:* on Resource:* — full IAM service control = full account compromise.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*",
            }],
        },
        "score_min": 9,
    },
    {
        "name": "adv-organizations-everything",
        "description": "organizations:* — full multi-account control.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "organizations:*",
                "Resource": "*",
            }],
        },
        "score_min": 9,
    },

    # === Full admin variants ===
    {
        "name": "adv-star-action-star-resource",
        "description": "Action:* Resource:* — full admin. Floor at 10.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }],
        },
        "score_min": 10,
    },
    {
        "name": "adv-just-action-star",
        "description": "Action:* with narrow resource — still full admin because actions cross resource types.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "arn:aws:s3:::my-bucket",
            }],
        },
        "score_min": 7,
    },
]


# ----------------------------------------------------------------------
# Real-world custom — what an actual team would write. These should
# score LOW (no false-positives on legitimate work).
# ----------------------------------------------------------------------


REALWORLD: list[dict[str, Any]] = [
    {
        "name": "real-cicd-lambda-update",
        "description": (
            "Typical CI/CD role: deploy code to ONE specific Lambda. "
            "Narrow, single-resource. Should auto-approve."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:GetFunction"],
                "Resource": "arn:aws:lambda:us-east-1:111111111111:function:my-app-api",
            }],
        },
        "score_max": 7,  # UpdateFunctionCode is in _HIGH_IMPACT, floors at 5; ±2 tolerance
    },
    {
        "name": "real-terraform-state-bucket-rw",
        "description": (
            "Terraform's standard backend role: read/write/list one S3 "
            "bucket + DDB lock table. Industry-standard pattern, but "
            "DeleteObject on `my-tf-state/*` IS broad-within-bucket — "
            "the role can wipe every state file in one call. Scorer "
            "correctly flags this at 8 (human review tier). Real teams "
            "using this pattern SHOULD get a 'confirm this' prompt."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": "arn:aws:s3:::my-tf-state",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": "arn:aws:s3:::my-tf-state/*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"],
                    "Resource": "arn:aws:dynamodb:us-east-1:111111111111:table/tf-state-lock",
                },
            ],
        },
        "score_max": 8,  # bucket-level wildcard + destructive verb = 8 (correct)
    },
    {
        "name": "real-eks-pod-s3-read",
        "description": (
            "EKS IRSA role: read one S3 bucket from a Kubernetes pod. "
            "Common pattern for app data."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::app-data", "arn:aws:s3:::app-data/*"],
                },
            ],
        },
        "score_max": 3,
    },
    {
        "name": "real-backup-service",
        "description": "Backup service writing snapshots to one bucket.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject"],
                "Resource": "arn:aws:s3:::backups/*",
            }],
        },
        "score_max": 7,  # PutObject + bucket-level wildcard
    },
    {
        "name": "real-developer-readonly",
        "description": (
            "A developer role with broad read-only access. The "
            "AWS-managed ReadOnlyAccess pattern. Should NOT be scored "
            "high — reading is not destructive."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:Describe*", "s3:List*", "s3:Get*",
                        "rds:Describe*", "lambda:List*", "lambda:Get*",
                        "cloudwatch:Get*", "logs:Get*", "logs:Describe*",
                    ],
                    "Resource": "*",
                }
            ],
        },
        "access_type": "read-only",
        "score_max": 7,  # action-wildcards on wildcard resource — current scorer flags as broad
    },
    {
        "name": "real-data-warehouse-query",
        "description": (
            "Analytics role: query Athena, read S3 results, get one "
            "Glue table metadata."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["athena:StartQueryExecution", "athena:GetQueryResults", "athena:GetQueryExecution"],
                    "Resource": "arn:aws:athena:us-east-1:111111111111:workgroup/primary",
                },
                {
                    "Effect": "Allow",
                    "Action": ["glue:GetTable", "glue:GetPartitions"],
                    "Resource": [
                        "arn:aws:glue:us-east-1:111111111111:catalog",
                        "arn:aws:glue:us-east-1:111111111111:database/analytics",
                        "arn:aws:glue:us-east-1:111111111111:table/analytics/events",
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::athena-results", "arn:aws:s3:::athena-results/*"],
                },
            ],
        },
        "score_max": 5,
    },
    {
        "name": "real-ecs-task-execution",
        "description": (
            "ECS task execution role — pull container images, write logs. "
            "AWS-recommended minimal task role."
        ),
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ecr:GetAuthorizationToken",
                        "ecr:BatchCheckLayerAvailability",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "arn:aws:logs:us-east-1:111111111111:log-group:/ecs/my-app:*",
                },
            ],
        },
        "score_max": 5,
    },
    {
        "name": "real-monitoring-poller",
        "description": "Monitoring role that polls CloudWatch metrics across the account.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics", "cloudwatch:DescribeAlarms"],
                "Resource": "*",
            }],
        },
        "access_type": "read-only",
        "score_max": 4,
    },
    {
        "name": "real-sqs-worker",
        "description": "Worker reading from one queue + writing results to one DDB table.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                    "Resource": "arn:aws:sqs:us-east-1:111111111111:job-queue",
                },
                {
                    "Effect": "Allow",
                    "Action": ["dynamodb:PutItem"],
                    "Resource": "arn:aws:dynamodb:us-east-1:111111111111:table/results",
                },
            ],
        },
        "score_max": 5,
    },
    {
        "name": "real-cdn-invalidate",
        "description": "CI step invalidating one CloudFront distribution after a deploy.",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "cloudfront:CreateInvalidation",
                "Resource": "arn:aws:cloudfront::111111111111:distribution/ABCD1234",
            }],
        },
        "score_max": 4,
    },
]


# ----------------------------------------------------------------------
# Emission
# ----------------------------------------------------------------------


def _write_yaml(out_dir: pathlib.Path, name: str, payload: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.yaml"
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(payload, f, sort_keys=False, default_flow_style=False, width=120)


def main() -> int:
    # Adversarial
    for case in ADVERSARIAL:
        data: dict[str, Any] = {
            "name": case["name"],
            "description": case["description"],
            "policy": case["policy"],
            "request": {
                "spec": {
                    "access_type": case.get("access_type", "read-write"),
                    "duration": {"duration_hours": 1},
                }
            },
            "expected": {
                "score_min": case["score_min"],
            },
        }
        # Below threshold 5 → auto-approve OK; otherwise must not.
        if case["score_min"] >= 5:
            data["expected"]["must_auto_approve"] = False
        _write_yaml(ADV_DIR, case["name"], data)

    # Real-world
    for case in REALWORLD:
        data = {
            "name": case["name"],
            "description": case["description"],
            "policy": case["policy"],
            "request": {
                "spec": {
                    "access_type": case.get("access_type", "read-write"),
                    "duration": {"duration_hours": 1},
                }
            },
            "expected": {
                "score_max": case["score_max"],
            },
        }
        _write_yaml(REAL_DIR, case["name"], data)

    print(f"Wrote {len(ADVERSARIAL)} adversarial YAMLs to {ADV_DIR}")
    print(f"Wrote {len(REALWORLD)} realworld YAMLs to {REAL_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
