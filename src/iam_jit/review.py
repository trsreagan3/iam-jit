"""Approver-side risk analysis.

Given a draft policy, produce a 1-10 risk score, list of risk factors, and
optionally an LLM-generated narrative. The score is fully deterministic; the
LLM can only ADD a narrative explanation — it cannot raise or lower the score.

Rubric (deterministic):
  10  literal Action: "*" anywhere; or *:* + Resource: "*"
   9  iam:* (any wildcard within iam); iam:PassRole + Resource: "*"
   8  service:* on a sensitive service (kms, secretsmanager, organizations)
   7  service:* on a normal service; or specific high-risk action with Resource: "*"
   6  any action in a sensitive service with Resource: "*"
   5  multiple wildcard-bearing actions across services
   4  Resource: "*" with non-sensitive services only
   3  scoped resources with broad action sets (read+list across multiple services)
   2  read/list on specific resources
   1  read on a single specific resource
"""

from __future__ import annotations

import datetime as _dt
import functools
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from policy_sentry.querying.actions import get_actions_with_access_level

from . import audit

if TYPE_CHECKING:
    from .llm import LLMBackend


def is_review_enabled() -> bool:
    """Return True if the deployment is configured to surface risk reviews.

    Risk scoring is part of the AI-feature surface — even though the score
    is deterministically computed from the policy, we treat it as part of
    the AI analysis layer. Deployments running in NoAI mode (`IAM_JIT_LLM=
    none` or no LLM env vars set) explicitly opted out of AI feedback,
    so the score is suppressed there. This keeps NoAI mode a clean
    "schema validation only" experience.
    """
    from .llm import NoOpBackend, get_backend

    return not isinstance(get_backend(), NoOpBackend)

_SENSITIVE_SERVICES = frozenset(
    {
        # Original set: credential/identity surface
        "secretsmanager", "kms", "ssm", "iam", "organizations", "sts",
        # IAM Identity Center / SSO — minting cross-account admin
        # via PermissionSets + AccountAssignment is account-compromise
        # tier; the actions live under sso-admin and identitystore.
        "sso-admin", "identitystore",
        # Bedrock — LLM invocations + knowledge-base poisoning. Cost-
        # burn primitive (foundation-model tokens are expensive) AND
        # RAG-prompt-injection vector if the attacker can write to a
        # knowledge base that production agents query.
        "bedrock",
        # 2026-05-13 expansions (adversarial agent findings):
        # - ebs: EBS direct-snapshot access reads raw disk blocks
        # - acm-pca: private CA = mint any certificate
        # - cognito-idp / cognito-identity: user-pool admin = impersonate
        # - imagebuilder: AMI poisoning supply-chain primitive
        # - sagemaker: ML notebook RCE + IAM PassRole composition
        # - glue: ETL job RCE via job code substitution
        # - ses: send-as-prod-domain = phishing-as-the-org
        "ebs", "acm-pca", "cognito-idp", "cognito-identity",
        "imagebuilder", "sagemaker", "glue", "ses",
    }
)


# Actions that *create or execute code* and which, when paired with
# `iam:PassRole`, compose into "run arbitrary code as that role" —
# the textbook IAM privilege-escalation primitive. The scorer floors
# the COMBINATION at 8-9 (see the composition-rule pass below). Each
# action ALONE doesn't deserve the score; it's the pairing with
# PassRole that converts "create resource" into "RCE-as-role."
_CODE_EXECUTION_PRIMITIVES = frozenset(
    {
        # Lambda: code is uploaded by the caller; runs as the function's role
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:CreateFunctionUrlConfig",  # also opens public surface
        # EC2 + ECS: instance starts with a passed instance profile; the
        # instance metadata service exposes the role's credentials
        "ec2:RunInstances",
        "ecs:RunTask",
        "ecs:CreateService",
        # CodeBuild / CodePipeline: buildspec is caller-controlled
        "codebuild:CreateProject",
        "codebuild:StartBuild",
        # Glue / Athena: ETL job code is caller-controlled
        "glue:CreateJob",
        "glue:UpdateJob",
        "glue:StartJobRun",
        # SageMaker: notebook = Jupyter shell with the role's perms
        "sagemaker:CreateNotebookInstance",
        "sagemaker:CreatePresignedNotebookInstanceUrl",
        "sagemaker:CreateProcessingJob",
        "sagemaker:CreateTrainingJob",
        # Step Functions: state machine orchestrates calls under the role
        "states:CreateStateMachine",
        "states:UpdateStateMachine",
        # CloudFormation: template provisions arbitrary resources under role
        "cloudformation:CreateStack",
        "cloudformation:UpdateStack",
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
        # App Runner: containerized service runs under instance role
        "apprunner:CreateService",
        "apprunner:UpdateService",
        # Batch: job runs under task role
        "batch:SubmitJob",
        "batch:RegisterJobDefinition",
        # Bedrock agents — caller-defined action groups call attacker-
        # controlled Lambdas with whatever the agent decides
        "bedrock:CreateAgent",
        "bedrock:UpdateAgent",
        "bedrock:CreateAgentActionGroup",
        # SageMaker — newer surface beyond NotebookInstance; Domain +
        # UserProfile + PresignedDomainUrl chain = interactive shell
        "sagemaker:CreateDomain",
        "sagemaker:CreateUserProfile",
        "sagemaker:CreatePresignedDomainUrl",
        # EMR / EMR Serverless — Spark/Hadoop job runs under role
        "elasticmapreduce:RunJobFlow",
        "elasticmapreduce:AddJobFlowSteps",
        # ROUND 3 additions:
        # Lambda Layers — publish + update-function-configuration =
        # inject attacker code that the function loads on next cold start
        "lambda:PublishLayerVersion",
        "lambda:UpdateFunctionConfiguration",
        # Glue Dev Endpoints — Jupyter-like notebook environment
        "glue:CreateDevEndpoint",
        "glue:UpdateDevEndpoint",
        # MWAA / Airflow — DAG = caller-controlled Python that runs
        # under the environment role
        "airflow:CreateEnvironment",
        "airflow:UpdateEnvironment",
        # Service Catalog — provisions products (CFN templates) under
        # a role the launching user picks
        "servicecatalog:CreateProduct",
        "servicecatalog:ProvisionProduct",
        # CloudWatch Synthetics canaries — caller-controlled JS runs
        # on a schedule under the canary's IAM role
        "synthetics:CreateCanary",
        "synthetics:UpdateCanary",
        # ROUND 6 additions:
        # EventBridge Pipes — `CreatePipe` consumes from a source
        # and invokes a target; both can be Lambdas + the pipe runs
        # under a passed role. Combined with PassRole this is the
        # classic "code-exec composition" pattern. Round 6 agent-166, 221.
        "pipes:CreatePipe",
        "pipes:UpdatePipe",
        # CodeDeploy — `CreateDeployment` ships an appspec.yml
        # whose hook scripts run on the deploy target with the
        # role's perms. Round 6 agent-167, 222.
        "codedeploy:CreateDeployment",
        "codedeploy:CreateApplication",
        # CodeStar — `CreateProject` provisions a multi-service
        # template that runs caller-controlled code paths under
        # a passed role. Round 6 agent-225. The
        # `CreateProjectFromTemplate` variant (research §1.27)
        # spawns CloudFormation under an elevated service role —
        # same risk class.
        "codestar:CreateProject",
        "codestar:CreateProjectFromTemplate",
        # ROUND 8 additions — more code-execution + PassRole partners:
        # Amplify, DMS, CodePipeline, EMR Serverless. Each provisions
        # a service that runs caller-controlled work under a passed
        # role. Combined with PassRole this is the code-exec class.
        # Round 8 BB agent-512, 513, 514, 515.
        "amplify:CreateApp",
        "amplify:CreateDomainAssociation",
        "dms:CreateReplicationTask",
        "dms:CreateReplicationInstance",
        "codepipeline:CreatePipeline",
        "codepipeline:UpdatePipeline",
        "emr-serverless:CreateApplication",
        "emr-serverless:StartJobRun",
    }
)


# Read actions whose response body commonly contains secrets / sensitive
# content. On a broad resource, these are exfiltration primitives even
# though they're IAM-classified as Read or List. Floor at 7 on broad
# resource (same as _HIGH_RISK_ACTIONS on broad).
_SECRET_BEARING_READS = frozenset(
    {
        # EC2 instance internals — boot logs and userData scripts often
        # contain bootstrap secrets, API keys, DB passwords
        "ec2:GetConsoleOutput",
        "ec2:GetConsoleScreenshot",
        "ec2:GetLaunchTemplateData",
        "ec2:GetPasswordData",  # Windows Administrator password decrypt
        # SSM — command invocation output frequently contains secrets
        "ssm:GetCommandInvocation",
        "ssm:GetParameterHistory",  # leaks previous secret values
        # CloudWatch Logs — application logs frequently leak secrets
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        # DynamoDB Streams + SQS — message bodies contain whatever the
        # app put there
        "dynamodb:GetRecords",
        "sqs:ReceiveMessage",
        # DynamoDB bulk-read primitives. `Scan` returns every item in a
        # table; `Query` returns every item matching a partition key.
        # On a wildcard-table ARN (or `*`), these are mass exfiltration.
        # Round 5 agent-144.
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:BatchGetItem",
        "dynamodb:ExecuteStatement",
        "dynamodb:PartiQLSelect",
        # ROUND 6 additions:
        # Lambda recon — `GetFunction` returns a presigned URL to
        # the deployment zip. The zip frequently contains hard-
        # coded secrets, env-var snapshots, and proprietary code.
        # Single-action exfil if Resource is broad. Round 6
        # agent-177 (SCARLETEEL reproduction).
        "lambda:GetFunction",
        # ECS task description — `DescribeTasks` returns task
        # metadata including the task role ARN and the IPv4 address
        # of the task container, enabling cross-task IAM theft
        # via the 2024 ECS-recon disclosure. Round 6 agent-178.
        "ecs:DescribeTasks",
        # RDS DB log file download — log files frequently contain
        # query strings with embedded credentials, slow-query
        # secrets, and connection-string leakage. Round 6 agent-187.
        "rds:DownloadDBLogFilePortion",
        "rds:DownloadCompleteDBLogFile",
        # S3 GetObject on broad resource (bucket-name wildcard like
        # `prod-*` or service-wide `arn:aws:s3:::*`) is data-exfil tier.
        # On a NARROW bucket-name (specific bucket) it's just routine
        # reading — _is_broad_resource gates this rule.
        "s3:GetObject",
        "s3:GetObjectVersion",
    }
)


# Actions that, in a single API call, set up ONGOING data exfiltration
# OR cross-account access to data. Different from _HIGH_IMPACT_MUTATION
# in that the BLAST is "everything that flows through this resource
# from now on" — a single configuration change causes long-lived
# unauthorized access. Floor at 8.
_CROSS_ACCOUNT_EXFIL_ACTIONS = frozenset(
    {
        # RDS / EBS / EC2 — share a snapshot with attacker account =
        # ongoing exfil of every byte of stored data
        "rds:ModifyDBSnapshotAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:ModifyImageAttribute",
        # ECR — change repository policy to allow attacker account
        # pulling images
        "ecr:SetRepositoryPolicy",
        # CloudWatch Logs subscription filter — every new log line
        # ships to attacker-controlled destination
        "logs:PutSubscriptionFilter",
        "logs:PutDestination",
        "logs:PutDestinationPolicy",
        # Lambda function URL — make a function publicly invokable
        "lambda:CreateFunctionUrlConfig",
        # Lambda resource-policy grants — `AddPermission` grants
        # cross-account `lambda:InvokeFunction` on the named function.
        # Combined with `Resource: *` it's "grant any account the right
        # to invoke any Lambda in this account." Round 5 agent-131.
        "lambda:AddPermission",
        # ECR image push — once an attacker controls an image tag that
        # production pulls (`:latest`, `:prod`, etc.), every subsequent
        # task restart runs attacker code under the task role. Supply-
        # chain compromise via single API call. Round 5 agent-139.
        "ecr:PutImage",
        # SES — send mail as the org's verified domain (phishing-as-org)
        "ses:SendEmail",
        "ses:SendRawEmail",
        # Resource-policy grants on sensitive services — single-call
        # cross-account access to secrets / keys / catalog data
        "secretsmanager:PutResourcePolicy",
        "kms:CreateGrant",
        "kms:PutKeyPolicy",  # already in _HIGH_IMPACT but also exfil-class
        "glue:PutResourcePolicy",
        "codeartifact:PutDomainPermissionsPolicy",
        "codeartifact:PutRepositoryPermissionsPolicy",
        # EventBridge — cross-account event delivery + API destination
        # (cron the attacker's HTTP endpoint with event data)
        "events:PutPermission",
        "events:CreateApiDestination",
        # S3 bucket-level resource policy / ACL = make a bucket public
        "s3:PutBucketAcl",  # also in _HIGH_IMPACT; also exfil-class
        # EC2 / TGW peering — bridge two VPCs (theirs + yours)
        "ec2:CreateVpcPeeringConnection",
        "ec2:AcceptVpcPeeringConnection",
        "ec2:CreateTransitGatewayPeeringAttachment",
        "ec2:AcceptTransitGatewayPeeringAttachment",
        # AWS Backup vault policy + cross-account copy
        "backup:PutBackupVaultAccessPolicy",
        "backup:StartCopyJob",
        # Scheduler — cron-trigger persistence
        "scheduler:CreateSchedule",
        # Lambda function URL config = make function publicly invokable
        # (also in _HIGH_IMPACT but exfil-tier on the "single-call public
        # surface" semantics)
        "lambda:CreateFunctionUrlConfig",
        # ROUND 3 additions:
        # Verified Permissions — policy store + identity-source = grant
        # cross-account access to anything that uses the policy store
        "verifiedpermissions:CreatePolicyStore",
        "verifiedpermissions:CreateIdentitySource",
        # AppFlow — moves data between SaaS apps + AWS. Configure a
        # flow to ship customer data to attacker SaaS.
        "appflow:CreateFlow",
        "appflow:UpdateFlow",
        "appflow:StartFlow",
        # OpenSearch Serverless data access policies
        "aoss:CreateAccessPolicy",
        "aoss:UpdateAccessPolicy",
        # ECR Public — push images to public registry = supply chain
        # exposure
        "ecr-public:PutImage",
        "ecr-public:CreateRepository",
        # Bedrock InvokeModel on cross-account ARN — when the model
        # ARN names a foundation model in a different account, the
        # invocation runs in that account's region/billing context
        # (LLMjacking cost-abuse + data egress to attacker-controlled
        # inference endpoint). Round 6 agent-164.
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        # Elastic Beanstalk environment / config descriptions — env
        # vars commonly contain DB passwords, third-party API keys,
        # OAuth client secrets. CloudGoat `beanstalk_secrets`
        # scenario. Research §3.10.
        "elasticbeanstalk:DescribeConfigurationSettings",
        "elasticbeanstalk:DescribeEnvironments",
        # Verified Access trust-provider mutation lets the attacker
        # rewrite who AWS treats as authenticated to internal apps.
        # Research §9.8.
        "verifiedaccess:CreateVerifiedAccessGroup",
        "verifiedaccess:CreateVerifiedAccessEndpoint",
        "verifiedaccess:ModifyVerifiedAccessTrustProvider",
        # Direct Connect — bridge VPC to attacker's on-prem
        "directconnect:CreateConnection",
        "directconnect:CreatePrivateVirtualInterface",
        "directconnect:CreateTransitVirtualInterface",
        "directconnect:CreateInterconnect",
        "directconnect:AllocatePrivateVirtualInterface",
        "directconnect:AcceptPrivateVirtualInterface",
        "directconnect:AcceptTransitVirtualInterface",
    }
)

_HIGH_RISK_ACTIONS = frozenset(
    {
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "sts:AssumeRole",
        # Federated-assume variants — semantically equivalent to
        # sts:AssumeRole but easy to omit. Round 6 finding agent-201
        # (StringLike `*` on `*:sub` lets any token from the IdP
        # assume) — federated assume is a high-risk primitive.
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
        # GetFederationToken / GetSessionToken mint short-lived creds
        # for callers — IAM-policy-bound but transmit the role's
        # entire permission set to whomever the federated token
        # reaches. Round 6 agent-175, 240.
        "sts:GetFederationToken",
        "sts:GetSessionToken",
        # RDS Data API — `rds-data:ExecuteStatement` runs arbitrary
        # SQL against Aurora Serverless using IAM authentication only
        # (no DB credentials). Narrow-cluster-ARN scope = full SQL
        # admin of that DB. Round 6 agent-160.
        "rds-data:ExecuteStatement",
        "rds-data:BatchExecuteStatement",
        "rds-data:ExecuteSql",
    }
)

# Actions whose IAM access level is Write but which are commonly assumed to be
# read-only because they're often used for SELECT-style queries. The same API
# call can also DELETE/UPDATE depending on the SQL/query the caller passes —
# so they're a real outage risk and shouldn't be silently allowed in a
# read-only request without flagging.
_DECEPTIVE_WRITE_ACTIONS = frozenset(
    {
        "rds-data:ExecuteStatement",
        "rds-data:BatchExecuteStatement",
        "rds-data:ExecuteSql",
        "redshift-data:ExecuteStatement",
        "redshift-data:BatchExecuteStatement",
        "athena:StartQueryExecution",
        "athena:StopQueryExecution",
        "neptune-db:ReadDataViaQuery",
        "neptune-db:WriteDataViaQuery",
        "timestream:Select",
        "qldb:SendCommand",
    }
)


# Mutation actions whose IMPACT is high even when scoped to a single
# specific resource ARN. The default scorer treats single-resource
# scoped writes as low-risk; that's wrong for these — a single DNS
# record change or a single route-table modification can take down
# production. Each action here floors the request's risk score at
# 5 (medium) regardless of how narrow the resource scope is. Operators
# who want to auto-approve specific cases override via the planned
# admin risk-context input (see `docs/ROADMAP.md` § "Admin-
# configurable risk context").
_HIGH_IMPACT_MUTATION_ACTIONS = frozenset(
    {
        # DNS — affects all of production traffic routing
        "route53:ChangeResourceRecordSets",
        "route53:DeleteHostedZone",
        "route53:CreateHostedZone",
        # Network — single edit can isolate or open infra
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:ModifySecurityGroupRules",
        "ec2:ModifyVpcEndpoint",
        "ec2:CreateRoute",
        "ec2:DeleteRoute",
        "ec2:ReplaceRoute",
        # EC2 instance attribute changes — userData edits = arbitrary code exec
        "ec2:ModifyInstanceAttribute",
        # Load balancers — traffic-shifting
        "elasticloadbalancing:ModifyListener",
        "elasticloadbalancing:DeleteListener",
        "elasticloadbalancing:ModifyTargetGroupAttributes",
        # IAM — even single-policy changes are escalation surface
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        # S3 — bucket policy / public-access / object ACL changes
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl",
        "s3:PutObjectAcl",            # object-level public exposure
        "s3:PutPublicAccessBlock",
        "s3:DeletePublicAccessBlock",
        # KMS — key policy changes
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
        # CloudFront / WAF / SES — operational outage surface
        "cloudfront:DeleteDistribution",
        "cloudfront:UpdateDistribution",
        "wafv2:DeleteWebACL",
        # Lambda — code-execution swap + cross-account invoke grants
        "lambda:UpdateFunctionCode",
        "lambda:DeleteFunction",
        "lambda:AddPermission",       # grant cross-account/cross-service invoke
        "lambda:RemovePermission",
        # Secrets — credential rotation / theft surface
        "secretsmanager:UpdateSecret",
        "secretsmanager:PutSecretValue",
        "secretsmanager:RotateSecret",
        # SSM — RCE + secret rotation
        "ssm:SendCommand",            # RCE on EC2 fleet
        "ssm:StartSession",
        "ssm:PutParameter",           # secret rotation when SecureString
        # ECS — code deploy via task definition swap
        "ecs:UpdateService",
        "ecs:RegisterTaskDefinition",
        # CloudFormation — stack mutations = infra rewrites
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:UpdateStack",
        "cloudformation:CreateStack",
        # CodePipeline / CodeBuild — production deploy triggers
        "codepipeline:StartPipelineExecution",
        "codebuild:StartBuild",
        # Container image poisoning — push to a repo prod pulls from
        # = next task restart runs attacker code with the task role.
        "ecr:PutImage",
        "ecr:BatchDeleteImage",
        # S3 replication = ongoing exfiltration. Single API call sets up
        # auto-copy of every new object to an attacker-chosen destination.
        "s3:PutBucketReplication",
        # ECS Exec — interactive shell on running tasks; data-plane RCE
        "ecs:ExecuteCommand",
        # EKS — Kubernetes API access + access-entry mutations
        "eks:AccessKubernetesApi",
        "eks:CreateAccessEntry",
        "eks:AssociateAccessPolicy",
        # AWS Transfer — SFTP / FTPS user creation + key import
        "transfer:CreateUser",
        "transfer:ImportSshPublicKey",
        "transfer:CreateServer",
        # CodeArtifact — package publishing = supply chain
        "codeartifact:PublishPackageVersion",
        # RDS — instance config + restore-from-snapshot
        "rds:ModifyDBInstance",
        "rds:RestoreDBInstanceFromDBSnapshot",
        # Bedrock — Knowledge Base seed / ingestion = inject prompt-
        # injection payloads into production RAG
        "bedrock:CreateKnowledgeBase",
        "bedrock:StartIngestionJob",
        # ROUND 6 additions:
        # Lake Formation `GetDataAccess` — bypasses fine-grained
        # access control by returning temporary creds to read raw
        # underlying data. Round 6 agent-161.
        "lakeformation:GetDataAccess",
        # EC2 Instance Connect — `SendSSHPublicKey` pushes a one-time
        # public key onto an instance's authorized_keys; combined
        # with a known IP/port + ec2-instance-connect:OpenTunnel
        # this is SSH-on-demand to any matching instance. Round 6
        # agent-162, 238.
        "ec2-instance-connect:SendSSHPublicKey",
        # EKS cluster config — `UpdateClusterConfig` can change
        # endpoint access (private→public) or enable logging
        # destinations. Round 6 agent-169.
        "eks:UpdateClusterConfig",
        # S3 Object Lambda response writing — write side of the
        # GetObject proxy; rewriting object content modifies what
        # downstream consumers see. Round 6 agent-170.
        "s3-object-lambda:WriteGetObjectResponse",
        # RAM cross-account sharing — `CreateResourceShare` extends
        # a resource to other accounts in/outside the org. Round 6
        # agent-172.
        "ram:CreateResourceShare",
        "ram:AssociateResourceShare",
        "ram:UpdateResourceShare",
        # VPC endpoint policy mutation — `ModifyVpcEndpoint` can
        # replace the endpoint's resource policy, removing all
        # access controls on the VPC's path to AWS APIs. Round 6
        # agent-173.
        "ec2:ModifyVpcEndpoint",
        # S3 lifecycle — `PutLifecycleConfiguration` can schedule
        # automatic deletion (or transition to Glacier) of objects;
        # weaponized against cloudtrail buckets it's silent log
        # destruction. Round 6 agent-174.
        "s3:PutLifecycleConfiguration",
        # CloudTrail Insight selectors — disabling insight selectors
        # silently blinds anomaly detection (writes still happen,
        # alerts don't). Round 6 agent-184.
        "cloudtrail:PutInsightSelectors",
        # Redshift temporary credentials — returns DB user creds
        # for the calling role. With broad scope this is admin-
        # equivalent for the Redshift cluster. Round 6 agent-186,
        # 239.
        "redshift:GetClusterCredentials",
        # Network bridging primitives — attaching/creating network
        # interfaces lets the attacker create a route between
        # otherwise-isolated network paths. Round 6 agent-189.
        "ec2:CreateNetworkInterface",
        "ec2:AttachNetworkInterface",
        # VPN endpoint creation — `CreateVpnConnection` and
        # `CreateClientVpnEndpoint` build network bridges from
        # attacker-controlled infrastructure into the VPC. Round 6
        # agent-245.
        "ec2:CreateVpnConnection",
        "ec2:CreateClientVpnEndpoint",
        # API Gateway authorizer mutation — `apigateway:PATCH` on a
        # method can switch its authorization type from IAM to
        # NONE, exposing the API publicly. Round 6 agent-179.
        "apigateway:PATCH",
        # Bedrock onboarding + cross-account invoke — `PutUseCase`
        # opts the account into model access; broad invoke without
        # model scoping is the LLMjacking attack class (cost abuse
        # + sensitive prompt processing). Round 6 agent-163, 191.
        "bedrock:PutUseCaseForModelAccess",
        "bedrock:CreateInferenceProfile",
        # ROUND 7 additions — newer services (2023-2026 surface):
        # Amazon Q Business — `CreateApplication` provisions a RAG
        # app whose knowledge base ingests caller-controlled data;
        # CreateDataSource adds attacker-controlled corpus. Round 7
        # agent-307.
        "qbusiness:CreateApplication",
        "qbusiness:CreateDataSource",
        "qbusiness:UpdateDataSource",
        # Amazon DataZone — `CreateDomain` provisions a data-mesh
        # domain whose governance rules the caller defines. Round 7
        # agent-308.
        "datazone:CreateDomain",
        "datazone:UpdateDomain",
        # AWS B2B Data Interchange — `CreateProfile` + Partnership
        # establishes data-exchange relationships with external
        # partners; weaponized as ongoing data egress. Round 7
        # agent-309.
        "b2bi:CreateProfile",
        "b2bi:CreatePartnership",
        # EC2 CreateImage — captures a snapshot of an instance's
        # disk that can then be shared with attacker accounts via
        # ec2:ModifyImageAttribute (already in cross-account-exfil).
        # The capture itself is high-impact even before the share.
        # Round 7 agent-311.
        "ec2:CreateImage",
        # MemoryDB — `CreateUser` provisions a Redis-protocol user
        # with ACL; takeover primitive for the cluster. Round 7
        # agent-312.
        "memorydb:CreateUser",
        "memorydb:UpdateUser",
        # AppSync GraphQL API keys — `CreateApiKey` mints an
        # unauthenticated API key for the GraphQL endpoint. Round 7
        # agent-313.
        "appsync:CreateApiKey",
        "appsync:UpdateApiKey",
        # Cognito User Pool creation — net-new pool the attacker
        # controls; can be federated into the org. Round 7 agent-314.
        "cognito-idp:CreateUserPool",
        "cognito-idp:CreateIdentityProvider",
        # RDS DB cluster endpoint — `CreateDBClusterEndpoint` adds
        # a custom endpoint with attacker-chosen reader/writer
        # routing; persistent backdoor to the cluster. Round 7
        # agent-324.
        "rds:CreateDBClusterEndpoint",
        "rds:ModifyDBClusterEndpoint",
        # EC2 Verified Access — `CreateVerifiedAccessEndpoint`
        # creates an alternative network path that bypasses normal
        # IAM evaluation. Round 7 agent-325.
        "ec2:CreateVerifiedAccessEndpoint",
        "ec2:ModifyVerifiedAccessEndpoint",
    }
)


# Actions whose blast radius is severe enough that they should ALWAYS
# floor at 9 regardless of resource scope or conditions. These are the
# "this single API call can compromise the account / destroy evidence /
# remove governance" surface — auto-approve is never appropriate.
_CATASTROPHIC_ACTIONS = frozenset(
    {
        # Account governance — irreversible
        "account:CloseAccount",
        "organizations:LeaveOrganization",
        # Closes any member account in the org — total data loss after
        # the 90-day grace window. Round 5 finding agent-117.
        "organizations:CloseAccount",
        # Audit / evidence destruction
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
        # Defense-disabling (round 5): turning off the security service
        # IS the attack — once disabled, every subsequent action goes
        # un-detected. Same impact class as cloudtrail:StopLogging.
        "guardduty:DeleteDetector",
        "securityhub:DisableSecurityHub",
        "config:StopConfigurationRecorder",
        "config:DeleteConfigurationRecorder",
        # IAM total-compromise primitives — even a narrowly-resourced
        # AttachRolePolicy can swing in AdministratorAccess if the
        # attacker picks an admin-ish managed policy ARN.
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:CreateAccessKey",
        # Round 5: UpdateAccessKey can REACTIVATE a previously-disabled
        # key — useful for persisting after a credential rotation that
        # only disables (rather than deletes) old keys. Same risk class
        # as CreateAccessKey for the credential-theft scenario.
        "iam:UpdateAccessKey",
        # Policy-version swap: silently change a managed policy by
        # creating a new version + setting it as default. Leaves no
        # explicit "policy modified" audit, just a version bump.
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        # KMS — schedule deletion of any key locks data forever, or
        # rewriting the key policy lets the attacker grant themselves
        # Decrypt permanently (and quietly — no separate "policy
        # changed" audit since key policy IS the resource policy).
        "kms:ScheduleKeyDeletion",
        "kms:PutKeyPolicy",
        # IAM Identity Center (SSO) — these mint cross-account admin in
        # one API call. CreatePermissionSet + AttachManagedPolicy*
        # composes to "grant AdministratorAccess across the org";
        # CreateAccountAssignment puts a principal on it.
        "sso-admin:CreatePermissionSet",
        "sso-admin:AttachManagedPolicyToPermissionSet",
        "sso-admin:PutInlinePolicyToPermissionSet",
        "sso-admin:CreateAccountAssignment",
        # Organizations — creating new accounts or moving them between
        # OUs evades SCP governance and is irreversible without org-
        # admin intervention. AcceptHandshake / InviteAccountToOrganization
        # let the attacker pull arbitrary accounts INTO the organization
        # (then exfil them out / drop SCPs on them). AttachPolicy /
        # DetachPolicy directly manipulate SCP enforcement.
        "organizations:CreateAccount",
        "organizations:MoveAccount",
        "organizations:AcceptHandshake",
        "organizations:InviteAccountToOrganization",
        "organizations:AttachPolicy",
        "organizations:DetachPolicy",
        # CloudFormation StackSets — org-wide blast radius in one
        # call. CreateStackSet defines the template; CreateStackInstances
        # deploys it to every member account. UpdateStackSet propagates
        # changes everywhere. Much larger blast than CreateStack (single-
        # account).
        "cloudformation:CreateStackSet",
        "cloudformation:CreateStackInstances",
        "cloudformation:UpdateStackSet",
        "cloudformation:UpdateStackInstances",
        # CloudFormation custom resource types — attacker registers a
        # type whose handler is attacker-controlled. Every subsequent
        # stack that uses the type runs attacker code with whatever
        # role the stack uses.
        "cloudformation:RegisterType",
        "cloudformation:ActivateType",
        "cloudformation:SetTypeDefaultVersion",
        # Federation IdP takeover: attacker registers an OIDC or SAML
        # provider they control, then any role trusting that provider
        # can be assumed by attacker-issued tokens.
        "iam:CreateOpenIDConnectProvider",
        "iam:UpdateOpenIDConnectProviderThumbprint",
        "iam:AddClientIDToOpenIDConnectProvider",
        "iam:CreateSAMLProvider",
        "iam:UpdateSAMLProvider",
        # IAM user console takeover — set/change another user's
        # password, deactivate their MFA, etc.
        "iam:UpdateLoginProfile",
        "iam:CreateLoginProfile",
        "iam:ChangePassword",
        "iam:DeactivateMFADevice",
        "iam:DeleteVirtualMFADevice",
        # Account-wide cert / SSH-key installation
        "iam:UploadServerCertificate",
        "iam:UploadSSHPublicKey",
        # Account password-policy weakening (lower min length, disable
        # reuse prevention, etc.)
        "iam:UpdateAccountPasswordPolicy",
        # Defense-disablement without a destructive-verb prefix
        # (Disassociate / Update can disable detection silently)
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "access-analyzer:UpdateAnalyzer",
        "access-analyzer:DeleteAnalyzer",
        "inspector2:Disable",
        "inspector2:DisassociateMember",
        # AWS Config PutConfigurationRecorder can replace the recorder
        # config with a no-op recording scope — silently disable the
        # service without firing Delete/Stop events.
        "config:PutConfigurationRecorder",
        "config:PutDeliveryChannel",
        # Data-plane RCE / admin-equivalent — flagged in adversarial
        # round 2. These reach customer data or running workloads
        # directly; floor at 9 even on narrow resources.
        "ecs:ExecuteCommand",           # interactive shell on running task
        "eks:AccessKubernetesApi",       # K8s API = cluster admin
        "eks:CreateAccessEntry",         # K8s ClusterRoleBinding equivalent
        "eks:AssociateAccessPolicy",     # AmazonEKSAdminPolicy attach
        "eks:UpdateAccessEntry",
        "transfer:CreateUser",           # SFTP backdoor user
        "transfer:UpdateUser",
        "transfer:ImportSshPublicKey",
        "transfer:CreateServer",
        # RDS — modifying master password / restoring from snapshot is
        # database-level admin. Master credential reset = take over the
        # database. Restore-from-snapshot can be used to bring up a
        # cloned DB the attacker queries unrestricted.
        "rds:ModifyDBInstance",
        "rds:ModifyDBCluster",
        "rds:RestoreDBInstanceFromDBSnapshot",
        "rds:RestoreDBClusterFromSnapshot",
        "rds:RestoreDBInstanceToPointInTime",
        # S3 bucket-policy mutation on any bucket = potential public
        # exposure or cross-account share. Treated as catastrophic
        # (always needs human review) even on narrow ARN — the
        # narrowness doesn't mitigate the "make this bucket public"
        # primitive.
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        # ROUND 3 additions:
        # IAM user/group policy-attach (symmetric to AttachRolePolicy
        # which was already catastrophic; user/group halves were missed)
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:PutGroupPolicy",
        "iam:AddUserToGroup",
        # IAM principal CREATION — attacker creates a fresh principal
        # (no audit trail of who they are), then attaches admin policy
        "iam:CreateUser",
        "iam:CreateRole",
        # IAM tag-based escalation: TagRole can bypass ABAC if any tag-
        # conditional policy trusts a tag the caller can write
        "iam:TagRole",
        "iam:TagUser",
        # Roles Anywhere X.509 trust-anchor — federate any X.509 CA;
        # attacker controls a CA → any role trusting it is theirs
        "rolesanywhere:CreateTrustAnchor",
        "rolesanywhere:CreateProfile",
        # Cognito identity pool role mapping = take over every
        # federated identity assuming a pool role
        "cognito-identity:SetIdentityPoolRoles",
        "cognito-identity:UpdateIdentityPool",
        # Lake Formation — data-lake-wide permissions grant + global
        # settings (drops fine-grained access control)
        "lakeformation:GrantPermissions",
        "lakeformation:PutDataLakeSettings",
        # SSM documents — define commands that run on every SSM-managed
        # instance. CreateDocument with attacker-controlled script +
        # ModifyDocumentPermission to share account-wide = persistent RCE.
        "ssm:CreateDocument",
        "ssm:UpdateDocument",
        "ssm:UpdateDocumentDefaultVersion",
        "ssm:ModifyDocumentPermission",
        # SSM interactive / command primitives — RCE on EC2 fleet (the
        # agent-68 finding confirmed these need catastrophic floor not
        # just high-impact)
        "ssm:StartSession",
        "ssm:SendCommand",
        # Instance-profile bind/unbind. The textbook EC2 escalation:
        # CreateInstanceProfile + AddRoleToInstanceProfile (passes any
        # role to a new instance profile). Combined with ec2:RunInstances
        # the box boots with admin creds reachable via metadata service.
        "iam:CreateInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile",
        # EC2-side of the instance-profile attack: swapping the profile
        # on a RUNNING instance changes its metadata-service credentials
        # to the new role's. Direct privesc from "SSH access to instance"
        # to "any role I can pass." Round 5 findings agent-126.
        "ec2:AssociateIamInstanceProfile",
        "ec2:ReplaceIamInstanceProfileAssociation",
        # EC2 userData injection — set the boot script of any instance to
        # attacker-controlled shell. On next boot/reboot/scale-up the
        # instance runs the script as root with the instance's role.
        # Round 5 agent-125.
        "ec2:ModifyInstanceAttribute",
        # Cognito user-pool admin — admin-create-user + admin-set-
        # password = impersonation of any user. Catastrophic for any
        # app that uses Cognito as IdP.
        "cognito-idp:AdminCreateUser",
        "cognito-idp:AdminSetUserPassword",
        "cognito-idp:AdminUpdateUserAttributes",
        "cognito-idp:AdminAddUserToGroup",
        "cognito-idp:AdminConfirmSignUp",
        # EC2 Image Builder — recipe = AMI build script. Poisoning here
        # is supply-chain attack on every instance booted from those AMIs.
        "imagebuilder:CreateComponent",
        "imagebuilder:CreateImageRecipe",
        "imagebuilder:CreateImagePipeline",
        "imagebuilder:UpdateImagePipeline",
        # Private CA — IssueCertificate mints a cert that any TLS peer
        # in the org will trust. Cross-service impersonation primitive.
        "acm-pca:IssueCertificate",
        # EBS direct snapshot access — reads raw disk blocks. Entire
        # database contents readable without going through any DB
        # access controls.
        "ebs:GetSnapshotBlock",
        "ebs:ListSnapshotBlocks",
        "ebs:ListChangedBlocks",
        # ROUND 6 additions:
        # Permission-boundary mutations remove the only guardrail
        # preventing a role from escalating to admin. Adding the
        # boundary requires `iam:PutRolePermissionsBoundary`; removing
        # it requires `iam:DeleteRolePermissionsBoundary`. Either
        # primitive single-handedly unlocks every other IAM mutation
        # the bounded role's policies allowed. Symmetric for users.
        # Round 6 findings agent-171, 220.
        "iam:PutRolePermissionsBoundary",
        "iam:DeleteRolePermissionsBoundary",
        "iam:PutUserPermissionsBoundary",
        "iam:DeleteUserPermissionsBoundary",
        # SSM Associations — `CreateAssociation` schedules a document
        # to run on every matching instance on a recurring schedule.
        # Equivalent to "install a cron" RCE primitive. Round 6
        # agent-223.
        "ssm:CreateAssociation",
        "ssm:UpdateAssociation",
        # Defense-evasion (round-6 agent-226 and adjacent):
        # disable/remove the recording mechanisms BEFORE the action
        # happens, so post-incident forensics find nothing. Same tier
        # as cloudtrail:StopLogging.
        "ec2:DeleteFlowLogs",
        "route53:DeleteQueryLoggingConfig",
        "wafv2:DisassociateWebACL",
        "logs:DeleteLogGroup",
        "logs:DeleteRetentionPolicy",
        # Bedrock AgentCore — `CreateCodeInterpreter` provisions a
        # sandboxed code-execution environment that runs under a
        # role. Combined with PassRole this is RCE-as-passed-role,
        # plus AgentCore Runtime sandboxes can call back to AWS
        # APIs. Round 6 findings agent-165, 224.
        "bedrock-agentcore:CreateCodeInterpreter",
        "bedrock-agentcore:CreateAgentRuntime",
        "bedrock-agentcore:UpdateAgentRuntime",
        # Organizations delegated administration — registering a
        # delegated admin for a service grants that account org-
        # wide privileges for the service. Privesc primitive at
        # the org level. Round 6 finding agent-244.
        "organizations:RegisterDelegatedAdministrator",
        # ROUND 7 additions:
        # Account API — `PutContactInformation` rewrites the AWS
        # account's primary contact info, enabling account-takeover
        # via the password-reset flow. Same severity as IAM CreateUser.
        # Round 7 agent-316.
        "account:PutContactInformation",
        "account:PutAlternateContact",
        # Macie defense-evasion — `DisableMacie` removes the only
        # data-loss-prevention engine actively scanning S3 buckets.
        # Tier-equivalent to cloudtrail:StopLogging. Round 7 agent-317.
        "macie2:DisableMacie",
        "macie2:DisableOrganizationAdminAccount",
        # CloudTrail Event Data Stores are the newer (post-2022)
        # alternative to trails. Deleting one destroys audit history
        # the same way DeleteTrail does. Round 7 agent-318.
        "cloudtrail:DeleteEventDataStore",
        "cloudtrail:UpdateEventDataStore",
        # CloudTrail PutResourcePolicy — rewrites who can read/write
        # the trail's data. Can be weaponized to deny CloudTrail
        # itself the ability to write to its destination bucket,
        # silently disabling audit. Round 8 agent-505.
        "cloudtrail:PutResourcePolicy",
        "cloudtrail:DeleteResourcePolicy",
        # IAM Identity Center — group-membership creation grants the
        # caller (or any user they specify) admin over every account
        # the source group is permissioned in. Sibling of the existing
        # sso-admin:CreateAccountAssignment but happens at the user
        # store layer. Round 8 BB agent-511.
        "identitystore:CreateGroupMembership",
        "identitystore:CreateUser",
        "identitystore:CreateGroup",
    }
)


# AWS IAM treats action names case-insensitively. The action-set constants
# above use canonical-case strings (matching the AWS docs); the
# comparison-time helpers below normalize to lowercase so policies with
# `iam:attachrolepolicy` are caught by the same rules as
# `iam:AttachRolePolicy`. Discovered by adversarial agent round 2 —
# `iam:attachrolepolicy` was bypassing the catastrophic-action check.

_CATASTROPHIC_ACTIONS_LC = frozenset(a.lower() for a in _CATASTROPHIC_ACTIONS)
_HIGH_IMPACT_MUTATION_ACTIONS_LC = frozenset(a.lower() for a in _HIGH_IMPACT_MUTATION_ACTIONS)
_HIGH_RISK_ACTIONS_LC = frozenset(a.lower() for a in _HIGH_RISK_ACTIONS)
_DECEPTIVE_WRITE_ACTIONS_LC = frozenset(a.lower() for a in _DECEPTIVE_WRITE_ACTIONS)
_SECRET_BEARING_READS_LC = frozenset(a.lower() for a in _SECRET_BEARING_READS)


# Service aliases — different AWS service-prefix names that all reach
# the same underlying resource/data. Treat them equivalently for rule
# matching. For now we collapse alternative prefixes to a canonical
# one so the set-based lookups still work (the matching code lowercases
# the service and looks up in this map before checking the constant
# sets).
_SERVICE_ALIASES = {
    # S3 Object Lambda / S3 on Outposts proxy GetObject through to S3
    "s3-object-lambda": "s3",
    "s3-outposts": "s3",
    # ECR Public is a separate IAM service but the actions are the same
    # shape; we keep them separate so the catastrophic list can target
    # ecr-public:PutImage specifically (already added in round 2).
    # IAM Identity Center: the `sso:` prefix is the legacy / display
    # form for the IAM Identity Center service whose canonical IAM
    # service-prefix is `sso-admin`. AWS accepts policies using either
    # prefix and resolves them equivalently. Round 6 finding agent-190
    # — without this alias `sso:AttachManagedPolicyToPermissionSet`
    # bypasses the `sso-admin:AttachManagedPolicyToPermissionSet`
    # entry in _CATASTROPHIC_ACTIONS.
    "sso": "sso-admin",
    # Bedrock has split into per-functionality service prefixes since
    # 2024 (`bedrock`, `bedrock-runtime`, `bedrock-agent`,
    # `bedrock-agent-runtime`). The catastrophic-action list targets
    # `bedrock:*` and `bedrock-agentcore:*`; collapse the runtime
    # variants so InvokeModel under `bedrock-runtime:InvokeModel`
    # still trips the cross-account-exfil rule for `bedrock:InvokeModel`.
    # Round 8 BB findings agent-508, 510 (Bedrock subprefix aliasing).
    "bedrock-runtime": "bedrock",
    "bedrock-agent": "bedrock",
    "bedrock-agent-runtime": "bedrock",
}


# ---------- Wildcard / glob helpers ----------
#
# AWS IAM treats `*` AND `?` as wildcard primitives in action and
# resource patterns. `*` matches any string; `?` matches any single
# character. The scorer was originally written assuming only `*`
# matters — round 4 white-box revealed 7 locations where `"*" in s`
# silently failed against `iam:?reateAccessKey`. These helpers
# centralize wildcard detection so adding a new wildcard primitive
# in the future is a single-file change.

import fnmatch as _fnmatch


def _has_wildcard(s: str) -> bool:
    """True if `s` contains an IAM wildcard primitive (`*` or `?`)."""
    return "*" in s or "?" in s


def _action_covers_any(action: str, target_set_lc: frozenset[str]) -> bool:
    """True if `action` matches at least one entry in `target_set_lc`
    (which must be lowercased).

    For literal actions (no wildcard), this is a fast exact-match
    against the set. For wildcard actions, it fnmatches the action
    pattern against every entry — so `iam:Create*` "covers" the
    catastrophic action `iam:CreateAccessKey` (any single concrete
    catastrophic action the glob would match means the rule applies).
    """
    a_lc = action.lower()
    if not _has_wildcard(a_lc):
        return a_lc in target_set_lc
    # Wildcard pattern: any target the pattern matches means yes.
    return any(_fnmatch.fnmatchcase(t, a_lc) for t in target_set_lc)


import unicodedata as _unicodedata


# Zero-width / non-printing characters that visually disappear but
# survive `.strip()` and equality comparisons. Used to defeat naive
# set-membership lookups. Round 6 white-box findings agent-216,
# agent-246, agent-247.
_ZERO_WIDTH_CHARS = (
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "⁠",  # WORD JOINER
    "﻿",  # BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
    "͏",  # COMBINING GRAPHEME JOINER
)


# Hangul filler chars (Lo category — not in Cf, so the category-strip
# in `_norm_grammar_str` won't remove them). Round 7 agent-428.
_HANGUL_FILLERS = ("ㅤ", "ᅠ")


# Cross-script homoglyphs. NFKC does NOT merge Cyrillic 'A' (U+0410)
# with Latin 'A' (U+0041) — they're in different Unicode blocks. An
# attacker writing `Effect: "Allow"` with the first char Cyrillic
# bypasses our case-insensitive Effect lookup. Round 7 agent-400
# (gap 8 — complete admin bypass). Conservative map: only chars
# that visually match Latin AND could appear in IAM grammar.
_LATIN_HOMOGLYPHS = {
    # Cyrillic capital → Latin capital
    "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "У": "Y", "Х": "X",
    # Cyrillic small → Latin small
    "а": "a", "в": "b", "е": "e", "к": "k",
    "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s",
    # Greek capital → Latin capital
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
    # Greek small → Latin small
    "α": "a", "ο": "o", "ν": "v", "ι": "i",
}

def _norm_grammar_str(s: object) -> str:
    """Normalize an IAM-grammar string for safe comparison.

    Steps (idempotent):
      1. Coerce to str; non-string returns "".
      2. Strip Hangul-filler chars (Lo category — would survive the
         Cf-strip below).
      3. Strip ALL Unicode `Cf` (format) and `Mn` (combining mark)
         chars. Covers ZWSP, ZWJ, ZWNJ, BOM, WJ, CGJ, RLO/LRO bidi
         overrides, and any future additions to those categories.
      4. NFKC-normalize: fullwidth Roman, ligatures, compatibility
         variants collapse to canonical ASCII.
      5. Map Cyrillic / Greek homoglyphs (\u0410 'A' etc.) to ASCII
         Latin counterparts. NFKC alone doesn't merge these across
         script blocks. Defeats `Effect: "Allow"` (Cyrillic first
         char, gap 8 bypass — round 7 agent-400).
      6. Strip leading/trailing whitespace + no-break-space variants.

    Round 6: agent-216 (fullwidth), agent-217 (whitespace), agent-230
    (Effect case), agent-246 (BOM), agent-247 (casefold). Round 7:
    agent-400 (Cyrillic, gap 8), agent-412-416 (RTL + Cf), agent-425
    (Cyrillic Deny), agent-428 (Hangul filler).
    """
    if not isinstance(s, str):
        return ""
    # Hangul fillers (Lo category — not caught by the Cf strip below)
    for hf in _HANGUL_FILLERS:
        if hf in s:
            s = s.replace(hf, "")
    # Strip Cf (format) + Mn (combining mark) by category
    s = "".join(
        c for c in s
        if _unicodedata.category(c) not in ("Cf", "Mn")
    )
    # NFKC compatibility normalization
    s = _unicodedata.normalize("NFKC", s)
    # Cross-script homoglyphs
    if any(c in _LATIN_HOMOGLYPHS for c in s):
        s = "".join(_LATIN_HOMOGLYPHS.get(c, c) for c in s)
    return s.strip().strip("   ")
_PRIVATE_IPV4_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",         # loopback
    "169.254.",     # link-local
)


def _condition_is_vacuous(condition: object) -> tuple[bool, str]:
    """Heuristic: does the Condition block fail to constrain the grant?

    Returns `(is_vacuous, reason)`. When True, the Condition LOOKS
    like a scoping signal to a casual reader but in fact imposes no
    real constraint — either it always matches, never matches, or
    inverts the operator's likely intent. This is one of the highest-
    leverage adversarial patterns in IAM policy auditing because
    operators (and most scoring tools) credit the *presence* of a
    condition as risk-reducing without checking its semantics.

    Patterns detected:
      1. `StringLike` with bare `"*"` value — degenerate wildcard.
      2. `Null` operator with value `"true"` on auth-bearing keys —
         inverts: "key MUST BE ABSENT" (often misread as "required").
      3. `IpAddress` / `IpAddressIfExists` with `0.0.0.0/0` — matches
         every IP.
      4. `IpAddress` on a private RFC1918 / loopback / link-local
         range — `aws:SourceIp` reflects the PUBLIC IP, so private
         CIDRs effectively never match.
      5. Empty-string condition value — matches absent / unspecified
         key; almost never the intended scope.
      6. `StringLike` on `*:sub` / `*:aud` (federated identity claims)
         with `*` inside the value — overbroad federated-assume.

    Round 6 findings agent-156, 182, 192, 201.
    """
    if not isinstance(condition, dict):
        return False, ""

    for op_raw, kvs in condition.items():
        # YAML quirk: an unquoted `Null:` key parses to Python None
        # rather than the string "Null". AWS still treats this as the
        # `Null` operator (JSON has no other interpretation). Round 6
        # finding agent-182 surfaced this — the rule was checking
        # `op == "Null"` but op was None.
        if op_raw is None:
            op = "Null"
        else:
            op = str(op_raw)
        op_lc = op.lower()
        if not isinstance(kvs, dict):
            continue

        for key_raw, val_raw in kvs.items():
            key = str(key_raw)
            key_lc = key.lower()
            vals = val_raw if isinstance(val_raw, list) else [val_raw]
            vals_str = [str(v) for v in vals]

            # Pattern 1: StringLike bare wildcard
            if op.startswith("StringLike") or op_lc == "stringlike":
                if any(v == "*" for v in vals_str):
                    return True, (
                        f"`Condition.{op}.{key}` value is `\"*\"` — "
                        "degenerate wildcard; the condition imposes "
                        "no actual constraint."
                    )
                # Pattern 6: StringLike on federated-identity claim
                # (sub/aud) with `*` inside the value.
                if key_lc.endswith(":sub") or key_lc.endswith(":aud"):
                    for v in vals_str:
                        if "*" in v:
                            return True, (
                                f"`Condition.{op}.{key}: \"{v}\"` "
                                "wildcards the federated-identity "
                                "claim — allows any matching token "
                                "from the identity provider, not a "
                                "specific repo/branch/principal."
                            )
                # Pattern 6b: StringLike on aws:PrincipalOrgID with
                # `o-*` value — looks like org-scoping but matches
                # every AWS organization. Round 7 agent-426.
                if key_lc.endswith("principalorgid") or key_lc.endswith("principalorgpaths"):
                    for v in vals_str:
                        # AWS org IDs are `o-XXXXXXXX`. Anything that
                        # starts `o-` followed only by wildcards is
                        # effectively a match-any-org.
                        stripped = v.lstrip("o-").lstrip("/")
                        if v.startswith("o-") and (stripped == "*" or stripped == ""):
                            return True, (
                                f"`Condition.{op}.{key}: \"{v}\"` "
                                "wildcards the org-id segment — "
                                "matches every AWS organization, not "
                                "a specific one. Use `StringEquals` "
                                "with the literal `o-XXXX` instead."
                            )

            # Pattern 2: Null inversion
            if op == "Null":
                for v in vals_str:
                    if v.lower() == "true":
                        return True, (
                            f"`Condition.Null.{key}: \"true\"` means "
                            "\"the key MUST BE ABSENT\" — opposite of "
                            "the typical \"require this key\" intent. "
                            "Often misread by reviewers."
                        )

            # Pattern 3 & 4: SourceIp degenerate CIDRs
            if "sourceip" in key_lc and op_lc.startswith("ipaddress"):
                for v in vals_str:
                    if v == "0.0.0.0/0":
                        return True, (
                            f"`Condition.{op}.{key}: 0.0.0.0/0` matches "
                            "every IP address — degenerate."
                        )
                    if any(v.startswith(p) for p in _PRIVATE_IPV4_PREFIXES):
                        return True, (
                            f"`Condition.{op}.{key}: {v}` uses a "
                            "private / loopback CIDR — `aws:SourceIp` "
                            "evaluates against the request's PUBLIC "
                            "IP, so this never matches in practice "
                            "(condition is unenforceable)."
                        )

            # Pattern 5: Empty-string condition value
            if vals_str and all(v == "" for v in vals_str):
                return True, (
                    f"`Condition.{op}.{key}` is empty string — matches "
                    "absent / unspecified key; almost certainly not "
                    "the intended scope."
                )

            # Pattern 5b: empty list value (`[]`) — same defect class.
            if isinstance(val_raw, list) and not val_raw:
                return True, (
                    f"`Condition.{op}.{key}: []` is an empty list — "
                    "matches absent / unspecified key; ambiguous "
                    "evaluator semantics."
                )

            # Pattern 7: ArnLike with `*` in identifying segments.
            # `aws:PrincipalArn arn:aws:iam::*:*` matches every account
            # and every principal — degenerate. Round 7 agent-302.
            if op == "ArnLike" or op_lc == "arnlike" or op == "ArnEquals":
                for v in vals_str:
                    if v.startswith("arn:"):
                        parts = v.split(":", 5)
                        if len(parts) >= 6:
                            partition, _svc = parts[1], parts[2]
                            account, spec = parts[4], parts[5]
                            wildcard_partition = "*" in partition
                            wildcard_account = "*" in account or account == ""
                            wildcard_spec = spec == "*" or (
                                "*" in spec and spec.count("*") >= 1
                                and len(spec.replace("*", "")) < 3
                            )
                            if (wildcard_partition or wildcard_account) and wildcard_spec:
                                return True, (
                                    f"`Condition.{op}.{key}: {v}` is "
                                    "an ARN pattern with wildcards in "
                                    "the identifying segments — "
                                    "matches effectively any principal."
                                )

            # Pattern 8: Bool inverted (`SecureTransport: "false"`). AWS
            # docs recommend `Bool: aws:SecureTransport: "true"` to
            # enforce HTTPS. A "false" value INVERTS that — only
            # cleartext (HTTP) requests pass. Often a typo / cargo-cult
            # mistake. Round 7 agent-303, agent-429.
            if op_lc == "bool" or op == "BoolIfExists":
                if "securetransport" in key_lc:
                    for v in vals_str:
                        if v.lower() == "false":
                            return True, (
                                f"`Condition.{op}.aws:SecureTransport: "
                                "\"false\"` means HTTPS is REJECTED, only "
                                "cleartext HTTP requests pass. Almost "
                                "certainly the opposite of intent."
                            )

            # Pattern 9: NumericLessThan with absurdly large value
            # (`aws:MultiFactorAuthAge: 999999999`) — effectively
            # always true; the MFA age check imposes no real bound.
            if op_lc.startswith("numericlessthan") or op_lc.startswith("numericgreaterthan"):
                for v in vals_str:
                    try:
                        n = float(v)
                        if n >= 1_000_000:  # ~12 days in seconds
                            return True, (
                                f"`Condition.{op}.{key}: {v}` is an "
                                "implausibly-large numeric value; the "
                                "condition imposes no real constraint."
                            )
                    except (TypeError, ValueError):
                        # Type mismatch (string value passed to a numeric
                        # operator) — also a defect class. AWS may fail
                        # the condition at evaluation, but the policy
                        # text doesn't reflect the author's intent.
                        return True, (
                            f"`Condition.{op}.{key}: \"{v}\"` is a "
                            "non-numeric value passed to a numeric "
                            "operator. AWS will fail to evaluate; the "
                            "condition is broken."
                        )

            # Pattern 10: DateLessThan with far-future date — tautology.
            # `aws:CurrentTime < 2099-12-31` always matches.
            if op_lc.startswith("datelessthan"):
                for v in vals_str:
                    if any(yr in v for yr in ("2099", "2100", "9999")):
                        return True, (
                            f"`Condition.{op}.{key}: {v}` is a far-"
                            "future date; the condition always matches."
                        )

            # Pattern 11: policy-variable injection in Condition VALUE
            # (not just Resource ARN). `s3:prefix: "${aws:PrincipalTag/x}/*"`
            # — if the principal can write their own tag, they control
            # what the condition value expands to. Round 7 agent-327.
            for v in vals_str:
                if (
                    "${aws:PrincipalTag/" in v
                    or "${aws:RequestTag/" in v
                    or "${aws:ResourceTag/" in v
                ):
                    return True, (
                        f"`Condition.{op}.{key}: \"{v}\"` interpolates "
                        "an attacker-controllable tag — if the caller "
                        "has `iam:TagRole`/`TagUser` on themselves, "
                        "they control what the condition value "
                        "expands to, defeating the apparent scope."
                    )

    return False, ""


def _principal_is_public(principal: object) -> bool:
    """True if a resource-based-policy `Principal` field grants to any
    AWS account or anonymous internet caller (`*` wildcard).

    AWS accepts the wildcard in several syntactic forms:
      - `Principal: "*"`                    (bare-string short form)
      - `Principal: {"AWS": "*"}`           (typed-string)
      - `Principal: {"AWS": ["*"]}`         (typed-list-of-one)
      - `Principal: {"AWS": ["*", ...]}`    (any list containing `*`)
    Federated and Service principals can also be `*` though that's
    rarer (e.g. `Principal: {Federated: "*"}` = any SAML/OIDC IdP).

    Round 6 architectural finding: the scorer previously never read
    `Principal` at all, so every resource-based-policy bypass passed
    invisibly. Findings agent-148..157, 180, 181, 208, 210, 211, 234.
    """
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    for v in principal.values():
        if v == "*":
            return True
        vals = v if isinstance(v, list) else [v]
        for item in vals:
            if not isinstance(item, str):
                continue
            if item == "*":
                return True
            # ARN-shaped principals: wildcards in account or partition
            # mean "any account / any partition" — public-equivalent
            # even though the literal string isn't `*`. Round 7 agent-
            # 401-403 (`arn:aws:iam::*:root`), agent-300 (Federated
            # SAML provider with wildcard account).
            if item.startswith("arn:"):
                parts = item.split(":", 5)
                if len(parts) >= 6:
                    partition, _svc = parts[1], parts[2]
                    account, spec = parts[4], parts[5]
                    if "*" in partition or "*" in account:
                        return True
                    # SAML/OIDC provider with wildcard provider name
                    if "*" in spec and (
                        spec.startswith("saml-provider/")
                        or spec.startswith("oidc-provider/")
                    ):
                        return True
    return False


def _effect_is_allow(stmt: dict) -> bool:
    """True if `stmt`'s Effect is Allow (case-insensitive, normalized).

    Treats missing Effect as Allow because:
      1. AWS itself rejects a missing-Effect statement at policy-attach
         time, BUT the scorer's job is to flag risk BEFORE AWS sees the
         policy. A malformed statement may still pass other gates
         (legacy code paths, import tools, copy-paste from docs).
      2. Conservative scoring policy: malformed = worst-case.
      3. The author put a statement here with an Action and a Resource
         and forgot Effect. The plausible intent is Allow (you don't
         write a Deny without saying Deny). Score that intent.

    Round 6 finding agent-159 (missing Effect implicit Allow), agent-230
    (lowercase "allow" exact-match bypass).
    """
    eff = stmt.get("Effect")
    if eff is None:
        return True
    # Effect-as-list: some IAM tools emit `Effect: ["Allow"]` even
    # though the canonical form is a bare string. Round 8 agent-610.
    if isinstance(eff, list):
        if not eff:
            # Empty list — malformed → conservative worst-case.
            return True
        eff = eff[0]
    # Effect-as-non-string (number, bool, dict). Same defect class.
    if not isinstance(eff, str):
        return True
    normalized = _norm_grammar_str(eff).lower()
    # Effect: "" — empty string, present but malformed. Round 8 agent-611.
    if not normalized:
        return True
    return normalized == "allow"


def _canonical_action(action: str) -> str:
    """Return the action lowercased with its service prefix canonicalized
    via _SERVICE_ALIASES. Returns the all-lowercase form so the result
    can be looked up directly in the *_LC mirror sets.

    Normalizes the input via `_norm_grammar_str` first so trailing/
    leading whitespace, fullwidth letters, BOMs, and zero-width joiners
    don't sneak past set-membership lookups.
    """
    action = _norm_grammar_str(action)
    if ":" not in action:
        return action.lower()
    svc, _, name = action.partition(":")
    canon_svc = _SERVICE_ALIASES.get(svc.lower(), svc.lower())
    return f"{canon_svc}:{name.lower()}"
_CROSS_ACCOUNT_EXFIL_ACTIONS_LC = frozenset(a.lower() for a in _CROSS_ACCOUNT_EXFIL_ACTIONS)
_CODE_EXECUTION_PRIMITIVES_LC = frozenset(a.lower() for a in _CODE_EXECUTION_PRIMITIVES)


def _is_broad_resource(r: str) -> bool:
    """A resource string is 'broad' if it covers an unbounded set of items.

    Catches:
      - literal `*` (account-wide)
      - service-wide wildcards where the entire resource-spec is `*`
      - bucket-level wildcards like `arn:aws:s3:::my-bucket/*`
      - bucket-NAME-prefix wildcards like `arn:aws:s3:::prod-*`
      - IAM trailing-wildcard forms (`role/*`, `user/*`)
      - Non-IAM collection wildcards like `arn:aws:kms:.::alias/*`
      - ARN account-segment wildcards like `arn:aws:lambda:us-east-1:*:function:foo`
        (matches the resource in EVERY account in the org — broad)

    Does NOT match:
      - Path-narrowed wildcards (specific bucket + sub-path wildcard
        with NO wildcard in the bucket-name part)
      - Suffix wildcards inside a deeper ARN path
        (`log-group:/app:*` = one log group's streams)
    """
    if r == "*":
        return True
    # ARN-shaped resources: inspect the resource-spec portion only.
    if r.startswith("arn:"):
        parts = r.split(":", 5)
        if len(parts) < 6:
            return False  # malformed ARN — treat as narrow
        # ARN structure: arn:partition:service:region:account:resource-spec.
        # Wildcards in ANY of the identifying segments make the ARN
        # cross-partition / cross-region / cross-account broad:
        #   parts[1] partition (round 7 agent-417)
        #   parts[3] region (round 7 agent-418)
        #   parts[4] account (round 3 finding)
        if "*" in parts[1] or "*" in parts[3] or parts[4] == "*":
            return True
        resource_spec = parts[5]
        service = parts[2]
    else:
        resource_spec = r
        service = ""

    # Service-wide wildcard: the entire resource-spec is just `*`.
    if resource_spec == "*":
        return True

    # Collection wildcards across services. For IAM, the collection
    # types are `role`, `user`, `group`, `policy`, `instance-profile`.
    # For KMS, `alias` (the alias collection — wildcarding it equals
    # "every key alias"). For Lambda, `function:*` is already handled
    # by `_is_strict_wildcard` via the `:` separator. Extend the
    # principal-collection list to include `alias` and other common
    # service-specific collection types.
    if "/" in resource_spec:
        first_segment, _, rest = resource_spec.partition("/")
        # Known per-service single-collection wildcards
        collection_types = {
            "iam": ("role", "user", "group", "policy", "instance-profile"),
            "kms": ("alias", "key"),  # `key/*` round 8 agent-227
            "secretsmanager": ("secret",),
            "ec2": ("instance", "vpc", "subnet", "security-group"),
            "logs": (),  # logs uses `:` not `/` — not handled here
            # Round 8 BB: data-plane collection wildcards.
            "dynamodb": ("table",),    # agent-606
            "kinesis": ("stream",),    # agent-608
            "dax": ("cache",),         # agent-609
            "lambda": ("function",),   # agent-419-class
        }
        if first_segment in collection_types.get(service, ()):
            if rest == "*" or (rest.endswith("*") and "/" not in rest):
                return True

    # S3-style: bucket-name component (before first `/`) contains a
    # wildcard. Uses `_has_wildcard` so `?` (single-char wildcard) is
    # recognized the same as `*`.
    if "/" not in resource_spec:
        if _has_wildcard(resource_spec):
            return True
    else:
        bucket_part, _, _path_part = resource_spec.partition("/")
        if _has_wildcard(bucket_part):
            return True
        # Single-bucket bucket-level wildcard: `bucket/*` (one slash, ends in `/*`)
        if resource_spec.endswith("/*") and resource_spec.count("/") <= 1:
            return True

    return False


def _resources_are_broad(resources: list[str]) -> bool:
    """True if any resource in the list is broad (see `_is_broad_resource`)."""
    return any(_is_broad_resource(r) for r in resources)


@functools.lru_cache(maxsize=None)
def _service_action_levels(service: str) -> dict[str, str]:
    """Return {action_name: access_level} for every action in `service`.

    Cached per-service so the policy_sentry lookups happen once per process.
    Returns an empty dict for unknown services.
    """
    levels: dict[str, str] = {}
    for level in ("Read", "List", "Write", "Tagging", "Permissions management"):
        try:
            for action_full in get_actions_with_access_level(service, level) or []:
                if ":" not in action_full:
                    continue
                _, name = action_full.split(":", 1)
                levels[name] = level
        except Exception:
            continue
    return levels


def _action_level(action: str) -> str | None:
    """Look up the IAM access level for a specific action.

    Returns one of "Read", "List", "Write", "Tagging", "Permissions management",
    or None if the action is wildcarded, malformed, or unknown to policy_sentry.
    """
    if not action or ":" not in action or _has_wildcard(action):
        return None
    service, name = action.split(":", 1)
    return _service_action_levels(service).get(name)


@dataclass
class ReviewAnalysis:
    risk_score: int
    risk_factors: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    deterministic_score: int = 1
    llm_narrative: str | None = None
    analyzed_at: str = ""
    analyzer: str = "deterministic"
    context_fingerprints: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_factors": list(self.risk_factors),
            "suggestions": list(self.suggestions),
            "deterministic_score": self.deterministic_score,
            "llm_narrative": self.llm_narrative,
            "analyzed_at": self.analyzed_at,
            "analyzer": self.analyzer,
            "context_fingerprints": dict(self.context_fingerprints),
        }


def analyze_policy(
    policy: dict[str, Any],
    request: dict[str, Any],
    *,
    backend: "LLMBackend | None" = None,
    extra_sensitive_services: tuple[str, ...] = (),
    extra_high_impact_actions: tuple[str, ...] = (),
) -> ReviewAnalysis:
    """Score the policy 1-10 deterministically; optionally annotate via LLM.

    When `backend` is provided, the LLM contributes a 2-3 sentence narrative
    summary AND a small set of additional risk-reduction suggestions that
    supplement the deterministic ones. The score itself is fully
    deterministic — the LLM cannot raise or lower it.

    `extra_sensitive_services` and `extra_high_impact_actions` extend
    the built-in calibration with admin-curated org-specific context.
    See docs/TUNING-RISK.md for the workflow (commit-or-UI).
    """
    score, factors, suggestions = _deterministic(
        policy, request,
        extra_sensitive_services=extra_sensitive_services,
        extra_high_impact_actions=extra_high_impact_actions,
    )
    analyzer = "deterministic"
    narrative: str | None = None

    if backend is not None:
        try:
            narrative = _narrate_with_llm(policy, request, backend, score, factors)
            analyzer = f"deterministic+{getattr(backend, 'name', 'llm')}"
        except Exception:
            narrative = None
        try:
            for s in _suggest_with_llm(policy, request, backend, factors):
                if s and s not in suggestions:
                    suggestions.append(s)
        except Exception:
            pass

    fingerprints = dict(audit._BOOT_FINGERPRINTS) if backend is not None else {}
    return ReviewAnalysis(
        risk_score=score,
        risk_factors=factors,
        suggestions=suggestions,
        deterministic_score=score,
        llm_narrative=narrative,
        analyzed_at=_dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        analyzer=analyzer,
        context_fingerprints=fingerprints,
    )


def _deterministic(
    policy: dict[str, Any],
    request: dict[str, Any],
    *,
    extra_sensitive_services: tuple[str, ...] = (),
    extra_high_impact_actions: tuple[str, ...] = (),
) -> tuple[int, list[str], list[str]]:
    # Effective sensitive-service set = built-in baseline + admin
    # additions. The admin context can EXPAND the set (mark more
    # services as sensitive) but not REMOVE built-ins.
    effective_sensitive = _SENSITIVE_SERVICES | set(extra_sensitive_services)
    effective_high_impact = _HIGH_IMPACT_MUTATION_ACTIONS | set(extra_high_impact_actions)
    # Lower-cased mirror for case-insensitive comparison. AWS IAM treats
    # action names case-insensitively, so the scorer must too — otherwise
    # `iam:attachrolepolicy` slips past `_HIGH_IMPACT_MUTATION_ACTIONS`
    # while `iam:AttachRolePolicy` is caught. (Discovered round 2.)
    effective_high_impact_lc = frozenset(a.lower() for a in effective_high_impact)
    if not policy:
        return 1, ["No statements in policy"], []
    # AWS IAM policy grammar officially allows `Statement` to be either a
    # list of statement objects OR a single statement object (a bare dict).
    # The single-dict form is widely used in service-linked-role docs and
    # is accepted by AWS as a complete admin policy. Without this
    # normalization, the scorer treats `Statement: {dict}` as "no
    # statements" and silently scores 1 — a complete bypass for any
    # policy submitted in that grammar form. See:
    #   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
    # ("Statement: A list of statements is encouraged, but a single
    #  statement is allowed.")
    # Round 5 finding agent-96.
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
        policy = {**policy, "Statement": statements}
    elif not isinstance(statements, list):
        return 1, ["No statements in policy"], []

    # Missing `Version` key. AWS uses legacy semantics in its absence,
    # which makes policy variables (`${aws:username}` etc.) inert — a
    # narrowing condition operators thought they had silently doesn't
    # apply. AWS Access Analyzer flags this as a validation finding.
    # Research §7.5.
    missing_version = "Version" not in policy

    # Per-element type guard. A malformed `Statement: [null]` or
    # `Statement: ["free-form-comment", {real-dict}]` would crash
    # downstream `.get()` calls (the per-statement helpers all assume
    # dict). Worse: a caller that catches the crash and falls back to
    # score=1 would silently approve a policy that smuggled a real
    # Allow statement after the malformed entries. Round 8 white-box
    # findings agent-636, 637.
    #
    # Strategy: filter non-dict entries out, then flag the presence of
    # ANY malformed entries at floor 5 so the malformedness itself is
    # a risk signal (some adversarial smuggling depends on the caller
    # silently dropping malformed-looking statements).
    score = 1
    factors: list[str] = []
    suggestions: list[str] = []

    if missing_version:
        score = max(score, 6)
        factors.append(
            "Policy lacks `Version` field. AWS uses legacy semantics "
            "in its absence — policy variables like `${aws:username}` "
            "are NOT expanded, so any narrowing conditions that rely "
            "on them silently fail to apply. AWS Access Analyzer flags "
            "this as a validation finding."
        )
        suggestions.append(
            "Add `\"Version\": \"2012-10-17\"` to the policy header."
        )

    # Cross-script homoglyphs in Effect / Resource ARNs are themselves
    # a red flag — even after `_norm_grammar_str` collapses them, an
    # author typing Cyrillic 'а' instead of Latin 'a' is suspicious
    # (typo or attempted spoof). Flag at 5 on the RAW string. The
    # Effect-specific check catches `Effect: "Аllow"` AND
    # `Effect: "Dеny"` — even when the latter would correctly evaluate
    # as Deny post-normalization, the malformedness is itself a
    # signal that warrants human review. Round 7 agent-400, 425.
    if isinstance(statements, list):
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            eff_raw = stmt.get("Effect")
            if isinstance(eff_raw, str) and any(c in _LATIN_HOMOGLYPHS for c in eff_raw):
                score = max(score, 5)
                factors.append(
                    f"Statement `Effect: {eff_raw!r}` contains cross-"
                    "script homoglyph(s). Even when the value normalizes "
                    "to Allow / Deny, the malformedness is suspicious — "
                    "typo or attempted spoof. AWS will accept the "
                    "policy because it's syntactically valid string-typed; "
                    "review what the author actually intended."
                )
                break

    if isinstance(statements, list):
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            for r in (stmt.get("Resource"), stmt.get("NotResource")):
                rs = r if isinstance(r, list) else [r]
                for rv in rs:
                    if not isinstance(rv, str):
                        continue
                    if any(c in _LATIN_HOMOGLYPHS for c in rv):
                        score = max(score, 5)
                        factors.append(
                            f"Resource `{rv!r}` contains cross-script "
                            "homoglyph(s) — Cyrillic / Greek characters "
                            "that visually match Latin ASCII. Almost "
                            "certainly a typo or attempted spoof. "
                            "Verify the resource name is what the "
                            "author intended."
                        )
                        break
                else:
                    continue
                break

    valid_statements = [s for s in statements if isinstance(s, dict)]
    if len(valid_statements) != len(statements):
        n_dropped = len(statements) - len(valid_statements)
        score = max(score, 5)
        factors.append(
            f"Policy contains {n_dropped} malformed Statement "
            "entries (non-dict). The valid statements are still "
            "scored, but the malformedness itself indicates either "
            "a generation error or an attempt to smuggle statements "
            "past validators that drop malformed entries silently."
        )
        suggestions.append(
            "Validate the policy JSON against the AWS IAM grammar "
            "before submission. AWS will reject this at policy-attach "
            "time anyway."
        )
        # Replace `statements` with the filtered list so the rest of
        # the function operates on dict-only entries.
        policy = {**policy, "Statement": valid_statements}
        statements = valid_statements
        if not valid_statements:
            return score, factors, suggestions

    spec = request.get("spec") or {}
    has_constraints = bool(spec.get("resource_constraints"))
    # If access_type is unset, don't impose a read-only constraint — only
    # apply the rule when the requester explicitly opted into read-only.
    access_type = (spec.get("access_type") or "").strip().lower()
    is_read_only = access_type == "read-only"
    duration_hours = _resolve_duration_hours(spec.get("duration") or {})

    # Read-only requests must contain only IAM-level Read or List actions.
    # Anything else gets flagged with a recommendation. Three classes of
    # mismatch, in increasing severity:
    #   - Wildcard mutation (e.g. s3:*)  → score 8, hard mismatch
    #   - Definite write action (e.g. s3:DeleteObject) → score 8, hard
    #   - "Deceptive write" (e.g. rds-data:ExecuteStatement) → score 6,
    #     softer because the action is often used for read-style queries
    #     but technically can mutate state.
    if is_read_only:
        for stmt in policy["Statement"]:
            if not _effect_is_allow(stmt):
                continue
            for action in _as_list(stmt.get("Action")):
                if ":" not in action:
                    continue

                # Wildcard handling first. `_has_wildcard` catches
                # both `*` and `?` so `iam:?reateAccessKey` doesn't slip
                # through as a "specific action."
                if _has_wildcard(action):
                    action_part = action.split(":", 1)[1] if ":" in action else action
                    if action == "*" or action.endswith(":*") or _has_wildcard(action_part[:3]):
                        score = max(score, 8)
                        factors.append(
                            f"Request marked read-only but policy includes wildcard `{action}`"
                        )
                        suggestions.append(
                            "Either flip access_type to read-write (and re-justify), or "
                            "narrow the action list to Get*/List*/Describe* only."
                        )
                    continue

                # Specific action: look up its IAM access level.
                level = _action_level(action)
                if level in ("Read", "List", None):
                    # Read/List are genuine reads. None means policy_sentry
                    # doesn't know the action — don't flag (could be a new
                    # service we haven't indexed yet).
                    continue

                if action.lower() in _DECEPTIVE_WRITE_ACTIONS_LC:
                    score = max(score, 6)
                    factors.append(
                        f"`{action}` is IAM-classified as `{level}` despite being commonly used "
                        "for read-style queries. The same API call can DELETE/UPDATE with crafted input."
                    )
                    suggestions.append(
                        f"Either remove `{action}` (and use service-specific read-only APIs instead) "
                        "or flip access_type to read-write so the request is reviewed accordingly."
                    )
                else:
                    score = max(score, 8)
                    factors.append(
                        f"Request marked read-only but `{action}` is IAM-classified as `{level}` (mutates state)"
                    )
                    suggestions.append(
                        f"Remove `{action}` from the policy, or change access_type to read-write."
                    )

    for stmt in policy["Statement"]:
        if not _effect_is_allow(stmt):
            continue
        actions = _as_list(stmt.get("Action"))
        resources = _as_list(stmt.get("Resource"))

        # ---- Principal / NotPrincipal handling (resource-based policy
        # shape detection) ----
        #
        # A statement with `Principal` is a resource-based-policy
        # statement (S3 bucket policy, KMS key policy, Lambda
        # resource policy, IAM trust policy). The rest of this loop
        # assumes identity-policy semantics where the principal is
        # the resource grant's recipient (implied by the role). When
        # `Principal: "*"` or `NotPrincipal` is present, the statement
        # grants access to ANYONE, INCLUDING anonymous internet
        # callers — far more severe than any "narrow Resource" rule
        # would suggest. Round 6 BB findings agent-148..157, 180,
        # 181, 208, 210, 211; WB findings agent-201/208/210/211/234.
        principal = stmt.get("Principal")
        not_principal_key_present = "NotPrincipal" in stmt
        if principal is not None or not_principal_key_present:
            if _principal_is_public(principal):
                score = max(score, 9)
                factors.append(
                    "Statement has `Principal: \"*\"` (or `AWS: \"*\"`) "
                    "— resource-based-policy grant to ANY principal in "
                    "any AWS account or anonymous internet caller. "
                    "Public access regardless of how narrow the "
                    "Resource is."
                )
                suggestions.append(
                    "Replace `Principal: \"*\"` with an explicit list "
                    "of trusted account/role ARNs. If anonymous access "
                    "is intended, the statement needs a tight "
                    "Condition (e.g. `aws:PrincipalOrgID`) AND an "
                    "explicit authorization review."
                )
            if not_principal_key_present:
                # `NotPrincipal` on `Allow` grants to everyone EXCEPT
                # the listed principals — including principals outside
                # the account. AWS docs explicitly warn against this
                # construct.
                score = max(score, 9)
                factors.append(
                    "`NotPrincipal` on `Allow` grants access to every "
                    "principal EXCEPT those listed — INCLUDING "
                    "principals OUTSIDE the account. AWS documentation "
                    "explicitly warns against this construct."
                )
                suggestions.append(
                    "Replace `NotPrincipal` with an explicit "
                    "`Principal` list of the entities meant to be "
                    "granted access. `NotPrincipal` is almost always "
                    "wider than the author intended."
                )
            # Empty Principal list (`{AWS: []}`) — semantics ambiguous
            # across IAM evaluators. Flag at human-review tier. Round 6
            # agent-181. (Floor 5 not 4 — 4 falls under the default
            # auto-approve threshold, hiding the defect signal.)
            if isinstance(principal, dict) and not _principal_is_public(principal):
                non_empty_vals = [
                    v for v in principal.values()
                    if v not in ("", [], None)
                ]
                if not non_empty_vals and principal:
                    score = max(score, 5)
                    factors.append(
                        "Statement has empty Principal list (e.g. "
                        "`{AWS: []}`) — ambiguous semantics; some IAM "
                        "evaluators treat empty as \"match anyone.\" "
                        "Defect-class signal — escalate for review."
                    )
                # CanonicalUser principal — legacy S3 ACL identifier
                # distinct from AWS ARN principals. The presence of
                # this principal type is a strong "this is a resource-
                # based bucket policy" signal that the rest of the
                # rules (assuming identity-policy semantics) won't
                # catch. Flag at human-review tier. Round 6 agent-180.
                if "CanonicalUser" in principal:
                    score = max(score, 5)
                    factors.append(
                        "Statement uses `Principal.CanonicalUser` — "
                        "legacy S3 ACL identifier in a resource-"
                        "based-policy statement. The CanonicalUser "
                        "may belong to ANY AWS account and is not "
                        "validated against principal-arn rules."
                    )
                # Service principal trust without Condition. A trust
                # policy / resource policy granting access to an AWS
                # service (e.g. `lambda.amazonaws.com`) without any
                # Condition is overbroad — every Lambda in every
                # account can assume / invoke. Round 6 agent-210.
                if "Service" in principal:
                    service_principals = principal["Service"]
                    if isinstance(service_principals, str):
                        service_principals = [service_principals]
                    has_condition = bool(stmt.get("Condition"))
                    if service_principals and not has_condition:
                        score = max(score, 6)
                        factors.append(
                            f"`Principal.Service` ({service_principals[0]}) "
                            "with no Condition — every caller from that "
                            "service in any account can use this grant. "
                            "Typical service-trust policies need an "
                            "`aws:SourceAccount` or `aws:SourceArn` "
                            "condition to scope to your own resources."
                        )
                # Federated principal handling. Two sub-cases:
                #   a) ARN-shaped (`arn:aws:iam::<acct>:saml-provider/X`)
                #      — the provider's account may differ from the
                #      policy owner's account. We can't verify without
                #      context, so flag at 7 conservatively. Attacker
                #      controls a SAML provider in their own account →
                #      mints tokens → assumes our role.
                #      Round 7 BB agent-300.
                #   b) Federated service principal (`cognito-identity.
                #      amazonaws.com`, `accounts.google.com`, etc.) WITHOUT
                #      a Condition narrowing aud/sub — anyone with a
                #      token from that IdP can assume.
                #      Round 7 BB agent-301.
                if "Federated" in principal:
                    federated_vals = principal["Federated"]
                    if isinstance(federated_vals, str):
                        federated_vals = [federated_vals]
                    has_condition = bool(stmt.get("Condition"))
                    for fv in federated_vals:
                        if not isinstance(fv, str):
                            continue
                        if fv.startswith("arn:"):
                            # Federated ARN — cross-account SAML/OIDC
                            # provider possibly attacker-controlled.
                            score = max(score, 7)
                            factors.append(
                                f"`Principal.Federated` is an ARN "
                                f"(`{fv}`) — without context the scorer "
                                "can't verify the named SAML/OIDC "
                                "provider is in the policy owner's "
                                "account. Cross-account federated "
                                "providers let third parties mint "
                                "tokens that assume this role."
                            )
                            break
                        elif not has_condition:
                            # Federated service principal (cognito, OIDC
                            # IdP service name) with no aud/sub condition.
                            score = max(score, 7)
                            factors.append(
                                f"`Principal.Federated: \"{fv}\"` with "
                                "no Condition narrowing `aud`/`sub` — "
                                "any token issued by that identity "
                                "provider can assume the role. Typical "
                                "trust policies need `StringEquals` on "
                                f"`{fv}:aud` (and `{fv}:sub` for tighter "
                                "scope)."
                            )
                            break

            # Trust-policy semantic detection: a statement with
            # Principal + sts:AssumeRole-class action is a TRUST POLICY
            # (attached to a role, declaring who can assume it).
            # Any literal-ARN principal that isn't a wildcard is still
            # a cross-account-trust grant when the named account isn't
            # the deployer's. We can't compare accounts without context,
            # so floor at 7 when the Principal.AWS has any literal ARN
            # (not just wildcards). Round 8 WB agent-600, 601, 623.
            actions_in_stmt = _as_list(stmt.get("Action"))
            is_assume_role_action = any(
                _canonical_action(a).startswith("sts:assumerole")
                or _action_covers_any(a, frozenset(["sts:assumerole"]))
                for a in actions_in_stmt
            )
            if is_assume_role_action and isinstance(principal, dict):
                aws_principals = principal.get("AWS")
                if aws_principals is not None and not _principal_is_public(principal):
                    pvals = aws_principals if isinstance(aws_principals, list) else [aws_principals]
                    has_literal_arn = any(
                        isinstance(v, str) and v.startswith("arn:") and "*" not in v.split(":", 5)[4]
                        for v in pvals if isinstance(v, str)
                    )
                    if has_literal_arn:
                        score = max(score, 7)
                        factors.append(
                            "Trust-policy statement with literal account-ARN "
                            "Principal on `sts:AssumeRole` — grants role-assume "
                            "to a specific external account. Without context "
                            "the scorer can't verify the account is trusted; "
                            "flagged for human review (Rhino #14 / Pacu "
                            "iam__backdoor_assume_role)."
                        )
                        suggestions.append(
                            "Verify the trusted account ID matches an "
                            "approved partner. Add a `aws:PrincipalOrgID` "
                            "condition if the trust should be org-bounded."
                        )

        # Policy-variable injection in Resource — `${aws:PrincipalTag/...}`,
        # `${aws:RequestTag/...}`, `${aws:ResourceTag/...}` expand at
        # evaluation time to a tag value the principal may control. An
        # attacker with `iam:TagUser` / `iam:TagRole` on self rewrites
        # the tag to construct an arbitrary ARN. Stable identity
        # variables (`${aws:userid}`, `${aws:username}`) are NOT
        # flagged — they're principal-immutable. Round 6 agent-168.
        for r in resources:
            if "${aws:PrincipalTag/" in r or "${aws:RequestTag/" in r or "${aws:ResourceTag/" in r:
                score = max(score, 7)
                factors.append(
                    f"Resource `{r}` interpolates an attacker-"
                    "controllable tag (`${{aws:PrincipalTag/...}}` or "
                    "`${{aws:RequestTag/...}}` or `${{aws:ResourceTag/...}}`). "
                    "If the caller has `iam:TagRole` / `iam:TagUser` "
                    "on themselves (common in ABAC patterns), they "
                    "can rewrite the tag to construct any resource "
                    "ARN — the Resource scope is illusory."
                )
                suggestions.append(
                    "Replace tag-driven Resource variables with "
                    "either explicit ARN lists or the immutable "
                    "`${aws:userid}` / `${aws:username}` variables, "
                    "and revoke `iam:Tag*` permissions on the "
                    "principal's own ARN."
                )
                break

        # ---- Condition vacuity detection ----
        # An IAM statement's Condition block is the most common
        # source of false confidence in policy review — operators
        # (and most scoring tools) credit the presence of a
        # condition as risk-reducing without checking whether the
        # condition can actually match. `_condition_is_vacuous`
        # detects the highest-leverage failure patterns. When a
        # vacuous condition is present, floor at 5 (above auto-
        # approve, below catastrophic) so the policy escalates to
        # human review where the operator can spot the broken
        # condition. Round 6 findings agent-156, 182, 192, 201.
        condition = stmt.get("Condition")
        if condition:
            is_vacuous, vac_reason = _condition_is_vacuous(condition)
            if is_vacuous:
                score = max(score, 5)
                factors.append(vac_reason)
                suggestions.append(
                    "The condition above does not actually constrain "
                    "the grant. Rewrite using a key + operator + value "
                    "that AWS can evaluate against real request "
                    "attributes (e.g. `StringEquals` on "
                    "`aws:PrincipalOrgID`, `aws:PrincipalAccount`, "
                    "`aws:SourceVpce`, or a specific resource tag)."
                )

        # NotAction / NotResource handling. These keys are the inverse
        # form: "grant everything EXCEPT this set." A statement using
        # NotAction on Resource: `*` is effectively `*:*` minus the
        # explicit exclusions — i.e., near-total account access. AWS
        # itself flags `NotAction` as a footgun in the docs; we flag it
        # as a high-risk pattern unless the exclusion set is broad
        # enough that the residual surface is small. For now, any use
        # of NotAction with a wildcard resource floors the score at 9
        # (admin-minus-set is admin for practical purposes).
        not_action_key_present = "NotAction" in stmt
        not_actions = _as_list(stmt.get("NotAction"))
        not_resources = _as_list(stmt.get("NotResource"))
        # Empty `NotAction: []` with the key present means "exclude
        # nothing from the action set" — semantically equivalent to
        # `Action: "*"`. Combined with broad Resource this is full admin.
        # Round 5 finding agent-109.
        if not_action_key_present and not not_actions:
            resources_for_empty = resources or ["*"]
            on_broad = any(r == "*" or r.endswith(":*") for r in resources_for_empty)
            score = max(score, 10 if on_broad else 9)
            factors.append(
                "`NotAction: []` (empty exclusion list) grants every "
                "action — semantically equivalent to `Action: \"*\"`."
            )
            suggestions.append(
                "Remove `NotAction` and use an explicit `Action` list "
                "of the specific operations the role actually needs."
            )
        if not_actions:
            # NotAction is "every action EXCEPT this list" — almost
            # always far broader than the author intended. With wildcard
            # resource, it's admin-minus-set (floor 9). With narrow
            # resource, it's still "every service in the account except
            # the excluded ones" on that resource — which for a typical
            # exclusion list of 1-5 services is hundreds of allowed
            # actions. Floor at 7 even on narrow resources; 9 on broad.
            # The exclusion-list cardinality is the wrong defense — AWS
            # has 400+ services, so excluding 3-5 still leaves 395+.
            resources_for_not = resources or ["*"]
            on_broad = any(r == "*" or r.endswith(":*") for r in resources_for_not)
            excluded = ", ".join(not_actions[:3])
            if on_broad:
                score = max(score, 9)
                factors.append(
                    f"`NotAction` with wildcard resource grants everything "
                    f"EXCEPT [{excluded}]. This is admin-minus-set, "
                    "treated as full account access for risk purposes."
                )
            else:
                # NotAction with narrow resource: figure out what
                # catastrophic actions are IMPLICITLY allowed (not in
                # the exclusion list). If any catastrophic action is
                # NOT excluded, it's implicitly granted on the narrow
                # resource — floor at 9 (the catastrophic floor)
                # rather than 7. Round-4 white-box finding agent-95.
                not_actions_lc = {a.lower() for a in not_actions}
                # An exclusion "covers" a catastrophic action if any
                # not_actions entry would fnmatch-match it.
                catastrophic_not_excluded = []
                for cat_lc in _CATASTROPHIC_ACTIONS_LC:
                    if not any(
                        _fnmatch.fnmatchcase(cat_lc, na_lc)
                        for na_lc in not_actions_lc
                    ):
                        catastrophic_not_excluded.append(cat_lc)
                if catastrophic_not_excluded:
                    score = max(score, 9)
                    factors.append(
                        f"`NotAction` (excluding [{excluded}]) implicitly "
                        f"allows {len(catastrophic_not_excluded)} catastrophic "
                        f"actions (e.g. `{catastrophic_not_excluded[0]}`) — "
                        "the exclusion list doesn't cover them."
                    )
                else:
                    score = max(score, 7)
                    factors.append(
                        f"`NotAction` (excluding [{excluded}]) on narrow resource "
                        "still grants every action in every service except those "
                        "few — typically hundreds of allowed actions, broader than "
                        "the author likely intended."
                    )
            suggestions.append(
                "Replace `NotAction` with an explicit `Action` list of "
                "the operations the role actually needs. NotAction is "
                "almost always wider than the author intended."
            )
        # NotResource semantically means "every resource EXCEPT these."
        # By definition this is broader than a positive Resource list —
        # the only way to make it narrower than `Resource: *` is to
        # exclude almost everything, which operators essentially never
        # do. So: when NotResource is set (and isn't itself wildcarded),
        # treat the statement's resource set as broad for the rest of
        # the scoring rules below.
        if not_resources:
            if any(r == "*" or r.endswith(":*") for r in not_resources):
                # NotResource[*] is mathematically nothing (grants nothing).
                # Flag at low severity — likely misconfiguration.
                score = max(score, 3)
                factors.append(
                    "`NotResource` containing `*` grants no access — "
                    "likely a misconfiguration."
                )
            else:
                # Promote this statement to broad-resource semantics.
                # The destructive-on-broad / high-impact / catastrophic
                # / PassRole / cross-account-exfil rules below all gate
                # on `wildcard_resource` / `broad_blast_resource`; by
                # setting those true here, the per-action rules apply
                # as if Resource: * was named.
                wildcard_resource = True
                broad_blast_resource = True
                if any("*" in a for a in actions):
                    score = max(score, 8)
                    factors.append(
                        f"`NotResource` with wildcard action grants the "
                        f"action on every resource EXCEPT {not_resources[:2]}. "
                        "This pattern is almost always broader than intended."
                    )
                else:
                    score = max(score, 6)
                    factors.append(
                        f"`NotResource` excluding {not_resources[:2]} = "
                        f"effective resource set is 'everything except those' "
                        f"— broader than a positive Resource list would be. "
                        "The destructive/high-impact/catastrophic rules now "
                        "apply as if Resource: * was named."
                    )
                suggestions.append(
                    "Replace `NotResource` with an explicit `Resource` "
                    "list of the ARNs the role should reach."
                )

        # Two senses of "wildcard" — kept distinct because they apply
        # to different rules:
        #
        # `wildcard_resource` (the strict sense): literal `*` or a
        # service-wide wildcard like `arn:aws:s3:::*`. Used by the
        # rules that flag *account-/service-wide* blast (e.g. the
        # "broad cross-resource read/access" suggestion) — the
        # standard idiom `["bucket", "bucket/*"]` for single-bucket
        # access should NOT trip these, NOR should the log-stream
        # wildcard pattern `arn:aws:logs:...:log-group:/path:*`
        # (a stream-wildcard WITHIN one specific log group; fine-
        # grained scoping).
        #
        # `broad_blast_resource` (the inclusive sense): ALSO includes
        # bucket-level wildcards like `arn:aws:s3:::bucket/*`. Used by
        # the destructive-verb / high-impact-mutation rules — where
        # "I can wipe every object in this one bucket" is still a wide
        # enough blast to warrant flagging.
        def _is_strict_wildcard(r: str) -> bool:
            """Literal `*`, service-wide wildcard, single-collection
            wildcard via colon (`function:*`, `topic:*`), or IAM-style
            trailing wildcard (`role/*`, `user/*`). Also S3 bucket-name
            wildcards (`prod-*`, `*-staging`).

            Trailing `:*` inside a DEEP ARN path (like a log-stream
            wildcard within one log-group) does NOT count — that's
            fine-grained scoping.

            Patterns matched (broad):
              - `*`                                   account-wide
              - `arn:aws:s3:::*`                      service-wide
              - `arn:aws:s3:::prod-*`                 bucket-name-prefix wildcard
              - `arn:aws:s3:::prod-*/*`               objects in matching buckets
              - `arn:aws:lambda:.::function:*`        all functions
              - `arn:aws:iam::.::role/*`              all roles
              - `arn:aws:iam::.::role/team-*`         role-name-prefix

            Patterns NOT matched (narrow):
              - `arn:aws:logs:.::log-group:/path:*`   one log group's streams
              - `arn:aws:s3:::specific-bucket/prefix/*`   narrowed path
              - `arn:aws:iam::.::role/svc-role`       specific role
            """
            if r == "*":
                return True
            if not r.startswith("arn:"):
                return False
            parts = r.split(":", 5)
            if len(parts) < 6:
                return False
            # Account-segment wildcard: `arn:aws:svc:region:*:resource`
            # = the same resource in every account in the org. Broad.
            if parts[4] == "*":
                return True
            resource_spec = parts[5]
            service = parts[2]
            if resource_spec == "*":
                return True
            # Single-collection wildcard via colon: `function:*`, `topic:*`,
            # `secret:*`. Pattern: `<type>:*` with no `/` in <type> (rules
            # out `log-group:/path:*`).
            if ":" in resource_spec:
                first, _, rest = resource_spec.partition(":")
                if rest == "*" and "/" not in first:
                    return True
            # Per-service collection wildcards via slash: `role/*`,
            # `alias/*`, `secret/*`. Service-specific because different
            # services have different collection types.
            if "/" in resource_spec:
                collection, _, tail = resource_spec.partition("/")
                collection_types = {
                    "iam": ("role", "user", "group", "policy", "instance-profile"),
                    "kms": ("alias",),
                    "secretsmanager": ("secret",),
                    "ec2": ("instance", "vpc", "subnet", "security-group"),
                }
                if collection in collection_types.get(service, ()):
                    if tail == "*" or (tail.endswith("*") and "/" not in tail):
                        return True
            # S3 bucket-name wildcards: `prod-*` (no slash, has `*`/`?`) or
            # `prod-*/*` / `*/path/*` (bucket-name component has `*`/`?`).
            # Uses `_has_wildcard` so single-char `?` is recognized.
            if "/" not in resource_spec:
                if _has_wildcard(resource_spec):
                    return True
            else:
                bucket_part = resource_spec.split("/", 1)[0]
                if _has_wildcard(bucket_part):
                    return True
            return False

        wildcard_resource = any(_is_strict_wildcard(r) for r in resources)
        broad_blast_resource = _resources_are_broad(resources)

        # NotResource override: when NotResource is set (and isn't itself
        # wildcarded with `*`), the effective resource set is "everything
        # except those" — broader than a positive Resource list. The
        # destructive-on-broad / high-impact / catastrophic / cross-
        # account-exfil rules should fire as if Resource: * was named.
        if not_resources and not any(r == "*" or r.endswith(":*") for r in not_resources):
            wildcard_resource = True
            broad_blast_resource = True

        if "*" in actions:
            return (
                10,
                ["Action `*` grants every AWS API call (full admin)"],
                ["Replace `*` with the specific API actions actually needed."],
            )

        for action in actions:
            if action == "*":
                continue
            # AWS IAM is case-insensitive on action names AND service
            # prefixes. Lowercase the service so `IAM:*` matches the
            # same rules as `iam:*` (the canonical set is all-lower).
            service = (action.split(":", 1)[0] if ":" in action else action).lower()

            # Wildcard in the service portion: `*:Create*`, `*:Decrypt`,
            # `*:GetSecretValue`, etc. Matches that action name across
            # EVERY service that exposes it — typically dozens of services.
            # This is account-compromise tier on its own (e.g. `*:Create*`
            # matches iam:CreateAccessKey + organizations:CreateAccount +
            # iam:CreateRole + sso-admin:CreatePermissionSet, any one of
            # which is catastrophic). Floor at 8, or 9 if the action-name
            # half is itself broad (`*:*`, `*`, or empty).
            if _has_wildcard(service):
                action_name = action.split(":", 1)[1] if ":" in action else ""
                # Bare `*` is already handled as full admin elsewhere; we
                # only hit here for `*:something` shapes.
                if action_name in ("*", "") or _has_wildcard(action_name) and len(action_name) <= 2:
                    score = max(score, 10)
                    factors.append(
                        f"`{action}` has wildcard in BOTH service AND "
                        "action — equivalent to full admin"
                    )
                else:
                    # Floor at 9: `*:Create*` matches iam:CreateAccessKey
                    # + organizations:CreateAccount + iam:CreateRole etc.,
                    # any one of which is catastrophic on its own.
                    # `*:Delete*` similarly. The wildcard match is across
                    # the entire AWS API surface; we can't trust that
                    # the specific actions matched are safe.
                    score = max(score, 9)
                    factors.append(
                        f"`{action}` has wildcard in the service portion — "
                        f"matches `{action_name}` across every service that "
                        "exposes it. Almost certainly matches one or more "
                        "catastrophic actions (iam:CreateAccessKey, "
                        "organizations:CreateAccount, etc.)."
                    )
                    suggestions.append(
                        f"Replace `{action}` with explicit service:Action "
                        "pairs — `*:` in the service portion is almost "
                        "never the intended meaning."
                    )
                continue  # don't run the rest of the action-specific rules

            if action.endswith(":*"):
                if service in effective_sensitive:
                    score = max(score, 9 if service in {"iam", "organizations"} else 8)
                    factors.append(
                        f"`{action}` grants every action in sensitive service `{service}`"
                    )
                    suggestions.append(
                        f"Replace `{action}` with the specific `{service}:` operations needed."
                    )
                else:
                    # Service-wildcard on broad resource (e.g. `ec2:*` on
                    # `Resource: *`) is near-admin within that service —
                    # every API, every resource. Floor at 8 to ensure it
                    # routes to human review even for non-sensitive
                    # services. Service-wildcard with narrow resource
                    # scoping (e.g. `s3:*` on a single bucket) still
                    # floors at 7 — the bucket is fully owned by this
                    # caller, but that's still "every action in s3".
                    score = max(score, 8 if wildcard_resource else 7)
                    factors.append(f"`{action}` grants every action in `{service}`")
                    suggestions.append(
                        f"Replace `{action}` with explicit `{service}:` actions."
                    )

            if _has_wildcard(action) and not action.endswith(":*"):
                # e.g. iam:Create*, ec2:*Network*, s3:Delete*. The
                # wildcard is a glob inside the action-name portion
                # (after the colon). Three cases worth distinguishing:
                #
                #   1. Sensitive service — floor at 7 regardless of
                #      what the pattern matches.
                #   2. Destructive-verb prefix (e.g. s3:Delete*,
                #      ec2:Terminate*, dynamodb:Drop*) — floor at 7,
                #      it matches every destructive verb in that
                #      service.
                #   3. Infix or other wildcard with broad resource —
                #      floor at 5. Catches `ec2:*Network*` matching
                #      CreateNetworkInterface + DeleteNetworkAcl etc.
                # Before service-sensitivity branch: check if this glob
                # would fnmatch any catastrophic action. `iam:Create*`
                # matches `iam:CreateAccessKey`, `iam:CreateOpenIDConnect-
                # Provider`, etc. — all catastrophic individually. If the
                # glob is a superset of catastrophic actions, floor at 9.
                # (Module-level `_fnmatch` is already imported.)
                action_lc = action.lower()
                matches_cat = any(
                    _fnmatch.fnmatchcase(cat_lc, action_lc)
                    for cat_lc in _CATASTROPHIC_ACTIONS_LC
                )
                if matches_cat:
                    matched_examples = sorted(
                        c for c in _CATASTROPHIC_ACTIONS
                        if _fnmatch.fnmatchcase(c.lower(), action_lc)
                    )[:3]
                    score = max(score, 9)
                    factors.append(
                        f"Action-name glob `{action}` matches catastrophic "
                        f"actions including {', '.join(matched_examples)} — "
                        "the glob is a superset of always-human-review actions."
                    )
                    suggestions.append(
                        f"Replace `{action}` with the specific actions actually "
                        "needed; the glob silently includes account-compromise "
                        "primitives."
                    )
                elif service in effective_sensitive:
                    score = max(score, 7)
                    factors.append(
                        f"Wildcard within sensitive service action: `{action}`"
                    )
                else:
                    action_part = (action.split(":", 1)[1] if ":" in action else action).lower()
                    destructive_prefixes_lc = (
                        "delete", "destroy", "reset", "terminate",
                        "disable", "stop", "revoke", "cancel", "drop",
                        "remove", "forget", "clear", "empty", "wipe",
                        "purge", "abort", "kill", "suspend", "detach",
                        "disassociate",
                    )
                    if action_part.startswith(destructive_prefixes_lc):
                        score = max(score, 7)
                        factors.append(
                            f"Destructive action-name wildcard `{action}` — "
                            f"matches every destructive {service} API"
                        )
                        suggestions.append(
                            f"Replace `{action}` with the specific destructive "
                            f"{service} operations actually needed."
                        )
                    elif wildcard_resource:
                        # Generic wildcard inside the action name with
                        # broad resource — covers ec2:*Network*,
                        # logs:*Subscription*, etc.
                        score = max(score, 5)
                        factors.append(
                            f"Action-name wildcard `{action}` on broad resource "
                            f"— matches multiple {service} APIs at once"
                        )
                        suggestions.append(
                            f"Replace `{action}` with the specific {service} "
                            "operations the role needs."
                        )

            if action.lower() == "iam:passrole":
                if wildcard_resource:
                    score = max(score, 9)
                    factors.append(
                        "`iam:PassRole` on Resource: `*` is a privilege-escalation path"
                    )
                    suggestions.append(
                        "Restrict iam:PassRole to specific role ARNs the requester needs to pass."
                    )
                else:
                    # Narrow PassRole still allows attaching ONE specific
                    # role to a service principal — if that role is more
                    # privileged than the caller, that's escalation. Always
                    # warrants a human glance; floor at 4 (medium tier).
                    score = max(score, 4)
                    factors.append(
                        "`iam:PassRole` is an escalation primitive — the "
                        "target role may have more privileges than the "
                        "caller. Even narrowly-scoped PassRole should be "
                        "reviewed against the role's actual policy."
                    )
                    suggestions.append(
                        "Confirm the target role's policy doesn't exceed "
                        "what the caller already has. Avoid auto-approve "
                        "even when PassRole is scoped to one role."
                    )
            elif action.lower() in _HIGH_RISK_ACTIONS_LC and wildcard_resource:
                score = max(score, 7)
                factors.append(
                    f"`{action}` on Resource: `*` (broad access to "
                    f"{'secrets' if 'secret' in action.lower() else 'sensitive resource'})"
                )
                suggestions.append(
                    f"Scope `{action}` to specific ARNs (`{service}:` resources)."
                )
            elif (
                ":" in action
                and service in effective_sensitive
                and wildcard_resource
            ):
                score = max(score, 6)
                factors.append(
                    f"`{action}` on Resource: `*` touches sensitive service `{service}`"
                )

        # Destructive-action-on-wildcard check. Applies REGARDLESS of
        # access_type (the read-only mismatch path above only fires when
        # access_type=read-only, and a malicious or sloppy requester
        # marking a destructive request as read-write bypassed all the
        # other checks). For explicit specific actions like
        # `s3:DeleteObject` + `s3:DeleteBucket` on Resource: `*` — or on
        # `arn:aws:s3:::bucket/*` (every object in one bucket) — the
        # broad blast radius is the risk, not the service-sensitivity
        # classification. Uses `broad_blast_resource` so bucket-level
        # wildcards fire this rule too.
        for action in actions:
            if action == "*" or ":" not in action:
                continue
            if not broad_blast_resource:
                continue
            level = _action_level(action)
            # Explicitly destructive shapes regardless of IAM class —
            # the verb itself describes irreversibility. Floor at 7
            # so they ALWAYS route to human review (above threshold
            # 5 by default; admins can raise threshold up to floor 5).
            # Lowercased so the prefix match is case-insensitive
            # (AWS IAM is case-insensitive; the round-4 white-box agent
            # found `s3:deletebucket` bypassing the canonical-case
            # `"Delete"` prefix). Expanded the verb list with round-4
            # additions: Remove, Forget, Clear, Empty, Wipe, Purge,
            # Abort, Kill, Suspend, Detach, Disassociate.
            action_name = (action.split(":", 1)[1] if ":" in action else action).lower()
            destructive_verbs_lc = (
                "delete", "destroy", "reset", "terminate",
                "disable", "stop", "revoke", "cancel",
                "drop", "remove", "forget", "clear",
                "empty", "wipe", "purge", "abort", "kill",
                "suspend", "detach", "disassociate",
            )
            if action_name.startswith(destructive_verbs_lc):
                # Floor at 8: a destructive verb on a broad resource is
                # always above the "auto-approve at threshold 5" line AND
                # above "medium" tier. The blast radius — every resource
                # in scope (literal `*`, service-wide, or one bucket) —
                # makes this categorically a human-review case.
                score = max(score, 8)
                factors.append(
                    f"Destructive action `{action}` on Resource: `*` "
                    f"(blast radius = every resource in this account)"
                )
                suggestions.append(
                    f"Scope `{action}` to specific resource ARNs (e.g., "
                    f"the one bucket/object/instance you actually need "
                    f"to operate on). Wildcard resource on a destructive "
                    "action is rarely intentional."
                )
            # Non-destructive but still IAM-class Write/Permissions/
            # Tagging actions on Resource: `*` are state-changing with
            # potentially broad reach. Floor at 6 (above default
            # threshold 5 but below the destructive floor).
            elif level in ("Write", "Permissions management", "Tagging"):
                score = max(score, 6)
                factors.append(
                    f"State-changing action `{action}` on Resource: `*` "
                    f"(IAM access level: {level})"
                )
                suggestions.append(
                    f"Scope `{action}` to specific resource ARNs so the "
                    "change can only affect the resources you've named."
                )

        if wildcard_resource and all(":" in a for a in actions):
            services_in_stmt = {a.split(":", 1)[0] for a in actions}
            # Skip the "broad cross-resource" rule entirely when EVERY
            # action is a metadata-listing pattern (action name starts
            # with Describe* or List*). These are routine "list
            # resources in this service" / "describe all in the
            # account" operations that aren't risky — no state change,
            # no resource content exposed, and commonly the entire
            # content of AWS-managed *ReadOnlyAccess policies.
            #
            # IMPORTANT: Get* actions are NOT included here. `Get*`
            # often reads resource CONTENT (s3:GetObject reads the
            # actual bytes, logs:GetLogEvents reads log text, etc.),
            # which IS sensitive on a service-wide wildcard. The
            # already-existing _HIGH_RISK_ACTIONS list handles the
            # individual content-read cases (secretsmanager:GetSecretValue,
            # kms:Decrypt, etc.). For Get* not in that list, the
            # cross-resource-read rule still fires.
            def _is_metadata_listing(a: str) -> bool:
                if "*" in a or ":" not in a:
                    return False
                name = a.split(":", 1)[1]
                return name.startswith(("Describe", "List"))

            all_metadata_listing = all(_is_metadata_listing(a) for a in actions)

            if not (services_in_stmt & effective_sensitive) and not all_metadata_listing:
                score = max(score, 4)
                services_label = ", ".join(sorted(services_in_stmt))
                factors.append(
                    f"Resource: `*` for {services_label} (broad cross-resource read/access)"
                )
                suggestions.append(
                    "Consider adding `resource_constraints` for "
                    f"{services_label} to scope to specific ARNs."
                )

        # High-impact mutation actions floor the score by resource scope:
        #   - narrow resource: floor 5 (still risky, but bounded)
        #   - broad/wildcard resource: floor 8 (catastrophic-tier blast)
        # Single-resource scope protects against scope creep but not
        # against the action's blast. On broad resource the action
        # mutates many resources in one call — a single DNS-record
        # primitive on `*` rewrites every record in every zone.
        # Round 6: previously a flat-5 floor; bumped on broad because
        # nearly all the round-6 high-impact-on-broad findings (RAM
        # CreateResourceShare, ec2:ModifyVpcEndpoint, eks:UpdateClusterConfig,
        # bedrock:PutUseCase, redshift:GetClusterCredentials, etc.)
        # are 8-tier severity when scoped account-wide.
        for action in actions:
            if (_canonical_action(action) in effective_high_impact_lc
                    or _action_covers_any(action, effective_high_impact_lc)):
                if wildcard_resource:
                    score = max(score, 8)
                    factors.append(
                        f"`{action}` is a high-impact mutation on broad "
                        "resource — single API call can rewrite every "
                        "matching resource in the account."
                    )
                else:
                    score = max(score, 5)
                    factors.append(
                        f"`{action}` is a high-impact mutation — a single "
                        "narrowly-scoped change can affect production "
                        "operations / security posture."
                    )
                suggestions.append(
                    "High-impact mutations should not auto-approve "
                    "below medium-risk thresholds — set "
                    "IAM_JIT_AUTO_APPROVE_RISK_BELOW lower than 5 "
                    "to route this through human review."
                )

        # Catastrophic actions floor at 9 regardless of resource scope.
        # These are API calls where the blast radius is "the entire
        # account / its governance / its evidence trail" — auto-approve
        # is never appropriate even on a single narrowly-resourced ARN.
        # See `_CATASTROPHIC_ACTIONS`.
        for action in actions:
            if (_canonical_action(action) in _CATASTROPHIC_ACTIONS_LC
                    or _action_covers_any(action, _CATASTROPHIC_ACTIONS_LC)):
                score = max(score, 9)
                factors.append(
                    f"`{action}` is catastrophic in blast radius "
                    "(account governance / IAM total compromise / "
                    "evidence destruction). Always route to human review."
                )
                suggestions.append(
                    f"Even with a specific resource ARN, `{action}` "
                    "should never auto-approve. If this is a legitimate "
                    "operational need, justify why a human shouldn't "
                    "approve it."
                )

        # Narrow-write floor. Even when scoped to a single specific
        # resource ARN, a state-changing action deserves to sit above
        # "completely safe" (score 1). Floor at 3 — still well below
        # the auto-approve threshold of 5, so this doesn't gate the
        # request, just acknowledges "this is a write, not a read."
        # Pure read-only statements (all actions are IAM-classified
        # Read or List) stay at 1. Wildcard-resource statements are
        # already handled by the destructive-on-wildcard / high-impact
        # rules above, so this only fires for narrow ARNs.
        # Narrow-write floor — refactored 2026-05-13 (round 4) to NOT
        # break early. The previous version exited at the first match,
        # making the resulting score depend on the action list ORDER
        # (a determinism bug). Now: walk every action, take the max.
        if not wildcard_resource:
            narrow_floor = 0
            for action in actions:
                if action == "*" or ":" not in action or _has_wildcard(action):
                    continue
                level = _action_level(action)
                if level in ("Write", "Permissions management"):
                    narrow_floor = max(narrow_floor, 3)
                elif level == "Tagging":
                    narrow_floor = max(narrow_floor, 2)
            if narrow_floor:
                score = max(score, narrow_floor)

        # Sensitive-service narrow-read floor. Reading IAM metadata
        # (GetRole, ListUsers), describing secrets, listing KMS keys
        # — these don't mutate but they leak organizational structure
        # and sensitive metadata. Floor at 2 (above noise, well below
        # threshold).
        if not wildcard_resource:
            for action in actions:
                if action == "*" or ":" not in action or _has_wildcard(action):
                    continue
                svc = action.split(":", 1)[0].lower()
                if svc in effective_sensitive:
                    level = _action_level(action)
                    if level in ("Read", "List"):
                        score = max(score, 2)
                        break

    # ============================================================
    # POLICY-LEVEL COMPOSITION RULES (cross-statement)
    # ============================================================
    # The per-statement loop above scores each statement in isolation.
    # Some attack patterns require composing actions across statements:
    # "I can create code" + "I can pass an admin role to it" = RCE-as-admin,
    # even when each statement on its own is medium-risk.
    #
    # Walk the whole policy once collecting (action, has_broad_resource)
    # signal, then check composition patterns.

    # For each action, track both senses of "broad":
    #   - inclusive_broad: bucket-level wildcards count. Used by the
    #     destructive-on-broad rule and the composition rules where
    #     bucket-level scope is still wide blast.
    #   - strict_broad: only account-wide / service-wide / bucket-NAME
    #     wildcards count. Used by the secret-bearing-read rule and
    #     cross-account-exfil rule, where single-bucket wildcards are
    #     legitimate (the EKS-pod-reads-one-bucket pattern).
    def _is_strict_wild_top(r: str) -> bool:
        """Module-level mirror of the local helper used inside the
        per-statement loop. Strict wildcard: literal `*`, service-wide,
        bucket-name wildcard, IAM trailing wildcard — but NOT
        S3 bucket/* (single-bucket scope) where surrounding ARN
        segments are fully narrow.

        The "single-bucket exemption" is service-specific:
          - S3 `bucket/foo` is genuinely narrow (one bucket's path).
          - DynamoDB `table/*` is a COLLECTION wildcard (every table
            in the account/region) — NOT narrow.
          - Kinesis `stream/*`, DAX `cache/*` same story.
        Round 8 WB finding agent-606/608/609: the original exemption
        was service-agnostic and accidentally exempted these non-S3
        collection wildcards.
        """
        if not _is_broad_resource(r):
            return False
        if not (r.startswith("arn:") and r.endswith("/*") and r.count("/") == 1):
            return True  # strict broad
        parts = r.split(":", 5)
        if len(parts) < 6:
            return True
        # Account or region wildcard → cross-account / cross-region broad,
        # NOT the legitimate "single-bucket sub-path" case.
        if "*" in parts[3] or "*" in parts[4]:
            return True
        # The single-bucket exemption only applies to services where
        # `<collection>/*` means "items inside ONE named container."
        # S3 is the main case. For other services where `<collection>/*`
        # is a service-wide wildcard, the exemption doesn't apply.
        service = parts[2]
        if service != "s3":
            return True
        # Resource-name segment must be literal (no `*`) for the
        # narrow-single-bucket exception to apply.
        resource_spec = parts[5]
        bucket_part = resource_spec.split("/", 1)[0]
        if "*" in bucket_part:
            return True
        return False  # genuinely narrow S3 single-bucket sub-path

    all_actions: list[tuple[str, bool, bool]] = []
    for stmt in policy["Statement"]:
        if not _effect_is_allow(stmt):
            continue
        resources_in_stmt = _as_list(stmt.get("Resource"))
        not_resources_in_stmt = _as_list(stmt.get("NotResource"))
        inclusive_broad = _resources_are_broad(resources_in_stmt)
        strict_broad = any(_is_strict_wild_top(r) for r in resources_in_stmt)
        # NotResource promotion (white-box round-4 finding agent-90):
        # the per-statement loop already promotes wildcard_resource +
        # broad_blast_resource when NotResource is set; the policy-level
        # all_actions collection must do the same or the composition
        # rules below see NotResource statements as "narrow." When
        # NotResource is set and isn't itself wildcarded, treat the
        # statement's resource set as broad for the composition rules.
        if not_resources_in_stmt and not any(
            r == "*" or r.endswith(":*") for r in not_resources_in_stmt
        ):
            inclusive_broad = True
            strict_broad = True
        for a in _as_list(stmt.get("Action")):
            all_actions.append((a, inclusive_broad, strict_broad))

    action_names = {a for a, _, _ in all_actions}

    # ---- Composition rule: code-execution-via-role ----
    # If the policy contains an action that creates/executes code AND
    # ALSO contains iam:PassRole, the combination = RCE-as-the-passed-role.
    # Floor at 9. Uses `_action_covers_any` (glob-aware) so a wildcard
    # action like `lambda:Create*` triggers the rule too — round-4
    # finding agent-88: the previous `set & set` intersection only
    # caught literal action names.
    action_names_lc = {a.lower() for a in action_names}
    has_code_exec = any(
        _action_covers_any(a, _CODE_EXECUTION_PRIMITIVES_LC)
        for a in action_names
    )
    pass_role_broad = any(
        a.lower() == "iam:passrole" and inclusive for a, inclusive, _ in all_actions
    )
    pass_role_any = "iam:passrole" in action_names_lc

    # Code-execution-primitive ALONE on broad resource (no PassRole)
    # still deserves a higher floor than the high-impact-mutation floor
    # of 5. The action could deploy attacker code to any matching
    # resource — even without explicit PassRole composition, the role
    # the resource runs under is at risk. Floor 7 on strict-broad.
    if any(
        _canonical_action(a) in _CODE_EXECUTION_PRIMITIVES_LC and strict
        for a, _i, strict in all_actions
    ):
        # Round 5: bumped from 7 → 8. A code-execution primitive on
        # `Resource: *` means "deploy attacker-controlled code under
        # every existing role of matching resources in the account."
        # That blast radius (typically dozens of Lambda roles, every
        # CloudFormation stack role, every Glue job role) is solidly
        # 8-tier, not 7. Agent findings 124, 127.
        score = max(score, 8)
        which_examples = sorted([
            a for a, _i, _s in all_actions
            if _canonical_action(a) in _CODE_EXECUTION_PRIMITIVES_LC
        ])[:3]
        factors.append(
            f"Code-execution primitive on broad resource: "
            f"{', '.join(which_examples)}. Deploys attacker-controlled "
            "code that runs under whatever role the matched resources "
            "use. Even without explicit PassRole, the existing roles "
            "of matched resources become the attack target."
        )

    if has_code_exec and pass_role_any:
        # Even with a narrow PassRole resource ARN, the COMBINATION is
        # full account-compromise tier: the attacker controls the code,
        # AND has the right to bind a role to it. The narrow ARN doesn't
        # mitigate — if it points at an admin-ish role, the result is
        # RCE-as-admin. Floor at 9 regardless of resource scope.
        floor = 9
        score = max(score, floor)
        # Find which actions matched. Use the glob-aware check so a
        # wildcard action like `lambda:Create*` is included in the
        # display (rather than producing an empty list and crashing).
        which = sorted([
            a for a in action_names
            if _action_covers_any(a, _CODE_EXECUTION_PRIMITIVES_LC)
        ])[:3]
        if not which:
            which = ["<wildcard>"]
        factors.append(
            f"Code-execution-via-role composition: {which[0]}"
            + (f" (+ {len(which) - 1} more)" if len(which) > 1 else "")
            + " combined with iam:PassRole = RCE as the passed role. "
            "Single-statement scoring underweights this; the composition "
            "is full account-compromise tier."
        )
        suggestions.append(
            "Remove iam:PassRole OR remove the code-execution action; "
            "they should not appear in the same role's permissions. If "
            "both are needed, scope iam:PassRole to a role with strictly "
            "less privilege than the caller, and audit the code-execution "
            "resource ARN is one specific function/instance/job."
        )

    # ---- Composition rule: IAM recon + sts:AssumeRole on broad role ----
    # Listing IAM roles is enumeration; sts:AssumeRole on `role/*` is the
    # actual movement. Each statement on its own scores below threshold;
    # the combo is textbook lateral movement.
    iam_recon_actions_lc = frozenset(a.lower() for a in {
        "iam:ListRoles", "iam:GetRole", "iam:ListPolicies",
        "iam:ListAttachedRolePolicies", "iam:GetRolePolicy",
        "iam:ListUsers", "iam:GetUser", "iam:ListGroups",
        "iam:ListAccessKeys", "iam:GetAccountAuthorizationDetails",
    })
    # Use glob-aware coverage: `iam:List*` or `iam:Get*` should fire
    # the rule too (they're recon-superset). Round-4 agent-89.
    has_iam_recon = any(
        _action_covers_any(a, iam_recon_actions_lc) for a in action_names
    )
    has_assume_broad = any(
        a.lower() == "sts:assumerole" and inclusive for a, inclusive, _ in all_actions
    )
    if has_iam_recon and has_assume_broad:
        # Lateral-movement-to-admin is full compromise; floor at 9.
        score = max(score, 9)
        factors.append(
            "IAM-recon + broad sts:AssumeRole composition — enumerate "
            "roles then assume any of them. Textbook lateral-movement "
            "primitive; the per-statement view misses it."
        )
        suggestions.append(
            "Scope sts:AssumeRole to specific role ARNs the caller has "
            "a documented need to assume; remove the broad iam: read "
            "permissions if not strictly required."
        )

    # ---- Secret-bearing-reads on broad resource ----
    # Get* actions that read content commonly containing secrets — when
    # on a *strictly* broad resource (account/service-wide or bucket-
    # NAME wildcard), they're exfil primitives. Single-bucket reads
    # (`bucket/*`) DON'T fire this — that's legitimate "read everything
    # in this app's bucket."
    for action, _inclusive, strict in all_actions:
        canon = _canonical_action(action)
        if (
            (canon in _SECRET_BEARING_READS_LC
             or _action_covers_any(canon, _SECRET_BEARING_READS_LC))
            and strict
        ):
            score = max(score, 7)
            factors.append(
                f"`{action}` on broad resource reads content that "
                "frequently contains secrets / sensitive data (boot "
                "logs, command output, log streams, message bodies)."
            )
            suggestions.append(
                f"Scope `{action}` to specific resource ARNs the caller "
                "needs to inspect."
            )
            break

    # ---- Cross-account exfil / persistent-exfil primitives ----
    # Setting up replication, log subscriptions, snapshot sharing, etc.
    # is a single API call that creates ONGOING unauthorized access.
    # Floor at 8 regardless of resource scope (the "configuration"
    # itself is the attack — narrow target ARN doesn't help).
    for action, _inclusive, _strict in all_actions:
        if (_canonical_action(action) in _CROSS_ACCOUNT_EXFIL_ACTIONS_LC
                or _action_covers_any(action, _CROSS_ACCOUNT_EXFIL_ACTIONS_LC)):
            score = max(score, 8)
            factors.append(
                f"`{action}` sets up ongoing cross-account / persistent "
                "exfiltration in a single call. The blast is 'everything "
                "that flows through this resource from now on,' not just "
                "what exists today."
            )
            suggestions.append(
                f"Confirm `{action}` is part of a documented operational "
                "flow (DR replication, log shipping to your own SIEM, "
                "etc.) and that the destination is your own account."
            )
            break

    if not factors:
        # No flags fired — score depends on resource specificity.
        if has_constraints:
            score = max(score, 2)
            factors.append("Scoped to specific resources via resource_constraints")
        else:
            factors.append("All statements are scoped or limited; no broad patterns")

    if is_read_only and not any("read-only" in f.lower() for f in factors):
        # Surface the read-only marker as a positive signal for the approver.
        factors.append("Request explicitly marked read-only (cannot mutate state)")

    # Duration adjustment — longer grants are riskier for the same policy.
    # The adjustment scales with the base score so a low-risk policy for
    # a long time stays low-risk, but a medium/high-risk policy for an
    # extended window gets pushed up.
    if duration_hours is not None and duration_hours > 24:
        days = duration_hours / 24
        adj = 0
        if score >= 4 and duration_hours > 24 * 7:  # > 1 week + non-trivial baseline
            adj = 1
        if score >= 6 and duration_hours > 24 * 30:  # > 1 month + meaningful baseline
            adj = max(adj, 2)
        if score >= 8 and duration_hours > 24:  # > 1 day on already-high-risk
            adj = max(adj, 1)
        if adj > 0:
            score = min(10, score + adj)
            factors.append(
                f"Duration {days:.0f}+ days — extended grant raises risk on top "
                "of the base policy score."
            )
            suggestions.append(
                "Consider a shorter window (re-request when needed) to reduce blast radius."
            )

    # Deduplicate while preserving order.
    factors = _dedupe(factors)
    suggestions = _dedupe(suggestions)
    return score, factors, suggestions


def _resolve_duration_hours(duration: dict[str, Any]) -> int | None:
    """Return the grant duration in hours from a `spec.duration` block.

    The schema requires exactly one of `duration_hours` or `not_after`; we
    handle both. For `not_after` we compute hours from now() so the
    effective window — not the calendar size — drives the risk adjustment.
    """
    if "duration_hours" in duration:
        try:
            return int(duration["duration_hours"])
        except (TypeError, ValueError):
            return None
    not_after = duration.get("not_after")
    if not isinstance(not_after, str):
        return None
    try:
        deadline = _dt.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    except ValueError:
        return None
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=_dt.UTC)
    delta = deadline - _dt.datetime.now(_dt.UTC)
    if delta.total_seconds() <= 0:
        return None
    return max(1, int(delta.total_seconds() / 3600))


def _narrate_with_llm(
    policy: dict[str, Any],
    request: dict[str, Any],
    backend: "LLMBackend",
    deterministic_score: int,
    factors: list[str],
) -> str | None:
    """Ask the LLM for a 2-3 sentence approver-facing summary.

    The LLM is bounded to commentary only — it cannot change the score or
    the factor list. We forward the policy/context and ask for narrative.
    """
    description = (request.get("spec") or {}).get("description") or ""
    services, _ = backend.refine(
        description=(
            "You are reviewing an IAM policy on behalf of a security/infra approver. "
            "Below is the policy and the requester's task description. "
            "Return a JSON object with one key `services` containing 1-3 short bullet-style "
            "concerns the approver should weigh, drawn from the actual policy and description. "
            "Do not invent actions; do not output IAM action strings; "
            "do not produce free text outside the JSON. "
            "IMPORTANT: this iam-jit instance can only see what's in the policy/description "
            "and any admin-provided org-context — it has NO access to the user's application "
            "code, repositories, kubeconfigs, the internet, or AWS account contents. "
            "Frame concerns from that limited vantage; recommend the user supplement with "
            "local context (e.g., a local AI agent that can read their codebase) when needed. "
            f"Deterministic risk score: {deterministic_score}/10. "
            f"Deterministic factors: {factors!r}. "
            f"Policy: {policy!r}. "
            f"Description: {description!r}"
        ),
        initial_services=[],
        initial_actions=[],
    )
    if not services:
        return None
    bullets = [s for s in services if isinstance(s, str) and s.strip()]
    if not bullets:
        return None
    return " ".join(bullets[:3])


def _suggest_with_llm(
    policy: dict[str, Any],
    request: dict[str, Any],
    backend: "LLMBackend",
    factors: list[str],
) -> list[str]:
    """Ask the LLM for concrete risk-reduction suggestions.

    Supplements the deterministic suggestions with LLM-generated ones.
    The LLM is constrained to short, actionable strings — never raw IAM
    actions or policy JSON.
    """
    description = (request.get("spec") or {}).get("description") or ""
    services, _ = backend.refine(
        description=(
            "You help a developer reduce the risk of their IAM policy request. "
            "Below is the policy + task description + the deterministic risk "
            "factors that already fired. "
            "Return a JSON object with one key `services` containing 1-3 short, "
            "actionable suggestions the requester could take to lower the risk. "
            "Each suggestion is a single sentence. Do NOT output IAM action strings "
            "or policy JSON; do NOT repeat the deterministic suggestions verbatim. "
            "IMPORTANT: this iam-jit instance can only see what's in the policy/description "
            "and any admin-provided org-context — it has NO access to the user's application "
            "code, repositories, kubeconfigs, the internet, or AWS account contents. "
            "Where the right scoping requires more context than is available, recommend the "
            "requester regenerate their policy locally with a tool like Claude Code that can "
            "read their actual code/manifests. "
            f"Deterministic factors: {factors!r}. "
            f"Policy: {policy!r}. "
            f"Description: {description!r}"
        ),
        initial_services=[],
        initial_actions=[],
    )
    if not services:
        return []
    return [s for s in services if isinstance(s, str) and s.strip()][:3]


def _as_list(value: object) -> list[str]:
    """Coerce an IAM string-or-list field to a list of normalized strings.

    AWS IAM accepts both `Action: "s3:GetObject"` and
    `Action: ["s3:GetObject", "s3:ListBucket"]`. This collapses both
    to the list form. Each entry is normalized via `_norm_grammar_str`
    so trailing whitespace, fullwidth Roman, BOMs etc. don't reach the
    set-membership lookups downstream.
    """
    if value is None:
        return []
    if isinstance(value, str):
        normalized = _norm_grammar_str(value)
        return [normalized] if normalized else []
    if isinstance(value, list):
        out: list[str] = []
        for v in value:
            normalized = _norm_grammar_str(str(v))
            if normalized:
                out.append(normalized)
        return out
    return []


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out
