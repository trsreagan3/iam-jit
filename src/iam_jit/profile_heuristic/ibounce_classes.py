# Phase 1 — ibounce (AWS) action prefix tables.
"""ibounce action classification.

The tables encode the design's per-class disposition for AWS actions
(`docs/PROFILE-GENERATION-DESIGN.md` §2.1). Each table is a tuple of
``(service_prefix, verb_prefix)`` pairs where ``service_prefix`` is
``"*"`` to match any service.

Lookup rules (applied in classify.py):

1. ``DESTRUCTIVE_DATA`` is checked FIRST — high-blast actions like
   ``s3:DeleteObject`` MUST classify destructive even if the bare verb
   ``Delete*`` is in the ADMIN class for IAM.
2. ``ADMIN`` is checked SECOND.
3. ``WRITE_DATA`` THIRD.
4. ``READ`` LAST.
5. Anything unmatched is ``UNKNOWN``.

The KNOWN_ADVERSARIAL_PATTERNS catalogue from
:mod:`iam_jit.deny_classifier.prompts` is overlaid on this in
classify.py as a defense-in-depth check — a match there forces
``ADMIN`` regardless of where the action falls in these tables.
"""

from __future__ import annotations


# Per design §2.1 destructive-data row. Tight even if observed 100×.
# Order matters less than completeness here; we evaluate all entries.
DESTRUCTIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    # S3 object + bucket destruction (the high-blast cases in design).
    ("s3", "DeleteObject"),
    ("s3", "DeleteObjects"),
    ("s3", "DeleteBucket"),
    ("s3", "DeleteBucketPolicy"),
    ("s3", "DeleteBucketLifecycle"),
    # DynamoDB row + table destruction.
    ("dynamodb", "DeleteItem"),
    ("dynamodb", "DeleteTable"),
    ("dynamodb", "BatchWriteItem"),  # can carry deletes
    # RDS / DocumentDB / Redshift instance destruction.
    ("rds", "DeleteDBInstance"),
    ("rds", "DeleteDBCluster"),
    ("rds", "DeleteDBSnapshot"),
    ("redshift", "DeleteCluster"),
    ("docdb", "DeleteDBCluster"),
    # EBS + EFS data destruction.
    ("ec2", "DeleteVolume"),
    ("ec2", "DeleteSnapshot"),
    ("efs", "DeleteFileSystem"),
    # KMS — schedule-key-deletion is in adversarial catalog (covers exfil);
    # we list the raw delete shape here for completeness.
    ("kms", "ScheduleKeyDeletion"),
    # Lambda function deletion is data-loss-shape.
    ("lambda", "DeleteFunction"),
    # Logs / observability data destruction.
    ("logs", "DeleteLogGroup"),
    ("logs", "DeleteLogStream"),
    ("cloudwatch", "DeleteAlarms"),
    # SQS / SNS data destruction.
    ("sqs", "DeleteQueue"),
    ("sqs", "PurgeQueue"),
    ("sns", "DeleteTopic"),
)


# Per design §2.1 admin / network / IAM row. Very tight + count >= 3
# required for auto-include.
ADMIN_PATTERNS: tuple[tuple[str, str], ...] = (
    # IAM — full surface is admin (create / delete / put / attach /
    # detach roles, users, policies). Any iam: write-shape is admin.
    ("iam", "Create"),
    ("iam", "Delete"),
    ("iam", "Put"),
    ("iam", "Attach"),
    ("iam", "Detach"),
    ("iam", "Update"),
    ("iam", "Add"),
    ("iam", "Remove"),
    ("iam", "PassRole"),
    ("iam", "AssumeRole"),  # STS / IAM boundary; classify as admin
    # STS session-shape admin.
    ("sts", "AssumeRole"),
    ("sts", "AssumeRoleWithSAML"),
    ("sts", "AssumeRoleWithWebIdentity"),
    ("sts", "GetFederationToken"),
    ("sts", "GetSessionToken"),
    # EC2 network admin — SG, VPC, route changes.
    ("ec2", "Authorize"),
    ("ec2", "Revoke"),
    ("ec2", "CreateSecurityGroup"),
    ("ec2", "DeleteSecurityGroup"),
    ("ec2", "ModifySecurityGroup"),
    ("ec2", "CreateNetworkAcl"),
    ("ec2", "DeleteNetworkAcl"),
    ("ec2", "CreateRoute"),
    ("ec2", "DeleteRoute"),
    ("ec2", "CreateInternetGateway"),
    ("ec2", "AttachInternetGateway"),
    # EC2 snapshot/AMI sharing (data-exfil shape).
    ("ec2", "ModifySnapshotAttribute"),
    ("ec2", "ModifyImageAttribute"),
    # RDS snapshot sharing.
    ("rds", "ModifyDBSnapshotAttribute"),
    ("rds", "ModifyDBClusterSnapshotAttribute"),
    # Route53 — domain-takeover surface.
    ("route53", "Change"),
    ("route53", "CreateHostedZone"),
    ("route53", "DeleteHostedZone"),
    # CloudTrail / Config / GuardDuty cover-tracks surface.
    ("cloudtrail", "StopLogging"),
    ("cloudtrail", "DeleteTrail"),
    ("cloudtrail", "PutEventSelectors"),
    ("config", "DeleteConfigurationRecorder"),
    ("config", "StopConfigurationRecorder"),
    ("guardduty", "DeleteDetector"),
    ("guardduty", "DisassociateFromMasterAccount"),
    # KMS key policy admin.
    ("kms", "PutKeyPolicy"),
    ("kms", "ScheduleKeyDeletion"),
    ("kms", "CancelKeyDeletion"),
    ("kms", "DisableKey"),
    # Organizations / Account admin.
    ("organizations", "Create"),
    ("organizations", "Delete"),
    ("organizations", "Leave"),
    ("organizations", "Remove"),
    ("organizations", "MoveAccount"),
    ("account", "Put"),
    # SSO / Identity Center admin.
    ("sso", "Create"),
    ("sso", "Delete"),
    ("sso-admin", "Create"),
    ("sso-admin", "Delete"),
    ("sso-admin", "Attach"),
    ("sso-admin", "Detach"),
    # S3 bucket-policy admin (public-bucket shape).
    ("s3", "PutBucketPolicy"),
    ("s3", "PutBucketAcl"),
    ("s3", "PutPublicAccessBlock"),
    ("s3", "DeletePublicAccessBlock"),
    ("s3", "PutObjectAcl"),
)


# Per design §2.1 write-data row. Tight scope: exact action + exact
# resource ARN.
WRITE_DATA_PATTERNS: tuple[tuple[str, str], ...] = (
    # Verb-prefix matches with service-wildcard. Match-order in classify.py
    # ensures admin/destructive precedence.
    ("*", "Put"),
    ("*", "Update"),
    ("*", "Modify"),
    ("*", "Tag"),
    ("*", "Untag"),
    ("*", "Set"),
    ("*", "Patch"),
    ("*", "Start"),
    ("*", "Stop"),
    ("*", "Restart"),
    ("*", "Reboot"),
    ("*", "Create"),
    # Explicit cross-resource writes not covered by verb-prefix.
    ("s3", "CopyObject"),
    ("s3", "RestoreObject"),
    ("s3", "UploadPart"),
    ("dynamodb", "BatchWriteItem"),
    # SNS / SQS publish.
    ("sns", "Publish"),
    ("sqs", "SendMessage"),
    ("sqs", "SendMessageBatch"),
    # Step Functions / Lambda invoke.
    ("states", "StartExecution"),
    ("lambda", "InvokeFunction"),
    ("lambda", "Invoke"),
)


# Per design §2.1 read row. Allow broadly when count >= 5 + 2+ resources.
READ_PATTERNS: tuple[tuple[str, str], ...] = (
    ("*", "Get"),
    ("*", "List"),
    ("*", "Describe"),
    ("*", "Head"),
    ("*", "Search"),
    ("*", "Query"),
    ("*", "Scan"),
    ("*", "Lookup"),
    ("*", "Batch"),  # BatchGet*, BatchRead* — admin/destructive checked first
    ("*", "View"),
    ("*", "Read"),
    ("*", "Test"),
    ("*", "Estimate"),
    ("*", "Check"),
    ("*", "Validate"),
    ("*", "Generate"),  # Generate* presigned URLs etc.
    # IAM / STS read.
    ("sts", "GetCallerIdentity"),
    # KMS read.
    ("kms", "Decrypt"),
    ("kms", "Encrypt"),
    ("kms", "GenerateDataKey"),
)


__all__ = [
    "READ_PATTERNS",
    "WRITE_DATA_PATTERNS",
    "ADMIN_PATTERNS",
    "DESTRUCTIVE_PATTERNS",
]
