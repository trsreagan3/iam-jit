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
    "READ_SIBLING_VERBS",
    "WRITE_SIBLING_VERBS",
    "CREATE_SIBLING_VERBS",
    "sibling_action_prefixes",
]


# ---------------------------------------------------------------------------
# Phase 3 prerequisite — sibling verb adjacency.
# ---------------------------------------------------------------------------
#
# Per ``docs/PROFILE-GENERATION-DESIGN.md`` §2.2 row 4 (adjacency): if
# the operator observed a Get*-shape read on a resource, the
# lean-permissive heuristic should silently include sibling read
# verbs (List* / Describe* / Head*) for the same resource because
# they're low-blast-radius reads with no incremental risk.
#
# These sibling sets are an INITIAL PASS. Per
# ``[[calibration-quality-bar]]`` + design §9 guess #4 (per-bouncer
# class prefix tables): coverage gaps are expected; Phase 10 corpus
# expands.
#
# Sibling verb sets. Match the table-driven verbs in
# READ_PATTERNS / WRITE_DATA_PATTERNS / ADMIN_PATTERNS above.

READ_SIBLING_VERBS: frozenset[str] = frozenset({
    "Get",
    "List",
    "Describe",
    "Head",
    "Lookup",
    "Search",
    "Filter",
    "Count",
    "Has",
    "Is",
    "Read",
    "Query",
    "Scan",
    "View",
    "Check",
})


WRITE_SIBLING_VERBS: frozenset[str] = frozenset({
    "Put",
    "Update",
    "Modify",
    "Replace",
    "Set",
    "Patch",
})


# Create siblings — paired with Put/Update because operators commonly
# observe one (Put) and need the others (Create / Update) for the same
# resource flow. The Phase 3 caller decides whether to honour the
# adjacency per the action's ActionClass — Create* on iam:* /
# organizations:* still classifies ADMIN, so the sibling expansion
# composes safely with the lean-permissive disposition table.
CREATE_SIBLING_VERBS: frozenset[str] = frozenset({
    "Create",
    "Register",
})


# Bands of verbs that should be considered siblings of each other. Each
# band is a sibling set; a verb's siblings are the union of all bands it
# appears in (minus itself). Put / Update / Create commonly co-occur on
# the same resource — observing one signals the operator's flow needs
# all three. Per the spec example: ``iam:PutRolePolicy`` siblings
# include ``iam:UpdateRolePolicy`` AND ``iam:CreateRolePolicy``.
_SIBLING_BANDS: tuple[frozenset[str], ...] = (
    READ_SIBLING_VERBS,
    WRITE_SIBLING_VERBS,
    CREATE_SIBLING_VERBS,
    # Cross-band: Put/Update/Create flow on the same resource.
    WRITE_SIBLING_VERBS | CREATE_SIBLING_VERBS,
)


def _build_verb_to_siblings() -> dict[str, frozenset[str]]:
    mapping: dict[str, set[str]] = {}
    for verb_set in _SIBLING_BANDS:
        for verb in verb_set:
            mapping.setdefault(verb, set()).update(v for v in verb_set if v != verb)
    return {verb: frozenset(siblings) for verb, siblings in mapping.items()}


_VERB_TO_SIBLINGS: dict[str, frozenset[str]] = _build_verb_to_siblings()


def _extract_verb_prefix(name: str) -> str:
    """Extract the leading TitleCase verb from an AWS action name.

    ``GetObject`` -> ``Get``; ``ListBucketVersions`` -> ``List``;
    ``DescribeInstances`` -> ``Describe``. Stops at the first uppercase
    letter that isn't the first character — i.e. the second
    capital boundary. ``Get`` (bare) -> ``Get``.

    Returns the empty string for non-TitleCase input.
    """
    if not name or not name[0].isupper():
        return ""
    # Walk forward until we hit the second uppercase boundary.
    for i in range(1, len(name)):
        if name[i].isupper():
            return name[:i]
    return name


def sibling_action_prefixes(action: str) -> set[str]:
    """Return well-known sibling action patterns for an AWS API action.

    Per ``docs/PROFILE-GENERATION-DESIGN.md`` §2.2 adjacency: if the
    operator observed ``s3:GetObject``, lean-permissive should consider
    including ``s3:ListObject*`` / ``s3:DescribeObject*`` /
    ``s3:HeadObject`` as low-blast-radius sibling reads.

    Pure function — same inputs always produce the same output. No I/O.

    Args:
        action: an AWS-shape action (``service:Action``). Non-AWS
            shapes (kbouncer / dbounce / gbounce) return the empty set
            because their action grammar isn't verb-prefix based.

    Returns:
        A set of ``service:VerbPrefix*`` patterns (the trailing ``*`` is
        intentional — the Phase 3 caller can either match exactly the
        observed object suffix or widen, per its disposition).

        Returns the empty set when the verb isn't in any known sibling
        band, or when the action isn't AWS-shape.
    """
    if not isinstance(action, str) or ":" not in action:
        return set()
    service, _, name = action.partition(":")
    if not service or not name:
        return set()

    verb = _extract_verb_prefix(name)
    if not verb:
        return set()

    siblings = _VERB_TO_SIBLINGS.get(verb)
    if not siblings:
        return set()

    # Strip the original verb from the name to get the "object" suffix
    # (e.g. GetObject -> Object). Phase 3 callers want patterns like
    # s3:ListObject* / s3:DescribeObject* that retain the noun.
    object_suffix = name[len(verb):]

    out: set[str] = set()
    for sibling_verb in siblings:
        if object_suffix:
            # Emit ``s3:ListObject*`` rather than ``s3:List*`` so the
            # Phase 3 caller stays narrow (sibling adjacency, NOT
            # service-wide verb widening). The trailing ``*`` covers
            # the natural variation (ListObjects vs ListObjectV2 etc.).
            out.add(f"{service}:{sibling_verb}{object_suffix}*")
        else:
            # Bare verb (e.g. action was ``s3:Get``) — emit
            # ``s3:List*`` etc.
            out.add(f"{service}:{sibling_verb}*")
    return out
