"""Resource extraction from task descriptions.

Two responsibilities:
  1. Pull explicit ARNs out of a free-text description.
  2. Recognize service-specific resource names ("the prod-logs bucket",
     "the deploy-api function") and construct the corresponding ARN
     given a context (account, region, partition).

When neither path produces a concrete resource, the generator falls
back to wildcards — the user's description didn't pin down a target
so the generated policy must match anything.

The patterns here are deliberately conservative. We'd rather miss a
name than misparse one. Misparsing produces a policy with the wrong
resource (e.g. granting access to a bucket the user didn't mention);
missing a name produces a policy with `Resource: "*"` which the
deterministic scorer will flag as broad and surface for review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .result import GenerationContext


# Match a fully-formed AWS ARN. Account ID is optional (can be empty
# for some services like S3). Resource segment can contain anything
# except whitespace. Conservative: requires `arn:` prefix.
_ARN_RE = re.compile(
    r"arn:[a-z][a-z0-9-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9*]*:[\w\-/.*?:${}/]+",
    re.IGNORECASE,
)

# Resource-name extraction patterns. Each tuple:
#   (compiled_regex, name_group_index, service_kind)
# `service_kind` is a string we use later to construct the ARN.
_NAME_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    # ---- S3 buckets ----
    # Forward: "S3 bucket X" / "bucket X" / "in bucket X"
    (re.compile(r"\b(?:s3\s+bucket|in\s+bucket|bucket)\s+([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\b", re.IGNORECASE), 1, "s3-bucket"),
    # Reverse: "the X bucket" / "X bucket"
    (re.compile(r"\bthe\s+([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\s+bucket\b", re.IGNORECASE), 1, "s3-bucket"),
    # ---- Lambda functions ----
    # Forward: "lambda function X" / "the function X" / "function X"
    (re.compile(r"\b(?:lambda\s+function|the\s+function|function)\s+([a-zA-Z][\w-]{0,63})\b"), 1, "lambda-function"),
    # Reverse: "the X function" / "the X lambda function"
    (re.compile(r"\bthe\s+([a-zA-Z][\w-]{1,63})\s+(?:lambda\s+)?function\b"), 1, "lambda-function"),
    # ---- DynamoDB tables ----
    (re.compile(r"\b(?:dynamodb\s+table|the\s+table|ddb\s+table|table)\s+([a-zA-Z][\w.\-]{2,254})\b", re.IGNORECASE), 1, "dynamodb-table"),
    # Reverse: "the X table" / "the X dynamodb table" (case-insensitive
    # for the literal "DynamoDB"/"dynamodb" since AWS people mix cases)
    (re.compile(r"\bthe\s+([a-zA-Z][\w.\-]{2,254})\s+(?:dynamodb\s+)?table\b", re.IGNORECASE), 1, "dynamodb-table"),
    # ---- CloudWatch log groups ----
    (re.compile(r"\blog\s+group\s+(/[\w./\-]+)\b"), 1, "logs-group"),
    # ---- SSM parameters ----
    (re.compile(r"\b(?:ssm\s+)?parameter\s+(/[\w./\-]+)\b"), 1, "ssm-parameter"),
    # ---- Secrets Manager ----
    (re.compile(r"\bsecret\s+([a-zA-Z][\w/\-]{0,511})\b"), 1, "secretsmanager-secret"),
    # ---- IAM roles ----
    (re.compile(r"\b(?:iam\s+)?role\s+([a-zA-Z][\w+=,.@\-]{0,63})\b"), 1, "iam-role"),
    # Reverse: "with the X role" / "the X role"
    (re.compile(r"\bthe\s+([a-zA-Z][\w+=,.@\-]{2,63})\s+role\b"), 1, "iam-role"),
    # ---- SQS queues ----
    # Require a NAME-like token; reject the service acronym SQS itself.
    # "queue SQS queue" would otherwise capture "SQS" as the queue name.
    (re.compile(r"\b(?:sqs\s+queue|to\s+queue|from\s+queue|the\s+queue|queue)\s+(?!sqs\b)([a-zA-Z][\w\-]{1,79})\b", re.IGNORECASE), 1, "sqs-queue"),
    # Reverse: "the X queue"
    (re.compile(r"\bthe\s+(?!sqs\b)([a-zA-Z][\w\-]{2,79})\s+queue\b", re.IGNORECASE), 1, "sqs-queue"),
    # ---- SNS topics ----
    (re.compile(r"\b(?:sns\s+)?topic\s+([a-zA-Z][\w\-]{0,255})\b"), 1, "sns-topic"),
    # ---- ECS services ----
    # Forward: "ecs service X" / "ecs task X"
    (re.compile(r"\becs\s+(?:service|task)\s+([a-zA-Z][\w\-]{0,254})\b"), 1, "ecs-service"),
    # Reverse: "the X service" / "the X ECS service"
    (re.compile(r"\bthe\s+([a-zA-Z][\w\-]{2,254})\s+(?:ecs\s+)?service\b", re.IGNORECASE), 1, "ecs-service"),
    # ---- RDS clusters ----
    (re.compile(r"\b(?:aurora\s+)?(?:rds\s+)?cluster\s+([a-z][a-z0-9\-]{0,62})\b"), 1, "rds-cluster"),
    # Reverse: "the X cluster"
    (re.compile(r"\bthe\s+([a-z][a-z0-9\-]{2,62})\s+(?:aurora\s+|rds\s+)?cluster\b"), 1, "rds-cluster"),
    # ---- KMS keys / aliases ----
    # Forward: "kms key X" / "kms alias X". Reject "kms" as the value
    # itself (otherwise "the kms key alias/foo" produces a bogus
    # extraction `key/kms`).
    (re.compile(r"\bkms\s+(?:key|alias)\s+(?!kms\s)([\w/\-]+)\b", re.IGNORECASE), 1, "kms-key"),
    # Reverse: "the X kms key" / "X kms key" (reject `kms` again).
    (re.compile(r"\bthe\s+(?!kms\s)([a-zA-Z][\w\-]{1,127})\s+kms\s+(?:key|alias)\b", re.IGNORECASE), 1, "kms-key"),
    (re.compile(r"\b(?!kms\s)([a-zA-Z][\w\-]{1,127})\s+kms\s+(?:key|alias)\b", re.IGNORECASE), 1, "kms-key"),
    # "decrypt with X key" form — only fires after "with"/"using" so
    # generic "key" in other contexts doesn't trigger.
    (re.compile(r"\b(?:with|using)\s+(?!kms\s)([\w\-]+)\s+key\b", re.IGNORECASE), 1, "kms-key"),
    # ---- Step Functions state machines ----
    (re.compile(r"\b(?:state\s+machine|workflow|step\s+function)\s+([a-zA-Z][\w\-]{1,79})\b", re.IGNORECASE), 1, "states-state-machine"),
    (re.compile(r"\bthe\s+([a-zA-Z][\w\-]{2,79})\s+state\s+machine\b", re.IGNORECASE), 1, "states-state-machine"),
]

# Reserved English words that should NOT be parsed as resource names
# even if they pattern-match. Two classes:
#   - Determiners/quantifiers: "the bucket" → "bucket" is just an
#     article, not a name.
#   - Prepositions: "function for incident response" → "for" is not
#     the function name. Catches the common case of the regex
#     greedily grabbing the next word after the resource type.
_NAME_STOPWORDS = {
    # Determiners / quantifiers / possessives
    "the", "a", "an", "this", "that", "these", "those", "all", "any",
    "every", "some", "my", "our", "their", "its", "your", "his", "her",
    # Prepositions
    "for", "to", "from", "with", "in", "on", "of", "by", "at", "as",
    "into", "onto", "via", "per", "during", "after", "before",
    # Conjunctions
    "and", "or", "but", "if", "when", "then",
    # Common verbs that pattern-match the regex
    "is", "are", "was", "were", "be", "been", "being",
}


@dataclass
class ExtractedResource:
    """A resource identified in the description.

    `arn` is the constructed ARN. `original_phrase` is what the
    description said (for audit / debugging). `service_kind` says
    which service this is — patterns use it to decide whether a
    given resource is consumable by their action set.
    """
    arn: str
    original_phrase: str
    service_kind: str
    is_wildcard: bool = False


def extract_resources(description: str, context: GenerationContext) -> list[ExtractedResource]:
    """Pull resources out of the description.

    Order of precedence:
      1. Explicit ARNs in the description (highest fidelity).
      2. Caller-supplied `context.resources` (next highest).
      3. Resource-name patterns (S3 bucket X, function Y).
    The returned list deduplicates by ARN.
    """
    seen_arns: set[str] = set()
    out: list[ExtractedResource] = []

    # 1. Explicit ARNs
    for m in _ARN_RE.finditer(description):
        arn = m.group(0)
        if arn in seen_arns:
            continue
        seen_arns.add(arn)
        out.append(ExtractedResource(
            arn=arn,
            original_phrase=arn,
            service_kind=_kind_from_arn(arn),
        ))

    # 2. Caller-supplied ARNs from context
    for arn in context.resources:
        if arn in seen_arns:
            continue
        seen_arns.add(arn)
        out.append(ExtractedResource(
            arn=arn,
            original_phrase=f"<context.resources: {arn}>",
            service_kind=_kind_from_arn(arn),
        ))

    # 3. Name-pattern matches → construct ARN from name + context
    partition = context.partition or "aws"
    region = context.region or "*"
    account = context.account_id or "*"
    for regex, group_idx, kind in _NAME_PATTERNS:
        for m in regex.finditer(description):
            name = m.group(group_idx)
            if not name or name.lower() in _NAME_STOPWORDS:
                continue
            arn = _construct_arn(kind, name, partition, region, account)
            if arn in seen_arns:
                continue
            seen_arns.add(arn)
            out.append(ExtractedResource(
                arn=arn,
                original_phrase=m.group(0),
                service_kind=kind,
            ))

    return out


def _kind_from_arn(arn: str) -> str:
    """Best-effort service-kind inference from ARN service segment."""
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return "unknown"
    service = parts[2]
    spec = parts[5] if len(parts) > 5 else ""
    if service == "s3":
        return "s3-bucket"
    if service == "lambda":
        return "lambda-function"
    if service == "dynamodb":
        return "dynamodb-table"
    if service == "logs":
        return "logs-group"
    if service == "ssm":
        return "ssm-parameter"
    if service == "secretsmanager":
        return "secretsmanager-secret"
    if service == "iam":
        if spec.startswith("role/"):
            return "iam-role"
        if spec.startswith("user/"):
            return "iam-user"
    if service == "sqs":
        return "sqs-queue"
    if service == "sns":
        return "sns-topic"
    if service == "ecs":
        return "ecs-service"
    if service == "rds":
        return "rds-cluster"
    if service == "kms":
        return "kms-key"
    return f"{service}-resource"


def _construct_arn(
    kind: str,
    name: str,
    partition: str,
    region: str,
    account: str,
) -> str:
    """Build a fully-qualified ARN from a resource kind + extracted name."""
    if kind == "s3-bucket":
        # S3 ARNs have no region or account in the bucket form.
        return f"arn:{partition}:s3:::{name}"
    if kind == "lambda-function":
        return f"arn:{partition}:lambda:{region}:{account}:function:{name}"
    if kind == "dynamodb-table":
        return f"arn:{partition}:dynamodb:{region}:{account}:table/{name}"
    if kind == "logs-group":
        # Drop leading slash for the logs ARN suffix
        suffix = name.lstrip("/")
        return f"arn:{partition}:logs:{region}:{account}:log-group:{name}"
    if kind == "ssm-parameter":
        # SSM parameter ARNs need leading slash in the path part
        param_path = name if name.startswith("/") else f"/{name}"
        return f"arn:{partition}:ssm:{region}:{account}:parameter{param_path}"
    if kind == "secretsmanager-secret":
        return f"arn:{partition}:secretsmanager:{region}:{account}:secret:{name}"
    if kind == "iam-role":
        return f"arn:{partition}:iam::{account}:role/{name}"
    if kind == "iam-user":
        return f"arn:{partition}:iam::{account}:user/{name}"
    if kind == "sqs-queue":
        return f"arn:{partition}:sqs:{region}:{account}:{name}"
    if kind == "sns-topic":
        return f"arn:{partition}:sns:{region}:{account}:{name}"
    if kind == "ecs-service":
        return f"arn:{partition}:ecs:{region}:{account}:service/{name}"
    if kind == "rds-cluster":
        return f"arn:{partition}:rds:{region}:{account}:cluster:{name}"
    if kind == "kms-key":
        # KMS keys can be UUID-style or alias/*; the regex captures both forms.
        if name.startswith("alias/"):
            return f"arn:{partition}:kms:{region}:{account}:{name}"
        return f"arn:{partition}:kms:{region}:{account}:key/{name}"
    if kind == "states-state-machine":
        return f"arn:{partition}:states:{region}:{account}:stateMachine:{name}"
    # Fallback: just embed the name; let the scorer flag.
    return f"arn:{partition}:{kind}:{region}:{account}:{name}"
