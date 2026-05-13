"""Narrowing pass: inspect a draft policy for overly-broad permissions and
generate targeted questions to scope them down.

The narrower runs after `suggest_policy` (or after a paste). When a flag fires,
the user answers with specific ARN patterns. Their answers become entries in
`spec.resource_constraints`, which `suggest_policy` then uses to produce a
tighter policy — replacing `Resource: "*"` with a concrete list per service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Services where wildcard resources warrant scrutiny by default.
_SENSITIVE_SERVICES = frozenset(
    {"secretsmanager", "kms", "ssm", "iam", "organizations", "sts", "rds-data"}
)

# Specific high-risk action+wildcard pairs that always warrant a question.
_HIGH_RISK_ACTIONS = frozenset(
    {
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "sts:AssumeRole",
    }
)

# Suggested ARN templates surfaced to the user as examples.
_ARN_TEMPLATES: dict[str, str] = {
    "secretsmanager": "arn:aws:secretsmanager:<region>:<account>:secret:<name-prefix>-*",
    "kms": "arn:aws:kms:<region>:<account>:key/<key-id> "
    "or arn:aws:kms:<region>:<account>:alias/<alias>",
    "s3": "arn:aws:s3:::<bucket> or arn:aws:s3:::<bucket>/<prefix>*",
    "ssm": "arn:aws:ssm:<region>:<account>:parameter/<path>",
    "iam": "arn:aws:iam::<account>:role/<role-name>",
    "sts": "arn:aws:iam::<account>:role/<role-name>",
    "rds-data": "arn:aws:rds:<region>:<account>:cluster:<cluster-name>",
    "dynamodb": "arn:aws:dynamodb:<region>:<account>:table/<table-name>",
    "lambda": "arn:aws:lambda:<region>:<account>:function:<function-name>",
    "ec2": "arn:aws:ec2:<region>:<account>:instance/<instance-id>",
}


@dataclass(frozen=True)
class NarrowingQuestion:
    """One question to ask the user to scope a broad permission."""

    id: str
    pattern: str
    service: str
    severity: str  # "high" | "medium" | "low"
    question: str
    suggested_arn_format: str | None
    triggering_actions: tuple[str, ...] = field(default_factory=tuple)


def detect_broadness(policy: dict[str, Any], request: dict[str, Any]) -> list[NarrowingQuestion]:
    """Return narrowing questions for any overly-broad statements in `policy`.

    Empty list = no broadness flags fired (policy looks reasonably scoped).
    """
    if not policy or not isinstance(policy.get("Statement"), list):
        return []
    questions: list[NarrowingQuestion] = []
    seen_ids: set[str] = set()

    for stmt_idx, stmt in enumerate(policy["Statement"]):
        if stmt.get("Effect") != "Allow":
            continue
        actions = _as_list(stmt.get("Action"))
        resources = _as_list(stmt.get("Resource"))
        wildcard_resource = "*" in resources
        wildcard_action_count = sum(1 for a in actions if "*" in a)

        # Rule 1: literal "*" action on any resource.
        if "*" in actions:
            q = NarrowingQuestion(
                id=f"stmt-{stmt_idx}-action-star",
                pattern="action-wildcard-literal",
                service="*",
                severity="high",
                question=(
                    "Action '*' would grant every AWS API call. "
                    "Which specific actions does this task actually need?"
                ),
                suggested_arn_format=None,
                triggering_actions=("*",),
            )
            questions.append(q)
            seen_ids.add(q.id)
            continue

        # Rule 2: service:* wildcards (e.g. s3:*).
        for action in actions:
            if action.endswith(":*") and action != "*":
                service = action.split(":", 1)[0]
                qid = f"stmt-{stmt_idx}-{service}-service-star"
                if qid in seen_ids:
                    continue
                severity = "high" if service in _SENSITIVE_SERVICES else "medium"
                q = NarrowingQuestion(
                    id=qid,
                    pattern="service-wildcard",
                    service=service,
                    severity=severity,
                    question=(
                        f"`{action}` grants every action in `{service}`. "
                        "Most tasks only need a subset (e.g. just Get*/List*). "
                        "Which sub-operations do you actually need?"
                    ),
                    suggested_arn_format=None,
                    triggering_actions=(action,),
                )
                questions.append(q)
                seen_ids.add(qid)

        # Rule 3: high-risk actions with Resource: "*".
        if wildcard_resource:
            for action in actions:
                if action in _HIGH_RISK_ACTIONS:
                    service = action.split(":", 1)[0]
                    qid = f"stmt-{stmt_idx}-{service}-wildcard-resource"
                    if qid in seen_ids:
                        continue
                    template = _ARN_TEMPLATES.get(service)
                    q = NarrowingQuestion(
                        id=qid,
                        pattern="high-risk-action-wildcard-resource",
                        service=service,
                        severity="high",
                        question=(
                            f"`{action}` on Resource: `*` is broad. "
                            f"Which specific {service} resource(s) do you need? "
                            "ARN patterns with prefixes are fine."
                        ),
                        suggested_arn_format=template,
                        triggering_actions=tuple(
                            a for a in actions if a in _HIGH_RISK_ACTIONS and a.startswith(service)
                        ),
                    )
                    questions.append(q)
                    seen_ids.add(qid)

        # Rule 4: any action in a sensitive service with Resource: "*".
        if wildcard_resource:
            for action in actions:
                if ":" not in action:
                    continue
                service = action.split(":", 1)[0]
                if service not in _SENSITIVE_SERVICES:
                    continue
                qid = f"stmt-{stmt_idx}-{service}-sensitive-wildcard"
                if qid in seen_ids:
                    continue
                template = _ARN_TEMPLATES.get(service)
                q = NarrowingQuestion(
                    id=qid,
                    pattern="sensitive-service-wildcard-resource",
                    service=service,
                    severity="medium",
                    question=(
                        f"This grants `{service}` actions on Resource: `*`. "
                        f"`{service}` typically holds secrets/credentials/identity data. "
                        "Can you scope to specific ARNs?"
                    ),
                    suggested_arn_format=template,
                    triggering_actions=tuple(
                        a for a in actions if a.startswith(f"{service}:")
                    ),
                )
                questions.append(q)
                seen_ids.add(qid)

        # Rule 5: iam:PassRole on Resource: "*" — privilege-escalation classic.
        if "iam:PassRole" in actions and wildcard_resource:
            qid = f"stmt-{stmt_idx}-passrole-star"
            if qid not in seen_ids:
                q = NarrowingQuestion(
                    id=qid,
                    pattern="passrole-wildcard",
                    service="iam",
                    severity="high",
                    question=(
                        "iam:PassRole on Resource: `*` allows handing any IAM role to any "
                        "compute service — a classic privilege-escalation path. "
                        "Which specific role(s) need to be passable?"
                    ),
                    suggested_arn_format=_ARN_TEMPLATES["iam"],
                    triggering_actions=("iam:PassRole",),
                )
                questions.append(q)
                seen_ids.add(qid)

        # Rule 6: many wildcard-bearing actions — accumulating risk.
        if wildcard_action_count >= 3:
            qid = f"stmt-{stmt_idx}-many-wildcards"
            if qid not in seen_ids:
                q = NarrowingQuestion(
                    id=qid,
                    pattern="multiple-wildcard-actions",
                    service="*",
                    severity="medium",
                    question=(
                        f"This statement has {wildcard_action_count} wildcard-bearing "
                        "actions. Listing exact actions usually narrows the blast "
                        "radius significantly."
                    ),
                    suggested_arn_format=None,
                    triggering_actions=tuple(a for a in actions if "*" in a),
                )
                questions.append(q)
                seen_ids.add(qid)

    return questions


def apply_constraints(
    request: dict[str, Any], answers: dict[str, list[str]]
) -> dict[str, Any]:
    """Update `request.spec.resource_constraints` from question answers.

    `answers` maps question.id -> list of ARN strings. Multiple questions for
    the same service merge their ARN patterns (de-duped).
    """
    if not answers:
        return request
    spec = request["spec"]
    existing: dict[str, list[str]] = {}
    for entry in spec.get("resource_constraints") or []:
        existing[entry["service"]] = list(entry.get("arn_patterns") or [])

    for question_id, arns in answers.items():
        # question_id format: stmt-<idx>-<service>-<rule>
        parts = question_id.split("-", 3)
        if len(parts) < 3:
            continue
        service = parts[2]
        if service == "*":
            continue
        bucket = existing.setdefault(service, [])
        for arn in arns:
            if arn and arn not in bucket:
                bucket.append(arn)

    spec["resource_constraints"] = [
        {"service": svc, "arn_patterns": arns}
        for svc, arns in sorted(existing.items())
        if arns
    ]
    return request


def _as_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []
