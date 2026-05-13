from __future__ import annotations

from typing import Any

from iam_jit.narrow import apply_constraints, detect_broadness


def _request(**overrides: Any) -> dict[str, Any]:
    base = {
        "metadata": {"requester": {"name": "x", "email": "x@example.com"}},
        "spec": {
            "description": "test",
            "task_intent": {"services": ["s3"], "actions": ["read"]},
            "accounts": [{"account_id": "111111111111"}],
            "duration": {"duration_hours": 1},
        },
    }
    base["spec"].update(overrides)
    return base


def test_no_flags_for_specific_resources() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::example/path/*",
            }
        ],
    }
    assert detect_broadness(policy, _request()) == []


def test_flag_action_literal_star() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    questions = detect_broadness(policy, _request())
    assert any(q.pattern == "action-wildcard-literal" for q in questions)


def test_flag_service_wildcard() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::a"}
        ],
    }
    questions = detect_broadness(policy, _request())
    assert any(q.pattern == "service-wildcard" and q.service == "s3" for q in questions)


def test_flag_high_risk_action_with_wildcard_resource() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": "*",
            }
        ],
    }
    questions = detect_broadness(policy, _request())
    matched = [q for q in questions if q.pattern == "high-risk-action-wildcard-resource"]
    assert matched
    assert matched[0].service == "secretsmanager"
    assert matched[0].suggested_arn_format
    assert "secretsmanager" in matched[0].suggested_arn_format


def test_flag_passrole_wildcard() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}
        ],
    }
    questions = detect_broadness(policy, _request())
    assert any(q.pattern == "passrole-wildcard" for q in questions)


def test_no_flag_for_passrole_with_specific_resource() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": ["arn:aws:iam::111111111111:role/specific-role"],
            }
        ],
    }
    questions = detect_broadness(policy, _request())
    assert not any(q.pattern == "passrole-wildcard" for q in questions)


def test_apply_constraints_creates_new_entry() -> None:
    request = _request()
    answers = {
        "stmt-0-secretsmanager-wildcard-resource": [
            "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/api-*"
        ]
    }
    refined = apply_constraints(request, answers)
    constraints = refined["spec"]["resource_constraints"]
    assert len(constraints) == 1
    assert constraints[0]["service"] == "secretsmanager"
    assert constraints[0]["arn_patterns"] == [
        "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/api-*"
    ]


def test_apply_constraints_merges_with_existing() -> None:
    request = _request(
        resource_constraints=[
            {"service": "kms", "arn_patterns": ["arn:aws:kms:us-east-1:111111111111:key/abc"]}
        ]
    )
    answers = {
        "stmt-0-kms-sensitive-wildcard": [
            "arn:aws:kms:us-east-1:111111111111:key/def"
        ]
    }
    refined = apply_constraints(request, answers)
    [entry] = refined["spec"]["resource_constraints"]
    assert entry["service"] == "kms"
    assert "arn:aws:kms:us-east-1:111111111111:key/abc" in entry["arn_patterns"]
    assert "arn:aws:kms:us-east-1:111111111111:key/def" in entry["arn_patterns"]


def test_apply_constraints_dedupes() -> None:
    request = _request(
        resource_constraints=[
            {"service": "s3", "arn_patterns": ["arn:aws:s3:::a"]}
        ]
    )
    answers = {"stmt-0-s3-sensitive-wildcard": ["arn:aws:s3:::a"]}
    refined = apply_constraints(request, answers)
    [entry] = refined["spec"]["resource_constraints"]
    assert entry["arn_patterns"].count("arn:aws:s3:::a") == 1


def test_apply_constraints_with_empty_answers_is_noop() -> None:
    request = _request()
    refined = apply_constraints(request, {})
    assert "resource_constraints" not in refined["spec"]
