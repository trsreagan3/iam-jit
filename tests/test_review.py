from __future__ import annotations

from typing import Any

from iam_jit.review import analyze_policy


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


def test_full_admin_scores_10() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    a = analyze_policy(policy, _request())
    assert a.risk_score == 10
    assert a.deterministic_score == 10
    assert any("every AWS API call" in f.lower() or "*" in f for f in a.risk_factors)


def test_iam_wildcard_scores_high() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
        ],
    }
    a = analyze_policy(policy, _request())
    assert a.risk_score >= 9


def test_passrole_wildcard_scores_9() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole", "lambda:InvokeFunction"],
                "Resource": "*",
            }
        ],
    }
    a = analyze_policy(policy, _request())
    assert a.risk_score == 9
    assert any("PassRole" in f for f in a.risk_factors)


def test_secretsmanager_get_on_wildcard_scores_7() -> None:
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
    a = analyze_policy(policy, _request())
    assert a.risk_score == 7
    assert any("secret" in f.lower() for f in a.risk_factors)


def test_service_wildcard_normal_service_on_wildcard_resource_scores_high() -> None:
    """`ec2:*` on `Resource: *` is near-admin within the service — every
    API on every resource. Recalibrated 2026-05-13 from 7 to 8 so it sits
    well above the auto-approve threshold (5) and clearly in the
    human-review tier alongside other near-admin patterns."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}],
    }
    a = analyze_policy(policy, _request())
    assert a.risk_score == 8


def test_service_wildcard_sensitive_service_scores_higher_than_normal() -> None:
    sensitive = analyze_policy(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "secretsmanager:*", "Resource": "*"}],
        },
        _request(),
    )
    normal = analyze_policy(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}],
        },
        _request(),
    )
    # secretsmanager is in _SENSITIVE_SERVICES → floors at 8; ec2 also
    # floors at 8 when resource is wildcarded, so sensitive should be
    # ≥ normal (tie is allowed; sensitive must not be lower).
    assert sensitive.risk_score >= normal.risk_score


def test_specific_resource_read_scores_low() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::example-config/file.txt",
            }
        ],
    }
    a = analyze_policy(policy, _request())
    assert a.risk_score <= 2


def test_resource_constraints_acknowledged() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::example-config", "arn:aws:s3:::example-config/*"],
            }
        ],
    }
    request = _request(
        resource_constraints=[
            {"service": "s3", "arn_patterns": ["arn:aws:s3:::example-config*"]}
        ]
    )
    a = analyze_policy(policy, request)
    assert a.risk_score <= 3
    assert any("scoped" in f.lower() or "no broad" in f.lower() for f in a.risk_factors)


def test_explicit_deny_does_not_raise_score() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::a/b",
            },
        ],
    }
    a = analyze_policy(policy, _request())
    assert a.risk_score <= 2  # the Deny should not be scored as risk


def test_analyzer_label_is_deterministic_without_backend() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::a/b"}],
    }
    a = analyze_policy(policy, _request())
    assert a.analyzer == "deterministic"
    assert a.llm_narrative is None


def test_duration_within_24h_no_adjustment() -> None:
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
    request = _request(duration={"duration_hours": 12})
    base = analyze_policy(policy, request).risk_score
    request24 = _request(duration={"duration_hours": 24})
    assert analyze_policy(policy, request24).risk_score == base


def test_long_duration_bumps_medium_risk() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*",
            }
        ],
    }
    short = analyze_policy(policy, _request(duration={"duration_hours": 24}))
    long_ = analyze_policy(policy, _request(duration={"duration_hours": 24 * 14}))
    # Same base policy + 2 weeks duration → score should go up.
    assert long_.risk_score > short.risk_score
    assert any("Duration" in f for f in long_.risk_factors)


def test_very_long_duration_bumps_high_risk_more() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:*"],
                "Resource": "*",
            }
        ],
    }
    medium = analyze_policy(policy, _request(duration={"duration_hours": 24 * 7}))
    very_long = analyze_policy(policy, _request(duration={"duration_hours": 24 * 60}))
    assert very_long.risk_score >= medium.risk_score
    assert any("Duration" in f for f in very_long.risk_factors)


def test_low_risk_policy_long_duration_stays_low() -> None:
    # A genuinely low-risk policy stays low even with a long duration —
    # there's nothing risky to amplify.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::specific/path/file.txt",
            }
        ],
    }
    a = analyze_policy(policy, _request(duration={"duration_hours": 24 * 90}))
    assert a.risk_score <= 3


def test_to_dict_round_trip() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    a = analyze_policy(policy, _request())
    d = a.to_dict()
    assert d["risk_score"] == 10
    assert "risk_factors" in d
    assert "analyzed_at" in d
