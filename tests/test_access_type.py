"""Tests for the coarse-grained access_type toggle (read-only / read-write)."""

from __future__ import annotations

from typing import Any

from iam_jit.review import analyze_policy
from iam_jit.schema import load_request, scaffold_request, validate_request
from iam_jit.suggest import suggest_policy


def _request(**overrides: Any) -> dict[str, Any]:
    base = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "x", "email": "x@example.com"}},
        "spec": {
            "description": "test description that is long enough",
            "task_intent": {"services": ["s3"], "actions": ["read", "list", "write"]},
            "accounts": [{"account_id": "111111111111"}],
            "duration": {"duration_hours": 1},
        },
    }
    base["spec"].update(overrides)
    return base


def test_scaffold_default_is_read_only(tmp_path) -> None:
    yaml_text = scaffold_request(
        description="long enough description",
        accounts=["111111111111"],
        duration_hours=1,
    )
    p = tmp_path / "scaffold.yaml"
    p.write_text(yaml_text)
    request = load_request(p)
    assert request["spec"]["access_type"] == "read-only"


def test_scaffold_write_access_when_requested(tmp_path) -> None:
    yaml_text = scaffold_request(
        description="long enough description",
        accounts=["111111111111"],
        duration_hours=1,
        access_type="read-write",
    )
    p = tmp_path / "scaffold.yaml"
    p.write_text(yaml_text)
    request = load_request(p)
    assert request["spec"]["access_type"] == "read-write"


def test_schema_accepts_read_only(tmp_path) -> None:
    request = _request(access_type="read-only")
    assert validate_request(request) == []


def test_schema_accepts_read_write(tmp_path) -> None:
    request = _request(access_type="read-write")
    assert validate_request(request) == []


def test_schema_rejects_unknown_access_type() -> None:
    request = _request(access_type="admin")
    errors = validate_request(request)
    assert any("access_type" in e for e in errors)


def test_suggest_strips_write_when_read_only() -> None:
    request = _request(
        access_type="read-only",
        task_intent={"services": ["s3"], "actions": ["read", "list", "write", "tagging"]},
    )
    policy = suggest_policy(request, use_llm=False)
    actions_in_policy = []
    for stmt in policy["Statement"]:
        actions = stmt["Action"]
        if isinstance(actions, str):
            actions = [actions]
        actions_in_policy.extend(actions)
    # No write/put/delete/create actions for s3 should be present.
    write_verbs = ("Put", "Delete", "Create", "Write", "Update", "Copy", "Restore")
    assert not any(
        any(verb in a for verb in write_verbs) for a in actions_in_policy
    ), [a for a in actions_in_policy if any(v in a for v in write_verbs)]


def test_suggest_keeps_write_when_read_write() -> None:
    request = _request(
        access_type="read-write",
        task_intent={"services": ["s3"], "actions": ["read", "write"]},
    )
    policy = suggest_policy(request, use_llm=False)
    actions_in_policy = []
    for stmt in policy["Statement"]:
        actions = stmt["Action"]
        if isinstance(actions, str):
            actions = [actions]
        actions_in_policy.extend(actions)
    # Some write actions (e.g. s3:PutObject) should appear.
    assert any(a.startswith("s3:Put") for a in actions_in_policy)


def test_review_flags_mismatched_read_only_with_wildcard_write() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*"],
                "Resource": "arn:aws:s3:::example",
            }
        ],
    }
    request = _request(access_type="read-only")
    analysis = analyze_policy(policy, request)
    assert analysis.risk_score >= 7
    assert any(
        "read-only but policy includes wildcard" in f.lower()
        or "marked read-only" in f.lower()
        for f in analysis.risk_factors
    )


def test_review_surfaces_read_only_as_positive_factor() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::example",
            }
        ],
    }
    request = _request(access_type="read-only")
    analysis = analyze_policy(policy, request)
    assert any(
        "read-only" in f.lower() or "cannot mutate" in f.lower()
        for f in analysis.risk_factors
    )


def test_review_flags_deceptive_write_in_read_only() -> None:
    """rds-data:ExecuteStatement is IAM Write but commonly used for SELECT.
    A read-only request containing it should get a softer warning that the
    user can either remove the action or flip to read-write."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["rds-data:ExecuteStatement"],
                "Resource": "arn:aws:rds:us-east-1:111111111111:cluster:my-db",
            }
        ],
    }
    request = _request(access_type="read-only")
    analysis = analyze_policy(policy, request)
    # Score is bumped to 6 (deceptive-write) but not 8 (definite write).
    assert analysis.risk_score >= 6
    assert any("rds-data:ExecuteStatement" in f for f in analysis.risk_factors)
    assert any(
        "DELETE/UPDATE" in f or "read-style queries" in f for f in analysis.risk_factors
    )
    assert any("flip access_type to read-write" in s for s in analysis.suggestions)


def test_review_flags_definite_write_in_read_only() -> None:
    """s3:DeleteObject is unambiguously a write — read-only requests containing
    it should get the strong warning to remove it or flip access_type."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:DeleteObject"],
                "Resource": "arn:aws:s3:::example/*",
            }
        ],
    }
    request = _request(access_type="read-only")
    analysis = analyze_policy(policy, request)
    assert analysis.risk_score >= 8
    assert any("s3:DeleteObject" in f for f in analysis.risk_factors)
    assert any("Write" in f for f in analysis.risk_factors)


def test_review_does_not_flag_genuine_reads_in_read_only() -> None:
    """A real read-only policy with specific IAM Read/List actions is not flagged."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "eks:DescribeCluster"],
                "Resource": "arn:aws:s3:::example",
            }
        ],
    }
    request = _request(access_type="read-only")
    analysis = analyze_policy(policy, request)
    # No mismatch factors should appear.
    assert not any("read-only but" in f.lower() for f in analysis.risk_factors)
    assert not any("DELETE/UPDATE" in f for f in analysis.risk_factors)


def test_review_does_not_flag_deceptive_action_when_read_write() -> None:
    """If the user opted into read-write, the deceptive-write flag doesn't fire."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["rds-data:ExecuteStatement"],
                "Resource": "arn:aws:rds:us-east-1:111111111111:cluster:my-db",
            }
        ],
    }
    request = _request(access_type="read-write")
    analysis = analyze_policy(policy, request)
    assert not any("DELETE/UPDATE" in f for f in analysis.risk_factors)


def test_review_no_read_only_factor_when_read_write() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::example",
            }
        ],
    }
    request = _request(access_type="read-write")
    analysis = analyze_policy(policy, request)
    assert not any("read-only" in f.lower() for f in analysis.risk_factors)
