"""Tests for `iam-jit verify-role` (#694).

Covers:
  - role-name extraction from ARN
  - action-list enumeration from inline + attached policies (mocked iam client)
  - verify_role_simulate injects aws:CurrentTime
  - CLI: explicit --action path
  - CLI: enumerate-all path
  - CLI: malformed-ARN guard
"""

from __future__ import annotations

import json
from unittest import mock

import pytest
from click.testing import CliRunner

from iam_jit.cli_verify_role import (
    _extract_actions_from_policy_doc,
    _enumerate_role_actions,
    _role_name_from_arn,
    register_verify_role_command,
    verify_role_simulate,
)


# ---------------------------------------------------------------------------
# Unit: role-name extraction
# ---------------------------------------------------------------------------


def test_role_name_from_arn_simple() -> None:
    assert _role_name_from_arn(
        "arn:aws:iam::123456789012:role/iam-jit-grant-abc"
    ) == "iam-jit-grant-abc"


def test_role_name_from_arn_with_path() -> None:
    assert _role_name_from_arn(
        "arn:aws:iam::123456789012:role/service-role/path1/iam-jit-grant-xyz"
    ) == "iam-jit-grant-xyz"


@pytest.mark.parametrize("bad", [
    "not-an-arn",
    "arn:aws:s3:::bucket",
    "arn:aws:iam::123456789012:user/alice",
    "arn:aws:iam::123456789012:role/",
])
def test_role_name_from_arn_rejects_malformed(bad: str) -> None:
    with pytest.raises(Exception):
        _role_name_from_arn(bad)


# ---------------------------------------------------------------------------
# Unit: policy-doc action extraction
# ---------------------------------------------------------------------------


def test_extract_actions_from_policy_doc_basic() -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"]},
            {"Effect": "Allow", "Action": "iam:PassRole"},
            {"Effect": "Deny", "Action": "s3:DeleteObject"},  # ignored
        ],
    }
    assert _extract_actions_from_policy_doc(doc) == {
        "s3:GetObject", "s3:ListBucket", "iam:PassRole",
    }


def test_extract_actions_from_policy_doc_handles_single_statement() -> None:
    doc = {"Statement": {"Effect": "Allow", "Action": "ec2:DescribeInstances"}}
    assert _extract_actions_from_policy_doc(doc) == {"ec2:DescribeInstances"}


def test_extract_actions_from_policy_doc_empty() -> None:
    assert _extract_actions_from_policy_doc({}) == set()
    assert _extract_actions_from_policy_doc({"Statement": []}) == set()


# ---------------------------------------------------------------------------
# Unit: enumerate actions from a mocked iam client
# ---------------------------------------------------------------------------


def test_enumerate_role_actions_collects_inline_and_attached() -> None:
    iam = mock.MagicMock()
    iam.list_role_policies.return_value = {"PolicyNames": ["inline1"]}
    iam.get_role_policy.return_value = {
        "PolicyDocument": {
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"]},
            ],
        }
    }
    iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [
            {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
        ],
    }
    iam.get_policy.return_value = {
        "Policy": {"DefaultVersionId": "v1"},
    }
    iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [
                    {"Effect": "Allow", "Action": ["ec2:DescribeInstances"]},
                ],
            }
        }
    }
    out = _enumerate_role_actions(iam, "iam-jit-grant-x")
    assert out == ["ec2:DescribeInstances", "s3:GetObject"]


# ---------------------------------------------------------------------------
# verify_role_simulate injects aws:CurrentTime
# ---------------------------------------------------------------------------


def test_verify_role_simulate_passes_current_time_context() -> None:
    iam = mock.MagicMock()
    iam.simulate_principal_policy.return_value = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:GetObject",
                "EvalDecision": "allowed",
                "MatchedStatements": [],
            },
        ],
    }
    rows = verify_role_simulate(
        iam,
        "arn:aws:iam::123456789012:role/iam-jit-grant-a",
        ["s3:GetObject"],
        now_iso="2026-05-28T12:00:00Z",
    )
    # The simulate call MUST have been invoked with an aws:CurrentTime
    # context entry — that's the root cause of the dogfood implicitDeny.
    call_kwargs = iam.simulate_principal_policy.call_args.kwargs
    assert call_kwargs["PolicySourceArn"] == (
        "arn:aws:iam::123456789012:role/iam-jit-grant-a"
    )
    ctx = call_kwargs["ContextEntries"]
    assert len(ctx) == 1
    assert ctx[0]["ContextKeyName"] == "aws:CurrentTime"
    assert ctx[0]["ContextKeyValues"] == ["2026-05-28T12:00:00Z"]
    assert rows == [
        {
            "action": "s3:GetObject",
            "decision": "allowed",
            "matched_statements": [],
        }
    ]


def test_verify_role_simulate_defaults_now_to_real_utc() -> None:
    iam = mock.MagicMock()
    iam.simulate_principal_policy.return_value = {"EvaluationResults": []}
    verify_role_simulate(
        iam, "arn:aws:iam::123:role/x", ["s3:GetObject"],
    )
    ctx = iam.simulate_principal_policy.call_args.kwargs["ContextEntries"]
    assert ctx[0]["ContextKeyName"] == "aws:CurrentTime"
    # Format check: ISO 8601 with `Z` suffix
    assert ctx[0]["ContextKeyValues"][0].endswith("Z")


def test_verify_role_simulate_empty_actions_returns_empty() -> None:
    iam = mock.MagicMock()
    out = verify_role_simulate(iam, "arn:aws:iam::1:role/r", [])
    assert out == []
    iam.simulate_principal_policy.assert_not_called()


# ---------------------------------------------------------------------------
# CLI end-to-end (mocked boto3 session)
# ---------------------------------------------------------------------------


def _make_main_group():
    import click as _click
    g = _click.Group()
    register_verify_role_command(g)
    return g


def _patched_boto3_session(iam_mock):
    """Build a `mock.patch` context manager that replaces
    `boto3.Session().client('iam')` with the given mock."""
    sess = mock.MagicMock()
    sess.client.return_value = iam_mock
    return mock.patch("boto3.Session", return_value=sess)


def test_verify_role_cli_with_explicit_action() -> None:
    iam = mock.MagicMock()
    iam.simulate_principal_policy.return_value = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:GetObject",
                "EvalDecision": "allowed",
                "MatchedStatements": [],
            },
        ],
    }
    runner = CliRunner()
    g = _make_main_group()
    with _patched_boto3_session(iam):
        result = runner.invoke(
            g,
            [
                "verify-role",
                "arn:aws:iam::123456789012:role/iam-jit-grant-abc",
                "--action", "s3:GetObject",
                "--now", "2026-05-28T12:00:00Z",
            ],
        )
    assert result.exit_code == 0, result.output
    assert "s3:GetObject" in result.output
    assert "ALLOW" in result.output


def test_verify_role_cli_json_output() -> None:
    iam = mock.MagicMock()
    iam.simulate_principal_policy.return_value = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:DeleteObject",
                "EvalDecision": "implicitDeny",
                "MatchedStatements": [],
            },
        ],
    }
    runner = CliRunner()
    g = _make_main_group()
    with _patched_boto3_session(iam):
        result = runner.invoke(
            g,
            [
                "verify-role",
                "arn:aws:iam::123456789012:role/iam-jit-grant-abc",
                "--action", "s3:DeleteObject",
                "--json",
                "--now", "2026-05-28T12:00:00Z",
            ],
        )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["role_arn"] == (
        "arn:aws:iam::123456789012:role/iam-jit-grant-abc"
    )
    assert payload["now"] == "2026-05-28T12:00:00Z"
    assert payload["results"][0]["action"] == "s3:DeleteObject"
    assert payload["results"][0]["decision"] == "implicitDeny"


def test_verify_role_cli_enumerate_all_actions_when_none_passed() -> None:
    iam = mock.MagicMock()
    iam.list_role_policies.return_value = {"PolicyNames": ["inline1"]}
    iam.get_role_policy.return_value = {
        "PolicyDocument": {
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"]},
            ],
        }
    }
    iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    iam.simulate_principal_policy.return_value = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:GetObject",
                "EvalDecision": "allowed",
                "MatchedStatements": [],
            },
            {
                "EvalActionName": "s3:ListBucket",
                "EvalDecision": "allowed",
                "MatchedStatements": [],
            },
        ],
    }
    runner = CliRunner()
    g = _make_main_group()
    with _patched_boto3_session(iam):
        result = runner.invoke(
            g, ["verify-role", "arn:aws:iam::1:role/x"],
        )
    assert result.exit_code == 0, result.output
    # Both actions should be in the output
    assert "s3:GetObject" in result.output
    assert "s3:ListBucket" in result.output
    assert "2 ALLOW" in result.output


def test_verify_role_cli_rejects_bad_arn() -> None:
    runner = CliRunner()
    g = _make_main_group()
    result = runner.invoke(g, ["verify-role", "not-an-arn"])
    assert result.exit_code != 0
    assert "arn:aws:iam" in result.output
