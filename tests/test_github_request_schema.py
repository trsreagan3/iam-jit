"""Schema coverage for the GitHubTokenRequest kind.

The request schema now validates two kinds (RoleRequest | GitHubTokenRequest)
via a kind-conditional allOf. These tests pin BOTH that GitHub requests
validate AND that the AWS branch is unaffected + the two kinds can't
cross-contaminate (the highest-risk property of the kind split).
"""

from __future__ import annotations

from iam_jit.schema import scaffold_github_request, validate_request

_AWS_OK = {
    "apiVersion": "iam-jit.dev/v1alpha1",
    "kind": "RoleRequest",
    "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
    "spec": {
        "description": "read s3",
        "access_type": "read-only",
        "task_intent": {"services": ["s3"], "actions": ["read", "list"]},
        "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
        "duration": {"duration_hours": 24},
        "policy": None,
        "provisioning": {"mode": "identity_center"},
    },
}


def _gh(**github):
    base = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "GitHubTokenRequest",
        "metadata": {"requester": {"name": "Bot", "email": "bot@example.com"}},
        "spec": {"github": {"org": "acme", "repositories": ["web"], "access": "write"}},
    }
    base["spec"]["github"].update(github)
    return base


def test_aws_request_still_validates_unchanged() -> None:
    assert validate_request(_AWS_OK) == []


def test_github_request_validates() -> None:
    assert validate_request(_gh()) == []
    assert validate_request(_gh(access="read", duration_minutes=15)) == []


def test_github_requires_org_repos_access() -> None:
    assert validate_request(_gh(repositories=[])) != []  # minItems 1
    bad = _gh()
    del bad["spec"]["github"]["org"]
    assert validate_request(bad) != []


def test_github_access_is_read_or_write_only() -> None:
    assert validate_request(_gh(access="admin")) != []
    assert validate_request(_gh(access="read")) == []


def test_duration_minutes_capped_at_60() -> None:
    assert validate_request(_gh(duration_minutes=60)) == []
    assert validate_request(_gh(duration_minutes=61)) != []
    assert validate_request(_gh(duration_minutes=0)) != []


def test_kinds_cannot_cross_contaminate() -> None:
    # AWS spec under a GitHub kind -> rejected
    aws_on_gh = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "GitHubTokenRequest",
        "metadata": {"requester": {"name": "B", "email": "b@e.com"}},
        "spec": {"accounts": [{"account_id": "060392206767"}], "duration": {"duration_hours": 1}},
    }
    assert validate_request(aws_on_gh) != []
    # GitHub spec under an AWS kind -> rejected
    gh_on_aws = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "B", "email": "b@e.com"}},
        "spec": {"github": {"org": "acme", "repositories": ["web"], "access": "write"}},
    }
    assert validate_request(gh_on_aws) != []


def test_unknown_kind_rejected() -> None:
    req = _gh()
    req["kind"] = "SomethingElse"
    assert validate_request(req) != []


def test_scaffold_github_request_is_valid() -> None:
    req = scaffold_github_request(
        org="acme", repositories=["web", "api"], access="write",
        duration_minutes=30, description="ship a fix",
    )
    assert req["kind"] == "GitHubTokenRequest"
    assert validate_request(req) == []
