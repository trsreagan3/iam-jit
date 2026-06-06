"""lifecycle.summarize / to_template must project the GitHubTokenRequest kind
so the shared queue/detail/all-requests templates can branch on it."""

from __future__ import annotations

from iam_jit import lifecycle

_GH = {
    "apiVersion": "iam-jit.dev/v1alpha1",
    "kind": "GitHubTokenRequest",
    "metadata": {"id": "ghr-1", "requester": {"name": "Bot", "email": "b@e.com"}},
    "spec": {
        "description": "open a PR",
        "github": {"org": "acme", "repositories": ["web", "api"],
                   "permissions": {"contents": "write", "pull_requests": "write"},
                   "duration_minutes": 30},
    },
    "status": {"state": "pending", "owner": "b@e.com"},
}

_AWS = {
    "apiVersion": "iam-jit.dev/v1alpha1",
    "kind": "RoleRequest",
    "metadata": {"id": "rq-1", "requester": {"name": "Dev", "email": "d@e.com"}},
    "spec": {
        "description": "read s3",
        "accounts": [{"account_id": "060392206767"}],
        "duration": {"duration_hours": 4},
    },
    "status": {"state": "pending", "owner": "d@e.com"},
}


def test_summarize_projects_github_fields() -> None:
    s = lifecycle.summarize(_GH)
    assert s["kind"] == "GitHubTokenRequest"
    assert s["github_org"] == "acme"
    assert s["github_repos"] == ["web", "api"]
    assert s["github_repo_count"] == 2
    assert s["github_permissions"] == {"contents": "write", "pull_requests": "write"}
    assert "contents:write" in s["github_perm_summary"]
    assert s["github_duration_minutes"] == 30


def test_summarize_aws_unaffected_and_kind_present() -> None:
    s = lifecycle.summarize(_AWS)
    assert s["kind"] == "RoleRequest"
    assert s["accounts"] == ["060392206767"]
    assert s["duration_hours"] == 4
    # GitHub projection fields are empty/None for AWS requests
    assert s["github_org"] is None and s["github_repos"] == [] and s["github_repo_count"] == 0


def test_to_template_keeps_github_block() -> None:
    t = lifecycle.to_template(_GH)
    assert t["kind"] == "GitHubTokenRequest"
    assert t["spec"]["github"]["org"] == "acme"
    assert "accounts" not in t["spec"]


def test_to_template_aws_unchanged() -> None:
    t = lifecycle.to_template(_AWS)
    assert t["kind"] == "RoleRequest"
    assert t["spec"]["accounts"] == [{"account_id": "060392206767"}]
    assert "github" not in t["spec"]
