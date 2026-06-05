from __future__ import annotations

import pathlib

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from iam_jit.github_scope import (
    AUTO_APPROVE_MAX_SCORE,
    analyze_github_scope,
    scope_github_task,
)


def test_scorer_low_for_single_repo_pr_write() -> None:
    r = analyze_github_scope(["repo-x"], {"pull_requests": "write"})
    assert r.band == "low"
    assert r.would_auto_approve
    assert r.risk_score <= AUTO_APPROVE_MAX_SCORE


def test_scorer_high_for_contents_write_across_many_repos() -> None:
    # the incident shape: write code everywhere
    r = analyze_github_scope([f"r{i}" for i in range(30)], {"contents": "write"})
    assert r.band == "high"
    assert not r.would_auto_approve
    assert r.risk_score >= 7


def test_scorer_high_for_workflows_or_admin_write_even_single_repo() -> None:
    # CI / settings write is the supply-chain vector → high even on one repo
    assert analyze_github_scope(["r"], {"workflows": "write"}).band == "high"
    assert analyze_github_scope(["r"], {"administration": "write"}).band == "high"


def test_scorer_reads_are_low() -> None:
    r = analyze_github_scope(["r"], {"contents": "read", "metadata": "read"})
    assert r.would_auto_approve and r.band == "low"


def test_scorer_empty_repos_scores_max() -> None:
    r = analyze_github_scope([], {"contents": "read"})
    assert r.risk_score == 10 and not r.would_auto_approve


def _registry(tmp_path: pathlib.Path) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    keyp = tmp_path / "app.pem"
    keyp.write_bytes(pem)
    reg = tmp_path / "gh.yaml"
    reg.write_text(
        "apiVersion: iam-jit.dev/v1alpha1\nkind: GitHubInstallationList\n"
        "installations:\n  - org: acme\n    app_id: \"1\"\n    installation_id: \"9\"\n"
        f"    private_key_path: {keyp}\n"
    )
    return str(reg)


def _mint_handler(captured: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        import json
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={"token": "ghs_issued", "expires_at": "2026-06-05T01:00:00Z",
                  "permissions": {"pull_requests": "write"}, "repositories": [{"name": "repo-x"}]},
        )
    return handler


def test_compose_low_risk_issues_token(tmp_path: pathlib.Path) -> None:
    captured: dict = {}
    client = httpx.Client(transport=httpx.MockTransport(_mint_handler(captured)))
    d = scope_github_task(
        installations_path=_registry(tmp_path), org="acme",
        description="open a PR on repo-x",
        repositories=["repo-x"], permissions={"pull_requests": "write"},
        http=client, now=lambda: 1_780_000_000,
    )
    assert d.decision == "issued"
    assert d.token == "ghs_issued"
    # it actually requested the exact down-scope
    assert captured["body"] == {"repositories": ["repo-x"], "permissions": {"pull_requests": "write"}}


def test_compose_high_risk_needs_approval_and_mints_NOTHING(tmp_path: pathlib.Path) -> None:
    captured: dict = {}
    client = httpx.Client(transport=httpx.MockTransport(_mint_handler(captured)))
    d = scope_github_task(
        installations_path=_registry(tmp_path), org="acme",
        description="rewrite contents everywhere (suspicious)",
        repositories=[f"r{i}" for i in range(30)], permissions={"contents": "write"},
        http=client, now=lambda: 1_780_000_000,
    )
    assert d.decision == "needs_approval"
    assert d.token is None
    # critical: a high-risk request must NOT have called GitHub to mint.
    assert "body" not in captured
