"""Web-route tests for the GitHub JIT-token UI.

Hermetic: a stub GitHubRequestService (httpx.MockTransport + fixed clock + an
in-tmp registry) is injected onto app.state.github_service, so no network or
real GitHub App is touched. Auth + CSRF are handled by the shared route
fixtures (DEV_INSECURE bypasses CSRF in tests).
"""

from __future__ import annotations

import pathlib

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from iam_jit.github_requests import GitHubRequestService, GitHubRequestStore

pytest_plugins = ["tests.conftest_routes"]

_REGISTRY = """\
apiVersion: iam-jit.dev/v1alpha1
kind: GitHubInstallationList
installations:
  - org: acme
    app_id: "12345"
    installation_id: "99"
    private_key_path: {keypath}
"""


def _mock_github(captured: dict) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/access_tokens"):
            captured["mint_count"] = captured.get("mint_count", 0) + 1
            return httpx.Response(
                201,
                json={
                    "token": "ghs_route_secret",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "permissions": {"contents": "read"},
                    "repositories": [{"name": "r1"}],
                },
            )
        if request.method == "DELETE":
            captured["revoke_count"] = captured.get("revoke_count", 0) + 1
            return httpx.Response(204)
        return httpx.Response(500, json={"message": "unexpected"})

    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture
def gh_captured() -> dict:
    return {}


@pytest.fixture
def gh_app(shared_app, tmp_path: pathlib.Path, gh_captured: dict):
    """Inject a hermetic GitHubRequestService onto the shared app."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    keyp = tmp_path / "app.pem"
    keyp.write_bytes(pem)
    reg = tmp_path / "github-installations.yaml"
    reg.write_text(_REGISTRY.format(keypath=str(keyp)))
    shared_app.state.github_service = GitHubRequestService(
        installations_path=str(reg),
        store=GitHubRequestStore(str(tmp_path / "gh-reqs")),
        http=_mock_github(gh_captured),
        now=lambda: 1_780_000_000,
    )
    return shared_app


def test_dashboard_requires_login(gh_app, client) -> None:
    r = client.get("/github", follow_redirects=False)
    assert r.status_code in (302, 303, 307)


def test_dashboard_renders_for_user(gh_app, as_dev) -> None:
    r = as_dev.get("/github")
    assert r.status_code == 200
    assert "GitHub scoped tokens" in r.text
    assert "acme" in r.text  # connected org listed


def test_low_risk_submit_shows_token_once(gh_app, as_dev, gh_captured) -> None:
    r = as_dev.post(
        "/github/requests",
        data={"org": "acme", "repositories": "r1", "permissions": "pull_requests:write",
              "description": "open a PR"},
    )
    assert r.status_code == 200
    assert "Token issued" in r.text
    assert "ghs_route_secret" in r.text  # shown exactly once
    assert gh_captured["mint_count"] == 1


def test_high_risk_submit_queues_no_mint(gh_app, as_dev, gh_captured) -> None:
    r = as_dev.post(
        "/github/requests",
        data={"org": "acme", "repositories": " ".join(f"r{i}" for i in range(30)),
              "permissions": "contents:write", "description": "rewrite everything"},
    )
    assert r.status_code == 200
    assert "Approval required" in r.text
    assert "ghs_route_secret" not in r.text
    assert gh_captured.get("mint_count", 0) == 0


def test_approver_can_approve_queued_request(gh_app, as_dev, as_approver, gh_captured) -> None:
    # dev queues a high-risk request
    as_dev.post(
        "/github/requests",
        data={"org": "acme", "repositories": "r1", "permissions": "administration:write",
              "description": "settings"},
    )
    svc = gh_app.state.github_service
    rid = svc.store.list()[0].id
    # a plain requester cannot approve (require_approver gate)
    forbidden = as_dev.post(f"/github/requests/{rid}/approve")
    assert forbidden.status_code in (401, 403)
    # the approver can — token minted + shown once
    r = as_approver.post(f"/github/requests/{rid}/approve")
    assert r.status_code == 200
    assert "ghs_route_secret" in r.text
    assert gh_captured["mint_count"] == 1


def test_revoke_active_grant_calls_delete(gh_app, as_dev, gh_captured) -> None:
    as_dev.post(
        "/github/requests",
        data={"org": "acme", "repositories": "r1", "permissions": "pull_requests:write"},
    )
    svc = gh_app.state.github_service
    rid = svc.store.list()[0].id
    r = as_dev.post(f"/github/requests/{rid}/revoke", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert gh_captured["revoke_count"] == 1
    assert svc.store.get(rid).status == "revoked"


def test_bad_permission_format_surfaces_error(gh_app, as_dev) -> None:
    r = as_dev.post(
        "/github/requests",
        data={"org": "acme", "repositories": "r1", "permissions": "contents"},  # no :level
    )
    assert r.status_code == 400
    assert "name:level" in r.text or "name:(read" in r.text
