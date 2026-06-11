"""Hermetic unit tests for the GitHub App provisioner (no network, no real org).

These prove iam-jit REQUESTS the correct down-scope + handles the lifecycle.
They do NOT prove GitHub ENFORCES the scope — that's the real-org blast-radius
UAT (docs/design/github-jit-tokens.md). Keep both.
"""

from __future__ import annotations

import json

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from iam_jit.github_provisioner import (
    GitHubAppConfig,
    GitHubAppProvisioner,
    GitHubProvisioningError,
    build_app_jwt,
)


def _keypair() -> tuple[str, object]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return pem, key.public_key()


def _provisioner(handler, *, private_pem: str) -> GitHubAppProvisioner:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    cfg = GitHubAppConfig(app_id="12345", private_key_pem=private_pem, installation_id="99")
    return GitHubAppProvisioner(cfg, http=client, now=lambda: 1_780_000_000)


def test_build_app_jwt_is_valid_rs256_and_short_lived() -> None:
    pem, pub = _keypair()
    tok = build_app_jwt("12345", pem, now=1_780_000_000)
    claims = jwt.decode(tok, pub, algorithms=["RS256"], options={"verify_exp": False})
    assert claims["iss"] == "12345"
    # exp must be <= 10 minutes after iat (GitHub rejects longer)
    assert 0 < claims["exp"] - claims["iat"] <= 600


def test_mint_requests_exact_downscope_and_parses_token() -> None:
    pem, pub = _keypair()
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/app/installations/99/access_tokens"
        # the App JWT must be present + valid (signed by our key)
        auth = request.headers["Authorization"]
        assert auth.startswith("Bearer ")
        claims = jwt.decode(auth[len("Bearer "):], pub, algorithms=["RS256"], options={"verify_exp": False})
        assert claims["iss"] == "12345"
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={
                "token": "ghs_scopedtoken",
                "expires_at": "2026-06-05T01:00:00Z",
                "permissions": {"pull_requests": "write"},
                "repository_selection": "selected",
                "repositories": [{"name": "repo-x"}],
            },
        )

    p = _provisioner(handler, private_pem=pem)
    out = p.mint_scoped_token(repositories=["repo-x"], permissions={"pull_requests": "write"})

    # THE point: we asked GitHub for exactly the task's repo + permission.
    assert captured["body"] == {"repositories": ["repo-x"], "permissions": {"pull_requests": "write"}}
    assert out.token == "ghs_scopedtoken"
    assert out.expires_at == "2026-06-05T01:00:00Z"
    assert out.repositories == ("repo-x",)
    assert out.permissions == {"pull_requests": "write"}


def test_mint_refuses_empty_repos_least_privilege_guard() -> None:
    pem, _ = _keypair()
    # an empty repo list = "all repos" to GitHub — the blast-radius footgun.
    p = _provisioner(lambda r: httpx.Response(201, json={}), private_pem=pem)
    with pytest.raises(GitHubProvisioningError, match="no repositories"):
        p.mint_scoped_token(repositories=[], permissions={"contents": "read"})


def test_mint_refuses_empty_permissions() -> None:
    pem, _ = _keypair()
    p = _provisioner(lambda r: httpx.Response(201, json={}), private_pem=pem)
    with pytest.raises(GitHubProvisioningError, match="no permissions"):
        p.mint_scoped_token(repositories=["repo-x"], permissions={})


def test_mint_surfaces_github_error() -> None:
    pem, _ = _keypair()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"message": "repository not accessible by integration"})

    p = _provisioner(handler, private_pem=pem)
    with pytest.raises(GitHubProvisioningError, match="not accessible") as e:
        p.mint_scoped_token(repositories=["repo-x"], permissions={"contents": "write"})
    assert e.value.status == 422


def test_revoke_ok_and_idempotent_on_expired() -> None:
    pem, _ = _keypair()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        assert request.url.path == "/installation/token"
        seen.append(request.headers["Authorization"])
        # 204 first call; 401 (already-expired) second call
        return httpx.Response(204 if len(seen) == 1 else 401)

    p = _provisioner(handler, private_pem=pem)
    p.revoke("ghs_scopedtoken")  # 204
    p.revoke("ghs_scopedtoken")  # 401 -> treated as success (idempotent)
    assert seen[0] == "Bearer ghs_scopedtoken"
