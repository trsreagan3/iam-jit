"""Integration tests for /api/v1/auth/oidc/{login,callback}.

Covers the route behavior + cookie handling + integration with
the existing user_store + audit module. ID-token validation
itself is covered in test_oidc.py — these tests focus on the
HTTP-route layer's correctness.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


@pytest.fixture
def oidc_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure OIDC env vars for Google (the most common case)."""
    monkeypatch.setenv("IAM_JIT_OIDC_PROVIDER", "google")
    monkeypatch.setenv("IAM_JIT_OIDC_CLIENT_ID", "test-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("IAM_JIT_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("IAM_JIT_OIDC_REDIRECT_URI", "https://x/api/v1/auth/oidc/callback")
    monkeypatch.setenv("IAM_JIT_OIDC_HOSTED_DOMAIN", "example.com")


@pytest.fixture
def oidc_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicitly unset OIDC env vars."""
    for var in [
        "IAM_JIT_OIDC_PROVIDER", "IAM_JIT_OIDC_CLIENT_ID",
        "IAM_JIT_OIDC_CLIENT_SECRET", "IAM_JIT_OIDC_REDIRECT_URI",
        "IAM_JIT_OIDC_HOSTED_DOMAIN", "IAM_JIT_OIDC_ISSUER",
    ]:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def stub_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub discover() — so the route doesn't try to reach Google."""
    from iam_jit import oidc
    from iam_jit.routes import oidc as oidc_route

    def _fake_discover(config, client):
        if config.provider == "google":
            return oidc.DiscoveredEndpoints(
                authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
                token_endpoint="https://oauth2.googleapis.com/token",
                jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
                issuer="https://accounts.google.com",
            )
        return oidc.DiscoveredEndpoints(
            authorization_endpoint=f"{config.issuer}/oauth/auth",
            token_endpoint=f"{config.issuer}/oauth/token",
            jwks_uri=f"{config.issuer}/oauth/keys",
            issuer=config.issuer,
        )

    monkeypatch.setattr(oidc, "discover", _fake_discover)
    oidc_route._reset_caches_for_tests()


def test_login_returns_503_when_oidc_not_configured(
    client: TestClient, oidc_env_unset
) -> None:
    resp = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    assert resp.status_code == 503


def test_callback_returns_503_when_oidc_not_configured(
    client: TestClient, oidc_env_unset
) -> None:
    resp = client.get(
        "/api/v1/auth/oidc/callback?code=x&state=y",
        follow_redirects=False,
    )
    assert resp.status_code == 503


def test_login_redirects_to_provider(
    client: TestClient, oidc_env, stub_discovery
) -> None:
    resp = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    assert resp.status_code == 303
    location = resp.headers["location"]
    parsed = urlparse(location)
    assert parsed.netloc == "accounts.google.com"
    params = parse_qs(parsed.query)
    assert "state" in params
    assert "nonce" in params
    assert params["client_id"][0] == "test-client-id.apps.googleusercontent.com"
    assert params["hd"][0] == "example.com"
    assert params["response_type"][0] == "code"
    assert "openid" in params["scope"][0]
    assert params["prompt"][0] == "select_account"


def test_login_sets_signed_state_and_nonce_cookies(
    client: TestClient, oidc_env, stub_discovery
) -> None:
    resp = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    cookies = resp.cookies
    assert "iam_jit_oidc_state" in cookies
    assert "iam_jit_oidc_nonce" in cookies


def test_callback_missing_code_returns_400(
    client: TestClient, oidc_env, stub_discovery
) -> None:
    resp = client.get(
        "/api/v1/auth/oidc/callback?state=somethnig",
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_callback_missing_state_returns_400(
    client: TestClient, oidc_env, stub_discovery
) -> None:
    resp = client.get(
        "/api/v1/auth/oidc/callback?code=somethnig",
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_callback_provider_returned_error_returns_401(
    client: TestClient, oidc_env, stub_discovery
) -> None:
    resp = client.get(
        "/api/v1/auth/oidc/callback?error=access_denied&error_description=user+declined",
        follow_redirects=False,
    )
    assert resp.status_code == 401


def test_callback_no_state_cookie_returns_401(
    client: TestClient, oidc_env, stub_discovery
) -> None:
    """Callback hit directly (no prior /login) → no state cookie → reject."""
    resp = client.get(
        "/api/v1/auth/oidc/callback?code=somecode&state=somestate",
        follow_redirects=False,
    )
    assert resp.status_code == 401


def test_callback_state_query_param_mismatch_returns_401(
    client: TestClient, oidc_env, stub_discovery
) -> None:
    """CSRF check: cookie state must match query param."""
    login_resp = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    # Use a DIFFERENT state in the callback than the cookie holds.
    resp = client.get(
        "/api/v1/auth/oidc/callback?code=somecode&state=ATTACKER-CONTROLLED",
        cookies=login_resp.cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 401
