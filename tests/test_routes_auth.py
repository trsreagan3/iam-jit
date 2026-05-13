from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def test_magic_link_returns_dev_link_for_known_user(client: TestClient) -> None:
    resp = client.post("/api/v1/auth/magic-link", json={"email": "admin@example.com"})
    assert resp.status_code == 202
    body = resp.json()
    assert "dev_link" in body
    assert "callback?token=" in body["dev_link"]


def test_magic_link_no_link_leak_for_unknown_email(client: TestClient) -> None:
    resp = client.post("/api/v1/auth/magic-link", json={"email": "nobody@example.com"})
    assert resp.status_code == 202
    body = resp.json()
    assert "dev_link" not in body


def test_magic_link_callback_sets_cookie(client: TestClient) -> None:
    resp = client.post("/api/v1/auth/magic-link", json={"email": "admin@example.com"})
    link = resp.json()["dev_link"]
    token = link.split("token=", 1)[1]
    cb = client.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    assert cb.status_code == 303
    assert "iam_jit_session" in cb.cookies


def test_magic_link_invalid_token_rejected(client: TestClient) -> None:
    cb = client.get("/api/v1/auth/callback?token=garbage")
    assert cb.status_code == 400


def test_magic_link_disabled_user_no_link(client: TestClient) -> None:
    resp = client.post("/api/v1/auth/magic-link", json={"email": "disabled@example.com"})
    assert resp.status_code == 202
    assert "dev_link" not in resp.json()


def test_magic_link_missing_email_returns_uniform_202(client: TestClient) -> None:
    """Missing/malformed email returns the same 202 as unknown-email
    so an attacker can't distinguish input shape from registration
    state. Behavior changed from the earlier 400-on-bad-input to
    close an enumeration side channel."""
    resp = client.post("/api/v1/auth/magic-link", json={})
    assert resp.status_code == 202
    assert "dev_link" not in resp.json()


def test_magic_link_email_with_control_chars_uniform_202(
    client: TestClient,
) -> None:
    resp = client.post(
        "/api/v1/auth/magic-link",
        json={"email": "victim@example.com\nBcc: attacker@evil.com"},
    )
    assert resp.status_code == 202
    assert "dev_link" not in resp.json()


def test_logout_clears_cookie(as_admin: TestClient) -> None:
    resp = as_admin.post("/api/v1/auth/logout")
    assert resp.status_code == 200
    # Cookie value gets cleared by the response
    assert resp.cookies.get("iam_jit_session", "") in {"", None}


def test_protected_endpoint_requires_auth(client: TestClient) -> None:
    resp = client.get("/api/v1/users/me")
    assert resp.status_code == 401


def test_disabled_user_session_rejected(client: TestClient) -> None:
    from iam_jit import auth as auth_mod

    cookie = auth_mod.sign_session("test-secret-for-route-tests-aaaaaaaaa", "email:disabled@example.com")
    client.cookies.set("iam_jit_session", cookie)
    resp = client.get("/api/v1/users/me")
    assert resp.status_code == 403
    client.cookies.clear()
