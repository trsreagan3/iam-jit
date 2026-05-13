"""Verify the banned-user check fires on every authentication and
state-changing surface.

For each entry point we expect a banned user to be rejected — never
to leave the system in a state that requires re-checking later.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


pytest_plugins = ["tests.conftest_routes"]


@pytest.fixture
def banned_dev() -> None:
    """Pre-populate the bans store with `email:dev@example.com`."""
    from iam_jit import bans

    bans.get_default_store().add(
        bans.Ban(
            user_id="email:dev@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["test"],
            snippets=[],
            confidence="high",
            actor="system",
        )
    )


# ---- API surfaces ----


def test_banned_user_get_users_me_403(
    as_dev: TestClient, banned_dev: None
) -> None:
    r = as_dev.get("/api/v1/users/me")
    assert r.status_code == 403


def test_banned_user_post_request_403(
    as_dev: TestClient, banned_dev: None, request_payload: dict
) -> None:
    r = as_dev.post("/api/v1/requests", json=request_payload)
    assert r.status_code == 403


def test_banned_user_list_requests_403(
    as_dev: TestClient, banned_dev: None
) -> None:
    r = as_dev.get("/api/v1/requests")
    assert r.status_code == 403


def test_banned_user_intake_turn_403(
    as_dev: TestClient, banned_dev: None
) -> None:
    r = as_dev.post(
        "/api/v1/intake/turn",
        json={"conversation": [{"role": "user", "content": "s3 read please"}]},
    )
    assert r.status_code == 403


def test_banned_user_token_create_403(
    as_dev: TestClient, banned_dev: None
) -> None:
    r = as_dev.post("/api/v1/tokens", json={"label": "test"})
    assert r.status_code == 403


def test_banned_user_token_list_403(
    as_dev: TestClient, banned_dev: None
) -> None:
    r = as_dev.get("/api/v1/tokens")
    assert r.status_code == 403


def test_banned_user_policy_analyze_403(
    as_dev: TestClient, banned_dev: None
) -> None:
    r = as_dev.post(
        "/api/v1/policy/analyze",
        json={
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ],
            }
        },
    )
    assert r.status_code == 403


# ---- web surfaces ----


def test_banned_user_chat_get_403(
    as_dev: TestClient, banned_dev: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from iam_jit import review

    monkeypatch.setattr(review, "is_review_enabled", lambda: True)
    r = as_dev.get("/requests/new/chat")
    assert r.status_code == 403


def test_banned_user_chat_post_403(
    as_dev: TestClient, banned_dev: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from iam_jit import review

    monkeypatch.setattr(review, "is_review_enabled", lambda: True)
    r = as_dev.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "I need s3 read"},
    )
    assert r.status_code == 403


def test_banned_user_chat_stream_403(
    as_dev: TestClient, banned_dev: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from iam_jit import review

    monkeypatch.setattr(review, "is_review_enabled", lambda: True)
    r = as_dev.post(
        "/requests/new/chat/stream",
        data={"conversation": "", "message": "I need s3 read"},
    )
    assert r.status_code == 403


def test_banned_user_web_action_approve_403(
    as_approver: TestClient, request_payload: dict
) -> None:
    """Banned approver can't approve via the web POST handler either."""
    from iam_jit import bans

    # Submit a request as dev first via the API.
    # We need a separate non-banned client for setup.
    # Instead, direct-write to the bans store after the fact.
    bans.get_default_store().add(
        bans.Ban(
            user_id="email:approver@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["test"],
            snippets=[],
            confidence="high",
            actor="system",
        )
    )
    r = as_approver.post(
        "/requests/rq-nonexistent/approve",
        data={"comment": ""},
    )
    assert r.status_code == 403


def test_banned_user_web_comment_form_403(
    as_dev: TestClient, banned_dev: None
) -> None:
    r = as_dev.post(
        "/requests/rq-nonexistent/comments",
        data={"message": "hello"},
    )
    assert r.status_code == 403


# ---- magic-link surfaces ----


def test_banned_user_cannot_get_session_via_web_magic_callback(
    client: TestClient,
) -> None:
    """A banned user signing in via the web magic-link callback gets
    refused before a session cookie is issued."""
    from iam_jit import auth as auth_mod, bans

    bans.get_default_store().add(
        bans.Ban(
            user_id="email:dev@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["test"],
            snippets=[],
            confidence="high",
            actor="system",
        )
    )
    secret = "test-secret-for-route-tests-aaaaaaaaa"
    token = auth_mod.sign_magic_link(secret, "email:dev@example.com")
    r = client.get(
        f"/auth/magic-callback?token={token}", follow_redirects=False
    )
    assert r.status_code == 403
    # No session cookie should be set on a refused sign-in.
    assert "iam_jit_session" not in r.cookies


def test_banned_user_cannot_get_session_via_api_magic_callback(
    client: TestClient,
) -> None:
    from iam_jit import auth as auth_mod, bans

    bans.get_default_store().add(
        bans.Ban(
            user_id="email:dev@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["test"],
            snippets=[],
            confidence="high",
            actor="system",
        )
    )
    secret = "test-secret-for-route-tests-aaaaaaaaa"
    token = auth_mod.sign_magic_link(secret, "email:dev@example.com")
    r = client.get(
        f"/api/v1/auth/callback?token={token}", follow_redirects=False
    )
    assert r.status_code == 403


def test_banned_user_no_link_emitted_via_api_magic_link_request(
    client: TestClient,
) -> None:
    from iam_jit import bans

    bans.get_default_store().add(
        bans.Ban(
            user_id="email:dev@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["test"],
            snippets=[],
            confidence="high",
            actor="system",
        )
    )
    r = client.post(
        "/api/v1/auth/magic-link", json={"email": "dev@example.com"}
    )
    assert r.status_code == 202
    # No dev_link for banned users — same shape as unknown email.
    assert "dev_link" not in r.json()


# ---- helpers ----


@pytest.fixture
def request_payload() -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
        "spec": {
            "description": "ban-uniformity test fixture request",
            "access_type": "read-only",
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 24},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::ex/*"],
                    }
                ],
            },
        },
    }
