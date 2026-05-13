"""Confirm agents can add users via API token (production-mode shape).

The existing test_routes_users.py asserts the route works via session
cookie, but agents authenticate with a Bearer token instead. This file
swaps the conftest's read-only FileUserStore for an in-memory writable
store so we can prove the dynamodb-mode (production) shape works.
"""

from __future__ import annotations

from typing import Any

import dataclasses
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_jit.api_tokens_store import APITokenRecord, InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.auth import hash_token, sign_session
from iam_jit.store import FilesystemStore
from iam_jit.users_store import User, UserStore, UserNotFound


_DEV_SECRET = "test-secret-for-route-tests-aaaaaaaaa"


class _WritableInMemoryUserStore:
    """Mimics DynamoDBUserStore (read/write) for tests."""

    name = "memory-rw"

    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        # Seed the personas the conftest fixtures expect.
        for u in [
            User(id="email:admin@example.com", roles=("admin",), display_name="Admin"),
            User(id="email:approver@example.com", roles=("approver",), display_name="Approver"),
            User(id="email:dev@example.com", roles=("requester",), display_name="Dev"),
        ]:
            self.users[u.id] = u

    def get(self, user_id: str) -> User:
        if user_id not in self.users:
            raise UserNotFound(user_id)
        return self.users[user_id]

    def list(self, *, include_disabled: bool = False) -> list[User]:
        return [u for u in self.users.values() if include_disabled or u.enabled]

    def put(self, user: User) -> None:
        self.users[user.id] = user

    def delete(self, user_id: str) -> None:
        self.users.pop(user_id, None)


@pytest.fixture
def app(tmp_path, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)
    return create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=_WritableInMemoryUserStore(),
        api_tokens_store=InMemoryAPITokenStore(),
    )


@pytest.fixture
def admin_client(app: FastAPI) -> TestClient:
    """Session-authed admin client (used to mint the agent token)."""
    c = TestClient(app)
    c.cookies.set(
        "iam_jit_session",
        sign_session(_DEV_SECRET, "email:admin@example.com"),
    )
    return c


@pytest.fixture
def admin_token(admin_client: TestClient) -> str:
    minted = admin_client.post(
        "/api/v1/tokens", json={"label": "agent"}
    ).json()
    return minted["token"]


@pytest.fixture
def agent_client(app: FastAPI, admin_token: str) -> TestClient:
    """Token-authed client — what an agent uses, no session cookie."""
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {admin_token}"
    return c


# ---- the actual tests ----


def test_agent_can_add_user_via_token(agent_client: TestClient) -> None:
    resp = agent_client.post(
        "/api/v1/users",
        json={
            "id": "email:newhire@example.com",
            "display_name": "New Hire",
            "roles": ["requester"],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] == "email:newhire@example.com"
    assert "requester" in body["roles"]


def test_agent_can_promote_user_via_token(
    agent_client: TestClient,
) -> None:
    """Patch role on existing user via Bearer auth."""
    # First create
    agent_client.post(
        "/api/v1/users",
        json={
            "id": "email:newhire@example.com",
            "display_name": "New Hire",
            "roles": ["requester"],
        },
    )
    # Then patch
    resp = agent_client.patch(
        "/api/v1/users/email:newhire@example.com",
        json={"roles": ["requester", "approver"]},
    )
    assert resp.status_code == 200, resp.text
    assert "approver" in resp.json()["roles"]


def test_agent_can_disable_user_via_token(
    agent_client: TestClient,
) -> None:
    resp = agent_client.patch(
        "/api/v1/users/email:dev@example.com",
        json={"enabled": False},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is False


def test_non_admin_token_cannot_add_user(
    app: FastAPI, admin_client: TestClient
) -> None:
    """An API token issued for a non-admin is correctly rejected by
    require_admin even with a valid bearer."""
    # Mint a token "as if" it were issued for the dev (requester) user.
    # We do this by directly inserting the record — the /tokens endpoint
    # binds the token to the caller, so this is the only way to spoof.
    tokens_store = app.state.api_tokens_store
    raw = "iamjit_synthetic_dev_token_for_test_purposes_aaaaaaaaaaaaaa"
    tokens_store.put(
        APITokenRecord(
            token_hash=hash_token(raw),
            user_id="email:dev@example.com",
            created_at=1_700_000_000,
            label="dev-spoof",
        )
    )
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {raw}"
    resp = c.post(
        "/api/v1/users",
        json={"id": "email:newhire@example.com", "roles": ["requester"]},
    )
    assert resp.status_code == 403


def test_agent_token_for_disabled_admin_refused(
    app: FastAPI, admin_client: TestClient, admin_token: str
) -> None:
    """If an admin gets disabled, their agent's token instantly stops
    working — the middleware re-checks user.enabled on every request."""
    user_store: UserStore = app.state.user_store
    admin = user_store.get("email:admin@example.com")
    user_store.put(dataclasses.replace(admin, enabled=False))

    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {admin_token}"
    resp = c.post(
        "/api/v1/users",
        json={"id": "email:newhire@example.com", "roles": ["requester"]},
    )
    assert resp.status_code == 403
