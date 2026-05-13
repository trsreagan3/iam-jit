from __future__ import annotations

from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def test_me_returns_caller(as_dev: TestClient) -> None:
    resp = as_dev.get("/api/v1/users/me")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "email:dev@example.com"
    assert body["roles"] == ["requester"]


def test_me_returns_agent_hints_for_token_minting(as_dev: TestClient) -> None:
    """An agent that lands on /api/v1/users/me with an auth header
    should be able to discover everything it needs to bootstrap, mint
    tokens, and submit requests — without reading the README."""
    body = as_dev.get("/api/v1/users/me").json()
    hints = body["agent_hints"]
    # Token minting
    assert hints["mint_token"]["method"] == "POST"
    assert hints["mint_token"]["path"] == "/api/v1/tokens"
    # List + revoke
    assert hints["list_my_tokens"]["path"] == "/api/v1/tokens"
    assert hints["revoke_token"]["path"].startswith("/api/v1/tokens/")
    # Submission paths
    assert hints["submit_request_structured"]["path"] == "/api/v1/requests"
    assert hints["submit_request_conversational"]["path"] == "/api/v1/intake/turn"
    # Read paths
    assert hints["list_my_requests"]["path"] == "/api/v1/requests"
    assert "hide_cancelled" in hints["list_my_requests"]["query"]
    assert hints["assume_instructions"]["path"].endswith("/assume")


def test_list_users_admin_only(as_dev: TestClient) -> None:
    resp = as_dev.get("/api/v1/users")
    assert resp.status_code == 403


def test_list_users_admin_ok(as_admin: TestClient) -> None:
    resp = as_admin.get("/api/v1/users")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 4  # admin, approver, dev, dev2 (disabled excluded)


def test_list_includes_disabled_when_requested(as_admin: TestClient) -> None:
    resp = as_admin.get("/api/v1/users?include_disabled=true")
    ids = {u["id"] for u in resp.json()["users"]}
    assert "email:disabled@example.com" in ids


def test_create_user_file_store_returns_409(as_admin: TestClient) -> None:
    """The test fixture uses FileUserStore, which is read-only."""
    resp = as_admin.post(
        "/api/v1/users",
        json={"id": "email:newbie@example.com", "roles": ["requester"]},
    )
    assert resp.status_code == 409


def test_create_user_validation(as_admin: TestClient) -> None:
    bad = as_admin.post("/api/v1/users", json={"id": "newbie@example.com", "roles": ["requester"]})
    assert bad.status_code == 400  # missing email:/iam: prefix
    bad2 = as_admin.post("/api/v1/users", json={"id": "email:x@y.com", "roles": ["wizard"]})
    assert bad2.status_code == 400


def test_dev_cannot_delete_user(as_dev: TestClient) -> None:
    resp = as_dev.delete("/api/v1/users/email:approver@example.com")
    assert resp.status_code == 403
