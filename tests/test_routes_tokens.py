from __future__ import annotations

from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def test_create_token_returns_raw_once(as_dev: TestClient) -> None:
    resp = as_dev.post("/api/v1/tokens", json={"label": "claude-code laptop"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["token"].startswith("iamjit_")
    assert body["user_id"] == "email:dev@example.com"
    assert body["label"] == "claude-code laptop"
    assert "warning" in body


def test_list_my_tokens_does_not_show_raw_values(as_dev: TestClient) -> None:
    create = as_dev.post("/api/v1/tokens", json={"label": "a"}).json()
    listed = as_dev.get("/api/v1/tokens").json()
    assert listed["count"] == 1
    only = listed["tokens"][0]
    assert only["token_hash"] == create["token_hash"]
    assert "token" not in only
    assert only["label"] == "a"


def test_token_authenticates_subsequent_requests(
    client: TestClient, as_dev: TestClient
) -> None:
    raw = as_dev.post("/api/v1/tokens", json={"label": "agent"}).json()["token"]
    # Use a fresh client without session cookie; only the bearer.
    client.cookies.clear()
    me = client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {raw}"}
    )
    assert me.status_code == 200, me.text
    assert me.json()["id"] == "email:dev@example.com"


def test_invalid_bearer_format_rejected(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer not-an-iamjit-token"},
    )
    assert resp.status_code == 401


def test_unknown_bearer_token_rejected(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer iamjit_abcdefghijklmnopqrstuvwxyz123456"},
    )
    assert resp.status_code == 401


def test_revoke_own_token(as_dev: TestClient) -> None:
    th = as_dev.post("/api/v1/tokens", json={}).json()["token_hash"]
    resp = as_dev.delete(f"/api/v1/tokens/{th}")
    assert resp.status_code == 200
    assert resp.json()["revoked"] is True
    listed = as_dev.get("/api/v1/tokens").json()
    assert listed["count"] == 0


def test_dev_cannot_revoke_others_token(
    as_dev: TestClient,
    as_dev2: TestClient,
) -> None:
    th = as_dev.post("/api/v1/tokens", json={}).json()["token_hash"]
    resp = as_dev2.delete(f"/api/v1/tokens/{th}")
    assert resp.status_code == 403
