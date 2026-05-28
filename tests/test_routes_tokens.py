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


# ---------------------------------------------------------------------------
# #697 — Token API honors `user_id` (admin mint-on-behalf-of). Pre-#697
# the field was silently dropped + tokens always minted for the session
# user. Now: admins mint for the target user; non-admins get 403; the
# admin path emits an OCSF class 6003 admin-action event.
# ---------------------------------------------------------------------------


def test_admin_can_mint_token_on_behalf_of_another_user(
    as_admin: TestClient,
) -> None:
    """Admin posts {user_id: dev} → token is owned by dev, NOT admin."""
    resp = as_admin.post("/api/v1/tokens", json={
        "user_id": "email:dev@example.com",
        "label": "for-dev",
    })
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # Token's owner is the TARGET user, not the admin actor.
    assert body["user_id"] == "email:dev@example.com"
    assert body["label"] == "for-dev"
    assert body["token"].startswith("iamjit_")


def test_admin_mint_on_behalf_token_authenticates_as_target_user(
    client: TestClient,
    as_admin: TestClient,
) -> None:
    """End-to-end: admin mints for dev → using the token resolves to
    dev's identity, not admin's. Proves the mint actually changed the
    token's owner field on the wire (not just the response body)."""
    raw = as_admin.post("/api/v1/tokens", json={
        "user_id": "email:dev@example.com",
    }).json()["token"]
    client.cookies.clear()
    me = client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {raw}"}
    )
    assert me.status_code == 200, me.text
    assert me.json()["id"] == "email:dev@example.com"


def test_non_admin_user_id_field_returns_403(as_dev: TestClient) -> None:
    """A non-admin caller passing user_id for someone else MUST be
    refused with 403 — silent-ignore is silent-degradation."""
    resp = as_dev.post("/api/v1/tokens", json={
        "user_id": "email:dev2@example.com",
    })
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    # FastAPI nests structured detail dicts under `detail`.
    assert detail.get("error") == "user_id requires admin scope"


def test_user_id_equal_to_self_is_a_no_op_for_non_admin(
    as_dev: TestClient,
) -> None:
    """Passing user_id=self is the legacy shape: no admin scope needed,
    no on-behalf-of audit event, behaves identically to omitting."""
    resp = as_dev.post("/api/v1/tokens", json={
        "user_id": "email:dev@example.com",
        "label": "self-mint",
    })
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["user_id"] == "email:dev@example.com"


def test_admin_mint_for_unknown_user_returns_404(
    as_admin: TestClient,
) -> None:
    """Admin minting for a user_id that doesn't exist in the user store
    gets a clean 404 — an unknown user_id silently creating an orphan
    token is the opposite of helpful."""
    resp = as_admin.post("/api/v1/tokens", json={
        "user_id": "email:ghost@example.com",
    })
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail.get("error") == "user_id not found"
    assert detail.get("user_id") == "email:ghost@example.com"


def test_user_id_non_string_rejected_400(as_admin: TestClient) -> None:
    """A malformed user_id (number, dict, list) gets a 400 instead of
    a confused 500 inside the store lookup."""
    resp = as_admin.post("/api/v1/tokens", json={"user_id": 42})
    assert resp.status_code == 400
    assert "user_id must be a string" in resp.text


def test_admin_mint_on_behalf_emits_admin_action_audit(
    as_admin: TestClient,
    monkeypatch,
) -> None:
    """The on-behalf-of mint path MUST fire emit_iam_jit_admin_action
    so the audit chain shows admin → mint → target_user. Otherwise
    the silent-ignore symptom comes back wearing a different mask."""
    captured: list[dict] = []

    def _fake_emit(**kwargs):
        captured.append(kwargs)

    from iam_jit import audit_admin_action

    monkeypatch.setattr(
        audit_admin_action, "emit_iam_jit_admin_action", _fake_emit,
    )
    # The route imports the helper lazily; patch the module attribute
    # at the import path the route uses.
    from iam_jit.routes import tokens as tokens_route
    monkeypatch.setattr(
        tokens_route, "__name__", tokens_route.__name__,  # no-op anchor
    )

    resp = as_admin.post("/api/v1/tokens", json={
        "user_id": "email:dev@example.com",
        "label": "audit-test",
    })
    assert resp.status_code == 201, resp.text
    assert len(captured) == 1
    evt = captured[0]
    assert evt["kind"] == "token.mint_on_behalf_of"
    assert evt["actor"] == "email:admin@example.com"
    assert evt["target_kind"] == "user"
    assert evt["target_id"] == "email:dev@example.com"
    assert evt["source"] == "api"
    assert evt["extra"]["label"] == "audit-test"
    assert "token_hash" in evt["extra"]


def test_self_mint_does_not_emit_on_behalf_of_audit(
    as_admin: TestClient,
    monkeypatch,
) -> None:
    """An admin minting for THEMSELVES should NOT fire the
    on-behalf-of audit — the audit kind would falsely imply
    delegation. Same path as a non-admin self-mint."""
    captured: list[dict] = []

    from iam_jit import audit_admin_action

    monkeypatch.setattr(
        audit_admin_action,
        "emit_iam_jit_admin_action",
        lambda **kw: captured.append(kw),
    )
    resp = as_admin.post("/api/v1/tokens", json={
        "user_id": "email:admin@example.com",
    })
    assert resp.status_code == 201, resp.text
    assert captured == []
