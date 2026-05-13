"""F34: admin token revocation surface."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


pytest_plugins = ["tests.conftest_routes"]


def _mint_token(as_dev: TestClient, label: str = "test") -> str:
    r = as_dev.post("/api/v1/tokens", json={"label": label})
    assert r.status_code == 201, r.text
    return r.json()["token"]


def test_admin_revokes_all_user_tokens(
    as_admin: TestClient, as_dev: TestClient
) -> None:
    _mint_token(as_dev, "first")
    _mint_token(as_dev, "second")
    listed_before = as_dev.get("/api/v1/tokens").json()["tokens"]
    assert len(listed_before) >= 2

    r = as_admin.post(
        "/api/v1/admin/users/email:dev@example.com/revoke-tokens",
        json={"reason": "user disabled — rotating credentials"},
    )
    assert r.status_code == 200
    assert r.json()["revoked_count"] >= 2

    listed_after = as_dev.get("/api/v1/tokens").json()["tokens"]
    assert listed_after == []


def test_non_admin_cannot_revoke_tokens(
    as_dev: TestClient, as_approver: TestClient
) -> None:
    body = {"reason": "should be refused"}
    assert (
        as_dev.post(
            "/api/v1/admin/users/email:dev@example.com/revoke-tokens",
            json=body,
        ).status_code
        == 403
    )
    assert (
        as_approver.post(
            "/api/v1/admin/users/email:dev@example.com/revoke-tokens",
            json=body,
        ).status_code
        == 403
    )


def test_admin_cannot_revoke_own_tokens_via_this_endpoint(
    as_admin: TestClient,
) -> None:
    """Self-revoke would lock the admin out mid-call — refused."""
    r = as_admin.post(
        "/api/v1/admin/users/email:admin@example.com/revoke-tokens",
        json={"reason": "self-revoke attempted"},
    )
    assert r.status_code == 403
    assert "self" in r.text.lower() or "use DELETE" in r.text


def test_revoke_requires_reason(as_admin: TestClient) -> None:
    r = as_admin.post(
        "/api/v1/admin/users/email:dev@example.com/revoke-tokens",
        json={"reason": ""},
    )
    assert r.status_code == 400


def test_revoke_user_with_no_tokens_returns_zero(
    as_admin: TestClient,
) -> None:
    """Idempotent — calling on a user with no tokens succeeds with 0."""
    r = as_admin.post(
        "/api/v1/admin/users/email:dev2@example.com/revoke-tokens",
        json={"reason": "preemptive cleanup"},
    )
    assert r.status_code == 200
    assert r.json()["revoked_count"] == 0


def test_revoked_token_no_longer_authenticates(
    as_admin: TestClient, as_dev: TestClient, client: TestClient
) -> None:
    raw = _mint_token(as_dev, "doomed")

    # Token works pre-revocation.
    r1 = client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {raw}"}
    )
    assert r1.status_code == 200

    as_admin.post(
        "/api/v1/admin/users/email:dev@example.com/revoke-tokens",
        json={"reason": "post-test"},
    )

    # Same token now fails.
    r2 = client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {raw}"}
    )
    assert r2.status_code in (401, 403)
