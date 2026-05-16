"""Banned-user enforcement at the middleware + admin /bans surface."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


@pytest.fixture(autouse=True)
def reset_bans() -> None:
    from iam_jit import bans

    bans.reset_default_store_for_tests()


@pytest.fixture(autouse=True)
def force_ai_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from iam_jit import review

    monkeypatch.setattr(review, "is_review_enabled", lambda: True)


# ---- middleware blocks banned users ----


def test_banned_user_blocked_at_middleware(
    as_dev: TestClient, request_payload: dict
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
    # Authenticated request now 403s on the middleware ban check.
    resp = as_dev.get("/api/v1/users/me")
    assert resp.status_code == 403
    assert "suspended" in resp.text.lower()


def test_unbanned_user_works_normally(as_dev: TestClient) -> None:
    resp = as_dev.get("/api/v1/users/me")
    assert resp.status_code == 200


# ---- chat injection → auto-ban ----


def test_chat_post_high_signal_injection_bans_user(
    as_dev: TestClient,
) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
def test_chat_post_medium_signal_refused_but_no_ban(
    as_dev: TestClient,
) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
def test_chat_stream_injection_bans_and_returns_403(
    as_dev: TestClient,
) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
def test_admin_user_is_not_banned_for_injection(
    as_admin: TestClient,
) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
# ---- /api/v1/intake/turn ----


def test_intake_turn_high_injection_bans(as_dev: TestClient) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
def test_intake_turn_clean_message_passes(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
# ---- admin /bans endpoints ----


def test_admin_can_list_bans(as_admin: TestClient) -> None:
    from iam_jit import bans

    bans.get_default_store().add(
        bans.Ban(
            user_id="email:badactor@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["approve-forgery"],
            snippets=["auto-approve"],
            confidence="high",
            actor="system",
        )
    )
    body = as_admin.get("/api/v1/admin/bans").json()
    assert body["count"] == 1
    assert body["bans"][0]["user_id"] == "email:badactor@example.com"


def test_non_admin_cannot_list_bans(
    as_dev: TestClient, as_approver: TestClient
) -> None:
    assert as_dev.get("/api/v1/admin/bans").status_code == 403
    assert as_approver.get("/api/v1/admin/bans").status_code == 403


def test_admin_can_unban_other_user(as_admin: TestClient) -> None:
    from iam_jit import bans

    bans.get_default_store().add(
        bans.Ban(
            user_id="email:dev@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["x"],
            snippets=[],
            confidence="high",
            actor="system",
        )
    )
    resp = as_admin.post(
        "/api/v1/admin/bans/email:dev@example.com/unban",
        json={"reason": "false positive — verified legitimate"},
    )
    assert resp.status_code == 200
    assert not bans.get_default_store().is_banned("email:dev@example.com")


def test_admin_cannot_unban_themselves(as_admin: TestClient) -> None:
    """Self-unban is explicitly refused — second pair of eyes required."""
    from iam_jit import bans

    bans.get_default_store().add(
        bans.Ban(
            user_id="email:admin@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["x"],
            snippets=[],
            confidence="high",
            actor="manual",
        )
    )
    resp = as_admin.post(
        "/api/v1/admin/bans/email:admin@example.com/unban",
        json={"reason": "lifting my own ban"},
    )
    # The middleware ban check fires before the route, so this returns
    # 403 from the middleware (not the self-check). Either way: refused.
    assert resp.status_code == 403


def test_admin_unban_requires_reason(as_admin: TestClient) -> None:
    from iam_jit import bans

    bans.get_default_store().add(
        bans.Ban(
            user_id="email:dev@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["x"],
            snippets=[],
            confidence="high",
            actor="system",
        )
    )
    resp = as_admin.post(
        "/api/v1/admin/bans/email:dev@example.com/unban",
        json={"reason": ""},
    )
    assert resp.status_code == 400


def test_admin_unban_unknown_user_is_404(as_admin: TestClient) -> None:
    resp = as_admin.post(
        "/api/v1/admin/bans/email:nobody@example.com/unban",
        json={"reason": "no-op verification"},
    )
    assert resp.status_code == 404


# ---- helpers ----


@pytest.fixture
def request_payload() -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
        "spec": {
            "description": "ban suite fixture request",
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
