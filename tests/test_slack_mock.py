"""Tests for the mock Slack server + an E2E test that points iam-jit's
slack_bot HTTP client at the mock."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit._test_support.slack_mock import MockSlackServer


@pytest.fixture
def mock() -> MockSlackServer:
    return MockSlackServer.build()


@pytest.fixture
def client(mock: MockSlackServer) -> TestClient:
    return TestClient(mock.app)


# ---------------------------------------------------------------------------
# Endpoint smoke tests.
# ---------------------------------------------------------------------------


def test_chat_post_message_returns_ts_and_records_call(
    mock: MockSlackServer, client: TestClient,
) -> None:
    r = client.post(
        "/api/chat.postMessage",
        headers={"Authorization": "Bearer xoxb-test"},
        json={"channel": "C123", "text": "hi", "blocks": [{"type": "section"}]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["channel"] == "C123"
    assert body["ts"].endswith(".000100")
    # Recorded:
    assert len(mock.calls) == 1
    call = mock.calls[0]
    assert call.url.endswith("/chat.postMessage")
    assert call.bot_token == "xoxb-tes…"  # masked per WB11-15
    assert call.json_body["text"] == "hi"


def test_chat_update(client: TestClient) -> None:
    r = client.post(
        "/api/chat.update",
        headers={"Authorization": "Bearer xoxb-test"},
        json={"channel": "C123", "ts": "1000000.000100", "text": "updated"},
    )
    body = r.json()
    assert body["ok"] is True
    assert body["channel"] == "C123"
    assert body["ts"] == "1000000.000100"


def test_views_open(client: TestClient) -> None:
    r = client.post(
        "/api/views.open",
        headers={"Authorization": "Bearer xoxb-test"},
        json={"trigger_id": "tid_123", "view": {"callback_id": "iam_jit_changes"}},
    )
    body = r.json()
    assert body["ok"] is True
    assert body["view"]["callback_id"] == "iam_jit_changes"


def test_users_info_known_user(mock: MockSlackServer, client: TestClient) -> None:
    mock.add_user(slack_id="U_ALICE", email="alice@example.com", name="alice")
    r = client.get(
        "/api/users.info",
        params={"user": "U_ALICE"},
        headers={"Authorization": "Bearer xoxb-test"},
    )
    body = r.json()
    assert body["ok"] is True
    assert body["user"]["profile"]["email"] == "alice@example.com"


def test_users_info_unknown_returns_not_ok(client: TestClient) -> None:
    r = client.get(
        "/api/users.info",
        params={"user": "U_GHOST"},
        headers={"Authorization": "Bearer xoxb-test"},
    )
    body = r.json()
    assert body["ok"] is False
    assert body["error"] == "user_not_found"


def test_auth_test(client: TestClient) -> None:
    r = client.post(
        "/api/auth.test",
        headers={"Authorization": "Bearer xoxb-test"},
        json={},
    )
    body = r.json()
    assert body["ok"] is True
    assert body["team_id"] == "T_MOCK"


# ---------------------------------------------------------------------------
# Failure-injection.
# ---------------------------------------------------------------------------


def test_fail_next_with_error_applies_once(
    mock: MockSlackServer, client: TestClient,
) -> None:
    mock.fail_next_with_error = "channel_not_found"
    r1 = client.post(
        "/api/chat.postMessage",
        headers={"Authorization": "Bearer xoxb-test"},
        json={"channel": "C123", "text": "x"},
    )
    assert r1.json() == {"ok": False, "error": "channel_not_found"}
    # Next call recovers — the flag is consumed.
    r2 = client.post(
        "/api/chat.postMessage",
        headers={"Authorization": "Bearer xoxb-test"},
        json={"channel": "C123", "text": "x"},
    )
    assert r2.json()["ok"] is True


def test_find_calls_by_suffix(mock: MockSlackServer, client: TestClient) -> None:
    client.post(
        "/api/chat.postMessage",
        headers={"Authorization": "Bearer xoxb"},
        json={"channel": "C1", "text": "a"},
    )
    client.post(
        "/api/chat.update",
        headers={"Authorization": "Bearer xoxb"},
        json={"channel": "C1", "ts": "1.000", "text": "b"},
    )
    assert len(mock.find_calls("/chat.postMessage")) == 1
    assert len(mock.find_calls("/chat.update")) == 1


# ---------------------------------------------------------------------------
# E2E: iam-jit slack_bot.post_approval_message → mock.
# Uses a stub SlackHTTPClient that proxies into the FastAPI TestClient,
# so we exercise the real iam-jit code path.
# ---------------------------------------------------------------------------


def test_e2e_post_approval_message_against_mock(
    mock: MockSlackServer, client: TestClient,
) -> None:
    from iam_jit import slack_bot

    class _ProxyClient:
        """Routes the bot's outbound HTTP into the mock TestClient
        instead of real Slack, by translating
        https://slack.com/api/<endpoint> → /api/<endpoint>."""

        def post_json(self, url: str, *, headers: dict[str, str], json_body: dict[str, Any]) -> dict[str, Any]:
            path = url.replace("https://slack.com", "")
            r = client.post(path, headers=headers, json=json_body)
            return r.json()

        def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]:
            r = client.get(
                "/api/users.info",
                params={"user": user_id},
                headers={"Authorization": f"Bearer {bot_token}"},
            )
            return r.json()

    cfg = slack_bot.SlackConfig(
        bot_token="xoxb-test",
        signing_secret="dummy-signing-secret",
        approval_channel="C_APPROVALS",
        expected_team_id="T_MOCK",
    )
    req: dict[str, Any] = {
        "metadata": {"id": "req-1", "owner": "email:alice@example.com", "state": "pending"},
        "spec": {
            "reason": "smoke test",
            "duration_hours": 1,
            "access_type": "read-only",
            "accounts": [{"account_id": "123456789012"}],
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
            },
        },
        "status": {"review": {"risk_score": 3, "factors": []}},
    }
    resp = slack_bot.post_approval_message(
        request=req, config=cfg, client=_ProxyClient(),
    )
    assert resp["ok"] is True
    assert resp["channel"] == "C_APPROVALS"
    # Mock recorded the call:
    posted = mock.find_calls("/chat.postMessage")
    assert len(posted) == 1
    call = posted[0]
    assert call.bot_token == "xoxb-tes…"  # masked per WB11-15
    assert call.json_body["channel"] == "C_APPROVALS"
    # The approval message has Block Kit blocks.
    assert "blocks" in call.json_body


# ---------------------------------------------------------------------------
# Phase 3 (minimal): post_mfa_step_up_nudge — DM the human authorizer
# when MFA blocks an agent's high-risk grant.
# ---------------------------------------------------------------------------


def test_mfa_step_up_nudge_posts_dm_with_reauth_link(
    mock: MockSlackServer, client: TestClient,
) -> None:
    from iam_jit import slack_bot

    class _ProxyClient:
        def post_json(self, url: str, *, headers: dict[str, str], json_body: dict[str, Any]) -> dict[str, Any]:
            path = url.replace("https://slack.com", "")
            r = client.post(path, headers=headers, json=json_body)
            return r.json()

        def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]:
            raise NotImplementedError

    cfg = slack_bot.SlackConfig(
        bot_token="xoxb-test",
        signing_secret="dummy",
        approval_channel="C_APPROVALS",
        expected_team_id="T_MOCK",
    )
    resp = slack_bot.post_mfa_step_up_nudge(
        user_id="email:alice@example.com",
        slack_user_id="U_ALICE",
        request_id="req-7f3a",
        config=cfg,
        deployment_url="https://iam-jit.example.com",
        reason="token_mfa_too_stale",
        client=_ProxyClient(),
    )
    assert resp["ok"] is True
    # Verify the DM was sent to the user's Slack ID + carries a
    # re-auth link with the request id baked in.
    posted = mock.find_calls("/chat.postMessage")
    assert len(posted) == 1
    body = posted[0].json_body
    assert body["channel"] == "U_ALICE"
    assert "req-7f3a" in body["text"]
    # The block kit payload should include a button URL pointing at
    # the OIDC login endpoint with `next=` set to the request URL.
    blocks_json = str(body["blocks"])
    assert "/api/v1/auth/oidc/login" in blocks_json
    assert "req-7f3a" in blocks_json


def test_mfa_step_up_nudge_requires_slack_user_id() -> None:
    """If we don't know the user's Slack ID, we can't DM them — fail
    explicitly rather than DM the wrong person."""
    from iam_jit import slack_bot
    cfg = slack_bot.SlackConfig(
        bot_token="xoxb-test",
        signing_secret="dummy",
        approval_channel="C_APPROVALS",
    )
    with pytest.raises(slack_bot.SlackError, match="no slack_user_id known"):
        slack_bot.post_mfa_step_up_nudge(
            user_id="email:alice@example.com",
            slack_user_id=None,
            request_id="req-7f3a",
            config=cfg,
        )
