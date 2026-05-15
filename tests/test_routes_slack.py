"""Integration tests for the Slack interactive-callback route.

Covers the full POST /api/v1/slack/interactive flow through FastAPI:
  - 503 when Slack config isn't on the deployment
  - 401 on bad signature / expired timestamp
  - 400 on malformed body / payload
  - Ephemeral error message when clicker is not an approver
  - Ephemeral error when Slack user can't be mapped to iam-jit User
  - Happy path: approver clicks → state transitions → channel
    message gets the completion-message replacement payload
  - Idempotent / race-safe: clicking after another approver already
    acted returns a clean error, not a 500
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit import slack_bot

pytest_plugins = ["tests.conftest_routes"]


_SIGNING_SECRET = "route-test-signing-secret"
_BOT_TOKEN = "xoxb-route-test"
_CHANNEL = "C-test-approvals"


def _sign(body: bytes, ts: str | None = None) -> tuple[str, str]:
    ts = ts if ts is not None else str(int(time.time()))
    base = f"v0:{ts}:".encode("utf-8") + body
    sig = "v0=" + hmac.new(_SIGNING_SECRET.encode(), base, hashlib.sha256).hexdigest()
    return ts, sig


def _form_body(payload: dict[str, Any]) -> bytes:
    """Build a Slack-format form-urlencoded body from a payload dict."""
    from urllib.parse import urlencode

    return urlencode({"payload": json.dumps(payload)}).encode("utf-8")


def _payload(
    *,
    verb: str = "approve",
    request_id: str = "rq-test",
    slack_user_id: str = "U-APPROVER",
    slack_username: str = "approver",
) -> dict[str, Any]:
    return {
        "type": "block_actions",
        "user": {"id": slack_user_id, "username": slack_username, "name": slack_username},
        "actions": [{"action_id": f"iamjit_{verb}", "value": f"{verb}:{request_id}"}],
        "response_url": "https://hooks.slack.com/actions/x",
        "trigger_id": "trig-x",
    }


@pytest.fixture
def slack_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_SLACK_BOT_TOKEN", _BOT_TOKEN)
    monkeypatch.setenv("IAM_JIT_SLACK_SIGNING_SECRET", _SIGNING_SECRET)
    monkeypatch.setenv("IAM_JIT_SLACK_APPROVAL_CHANNEL", _CHANNEL)


@pytest.fixture
def slack_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_SLACK_BOT_TOKEN", raising=False)
    monkeypatch.delenv("IAM_JIT_SLACK_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("IAM_JIT_SLACK_APPROVAL_CHANNEL", raising=False)


@pytest.fixture
def stub_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace ApproverResolver.resolve with a deterministic stub
    that maps Slack user IDs → fake Users without calling Slack."""

    from iam_jit.users_store import User

    def _fake_resolve(self, slack_user_id: str):
        if slack_user_id == "U-APPROVER":
            return User(id="email:approver@example.com", roles=("approver",))
        if slack_user_id == "U-ADMIN":
            return User(id="email:admin@example.com", roles=("admin",))
        if slack_user_id == "U-REQUESTER":
            raise slack_bot.UserNotApprover("requester is not an approver")
        if slack_user_id == "U-DISABLED":
            raise slack_bot.UserNotApprover("user disabled")
        if slack_user_id == "U-UNMAPPED":
            raise slack_bot.SlackUserUnresolvable("no matching user")
        raise slack_bot.SlackUserUnresolvable(f"unknown {slack_user_id}")

    monkeypatch.setattr(slack_bot.ApproverResolver, "resolve", _fake_resolve)


@pytest.fixture
def pending_request_factory(shared_app, make_client):
    """Factory that creates a pending request via the real submit
    API so the schema-validated, fully-stamped request lands in the
    store the same way a production request would."""

    counter = {"n": 0}

    def _make() -> str:
        counter["n"] += 1
        suffix = counter["n"]
        dev = make_client("email:dev@example.com")
        payload = {
            "apiVersion": "iam-jit.dev/v1alpha1",
            "kind": "RoleRequest",
            "metadata": {
                "requester": {
                    "name": "Dev",
                    "email": "dev@example.com",
                    "principal_arn": "arn:aws:iam::060392206767:user/dev",
                },
            },
            "spec": {
                "description": f"slack-test #{suffix}",
                "access_type": "read-only",
                "task_intent": {"services": ["s3"], "actions": ["read"]},
                "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
                "duration": {"duration_hours": 1},
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": "arn:aws:s3:::example",
                        }
                    ],
                },
                "provisioning": {"mode": "classic_iam"},
            },
        }
        resp = dev.post("/api/v1/requests", json=payload)
        assert resp.status_code == 201, resp.text
        return resp.json()["request"]["metadata"]["id"]

    return _make


# ---------------------------------------------------------------------------
# Config-not-set behavior.
# ---------------------------------------------------------------------------


def test_503_when_slack_not_configured(client: TestClient, slack_env_unset) -> None:
    """Without env vars set, the route must return 503 — not 500."""
    body = _form_body(_payload())
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Signature verification.
# ---------------------------------------------------------------------------


def test_401_on_missing_signature(client: TestClient, slack_env) -> None:
    body = _form_body(_payload())
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 401


def test_401_on_wrong_signature(client: TestClient, slack_env) -> None:
    body = _form_body(_payload())
    ts = str(int(time.time()))
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": "v0=" + "0" * 64,
        },
    )
    assert resp.status_code == 401


def test_401_on_old_timestamp(client: TestClient, slack_env) -> None:
    body = _form_body(_payload())
    old_ts = str(int(time.time()) - 3600)
    _, sig = _sign(body, ts=old_ts)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": old_ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 401


def test_401_on_body_tampering(client: TestClient, slack_env) -> None:
    """A valid sig over a different body must be rejected."""
    legitimate = _form_body(_payload(request_id="rq-A"))
    ts, sig = _sign(legitimate)
    tampered = _form_body(_payload(request_id="rq-B"))
    resp = client.post(
        "/api/v1/slack/interactive",
        content=tampered,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Payload parsing.
# ---------------------------------------------------------------------------


def test_400_on_missing_payload_field(client: TestClient, slack_env) -> None:
    body = b"not_payload=foo"
    ts, sig = _sign(body)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 400


def test_400_on_malformed_payload(client: TestClient, slack_env) -> None:
    """payload is present but not a Slack interactive shape."""
    from urllib.parse import urlencode

    body = urlencode({"payload": "this is not json"}).encode("utf-8")
    ts, sig = _sign(body)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 400


def test_400_on_unknown_verb(client: TestClient, slack_env) -> None:
    """Smuggling in `delete:RQ` shouldn't even pass the parser."""
    payload = _payload()
    payload["actions"][0]["value"] = "delete:rq-X"
    body = _form_body(payload)
    ts, sig = _sign(body)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Authorization.
# ---------------------------------------------------------------------------


def test_ephemeral_reply_when_clicker_not_approver(
    client: TestClient, slack_env, stub_resolver, pending_request_factory
) -> None:
    rid = pending_request_factory()
    payload = _payload(slack_user_id="U-REQUESTER", request_id=rid)
    body = _form_body(payload)
    ts, sig = _sign(body)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 200
    body_json = resp.json()
    assert body_json["response_type"] == "ephemeral"
    assert "approver" in body_json["text"].lower()


def test_ephemeral_reply_when_slack_user_unmapped(
    client: TestClient, slack_env, stub_resolver, pending_request_factory
) -> None:
    rid = pending_request_factory()
    payload = _payload(slack_user_id="U-UNMAPPED", request_id=rid)
    body = _form_body(payload)
    ts, sig = _sign(body)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 200
    body_json = resp.json()
    assert body_json["response_type"] == "ephemeral"
    assert "mapped" in body_json["text"].lower() or "register" in body_json["text"].lower()


# ---------------------------------------------------------------------------
# Happy path.
# ---------------------------------------------------------------------------


def test_approver_clicks_approve_transitions_state(
    shared_app, client: TestClient, slack_env, stub_resolver, pending_request_factory
) -> None:
    rid = pending_request_factory()
    payload = _payload(verb="approve", slack_user_id="U-APPROVER", request_id=rid)
    body = _form_body(payload)
    ts, sig = _sign(body)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 200
    body_json = resp.json()
    assert body_json["replace_original"] is True
    assert "approved" in body_json["text"].lower()
    # Persisted state moved to provisioning (the approve transition target).
    req = shared_app.state.request_store.get(rid)
    assert req["status"]["state"] == "provisioning"
    # Audit history captured Slack as the channel. `extra` keys are
    # MERGED into the event at the top level by lifecycle._commit.
    history = req["status"]["history"]
    last = history[-1]
    assert last["action"] == "approve"
    assert last.get("channel") == "slack"
    assert last.get("slack_user_id") == "U-APPROVER"


def test_approver_clicks_reject_transitions_state(
    shared_app, client: TestClient, slack_env, stub_resolver, pending_request_factory
) -> None:
    rid = pending_request_factory()
    payload = _payload(verb="reject", slack_user_id="U-APPROVER", request_id=rid)
    body = _form_body(payload)
    ts, sig = _sign(body)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 200
    body_json = resp.json()
    assert "rejected" in body_json["text"].lower()
    req = shared_app.state.request_store.get(rid)
    assert req["status"]["state"] == "rejected"


def test_admin_can_also_approve(
    shared_app, client: TestClient, slack_env, stub_resolver, pending_request_factory
) -> None:
    rid = pending_request_factory()
    payload = _payload(slack_user_id="U-ADMIN", request_id=rid)
    body = _form_body(payload)
    ts, sig = _sign(body)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 200
    req = shared_app.state.request_store.get(rid)
    assert req["status"]["state"] == "provisioning"


# ---------------------------------------------------------------------------
# Idempotency / races.
# ---------------------------------------------------------------------------


def test_second_click_on_already_approved_returns_clean_message(
    shared_app, client: TestClient, slack_env, stub_resolver, pending_request_factory
) -> None:
    rid = pending_request_factory()
    payload = _payload(verb="approve", slack_user_id="U-APPROVER", request_id=rid)
    body = _form_body(payload)
    ts, sig = _sign(body)
    # First click — succeeds.
    resp1 = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp1.status_code == 200

    # Second click — same payload, re-signed in a new envelope to
    # avoid timestamp-replay rejection.
    ts2, sig2 = _sign(body)
    resp2 = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts2,
            "x-slack-signature": sig2,
        },
    )
    # Not a 500 — returns a clean ephemeral reply.
    assert resp2.status_code == 200
    body_json = resp2.json()
    assert body_json.get("response_type") == "ephemeral"
    assert "couldn't" in body_json["text"].lower() or "already" in body_json["text"].lower()


def test_404_request_returns_clean_message(
    client: TestClient, slack_env, stub_resolver
) -> None:
    """If the request_id in the action value doesn't exist (cancelled,
    typo'd, expired), respond with an ephemeral message — not 500."""
    payload = _payload(slack_user_id="U-APPROVER", request_id="rq-never-existed")
    body = _form_body(payload)
    ts, sig = _sign(body)
    resp = client.post(
        "/api/v1/slack/interactive",
        content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": sig,
        },
    )
    assert resp.status_code == 200
    body_json = resp.json()
    assert body_json.get("response_type") == "ephemeral"
    assert "not found" in body_json["text"].lower() or "expired" in body_json["text"].lower()
