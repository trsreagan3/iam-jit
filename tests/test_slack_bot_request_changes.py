"""Slack 'Request changes' (modal-based "add context and rerun") tests.

The request_changes flow:
  1. Approver clicks the "Request changes" button on the approval card
  2. iam-jit calls views.open to display a modal asking for the message
  3. Approver fills in the textarea + submits the modal
  4. Slack POSTs a view_submission to /api/v1/slack/interactive
  5. iam-jit verifies + transitions pending → needs_changes with the
     approver's text as the transition reason

These tests focus on:
  - Modal definition: correct private_metadata, callback_id, fields
  - Parse view_submission: rejects malformed shapes, malicious payloads,
    too-short / too-long text, wrong callback_id, missing
    private_metadata
  - Button click → views.open is invoked with auth check FIRST
  - Modal submission → state transition + audit captured
  - Non-approver clicks button → no modal opens
  - Non-approver submits modal somehow → rejected with `errors` response
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import pytest

from iam_jit import slack_bot


_SIGNING_SECRET = "view-test-signing-secret"
_BOT_TOKEN = "xoxb-view-test"
_CHANNEL = "C-view-test"


# ---------------------------------------------------------------------------
# Modal rendering.
# ---------------------------------------------------------------------------


class TestRenderRequestChangesModal:
    def test_basic_shape(self) -> None:
        modal = slack_bot.render_request_changes_modal("rq-abc")
        assert modal["type"] == "modal"
        assert modal["callback_id"] == "iamjit_request_changes_modal"
        assert modal["private_metadata"] == "rq-abc"
        # Has a submit + close button.
        assert "submit" in modal and "close" in modal

    def test_has_text_input(self) -> None:
        modal = slack_bot.render_request_changes_modal("rq-x")
        input_block = next(b for b in modal["blocks"] if b.get("type") == "input")
        elem = input_block["element"]
        assert elem["type"] == "plain_text_input"
        assert elem["action_id"] == "context_text"
        assert elem["multiline"] is True
        assert elem["max_length"] == 2000

    def test_request_id_appears_in_text(self) -> None:
        modal = slack_bot.render_request_changes_modal("rq-SHOWN")
        text_blocks_text = json.dumps(modal["blocks"])
        assert "rq-SHOWN" in text_blocks_text


# ---------------------------------------------------------------------------
# parse_view_submission.
# ---------------------------------------------------------------------------


def _build_view_submission_payload(
    *,
    text: str = "Tighten S3 to a single bucket prefix.",
    request_id: str = "rq-vsub",
    callback_id: str = "iamjit_request_changes_modal",
    user_id: str = "U-APPROVER",
    block_id: str = "context_block",
) -> str:
    return json.dumps(
        {
            "type": "view_submission",
            "user": {"id": user_id, "username": "approver", "name": "approver"},
            "view": {
                "callback_id": callback_id,
                "private_metadata": request_id,
                "state": {
                    "values": {
                        block_id: {
                            "context_text": {
                                "type": "plain_text_input",
                                "value": text,
                            }
                        }
                    }
                },
            },
        }
    )


class TestParseViewSubmission:
    def test_happy_path(self) -> None:
        payload = _build_view_submission_payload()
        vs = slack_bot.parse_view_submission(payload)
        assert vs.callback_id == "iamjit_request_changes_modal"
        assert vs.request_id == "rq-vsub"
        assert vs.submitter_slack_user_id == "U-APPROVER"
        assert "S3" in vs.text

    def test_non_view_submission_type_rejected(self) -> None:
        payload = json.dumps({"type": "block_actions", "user": {"id": "U-X"}})
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_view_submission(payload)

    def test_wrong_callback_id_rejected(self) -> None:
        """An attacker can't open ANY modal and have us treat it
        as a request_changes submission."""
        payload = _build_view_submission_payload(
            callback_id="some_other_modal"
        )
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_view_submission(payload)

    def test_missing_private_metadata_rejected(self) -> None:
        payload = json.dumps(
            {
                "type": "view_submission",
                "user": {"id": "U-X"},
                "view": {
                    "callback_id": "iamjit_request_changes_modal",
                    "private_metadata": "",
                    "state": {"values": {}},
                },
            }
        )
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_view_submission(payload)

    def test_text_too_short_rejected(self) -> None:
        payload = _build_view_submission_payload(text="ok")
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_view_submission(payload)

    def test_text_too_long_truncated(self) -> None:
        payload = _build_view_submission_payload(text="x" * 5000)
        vs = slack_bot.parse_view_submission(payload)
        assert len(vs.text) == 2000  # truncated to max_length

    def test_text_whitespace_stripped_before_min_length_check(self) -> None:
        """An attacker submitting "    " (5 spaces) shouldn't pass
        the min-length check by gaming whitespace."""
        payload = _build_view_submission_payload(text="     ")
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_view_submission(payload)

    def test_payload_xss_attempt_passes_through_safely(self) -> None:
        """The modal text is captured as the audit reason. We don't
        execute it — we just store and display it. But verify the
        payload that contains script-tag-like text still parses
        cleanly without mangling."""
        text = "<script>alert(1)</script>; DROP TABLE users; --"
        payload = _build_view_submission_payload(text=text)
        vs = slack_bot.parse_view_submission(payload)
        assert vs.text == text

    def test_missing_user_id_rejected(self) -> None:
        payload = json.dumps(
            {
                "type": "view_submission",
                "user": {"username": "no-id"},
                "view": {
                    "callback_id": "iamjit_request_changes_modal",
                    "private_metadata": "rq",
                    "state": {
                        "values": {
                            "context_block": {
                                "context_text": {
                                    "type": "plain_text_input",
                                    "value": "abcdefghij",
                                }
                            }
                        }
                    },
                },
            }
        )
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_view_submission(payload)

    def test_invalid_json_rejected(self) -> None:
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_view_submission("{not json")

    def test_empty_state_values_rejected(self) -> None:
        """If Slack sent us a view with no text field at all,
        we should reject — not silently treat as ''."""
        payload = json.dumps(
            {
                "type": "view_submission",
                "user": {"id": "U-X"},
                "view": {
                    "callback_id": "iamjit_request_changes_modal",
                    "private_metadata": "rq",
                    "state": {"values": {}},
                },
            }
        )
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_view_submission(payload)


# ---------------------------------------------------------------------------
# Approval message now has THREE buttons.
# ---------------------------------------------------------------------------


class TestApprovalCardHasRequestChangesButton:
    def test_three_action_buttons_present(self) -> None:
        body = slack_bot.render_approval_message(
            {"id": "rq-three"}, deployment_url=None
        )
        actions_block = next(b for b in body["blocks"] if b.get("type") == "actions")
        values = [b.get("value") for b in actions_block["elements"] if "value" in b]
        assert "approve:rq-three" in values
        assert "reject:rq-three" in values
        assert "request_changes:rq-three" in values

    def test_parse_interactive_payload_accepts_request_changes(self) -> None:
        payload = json.dumps(
            {
                "type": "block_actions",
                "user": {"id": "U-X", "username": "approver"},
                "actions": [
                    {"action_id": "iamjit_request_changes",
                     "value": "request_changes:rq-RC"}
                ],
                "response_url": "https://hooks.slack.com/x",
                "trigger_id": "trig-RC",
            }
        )
        action = slack_bot.parse_interactive_payload(payload)
        assert action.verb == "request_changes"
        assert action.request_id == "rq-RC"
        assert action.trigger_id == "trig-RC"


# ---------------------------------------------------------------------------
# open_modal.
# ---------------------------------------------------------------------------


class _StubClient:
    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.response = response or {"ok": True, "view": {"id": "V-stub"}}
        self.calls: list[dict[str, Any]] = []

    def post_json(self, url, *, headers, json_body):
        self.calls.append({"url": url, "headers": headers, "body": json_body})
        return self.response

    def get_user_info(self, user_id, *, bot_token):
        raise NotImplementedError


_CFG = slack_bot.SlackConfig(
    bot_token=_BOT_TOKEN, signing_secret=_SIGNING_SECRET, approval_channel=_CHANNEL,
)


class TestOpenModal:
    def test_calls_views_open_with_trigger_id(self) -> None:
        stub = _StubClient()
        view = slack_bot.render_request_changes_modal("rq-OM")
        slack_bot.open_modal(
            trigger_id="trig-from-button", view=view,
            config=_CFG, client=stub,
        )
        assert len(stub.calls) == 1
        call = stub.calls[0]
        assert call["url"].endswith("/views.open")
        assert call["body"]["trigger_id"] == "trig-from-button"
        assert call["body"]["view"]["callback_id"] == "iamjit_request_changes_modal"

    def test_views_open_not_ok_raises(self) -> None:
        stub = _StubClient(response={"ok": False, "error": "trigger_expired"})
        view = slack_bot.render_request_changes_modal("rq-OM2")
        with pytest.raises(slack_bot.SlackError) as exc:
            slack_bot.open_modal(
                trigger_id="x", view=view, config=_CFG, client=stub,
            )
        assert "trigger_expired" in str(exc.value)


# ---------------------------------------------------------------------------
# Route-level: button click → views.open; modal submission → transition.
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def _sign(body: bytes, ts: str | None = None) -> tuple[str, str]:
    ts = ts if ts is not None else str(int(time.time()))
    base = f"v0:{ts}:".encode("utf-8") + body
    sig = "v0=" + hmac.new(_SIGNING_SECRET.encode(), base, hashlib.sha256).hexdigest()
    return ts, sig


def _form_body(payload: dict[str, Any]) -> bytes:
    from urllib.parse import urlencode

    return urlencode({"payload": json.dumps(payload)}).encode("utf-8")


@pytest.fixture
def slack_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_SLACK_BOT_TOKEN", _BOT_TOKEN)
    monkeypatch.setenv("IAM_JIT_SLACK_SIGNING_SECRET", _SIGNING_SECRET)
    monkeypatch.setenv("IAM_JIT_SLACK_APPROVAL_CHANNEL", _CHANNEL)


@pytest.fixture
def stub_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    from iam_jit.users_store import User

    def _fake_resolve(self, slack_user_id: str):
        if slack_user_id == "U-APPROVER":
            return User(id="email:approver@example.com", roles=("approver",))
        if slack_user_id == "U-REQUESTER":
            raise slack_bot.UserNotApprover("not approver")
        raise slack_bot.SlackUserUnresolvable("unknown")

    monkeypatch.setattr(slack_bot.ApproverResolver, "resolve", _fake_resolve)


@pytest.fixture
def stub_open_modal(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Track calls to open_modal without actually hitting Slack."""
    recorded: dict[str, Any] = {"calls": []}

    def _fake_open(*, trigger_id, view, config, client=None):
        recorded["calls"].append({"trigger_id": trigger_id, "view": view})
        return {"ok": True}

    monkeypatch.setattr(slack_bot, "open_modal", _fake_open)
    return recorded


@pytest.fixture
def pending_request_factory(shared_app, make_client):
    counter = {"n": 0}

    def _make() -> str:
        counter["n"] += 1
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
                "description": f"rc-test #{counter['n']}",
                "access_type": "read-only",
                "task_intent": {"services": ["s3"], "actions": ["read"]},
                "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
                "duration": {"duration_hours": 1},
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": ["s3:GetObject"],
                         "Resource": "arn:aws:s3:::ex"}
                    ],
                },
                "provisioning": {"mode": "classic_iam"},
            },
        }
        resp = dev.post("/api/v1/requests", json=payload)
        assert resp.status_code == 201
        return resp.json()["request"]["metadata"]["id"]

    return _make


def _button_payload(rid: str, slack_user_id: str = "U-APPROVER") -> dict[str, Any]:
    return {
        "type": "block_actions",
        "user": {"id": slack_user_id, "username": "approver"},
        "actions": [
            {"action_id": "iamjit_request_changes",
             "value": f"request_changes:{rid}"}
        ],
        "response_url": "https://hooks.slack.com/x",
        "trigger_id": "trig-button-click",
    }


def _modal_submit_payload(rid: str, text: str, slack_user_id: str = "U-APPROVER") -> dict[str, Any]:
    return {
        "type": "view_submission",
        "user": {"id": slack_user_id, "username": "approver"},
        "view": {
            "callback_id": "iamjit_request_changes_modal",
            "private_metadata": rid,
            "state": {
                "values": {
                    "context_block": {
                        "context_text": {
                            "type": "plain_text_input",
                            "value": text,
                        }
                    }
                }
            },
        },
    }


class TestRequestChangesEndToEnd:
    def test_button_click_opens_modal(
        self, client: TestClient, slack_env, stub_resolver, stub_open_modal,
        pending_request_factory
    ) -> None:
        rid = pending_request_factory()
        body = _form_body(_button_payload(rid))
        ts, sig = _sign(body)
        resp = client.post(
            "/api/v1/slack/interactive", content=body,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-slack-request-timestamp": ts,
                "x-slack-signature": sig,
            },
        )
        assert resp.status_code == 200
        # Modal was opened.
        assert len(stub_open_modal["calls"]) == 1
        assert stub_open_modal["calls"][0]["trigger_id"] == "trig-button-click"
        assert stub_open_modal["calls"][0]["view"]["private_metadata"] == rid

    def test_button_click_non_approver_no_modal(
        self, client: TestClient, slack_env, stub_resolver, stub_open_modal,
        pending_request_factory
    ) -> None:
        rid = pending_request_factory()
        body = _form_body(_button_payload(rid, slack_user_id="U-REQUESTER"))
        ts, sig = _sign(body)
        resp = client.post(
            "/api/v1/slack/interactive", content=body,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-slack-request-timestamp": ts,
                "x-slack-signature": sig,
            },
        )
        assert resp.status_code == 200
        body_json = resp.json()
        assert body_json["response_type"] == "ephemeral"
        # No modal opened.
        assert len(stub_open_modal["calls"]) == 0

    def test_modal_submission_transitions_state(
        self, shared_app, client: TestClient, slack_env, stub_resolver,
        pending_request_factory,
    ) -> None:
        rid = pending_request_factory()
        body = _form_body(
            _modal_submit_payload(
                rid, "Please tighten to a specific bucket prefix."
            )
        )
        ts, sig = _sign(body)
        resp = client.post(
            "/api/v1/slack/interactive", content=body,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-slack-request-timestamp": ts,
                "x-slack-signature": sig,
            },
        )
        assert resp.status_code == 200
        req = shared_app.state.request_store.get(rid)
        assert req["status"]["state"] == "needs_changes"
        # Audit captured approver's text as the transition reason.
        history = req["status"]["history"]
        last = history[-1]
        assert last["action"] == "request_changes"
        assert "tighten to a specific bucket prefix" in last.get("reason", "")
        assert last.get("channel") == "slack"

    def test_modal_submission_non_approver_rejected_with_errors(
        self, client: TestClient, slack_env, stub_resolver,
        pending_request_factory,
    ) -> None:
        """If somehow a non-approver POSTs a view_submission (e.g.
        attacker who knows about the callback_id), iam-jit must
        reject — returning Slack's `errors` shape so the modal
        shows the error inline rather than transitioning state."""
        rid = pending_request_factory()
        body = _form_body(
            _modal_submit_payload(rid, "x" * 10, slack_user_id="U-REQUESTER")
        )
        ts, sig = _sign(body)
        resp = client.post(
            "/api/v1/slack/interactive", content=body,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-slack-request-timestamp": ts,
                "x-slack-signature": sig,
            },
        )
        assert resp.status_code == 200
        body_json = resp.json()
        assert body_json.get("response_action") == "errors"
        assert "approver" in body_json["errors"]["context_block"].lower()

    def test_modal_submission_for_nonexistent_request_returns_errors(
        self, client: TestClient, slack_env, stub_resolver,
    ) -> None:
        body = _form_body(
            _modal_submit_payload(
                "rq-never-existed",
                "Please clarify the scope of the request.",
            )
        )
        ts, sig = _sign(body)
        resp = client.post(
            "/api/v1/slack/interactive", content=body,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-slack-request-timestamp": ts,
                "x-slack-signature": sig,
            },
        )
        assert resp.status_code == 200
        body_json = resp.json()
        assert body_json.get("response_action") == "errors"

    def test_modal_submission_after_already_approved_returns_errors(
        self, shared_app, client: TestClient, slack_env, stub_resolver,
        pending_request_factory,
    ) -> None:
        """After approve, the request is no longer in 'pending' so
        request_changes is an illegal transition. Return errors,
        not 500."""
        rid = pending_request_factory()
        # First: approver clicks Approve.
        approve_body = _form_body({
            "type": "block_actions",
            "user": {"id": "U-APPROVER", "username": "approver"},
            "actions": [
                {"action_id": "iamjit_approve", "value": f"approve:{rid}"}
            ],
            "response_url": "https://hooks.slack.com/x",
            "trigger_id": "trig-A",
        })
        ts, sig = _sign(approve_body)
        client.post(
            "/api/v1/slack/interactive", content=approve_body,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-slack-request-timestamp": ts,
                "x-slack-signature": sig,
            },
        )
        # Then: try to submit a "Request changes" modal for the same request.
        body = _form_body(
            _modal_submit_payload(rid, "Now I want to change my mind.")
        )
        ts2, sig2 = _sign(body)
        resp = client.post(
            "/api/v1/slack/interactive", content=body,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-slack-request-timestamp": ts2,
                "x-slack-signature": sig2,
            },
        )
        assert resp.status_code == 200
        body_json = resp.json()
        assert body_json.get("response_action") == "errors"

    def test_modal_text_with_malicious_content_captured_as_plain_text(
        self, shared_app, client: TestClient, slack_env, stub_resolver,
        pending_request_factory,
    ) -> None:
        """An approver's modal text is stored verbatim as the audit
        reason — we don't try to be a sanitizer. The downstream
        consumers (UI, audit log, JSON API) handle escaping at
        render time. We just verify here that nothing in the text
        causes us to misroute or crash."""
        rid = pending_request_factory()
        malicious = (
            "<script>alert(1)</script>"
            "'); DROP TABLE users; --"
            '{"injected": "json"}'
            "\x00\x1bNUL+ESC"
        )
        body = _form_body(_modal_submit_payload(rid, malicious))
        ts, sig = _sign(body)
        resp = client.post(
            "/api/v1/slack/interactive", content=body,
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "x-slack-request-timestamp": ts,
                "x-slack-signature": sig,
            },
        )
        assert resp.status_code == 200
        req = shared_app.state.request_store.get(rid)
        last = req["status"]["history"][-1]
        # Stored verbatim — the audit log is the right place for
        # escaping to happen at render time.
        assert "<script>" in last["reason"]
        assert req["status"]["state"] == "needs_changes"
