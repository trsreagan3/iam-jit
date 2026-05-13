"""Web + API routes for the conversational intake."""

from __future__ import annotations

import html
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def _extract_token(body: str) -> str:
    """Pull the conversation token from a rendered chat page.

    The signed token contains the raw JSON payload (itsdangerous
    appends, doesn't base64), so Jinja HTML-escapes apostrophes etc.
    inside the value attribute. Unescape so the token re-posts cleanly.
    """
    start = body.find('name="conversation" value="') + len('name="conversation" value="')
    end = body.find('"', start)
    return html.unescape(body[start:end])


class _StubBackend:
    name = "stub"

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)

    def refine(self, **kw: Any) -> Any:
        return [], []

    def chat(self, *, system_prompt: str, messages: list[dict[str, str]]) -> str:
        if not self.responses:
            return ""
        return self.responses.pop(0)


@pytest.fixture
def stub_backend(monkeypatch: pytest.MonkeyPatch):
    """Replace iam_jit.llm.get_backend with one returning a fresh stub."""
    from iam_jit import llm

    holder = {"backend": None}

    def factory() -> Any:
        return holder["backend"]

    monkeypatch.setattr(llm, "get_backend", factory)
    monkeypatch.setattr(
        "iam_jit.review.is_review_enabled", lambda: True
    )
    return holder


# ---- API ----


def test_api_intake_turn_requires_auth(client: TestClient) -> None:
    r = client.post("/api/v1/intake/turn", json={"conversation": []})
    assert r.status_code == 401


def test_api_intake_turn_returns_question(
    as_dev: TestClient, stub_backend
) -> None:
    stub_backend["backend"] = _StubBackend(
        [json.dumps({"ask": "Which account?", "fields": {}, "complete": False})]
    )
    r = as_dev.post(
        "/api/v1/intake/turn",
        json={"conversation": [{"role": "user", "content": "I need s3 access"}]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ask"] == "Which account?"
    assert body["complete"] is False
    assert body["prefill"] is None


def test_api_intake_turn_validates_role_field(
    as_dev: TestClient, stub_backend
) -> None:
    stub_backend["backend"] = _StubBackend(
        [json.dumps({"ask": "x", "fields": {}, "complete": False})]
    )
    r = as_dev.post(
        "/api/v1/intake/turn",
        json={"conversation": [{"role": "system", "content": "x"}]},
    )
    assert r.status_code == 422


def test_api_intake_complete_returns_prefill(
    as_dev: TestClient, stub_backend
) -> None:
    stub_backend["backend"] = _StubBackend(
        [
            json.dumps(
                {
                    "ask": None,
                    "fields": {
                        "account_id": "123456789012",
                        "region": "us-east-1",
                        "services": ["s3"],
                        "access_type": "read-only",
                        "duration_hours": 24,
                        "description": "Read configs",
                    },
                    "complete": True,
                    "draft_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:GetObject"],
                                "Resource": "arn:aws:s3:::example",
                            }
                        ],
                    },
                }
            )
        ]
    )
    r = as_dev.post(
        "/api/v1/intake/turn",
        json={
            "conversation": [
                {"role": "assistant", "content": "What account?"},
                {"role": "user", "content": "123456789012, us-east-1, 24h, read-only"},
            ]
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["complete"] is True
    assert body["prefill"]["accounts"] == "123456789012"
    assert "s3:GetObject" in body["prefill"]["policy"]


# ---- Web ----


def test_web_chat_redirects_when_no_ai(as_dev: TestClient) -> None:
    # No `with_llm` fixture here — review.is_review_enabled() returns False.
    r = as_dev.get("/requests/new/chat", follow_redirects=False)
    assert r.status_code == 303
    assert "/paste" in r.headers["location"]


def test_web_chat_renders_opening_question(
    as_dev: TestClient, stub_backend
) -> None:
    stub_backend["backend"] = _StubBackend(
        [json.dumps({"ask": "What can I help you access?", "fields": {}, "complete": False})]
    )
    r = as_dev.get("/requests/new/chat")
    assert r.status_code == 200
    assert "What can I help you access?" in r.text


def test_web_chat_post_renders_followup(
    as_dev: TestClient, stub_backend
) -> None:
    # GET uses a hardcoded opener — no LLM call. Only the POST hits the
    # backend. So we only need ONE stubbed response.
    stub_backend["backend"] = _StubBackend(
        [
            json.dumps({"ask": "Which account?", "fields": {"services": ["s3"]}, "complete": False}),
        ]
    )
    r = as_dev.get("/requests/new/chat")
    body = r.text
    token = _extract_token(body)
    follow = as_dev.post(
        "/requests/new/chat",
        data={"conversation": token, "message": "I want to read s3"},
    )
    assert follow.status_code == 200
    assert "Which account?" in follow.text


def test_web_chat_initial_get_does_not_call_llm(
    as_dev: TestClient, stub_backend
) -> None:
    """The opener is hardcoded — landing on /chat must not hit the LLM.

    Otherwise a slow/unreachable model produces a confusing
    'llm_parse_error' banner before the user has typed anything.
    """
    # Empty stub: any LLM call would return "" and trigger the parse-error
    # path. The test would render that banner.
    stub_backend["backend"] = _StubBackend([])
    r = as_dev.get("/requests/new/chat")
    assert r.status_code == 200
    assert "llm_parse_error" not in r.text
    assert "I couldn't follow that" not in r.text
    # Static greeting must always render so the user can start typing.
    assert "What can I help you access?" in r.text


def test_web_chat_redirects_to_login_when_unauthenticated(
    client: TestClient, stub_backend
) -> None:
    stub_backend["backend"] = _StubBackend(
        [json.dumps({"ask": "x", "fields": {}, "complete": False})]
    )
    r = client.get("/requests/new/chat", follow_redirects=False)
    assert r.status_code == 303
    # The chat page now passes return_to through to /login so the user
    # lands back on chat after sign-in. The base path is still /login.
    assert r.headers["location"].startswith("/login")
    assert "return_to=/requests/new/chat" in r.headers["location"]


def test_requests_new_chooser_redirects_to_chat_when_ai_enabled(
    as_dev: TestClient, stub_backend
) -> None:
    stub_backend["backend"] = _StubBackend(
        [json.dumps({"ask": "x", "fields": {}, "complete": False})]
    )
    r = as_dev.get("/requests/new", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/requests/new/chat"


def test_chat_parse_error_renders_regenerate_button(
    as_dev: TestClient, stub_backend
) -> None:
    """When the LLM returns garbage, surface a regenerate button so the
    user isn't stuck."""
    stub_backend["backend"] = _StubBackend(["this is not json"])
    r = as_dev.get("/requests/new/chat")
    body = r.text
    token = _extract_token(body)
    follow = as_dev.post(
        "/requests/new/chat",
        data={"conversation": token, "message": "I want s3 access"},
    )
    assert follow.status_code == 200
    assert "regenerate" in follow.text.lower()
    # Switch-to-paste suggestion only appears after the SECOND failure.
    assert "switch to paste mode" not in follow.text


def test_chat_two_consecutive_parse_errors_suggest_paste_mode(
    as_dev: TestClient, stub_backend
) -> None:
    """After 2 consecutive parse errors, prominently surface paste mode."""
    stub_backend["backend"] = _StubBackend(["garbage 1", "garbage 2"])
    r = as_dev.get("/requests/new/chat")
    body = r.text
    token = _extract_token(body)
    # First failure
    f1 = as_dev.post(
        "/requests/new/chat",
        data={"conversation": token, "message": "I want s3"},
    )
    body = f1.text
    token = _extract_token(body)
    # Second failure (regenerate)
    f2 = as_dev.post(
        "/requests/new/chat",
        data={"conversation": token, "regenerate": "1"},
    )
    assert "switch to paste mode" in f2.text.lower()
    assert "/requests/new/paste" in f2.text


def test_chat_regenerate_drops_trailing_assistant_turn(
    as_dev: TestClient, stub_backend
) -> None:
    """Regenerate must replay the same user message, not echo a stale
    assistant question. Tests that the last assistant turn is dropped
    before re-running take_turn."""
    stub_backend["backend"] = _StubBackend(
        [
            # First normal call returns an ask
            json.dumps({"ask": "Which account?", "fields": {}, "complete": False}),
            # After regenerate, we expect a SECOND call. If the trailing
            # assistant turn was kept, the model would see it as history
            # and likely respond differently. With the drop, the LLM sees
            # the same input as the first call and is free to retry.
            json.dumps({"ask": "Which AWS account?", "fields": {}, "complete": False}),
        ]
    )
    r = as_dev.get("/requests/new/chat")
    body = r.text
    token = _extract_token(body)
    f1 = as_dev.post(
        "/requests/new/chat",
        data={"conversation": token, "message": "I want s3"},
    )
    assert "Which account?" in f1.text
    body = f1.text
    token = _extract_token(body)
    f2 = as_dev.post(
        "/requests/new/chat",
        data={"conversation": token, "regenerate": "1"},
    )
    # New question rendered (not the stale one twice).
    assert "Which AWS account?" in f2.text


def test_requests_new_chooser_renders_when_ai_disabled(as_dev: TestClient) -> None:
    r = as_dev.get("/requests/new")
    assert r.status_code == 200
    assert "Generate a new role" in r.text or "Paste a role" in r.text
