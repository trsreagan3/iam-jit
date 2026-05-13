"""Chat resume + session-loss resilience.

Covers the F24 scenarios:
  - user posts a chat turn → server saves a draft
  - user reloads /requests/new/chat → "resume previous draft?" banner
  - user clicks resume → conversation rehydrates with prior history
  - cross-user isolation: dev can't resume admin's draft via ?resume=
  - draft TTL: stale drafts (>4h) don't show the resume banner
  - logged-out chat POST returns 401 (so the page JS can redirect)
"""

from __future__ import annotations

import datetime as _dt

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


@pytest.fixture(autouse=True)
def reset_drafts() -> None:
    from iam_jit import intake_drafts

    intake_drafts.reset_default_store_for_tests()


@pytest.fixture(autouse=True)
def force_ai_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """The chat surface only renders when review.is_review_enabled() —
    flip it on for these tests so the routes don't redirect to /paste."""
    from iam_jit import review

    monkeypatch.setattr(review, "is_review_enabled", lambda: True)


@pytest.fixture
def stub_take_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the LLM call deterministic and instant."""
    from iam_jit import intake as intake_mod

    def _stub(history, backend):
        return intake_mod.IntakeTurn(
            ask="ok, what AWS account is this for?",
            complete=False,
            fields={},
        )

    monkeypatch.setattr(intake_mod, "take_turn", _stub)


def test_chat_post_saves_draft(
    as_dev: TestClient, stub_take_turn: None
) -> None:
    """Posting to /requests/new/chat persists a server-side draft."""
    # First seed a token by GET-ing the page.
    resp = as_dev.get("/requests/new/chat")
    assert resp.status_code == 200
    assert "available_draft" not in resp.text or "Resume your last" not in resp.text

    # Now post a message.
    resp = as_dev.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "I need s3 access in dev"},
    )
    assert resp.status_code == 200

    # Draft should be queryable.
    from iam_jit import intake_drafts

    store = intake_drafts.get_default_store()
    draft = store.get_most_recent("email:dev@example.com")
    assert draft is not None
    # First message + assistant ask = 2 messages.
    assert len(draft.history) >= 2
    user_messages = [m for m in draft.history if m["role"] == "user"]
    assert any("s3 access" in m["content"] for m in user_messages)


def test_chat_get_offers_resume_when_draft_exists(
    as_dev: TestClient, stub_take_turn: None
) -> None:
    """After a draft exists, GET /requests/new/chat surfaces the
    resume prompt in the rendered HTML."""
    # Create a draft.
    as_dev.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "draft seeding message"},
    )
    # Subsequent GET shows the resume banner.
    body = as_dev.get("/requests/new/chat").text
    assert "Resume your last draft" in body
    assert "resume=drft-" in body or "resume=" in body


def test_chat_get_with_resume_param_rehydrates_conversation(
    as_dev: TestClient, stub_take_turn: None
) -> None:
    as_dev.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "rehydrate me — read s3 in dev"},
    )
    from iam_jit import intake_drafts

    draft = intake_drafts.get_default_store().get_most_recent(
        "email:dev@example.com"
    )
    assert draft is not None

    body = as_dev.get(f"/requests/new/chat?resume={draft.draft_id}").text
    assert "rehydrate me" in body
    assert "Picking up where you left off" in body


def test_chat_resume_param_for_other_user_is_ignored(
    as_dev: TestClient, as_dev2: TestClient, stub_take_turn: None
) -> None:
    """Cross-user isolation: dev can't resume dev2's draft."""
    as_dev2.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "this belongs to dev2"},
    )
    from iam_jit import intake_drafts

    draft = intake_drafts.get_default_store().get_most_recent(
        "email:dev2@example.com"
    )
    assert draft is not None

    body = as_dev.get(f"/requests/new/chat?resume={draft.draft_id}").text
    # dev does NOT see dev2's content.
    assert "this belongs to dev2" not in body
    # And the resume banner shouldn't claim there's a draft to resume.
    assert "Picking up where you left off" not in body


def test_expired_drafts_do_not_offer_resume(
    as_dev: TestClient, stub_take_turn: None
) -> None:
    as_dev.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "old draft"},
    )
    from iam_jit import intake_drafts

    store = intake_drafts.get_default_store()
    draft = store.get_most_recent("email:dev@example.com")
    assert draft is not None
    # Backdate to make it expired.
    draft.last_updated_at = "2020-01-01T00:00:00Z"

    body = as_dev.get("/requests/new/chat").text
    assert "Resume your last draft" not in body


def test_chat_stream_returns_401_when_logged_out(
    client: TestClient,
) -> None:
    """The SSE endpoint must return 401 (not 303 redirect) so the
    client-side JS can detect session expiry and redirect."""
    resp = client.post(
        "/requests/new/chat/stream",
        data={"conversation": "", "message": "hi"},
    )
    assert resp.status_code == 401


def test_chat_get_redirects_to_login_when_logged_out(
    client: TestClient,
) -> None:
    """The HTML chat page redirects to /login (preserving return_to)
    so the user lands back on chat after re-auth."""
    resp = client.get("/requests/new/chat", follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]
    assert "return_to" in resp.headers["location"]


def test_resume_param_with_unknown_id_falls_through_to_fresh_chat(
    as_dev: TestClient, stub_take_turn: None
) -> None:
    """A bogus ?resume=X shouldn't 500 — it just shows fresh chat."""
    resp = as_dev.get("/requests/new/chat?resume=drft-totallynotreal")
    assert resp.status_code == 200
    assert "What can I help you access?" in resp.text


def test_chat_draft_carries_parse_error_count(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the model returned a parse error, the draft should remember
    that so the resume flow doesn't reset the error counter."""
    from iam_jit import intake as intake_mod

    def _stub_err(history, backend):
        return intake_mod.IntakeTurn(
            ask=None, complete=False, error="llm_parse_error", fields={}
        )

    monkeypatch.setattr(intake_mod, "take_turn", _stub_err)
    as_dev.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "first try"},
    )
    from iam_jit import intake_drafts

    draft = intake_drafts.get_default_store().get_most_recent(
        "email:dev@example.com"
    )
    assert draft is not None
    assert draft.parse_error_count == 1
