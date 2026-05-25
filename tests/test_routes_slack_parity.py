"""#596 — web /requests/new/paste must notify Slack approvers
identically to the API submit path.

PDF v2 build agent finding 2026-05-25: web paste-form submission
created the request but did NOT fire the Slack approval notification
that the API submit path fires. Silent parity gap of the same shape
as #560 / #594 / MRR-2 Pattern B per [[ibounce-honest-positioning]].

These tests assert OBSERVABLE state per docs/CONTRIBUTING.md — every
test checks what landed at the mock Slack server (POST captured,
JSON shape, channel) rather than just whether a Python function
returned a value.

Tests:
  1. Web paste-form submit fires Slack chat.postMessage when Slack
     env vars are configured.
  2. API submit path also fires chat.postMessage (regression — the
     pre-#596 behaviour must stay working).
  3. Both paths produce IDENTICAL Block Kit payloads (parity check —
     the [[cross-product-agent-parity]] discipline).
  4. Web paste with no Slack token — submit still succeeds; no POST
     to Slack; no crash (silent no-op is correct for "no Slack"
     deployments per [[ibounce-honest-positioning]]).
  5. API submit with no Slack token — same.
  6. Web paste when Slack POST fails — request is still created and
     persisted (notification failure must not break request creation
     per [[ibounce-honest-positioning]]).
  7. Sabotage check — monkeypatching the helper to a no-op makes
     test #1 fail. Proves the test is load-bearing on the real call
     path, not just spuriously green because the helper is wired
     through some other channel.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit import slack_bot
from iam_jit._test_support.slack_mock import MockSlackServer

pytest_plugins = ["tests.conftest_routes"]


_BOT_TOKEN = "xoxb-parity-test"
_SIGNING_SECRET = "parity-signing-secret"
_CHANNEL = "C-PARITY-APPROVALS"


@pytest.fixture
def mock_slack() -> MockSlackServer:
    """A fresh mock Slack server for each test."""
    return MockSlackServer.build()


@pytest.fixture
def mock_slack_client(mock_slack: MockSlackServer) -> TestClient:
    return TestClient(mock_slack.app)


@pytest.fixture
def route_slack_to_mock(
    mock_slack_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replace slack_bot.HttpxSlackClient so any outbound Slack call
    from the iam-jit submit handlers lands at the mock instead of
    real Slack.

    We do NOT change the route handlers themselves — they still call
    the shared `approval_notifier.notify_approvers_for_new_request`
    helper, which calls `slack_bot.post_approval_message`, which
    instantiates an HttpxSlackClient. By swapping that class at the
    module level, we exercise the REAL code path through to the
    HTTP client boundary and verify what would have hit the wire.
    """

    class _MockTransportSlackClient:
        name = "mock-transport"

        def post_json(
            self,
            url: str,
            *,
            headers: dict[str, str],
            json_body: dict[str, Any],
        ) -> dict[str, Any]:
            # Map https://slack.com/api/<endpoint> → /api/<endpoint>
            # on the mock TestClient.
            path = url.replace("https://slack.com", "")
            r = mock_slack_client.post(path, headers=headers, json=json_body)
            return r.json()

        def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]:
            r = mock_slack_client.get(
                "/api/users.info",
                params={"user": user_id},
                headers={"Authorization": f"Bearer {bot_token}"},
            )
            return r.json()

    monkeypatch.setattr(slack_bot, "HttpxSlackClient", _MockTransportSlackClient)


@pytest.fixture
def slack_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Slack configured for this test — both submit paths should
    fire chat.postMessage."""
    monkeypatch.setenv("IAM_JIT_SLACK_BOT_TOKEN", _BOT_TOKEN)
    monkeypatch.setenv("IAM_JIT_SLACK_SIGNING_SECRET", _SIGNING_SECRET)
    monkeypatch.setenv("IAM_JIT_SLACK_APPROVAL_CHANNEL", _CHANNEL)


@pytest.fixture
def slack_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Slack NOT configured — submit paths should succeed but post
    no message (silent no-op is the right behaviour)."""
    monkeypatch.delenv("IAM_JIT_SLACK_BOT_TOKEN", raising=False)
    monkeypatch.delenv("IAM_JIT_SLACK_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("IAM_JIT_SLACK_APPROVAL_CHANNEL", raising=False)


# ----- Payload helpers ---------------------------------------------------


_PASTE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::example-config",
            }
        ],
    }
)


def _paste_form_fields() -> dict[str, str]:
    """Form fields for POST /requests/new/paste — mirrors what the
    new_paste.html form would submit."""
    return {
        "description": "Read S3 config files for service X (web paste).",
        "policy": _PASTE_POLICY,
        "accounts": "060392206767",
        "duration_hours": "24",
        "access_type": "read-only",
        # principal_arn intentionally blank — handler infers from session
        # per #594 fix, just like a real human filling the form.
        "assume_principal_arn": "",
        "assume_session_name": "",
        "ticket": "",
    }


def _api_submit_payload() -> dict[str, Any]:
    """JSON body for POST /api/v1/requests — semantically equivalent
    to the web paste form so the two paths produce identical Block
    Kit cards (parity assertion)."""
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                "principal_arn": "arn:aws:iam::060392206767:user/dev@example.com",
            },
        },
        "spec": {
            "description": "Read S3 config files for service X (web paste).",
            "access_type": "read-only",
            "task_intent": {"services": ["s3"], "actions": ["read", "list"]},
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 24},
            "policy": json.loads(_PASTE_POLICY),
            "provisioning": {"mode": "identity_center"},
            "assume_by": {
                "principal_arn": "arn:aws:iam::060392206767:user/dev@example.com",
            },
        },
    }


# ----- Tests -------------------------------------------------------------


def test_web_paste_submit_triggers_slack_post_when_configured(
    as_dev: TestClient,
    mock_slack: MockSlackServer,
    route_slack_to_mock: None,
    slack_env: None,
) -> None:
    """#596 core fix — POSTing the web paste form must fire the
    Slack approval card just like the API path does."""
    resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(),
        follow_redirects=False,
    )
    # Form handler issues a 303 redirect to the new request's detail
    # page on success.
    assert resp.status_code == 303, resp.text
    posted = mock_slack.find_calls("/chat.postMessage")
    assert len(posted) == 1, (
        "web paste submit failed to post Slack approval card "
        f"(this is the #596 silent gap); calls={mock_slack.calls}"
    )
    call = posted[0]
    assert call.json_body["channel"] == _CHANNEL
    assert "blocks" in call.json_body
    # WB11-15: token is masked in the recorded call.
    assert call.bot_token == _BOT_TOKEN[:8] + "…"


def test_api_submit_triggers_slack_post_when_configured(
    as_dev: TestClient,
    mock_slack: MockSlackServer,
    route_slack_to_mock: None,
    slack_env: None,
) -> None:
    """Regression check — the pre-existing API submit path must
    still fire the Slack approval card after #596 refactored both
    paths through the shared helper."""
    resp = as_dev.post("/api/v1/requests", json=_api_submit_payload())
    assert resp.status_code in (200, 201), resp.text
    posted = mock_slack.find_calls("/chat.postMessage")
    assert len(posted) == 1
    call = posted[0]
    assert call.json_body["channel"] == _CHANNEL
    assert "blocks" in call.json_body


def test_web_paste_and_api_post_identical_block_kit(
    as_dev: TestClient,
    mock_slack: MockSlackServer,
    route_slack_to_mock: None,
    slack_env: None,
) -> None:
    """Parity assertion — both paths produce the same Block Kit
    payload shape per [[cross-product-agent-parity]]. The request
    bodies differ (the web form's description vs. the API
    description) but the structural fields the helper emits must
    match: same channel, same set of block types, same buttons.

    This is the test that would have caught #596 at write-time:
    if only one path fired, the lists would be unequal lengths.
    """
    # API path first.
    api_resp = as_dev.post("/api/v1/requests", json=_api_submit_payload())
    assert api_resp.status_code in (200, 201), api_resp.text
    # Web paste second.
    web_resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(),
        follow_redirects=False,
    )
    assert web_resp.status_code == 303, web_resp.text
    posted = mock_slack.find_calls("/chat.postMessage")
    assert len(posted) == 2, (
        "expected one chat.postMessage per submit path; got "
        f"{len(posted)}. The #596 silent gap would manifest as 1 here."
    )
    api_body, web_body = posted[0].json_body, posted[1].json_body
    # Same target channel.
    assert api_body["channel"] == web_body["channel"] == _CHANNEL
    # Same block-type sequence (semantic shape — the actual text
    # differs because the request descriptions differ, but the
    # structural template is identical).
    api_block_types = [b.get("type") for b in api_body.get("blocks", [])]
    web_block_types = [b.get("type") for b in web_body.get("blocks", [])]
    assert api_block_types == web_block_types, (
        "Block Kit structure diverges between API and web paths — "
        "[[cross-product-agent-parity]] violation. api="
        f"{api_block_types} web={web_block_types}"
    )
    # Same set of action button IDs (approve/reject/request-changes).
    def _action_ids(body: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for block in body.get("blocks", []):
            for el in block.get("elements", []) or []:
                aid = el.get("action_id")
                if aid:
                    out.append(aid)
        return sorted(out)

    assert _action_ids(api_body) == _action_ids(web_body), (
        "approval-card buttons differ between API and web paths — "
        "[[cross-product-agent-parity]] violation."
    )
    # Both must include unfurl suppression for clean rendering.
    assert api_body.get("unfurl_links") is False
    assert web_body.get("unfurl_links") is False


def test_web_paste_no_slack_token_no_crash(
    as_dev: TestClient,
    mock_slack: MockSlackServer,
    route_slack_to_mock: None,
    slack_env_unset: None,
) -> None:
    """Honest no-op — when Slack isn't configured, the web paste
    submit succeeds and posts nothing. Silent no-op is the right
    behaviour per [[ibounce-honest-positioning]] because the
    operator never asked for Slack notifications in this deployment.
    """
    resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    assert mock_slack.find_calls("/chat.postMessage") == []


def test_api_submit_no_slack_token_no_crash(
    as_dev: TestClient,
    mock_slack: MockSlackServer,
    route_slack_to_mock: None,
    slack_env_unset: None,
) -> None:
    """Parity of the no-Slack path — the API submit also stays
    silent when Slack isn't configured."""
    resp = as_dev.post("/api/v1/requests", json=_api_submit_payload())
    assert resp.status_code in (200, 201), resp.text
    assert mock_slack.find_calls("/chat.postMessage") == []


def test_web_paste_slack_post_failure_doesnt_fail_request_creation(
    as_dev: TestClient,
    mock_slack: MockSlackServer,
    route_slack_to_mock: None,
    slack_env: None,
) -> None:
    """Honest degradation per [[ibounce-honest-positioning]] — when
    the Slack POST fails (mock returns ok=False), the request must
    still be created and persisted. The operator chases the missing
    notification out-of-band; iam-jit does NOT block submission on a
    notification-channel outage.
    """
    mock_slack.fail_next_with_error = "channel_not_found"
    resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(),
        follow_redirects=False,
    )
    # 303 redirect = request was successfully persisted.
    assert resp.status_code == 303, resp.text
    # The Slack POST was attempted (the failure was injected on the
    # next chat.postMessage), and the request still landed in the
    # store. We can verify the latter by following the redirect to
    # the detail page.
    detail_path = resp.headers["location"]
    detail_resp = as_dev.get(detail_path)
    assert detail_resp.status_code == 200, (
        "request not persisted after Slack POST failure — "
        "honest-degradation discipline violated"
    )
    # The helper logs a warning but does not raise; we don't assert
    # on the log message here (caplog adds flakiness) — the
    # important observable is that the request exists.


# ----- Sabotage check ----------------------------------------------------


def test_sabotage_disabling_helper_makes_parity_test_fail(
    as_dev: TestClient,
    mock_slack: MockSlackServer,
    route_slack_to_mock: None,
    slack_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage check — if we no-op the shared helper, the web
    paste-form path must NOT post to Slack. Proves the
    `test_web_paste_submit_triggers_slack_post_when_configured`
    test above is load-bearing on the real call path; without
    this sabotage, the test could be spuriously green if the helper
    were wired through some other channel we didn't realise.
    """
    from iam_jit import approval_notifier

    monkeypatch.setattr(
        approval_notifier,
        "notify_approvers_for_new_request",
        lambda request: None,
    )
    resp = as_dev.post(
        "/requests/new/paste",
        data=_paste_form_fields(),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    # The helper is no-op'd → no Slack POST should have happened.
    assert mock_slack.find_calls("/chat.postMessage") == [], (
        "the route handler is reaching Slack through some path "
        "OTHER than approval_notifier.notify_approvers_for_new_request "
        "— the parity test above isn't actually load-bearing on the "
        "shared helper"
    )
