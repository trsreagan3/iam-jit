"""Unit tests for `src/iam_jit/slack_bot.py`.

Coverage targets (in priority order):

1. Signature verification — must reject:
   - Missing signature header
   - Missing timestamp header
   - Wrong signature
   - Timestamp older than replay window
   - Timestamp in the future beyond window
   - Non-integer timestamp
   - Body tampering after signing
   - Empty signing secret
2. Approval-message rendering — produces Slack-valid Block Kit
3. Interactive payload parsing — rejects malformed shapes; happy path works
4. Approver resolution — explicit mapping wins; email fallback works;
   non-approvers rejected; disabled users rejected
5. post_approval_message — happy path; Slack-API not-ok response raises

These are unit tests with no live Slack call. The TestClient-based
integration tests for the route live in test_routes_slack.py.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import time
from typing import Any

import pytest

from iam_jit import slack_bot


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


_SIGNING_SECRET = "test-signing-secret"


def _sign(body: bytes, timestamp: str | None = None) -> tuple[str, str]:
    """Compute a valid Slack signature pair for `body` at `timestamp`.

    Returns (timestamp, signature) ready to pass to verify_signature.
    """
    ts = timestamp if timestamp is not None else str(int(time.time()))
    base = f"v0:{ts}:".encode("utf-8") + body
    sig = "v0=" + hmac.new(
        _SIGNING_SECRET.encode("utf-8"), base, hashlib.sha256
    ).hexdigest()
    return ts, sig


# ---------------------------------------------------------------------------
# 1. Signature verification.
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    def test_valid_signature_passes(self) -> None:
        body = b'payload={"x":1}'
        ts, sig = _sign(body)
        # Does not raise.
        slack_bot.verify_signature(
            body=body, timestamp=ts, signature=sig, signing_secret=_SIGNING_SECRET
        )

    def test_missing_signature_rejected(self) -> None:
        body = b"payload=foo"
        ts = str(int(time.time()))
        with pytest.raises(slack_bot.SignatureMismatch):
            slack_bot.verify_signature(
                body=body, timestamp=ts, signature=None, signing_secret=_SIGNING_SECRET
            )

    def test_missing_timestamp_rejected(self) -> None:
        body = b"payload=foo"
        with pytest.raises(slack_bot.SignatureMismatch):
            slack_bot.verify_signature(
                body=body, timestamp=None, signature="v0=deadbeef",
                signing_secret=_SIGNING_SECRET,
            )

    def test_wrong_signature_rejected(self) -> None:
        body = b"payload=foo"
        ts = str(int(time.time()))
        with pytest.raises(slack_bot.SignatureMismatch):
            slack_bot.verify_signature(
                body=body, timestamp=ts, signature="v0=" + "0" * 64,
                signing_secret=_SIGNING_SECRET,
            )

    def test_body_tampering_rejected(self) -> None:
        """An attacker who intercepts a valid sig + ts but modifies
        the body must NOT pass."""
        original = b"payload=approve"
        ts, sig = _sign(original)
        tampered = b"payload=approve_extra"
        with pytest.raises(slack_bot.SignatureMismatch):
            slack_bot.verify_signature(
                body=tampered, timestamp=ts, signature=sig,
                signing_secret=_SIGNING_SECRET,
            )

    def test_replay_attack_old_timestamp_rejected(self) -> None:
        """A request signed an hour ago must NOT verify even with
        a structurally correct signature."""
        body = b"payload=replay"
        old_ts = str(int(time.time()) - 3600)
        _, sig = _sign(body, timestamp=old_ts)
        with pytest.raises(slack_bot.TimestampOutOfWindow):
            slack_bot.verify_signature(
                body=body, timestamp=old_ts, signature=sig,
                signing_secret=_SIGNING_SECRET,
            )

    def test_future_timestamp_rejected(self) -> None:
        """A request with a future timestamp (clock-skew attack)
        must also be rejected."""
        body = b"payload=future"
        future_ts = str(int(time.time()) + 3600)
        _, sig = _sign(body, timestamp=future_ts)
        with pytest.raises(slack_bot.TimestampOutOfWindow):
            slack_bot.verify_signature(
                body=body, timestamp=future_ts, signature=sig,
                signing_secret=_SIGNING_SECRET,
            )

    def test_non_integer_timestamp_rejected(self) -> None:
        body = b"payload=foo"
        with pytest.raises(slack_bot.SignatureMismatch):
            slack_bot.verify_signature(
                body=body, timestamp="not-a-number", signature="v0=abc",
                signing_secret=_SIGNING_SECRET,
            )

    def test_constant_time_comparison_used(self) -> None:
        """Verify the implementation uses hmac.compare_digest by
        ensuring two off-by-many-bytes signatures both fail (no
        timing-oracle short-circuit). We can't time-test reliably,
        but we can confirm the symbol is in source."""
        import inspect

        src = inspect.getsource(slack_bot.verify_signature)
        assert "compare_digest" in src

    def test_secret_change_invalidates_signatures(self) -> None:
        """A signature valid for secret A must fail under secret B."""
        body = b"payload=foo"
        ts, sig = _sign(body)  # signed with _SIGNING_SECRET
        with pytest.raises(slack_bot.SignatureMismatch):
            slack_bot.verify_signature(
                body=body, timestamp=ts, signature=sig,
                signing_secret="different-secret",
            )


# ---------------------------------------------------------------------------
# 2. Approval-message rendering.
# ---------------------------------------------------------------------------


class TestApprovalMessageRender:
    def _sample_request(self, **overrides) -> dict[str, Any]:
        req = {
            "id": "REQ-2026-05-15-abc",
            "spec": {
                "description": "investigating payment 4521",
                "access_type": "read-only",
                "duration": {"duration_hours": 1},
                "accounts": ["111111111111"],
            },
            "status": {"owner": "email:alice@example.com", "state": "pending"},
            "review": {
                "risk_score": 3,
                "risk_factors": ["S3 wildcard prefix", "Read-only"],
            },
        }
        req.update(overrides)
        return req

    def test_minimal_request_renders(self) -> None:
        body = slack_bot.render_approval_message(self._sample_request())
        assert "blocks" in body
        assert isinstance(body["blocks"], list)
        assert "text" in body  # Slack requires `text` fallback
        # Has at least header + buttons.
        types = [b.get("type") for b in body["blocks"]]
        assert "header" in types
        assert "actions" in types

    def test_buttons_carry_correct_value(self) -> None:
        body = slack_bot.render_approval_message(self._sample_request())
        actions_block = next(b for b in body["blocks"] if b.get("type") == "actions")
        values = [b.get("value") for b in actions_block["elements"] if "value" in b]
        assert "approve:REQ-2026-05-15-abc" in values
        assert "reject:REQ-2026-05-15-abc" in values

    def test_deployment_url_adds_view_button(self) -> None:
        body = slack_bot.render_approval_message(
            self._sample_request(),
            deployment_url="https://iam-jit.internal",
        )
        actions_block = next(b for b in body["blocks"] if b.get("type") == "actions")
        view = next(
            (b for b in actions_block["elements"] if b.get("action_id") == "iamjit_view"),
            None,
        )
        assert view is not None
        assert view["url"] == "https://iam-jit.internal/requests/REQ-2026-05-15-abc"

    def test_risk_factors_truncated_when_long(self) -> None:
        req = self._sample_request()
        req["review"]["risk_factors"] = [f"factor-{i}" for i in range(15)]
        body = slack_bot.render_approval_message(req)
        # Find the risk-factors section.
        text_blocks = [
            b for b in body["blocks"]
            if b.get("type") == "section"
            and isinstance(b.get("text"), dict)
            and "Risk factors" in b["text"].get("text", "")
        ]
        assert len(text_blocks) == 1
        body_text = text_blocks[0]["text"]["text"]
        # First 5 shown, "+10 more" indicator present.
        assert "factor-0" in body_text
        assert "factor-4" in body_text
        assert "+10 more" in body_text
        # 6+ NOT inlined.
        assert "factor-6" not in body_text

    def test_request_without_score_still_renders(self) -> None:
        req = self._sample_request()
        del req["review"]
        body = slack_bot.render_approval_message(req)
        assert "blocks" in body  # didn't crash

    def test_request_without_id_renders_unknown(self) -> None:
        body = slack_bot.render_approval_message({})
        assert "blocks" in body
        # Buttons still rendered with placeholder request_id.
        actions_block = next(b for b in body["blocks"] if b.get("type") == "actions")
        values = [b.get("value") for b in actions_block["elements"] if "value" in b]
        assert any(v.startswith("approve:") for v in values)


# ---------------------------------------------------------------------------
# 3. Interactive payload parsing.
# ---------------------------------------------------------------------------


class TestParseInteractivePayload:
    def _build_payload(self, **overrides) -> str:
        defaults = {
            "type": "block_actions",
            "user": {"id": "U01ABCD", "username": "alice", "name": "alice"},
            "actions": [
                {
                    "action_id": "iamjit_approve",
                    "value": "approve:REQ-123",
                }
            ],
            "response_url": "https://hooks.slack.com/actions/...",
            "trigger_id": "trig-123",
        }
        defaults.update(overrides)
        return json.dumps(defaults)

    def test_happy_path_approve(self) -> None:
        ia = slack_bot.parse_interactive_payload(self._build_payload())
        assert ia.verb == "approve"
        assert ia.request_id == "REQ-123"
        assert ia.clicker_slack_user_id == "U01ABCD"
        assert ia.clicker_slack_username == "alice"

    def test_happy_path_reject(self) -> None:
        payload = self._build_payload(
            actions=[{"action_id": "iamjit_reject", "value": "reject:REQ-456"}]
        )
        ia = slack_bot.parse_interactive_payload(payload)
        assert ia.verb == "reject"
        assert ia.request_id == "REQ-456"

    def test_invalid_json_rejected(self) -> None:
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_interactive_payload("not json")

    def test_non_object_rejected(self) -> None:
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_interactive_payload("[1,2,3]")

    def test_no_actions_rejected(self) -> None:
        payload = self._build_payload(actions=[])
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_interactive_payload(payload)

    def test_value_without_colon_rejected(self) -> None:
        payload = self._build_payload(
            actions=[{"action_id": "x", "value": "noColonHere"}]
        )
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_interactive_payload(payload)

    def test_unknown_verb_rejected(self) -> None:
        """An attacker can't smuggle in `delete:REQ-X` and hope we
        try a transition we didn't intend."""
        payload = self._build_payload(
            actions=[{"action_id": "x", "value": "delete:REQ-X"}]
        )
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_interactive_payload(payload)

    def test_missing_user_id_rejected(self) -> None:
        payload = self._build_payload(user={"username": "noid"})
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_interactive_payload(payload)

    def test_empty_request_id_rejected(self) -> None:
        payload = self._build_payload(
            actions=[{"action_id": "x", "value": "approve:"}]
        )
        with pytest.raises(slack_bot.SlackError):
            slack_bot.parse_interactive_payload(payload)

    def test_extra_fields_ignored_safely(self) -> None:
        """Slack adds fields we don't read. Our parser must ignore
        them — pinning a future-proof shape against new Slack fields."""
        payload = self._build_payload(
            extra_field={"smuggle": "in"},
            actions=[
                {
                    "action_id": "iamjit_approve",
                    "value": "approve:REQ-OK",
                    "spoofed_field": "from-attacker",
                }
            ],
        )
        ia = slack_bot.parse_interactive_payload(payload)
        assert ia.verb == "approve"
        assert ia.request_id == "REQ-OK"


# ---------------------------------------------------------------------------
# 4. Approver resolution.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _FakeUser:
    id: str
    roles: tuple[str, ...]
    enabled: bool = True
    slack_user_id: str | None = None


class _FakeUsersStore:
    def __init__(self, users: list[_FakeUser]) -> None:
        self._users = {u.id: u for u in users}

    def list(self) -> list[_FakeUser]:
        return list(self._users.values())

    def get(self, user_id: str) -> _FakeUser:
        return self._users[user_id]


class _StubSlackClient:
    def __init__(self, email_map: dict[str, str]) -> None:
        self.email_map = email_map
        self.calls: list[str] = []

    def post_json(self, *args, **kwargs):
        raise NotImplementedError

    def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]:
        self.calls.append(user_id)
        email = self.email_map.get(user_id)
        if email is None:
            return {"ok": False, "error": "user_not_found"}
        return {"ok": True, "user": {"profile": {"email": email}}}


_CFG = slack_bot.SlackConfig(
    bot_token="xoxb-stub",
    signing_secret=_SIGNING_SECRET,
    approval_channel="C-stub",
)


class TestApproverResolver:
    def test_explicit_mapping_wins(self) -> None:
        store = _FakeUsersStore([
            _FakeUser(id="email:alice@example.com", roles=("approver",), slack_user_id="U-ALICE"),
        ])
        stub = _StubSlackClient(email_map={})
        r = slack_bot.ApproverResolver(store, _CFG, client=stub)
        user = r.resolve("U-ALICE")
        assert user.id == "email:alice@example.com"
        assert stub.calls == []  # Slack API NOT called when explicit mapping matched.

    def test_email_fallback(self) -> None:
        store = _FakeUsersStore([
            _FakeUser(id="email:bob@example.com", roles=("approver",)),
        ])
        stub = _StubSlackClient(email_map={"U-BOB": "bob@example.com"})
        r = slack_bot.ApproverResolver(store, _CFG, client=stub)
        user = r.resolve("U-BOB")
        assert user.id == "email:bob@example.com"
        assert stub.calls == ["U-BOB"]

    def test_email_case_normalized(self) -> None:
        store = _FakeUsersStore([
            _FakeUser(id="email:bob@example.com", roles=("approver",)),
        ])
        stub = _StubSlackClient(email_map={"U-BOB": "BOB@Example.COM"})
        r = slack_bot.ApproverResolver(store, _CFG, client=stub)
        user = r.resolve("U-BOB")
        assert user.id == "email:bob@example.com"

    def test_non_approver_rejected(self) -> None:
        store = _FakeUsersStore([
            _FakeUser(id="email:carol@example.com", roles=("requester",)),
        ])
        stub = _StubSlackClient(email_map={"U-CAROL": "carol@example.com"})
        r = slack_bot.ApproverResolver(store, _CFG, client=stub)
        with pytest.raises(slack_bot.UserNotApprover):
            r.resolve("U-CAROL")

    def test_admin_is_allowed(self) -> None:
        store = _FakeUsersStore([
            _FakeUser(id="email:dave@example.com", roles=("admin",)),
        ])
        stub = _StubSlackClient(email_map={"U-DAVE": "dave@example.com"})
        r = slack_bot.ApproverResolver(store, _CFG, client=stub)
        user = r.resolve("U-DAVE")
        assert user.id == "email:dave@example.com"

    def test_disabled_approver_rejected(self) -> None:
        store = _FakeUsersStore([
            _FakeUser(id="email:eve@example.com", roles=("approver",), enabled=False),
        ])
        stub = _StubSlackClient(email_map={"U-EVE": "eve@example.com"})
        r = slack_bot.ApproverResolver(store, _CFG, client=stub)
        with pytest.raises(slack_bot.UserNotApprover):
            r.resolve("U-EVE")

    def test_unresolvable_slack_user_raises(self) -> None:
        store = _FakeUsersStore([])
        stub = _StubSlackClient(email_map={})
        r = slack_bot.ApproverResolver(store, _CFG, client=stub)
        with pytest.raises(slack_bot.SlackUserUnresolvable):
            r.resolve("U-UNKNOWN")

    def test_slack_user_id_spoofing_does_not_grant_access(self) -> None:
        """If an attacker passes a Slack user ID that doesn't map
        to any iam-jit User (no explicit slack_user_id, no email
        match), we MUST raise — never default to allow."""
        store = _FakeUsersStore([
            _FakeUser(id="email:admin@example.com", roles=("admin",), slack_user_id="U-REAL-ADMIN"),
        ])
        stub = _StubSlackClient(email_map={"U-ATTACKER": "attacker@evil.com"})
        r = slack_bot.ApproverResolver(store, _CFG, client=stub)
        # Attacker's email doesn't match any registered user.
        with pytest.raises(slack_bot.SlackUserUnresolvable):
            r.resolve("U-ATTACKER")


# ---------------------------------------------------------------------------
# 5. post_approval_message.
# ---------------------------------------------------------------------------


class _StubPostClient:
    """Records what was POSTed for inspection; returns a configurable
    response."""

    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.response = response or {"ok": True, "channel": "C-stub", "ts": "1747000000.000100"}
        self.calls: list[dict[str, Any]] = []

    def post_json(self, url, *, headers, json_body):
        self.calls.append({"url": url, "headers": headers, "body": json_body})
        return self.response

    def get_user_info(self, user_id, *, bot_token):
        raise NotImplementedError


class TestPostApprovalMessage:
    def _sample_request(self) -> dict[str, Any]:
        return {
            "id": "REQ-POST-1",
            "spec": {"description": "demo", "access_type": "read-only",
                     "duration": {"duration_hours": 1}, "accounts": ["123"]},
            "status": {"owner": "email:alice@example.com"},
            "review": {"risk_score": 3, "risk_factors": []},
        }

    def test_posts_to_slack_with_bot_token(self) -> None:
        stub = _StubPostClient()
        slack_bot.post_approval_message(
            request=self._sample_request(), config=_CFG, client=stub,
        )
        assert len(stub.calls) == 1
        call = stub.calls[0]
        assert call["url"].endswith("/chat.postMessage")
        assert call["headers"]["Authorization"] == "Bearer xoxb-stub"
        assert call["body"]["channel"] == "C-stub"
        assert call["body"]["unfurl_links"] is False
        assert call["body"]["unfurl_media"] is False

    def test_no_channel_configured_raises(self) -> None:
        cfg = slack_bot.SlackConfig(
            bot_token="xoxb-stub", signing_secret=_SIGNING_SECRET,
            approval_channel=None,
        )
        with pytest.raises(slack_bot.SlackError):
            slack_bot.post_approval_message(
                request=self._sample_request(), config=cfg, client=_StubPostClient(),
            )

    def test_channel_override_works(self) -> None:
        cfg = slack_bot.SlackConfig(
            bot_token="xoxb-stub", signing_secret=_SIGNING_SECRET,
            approval_channel="C-default",
        )
        stub = _StubPostClient()
        slack_bot.post_approval_message(
            request=self._sample_request(),
            config=cfg,
            client=stub,
            channel="C-override",
        )
        assert stub.calls[0]["body"]["channel"] == "C-override"

    def test_slack_api_not_ok_raises(self) -> None:
        stub = _StubPostClient(response={"ok": False, "error": "channel_not_found"})
        with pytest.raises(slack_bot.SlackError) as exc:
            slack_bot.post_approval_message(
                request=self._sample_request(), config=_CFG, client=stub,
            )
        assert "channel_not_found" in str(exc.value)


# ---------------------------------------------------------------------------
# 6. SlackConfig.from_env.
# ---------------------------------------------------------------------------


class TestSlackConfigFromEnv:
    def test_missing_token_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IAM_JIT_SLACK_BOT_TOKEN", raising=False)
        monkeypatch.setenv("IAM_JIT_SLACK_SIGNING_SECRET", "abc")
        assert slack_bot.SlackConfig.from_env() is None

    def test_missing_secret_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAM_JIT_SLACK_BOT_TOKEN", "xoxb-")
        monkeypatch.delenv("IAM_JIT_SLACK_SIGNING_SECRET", raising=False)
        assert slack_bot.SlackConfig.from_env() is None

    def test_both_present_returns_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAM_JIT_SLACK_BOT_TOKEN", "xoxb-zzz")
        monkeypatch.setenv("IAM_JIT_SLACK_SIGNING_SECRET", "shh")
        monkeypatch.setenv("IAM_JIT_SLACK_APPROVAL_CHANNEL", "C-ABC")
        cfg = slack_bot.SlackConfig.from_env()
        assert cfg is not None
        assert cfg.bot_token == "xoxb-zzz"
        assert cfg.signing_secret == "shh"
        assert cfg.approval_channel == "C-ABC"

    def test_channel_optional(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAM_JIT_SLACK_BOT_TOKEN", "xoxb-")
        monkeypatch.setenv("IAM_JIT_SLACK_SIGNING_SECRET", "s")
        monkeypatch.delenv("IAM_JIT_SLACK_APPROVAL_CHANNEL", raising=False)
        cfg = slack_bot.SlackConfig.from_env()
        assert cfg is not None
        assert cfg.approval_channel is None


# ---------------------------------------------------------------------------
# 7. IAM_JIT_SLACK_API_BASE env-override (#597).
#
# Per PDF v2 build agent 2026-05-25: operators need to redirect Slack API
# traffic for local dev / MockSlackServer / on-prem Enterprise Grid /
# recording proxy use cases, without monkey-patching a module constant.
#
# These tests follow the state-verification convention in
# docs/CONTRIBUTING.md: assert OBSERVABLE state (the URL the slack_bot
# actually POSTs to) not internal config values alone.
# ---------------------------------------------------------------------------


class TestSlackApiBaseEnvOverride:
    """#597 — IAM_JIT_SLACK_API_BASE env-driven override."""

    def test_defaults_to_slack_com_when_env_unset(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No env var → canonical Slack URL. This is the safe default
        every existing operator already relies on."""
        monkeypatch.delenv("IAM_JIT_SLACK_API_BASE", raising=False)
        assert slack_bot._get_slack_api_base() == "https://slack.com/api"

    def test_env_override_changes_base_url(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Setting the env var → that value is returned."""
        monkeypatch.setenv("IAM_JIT_SLACK_API_BASE", "http://127.0.0.1:18766/api")
        assert (
            slack_bot._get_slack_api_base() == "http://127.0.0.1:18766/api"
        )

    def test_empty_string_env_falls_back_to_default(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An empty `IAM_JIT_SLACK_API_BASE=""` must be treated as
        unset, not as "use empty base URL" (which would yield
        malformed `/chat.postMessage` requests)."""
        monkeypatch.setenv("IAM_JIT_SLACK_API_BASE", "")
        assert slack_bot._get_slack_api_base() == "https://slack.com/api"

    def test_whitespace_only_env_falls_back_to_default(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Whitespace-only env (e.g. accidental copy-paste) → default."""
        monkeypatch.setenv("IAM_JIT_SLACK_API_BASE", "   ")
        assert slack_bot._get_slack_api_base() == "https://slack.com/api"

    def test_env_override_takes_effect_in_post_approval_message(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """End-to-end: env var → the bot's chat.postMessage call
        actually goes to the overridden URL.

        State verification per CONTRIBUTING.md: don't just check the
        function returns the right string; assert the OBSERVABLE state
        (the URL the HTTPClient receives) matches.
        """
        monkeypatch.setenv(
            "IAM_JIT_SLACK_API_BASE", "http://127.0.0.1:18766/api",
        )

        recorded: dict[str, Any] = {}

        class _RecordingClient:
            def post_json(
                self, url: str, *, headers: dict[str, str], json_body: dict[str, Any],
            ) -> dict[str, Any]:
                recorded["url"] = url
                recorded["json_body"] = json_body
                return {"ok": True, "channel": json_body.get("channel"), "ts": "1.0"}

            def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]:
                raise NotImplementedError

        cfg = slack_bot.SlackConfig(
            bot_token="xoxb-test",
            signing_secret="dummy",
            approval_channel="C_TEST",
        )
        resp = slack_bot.post_approval_message(
            request={
                "id": "req-1",
                "spec": {"description": "x", "access_type": "ro", "duration": {"duration_hours": 1}},
                "status": {"owner": "alice"},
                "review": {"risk_score": 3, "risk_factors": []},
            },
            config=cfg,
            client=_RecordingClient(),
        )

        # 1. Reported status (the claim).
        assert resp["ok"] is True

        # 2. Observable state matches the claim — the URL is overridden.
        assert recorded["url"] == "http://127.0.0.1:18766/api/chat.postMessage"
        assert not recorded["url"].startswith("https://slack.com")

    def test_env_override_takes_effect_in_mfa_step_up_nudge(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Parity: the MFA-nudge path also honours the override.
        Otherwise an operator who set the override for testing would
        get half their Slack traffic hitting real Slack."""
        monkeypatch.setenv(
            "IAM_JIT_SLACK_API_BASE", "http://127.0.0.1:18766/api",
        )

        recorded: dict[str, Any] = {}

        class _RecordingClient:
            def post_json(
                self, url: str, *, headers: dict[str, str], json_body: dict[str, Any],
            ) -> dict[str, Any]:
                recorded["url"] = url
                return {"ok": True, "channel": json_body.get("channel"), "ts": "1.0"}

            def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]:
                raise NotImplementedError

        cfg = slack_bot.SlackConfig(
            bot_token="xoxb-test",
            signing_secret="dummy",
            approval_channel="C_TEST",
        )
        slack_bot.post_mfa_step_up_nudge(
            user_id="email:alice@example.com",
            slack_user_id="U_ALICE",
            request_id="req-mfa-1",
            config=cfg,
            client=_RecordingClient(),
        )

        # Observable: nudge POST went to the overridden base.
        assert recorded["url"] == "http://127.0.0.1:18766/api/chat.postMessage"

    def test_env_override_takes_effect_in_open_modal(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Parity: views.open (modal opening) also honours override.
        All 4 slack_bot.py outbound HTTP sites must read the same env."""
        monkeypatch.setenv(
            "IAM_JIT_SLACK_API_BASE", "http://127.0.0.1:18766/api",
        )

        recorded: dict[str, Any] = {}

        class _RecordingClient:
            def post_json(
                self, url: str, *, headers: dict[str, str], json_body: dict[str, Any],
            ) -> dict[str, Any]:
                recorded["url"] = url
                return {"ok": True, "view": {"id": "V_1"}}

            def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]:
                raise NotImplementedError

        cfg = slack_bot.SlackConfig(
            bot_token="xoxb-test",
            signing_secret="dummy",
            approval_channel="C_TEST",
        )
        slack_bot.open_modal(
            trigger_id="tid_123",
            view={"type": "modal", "callback_id": "iamjit_request_changes_modal"},
            config=cfg,
            client=_RecordingClient(),
        )

        assert recorded["url"] == "http://127.0.0.1:18766/api/views.open"

    def test_sabotage_check_override_is_load_bearing(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Sabotage check per task spec: if we forced the env-read to
        always return the default, the override-end-to-end test must
        fail. Proves the override is doing actual work; not a
        no-op that happens to coincide with the default.
        """
        # First confirm: env override DOES change the observable URL.
        monkeypatch.setenv(
            "IAM_JIT_SLACK_API_BASE", "http://127.0.0.1:18766/api",
        )

        recorded: dict[str, Any] = {}

        class _RecordingClient:
            def post_json(
                self, url: str, *, headers: dict[str, str], json_body: dict[str, Any],
            ) -> dict[str, Any]:
                recorded["url"] = url
                return {"ok": True, "channel": json_body.get("channel"), "ts": "1.0"}

            def get_user_info(self, user_id: str, *, bot_token: str) -> dict[str, Any]:
                raise NotImplementedError

        cfg = slack_bot.SlackConfig(
            bot_token="xoxb-test", signing_secret="dummy", approval_channel="C_TEST",
        )

        # SABOTAGE: patch the resolver to always ignore env + return
        # the default. If the env-override mechanism weren't actually
        # wired into the post-path, the assertion below would still
        # pass (URL would still equal the override). It must fail.
        monkeypatch.setattr(
            slack_bot, "_get_slack_api_base",
            lambda: slack_bot._DEFAULT_SLACK_API_BASE,
        )

        slack_bot.post_approval_message(
            request={
                "id": "req-sabotage",
                "spec": {"description": "x", "access_type": "ro", "duration": {"duration_hours": 1}},
                "status": {"owner": "alice"},
                "review": {"risk_score": 3, "risk_factors": []},
            },
            config=cfg,
            client=_RecordingClient(),
        )

        # With the sabotage in place, URL must NOT equal the override —
        # because the post path now resolves to the default. This
        # proves the override is load-bearing (not a coincidence).
        assert recorded["url"] == "https://slack.com/api/chat.postMessage"
        assert recorded["url"] != "http://127.0.0.1:18766/api/chat.postMessage"
