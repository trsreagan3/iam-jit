"""Pinned tests for round-8 audit MED closures.

WB8-02: ambiguous slack_user_id mapping → refuses on multi-match
WB8-03: missing workspace pin → optional IAM_JIT_SLACK_TEAM_ID
WB8-04: missing channel pin → optional approval_channel ID check
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from iam_jit import slack_bot


_CFG_PINNED = slack_bot.SlackConfig(
    bot_token="xoxb-test",
    signing_secret="test-secret",
    approval_channel="C-APPROVALS",
    expected_team_id="T-WORKSPACE-A",
    expected_channel_id="C-APPROVALS",
)

_CFG_UNPINNED = slack_bot.SlackConfig(
    bot_token="xoxb-test",
    signing_secret="test-secret",
    approval_channel="C-APPROVALS",
)


# ---------------------------------------------------------------------------
# WB8-02 — ambiguous slack_user_id mapping refused.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _FakeUser:
    id: str
    roles: tuple[str, ...] = ("approver",)
    enabled: bool = True
    slack_user_id: str | None = None


class _FakeUsersStore:
    def __init__(self, users: list[_FakeUser]) -> None:
        self._users = users

    def list(self) -> list[_FakeUser]:
        return list(self._users)

    def get(self, user_id: str) -> _FakeUser:
        for u in self._users:
            if u.id == user_id:
                return u
        raise KeyError(user_id)


class _NoSlackClient:
    """Stub that never gets called when explicit mapping resolves."""

    def post_json(self, *args, **kwargs):
        raise NotImplementedError

    def get_user_info(self, *args, **kwargs):
        raise NotImplementedError("should not be called when explicit mapping wins/errors")


def test_wb8_02_single_explicit_mapping_works() -> None:
    """Single user with the slack_user_id resolves normally."""
    store = _FakeUsersStore([
        _FakeUser(id="email:alice@example.com", slack_user_id="U-ALICE"),
    ])
    resolver = slack_bot.ApproverResolver(store, _CFG_UNPINNED, client=_NoSlackClient())
    user = resolver.resolve("U-ALICE")
    assert user.id == "email:alice@example.com"


def test_wb8_02_two_users_with_same_slack_user_id_raises() -> None:
    """When two iam-jit users have the same slack_user_id (admin
    misconfig), refuse the action explicitly rather than silently
    picking one."""
    store = _FakeUsersStore([
        _FakeUser(id="email:alice@example.com", slack_user_id="U-DUPE"),
        _FakeUser(id="email:bob@example.com", slack_user_id="U-DUPE"),
    ])
    resolver = slack_bot.ApproverResolver(store, _CFG_UNPINNED, client=_NoSlackClient())
    with pytest.raises(slack_bot.SlackUserUnresolvable) as exc:
        resolver.resolve("U-DUPE")
    assert "ambiguous" in str(exc.value).lower()
    assert "alice" in str(exc.value) and "bob" in str(exc.value)


def test_wb8_02_three_users_with_same_slack_user_id_raises() -> None:
    """Same closure scales to N users with the same mapping."""
    store = _FakeUsersStore([
        _FakeUser(id="email:a@example.com", slack_user_id="U-TRIPLE"),
        _FakeUser(id="email:b@example.com", slack_user_id="U-TRIPLE"),
        _FakeUser(id="email:c@example.com", slack_user_id="U-TRIPLE"),
    ])
    resolver = slack_bot.ApproverResolver(store, _CFG_UNPINNED, client=_NoSlackClient())
    with pytest.raises(slack_bot.SlackUserUnresolvable):
        resolver.resolve("U-TRIPLE")


# ---------------------------------------------------------------------------
# WB8-03 — workspace pinning via team.id.
# ---------------------------------------------------------------------------


def _payload(*, team_id: str = "T-WORKSPACE-A", channel_id: str = "C-APPROVALS") -> str:
    return json.dumps({
        "type": "block_actions",
        "user": {"id": "U-X"},
        "team": {"id": team_id},
        "channel": {"id": channel_id},
        "actions": [{"action_id": "iamjit_approve", "value": "approve:rq-X"}],
    })


def test_wb8_03_workspace_match_passes() -> None:
    slack_bot.validate_workspace_and_channel(
        _payload(team_id="T-WORKSPACE-A"), config=_CFG_PINNED,
    )  # Does not raise.


def test_wb8_03_workspace_mismatch_raises() -> None:
    """A signed callback from a different workspace must be rejected."""
    with pytest.raises(slack_bot.WorkspaceMismatch):
        slack_bot.validate_workspace_and_channel(
            _payload(team_id="T-WORKSPACE-B"), config=_CFG_PINNED,
        )


def test_wb8_03_workspace_missing_in_payload_rejects() -> None:
    """When the deployment requires a team_id but the payload doesn't
    include one, reject. Defensive."""
    payload = json.dumps({
        "type": "block_actions",
        "user": {"id": "U-X"},
        # team key intentionally missing
        "channel": {"id": "C-APPROVALS"},
        "actions": [{"action_id": "iamjit_approve", "value": "approve:rq-X"}],
    })
    with pytest.raises(slack_bot.WorkspaceMismatch):
        slack_bot.validate_workspace_and_channel(payload, config=_CFG_PINNED)


def test_wb8_03_no_pin_skips_check() -> None:
    """Backward-compat: if IAM_JIT_SLACK_TEAM_ID isn't set, no check."""
    slack_bot.validate_workspace_and_channel(
        _payload(team_id="T-ANY-WORKSPACE"), config=_CFG_UNPINNED,
    )  # Does not raise.


# ---------------------------------------------------------------------------
# WB8-04 — channel pinning.
# ---------------------------------------------------------------------------


def test_wb8_04_channel_match_passes() -> None:
    slack_bot.validate_workspace_and_channel(
        _payload(channel_id="C-APPROVALS"), config=_CFG_PINNED,
    )  # Does not raise.


def test_wb8_04_channel_mismatch_raises() -> None:
    """A signed click from a different channel is rejected when the
    deployment has channel pinning configured."""
    with pytest.raises(slack_bot.ChannelMismatch):
        slack_bot.validate_workspace_and_channel(
            _payload(channel_id="C-OTHER"), config=_CFG_PINNED,
        )


def test_wb8_04_channel_missing_in_payload_passes() -> None:
    """view_submission payloads don't include channel.id. Don't
    reject those — they're modal submissions, not channel-based."""
    payload = json.dumps({
        "type": "view_submission",
        "user": {"id": "U-X"},
        "team": {"id": "T-WORKSPACE-A"},
        # No `channel` key (modal submission)
        "view": {
            "callback_id": "iamjit_request_changes_modal",
            "private_metadata": "rq-X",
            "state": {"values": {}},
        },
    })
    # Should NOT raise — channel is absent, which is legitimate.
    slack_bot.validate_workspace_and_channel(payload, config=_CFG_PINNED)


def test_wb8_04_no_pin_skips_check() -> None:
    """When approval_channel isn't set, channel check is skipped."""
    cfg = slack_bot.SlackConfig(
        bot_token="xoxb", signing_secret="s",
        approval_channel=None, expected_channel_id=None,
    )
    slack_bot.validate_workspace_and_channel(
        _payload(channel_id="C-ANYTHING"), config=cfg,
    )  # Does not raise.


# ---------------------------------------------------------------------------
# Combined: malformed JSON during validation.
# ---------------------------------------------------------------------------


def test_invalid_json_during_validation_raises_slack_error() -> None:
    with pytest.raises(slack_bot.SlackError):
        slack_bot.validate_workspace_and_channel(
            "{not valid json", config=_CFG_PINNED,
        )


def test_env_loads_team_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """SlackConfig.from_env() picks up IAM_JIT_SLACK_TEAM_ID."""
    monkeypatch.setenv("IAM_JIT_SLACK_BOT_TOKEN", "xoxb-x")
    monkeypatch.setenv("IAM_JIT_SLACK_SIGNING_SECRET", "shh")
    monkeypatch.setenv("IAM_JIT_SLACK_APPROVAL_CHANNEL", "C-X")
    monkeypatch.setenv("IAM_JIT_SLACK_TEAM_ID", "T-FROM-ENV")
    cfg = slack_bot.SlackConfig.from_env()
    assert cfg is not None
    assert cfg.expected_team_id == "T-FROM-ENV"
    assert cfg.expected_channel_id == "C-X"
