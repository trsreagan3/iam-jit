"""#413 / §A57 — autopilot --notify-denies stderr + webhook tone tests.

Per [[ambient-value-prop-and-friction-framing]]:
  * stderr line leads with "Your bouncer caught" NEVER "ERROR" /
    "DENIED" / "BLOCKED".
  * webhook payload is a Slack/Discord-shaped card whose top-level
    `text` is the caught-framing.
  * adversarial classifications surface a halt+escalate recommendation
    (loud, not whispered) per [[ibounce-honest-positioning]].
"""

from __future__ import annotations

import io
import sys
from typing import Any

import pytest

from iam_jit.autopilot.daemon import (
    AutopilotSupervisor,
    _structured_deny_to_webhook_card,
)
from iam_jit.profile_allow.denies import DenyRow
from iam_jit.structured_deny import build_structured_deny


def _row(
    *,
    action: str = "s3:GetObject",
    resource: str = "arn:aws:s3:::cache-bucket/x.json",
    deny_source: str = "static_profile",
    deny_reason: str = "profile 'safe-default' has no matching allow",
    bouncer: str = "ibounce",
) -> DenyRow:
    return DenyRow(
        when="2026-05-23T10:00:00Z",
        bouncer=bouncer,
        agent_session_id="sess-1",
        action=action,
        resource=resource,
        deny_reason=deny_reason,
        deny_source=deny_source,
        rule_id_if_dynamic=None,
        suggested_allow_command=(
            f"iam-jit profile allow --target '{resource}' "
            f"--action '{action}' --reason \"<why this is safe>\""
        ),
    )


# ---------------------------------------------------------------------------
# --notify-denies stderr
# ---------------------------------------------------------------------------


def _make_supervisor(notify_denies: str) -> AutopilotSupervisor:
    return AutopilotSupervisor(
        declaration={
            "iam-jit": {
                "enabled": True,
                "posture": "ambient",
                "bouncers": {},
            }
        },
        config_source="<test>",
        notify_denies=notify_denies,
    )


def test_notify_denies_stderr_uses_caught_framing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """stderr output MUST lead with "Your <bouncer> bouncer caught"
    not "ERROR" / "DENIED" / "BLOCKED"."""
    sup = _make_supervisor("stderr")
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache/x",
        deny_reason="profile 'safe-default' has no matching allow",
        deny_source="static_profile",
    )
    sup._notify_stderr(sd)
    captured = capsys.readouterr()
    assert captured.err.startswith("[autopilot] ")
    # Per the canonical: lead with the bouncer's action.
    assert "Your ibounce bouncer caught" in captured.err
    for forbidden in ("ERROR", "DENIED", "BLOCKED"):
        assert forbidden not in captured.err


def test_notify_denies_stderr_adversarial_recommends_halt_escalate(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Per [[ibounce-honest-positioning]]: adversarial classifications
    still escalate — the line MUST include the halt + escalate
    recommendation, NOT the easy-allow nudge."""
    sup = _make_supervisor("stderr")
    sd = build_structured_deny(
        bouncer="ibounce",
        action="iam:DeleteUser",
        resource="arn:aws:iam::123:user/svc",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
    )
    sup._notify_stderr(sd)
    captured = capsys.readouterr()
    assert "halt + escalate" in captured.err
    # Easy-allow nudge MUST NOT be the lead message for adversarial.
    assert "Allow if legit" not in captured.err


# ---------------------------------------------------------------------------
# --notify-denies webhook
# ---------------------------------------------------------------------------


def test_notify_denies_webhook_payload_card_shape() -> None:
    """The webhook payload MUST be a Slack/Discord-shaped card
    (top-level `text` + `attachments` array)."""
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache/x",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
    )
    card = _structured_deny_to_webhook_card(sd)
    assert "text" in card
    assert "attachments" in card
    assert isinstance(card["attachments"], list)
    assert len(card["attachments"]) >= 1
    # Lead text leads with caught framing.
    assert card["text"].startswith("Your ibounce bouncer caught")
    # Attachment carries the structured fields.
    att = card["attachments"][0]
    titles = [f["title"] for f in att["fields"]]
    assert "Agent tried" in titles
    assert "Why caught" in titles
    assert "Classification" in titles
    assert "Recommended action" in titles


def test_notify_denies_webhook_payload_adversarial_color_danger() -> None:
    """Adversarial denies surface as `color: danger` so Slack renders
    them with the red bar (loud, not whispered)."""
    sd = build_structured_deny(
        bouncer="ibounce",
        action="iam:DeleteUser",
        resource="arn:aws:iam::123:user/svc",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
    )
    card = _structured_deny_to_webhook_card(sd)
    assert card["attachments"][0]["color"] == "danger"
    # The top-level text leads with the halt recommendation.
    assert "halt + escalate" in card["text"]


def test_notify_denies_webhook_payload_legit_color_warning_or_good() -> None:
    """Non-adversarial denies use `warning` (ambiguous) or `good`
    (legitimate) — never `danger` — so the operator's eye-scan is
    quiet where it should be."""
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache/x",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
    )
    card = _structured_deny_to_webhook_card(sd)
    assert card["attachments"][0]["color"] in ("warning", "good")


def test_notify_denies_webhook_no_url_skips_silently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When IAM_JIT_AUTOPILOT_DENY_WEBHOOK_URL is unset, _notify_webhook
    is a silent no-op (does NOT raise + does NOT print). Per
    [[ibounce-honest-positioning]] webhook flakiness must not become a
    deny-notification outage."""
    monkeypatch.delenv("IAM_JIT_AUTOPILOT_DENY_WEBHOOK_URL", raising=False)
    sup = _make_supervisor("webhook")
    sd = build_structured_deny(
        bouncer="ibounce",
        action="s3:GetObject",
        resource="arn:aws:s3:::cache/x",
        deny_reason="profile 'safe-default'",
        deny_source="static_profile",
    )
    # Must not raise.
    sup._notify_webhook(sd)
