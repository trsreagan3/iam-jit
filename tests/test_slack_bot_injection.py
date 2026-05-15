"""Pinned tests for WB8-01 (HIGH) — Block Kit / mrkdwn injection
via requester-influenced fields in the Slack approval card.

These attacks come from the REQUESTER side. The requester controls
`spec.description` and influences `review.risk_factors`. The
APPROVER reads the rendered card and clicks Approve/Reject based
on it — making the approver's perception of the card the entire
authorization boundary of the bot.

Slack's mrkdwn renderer interprets several special forms that an
unescaped requester string can smuggle:

  <@USERID>             → user mention (looks legitimate; fake)
  <!channel>            → channel-wide ping (spam)
  <!here>               → active-users ping (spam)
  <!subteam^TEAMID>     → group ping (social engineering)
  <https://x.com/|text> → link with arbitrary display text
                          (could read "Approve in iam-jit")

The fix (in slack_bot._escape_mrkdwn) replaces & → &amp;,
< → &lt;, > → &gt;. Order matters — & first.
"""

from __future__ import annotations

from iam_jit import slack_bot


def _render_with_description(text: str) -> str:
    """Helper: render an approval card with the given description
    and return the rendered mrkdwn string for the description block."""
    body = slack_bot.render_approval_message({
        "id": "rq-test",
        "spec": {
            "description": text,
            "access_type": "read-only",
            "duration": {"duration_hours": 1},
            "accounts": ["123456789012"],
        },
        "status": {"owner": "email:alice@example.com"},
        "review": {"risk_score": 3, "risk_factors": []},
    })
    reason_block = next(
        b for b in body["blocks"]
        if b.get("type") == "section"
        and isinstance(b.get("text"), dict)
        and "Reason" in b["text"].get("text", "")
    )
    return reason_block["text"]["text"]


def test_user_mention_smuggling_is_escaped() -> None:
    """A requester's description can't render as a fake user mention."""
    rendered = _render_with_description("Please approve <@USLACKBOT>")
    assert "<@USLACKBOT>" not in rendered
    assert "&lt;@USLACKBOT&gt;" in rendered


def test_channel_ping_smuggling_is_escaped() -> None:
    rendered = _render_with_description("Need this now <!channel>")
    assert "<!channel>" not in rendered
    assert "&lt;!channel&gt;" in rendered


def test_here_ping_smuggling_is_escaped() -> None:
    rendered = _render_with_description("<!here> urgent")
    assert "<!here>" not in rendered
    assert "&lt;!here&gt;" in rendered


def test_subteam_ping_smuggling_is_escaped() -> None:
    rendered = _render_with_description("<!subteam^S12345|@security>")
    assert "<!subteam" not in rendered
    assert "&lt;!subteam" in rendered


def test_link_text_smuggling_is_escaped() -> None:
    """The 'Approve in iam-jit' link-text spoofing primitive."""
    rendered = _render_with_description(
        "Routine read access. <https://attacker.example/approve|"
        "Approve in iam-jit>"
    )
    assert "<https://attacker.example" not in rendered
    assert "&lt;https://attacker.example" in rendered
    # The pipe + display-text form is also defused — the > is escaped.
    assert "Approve in iam-jit&gt;" in rendered


def test_ampersand_escaped_first_no_double_encoding() -> None:
    """Ordering matters: & must be replaced first, otherwise we'd
    double-escape the entity references we just emitted (&lt; → &amp;lt;).
    """
    rendered = _render_with_description("AT&T request <@U123>")
    assert "AT&amp;T" in rendered
    assert "&lt;@U123&gt;" in rendered
    # No double-escape of the entity refs we just produced.
    assert "&amp;lt;" not in rendered
    assert "&amp;gt;" not in rendered


def test_plain_description_unchanged() -> None:
    """Non-injection text shouldn't be visibly mangled (single & is
    rare in real descriptions; we accept the modest cosmetic cost)."""
    rendered = _render_with_description("Read S3 objects from prod-uploads")
    assert "Read S3 objects from prod-uploads" in rendered


def test_risk_factors_are_escaped() -> None:
    """Risk-factor strings get interpolated user-influenced policy
    text (action names, resource ARNs). Same injection surface."""
    body = slack_bot.render_approval_message({
        "id": "rq-rf",
        "spec": {"description": "x", "access_type": "read-only",
                 "duration": {"duration_hours": 1}, "accounts": []},
        "status": {"owner": "email:a@b.com"},
        "review": {
            "risk_score": 7,
            "risk_factors": [
                "Resource <!channel> seemed concerning",
                "Action <@U999> appears in policy",
                "Trust includes <https://evil.example/|Approve here>",
            ],
        },
    })
    factor_block = next(
        b for b in body["blocks"]
        if b.get("type") == "section"
        and isinstance(b.get("text"), dict)
        and "Risk factors" in b["text"].get("text", "")
    )
    rendered = factor_block["text"]["text"]
    assert "<!channel>" not in rendered
    assert "<@U999>" not in rendered
    assert "<https://evil.example" not in rendered
    assert "&lt;!channel&gt;" in rendered
    assert "&lt;@U999&gt;" in rendered
    assert "&lt;https://evil.example" in rendered


def test_escape_helper_idempotency_check() -> None:
    """Calling the escape helper twice doesn't compound the entity
    refs. (Documents the trade-off — running it twice DOES double-
    escape `&`. The fix is to call it exactly once per untrusted
    field, which the renderer enforces.)"""
    once = slack_bot._escape_mrkdwn("a & <b>")
    twice = slack_bot._escape_mrkdwn(once)
    assert once == "a &amp; &lt;b&gt;"
    # Double-escape DOES happen — this pins the trade-off so future
    # refactors don't accidentally call the helper twice.
    assert twice == "a &amp;amp; &amp;lt;b&amp;gt;"


def test_escape_helper_handles_non_string() -> None:
    """Defensive: if a callback hands the renderer a non-string
    description (an integer, list, dict), the helper coerces."""
    assert slack_bot._escape_mrkdwn(42) == "42"
    assert slack_bot._escape_mrkdwn(None) == "None"
