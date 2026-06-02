"""Slack notification channel for bouncer deny / pending-approval events
(ADOPT-8 / #732).

What this is
------------
When a bouncer DENIES a request (or queues a self-grant for approval),
post a neutral notification to Slack so a human sees it and can act. It
is a thin, contained CHANNEL — it does NOT introduce a stateful Slack
app with interactive callbacks. Instead it:

  1. Renders the existing :class:`~iam_jit.structured_deny.response.StructuredDenyResponse`
     into a Slack incoming-webhook payload (same top-level
     ``text`` + ``attachments`` shape the autopilot ``--notify-denies
     webhook`` path already speaks), and
  2. Tells the operator HOW to review / approve via the EXISTING §A25
     pending-approval queue surface (``iam-jit denies recent`` +
     ``iam-jit profile allow ...``) rather than a hosted callback
     endpoint.

This reuses, not reinvents:
  - the deny-event shape from ADOPT-3/#388 (``StructuredDenyResponse``
    + the ``_structured_deny_to_webhook_card`` Slack/Discord card shape
    in :mod:`iam_jit.autopilot.daemon`), and
  - the pending-approval backend
    (:func:`iam_jit.profile_allow.operations.list_pending`) for the
    "approve via the queue" linkage.

Configuration (default-OFF)
---------------------------
All config comes from the environment so a webhook URL / bot token is
never taken as a CLI arg (per [[push-policy-public-repo]] — webhook
URLs and bot tokens routinely embed secrets):

  IAM_JIT_NOTIFY_SLACK_WEBHOOK   incoming-webhook URL (primary path)
  IAM_JIT_SLACK_BOT_TOKEN        optional bot token (chat.postMessage)
  IAM_JIT_SLACK_APPROVAL_CHANNEL channel id/name for the bot-token path
  IAM_JIT_PUBLIC_URL             optional deployment URL to deep-link the
                                 operator review surface

When NEITHER a webhook URL NOR a (bot-token + channel) pair is
configured, :func:`configured` returns False and every send is a
silent no-op. That is the correct behaviour for a "no Slack"
deployment — the operator never asked for a card.

Honest degradation (per [[ibounce-honest-positioning]])
-------------------------------------------------------
  - Default-off: no config → no-op.
  - Fail-soft: if Slack is configured but the post fails (Slack down,
    network blip), we log a WARNING and return — we NEVER raise into
    the deny hot path and we NEVER drop the underlying deny/audit. The
    operator can always fall back to ``iam-jit denies recent``.

No secret leak
--------------
  - The webhook URL + bot token are NEVER logged and NEVER placed in a
    Slack message body.
  - The denied REQUEST's own payload (headers, body, query) is never
    forwarded — only the structured-deny fields (action / verdict /
    reason / agent session id) that are already operator-safe go into
    the card.

Neutral language (per [[safety-mode-lean-permissive]])
------------------------------------------------------
The card LEADS with "your bouncer caught N thing(s)" framing, not
surveillance / accusation language. The canonical strings avoid the
``audit_export.alerts.FORBIDDEN_ALERT_WORDS`` (violation / infraction /
unauthorized); a test asserts this stays clean.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..structured_deny.response import StructuredDenyResponse

logger = logging.getLogger("iam_jit.notify.slack")


# ---------------------------------------------------------------------------
# Env var names (single source of truth)
# ---------------------------------------------------------------------------

ENV_WEBHOOK_URL = "IAM_JIT_NOTIFY_SLACK_WEBHOOK"
ENV_BOT_TOKEN = "IAM_JIT_SLACK_BOT_TOKEN"
ENV_BOT_CHANNEL = "IAM_JIT_SLACK_APPROVAL_CHANNEL"
ENV_PUBLIC_URL = "IAM_JIT_PUBLIC_URL"

# Slack chat.postMessage endpoint. Overridable for tests via the same
# base-url override slack_bot.py already honours.
_CHAT_POST_MESSAGE = "/api/chat.postMessage"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SlackNotifyConfig:
    """Resolved Slack deny-notify configuration.

    Exactly one transport is selected, preferring the incoming-webhook
    (simplest, no scopes). ``review_url`` is an optional deep-link to
    the operator review surface; ``None`` falls back to the CLI hint.

    The secret fields (``webhook_url`` / ``bot_token``) are deliberately
    excluded from ``repr`` so a config object can never accidentally
    leak its secret into a log line / traceback.
    """

    webhook_url: str | None = None
    bot_token: str | None = None
    bot_channel: str | None = None
    review_url: str | None = None

    def __repr__(self) -> str:  # pragma: no cover - trivial
        # Never echo the secret values. Report only WHICH transport is
        # set so operators can sanity-check enablement from a log.
        return (
            "SlackNotifyConfig("
            f"webhook={'set' if self.webhook_url else 'unset'}, "
            f"bot_token={'set' if self.bot_token else 'unset'}, "
            f"bot_channel={self.bot_channel or 'unset'}, "
            f"review_url={'set' if self.review_url else 'unset'})"
        )

    @property
    def uses_webhook(self) -> bool:
        return bool(self.webhook_url)

    @property
    def uses_bot(self) -> bool:
        return bool(self.bot_token and self.bot_channel)


def from_env(env: dict[str, str] | None = None) -> SlackNotifyConfig | None:
    """Resolve the Slack deny-notify config from the environment.

    Returns ``None`` when no usable transport is configured (default
    state) so callers can cheaply short-circuit to a no-op. A webhook
    URL alone is enough; the bot-token path additionally needs a
    channel.
    """
    src = env if env is not None else os.environ
    webhook = (src.get(ENV_WEBHOOK_URL) or "").strip() or None
    bot_token = (src.get(ENV_BOT_TOKEN) or "").strip() or None
    bot_channel = (src.get(ENV_BOT_CHANNEL) or "").strip() or None
    review_url = (src.get(ENV_PUBLIC_URL) or "").strip() or None

    # Defensive: the webhook URL is operator-supplied and POSTed to
    # directly. A misconfigured non-https scheme (e.g. file:// or an
    # internal http:// host) is a self-inflicted SSRF / data-exfil angle,
    # so reject anything that is not https:// — treat it as unconfigured
    # rather than POST to it. We name the problem at WARNING but NEVER
    # echo the URL value (it routinely embeds the webhook secret).
    if webhook is not None and not webhook.lower().startswith("https://"):
        logger.warning(
            "%s is set but is not an https:// URL; ignoring it "
            "(Slack incoming webhooks are always https). The webhook "
            "value is not logged.",
            ENV_WEBHOOK_URL,
        )
        webhook = None

    has_webhook = bool(webhook)
    has_bot = bool(bot_token and bot_channel)
    if not has_webhook and not has_bot:
        return None
    return SlackNotifyConfig(
        webhook_url=webhook,
        bot_token=bot_token,
        bot_channel=bot_channel,
        review_url=review_url,
    )


def configured(env: dict[str, str] | None = None) -> bool:
    """True iff a usable Slack transport is configured. Default: False."""
    return from_env(env) is not None


# ---------------------------------------------------------------------------
# Payload builder — neutral language, no secret leak
# ---------------------------------------------------------------------------


def _pending_count(queue_path: Any = None) -> int:
    """Best-effort count of entries in the §A25 pending-approval queue.

    Reused for the "your bouncer caught N thing(s)" lead. Any read error
    degrades to 0 (the card still posts, just without a count) rather
    than failing the notification.
    """
    try:
        from ..profile_allow.operations import list_pending

        return len(list_pending(queue_path=queue_path))
    except Exception as e:
        logger.debug("pending-queue count unavailable: %s", e)
        return 0


def _review_hint(cfg: SlackNotifyConfig) -> str:
    """How-to-review/approve line that points at the EXISTING queue.

    Prefers a deep-link to the deployment's review surface when
    ``IAM_JIT_PUBLIC_URL`` is set; otherwise gives the CLI surface
    (``iam-jit denies recent`` to see it, ``iam-jit profile allow ...``
    to approve via the pending-approval queue). No hosted callback
    endpoint is required.
    """
    if cfg.review_url:
        base = cfg.review_url.rstrip("/")
        return f"Review + approve: {base}/requests"
    return (
        "Review with `iam-jit denies recent`; approve via the "
        "pending-approval queue with `iam-jit profile allow ...` "
        "(the suggested command is below when one applies)."
    )


def build_deny_payload(
    sd: StructuredDenyResponse,
    *,
    cfg: SlackNotifyConfig,
    pending_count: int | None = None,
) -> dict[str, Any]:
    """Render a :class:`StructuredDenyResponse` into a Slack
    incoming-webhook payload.

    Shape: top-level ``text`` + ``attachments`` array (the Slack legacy
    incoming-webhook contract that the autopilot webhook path already
    speaks; Discord renders ``text`` directly too).

    Neutral language: the lead is "Your <bouncer> bouncer caught N
    thing(s)", never accusatory. Adversarial classifications get a
    ``danger`` colour + an explicit "recommended: halt + escalate"
    line so a true injection is loud, not whispered (per
    [[ibounce-honest-positioning]]).

    No secret leak: only the structured-deny fields go in. The denied
    request's raw payload is never forwarded; the webhook URL / bot
    token never appear in the body.
    """
    cls = getattr(sd, "is_likely_injection_classification", "ambiguous")
    color = {
        "appears_adversarial": "danger",
        "ambiguous": "warning",
        "appears_legitimate": "good",
        "pending_classification": "warning",
    }.get(cls, "warning")

    bouncer = getattr(sd, "caught_by_bouncer", "") or "bouncer"
    action = getattr(sd, "action", "") or "(unknown action)"
    resource = getattr(sd, "resource", "") or "(unknown resource)"
    reason = (
        getattr(sd, "deny_reason", "")
        or getattr(sd, "deny_source", "")
        or "(no reason supplied)"
    )
    recommended = getattr(sd, "recommended_action", "") or "easy-allow"
    suggested = getattr(sd, "suggested_allow_command", "")
    deny_event_id = getattr(sd, "deny_event_id", "")
    agent_session_id = getattr(sd, "agent_session_id", "")

    n = pending_count if pending_count is not None else _pending_count()
    thing = "thing" if n == 1 else "things"
    if n > 0:
        lead = f"Your {bouncer} bouncer caught {n} {thing} for review."
    else:
        lead = f"Your {bouncer} bouncer caught something for review."
    if cls == "appears_adversarial":
        lead += " Recommended: halt + escalate (do NOT auto-allow)."

    fields: list[dict[str, Any]] = [
        {"title": "Agent tried", "value": f"{action} on {resource}", "short": False},
        {"title": "Why caught", "value": reason, "short": False},
        {"title": "Classification", "value": cls, "short": True},
        {"title": "Recommended action", "value": recommended, "short": True},
    ]
    if agent_session_id:
        fields.append(
            {"title": "Agent session", "value": agent_session_id, "short": True}
        )
    if suggested:
        fields.append(
            {"title": "Approve / allow with", "value": f"`{suggested}`", "short": False}
        )
    if deny_event_id:
        fields.append(
            {"title": "Deny event id", "value": deny_event_id, "short": False}
        )
    fields.append({"title": "How to review", "value": _review_hint(cfg), "short": False})

    return {
        "text": lead,
        "attachments": [
            {
                "color": color,
                "fallback": f"Your {bouncer} bouncer caught {action} on {resource}",
                "title": "iam-jit — bouncer caught something for review",
                "fields": fields,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


def _slack_api_base() -> str:
    """Slack API base, overridable for tests (mirrors slack_bot.py)."""
    override = (os.environ.get("IAM_JIT_SLACK_API_BASE") or "").strip()
    if override:
        return override.rstrip("/")
    return "https://slack.com"


def _post_webhook(url: str, payload: dict[str, Any]) -> None:
    """POST the payload to a Slack incoming-webhook URL.

    Fail-soft: a transport error is logged at WARNING (so the operator
    can see "Slack configured but the card never landed") and
    swallowed. We never raise into the deny hot path.
    """
    import json
    import urllib.request

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # Short timeout — Slack delivery latency must not stall the
        # deny path or the autopilot sweep loop.
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            resp.read()
    except Exception as e:
        # Deliberately do NOT include `url` in the log line — it embeds
        # the webhook secret.
        logger.warning("slack deny notification (webhook) failed: %s", e)


def _post_bot(cfg: SlackNotifyConfig, payload: dict[str, Any]) -> None:
    """POST via chat.postMessage using the bot token.

    Fail-soft, same contract as the webhook path. The bot token goes in
    the Authorization header only — never in the message body and never
    in a log line.
    """
    import json
    import urllib.request

    body = dict(payload)
    body["channel"] = cfg.bot_channel
    url = f"{_slack_api_base()}{_CHAT_POST_MESSAGE}"
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Authorization": f"Bearer {cfg.bot_token}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            raw = resp.read()
        # chat.postMessage returns 200 + {"ok": false, ...} on logical
        # failures; surface that at WARNING without echoing the token.
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            parsed = {}
        if isinstance(parsed, dict) and parsed.get("ok") is False:
            logger.warning(
                "slack deny notification (bot) rejected: %s",
                parsed.get("error", "unknown"),
            )
    except Exception as e:
        logger.warning("slack deny notification (bot) failed: %s", e)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def notify_deny(
    sd: StructuredDenyResponse,
    *,
    cfg: SlackNotifyConfig | None = None,
    pending_count: int | None = None,
) -> bool:
    """Post a neutral Slack notification for a deny / pending-approval
    event. Reuse this for both "bouncer denied" and "self-grant queued
    for approval" — both are operator-review events.

    Returns True iff a post was attempted (Slack configured), False on
    the default-off no-op path. Never raises — fail-soft per
    [[ibounce-honest-positioning]]; a notification failure must never
    break the deny hot path or drop the underlying audit/deny.
    """
    resolved = cfg if cfg is not None else from_env()
    if resolved is None:
        # Default-off: no Slack configured → silent no-op.
        return False
    try:
        payload = build_deny_payload(sd, cfg=resolved, pending_count=pending_count)
        if resolved.uses_webhook:
            _post_webhook(resolved.webhook_url or "", payload)
        elif resolved.uses_bot:
            _post_bot(resolved, payload)
    except Exception as e:
        # Belt-and-suspenders: any unexpected error in build/post is
        # logged + swallowed so the deny path is never impacted. We
        # still report True — a post WAS attempted (Slack is configured);
        # the failure is surfaced via the WARNING log, not the return.
        logger.warning("slack deny notification failed: %s", e)
    # Slack was configured → a post was attempted regardless of outcome.
    return True


__all__ = [
    "ENV_BOT_CHANNEL",
    "ENV_BOT_TOKEN",
    "ENV_PUBLIC_URL",
    "ENV_WEBHOOK_URL",
    "SlackNotifyConfig",
    "build_deny_payload",
    "configured",
    "from_env",
    "notify_deny",
]
