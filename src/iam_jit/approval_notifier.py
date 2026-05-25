"""Approver-notification dispatch for newly-created requests.

Single entry point — `notify_approvers_for_new_request` — that the
submit handlers in `routes/requests.py` (API path) and `routes/web.py`
(web paste-form path) both call after a request is persisted in
`pending` state. Centralising this keeps the two paths from drifting
per [[cross-product-agent-parity]]; the silent gap closed by #596 was
exactly that drift in the first place.

Distinct responsibility from `notifications.py`: that module is the
admin-webhook surface for operational alerts (provisioning failures,
expiry errors). This module is the approver-facing surface for "a new
request landed in pending, please review" — which today is the Slack
Block Kit approval card and tomorrow may be webhook / email / Teams.

Discipline:
  - Honest degradation (per [[ibounce-honest-positioning]]): if no
    notification channel is configured, no-op silently — that's a
    legitimate deployment shape. If a channel IS configured and the
    post fails, log a WARNING (operator can see "approval submitted
    but Slack never got the card") but DO NOT raise — request
    creation must not depend on a healthy notification channel.

  - Idempotent: safe to call any number of times for the same request;
    duplicate cards in Slack are better than a missing one.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("iam_jit.approval_notifier")


def notify_approvers_for_new_request(request: dict[str, Any]) -> None:
    """Fire all configured approver-notification channels for a
    newly-created request that needs approval review.

    Currently supports: Slack Block Kit approval card (when
    IAM_JIT_SLACK_BOT_TOKEN + IAM_JIT_SLACK_SIGNING_SECRET +
    IAM_JIT_SLACK_APPROVAL_CHANNEL are configured).

    Caller responsibility: only call when the request actually needs
    approver attention (i.e., it landed in `pending` state, not
    auto-approved). This helper does not re-check the request state
    — it trusts the caller.

    Failures are logged and SWALLOWED so a notification-channel
    outage cannot block request creation. The request is already
    persisted; the operator can chase down the missing notification
    out-of-band via the audit log.
    """
    _try_post_slack_approval_card(request)
    # Future channels (webhook, SES, Teams, PagerDuty) extend here.


def _try_post_slack_approval_card(request: dict[str, Any]) -> None:
    """Post the Slack Block Kit approval card if Slack is configured.

    Silent no-op when Slack is not configured (legitimate "no Slack"
    deployment). Logs WARNING on post failure (Slack configured but
    unreachable — operator-visible degradation).
    """
    try:
        from . import slack_bot

        slack_cfg = slack_bot.SlackConfig.from_env()
        if slack_cfg is None:
            # Slack not configured — silent no-op is the right
            # behaviour for "no Slack" deployments. The operator
            # never asked for a card; not posting one is correct.
            return
        slack_bot.post_approval_message(
            request=request,
            config=slack_cfg,
            deployment_url=os.environ.get("IAM_JIT_PUBLIC_URL"),
        )
    except Exception as e:
        # Slack configured but post failed — honest degradation
        # per [[ibounce-honest-positioning]]: surface the gap in
        # logs so the operator knows the approval card never landed,
        # but do NOT fail request creation (the request is already
        # persisted and the operator can chase the notification
        # out-of-band via the audit log).
        logger.warning(
            "slack approval post failed (request still submitted): %s", e
        )
