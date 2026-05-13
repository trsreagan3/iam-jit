"""How magic-links reach their owner.

Three delivery channels, picked at request time based on env config:

  1. **SES email** — production happy path. Requires
     `IAM_JIT_SES_SENDER` set to a verified address. The link is sent
     via SES; nothing is logged.

  2. **CloudWatch / stderr log** — Phase 1 no-email mode (no SES
     verification needed). When `IAM_JIT_SES_SENDER` is empty AND
     `IAM_JIT_DEV_INSECURE_SECRET` is NOT set, we emit a structured
     log line the operator can grep from CloudWatch (or stderr in
     local dev). The link is NOT included in any HTTP response, so a
     hostile caller can't enter someone else's email to read their
     link.

     Trust boundary: anyone with read access to the Lambda's log
     group can read magic-links. That's roughly the same set of
     people who already have iam-jit admin access, so the
     equivalence is reasonable for small teams. Larger orgs should
     wire up SES; the SAM template's `SesSenderAddress` parameter
     makes it a one-line config change.

  3. **In-response dev_link** — local-dev convenience. When
     `IAM_JIT_DEV_INSECURE_SECRET=1`, the link is returned on the
     login_sent page so the developer doesn't bounce through email
     or logs. **Strictly local-dev only** — an attacker submitting
     another user's email would otherwise read that user's link.

The same channel-selection function is reused by the JSON
`/api/v1/auth/magic-link` endpoint so the deploy mode is consistent
across surfaces.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger("iam_jit.auth")


@dataclass(frozen=True)
class DeliveryDecision:
    """How a single magic-link should be delivered."""

    channel: str
    """One of: 'email', 'log', 'in_response', 'none'."""
    show_in_response: bool
    """True only for in_response (dev-mode). Web routes consult this
    to decide whether to render the link on the login_sent page."""


def decide() -> DeliveryDecision:
    """Pick the delivery channel for the current deployment."""
    if os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") == "1":
        return DeliveryDecision(
            channel="in_response", show_in_response=True
        )
    if os.environ.get("IAM_JIT_SES_SENDER", "").strip():
        return DeliveryDecision(channel="email", show_in_response=False)
    return DeliveryDecision(channel="log", show_in_response=False)


def deliver(*, email: str, user_id: str, link: str) -> DeliveryDecision:
    """Send the link through whichever channel `decide()` picked.

    `email` is the recipient address (already validated upstream).
    `user_id` is the iam-jit-internal id, used only for the log line
    so operators can correlate. `link` is the full magic-callback URL.

    Returns the DeliveryDecision so the caller can react — in
    particular the web `/login` handler uses `show_in_response` to
    decide whether to render the link on the confirmation page.
    """
    decision = decide()

    if decision.channel == "email":
        try:
            import boto3

            sender = os.environ["IAM_JIT_SES_SENDER"]
            boto3.client("ses").send_email(
                Source=sender,
                Destination={"ToAddresses": [email]},
                Message={
                    "Subject": {"Data": "iam-jit sign-in link"},
                    "Body": {
                        "Text": {
                            "Data": (
                                f"Click to sign in: {link}\n\n"
                                "This link expires in 15 minutes and can be "
                                "used once."
                            )
                        }
                    },
                },
            )
        except Exception:
            # Don't reveal SES errors to callers; logs only. This is
            # the same swallow-and-log behavior the JSON auth path
            # used before delivery was centralized.
            logger.exception("SES send_email failed; magic-link was NOT delivered")
        return decision

    if decision.channel == "log":
        # Structured one-line emit so operators can grep CloudWatch:
        #   aws logs filter-log-events --log-group-name /aws/lambda/iam-jit \
        #     --filter-pattern 'MAGIC_LINK'
        logger.warning(
            "MAGIC_LINK channel=log user_id=%s url=%s",
            user_id, link,
        )
        return decision

    # in_response: the caller (web route) renders it inline. We do
    # nothing here; the decision flag tells the caller to render.
    return decision


def channel_summary() -> dict[str, Any]:
    """Surface for the admin / health UI. No secrets — just enough
    information to confirm the deploy posture."""
    d = decide()
    has_ses = bool(os.environ.get("IAM_JIT_SES_SENDER", "").strip())
    dev_secret = os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") == "1"
    return {
        "channel": d.channel,
        "ses_configured": has_ses,
        "dev_insecure_secret": dev_secret,
    }
