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
    """Pick the delivery channel for the current deployment.

    Precedence (MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES round-3 closure):
      1. **SES email** wins over EVERYTHING when configured. If a
         deployment has `IAM_JIT_SES_SENDER` set, that's the
         production posture and we refuse to fall back to channels
         that leak the link (in_response, log) — even if a
         developer's `.env` template accidentally inherited
         `IAM_JIT_DEV_INSECURE_SECRET=1` into prod.
      2. `IAM_JIT_DEV_INSECURE_SECRET=1` → in_response (local-dev
         convenience). Refused when running in Lambda
         (`AWS_LAMBDA_FUNCTION_NAME` set) unless the operator also
         sets `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1` — closes
         the DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN finding's
         delivery leg.
      3. `IAM_JIT_ALLOW_LOG_CHANNEL=1` → log (opt-in; small teams
         that genuinely want CloudWatch as the delivery channel).
         Log line emits only the token *fingerprint*, NOT the full
         URL — see deliver().
      4. Otherwise → none. Refuse to issue rather than leak.
    """
    if os.environ.get("IAM_JIT_SES_SENDER", "").strip():
        return DeliveryDecision(channel="email", show_in_response=False)

    from .auth import is_dev_insecure_active

    if is_dev_insecure_active():
        return DeliveryDecision(
            channel="in_response", show_in_response=True
        )
    if os.environ.get("IAM_JIT_ALLOW_LOG_CHANNEL", "").lower() in {
        "1", "true", "yes"
    }:
        return DeliveryDecision(channel="log", show_in_response=False)
    return DeliveryDecision(channel="none", show_in_response=False)


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
        # Log the token FINGERPRINT — never the full URL. A reader
        # with CloudWatch access can confirm a magic link was issued
        # for `user_id` and correlate against access logs, but can't
        # use the fingerprint to construct a working link without
        # also possessing the magic-link secret. Reconstruction
        # requires both the secret AND the original token, so the
        # log line alone is non-spendable.
        import hashlib

        fp = hashlib.sha256(link.encode("utf-8")).hexdigest()[:16]
        logger.warning(
            "MAGIC_LINK channel=log user_id=%s link_fingerprint=%s "
            "(out-of-band: deliver the link to user via your own channel)",
            user_id, fp,
        )
        return decision

    if decision.channel == "none":
        # No delivery channel configured. Surface loudly so the
        # operator notices at launch rather than silently dropping
        # auth attempts.
        logger.error(
            "MAGIC_LINK channel=none user_id=%s — refusing to issue. "
            "Configure IAM_JIT_SES_SENDER, IAM_JIT_ALLOW_LOG_CHANNEL=1, "
            "or IAM_JIT_DEV_INSECURE_SECRET=1.",
            user_id,
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
