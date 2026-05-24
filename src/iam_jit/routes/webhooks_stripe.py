"""Stripe webhook receiver — `POST /api/v1/webhooks/stripe`.

Thin HTTP wrapper around `iam_jit.stripe_webhook` business logic. The
endpoint:

  1. Reads the raw request body (we need EXACT bytes for HMAC).
  2. Verifies the Stripe-Signature header.
  3. Dispatches to `stripe_webhook.dispatch_event()`.
  4. Always returns HTTP 200 on successful verification (per Stripe's
     guidance — return 200 so they don't retry events we chose not
     to handle).
  5. Returns HTTP 400 on signature failures so Stripe surfaces the
     misconfiguration in their dashboard.

Configuration env vars:

  - `STRIPE_WEBHOOK_SECRET` (required) — the signing secret from
    your Stripe webhook endpoint config.
  - `STRIPE_PRICE_ID_TO_TIER` (required) — JSON map of price IDs to
    iam-jit tier names, e.g. `{"price_1ABC": "indie"}`.
  - `STRIPE_KEY_DELIVERY_FROM_EMAIL` (optional) — SES sender for the
    "here's your API key" email. If unset, no email is sent and the
    operator must deliver the key out-of-band (read it from the
    api_tokens table by the issued-token hash).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status

from .. import stripe_webhook
from ..middleware import get_api_tokens_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


def _ses_mailer(email: str, raw_token: str, tier: str) -> None:
    """SES-backed mailer for delivering issued API keys.

    Reads `STRIPE_KEY_DELIVERY_FROM_EMAIL` for the sender. If not set,
    raises — caller catches and logs (mail failures must not block
    the webhook 200 response).
    """
    sender = (os.environ.get("STRIPE_KEY_DELIVERY_FROM_EMAIL") or "").strip()
    if not sender:
        raise RuntimeError("STRIPE_KEY_DELIVERY_FROM_EMAIL not configured")

    import boto3  # imported lazily so unit tests don't need boto3

    # Self-host operator template — the hosted iam-risk-score Lambda
    # was dropped 2026-05-24 per [[no-hosted-saas]] restoration, so
    # this email template no longer points at a public endpoint.
    # Operators wiring Stripe to a self-hosted iam-jit deployment
    # should customize this body to point at THEIR endpoint.
    body_text = (
        f"Welcome — your {tier} tier is active.\n"
        f"\n"
        f"Your API key (save this somewhere safe — you won't be shown it again):\n"
        f"\n"
        f"    {raw_token}\n"
        f"\n"
        f"Use it via the Authorization header on every request to your\n"
        f"self-hosted iam-jit endpoint.\n"
        f"\n"
        f"Manage your subscription via the Stripe Customer Portal — link in\n"
        f"your Checkout receipt. Questions: reply to this email.\n"
    )
    boto3.client("ses").send_email(
        Source=sender,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Your iam-jit API key"},
            "Body": {"Text": {"Data": body_text}},
        },
    )


@router.post("/stripe")
async def stripe_webhook_endpoint(
    request: Request,
    stripe_signature: str | None = Header(default=None, alias="Stripe-Signature"),
) -> dict[str, Any]:
    """Receive a Stripe webhook event.

    Stripe POSTs JSON with a `Stripe-Signature` header. We verify the
    signature using the webhook signing secret, then dispatch to the
    matching event handler.
    """
    body = await request.body()

    secret = (os.environ.get("STRIPE_WEBHOOK_SECRET") or "").strip()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Stripe webhook endpoint is not configured "
                "(STRIPE_WEBHOOK_SECRET unset)."
            ),
        )

    try:
        event = stripe_webhook.verify_stripe_signature(
            payload=body,
            sig_header=stripe_signature or "",
            secret=secret,
        )
    except stripe_webhook.InvalidStripeSignature as e:
        # BB3-04 closure: detailed reason (server clock, timestamp,
        # tolerance window) stays in operator logs only. The
        # response body returns a generic message — an attacker
        # probing with bad signatures no longer gets a free
        # server-clock-sync gadget.
        logger.warning("Stripe webhook signature verification failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="signature verification failed",
        )

    tokens_store = get_api_tokens_store(request)
    if tokens_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="api_tokens_store is not configured",
        )

    # If we have an SES sender configured, wire it through; otherwise
    # the handler skips the email step and the operator can read the
    # raw token from the dashboard / DDB out-of-band.
    mailer = _ses_mailer if (os.environ.get("STRIPE_KEY_DELIVERY_FROM_EMAIL") or "").strip() else None

    processed_events_store = getattr(
        request.app.state, "processed_events_store", None,
    )

    try:
        return stripe_webhook.dispatch_event(
            event,
            tokens_store=tokens_store,
            mailer=mailer,
            processed_events_store=processed_events_store,
        )
    except stripe_webhook.HandlerPreWriteError as e:
        # Pre-write soft-fail (missing email, unmapped price, etc.).
        # dispatch_event already released the claim. Return 200 so
        # Stripe DOESN'T immediately retry, but flag the rejection
        # so the operator's dashboard surfaces the lockout case.
        # When the underlying data is corrected (customer adds
        # email, operator maps price), a redelivery via the Stripe
        # dashboard will succeed.
        logger.warning(
            "Stripe handler pre-write failure on event %s: %s",
            event.get("id"), e,
        )
        return {
            "handled": False,
            "rejected": True,
            "reason": "pre_write_handler_failure",
            "event_id": event.get("id", ""),
        }
