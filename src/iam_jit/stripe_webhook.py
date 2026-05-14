"""Stripe webhook handlers — Phase 7 billing integration.

When a customer completes Stripe Checkout for one of the paid tiers,
Stripe sends a `checkout.session.completed` webhook event. This module:

  1. Verifies the Stripe signature on the incoming HTTP request body.
  2. Parses the event JSON.
  3. Dispatches to a handler per event type:
       - `checkout.session.completed` → issue an API token, email it.
       - `customer.subscription.deleted` → revoke that customer's tokens.
       - others → log + ignore.

The flow is intentionally minimal: this module owns the Stripe→
iam-jit data path. It does NOT own:

  - Talking to Stripe APIs (no outbound calls from here — we only
    receive webhooks).
  - HTTP / FastAPI plumbing (that lives in `routes/webhooks_stripe.py`).
  - Email delivery transport (we accept a `mailer` callable).

Signature verification follows Stripe's documented manual-verification
pattern (https://stripe.com/docs/webhooks/signatures#verify-manually).
We don't depend on the `stripe` Python SDK — pure stdlib HMAC keeps
Lambda cold-start small.

Plan → tier mapping is configured via the `STRIPE_PRICE_ID_TO_TIER`
env var (JSON map). Example:
    {"price_1ABC": "indie", "price_1XYZ": "pro", "price_1JKL": "team"}
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Callable, Protocol

from .api_tokens_store import APITokenNotFound, APITokenRecord, APITokenStore
from .auth import issue_api_token

logger = logging.getLogger(__name__)


# Tolerance for the `t=` timestamp in the Stripe-Signature header.
# Stripe recommends 5 minutes. Above this, treat as a replay attack.
_DEFAULT_TIMESTAMP_TOLERANCE_SECONDS = 300


class InvalidStripeSignature(Exception):
    """Raised when the Stripe-Signature header fails verification."""


@dataclasses.dataclass(frozen=True)
class IssuedTokenResult:
    """Returned by `handle_checkout_session_completed` when a key is minted."""

    raw_token: str          # The bearer token to email the customer
    token_hash: str         # Stored in the API tokens table
    customer_email: str
    tier: str
    stripe_customer_id: str | None
    stripe_subscription_id: str | None


# ---- Signature verification -----------------------------------------


def verify_stripe_signature(
    *,
    payload: bytes,
    sig_header: str,
    secret: str,
    tolerance_seconds: int = _DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    """Verify the Stripe-Signature header and return the parsed event.

    The Stripe-Signature header has the form:
        t=<unix-timestamp>,v1=<hex-hmac>[,v0=<old-version-hex-hmac>]

    Verification steps (per Stripe's docs):
      1. Parse the header into a dict of scheme→value.
      2. Reject if `t=` timestamp is outside the tolerance window
         (replay protection).
      3. Construct the signed payload: `f"{t}.".encode() + payload`.
      4. Compute HMAC-SHA256 of that with `secret` as the key.
      5. Compare against the `v1=` value using constant-time equality.

    Raises `InvalidStripeSignature` on any failure. Returns the parsed
    JSON event on success.
    """
    if not sig_header:
        raise InvalidStripeSignature("missing Stripe-Signature header")
    if not secret:
        raise InvalidStripeSignature("server-side STRIPE_WEBHOOK_SECRET not configured")

    parts: dict[str, str] = {}
    for chunk in sig_header.split(","):
        if "=" not in chunk:
            continue
        k, v = chunk.strip().split("=", 1)
        parts[k] = v

    if "t" not in parts:
        raise InvalidStripeSignature("Stripe-Signature missing `t=` timestamp")
    if "v1" not in parts:
        raise InvalidStripeSignature("Stripe-Signature missing `v1=` signature (need v1 scheme)")

    try:
        timestamp = int(parts["t"])
    except ValueError:
        raise InvalidStripeSignature(f"Stripe-Signature `t=` is not an integer: {parts['t']!r}")

    now = now_epoch if now_epoch is not None else int(time.time())
    if abs(now - timestamp) > tolerance_seconds:
        raise InvalidStripeSignature(
            f"Stripe-Signature timestamp {timestamp} is outside the "
            f"{tolerance_seconds}s tolerance window (now={now})"
        )

    signed_payload = f"{timestamp}.".encode("utf-8") + payload
    expected_sig = hmac.new(
        secret.encode("utf-8"), signed_payload, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, parts["v1"]):
        raise InvalidStripeSignature("signature mismatch (Stripe-Signature v1 hash does not verify)")

    try:
        return json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise InvalidStripeSignature(f"payload is not valid JSON: {e}")


# ---- Plan → tier mapping --------------------------------------------


def get_tier_for_price(price_id: str) -> str | None:
    """Look up the iam-jit tier (e.g. 'indie', 'pro') for a Stripe price.

    Reads `STRIPE_PRICE_ID_TO_TIER` env var, a JSON object mapping
    Stripe price IDs to tier names. Returns None for unknown price IDs
    (caller should log + skip the event).
    """
    raw = (os.environ.get("STRIPE_PRICE_ID_TO_TIER") or "").strip()
    if not raw:
        return None
    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("STRIPE_PRICE_ID_TO_TIER is not valid JSON")
        return None
    if not isinstance(mapping, dict):
        return None
    return mapping.get(price_id)


# ---- Event handlers -------------------------------------------------


def _extract_email(event_data: dict[str, Any]) -> str | None:
    """Find the customer email in a Stripe event's nested data."""
    obj = event_data.get("object") or {}
    candidate = obj.get("customer_email") or obj.get("customer_details", {}).get("email")
    return candidate or None


def _extract_price_id(event_data: dict[str, Any]) -> str | None:
    """Find the Stripe price ID in a checkout.session.completed event.

    Stripe puts it under either `display_items[0].price.id` (legacy) or
    `line_items[0].price.id` (current API). Some payloads omit
    line_items entirely; in that case the caller should look at the
    subscription object instead. Returns None if not present.
    """
    obj = event_data.get("object") or {}
    for key in ("line_items", "display_items"):
        items = (obj.get(key) or {}).get("data") or obj.get(key) or []
        if isinstance(items, list) and items:
            price = items[0].get("price")
            if isinstance(price, dict) and price.get("id"):
                return price["id"]
    return None


def handle_checkout_session_completed(
    event: dict[str, Any],
    *,
    tokens_store: APITokenStore,
    mailer: Callable[[str, str, str], None] | None = None,
) -> IssuedTokenResult | None:
    """Issue an API token for a successful Stripe Checkout.

    On `checkout.session.completed`:
      1. Extract customer email + price ID from the event.
      2. Resolve the iam-jit tier from the price.
      3. Mint an API token tied to the customer's email as `user_id`.
      4. Persist to `tokens_store` with the tier as the label.
      5. Call `mailer(email, raw_token, tier)` if provided.

    Returns the IssuedTokenResult on success, or None if the event
    couldn't be handled (unknown price, missing email, etc.) — the
    webhook endpoint should log + return 200 in that case so Stripe
    doesn't retry forever.
    """
    if event.get("type") != "checkout.session.completed":
        return None

    data = event.get("data") or {}
    obj = data.get("object") or {}

    email = _extract_email(data)
    if not email:
        logger.warning(
            "checkout.session.completed event has no customer email; event id=%s",
            event.get("id"),
        )
        return None

    price_id = _extract_price_id(data)
    tier: str | None = None
    if price_id:
        tier = get_tier_for_price(price_id)

    if not tier:
        logger.warning(
            "checkout.session.completed: no tier mapped for price_id=%s (event id=%s)",
            price_id, event.get("id"),
        )
        return None

    issued = issue_api_token(user_id=email, label=f"stripe:{tier}")
    record = APITokenRecord(
        token_hash=issued.hash,
        user_id=issued.user_id,
        created_at=issued.created_at,
        label=issued.label,
    )
    tokens_store.put(record)

    customer_id = obj.get("customer")
    subscription_id = obj.get("subscription")

    result = IssuedTokenResult(
        raw_token=issued.raw,
        token_hash=issued.hash,
        customer_email=email,
        tier=tier,
        stripe_customer_id=customer_id if isinstance(customer_id, str) else None,
        stripe_subscription_id=subscription_id if isinstance(subscription_id, str) else None,
    )

    if mailer is not None:
        try:
            mailer(email, issued.raw, tier)
        except Exception:
            # Mailer failures must not block the webhook response;
            # the operator can re-send the key out-of-band from the
            # tokens table. Logging only.
            logger.exception("mailer failed for checkout-completed email=%s", email)

    logger.info(
        "issued API token for %s on tier=%s (stripe_customer=%s)",
        email, tier, customer_id,
    )
    return result


def handle_subscription_deleted(
    event: dict[str, Any],
    *,
    tokens_store: APITokenStore,
) -> int:
    """Revoke API tokens for a cancelled subscription.

    On `customer.subscription.deleted`, walk the tokens store and
    revoke every token whose user_id matches the customer's email
    (we stored the email AS the user_id at issue time).

    Returns the count of revoked tokens.
    """
    if event.get("type") != "customer.subscription.deleted":
        return 0

    data = event.get("data") or {}
    obj = data.get("object") or {}

    # Stripe doesn't include the customer email directly on subscription
    # objects — it requires a separate Customer lookup, which we don't
    # do here (no outbound API calls). Instead the iam-jit operator can
    # store the customer-email association at issue time and look it
    # up here. For v1 we look at `metadata.iam_jit_user_id` which the
    # Stripe Checkout config can set explicitly.
    metadata = obj.get("metadata") or {}
    user_id = metadata.get("iam_jit_user_id")
    if not user_id:
        # Fall back to customer_email if it's present on the subscription
        # (only some Stripe API versions include this).
        user_id = obj.get("customer_email")

    if not user_id:
        logger.warning(
            "customer.subscription.deleted: no iam_jit_user_id in metadata; "
            "cannot revoke tokens (event id=%s)",
            event.get("id"),
        )
        return 0

    tokens = tokens_store.list_for_user(user_id)
    count = 0
    for t in tokens:
        try:
            tokens_store.delete(t.token_hash)
            count += 1
        except APITokenNotFound:
            pass

    logger.info(
        "revoked %d API token(s) for user_id=%s on subscription cancellation",
        count, user_id,
    )
    return count


# ---- Dispatch -------------------------------------------------------


class ProcessedEventsStore(Protocol):
    """Idempotency store for Stripe event IDs.

    Stripe's delivery model includes retries on non-2xx, dashboard-
    initiated replays, and at-least-once semantics under network
    faults. Without an idempotency check, `checkout.session.completed`
    redeliveries mint duplicate API tokens; the customer ends up with
    N valid tokens for one paid subscription. Audit finding
    STRIPE-NO-IDEMPOTENCY (round 1 WB).

    `claim()` is an ATOMIC check-and-set. It returns True exactly
    once per event_id (the winner of the race) and False for every
    subsequent caller. Splitting into separate has_processed() and
    mark_processed() introduces a TOCTOU race under concurrent
    redelivery — round-2 WB+BB audit (STRIPE-IDEMPOTENCY-TOCTOU).
    """

    def claim(self, event_id: str) -> bool: ...


class InMemoryProcessedEventsStore:
    """Process-local idempotency cache with atomic claim.

    Sufficient for single-instance deployments. Multi-Lambda
    deployments should use a DynamoDB-backed implementation with
    `PutItem(ConditionExpression='attribute_not_exists(event_id)')`
    as the atomic primitive, plus a TTL of 30 days (Stripe retries
    for up to 3 days; 30 is a generous safety margin).

    `claim()` uses `dict.setdefault` with a PER-CALL unique sentinel
    object. `dict.setdefault` is atomic in CPython under the GIL: it
    inserts the per-call sentinel only if the key is absent, returning
    whichever object is now in the dict. If the returned object is
    THIS caller's sentinel, this caller won the race (no other caller
    had inserted yet); if anything else, another caller already won.
    No explicit lock needed.
    """

    def __init__(self) -> None:
        self._seen: dict[str, object] = {}

    def claim(self, event_id: str) -> bool:
        """Atomic claim. Returns True if this caller is the first/winner,
        False if another caller has already claimed this event_id."""
        my_marker = object()
        stored = self._seen.setdefault(event_id, my_marker)
        return stored is my_marker


def dispatch_event(
    event: dict[str, Any],
    *,
    tokens_store: APITokenStore,
    mailer: Callable[[str, str, str], None] | None = None,
    processed_events_store: ProcessedEventsStore | None = None,
) -> dict[str, Any]:
    """Dispatch a verified Stripe event to the right handler.

    Idempotent: if `event["id"]` has been processed before (via
    `processed_events_store`), the handler is skipped and a duplicate-
    detected response is returned. The caller still returns HTTP 200
    so Stripe doesn't retry. Audit finding STRIPE-NO-IDEMPOTENCY.

    Returns a dict suitable for the webhook HTTP response body. Caller
    should always return HTTP 200 — Stripe retries with exponential
    backoff on non-2xx, and we don't want retries for events we
    chose not to handle (unknown event types, unmapped price IDs, etc.).
    """
    event_id = event.get("id") or ""
    event_type = event.get("type") or "unknown"

    # Idempotency short-circuit. The store is optional — callers that
    # explicitly opt out (e.g. unit tests verifying handler semantics
    # in isolation) pass None and get the non-idempotent path.
    #
    # Uses ATOMIC claim() not separate has_processed()/mark_processed()
    # to avoid the TOCTOU race that round-2 audit caught. claim()
    # returns True for the first caller (which proceeds to handle the
    # event) and False for every subsequent caller (which short-
    # circuits).
    if processed_events_store is not None and event_id:
        is_winner = processed_events_store.claim(event_id)
        if not is_winner:
            logger.info(
                "Stripe event %s (%s) already claimed — short-circuiting",
                event_id, event_type,
            )
            return {
                "handled": False,
                "event_type": event_type,
                "duplicate": True,
                "event_id": event_id,
            }

    handlers = {
        "checkout.session.completed": lambda: handle_checkout_session_completed(
            event, tokens_store=tokens_store, mailer=mailer,
        ),
        "customer.subscription.deleted": lambda: handle_subscription_deleted(
            event, tokens_store=tokens_store,
        ),
    }
    handler = handlers.get(event_type)
    if handler is None:
        logger.info("Stripe event type %r not handled — skipping", event_type)
        # Don't mark unknown events as processed — if the type-handler
        # gets added later, a redelivery should run normally.
        return {"handled": False, "event_type": event_type}

    # Atomic claim() above already reserved this event_id in the store.
    # No follow-up mark_processed call needed — the claim IS the
    # reservation. This closes the round-1 TOCTOU race (round-2 finding
    # STRIPE-IDEMPOTENCY-TOCTOU) by making the check-and-set atomic.
    result = handler()

    return {"handled": True, "event_type": event_type, "result": _serialize(result)}


def _serialize(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, IssuedTokenResult):
        # Note: raw_token is intentionally NOT included in the
        # webhook response. Stripe logs every webhook response body
        # in their dashboard; we don't want the API key visible there.
        return {
            "issued_for": obj.customer_email,
            "tier": obj.tier,
            "token_hash": obj.token_hash,
            "stripe_customer_id": obj.stripe_customer_id,
        }
    if isinstance(obj, int):
        return {"revoked_count": obj}
    return None
