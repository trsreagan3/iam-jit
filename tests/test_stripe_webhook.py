"""Tests for the Stripe webhook handler.

Two layers:
  - `iam_jit.stripe_webhook` business logic (signature verification,
    plan→tier mapping, event dispatch, token issuance, revocation).
  - `iam_jit.routes.webhooks_stripe` HTTP endpoint integration.

We don't use the `stripe` Python SDK — the signature scheme is small
enough to verify manually with stdlib HMAC. The tests construct
valid signatures the same way Stripe does.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit import stripe_webhook
from iam_jit.api_tokens_store import InMemoryAPITokenStore

pytest_plugins = ["tests.conftest_routes"]


# ---- Helpers --------------------------------------------------------


def _sign(payload: bytes, secret: str, *, t: int | None = None) -> tuple[str, int]:
    """Construct a valid Stripe-Signature header value for `payload`."""
    if t is None:
        t = int(time.time())
    signed = f"{t}.".encode() + payload
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={t},v1={sig}", t


def _checkout_event(
    *,
    email: str = "buyer@example.com",
    price_id: str = "price_indie_test",
    event_id: str = "evt_test_1",
) -> dict[str, Any]:
    return {
        "id": event_id,
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer_email": email,
                "customer": "cus_test_123",
                "subscription": "sub_test_456",
                "line_items": {
                    "data": [
                        {
                            "price": {"id": price_id},
                        }
                    ]
                },
            }
        },
    }


# ---- Signature verification -----------------------------------------


def test_signature_verifies_when_correct() -> None:
    secret = "whsec_test_supersecret"
    payload = json.dumps({"id": "evt_test"}).encode()
    sig_header, _ = _sign(payload, secret)

    event = stripe_webhook.verify_stripe_signature(
        payload=payload, sig_header=sig_header, secret=secret,
    )
    assert event["id"] == "evt_test"


def test_signature_rejects_when_secret_mismatches() -> None:
    payload = b'{"id":"evt"}'
    sig_header, _ = _sign(payload, "secret_a")
    with pytest.raises(stripe_webhook.InvalidStripeSignature):
        stripe_webhook.verify_stripe_signature(
            payload=payload, sig_header=sig_header, secret="secret_b",
        )


def test_signature_rejects_when_payload_tampered() -> None:
    secret = "whsec"
    sig_header, _ = _sign(b'{"id":"evt"}', secret)
    with pytest.raises(stripe_webhook.InvalidStripeSignature):
        stripe_webhook.verify_stripe_signature(
            payload=b'{"id":"different"}',
            sig_header=sig_header, secret=secret,
        )


def test_signature_rejects_when_timestamp_too_old() -> None:
    secret = "whsec"
    payload = b'{"id":"evt"}'
    # Sign with a timestamp from 30 minutes ago
    old_t = int(time.time()) - (30 * 60)
    sig_header, _ = _sign(payload, secret, t=old_t)
    with pytest.raises(stripe_webhook.InvalidStripeSignature) as exc_info:
        stripe_webhook.verify_stripe_signature(
            payload=payload, sig_header=sig_header, secret=secret,
            tolerance_seconds=300,
        )
    assert "tolerance" in str(exc_info.value).lower()


def test_signature_rejects_empty_header() -> None:
    with pytest.raises(stripe_webhook.InvalidStripeSignature):
        stripe_webhook.verify_stripe_signature(
            payload=b'{"id":"evt"}', sig_header="", secret="whsec",
        )


def test_signature_rejects_when_no_v1_scheme() -> None:
    """v0 alone (legacy) must not authenticate; we require v1."""
    secret = "whsec"
    payload = b'{}'
    t = int(time.time())
    v0_sig = hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()
    sig_header = f"t={t},v0={v0_sig}"
    with pytest.raises(stripe_webhook.InvalidStripeSignature):
        stripe_webhook.verify_stripe_signature(
            payload=payload, sig_header=sig_header, secret=secret,
        )


def test_signature_rejects_when_server_secret_unset() -> None:
    payload = b'{}'
    sig_header, _ = _sign(payload, "whsec")
    with pytest.raises(stripe_webhook.InvalidStripeSignature):
        stripe_webhook.verify_stripe_signature(
            payload=payload, sig_header=sig_header, secret="",
        )


# ---- Plan → tier mapping --------------------------------------------


def test_tier_mapping_known_price(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "STRIPE_PRICE_ID_TO_TIER",
        json.dumps({"price_indie_test": "indie", "price_pro_test": "pro"}),
    )
    assert stripe_webhook.get_tier_for_price("price_indie_test") == "indie"
    assert stripe_webhook.get_tier_for_price("price_pro_test") == "pro"


def test_tier_mapping_unknown_price_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIPE_PRICE_ID_TO_TIER", '{"price_a": "indie"}')
    assert stripe_webhook.get_tier_for_price("price_zzz") is None


def test_tier_mapping_malformed_env_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIPE_PRICE_ID_TO_TIER", "not-json-at-all")
    assert stripe_webhook.get_tier_for_price("price_a") is None


def test_tier_mapping_env_unset_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIPE_PRICE_ID_TO_TIER", raising=False)
    assert stripe_webhook.get_tier_for_price("price_a") is None


# ---- Handler: checkout.session.completed ---------------------------


def test_checkout_completed_issues_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "STRIPE_PRICE_ID_TO_TIER", '{"price_indie_test": "indie"}',
    )
    store = InMemoryAPITokenStore()
    event = _checkout_event(email="alice@example.com", price_id="price_indie_test")

    result = stripe_webhook.handle_checkout_session_completed(
        event, tokens_store=store,
    )
    assert result is not None
    assert result.customer_email == "alice@example.com"
    assert result.tier == "indie"
    assert result.raw_token.startswith("iamjit_")
    assert len(result.raw_token) > 20
    # Token persisted
    records = store.list_for_user("alice@example.com")
    assert len(records) == 1
    assert records[0].label == "stripe:indie"
    # Raw token is NOT what's stored — only the hash
    assert result.token_hash != result.raw_token
    assert records[0].token_hash == result.token_hash


def test_checkout_completed_skips_unknown_price(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIPE_PRICE_ID_TO_TIER", '{"price_indie": "indie"}')
    store = InMemoryAPITokenStore()
    event = _checkout_event(price_id="price_unknown_xyz")
    result = stripe_webhook.handle_checkout_session_completed(
        event, tokens_store=store,
    )
    assert result is None
    assert store.list_all() == []


def test_checkout_completed_skips_missing_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIPE_PRICE_ID_TO_TIER", '{"price_indie_test": "indie"}')
    store = InMemoryAPITokenStore()
    event = _checkout_event()
    # Strip the email
    event["data"]["object"]["customer_email"] = None
    event["data"]["object"]["customer_details"] = {}
    result = stripe_webhook.handle_checkout_session_completed(
        event, tokens_store=store,
    )
    assert result is None
    assert store.list_all() == []


def test_checkout_completed_calls_mailer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIPE_PRICE_ID_TO_TIER", '{"price_pro": "pro"}')
    store = InMemoryAPITokenStore()
    calls: list[tuple[str, str, str]] = []

    def fake_mailer(email: str, token: str, tier: str) -> None:
        calls.append((email, token, tier))

    event = _checkout_event(email="bob@example.com", price_id="price_pro")
    result = stripe_webhook.handle_checkout_session_completed(
        event, tokens_store=store, mailer=fake_mailer,
    )
    assert result is not None
    assert len(calls) == 1
    assert calls[0][0] == "bob@example.com"
    assert calls[0][2] == "pro"
    assert calls[0][1].startswith("iamjit_")


def test_checkout_completed_mailer_failure_does_not_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the mailer raises (SES down, sender unverified, etc.), the
    webhook must still successfully issue the token. The operator can
    redeliver the key out-of-band."""
    monkeypatch.setenv("STRIPE_PRICE_ID_TO_TIER", '{"price_pro": "pro"}')
    store = InMemoryAPITokenStore()

    def broken_mailer(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("SES is down")

    event = _checkout_event(price_id="price_pro")
    result = stripe_webhook.handle_checkout_session_completed(
        event, tokens_store=store, mailer=broken_mailer,
    )
    assert result is not None
    assert store.list_all()


# ---- Handler: customer.subscription.deleted -----------------------


def test_subscription_deleted_revokes_tokens() -> None:
    store = InMemoryAPITokenStore()
    # Pre-populate two tokens for one user
    from iam_jit.api_tokens_store import APITokenRecord
    store.put(APITokenRecord("hash-a", "carol@example.com", 100, "stripe:indie"))
    store.put(APITokenRecord("hash-b", "carol@example.com", 200, "stripe:indie"))
    # And one for an unrelated user
    store.put(APITokenRecord("hash-c", "dave@example.com", 300, None))

    event = {
        "id": "evt_canc",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "metadata": {"iam_jit_user_id": "carol@example.com"},
            }
        },
    }
    n = stripe_webhook.handle_subscription_deleted(event, tokens_store=store)
    assert n == 2
    # carol's tokens gone; dave's intact
    assert store.list_for_user("carol@example.com") == []
    assert len(store.list_for_user("dave@example.com")) == 1


def test_subscription_deleted_without_user_id_metadata_skips() -> None:
    store = InMemoryAPITokenStore()
    event = {
        "id": "evt", "type": "customer.subscription.deleted",
        "data": {"object": {}},
    }
    n = stripe_webhook.handle_subscription_deleted(event, tokens_store=store)
    assert n == 0


# ---- Dispatch -------------------------------------------------------


def test_dispatch_unhandled_event_does_not_echo_event_type() -> None:
    """BB3-10 closure — the not-handled response no longer echoes
    the caller's event_type. Operator visibility lives in logs."""
    store = InMemoryAPITokenStore()
    event = {"id": "evt", "type": "invoice.paid", "data": {"object": {}}}
    result = stripe_webhook.dispatch_event(event, tokens_store=store)
    assert result["handled"] is False
    assert "event_type" not in result


def test_dispatch_handles_checkout_completed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIPE_PRICE_ID_TO_TIER", '{"price_indie_test": "indie"}')
    store = InMemoryAPITokenStore()
    event = _checkout_event()
    result = stripe_webhook.dispatch_event(event, tokens_store=store)
    assert result["handled"] is True
    assert result["event_type"] == "checkout.session.completed"
    # Critical: the raw_token is NOT in the response (it'd leak via Stripe's
    # webhook logs UI). Only hash + email + tier.
    inner = result["result"]
    assert "raw_token" not in inner
    assert "token_hash" in inner
    assert inner["issued_for"] == "buyer@example.com"
    assert inner["tier"] == "indie"


# ---- HTTP endpoint --------------------------------------------------


def test_endpoint_returns_503_when_secret_unset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    r = client.post(
        "/api/v1/webhooks/stripe",
        content=b"{}",
        headers={"Stripe-Signature": "t=1,v1=deadbeef"},
    )
    assert r.status_code == 503
    assert "not configured" in r.json()["detail"]


def test_endpoint_returns_400_on_bad_signature(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    r = client.post(
        "/api/v1/webhooks/stripe",
        content=b'{"id":"evt"}',
        headers={"Stripe-Signature": "t=1,v1=wrong"},
    )
    assert r.status_code == 400
    assert "signature" in r.json()["detail"].lower()


def test_endpoint_returns_200_on_valid_event(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    monkeypatch.setenv("STRIPE_PRICE_ID_TO_TIER", '{"price_indie_test": "indie"}')

    payload = json.dumps(_checkout_event(email="eve@example.com")).encode()
    sig_header, _ = _sign(payload, "whsec_test")

    r = client.post(
        "/api/v1/webhooks/stripe",
        content=payload,
        headers={
            "Stripe-Signature": sig_header,
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["handled"] is True
    assert body["result"]["issued_for"] == "eve@example.com"
    assert body["result"]["tier"] == "indie"
    # raw_token never exposed in response body
    assert "raw_token" not in body["result"]
