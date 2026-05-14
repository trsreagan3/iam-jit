"""End-to-end test for the LLM-budget wiring at /api/v1/score.

Pins:
- Anonymous callers get no LLM narrative (free tier).
- Bearer with a Pro-tier `iamjit_*` token gets LLM narrative
  AND ticks the budget counter.
- A Pro-tier token over its monthly budget gets
  `llm_budget_exceeded=true` and no narrative, but the
  deterministic score still works.
"""

from __future__ import annotations

import pytest

from iam_jit import llm_budget
from iam_jit.api_tokens_store import (
    APITokenRecord,
    InMemoryAPITokenStore,
)
from iam_jit.auth import hash_token


pytest_plugins = ["tests.conftest_routes"]


_LOW_RISK_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/data.csv",
        }
    ],
}


def _score_request_body() -> dict:
    return {
        "policy": _LOW_RISK_POLICY,
        "access_type": "read-only",
        "duration_hours": 1,
    }


@pytest.fixture(autouse=True)
def _reset_budget_store() -> None:
    llm_budget.reset_default_store_for_tests()


def test_anonymous_score_returns_no_narrative_and_no_budget_flag(
    client,
) -> None:
    r = client.post("/api/v1/score", json=_score_request_body())
    assert r.status_code == 200, r.text
    body = r.json()
    # Anonymous = free tier = deterministic only. Narrative is None,
    # budget flag is False (the caller never had a budget to exceed).
    assert body["llm_narrative"] is None
    assert body["llm_budget_exceeded"] is False


def test_pro_tier_token_marks_budget_consumed_even_if_backend_noops(
    shared_app, client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bearer token whose label is `stripe:pro` ticks the LLM
    budget counter. We don't assert the narrative content (the
    LLM backend in test is NoOp) — we DO assert the counter
    incremented, which proves the wiring."""
    # Issue a Pro-tier API token for a test customer.
    token_store: InMemoryAPITokenStore = shared_app.state.api_tokens_store
    raw_token = "iamjit_pro_customer_test_token_abc123"
    token_store.put(
        APITokenRecord(
            token_hash=hash_token(raw_token),
            user_id="email:procustomer@example.com",
            created_at=0,
            label="stripe:pro",
        )
    )

    # Score with the Pro bearer.
    r = client.post(
        "/api/v1/score",
        json=_score_request_body(),
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert r.status_code == 200, r.text

    # Budget store should now show one consumption for this customer.
    usage = llm_budget.get_default_store().usage_for(
        "email:procustomer@example.com"
    )
    assert usage == 1


def test_pro_tier_over_budget_returns_llm_budget_exceeded_flag(
    shared_app, client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the Pro tier's cap is reached, the next request returns
    `llm_budget_exceeded=true` and `llm_narrative=null`. The score
    itself is unchanged."""
    # Force the Pro cap to 1 for this test so we hit it after one call.
    monkeypatch.setenv("IAM_JIT_LLM_BUDGET_PRO", "1")
    llm_budget.reset_default_store_for_tests()

    token_store: InMemoryAPITokenStore = shared_app.state.api_tokens_store
    raw_token = "iamjit_pro_over_budget_token_xyz789"
    token_store.put(
        APITokenRecord(
            token_hash=hash_token(raw_token),
            user_id="email:overbudget@example.com",
            created_at=0,
            label="stripe:pro",
        )
    )

    auth = {"Authorization": f"Bearer {raw_token}"}

    # First request consumes the only budget slot.
    r1 = client.post("/api/v1/score", json=_score_request_body(), headers=auth)
    assert r1.status_code == 200
    assert r1.json()["llm_budget_exceeded"] is False

    # Second request: over budget.
    r2 = client.post("/api/v1/score", json=_score_request_body(), headers=auth)
    assert r2.status_code == 200
    body = r2.json()
    assert body["llm_budget_exceeded"] is True
    assert body["llm_narrative"] is None
    # Score itself is unaffected — deterministic floor holds.
    assert isinstance(body["score"], int)
    assert 1 <= body["score"] <= 10


def test_unknown_tier_in_token_label_falls_back_to_free(
    shared_app, client,
) -> None:
    """If Stripe sets a label we don't recognize (e.g.,
    `stripe:platinum-deluxe`), normalize to free — no narrative,
    no budget consumed."""
    token_store: InMemoryAPITokenStore = shared_app.state.api_tokens_store
    raw_token = "iamjit_unknown_tier_token_qqq"
    token_store.put(
        APITokenRecord(
            token_hash=hash_token(raw_token),
            user_id="email:unknown@example.com",
            created_at=0,
            label="stripe:platinum-deluxe",
        )
    )

    r = client.post(
        "/api/v1/score",
        json=_score_request_body(),
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["llm_narrative"] is None
    assert body["llm_budget_exceeded"] is False
    # Counter should NOT have been ticked.
    usage = llm_budget.get_default_store().usage_for("email:unknown@example.com")
    assert usage == 0


def test_indie_tier_token_does_not_consume_budget(
    shared_app, client,
) -> None:
    """Indie is deterministic-only by tier definition — does not
    consume LLM budget even though it's an authenticated tier."""
    token_store: InMemoryAPITokenStore = shared_app.state.api_tokens_store
    raw_token = "iamjit_indie_customer_token_nnn"
    token_store.put(
        APITokenRecord(
            token_hash=hash_token(raw_token),
            user_id="email:indie@example.com",
            created_at=0,
            label="stripe:indie",
        )
    )

    r = client.post(
        "/api/v1/score",
        json=_score_request_body(),
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert r.status_code == 200
    assert r.json()["llm_narrative"] is None
    assert r.json()["llm_budget_exceeded"] is False
    usage = llm_budget.get_default_store().usage_for("email:indie@example.com")
    assert usage == 0
