"""Pinned tests for per-account LLM policy wired into /api/v1/score.

Per [[per-account-llm-policy]] memo. The score endpoint accepts
an optional `account_id` field. When provided AND the account is
registered with `llm_policy=deterministic_only`, the LLM backend
is skipped regardless of the caller's tier or budget.

Decision flow (cheapest gate first):
  1. caller_tier in {pro, team, enterprise}? if not → skip LLM
  2. account.llm_policy set? honor it
  3. deployment default? honor it
  4. per-customer LLM budget cap? gate it
  5. LLM backend init succeeds? proceed; else fall back to deterministic
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def _payload(account_id: str | None = None) -> dict:
    body = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::foo/*",
                }
            ],
        },
        "access_type": "read-only",
        "duration_hours": 1,
    }
    if account_id is not None:
        body["account_id"] = account_id
    return body


# ---------------------------------------------------------------------------


def test_response_includes_new_llm_skip_fields(client: TestClient) -> None:
    """Schema includes llm_used + llm_skip_reason + llm_skip_detail."""
    resp = client.post("/api/v1/score", json=_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert "llm_used" in body
    assert "llm_skip_reason" in body
    assert "llm_skip_detail" in body


def test_free_tier_caller_skips_llm_with_tier_reason(client: TestClient) -> None:
    """Anonymous / free-tier callers don't get LLM. Skip reason is
    tier_does_not_use_llm, not anything more alarming."""
    resp = client.post("/api/v1/score", json=_payload())
    body = resp.json()
    assert body["llm_used"] is False
    assert body["llm_skip_reason"] == "tier_does_not_use_llm"


def test_invalid_account_id_format_rejected_by_pydantic(client: TestClient) -> None:
    """account_id must be 12-digit AWS account ID per pydantic pattern."""
    payload = _payload(account_id="not-an-account-id")
    resp = client.post("/api/v1/score", json=payload)
    assert resp.status_code == 422  # pydantic validation


def test_account_id_optional(client: TestClient) -> None:
    """No account_id should still work; falls through to deployment default."""
    resp = client.post("/api/v1/score", json=_payload(account_id=None))
    assert resp.status_code == 200


def test_account_id_valid_format_accepted(client: TestClient) -> None:
    """12-digit account_id passes validation; resolves via accounts_store
    (which the test app has). When the account isn't registered, falls
    through to deployment default."""
    resp = client.post("/api/v1/score", json=_payload(account_id="111122223333"))
    assert resp.status_code == 200
    # In the test app, this account isn't registered + no env policy set,
    # so we fall through to deployment-default (use_llm). But caller is
    # anonymous/free tier, so llm is still skipped for tier reason.
    body = resp.json()
    assert body["llm_used"] is False
    assert body["llm_skip_reason"] == "tier_does_not_use_llm"


def test_backward_compat_existing_fields_unchanged(client: TestClient) -> None:
    """Adding the new fields must NOT break existing ones."""
    resp = client.post("/api/v1/score", json=_payload())
    body = resp.json()
    # Existing required fields still present
    assert "score" in body
    assert "tier" in body
    assert "would_auto_approve_at_threshold_5" in body
    assert "factors" in body
    assert "suggestions" in body
    assert "analyzer" in body
    assert "policy_fingerprint" in body
    assert "api_version" in body
    assert "llm_budget_exceeded" in body
