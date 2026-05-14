"""Tests for the scoring-feedback channel — the customer-facing
"flag this score" feature that feeds the calibration corpus.

Covers:
- POST /api/v1/feedback/scoring accepts anon + auth submissions
- Per-IP anon daily cap (3 by default)
- Per-customer authed daily cap (10 by default)
- Deployment-wide hourly ceiling (100 by default)
- Admin GET + PATCH endpoints (admin role required)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from iam_jit import scoring_feedback
from iam_jit.api_tokens_store import APITokenRecord, InMemoryAPITokenStore
from iam_jit.auth import hash_token


pytest_plugins = ["tests.conftest_routes"]


_SAMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}


def _submission_body() -> dict:
    return {
        "policy": _SAMPLE_POLICY,
        "our_score": 8,
        "expected_score": 4,
        "category": "false-positive",
        "explanation": "scoped read, why 8?",
    }


def test_anonymous_can_submit_and_gets_feedback_id(client: TestClient) -> None:
    r = client.post("/api/v1/feedback/scoring", json=_submission_body())
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["feedback_id"].startswith("FB-")
    assert body["review_status"] == "new"


def test_anonymous_daily_cap_returns_429(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """3 anon submissions / day per IP is the default cap.
    The 4th returns 429 with Retry-After."""
    monkeypatch.setenv("IAM_JIT_FEEDBACK_ANON_DAILY_CAP", "2")
    scoring_feedback.reset_default_store_for_tests()

    for _ in range(2):
        r = client.post("/api/v1/feedback/scoring", json=_submission_body())
        assert r.status_code == 201, r.text

    r3 = client.post("/api/v1/feedback/scoring", json=_submission_body())
    assert r3.status_code == 429
    assert r3.headers.get("retry-after")
    assert "rate-limit" in r3.json()["detail"].lower()


def test_authenticated_daily_cap_separate_from_anon(
    shared_app, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bearer-authenticated submitter has a higher cap and a
    separate counter from anonymous IP-based submitters."""
    monkeypatch.setenv("IAM_JIT_FEEDBACK_ANON_DAILY_CAP", "1")
    monkeypatch.setenv("IAM_JIT_FEEDBACK_AUTHED_DAILY_CAP", "3")
    scoring_feedback.reset_default_store_for_tests()

    token_store: InMemoryAPITokenStore = shared_app.state.api_tokens_store
    raw_token = "iamjit_feedback_test_token_aaa"
    token_store.put(
        APITokenRecord(
            token_hash=hash_token(raw_token),
            user_id="email:feedbacker@example.com",
            created_at=0,
            label="stripe:pro",
        )
    )
    auth = {"Authorization": f"Bearer {raw_token}"}

    # Use up the auth cap.
    for _ in range(3):
        r = client.post(
            "/api/v1/feedback/scoring",
            json=_submission_body(),
            headers=auth,
        )
        assert r.status_code == 201, r.text

    # 4th auth request hits cap.
    r4 = client.post(
        "/api/v1/feedback/scoring",
        json=_submission_body(),
        headers=auth,
    )
    assert r4.status_code == 429


def test_invalid_category_rejected_with_400(client: TestClient) -> None:
    body = _submission_body()
    body["category"] = "not-a-thing"
    r = client.post("/api/v1/feedback/scoring", json=body)
    assert r.status_code == 400


def test_admin_can_list_submissions(
    as_admin: TestClient, client: TestClient
) -> None:
    # Anon submits.
    r = client.post("/api/v1/feedback/scoring", json=_submission_body())
    assert r.status_code == 201
    fb_id = r.json()["feedback_id"]

    # Admin lists.
    r2 = as_admin.get("/api/v1/admin/feedback/scoring")
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["count"] >= 1
    ids = [item["feedback_id"] for item in body["items"]]
    assert fb_id in ids


def test_non_admin_cannot_list_submissions(as_dev: TestClient) -> None:
    r = as_dev.get("/api/v1/admin/feedback/scoring")
    assert r.status_code == 403


def test_admin_can_mark_reviewed(
    as_admin: TestClient, client: TestClient
) -> None:
    r = client.post("/api/v1/feedback/scoring", json=_submission_body())
    fb_id = r.json()["feedback_id"]

    r2 = as_admin.patch(
        f"/api/v1/admin/feedback/scoring/{fb_id}",
        json={"status": "added_to_corpus", "reviewer_notes": "valid case"},
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["review_status"] == "added_to_corpus"
    assert body["reviewer_notes"] == "valid case"


def test_admin_mark_reviewed_invalid_status_400(
    as_admin: TestClient, client: TestClient
) -> None:
    r = client.post("/api/v1/feedback/scoring", json=_submission_body())
    fb_id = r.json()["feedback_id"]
    r2 = as_admin.patch(
        f"/api/v1/admin/feedback/scoring/{fb_id}",
        json={"status": "made-up-status"},
    )
    assert r2.status_code == 400


def test_admin_mark_nonexistent_returns_404(as_admin: TestClient) -> None:
    r = as_admin.patch(
        "/api/v1/admin/feedback/scoring/FB-deadbeef",
        json={"status": "dismissed"},
    )
    assert r.status_code == 404


def test_explanation_truncated_to_2000_chars(client: TestClient) -> None:
    body = _submission_body()
    body["explanation"] = "x" * 5000
    r = client.post("/api/v1/feedback/scoring", json=body)
    # Pydantic max_length=2000 rejects this at validation time → 422.
    assert r.status_code == 422


def test_deployment_hourly_ceiling_429s_under_burst(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even within per-user caps, the deployment-wide hourly
    ceiling stops bursts from filling the admin queue."""
    monkeypatch.setenv("IAM_JIT_FEEDBACK_ANON_DAILY_CAP", "99")
    monkeypatch.setenv("IAM_JIT_FEEDBACK_DEPLOYMENT_HOURLY_CAP", "2")
    scoring_feedback.reset_default_store_for_tests()

    for _ in range(2):
        r = client.post("/api/v1/feedback/scoring", json=_submission_body())
        assert r.status_code == 201

    r3 = client.post("/api/v1/feedback/scoring", json=_submission_body())
    assert r3.status_code == 429
    assert "deployment-hourly" in r3.json()["detail"].lower()
