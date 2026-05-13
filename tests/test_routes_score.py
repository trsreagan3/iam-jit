"""Tests for the standalone scoring API (POST /api/v1/score).

The scoring API is the launch feature — pipelines, CI/CD, and AI
agents call it to "get a score for an IAM policy" without going
through the full submission lifecycle. The tests cover:

  - Happy path: simple low-risk policy returns the expected shape
  - Validation: malformed payloads return 400 with useful errors
  - Auth: when IAM_JIT_SCORE_API_KEY is set, the header is required
  - Rate limiting: per-IP cap enforces with 429 + Retry-After
  - Deterministic-only: no LLM dependency in the API path
  - Stability: the policy_fingerprint is consistent across calls
  - Admin context: additional_sensitive_services bumps the score
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def _low_risk_payload() -> dict:
    return {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ec2:DescribeInstances"],
                    "Resource": [
                        "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890"
                    ],
                }
            ],
        },
        "access_type": "read-only",
        "duration_hours": 1,
    }


def _high_risk_payload() -> dict:
    return {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:DeleteObject", "s3:DeleteBucket"],
                    "Resource": ["*"],
                }
            ],
        },
        "access_type": "read-write",
        "duration_hours": 1,
    }


# ---- Happy path ------------------------------------------------------


def test_score_low_risk_policy_returns_full_shape(client: TestClient) -> None:
    """The endpoint is unauthenticated by default — anyone can score."""
    r = client.post("/api/v1/score", json=_low_risk_payload())
    assert r.status_code == 200, r.text
    body = r.json()
    # Schema fields all present
    for key in (
        "score", "tier", "would_auto_approve_at_threshold_5",
        "factors", "suggestions", "llm_narrative", "analyzer",
        "policy_fingerprint", "api_version",
    ):
        assert key in body, f"missing key: {key}"
    # Calibration
    assert 1 <= body["score"] <= 3, body
    assert body["tier"] == "low"
    assert body["would_auto_approve_at_threshold_5"] is True
    assert body["analyzer"] == "deterministic"
    assert body["llm_narrative"] is None  # NoAI in tests
    assert body["api_version"] == "v1"
    assert body["policy_fingerprint"].startswith("sha256:")


def test_score_high_risk_policy_correctly_flagged(client: TestClient) -> None:
    r = client.post("/api/v1/score", json=_high_risk_payload())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["score"] >= 7, body  # destructive on wildcard
    assert body["tier"] == "high"
    assert body["would_auto_approve_at_threshold_5"] is False
    assert any("destructive" in f.lower() for f in body["factors"]), body


def test_score_response_is_stable_across_calls(client: TestClient) -> None:
    """Same input → same output. The fingerprint AND the score
    must be deterministic — callers rely on this for CI caching."""
    payload = _low_risk_payload()
    r1 = client.post("/api/v1/score", json=payload).json()
    r2 = client.post("/api/v1/score", json=payload).json()
    assert r1["score"] == r2["score"]
    assert r1["policy_fingerprint"] == r2["policy_fingerprint"]
    assert r1["factors"] == r2["factors"]


# ---- Validation -----------------------------------------------------


def test_score_rejects_missing_policy(client: TestClient) -> None:
    r = client.post("/api/v1/score", json={"access_type": "read-only"})
    assert r.status_code == 422  # pydantic validation


def test_score_rejects_policy_without_statement(client: TestClient) -> None:
    r = client.post(
        "/api/v1/score",
        json={"policy": {"Version": "2012-10-17"}},
    )
    assert r.status_code == 400
    assert "Statement" in r.json()["detail"]


def test_score_rejects_policy_thats_not_an_object(client: TestClient) -> None:
    r = client.post("/api/v1/score", json={"policy": "not a policy"})
    # pydantic rejects type mismatch at the model boundary
    assert r.status_code == 422


def test_score_rejects_invalid_access_type(client: TestClient) -> None:
    """The scorer accepts any string for access_type today; this test
    pins behavior — invalid values don't crash, they just route through
    the read-write code path (since they don't match 'read-only')."""
    payload = _low_risk_payload()
    payload["access_type"] = "banana"
    r = client.post("/api/v1/score", json=payload)
    # Today: accepted (banana != read-only → treated as read-write).
    # If we tighten this to reject, change the assertion + add a 400 test.
    assert r.status_code == 200


def test_score_rejects_out_of_range_duration(client: TestClient) -> None:
    payload = _low_risk_payload()
    payload["duration_hours"] = 999999
    r = client.post("/api/v1/score", json=payload)
    assert r.status_code == 422


# ---- Admin context overrides ----------------------------------------


def test_score_respects_additional_sensitive_services(
    client: TestClient,
) -> None:
    """The admin-context extension points are exposed in the API too —
    integrators can declare org-specific sensitivity inline per
    request without needing a separate config endpoint."""
    payload = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["athena:GetQueryResults"],
                    "Resource": ["*"],
                }
            ],
        },
        "access_type": "read-only",
        "additional_sensitive_services": ["athena"],
    }
    r = client.post("/api/v1/score", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    # With athena marked sensitive + wildcard resource, the scorer
    # should bump the score above the threshold-of-5 cutoff.
    assert body["score"] >= 5, body


# ---- Auth -----------------------------------------------------------


def test_score_no_auth_when_key_not_configured(client: TestClient) -> None:
    """The default open-API posture: scoring is free, no auth needed."""
    r = client.post("/api/v1/score", json=_low_risk_payload())
    assert r.status_code == 200


def test_score_requires_auth_when_key_configured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_SCORE_API_KEY", "secret-test-key")
    r = client.post("/api/v1/score", json=_low_risk_payload())
    assert r.status_code == 401
    assert "API key" in r.json()["detail"]


def test_score_accepts_bearer_api_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_SCORE_API_KEY", "secret-test-key")
    r = client.post(
        "/api/v1/score",
        json=_low_risk_payload(),
        headers={"Authorization": "Bearer secret-test-key"},
    )
    assert r.status_code == 200


def test_score_accepts_bare_api_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tolerate 'Authorization: <key>' without 'Bearer ' prefix —
    common in agent code that doesn't follow RFC 6750 exactly."""
    monkeypatch.setenv("IAM_JIT_SCORE_API_KEY", "secret-test-key")
    r = client.post(
        "/api/v1/score",
        json=_low_risk_payload(),
        headers={"Authorization": "secret-test-key"},
    )
    assert r.status_code == 200


def test_score_rejects_wrong_api_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_SCORE_API_KEY", "secret-test-key")
    r = client.post(
        "/api/v1/score",
        json=_low_risk_payload(),
        headers={"Authorization": "Bearer WRONG"},
    )
    assert r.status_code == 401


# ---- Rate limiting --------------------------------------------------


def test_score_rate_limit_enforced(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Set the cap very low and hammer until 429."""
    monkeypatch.setenv("IAM_JIT_SCORE_RATE_PER_MINUTE", "3")
    # Recreate the limiter so the new env value is picked up
    from iam_jit.routes import score as score_mod
    score_mod._reset_limiter_for_tests()

    for _ in range(3):
        r = client.post("/api/v1/score", json=_low_risk_payload())
        assert r.status_code == 200, r.text
    # 4th call exceeds the cap
    r = client.post("/api/v1/score", json=_low_risk_payload())
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    assert int(r.headers["Retry-After"]) >= 1
    assert "rate limit" in r.json()["detail"].lower()


# ---- Calibration cross-checks ---------------------------------------


def test_score_matches_calibration_corpus(client: TestClient) -> None:
    """The API endpoint and the deterministic scorer must produce
    the SAME verdict for the same policy. Any divergence would
    mean the API is doing extra work / different work, which is a
    bug. This pins them together."""
    from iam_jit import review

    api_resp = client.post("/api/v1/score", json=_high_risk_payload()).json()
    direct = review.analyze_policy(
        _high_risk_payload()["policy"],
        {"spec": {
            "access_type": "read-write",
            "duration": {"duration_hours": 1},
            "resource_constraints": [],
        }},
    )
    assert api_resp["score"] == direct.risk_score
    assert api_resp["factors"] == list(direct.risk_factors)
