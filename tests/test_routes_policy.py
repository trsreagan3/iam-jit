from __future__ import annotations

from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def test_analyze_requires_auth(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/policy/analyze",
        json={"policy": {"Version": "2012-10-17", "Statement": []}},
    )
    assert resp.status_code == 401


def test_analyze_noai_returns_questions_no_review(as_dev: TestClient) -> None:
    """NoAI mode: the analyze endpoint still returns narrowing questions
    (deterministic) but `review` is null and `ai_enabled` is False."""
    payload = {
        "description": "Read secrets",
        "access_type": "read-only",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": "*",
                }
            ],
        },
    }
    resp = as_dev.post("/api/v1/policy/analyze", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["review"] is None
    assert body["ai_enabled"] is False
    assert len(body["narrowing_questions"]) >= 1


def test_analyze_with_llm_returns_review_and_questions(
    with_llm: None, as_dev: TestClient
) -> None:
    payload = {
        "description": "Read S3 config files",
        "access_type": "read-only",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": "*",
                }
            ],
        },
    }
    resp = as_dev.post("/api/v1/policy/analyze", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["review"] is not None
    assert body["ai_enabled"] is True
    assert len(body["narrowing_questions"]) >= 1
    assert body["review"]["risk_score"] >= 6


def test_analyze_clean_policy_no_narrowing(as_dev: TestClient) -> None:
    payload = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::specific/path/file.txt",
                }
            ],
        },
    }
    resp = as_dev.post("/api/v1/policy/analyze", json=payload)
    assert resp.status_code == 200
    assert resp.json()["narrowing_questions"] == []


def test_analyze_requires_policy(as_dev: TestClient) -> None:
    resp = as_dev.post("/api/v1/policy/analyze", json={})
    assert resp.status_code == 400
