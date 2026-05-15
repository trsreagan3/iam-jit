"""Tests for the threshold-aware feedback fields on /score.

The standalone /score endpoint previously returned only a
hardcoded `would_auto_approve_at_threshold_5` hint. Agents
calling /score in CI/MCP flows now also get:

  - auto_approve_threshold: the deployment's actual configured
    threshold (from settings_store)
  - would_auto_approve: threshold-aware boolean (vs the hardcoded
    5 variant)
  - threshold_advice: human/agent-readable "drop by N+ to qualify"
    when the score is at-or-above the threshold

When auto-approve is disabled on the deployment, all three new
fields are null (the endpoint falls back to the hardcoded hint).
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
                    "Resource": "*",
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
                    "Action": ["*"],
                    "Resource": "*",
                }
            ],
        },
        "access_type": "read-write",
        "duration_hours": 24,
    }


def _set_threshold(shared_app, threshold: int | None) -> None:
    """Helper: configure the auto-approve threshold on the deployment."""
    from iam_jit import settings_store as _s

    store = _s.get_default_store()
    settings = store.get()
    settings = settings._replace(auto_approve_risk_below=threshold) \
        if hasattr(settings, "_replace") else settings
    # Modern store uses dataclass; tolerate both.
    import dataclasses
    if dataclasses.is_dataclass(settings):
        settings = dataclasses.replace(settings, auto_approve_risk_below=threshold)
    store.put(settings)


# ---------------------------------------------------------------------------


def test_response_includes_new_threshold_fields(client: TestClient) -> None:
    """Schema should include the three new fields even when null."""
    resp = client.post("/api/v1/score", json=_low_risk_payload())
    assert resp.status_code == 200
    body = resp.json()
    # Backward-compat field still present.
    assert "would_auto_approve_at_threshold_5" in body
    # New fields present (may be null if settings not set).
    assert "auto_approve_threshold" in body
    assert "would_auto_approve" in body
    assert "threshold_advice" in body


def test_low_risk_under_threshold_gives_no_advice(
    shared_app, client: TestClient,
) -> None:
    """A low-scoring policy under the deployment threshold gets
    would_auto_approve=True and no threshold_advice."""
    _set_threshold(shared_app, threshold=5)
    resp = client.post("/api/v1/score", json=_low_risk_payload())
    body = resp.json()
    assert body["score"] < 5
    assert body["auto_approve_threshold"] == 5
    assert body["would_auto_approve"] is True
    # No advice — user is already in the auto-approve band.
    assert body["threshold_advice"] is None


def test_high_risk_above_threshold_includes_drop_by_advice(
    shared_app, client: TestClient,
) -> None:
    """A high-scoring policy above the threshold should include
    explicit "drop by N+ to qualify" advice in threshold_advice."""
    _set_threshold(shared_app, threshold=4)
    resp = client.post("/api/v1/score", json=_high_risk_payload())
    body = resp.json()
    assert body["score"] >= 4
    assert body["auto_approve_threshold"] == 4
    assert body["would_auto_approve"] is False
    advice = body["threshold_advice"]
    assert advice is not None
    # Must reference the threshold + the drop-by amount.
    assert "threshold" in advice.lower() or "qualify" in advice.lower()
    assert "Drop the score by" in advice
    # Mentions concrete tightening levers.
    assert any(s in advice for s in ("ARN", "wildcard", "duration", "splitting"))


def test_advice_drop_by_matches_arithmetic(
    shared_app, client: TestClient,
) -> None:
    """The 'drop by N+' in advice should match (score - threshold + 1)."""
    _set_threshold(shared_app, threshold=4)
    resp = client.post("/api/v1/score", json=_high_risk_payload())
    body = resp.json()
    if body["would_auto_approve"]:
        pytest.skip("Test policy scored under threshold; can't probe advice arithmetic")
    expected_gap = body["score"] - body["auto_approve_threshold"] + 1
    advice = body["threshold_advice"]
    assert f"Drop the score by {expected_gap}+" in advice


def test_threshold_disabled_returns_null_fields(
    shared_app, client: TestClient,
) -> None:
    """When auto-approve is disabled on the deployment
    (auto_approve_risk_below=None), the new fields are null but
    the hardcoded-5 backward-compat flag still ships."""
    _set_threshold(shared_app, threshold=None)
    resp = client.post("/api/v1/score", json=_low_risk_payload())
    body = resp.json()
    assert body["auto_approve_threshold"] is None
    assert body["would_auto_approve"] is None
    assert body["threshold_advice"] is None
    # Backward compat still present.
    assert "would_auto_approve_at_threshold_5" in body
    assert isinstance(body["would_auto_approve_at_threshold_5"], bool)


def test_backward_compat_threshold_5_flag_unchanged(
    shared_app, client: TestClient,
) -> None:
    """The hardcoded-5 flag MUST still ship and equal (score < 5),
    independent of the deployment's configured threshold. Existing
    callers (CI scripts, GitHub Action) depend on this exact field."""
    _set_threshold(shared_app, threshold=2)  # different from 5
    resp = client.post("/api/v1/score", json=_low_risk_payload())
    body = resp.json()
    expected = body["score"] < 5
    assert body["would_auto_approve_at_threshold_5"] is expected
