"""/api/v1/requests/preview — pre-submit risk + auto-approve preview.

The UX-critical flow: a user (or agent) iterates on a policy in
the UI and clicks "re-evaluate" between each tightening. The
preview endpoint returns:

  - the deterministic risk score + factors + suggestions
  - the current auto-approve threshold
  - whether THIS request would auto-approve right now
  - concrete advice for getting under the threshold

NO state mutation — the preview is purely informational. The
quota counter doesn't advance; no request is stored; no audit
event is emitted.

This is the "dial" the user asked for: see your current level vs
the threshold, iterate to drop under it, only then submit.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit import settings_store


pytest_plugins = ["tests.conftest_routes"]


def _payload(
    *,
    action: str = "ec2:DescribeInstances",
    resource: str = "arn:aws:ec2:us-east-1:111111111111:instance/i-abc",
    access_type: str = "read-only",
    description: str = "look up the public IP of one instance",
) -> dict[str, Any]:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
        "spec": {
            "description": description,
            "access_type": access_type,
            "accounts": [{"account_id": "111111111111", "regions": ["us-east-1"]}],
            "duration": {"duration_hours": 1},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [action],
                        "Resource": resource,
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
    }


def test_preview_reports_score_and_no_auto_approve_by_default(
    as_dev: TestClient,
) -> None:
    """Default Settings() → threshold None → never auto-approves.
    The preview surfaces that clearly so the user knows what's
    needed before they submit."""
    settings_store.reset_default_store_for_tests()

    r = as_dev.post("/api/v1/requests/preview", json=_payload())
    assert r.status_code == 200, r.text
    body = r.json()
    assert "review" in body
    assert "risk_score" in body["review"]
    assert body["would_auto_approve"] is False
    assert body["auto_approve_threshold"] is None
    assert any("disabled" in a.lower() for a in body["advice"])


def test_preview_indicates_auto_approve_for_low_risk_below_threshold(
    as_dev: TestClient,
) -> None:
    """When threshold is set and the request scores below it, the
    preview should report would_auto_approve=True."""
    settings_store.reset_default_store_for_tests()
    store = settings_store.get_default_store()
    store.put(
        settings_store.Settings(
            auto_approve_risk_below=4,
            never_auto_approve_services=(),
        ),
    )

    r = as_dev.post("/api/v1/requests/preview", json=_payload())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["auto_approve_threshold"] == 4
    assert body["review"]["risk_score"] <= 3, (
        f"a single-instance describe should score low; got {body['review']}"
    )
    assert body["would_auto_approve"] is True
    assert body["auto_approve_decision"]["reason"] == "success"


def test_preview_returns_advice_when_score_above_threshold(
    as_dev: TestClient,
) -> None:
    """A wildcard request scores high → preview tells the user
    exactly how far they are from auto-approve threshold + how to
    drop."""
    settings_store.reset_default_store_for_tests()
    store = settings_store.get_default_store()
    store.put(
        settings_store.Settings(
            auto_approve_risk_below=3,
            never_auto_approve_services=(),
        ),
    )

    payload = _payload()
    payload["spec"]["access_type"] = "read-write"
    payload["spec"]["policy"]["Statement"][0]["Action"] = ["s3:*"]
    payload["spec"]["policy"]["Statement"][0]["Resource"] = "*"

    r = as_dev.post("/api/v1/requests/preview", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["would_auto_approve"] is False
    assert body["review"]["risk_score"] >= 7
    # Advice should mention dropping the score / tightening scope.
    advice_blob = " ".join(body["advice"]).lower()
    assert "tighten" in advice_blob or "narrow" in advice_blob or "drop" in advice_blob or "scope" in advice_blob


def test_preview_does_not_advance_quota(as_dev: TestClient) -> None:
    """Repeated preview calls must NOT burn the user's auto-approve
    quota. Iteration should be free."""
    settings_store.reset_default_store_for_tests()
    store = settings_store.get_default_store()
    store.put(
        settings_store.Settings(
            auto_approve_risk_below=4,
            auto_approve_quota_per_hour=2,
            never_auto_approve_services=(),
        ),
    )

    # Hit preview 10 times.
    for _ in range(10):
        r = as_dev.post("/api/v1/requests/preview", json=_payload())
        assert r.status_code == 200
        assert r.json()["would_auto_approve"] is True, (
            "preview should report would_auto_approve=True every time; "
            "if the real quota were being consumed, eventually it'd "
            "report over_quota — and that's the bug we're guarding "
            "against."
        )


def test_preview_does_not_store_request(as_dev: TestClient) -> None:
    """Submitting via /preview must NOT create a request record.
    Verify by listing requests after a preview."""
    settings_store.reset_default_store_for_tests()
    pre_list = as_dev.get("/api/v1/requests").json()
    pre_count = len(pre_list.get("requests", []))

    r = as_dev.post("/api/v1/requests/preview", json=_payload())
    assert r.status_code == 200

    post_list = as_dev.get("/api/v1/requests").json()
    post_count = len(post_list.get("requests", []))
    assert pre_count == post_count, (
        f"preview created a request: {pre_count} → {post_count}"
    )


def test_max_role_duration_caps_submissions(
    as_dev: TestClient,
) -> None:
    """Admin sets max_role_duration_hours=24. A 48h submission must
    be refused with HTTP 400 + an actionable error message. A 1h
    submission succeeds."""
    settings_store.reset_default_store_for_tests()
    store = settings_store.get_default_store()
    store.put(
        settings_store.Settings(max_role_duration_hours=24),
    )

    # Refused: 48h > 24h cap
    payload_long = _payload()
    payload_long["spec"]["duration"]["duration_hours"] = 48
    r = as_dev.post("/api/v1/requests", json=payload_long)
    assert r.status_code == 400, r.text
    assert "exceeds" in r.text.lower() or "max" in r.text.lower()

    # Allowed: 1h ≤ 24h cap
    payload_short = _payload()
    payload_short["spec"]["duration"]["duration_hours"] = 1
    r = as_dev.post("/api/v1/requests", json=payload_short)
    assert r.status_code == 201, r.text


def test_max_role_duration_disabled_by_default(as_dev: TestClient) -> None:
    """With no max set, any duration is allowed (subject to other
    rules)."""
    settings_store.reset_default_store_for_tests()
    payload = _payload()
    payload["spec"]["duration"]["duration_hours"] = 24 * 60  # 60 days
    r = as_dev.post("/api/v1/requests", json=payload)
    assert r.status_code == 201


def test_preview_blocked_service_surfaces_in_decision(
    as_dev: TestClient,
) -> None:
    """When a request scores low but touches a blocklisted service,
    the preview's auto_approve_decision must show why."""
    settings_store.reset_default_store_for_tests()
    store = settings_store.get_default_store()
    store.put(
        settings_store.Settings(
            auto_approve_risk_below=10,
            never_auto_approve_services=("iam",),
        ),
    )

    payload = _payload(
        action="iam:GetRole",
        resource="arn:aws:iam::111111111111:role/example",
    )
    r = as_dev.post("/api/v1/requests/preview", json=payload)
    body = r.json()
    assert body["would_auto_approve"] is False
    assert body["auto_approve_decision"]["reason"] == "service_blocked"
    assert body["auto_approve_decision"]["details"]["service"] == "iam"
