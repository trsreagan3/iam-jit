"""Shadow mode — the safe-deployment toggle.

When `IAM_JIT_SHADOW_MODE=1`, the scorer runs as normal but the
decision is OBSERVED, not enforced. Customers deploy iam-jit
alongside their existing approval workflow and watch the
scorer's verdicts for weeks before flipping it on for real.

This is the gate to enterprise adoption: no security team trusts
auto-approve without observation period. The tests pin the
behavior contract:

  1. Scoring still runs (deterministic verdict produced)
  2. State stays at `pending` regardless of would-auto-approve
  3. Audit event records the shadow decision with full detail
  4. Without IAM_JIT_SHADOW_MODE=1, behavior is unchanged
     (auto-approve fires if conditions are met)
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def _low_risk_payload() -> dict[str, Any]:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "requester": {
                "name": "Shadow Test",
                "email": "dev@example.com",
            }
        },
        "spec": {
            "description": "low-risk request for shadow-mode test",
            "access_type": "read-only",
            "duration": {"duration_hours": 1},
            "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["ec2:DescribeInstances"],
                        "Resource": [
                            "arn:aws:ec2:us-east-1:060392206767:instance/i-0123456789abcdef0"
                        ],
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
    }


def _enable_auto_approve(as_admin: TestClient) -> None:
    """Threshold low enough that the low-risk payload qualifies."""
    r = as_admin.patch(
        "/api/v1/admin/auto-approve/settings",
        json={
            "auto_approve_risk_below": 5,
            "auto_approve_quota_per_hour": 10,
            "never_auto_approve_services": [
                "iam", "organizations", "sts", "kms", "secretsmanager",
            ],
            "never_auto_approve_accounts": [],
        },
    )
    assert r.status_code == 200, r.text


# ---- Tests ----------------------------------------------------------


def test_baseline_auto_approve_fires_without_shadow_mode(
    as_admin: TestClient,
    as_dev: TestClient,
) -> None:
    """Sanity check: with auto-approve enabled and shadow mode OFF,
    a low-risk request fires the auto-approve flow (state advances
    past pending)."""
    _enable_auto_approve(as_admin)
    r = as_dev.post("/api/v1/requests", json=_low_risk_payload())
    assert r.status_code == 201, r.text
    body = r.json()
    # State advances; auto_approve_decision is populated
    assert body["request"]["status"]["state"] in (
        "provisioning", "provisioning_failed", "active",
    ), body["request"]["status"]
    assert body["auto_approve_decision"] is not None
    assert body["auto_approve_decision"]["auto_approve"] is True


def test_shadow_mode_keeps_state_at_pending(
    as_admin: TestClient,
    as_dev: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With IAM_JIT_SHADOW_MODE=1, the SAME low-risk request that
    would have auto-approved must stay at `pending`."""
    monkeypatch.setenv("IAM_JIT_SHADOW_MODE", "1")
    _enable_auto_approve(as_admin)

    r = as_dev.post("/api/v1/requests", json=_low_risk_payload())
    assert r.status_code == 201, r.text
    body = r.json()

    # State did NOT advance
    assert body["request"]["status"]["state"] == "pending", (
        f"shadow mode must keep state at pending; got "
        f"{body['request']['status']['state']}"
    )
    # No provisioned block, no role
    assert body["request"]["status"].get("provisioned") is None
    # The scorer DID still run (review block populated)
    assert body["review"] is not None
    # The auto-approve DECISION is computed and surfaced (so customers
    # see what WOULD have happened) — but it's an observation,
    # not an action.
    assert body["auto_approve_decision"] is not None
    assert body["auto_approve_decision"]["auto_approve"] is True


def test_shadow_mode_emits_audit_event(
    as_admin: TestClient,
    as_dev: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shadow decision must be captured in the audit trail so
    admins can review observation-period metrics."""
    monkeypatch.setenv("IAM_JIT_SHADOW_MODE", "1")
    _enable_auto_approve(as_admin)

    captured: list[dict[str, Any]] = []

    def _capture(**kwargs: Any) -> None:
        captured.append(kwargs)

    from iam_jit import audit as audit_mod

    monkeypatch.setattr(audit_mod, "emit", _capture)

    r = as_dev.post("/api/v1/requests", json=_low_risk_payload())
    assert r.status_code == 201

    shadow_events = [
        e for e in captured
        if e.get("kind", "").startswith("shadow.")
    ]
    assert len(shadow_events) >= 1, (
        f"expected at least one shadow.* audit event; got "
        f"{[e.get('kind') for e in captured]}"
    )
    ev = shadow_events[0]
    assert ev["details"]["shadow_mode"] is True
    assert ev["details"]["would_auto_approve"] is True
    assert ev["actor"] == "system:shadow-mode"


def test_shadow_mode_records_would_route_to_review_for_high_risk(
    as_admin: TestClient,
    as_dev: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the scorer says 'route to review' AND shadow mode is on,
    the audit event uses the `shadow.would_route_to_review` kind
    so admins can split the observation metric by direction."""
    monkeypatch.setenv("IAM_JIT_SHADOW_MODE", "1")
    _enable_auto_approve(as_admin)

    captured: list[dict[str, Any]] = []

    def _capture(**kwargs: Any) -> None:
        captured.append(kwargs)

    from iam_jit import audit as audit_mod

    monkeypatch.setattr(audit_mod, "emit", _capture)

    # High-risk request: iam:PassRole on * is the classic priv-esc
    payload = _low_risk_payload()
    payload["spec"]["policy"] = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": ["*"],
            }
        ],
    }
    payload["spec"]["access_type"] = "read-write"

    r = as_dev.post("/api/v1/requests", json=payload)
    assert r.status_code == 201, r.text
    body = r.json()

    # Scorer correctly flagged it; would not have auto-approved
    assert body["request"]["status"]["state"] == "pending"
    assert body["auto_approve_decision"]["auto_approve"] is False

    # Audit event uses the route-to-review variant
    review_events = [
        e for e in captured
        if e.get("kind") == "shadow.would_route_to_review"
    ]
    assert len(review_events) >= 1, (
        f"expected shadow.would_route_to_review event; got "
        f"{[e.get('kind') for e in captured]}"
    )


def test_shadow_mode_off_by_default(
    as_admin: TestClient,
    as_dev: TestClient,
) -> None:
    """No IAM_JIT_SHADOW_MODE env var = production behavior. The
    request advances past pending. This pins the default."""
    _enable_auto_approve(as_admin)
    r = as_dev.post("/api/v1/requests", json=_low_risk_payload())
    body = r.json()
    assert body["request"]["status"]["state"] != "pending"
