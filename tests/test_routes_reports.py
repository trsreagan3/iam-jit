from __future__ import annotations

from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def _seed(as_dev: TestClient, as_approver: TestClient, request_payload: dict) -> str:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    as_approver.post(f"/api/v1/requests/{rid}/approve")
    return rid


def test_grants_admin_only(as_dev: TestClient) -> None:
    resp = as_dev.get("/api/v1/reports/grants")
    assert resp.status_code == 403


def test_grants_json(
    as_admin: TestClient,
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    _seed(as_dev, as_approver, request_payload)
    resp = as_admin.get("/api/v1/reports/grants")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 1
    assert "id" in body["rows"][0]


def test_grants_csv(
    as_admin: TestClient,
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    _seed(as_dev, as_approver, request_payload)
    resp = as_admin.get("/api/v1/reports/grants?format=csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    body = resp.text
    assert body.splitlines()[0].startswith("id,owner,state,access_type,")


def test_grants_filter_by_state(
    as_admin: TestClient,
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    _seed(as_dev, as_approver, request_payload)
    resp = as_admin.get("/api/v1/reports/grants?state=provisioning")
    assert resp.status_code == 200
    rows = resp.json()["rows"]
    for r in rows:
        assert r["state"] == "provisioning"


def test_approvals_report(
    as_admin: TestClient,
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    _seed(as_dev, as_approver, request_payload)
    resp = as_admin.get("/api/v1/reports/approvals")
    assert resp.status_code == 200
    rows = resp.json()["rows"]
    assert any(r["approver"] == "email:approver@example.com" and r["action"] == "approve" for r in rows)


def test_activity_report(
    as_admin: TestClient,
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    _seed(as_dev, as_approver, request_payload)
    resp = as_admin.get("/api/v1/reports/activity?user_id=email:dev@example.com")
    assert resp.status_code == 200
    rows = resp.json()["rows"]
    actions = {r["action"] for r in rows}
    assert "submit" in actions


def test_risk_distribution_with_llm(
    with_llm: None,
    as_admin: TestClient,
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    _seed(as_dev, as_approver, request_payload)
    resp = as_admin.get("/api/v1/reports/risk-distribution")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert isinstance(body["rows"], list)
    assert len(body["rows"]) == 10


def test_risk_distribution_populated_in_noai_mode(
    as_admin: TestClient,
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    """NoAI deployments DO compute deterministic risk scores at
    submission — the score has no LLM dependency and drives
    auto-approve. The histogram therefore populates regardless of
    LLM presence. Only the LLM-narrative side of the review is
    suppressed in NoAI mode. (Previously asserted the opposite — see
    the dev-agent feedback report that caught this bug.)"""
    _seed(as_dev, as_approver, request_payload)
    resp = as_admin.get("/api/v1/reports/risk-distribution")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] > 0, (
        "deterministic scoring must run in NoAI mode so auto-approve "
        "can fire and so this report has data to show"
    )


def test_users_report(as_admin: TestClient) -> None:
    resp = as_admin.get("/api/v1/reports/users")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 4


def test_users_report_csv_columns(as_admin: TestClient) -> None:
    resp = as_admin.get("/api/v1/reports/users?format=csv")
    assert resp.status_code == 200
    header = resp.text.splitlines()[0]
    assert header == "id,display_name,roles,enabled"
