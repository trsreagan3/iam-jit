from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


def test_submit_requires_auth(client: TestClient, request_payload: dict) -> None:
    resp = client.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 401


def test_submit_as_dev_noai_mode(as_dev: TestClient, request_payload: dict) -> None:
    """In NoAI mode, submission succeeds AND the deterministic risk
    review block is populated.

    The deterministic scorer has no LLM dependency. Suppressing the
    score in NoAI mode would also disable auto-approve — leaving
    requests stuck at `pending` forever in single-admin / sandbox
    deployments where self-approve is forbidden. See the dev-agent
    feedback report (the bug this test pins).

    Only the LLM-generated narrative (`llm_narrative`) is suppressed
    in NoAI mode — that's the legitimate AI-feature-surface gate.
    """
    resp = as_dev.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["request"]["status"]["state"] in ("pending", "approved")
    assert body["request"]["status"]["owner"] == "email:dev@example.com"
    assert "submitted_at" in body["request"]["status"]
    assert body["review"] is not None, (
        "deterministic review must populate even in NoAI mode"
    )
    assert "risk_score" in body["review"]
    assert 1 <= body["review"]["risk_score"] <= 10
    assert body["review"]["llm_narrative"] is None, (
        "LLM narrative should be suppressed in NoAI mode"
    )
    assert body["request"]["metadata"]["id"]


def test_submit_as_dev_with_llm(
    with_llm: None, as_dev: TestClient, request_payload: dict
) -> None:
    """When LLM is enabled, submission response carries a risk review block."""
    resp = as_dev.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["review"] is not None
    assert "risk_score" in body["review"]
    assert 1 <= body["review"]["risk_score"] <= 10


def test_submit_then_get_by_owner(as_dev: TestClient, request_payload: dict) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    fetched = as_dev.get(f"/api/v1/requests/{rid}")
    assert fetched.status_code == 200
    assert fetched.json()["status"]["owner"] == "email:dev@example.com"


def test_dev_cannot_view_others_requests(
    as_dev: TestClient,
    as_dev2: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev2.get(f"/api/v1/requests/{rid}")
    assert resp.status_code == 403


def test_approver_can_view_anyones_request(
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_approver.get(f"/api/v1/requests/{rid}")
    assert resp.status_code == 200


def test_list_requests_dev_sees_only_own(
    as_dev: TestClient,
    as_dev2: TestClient,
    request_payload: dict,
) -> None:
    rid_dev = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    rid_dev2 = as_dev2.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev.get("/api/v1/requests")
    assert resp.status_code == 200
    ids = {r["id"] for r in resp.json()["requests"]}
    assert rid_dev in ids
    assert rid_dev2 not in ids


def test_list_requests_approver_sees_all(
    as_dev: TestClient,
    as_dev2: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    rid_dev = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    rid_dev2 = as_dev2.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_approver.get("/api/v1/requests")
    ids = {r["id"] for r in resp.json()["requests"]}
    assert rid_dev in ids
    assert rid_dev2 in ids


def test_approve_requires_approver(
    as_dev: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev.post(f"/api/v1/requests/{rid}/approve")
    assert resp.status_code == 403


def test_approve_advances_state(
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_approver.post(f"/api/v1/requests/{rid}/approve")
    assert resp.status_code == 200, resp.text
    # After my F2 wiring, approve also synchronously provisions the role.
    # The route-test conftest stubs provision.provision() to always
    # succeed, so the final state is `active` not `provisioning`.
    state = resp.json()["request"]["status"]["state"]
    assert state == "active", state
    provisioned = resp.json()["request"]["status"].get("provisioned")
    assert provisioned is not None
    assert "role_arn" in provisioned
    assert "assume_instructions" in provisioned


def test_approver_cannot_approve_own(
    as_approver: TestClient, request_payload: dict
) -> None:
    # Approver submits their own request, then tries to approve it.
    rid = as_approver.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_approver.post(f"/api/v1/requests/{rid}/approve")
    assert resp.status_code == 403


def test_reject_advances_state(
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_approver.post(f"/api/v1/requests/{rid}/reject", json={"reason": "too broad"})
    assert resp.status_code == 200
    assert resp.json()["request"]["status"]["state"] == "rejected"


def test_request_changes_advances_state(
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_approver.post(
        f"/api/v1/requests/{rid}/request-changes",
        json={"suggestions": ["scope to specific bucket"]},
    )
    assert resp.status_code == 200
    assert resp.json()["request"]["status"]["state"] == "needs_changes"


def test_owner_can_cancel(
    as_dev: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev.post(f"/api/v1/requests/{rid}/cancel")
    assert resp.status_code == 200
    assert resp.json()["request"]["status"]["state"] == "cancelled"


def test_other_dev_cannot_cancel(
    as_dev: TestClient,
    as_dev2: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev2.post(f"/api/v1/requests/{rid}/cancel")
    # Dev2 isn't the owner — currently 403 from view check or transition.
    assert resp.status_code in {403, 404}


def test_approver_cannot_cancel_others_request(
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_approver.post(f"/api/v1/requests/{rid}/cancel")
    assert resp.status_code == 403


def test_owner_can_edit_pending(
    as_dev: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    edit = {"spec": {"description": "Updated description after first review."}}
    resp = as_dev.patch(f"/api/v1/requests/{rid}/", json=edit)
    # FastAPI tolerates trailing slash in routes via mount; if 404, retry without slash:
    if resp.status_code == 404:
        resp = as_dev.patch(f"/api/v1/requests/{rid}", json=edit)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["request"]["spec"]["description"].startswith("Updated description")


def test_other_dev_cannot_edit(
    as_dev: TestClient,
    as_dev2: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev2.patch(
        f"/api/v1/requests/{rid}",
        json={"spec": {"description": "Updated description, long enough to pass schema."}},
    )
    assert resp.status_code in {403, 404}


def test_post_comment(
    as_dev: TestClient,
    as_approver: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_approver.post(
        f"/api/v1/requests/{rid}/comments",
        json={"message": "please scope to bucket X"},
    )
    assert resp.status_code == 201
    fetched = as_dev.get(f"/api/v1/requests/{rid}").json()
    comments = fetched["status"]["comments"]
    assert any(c["author"] == "email:approver@example.com" for c in comments)


def test_get_missing_returns_404(as_admin: TestClient) -> None:
    resp = as_admin.get("/api/v1/requests/nope-not-here")
    assert resp.status_code == 404


def test_download_template_yaml(as_dev: TestClient, request_payload: dict) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev.get(f"/api/v1/requests/{rid}/download?as=yaml&mode=template")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/yaml")
    body = resp.text
    assert "apiVersion" in body
    assert "Read S3 config files" in body
    assert "status:" not in body
    assert "history:" not in body
    assert "attachment" in resp.headers["content-disposition"]
    assert ".yaml" in resp.headers["content-disposition"]


def test_download_template_json(as_dev: TestClient, request_payload: dict) -> None:
    import json as _json

    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev.get(f"/api/v1/requests/{rid}/download?as=json&mode=template")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    body = _json.loads(resp.text)
    assert "spec" in body
    assert "status" not in body
    assert body["spec"]["description"].startswith("Read S3")


def test_download_full_includes_status(as_dev: TestClient, request_payload: dict) -> None:
    import json as _json

    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev.get(f"/api/v1/requests/{rid}/download?as=json&mode=full")
    assert resp.status_code == 200
    body = _json.loads(resp.text)
    assert "status" in body
    assert body["status"]["state"] == "pending"
    assert body["status"]["owner"] == "email:dev@example.com"


def test_download_template_is_resubmittable(as_dev: TestClient, request_payload: dict) -> None:
    """A downloaded template must validate as a fresh submission body."""
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    template = as_dev.get(f"/api/v1/requests/{rid}/download?as=json&mode=template").json()
    resub = as_dev.post("/api/v1/requests", json=template)
    assert resub.status_code == 201, resub.text
    new_rid = resub.json()["request"]["metadata"]["id"]
    assert new_rid != rid


def test_download_other_users_request_forbidden(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = as_dev2.get(f"/api/v1/requests/{rid}/download?as=yaml&mode=template")
    assert resp.status_code == 403


def test_download_requires_auth(
    client: TestClient, request_payload: dict, as_dev: TestClient
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    resp = client.get(f"/api/v1/requests/{rid}/download")
    assert resp.status_code == 401
