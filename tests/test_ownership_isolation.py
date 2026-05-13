"""Comprehensive ownership-isolation tests.

A non-admin, non-approver requester (`as_dev`) must only see and act on
their own requests. Approvers (`as_approver`) and admins (`as_admin`)
see all. This file exercises every read and write surface to catch any
regression where a check is forgotten.

Each test follows the pattern:
  1. dev1 submits a request
  2. dev2 (different non-admin) attempts to access/act on it
  3. assert 403/404 (never 200 with leakage)
"""

from __future__ import annotations

from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


# ---- LIST surfaces ----


def test_list_api_filters_by_owner_for_dev(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    """GET /api/v1/requests as a requester returns only their own."""
    rid_dev = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    rid_dev2 = as_dev2.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    listed = as_dev.get("/api/v1/requests").json()
    ids = {r["id"] for r in listed["requests"]}
    assert rid_dev in ids
    assert rid_dev2 not in ids


def test_list_api_returns_all_for_approver(
    as_dev: TestClient, as_dev2: TestClient, as_approver: TestClient, request_payload: dict
) -> None:
    rid_dev = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    rid_dev2 = as_dev2.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    ids = {r["id"] for r in as_approver.get("/api/v1/requests").json()["requests"]}
    assert rid_dev in ids
    assert rid_dev2 in ids


def test_list_api_returns_all_for_admin(
    as_dev: TestClient, as_dev2: TestClient, as_admin: TestClient, request_payload: dict
) -> None:
    rid_dev = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    rid_dev2 = as_dev2.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    ids = {r["id"] for r in as_admin.get("/api/v1/requests").json()["requests"]}
    assert rid_dev in ids
    assert rid_dev2 in ids


def test_web_home_page_only_lists_own_requests_for_dev(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid_dev = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    rid_dev2 = as_dev2.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    body = as_dev.get("/").text
    # dev's own id appears (linked from the table).
    assert rid_dev in body
    # dev2's id MUST NOT leak into dev's home view.
    assert rid_dev2 not in body


# ---- READ surfaces ----


def test_api_get_by_id_403_for_other_dev(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    assert as_dev2.get(f"/api/v1/requests/{rid}").status_code == 403


def test_api_get_by_id_200_for_owner_approver_admin(
    as_dev: TestClient,
    as_approver: TestClient,
    as_admin: TestClient,
    request_payload: dict,
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    assert as_dev.get(f"/api/v1/requests/{rid}").status_code == 200
    assert as_approver.get(f"/api/v1/requests/{rid}").status_code == 200
    assert as_admin.get(f"/api/v1/requests/{rid}").status_code == 200


def test_web_detail_page_403_for_other_dev(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    assert as_dev2.get(f"/requests/{rid}", follow_redirects=False).status_code == 403


def test_download_403_for_other_dev(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    for fmt in ("yaml", "json"):
        for mode in ("template", "full"):
            r = as_dev2.get(
                f"/api/v1/requests/{rid}/download?as={fmt}&mode={mode}"
            )
            assert r.status_code == 403, f"{fmt}/{mode} leaked"


def test_assume_instructions_403_for_other_dev(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    assert as_dev2.get(f"/api/v1/requests/{rid}/assume").status_code == 403


# ---- WRITE/ACTION surfaces ----


def test_other_dev_cannot_edit(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    r = as_dev2.patch(
        f"/api/v1/requests/{rid}",
        json={"spec": {"description": "hijacked description, long enough."}},
    )
    assert r.status_code in {403, 404}


def test_other_dev_cannot_cancel(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    assert as_dev2.post(f"/api/v1/requests/{rid}/cancel").status_code in {403, 404}


def test_other_dev_cannot_approve(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    assert as_dev2.post(f"/api/v1/requests/{rid}/approve").status_code == 403


def test_other_dev_cannot_reject(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    r = as_dev2.post(
        f"/api/v1/requests/{rid}/reject", json={"reason": "no thanks"}
    )
    assert r.status_code == 403


def test_other_dev_cannot_request_changes(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    r = as_dev2.post(
        f"/api/v1/requests/{rid}/request-changes", json={"suggestions": ["x"]}
    )
    assert r.status_code == 403


def test_other_dev_cannot_post_comment(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    r = as_dev2.post(
        f"/api/v1/requests/{rid}/comments", json={"message": "snooping comment"}
    )
    # Either 403 (view denied) or 404 (treat as not-existing). Never 201.
    assert r.status_code in {403, 404}


def test_other_dev_cannot_retry_provisioning(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    """Retry is approver-only — dev2 hitting it on dev's request is 403."""
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    r = as_dev2.post(f"/api/v1/requests/{rid}/retry-provisioning")
    assert r.status_code == 403


# ---- ADMIN-ONLY surfaces are out of reach for dev ----


def test_dev_cannot_access_queue(as_dev: TestClient) -> None:
    assert as_dev.get("/queue", follow_redirects=False).status_code == 403


def test_dev_cannot_access_admin_routes(as_dev: TestClient) -> None:
    """Admin-only endpoints reject dev with 403."""
    forbidden = [
        ("GET", "/api/v1/users"),
        ("GET", "/api/v1/accounts"),
        ("POST", "/api/v1/accounts/onboarding/preview"),
        ("GET", "/api/v1/reports/grants"),
        ("GET", "/api/v1/reports/audit-log"),
    ]
    for method, path in forbidden:
        r = as_dev.request(
            method,
            path,
            json={"account_id": "060392206767"} if method == "POST" else None,
        )
        assert r.status_code in {403, 404}, f"{method} {path} returned {r.status_code}"


def test_dev_sees_only_own_in_intake_api(
    as_dev: TestClient, as_dev2: TestClient, request_payload: dict
) -> None:
    """The intake API is for live conversation flow — it doesn't surface
    other users' requests, but verify it doesn't leak via the response shape."""
    rid_other = as_dev2.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    # dev calling intake/turn shouldn't be able to retrieve dev2's request data.
    # The intake endpoint doesn't take a request_id, so this is implicit, but
    # we exercise it for completeness.
    r = as_dev.post(
        "/api/v1/intake/turn",
        json={"conversation": [{"role": "user", "content": "hi"}]},
    )
    # 200 is fine — the endpoint runs the LLM. Just verify dev2's request id
    # doesn't appear in the response.
    if r.status_code == 200:
        assert rid_other not in r.text


# ---- Comments visibility on their own requests ----


def test_dev_can_comment_on_own_request(
    as_dev: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    r = as_dev.post(
        f"/api/v1/requests/{rid}/comments", json={"message": "additional context"}
    )
    assert r.status_code == 201, r.text


def test_dev_can_view_and_download_own(
    as_dev: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    assert as_dev.get(f"/api/v1/requests/{rid}").status_code == 200
    assert as_dev.get(f"/api/v1/requests/{rid}/download?as=json&mode=template").status_code == 200
    assert as_dev.get(f"/api/v1/requests/{rid}/assume").status_code == 200


# ---- Tokens isolation ----


def test_dev_cannot_revoke_other_devs_token(
    as_dev: TestClient, as_dev2: TestClient
) -> None:
    """Already covered in test_routes_tokens, but here for the central
    isolation audit so a future regression in the token surface is caught
    by this file too."""
    th = as_dev.post("/api/v1/tokens", json={"label": "mine"}).json()["token_hash"]
    r = as_dev2.delete(f"/api/v1/tokens/{th}")
    assert r.status_code == 403
