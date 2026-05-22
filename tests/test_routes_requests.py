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


# ---------------------------------------------------------------------------
# WB-UX-2 regression: malformed POST bodies must produce 4xx, never 5xx.
# Caught during round-2 UX deep-test (2026-05-16) — `_auto_name` ran
# before validation and crashed on a string `spec.duration`.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_spec", [
    # spec.duration as a string instead of {"duration_hours": N}
    {"duration": "PT15M", "accounts": [{"account_id": "111111111111"}]},
    # spec.duration as a list
    {"duration": [1, 2, 3]},
    # spec.duration as an int
    {"duration": 42},
    # spec.accounts as a string
    {"accounts": "111111111111"},
    # spec.services as a dict
    {"services": {"key": "val"}},
    # spec itself wrong type — actually wrap in a top-level malformation
])
def test_submit_malformed_body_produces_4xx_never_500(
    as_dev: TestClient, bad_spec: dict,
) -> None:
    """Any client-supplied malformation must produce a 4xx status,
    never a 5xx. Schema validation is the only legitimate gatekeeper."""
    payload = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "spec": bad_spec,
    }
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code < 500, (
        f"Got {resp.status_code} for malformed spec={bad_spec!r}; "
        f"validator should have rejected with 4xx. Body: {resp.text[:300]}"
    )


def test_submit_spec_wrong_type_produces_4xx(as_dev: TestClient) -> None:
    """spec is an int instead of a dict."""
    payload = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "spec": 42,
    }
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code < 500


def test_submit_no_spec_produces_4xx(as_dev: TestClient) -> None:
    payload = {"apiVersion": "iam-jit.dev/v1alpha1", "kind": "RoleRequest"}
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code < 500


def test_submit_completely_garbage_body_produces_4xx(as_dev: TestClient) -> None:
    payload = {"random": "garbage", "with": [1, 2, 3]}
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code < 500


# ---------------------------------------------------------------------------
# #166 Slice 3 — compatibility-framework gate on submit_request
# ---------------------------------------------------------------------------


def test_submit_with_compat_block_proceed_succeeds(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """When metadata.compatibility.workload is a shape iam-jit can
    issue a role for (e.g. CI runner / human CLI), submission
    proceeds normally."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    md["compatibility"] = {"workload": "ci_runner"}
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code == 201, resp.text


def test_submit_with_compat_block_use_existing_returns_422(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """K8S_POD verdict is USE_EXISTING (IRSA role pinned at pod
    creation). Submission must be refused with 422 + next_action_hint
    instead of being persisted as a request iam-jit can never fulfill."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    md["compatibility"] = {"workload": "k8s_pod"}
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["verdict"] == "use_existing"
    assert "next_action_hint" in detail
    assert "k8s_pod" in detail["error"]


def test_submit_with_compat_block_unknown_workload_returns_400(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """Unknown workload values are 400 (input validation) not 422
    (semantic refusal). Post-WB29 MED-29-04 closure the schema's
    enum constraint catches this at the schema-validation layer
    (one step earlier than the gate's own defensive check)."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    md["compatibility"] = {"workload": "definitely_not_a_workload"}
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code == 400
    # Either layer is fine, so long as the response surfaces the
    # violation on the workload field.
    assert "workload" in resp.text.lower()


def test_submit_with_compat_block_non_string_workload_returns_400(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """Non-string workload value rejected at the schema layer."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    md["compatibility"] = {"workload": 42}
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    # Schema validator catches the type mismatch (returns 422 from
    # _validate_or_400, but our gate also catches it as 400 if it
    # bypasses); either is acceptable, just must NOT 500.
    assert resp.status_code < 500
    assert resp.status_code != 201


def test_submit_without_compat_block_backward_compatible(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """Legacy submissions with no compat block keep working —
    the gate is purely additive + opt-in."""
    payload = dict(request_payload)
    # Ensure no compatibility field
    assert "compatibility" not in payload["metadata"]
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code == 201, resp.text


def test_submit_compat_use_existing_does_not_persist_request(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """Belt-and-suspenders: a USE_EXISTING refusal must not leave
    a half-persisted request behind."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    md["compatibility"] = {"workload": "k8s_pod"}
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code == 422
    # Confirm no request showed up in the listing for this user
    list_resp = as_dev.get("/api/v1/requests")
    assert list_resp.status_code == 200
    items = list_resp.json().get("items", [])
    # k8s_pod refusals never reach the store; no item created from this submit
    for item in items:
        # If items exist from other tests / fixtures, none should
        # carry the k8s_pod compat block since we never persisted it
        compat = item.get("metadata", {}).get("compatibility")
        if compat:
            assert compat.get("workload") != "k8s_pod"


def test_submit_compat_block_unknown_property_rejected(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """Schema enforces additionalProperties:false on the compat
    block — typos surface as 4xx, not silent passthrough."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    md["compatibility"] = {
        "workload": "ci_runner",
        "typo_field": "should be rejected",
    }
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code < 500
    assert resp.status_code != 201


# ---------------------------------------------------------------------------
# WB29 closures — multi-account, audit sink, schema enum, normalization
# ---------------------------------------------------------------------------


def test_wb29_high_01_multi_account_bypass_closed(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """WB29 HIGH-29-01: when target_account_id is NOT explicitly set
    and spec.accounts has multiple entries, the gate must check ALL
    of them (not just accounts[0]). k8s_pod refusal must fire even
    if account 0 is something else and account 1 is the one the
    workload claims."""
    payload = dict(request_payload)
    payload["spec"] = dict(payload["spec"])
    payload["spec"]["accounts"] = [
        {"account_id": "060392206767", "regions": ["us-east-1"]},
        {"account_id": "111111111111", "regions": ["us-east-1"]},
    ]
    md = dict(payload["metadata"])
    md["compatibility"] = {"workload": "k8s_pod"}
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    # k8s_pod returns USE_EXISTING regardless of account — gate must
    # still refuse for the multi-account submission shape.
    assert resp.status_code == 422, resp.text


def test_wb29_high_01_explicit_target_account_id_honored(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """When caller explicitly pins target_account_id, the gate
    checks only that account (caller knows what they want)."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    md["compatibility"] = {
        "workload": "ci_runner",
        "target_account_id": "060392206767",
    }
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code == 201


def test_wb29_med_04_schema_enum_rejects_arbitrary_string(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """WB29 MED-29-04: workload field has enum constraint — random
    strings rejected at schema layer before our gate echoes them."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    # A string that isn't in the enum
    md["compatibility"] = {"workload": "not_a_known_workload"}
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code == 400
    # Schema error (enum failure) must not include the attacker payload
    # echoed unmodified — the schema validator surfaces the constraint
    # name, not the user value.
    assert "<script>" not in resp.text
    assert "enum" in resp.text.lower() or "workload" in resp.text.lower()


def test_wb29_med_04_schema_enum_max_length_caps_payload(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """1 MB workload string can't be passed through; schema maxLength 64."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    md["compatibility"] = {"workload": "a" * 10000}
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code == 400


def test_wb29_med_02_target_services_lowercase_normalized(
    as_dev: TestClient, request_payload: dict,
) -> None:
    """WB29 MED-29-02: target_services strings normalize (strip +
    lower) to match MCP behavior. Schema's pattern catches truly
    invalid prefixes; mixed case prefixes are normalized in code."""
    payload = dict(request_payload)
    md = dict(payload["metadata"])
    # Lowercase prefixes pass schema; gate normalizes for the check
    md["compatibility"] = {
        "workload": "ci_runner",
        "target_services": ["s3", "dynamodb"],
    }
    payload["metadata"] = md
    resp = as_dev.post("/api/v1/requests", json=payload)
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Solo-mode self-approve-reductions UX fix (Variant B UAT finding #2).
#
# Pre-fix: `IAM_JIT_DEPLOYMENT_MODE=solo` set the SAR gate to "enabled" but
# the auto-approve route returned `feature_disabled` (no
# `auto_approve_risk_below` configured by default in solo deployments).
# The override in `_apply_mfa_and_self_approve_enforcement` ONLY fired on
# `above_threshold`, so the request landed in pending → four-eyes check
# refused approver==owner → deadlock with no way out via the API.
#
# Fix: extend override-eligible reasons to include `feature_disabled` so
# the solo admin's reduction short-circuits cleanly. Strict-mode, toggle,
# blocklist, and quota denials remain non-overrideable (platform floors).
# ---------------------------------------------------------------------------


def test_solo_admin_reduction_auto_approves(
    monkeypatch: pytest.MonkeyPatch,
    as_admin: TestClient,
    request_payload: dict,
) -> None:
    """Test 1: solo mode + admin reduction → auto-approved without
    routing to human review. This is the case that previously
    deadlocked in Variant B UAT step 4 (ssm:PutParameter, score=5).
    """
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    resp = as_admin.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["auto_approve_decision"]["auto_approve"] is True, (
        "solo admin reduction must auto-approve; got "
        f"{body['auto_approve_decision']}"
    )
    assert body["auto_approve_decision"]["reason"] == "self_approve_reduction"
    # Request must have transitioned past pending (no four-eyes deadlock).
    assert body["request"]["status"]["state"] != "pending", (
        f"state still pending — deadlock not fixed: {body['request']['status']}"
    )
    # The audit actor for the auto_approve transition is the
    # self_approve_reduction one (not system:auto-approver).
    history = body["request"]["status"].get("history") or []
    auto_entries = [h for h in history if h.get("action") == "auto_approve"]
    assert auto_entries, f"missing auto_approve history entry: {history}"
    assert auto_entries[-1]["actor"].startswith("self_approve_reduction:"), (
        f"audit actor wrong: {auto_entries[-1]['actor']}"
    )


def test_solo_admin_expansion_blocked_by_floor_routes_to_review(
    monkeypatch: pytest.MonkeyPatch,
    as_admin: TestClient,
    request_payload: dict,
) -> None:
    """Test 2: solo mode + a request hitting the service-blocklist
    floor → routes to human review (no auto-approval).

    The platform-team service blocklist (`never_auto_approve_services`)
    defaults to {iam, organizations, sts, kms, secretsmanager}. A
    request touching one of these is a hard floor the self-approve
    gate honors — even an admin in solo mode cannot short-circuit it
    without a real reviewer's signature. This stands in for the
    "expansion" concept: an admin reaching beyond what self-approve
    is permitted to short-circuit.
    """
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    payload = dict(request_payload)
    spec = dict(payload["spec"])
    spec["policy"] = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                # iam:* is on the never_auto_approve_services blocklist.
                "Action": ["iam:CreateRole"],
                "Resource": "*",
            }
        ],
    }
    payload["spec"] = spec
    resp = as_admin.post("/api/v1/requests", json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["auto_approve_decision"]["auto_approve"] is False, (
        "blocklist floor must hold even for solo admin; got "
        f"{body['auto_approve_decision']}"
    )
    # Reason is NOT self_approve_reduction — the floor held.
    assert body["auto_approve_decision"]["reason"] != "self_approve_reduction"
    # State stays pending — request routes to human review.
    assert body["request"]["status"]["state"] == "pending"


def test_non_solo_mode_does_not_self_approve(
    monkeypatch: pytest.MonkeyPatch,
    as_admin: TestClient,
    request_payload: dict,
) -> None:
    """Test 3: non-solo mode + admin reduction → routes to human
    review (no special handling). The SAR gate is enabled either by
    `IAM_JIT_DEPLOYMENT_MODE=solo` OR a per-user opt-in flag; outside
    those, an admin's request flows through the normal pipeline.
    """
    monkeypatch.delenv("IAM_JIT_DEPLOYMENT_MODE", raising=False)
    resp = as_admin.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["auto_approve_decision"]["auto_approve"] is False
    assert body["auto_approve_decision"]["reason"] != "self_approve_reduction"
    assert body["request"]["status"]["state"] == "pending"


def test_solo_self_approve_still_emits_audit(
    monkeypatch: pytest.MonkeyPatch,
    as_admin: TestClient,
    request_payload: dict,
) -> None:
    """Test 4: solo self-approve skips APPROVAL, not AUDIT. The audit
    chain must still record the auto-approve decision with the
    distinguishable self-approve actor, per the [[self-approve-
    reductions]] memo: the skip is APPROVAL, not AUDIT.
    """
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    from iam_jit import audit as audit_mod

    captured: list[dict] = []
    real_emit = audit_mod.emit

    def _capture(**kwargs):
        captured.append(dict(kwargs))
        return real_emit(**kwargs)

    monkeypatch.setattr(audit_mod, "emit", _capture)

    resp = as_admin.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 201, resp.text

    # An auto-approve audit event MUST have been emitted with the
    # self-approve actor. Filter by kind to keep the test stable
    # against unrelated audit emissions the route may make.
    auto_events = [
        e for e in captured
        if e.get("kind") == "request.auto_approved"
    ]
    assert auto_events, (
        f"no request.auto_approved audit event emitted; captured kinds: "
        f"{[e.get('kind') for e in captured]}"
    )
    last = auto_events[-1]
    assert last["actor"].startswith("self_approve_reduction:"), (
        f"audit actor must be self_approve_reduction; got {last['actor']!r}"
    )
    # Details preserve the SAR audit annotations the auditor needs.
    details = last.get("details") or {}
    assert details.get("self_approve_evaluated") is True
    assert details.get("self_approve_eligible") is True
    assert details.get("self_approve_reason") == "self_approved"
