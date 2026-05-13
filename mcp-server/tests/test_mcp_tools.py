"""Smoke tests for the iam-jit MCP tool functions.

We don't test the MCP protocol layer itself (well-tested upstream by the
mcp SDK). We test that each tool builds the right HTTP request, includes
the bearer token, and parses success/error responses correctly.

Tests run against a respx-mocked iam-jit. The tools are imported directly
as Python functions — bypassing the MCP transport.
"""

from __future__ import annotations

import os

import httpx
import pytest
import respx

import iam_jit_mcp as m


_BASE = "https://iam-jit.test"
_TOKEN = "iamjit_testtoken123456789012345"


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_BASE_URL", _BASE)
    monkeypatch.setenv("IAM_JIT_API_TOKEN", _TOKEN)


def _underlying(tool):
    """FastMCP wraps tool functions; recover the original callable."""
    fn = getattr(tool, "fn", None) or tool
    return fn


def test_submit_role_request_with_services() -> None:
    submit = _underlying(m.submit_role_request)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(f"{_BASE}/api/v1/requests").mock(
            return_value=httpx.Response(
                201,
                json={
                    "request": {"metadata": {"id": "abc123"}, "status": {"state": "pending"}},
                    "review": None,
                    "narrowing_questions": [],
                },
            )
        )
        out = submit(
            description="Read S3 config files",
            accounts=["060392206767"],
            duration_hours=24,
            services=["s3"],
        )
    assert out["request"]["metadata"]["id"] == "abc123"
    request = route.calls[0].request
    assert request.headers["authorization"] == f"Bearer {_TOKEN}"
    body = request.read().decode()
    assert "s3" in body
    assert "060392206767" in body


def test_submit_role_request_with_policy() -> None:
    submit = _underlying(m.submit_role_request)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
    }
    with respx.mock(assert_all_called=True) as mock:
        mock.post(f"{_BASE}/api/v1/requests").mock(
            return_value=httpx.Response(
                201,
                json={"request": {"metadata": {"id": "xyz"}}, "review": None, "narrowing_questions": []},
            )
        )
        out = submit(
            description="Read",
            accounts=["111111111111"],
            policy=policy,
        )
    assert out["request"]["metadata"]["id"] == "xyz"


def test_check_request_status() -> None:
    check = _underlying(m.check_request_status)
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{_BASE}/api/v1/requests/req1").mock(
            return_value=httpx.Response(200, json={"metadata": {"id": "req1"}, "status": {"state": "pending"}})
        )
        out = check("req1")
    assert out["status"]["state"] == "pending"


def test_list_pending_requests_filters_state() -> None:
    listfn = _underlying(m.list_pending_requests)
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{_BASE}/api/v1/requests").mock(
            return_value=httpx.Response(
                200, json={"requests": [{"id": "a"}, {"id": "b"}], "count": 2}
            )
        )
        out = listfn()
    assert out["count"] == 2


def test_approve_request_with_comment() -> None:
    approve = _underlying(m.approve_request)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(f"{_BASE}/api/v1/requests/req1/approve").mock(
            return_value=httpx.Response(200, json={"request": {"status": {"state": "provisioning"}}})
        )
        approve("req1", comment="looks good")
    body = route.calls[0].request.read().decode()
    assert "looks good" in body


def test_reject_request() -> None:
    reject = _underlying(m.reject_request)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(f"{_BASE}/api/v1/requests/req1/reject").mock(
            return_value=httpx.Response(200, json={"request": {"status": {"state": "rejected"}}})
        )
        out = reject("req1", reason="too broad")
    assert out["request"]["status"]["state"] == "rejected"
    body = route.calls[0].request.read().decode()
    assert "too broad" in body


def test_request_changes_with_suggestions() -> None:
    rc = _underlying(m.request_changes)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(f"{_BASE}/api/v1/requests/req1/request-changes").mock(
            return_value=httpx.Response(200, json={"request": {"status": {"state": "needs_changes"}}})
        )
        rc("req1", suggestions=["scope to bucket X", "remove iam:*"], comment="please")
    body = route.calls[0].request.read().decode()
    assert "scope to bucket X" in body
    assert "please" in body


def test_comment_on_request_with_constraints() -> None:
    comment = _underlying(m.comment_on_request)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(f"{_BASE}/api/v1/requests/req1/comments").mock(
            return_value=httpx.Response(201, json={"comment": {"posted_at": "now"}})
        )
        comment(
            "req1",
            "scope to staging only",
            suggested_constraints=[
                {"service": "s3", "arn_patterns": ["arn:aws:s3:::staging-*"]}
            ],
        )
    body = route.calls[0].request.read().decode()
    assert "staging-*" in body


def test_cancel_request() -> None:
    cancel = _underlying(m.cancel_request)
    with respx.mock(assert_all_called=True) as mock:
        mock.post(f"{_BASE}/api/v1/requests/req1/cancel").mock(
            return_value=httpx.Response(200, json={"request": {"status": {"state": "cancelled"}}})
        )
        out = cancel("req1")
    assert out["request"]["status"]["state"] == "cancelled"


def test_download_request_template() -> None:
    download = _underlying(m.download_request)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get(f"{_BASE}/api/v1/requests/req1/download").mock(
            return_value=httpx.Response(
                200,
                json={
                    "apiVersion": "iam-jit.dev/v1alpha1",
                    "kind": "RoleRequest",
                    "metadata": {"requester": {"name": "x", "email": "x@example.com"}},
                    "spec": {"description": "saved request", "policy": {}},
                },
            )
        )
        out = download("req1")
    assert out["spec"]["description"] == "saved request"
    request = route.calls[0].request
    # Default mode is template, format is json
    assert "mode=template" in str(request.url)
    assert "as=json" in str(request.url)


def test_download_request_full() -> None:
    download = _underlying(m.download_request)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get(f"{_BASE}/api/v1/requests/req1/download").mock(
            return_value=httpx.Response(200, json={"status": {"state": "active"}})
        )
        download("req1", mode="full")
    request = route.calls[0].request
    assert "mode=full" in str(request.url)


def test_analyze_policy() -> None:
    analyze = _underlying(m.analyze_policy)
    with respx.mock(assert_all_called=True) as mock:
        mock.post(f"{_BASE}/api/v1/policy/analyze").mock(
            return_value=httpx.Response(
                200,
                json={
                    "review": {"risk_score": 7, "risk_factors": ["..."]},
                    "narrowing_questions": [],
                    "ai_enabled": True,
                },
            )
        )
        out = analyze(
            policy={"Version": "2012-10-17", "Statement": []},
            description="test",
        )
    assert out["review"]["risk_score"] == 7


def test_list_users() -> None:
    listfn = _underlying(m.list_users)
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{_BASE}/api/v1/users").mock(
            return_value=httpx.Response(200, json={"users": [], "count": 0})
        )
        out = listfn()
    assert out["count"] == 0


def test_report_grants_with_filters() -> None:
    report = _underlying(m.report_grants)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get(f"{_BASE}/api/v1/reports/grants").mock(
            return_value=httpx.Response(200, json={"rows": [], "count": 0})
        )
        report(state="active", account_id="111111111111")
    request = route.calls[0].request
    assert "state=active" in str(request.url)
    assert "account_id=111111111111" in str(request.url)


def test_missing_base_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_BASE_URL", raising=False)
    check = _underlying(m.check_request_status)
    with pytest.raises(RuntimeError, match="IAM_JIT_BASE_URL"):
        check("req1")


def test_missing_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_API_TOKEN", raising=False)
    check = _underlying(m.check_request_status)
    with pytest.raises(RuntimeError, match="IAM_JIT_API_TOKEN"):
        check("req1")


def test_api_error_surfaces_status_and_detail() -> None:
    check = _underlying(m.check_request_status)
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{_BASE}/api/v1/requests/req1").mock(
            return_value=httpx.Response(403, json={"detail": "not authorized"})
        )
        with pytest.raises(RuntimeError) as exc_info:
            check("req1")
    assert "403" in str(exc_info.value)
    assert "not authorized" in str(exc_info.value)
