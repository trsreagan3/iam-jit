"""Smoke tests for the human web UI.

We don't render-check every pixel; we verify routes return 200 with the right
content type and key landmarks, and that protected pages redirect to /login
for unauthenticated requests.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


# ---- Login flow ----


def test_login_page_renders(client: TestClient) -> None:
    resp = client.get("/login")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "Sign in" in resp.text


def test_login_submit_known_user_returns_dev_link(client: TestClient) -> None:
    resp = client.post(
        "/login",
        data={"email": "admin@example.com"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "Check your email" in resp.text
    assert "auth/magic-callback" in resp.text


def test_login_submit_unknown_user_no_link(client: TestClient) -> None:
    resp = client.post(
        "/login", data={"email": "ghost@example.com"}, follow_redirects=False
    )
    assert resp.status_code == 200
    assert "Check your email" in resp.text
    assert "auth/magic-callback" not in resp.text


def test_magic_callback_sets_session_cookie(client: TestClient) -> None:
    sent = client.post("/login", data={"email": "admin@example.com"})
    # extract token from the rendered link
    body = sent.text
    start = body.find("?token=") + len("?token=")
    end = body.find('"', start)
    token = body[start:end]
    cb = client.get(f"/auth/magic-callback?token={token}", follow_redirects=False)
    assert cb.status_code == 303
    assert "iam_jit_session" in cb.cookies
    # Session cookie now lets us hit the home page.
    home = client.get("/", follow_redirects=False)
    assert home.status_code == 200
    assert "My requests" in home.text


def test_magic_callback_invalid_token_redirects_to_login(client: TestClient) -> None:
    cb = client.get("/auth/magic-callback?token=garbage", follow_redirects=False)
    assert cb.status_code == 303
    assert cb.headers["location"].startswith("/login")


def test_logout_clears_cookie(as_admin: TestClient) -> None:
    resp = as_admin.get("/logout", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


# ---- Protected pages redirect when unauthenticated ----


def test_home_redirects_to_login(client: TestClient) -> None:
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_new_request_chooser_redirects(client: TestClient) -> None:
    resp = client.get("/requests/new", follow_redirects=False)
    assert resp.status_code == 303


def test_tokens_page_redirects(client: TestClient) -> None:
    resp = client.get("/tokens", follow_redirects=False)
    assert resp.status_code == 303


# ---- Authenticated pages render ----


def test_home_renders_for_authenticated_user(as_dev: TestClient) -> None:
    resp = as_dev.get("/")
    assert resp.status_code == 200
    assert "My requests" in resp.text
    assert "+ new request" in resp.text


def test_queue_visible_to_approver(as_approver: TestClient) -> None:
    resp = as_approver.get("/queue")
    assert resp.status_code == 200
    assert "Pending requests" in resp.text


def test_queue_forbidden_to_dev(as_dev: TestClient) -> None:
    resp = as_dev.get("/queue")
    assert resp.status_code == 403


def test_all_requests_page_renders_for_authenticated_user(
    as_dev: TestClient,
) -> None:
    """Closes the dangling /all link from queue.html — the route exists
    and renders for any authenticated user (filtered by ownership)."""
    resp = as_dev.get("/all")
    assert resp.status_code == 200
    assert "All requests" in resp.text


def test_all_requests_page_redirects_unauthenticated(client: TestClient) -> None:
    resp = client.get("/all", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_new_request_chooser_renders(as_dev: TestClient) -> None:
    resp = as_dev.get("/requests/new")
    assert resp.status_code == 200
    assert "Generate a new role" in resp.text
    assert "Paste a role" in resp.text


def test_new_paste_form_renders(as_dev: TestClient) -> None:
    resp = as_dev.get("/requests/new/paste")
    assert resp.status_code == 200
    assert "Paste a policy" in resp.text


def test_new_describe_redirects_when_no_ai(as_dev: TestClient) -> None:
    import pytest
    pytest.skip("closed by deletion: route removed in 0.4.0 ([[no-nl-synthesis]] Stage 4); replaced by paste-mode + MCP submit_policy.")

def test_new_describe_renders_when_ai_enabled(with_llm: None, as_dev: TestClient) -> None:
    import pytest
    pytest.skip("closed by deletion: route removed in 0.4.0 ([[no-nl-synthesis]] Stage 4); replaced by paste-mode + MCP submit_policy.")

def test_tokens_page_renders(as_dev: TestClient) -> None:
    resp = as_dev.get("/tokens")
    assert resp.status_code == 200
    assert "Your API tokens" in resp.text


# ---- End-to-end paste-mode submission ----


def test_paste_submit_end_to_end(as_dev: TestClient) -> None:
    policy_json = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Action":["s3:GetObject"],'
        '"Resource":"arn:aws:s3:::example-config/path/file.txt"}]}'
    )
    resp = as_dev.post(
        "/requests/new/paste",
        data={
            "description": "Read S3 config files for service X.",
            "policy": policy_json,
            "access_type": "read-only",
            "accounts": "060392206767",
            "duration_hours": "24",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    detail_url = resp.headers["location"]
    assert detail_url.startswith("/requests/")
    detail = as_dev.get(detail_url)
    assert detail.status_code == 200
    assert "pending" in detail.text


def test_paste_submit_invalid_policy_re_renders_form(as_dev: TestClient) -> None:
    resp = as_dev.post(
        "/requests/new/paste",
        data={
            "description": "Read S3 config files long enough.",
            "policy": "this is not valid json or yaml: { unclosed",
            "access_type": "read-only",
            "accounts": "060392206767",
            "duration_hours": "24",
        },
    )
    assert resp.status_code == 200
    assert "Couldn't submit" in resp.text or "could not parse" in resp.text


# ---- Static files mounted ----


def test_static_css_served(client: TestClient) -> None:
    resp = client.get("/static/style.css")
    assert resp.status_code == 200
    assert "iam-jit" not in resp.text  # plain css, no brand strings
    assert "--accent" in resp.text


# ---- Protected detail page authz ----


def test_dev_cannot_view_others_detail_page(
    as_dev: TestClient, as_dev2: TestClient
) -> None:
    policy_json = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Action":["s3:GetObject"],"Resource":"arn:aws:s3:::ex"}]}'
    )
    submit = as_dev.post(
        "/requests/new/paste",
        data={
            "description": "Read for service X (long enough).",
            "policy": policy_json,
            "access_type": "read-only",
            "accounts": "060392206767",
            "duration_hours": "24",
        },
        follow_redirects=False,
    )
    detail_url = submit.headers["location"]
    resp = as_dev2.get(detail_url, follow_redirects=False)
    assert resp.status_code == 403
