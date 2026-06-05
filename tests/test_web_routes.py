"""Smoke tests for the human web UI.

We don't render-check every pixel; we verify routes return 200 with the right
content type and key landmarks, and that protected pages redirect to /login
for unauthenticated requests.
"""

from __future__ import annotations

import pathlib

import pytest
from fastapi.testclient import TestClient

from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore

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


# ---- #670: case-insensitive login lookup ----
# macOS hostnames often contain uppercase (e.g. "MacBook-Pro"), so the
# auto-seeded user_id preserves mixed case while _normalize_login_email
# lowercases the typed email. The case-insensitive fallback must bridge that.


_MIXED_CASE_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:DevUser@test-Host.local
    display_name: Mixed-case local admin
    roles: [admin, approver, requester]
    enabled: true
"""

_DISABLED_MIXED_CASE_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:DevUser@test-Host.local
    display_name: Disabled mixed-case user
    roles: [admin]
    enabled: false
"""

_DEV_SECRET_670 = "test-secret-for-670-case-insensitive-aa"


@pytest.fixture
def mixed_case_client(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    """App seeded with a mixed-case user id, simulating a macOS
    machine whose hostname contained uppercase letters."""
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET_670)
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_MIXED_CASE_USERS_YAML)
    app = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    return TestClient(app, raise_server_exceptions=True, client=("127.0.0.1", 50000))


@pytest.fixture
def disabled_mixed_case_client(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    """App seeded with a disabled mixed-case user id."""
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET_670)
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_DISABLED_MIXED_CASE_USERS_YAML)
    app = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    return TestClient(app, raise_server_exceptions=True, client=("127.0.0.1", 50000))


def test_login_case_insensitive_uppercase_stored_lowercase_typed(
    mixed_case_client: TestClient,
) -> None:
    """#670: user stored with mixed-case id (e.g. DevUser@test-Host.local),
    operator types lowercase email → login must succeed (dev_link rendered)."""
    resp = mixed_case_client.post(
        "/login",
        data={"email": "devuser@test-host.local"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    # The dev_link is only rendered when the user is found and enabled.
    assert "auth/magic-callback" in resp.text, (
        "case-insensitive lookup failed: no magic-link rendered for lowercase "
        "login against a mixed-case stored user id"
    )


def test_login_case_insensitive_lowercase_stored_uppercase_typed(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#670 symmetric: user stored lowercase, operator types mixed-case → succeeds."""
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET_670)
    yaml_content = (
        "schema_version: 1\nauth_mode: local\nusers:\n"
        "  - id: email:alice@test-host.local\n"
        "    display_name: Alice\n"
        "    roles: [admin]\n"
        "    enabled: true\n"
    )
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(yaml_content)
    app = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app, raise_server_exceptions=True, client=("127.0.0.1", 50000))
    # Operator types mixed-case version of a lowercase-stored email.
    resp = c.post(
        "/login",
        data={"email": "Alice@Test-Host.local"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "auth/magic-callback" in resp.text, (
        "case-insensitive lookup failed: no magic-link rendered for mixed-case "
        "login against a lowercase stored user id"
    )


def test_login_case_insensitive_no_false_positive(
    mixed_case_client: TestClient,
) -> None:
    """#670: a completely different email must NOT match (no false-positive)."""
    resp = mixed_case_client.post(
        "/login",
        data={"email": "other@test-host.local"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "auth/magic-callback" not in resp.text, (
        "case-insensitive lookup produced a false-positive match"
    )


def test_login_case_insensitive_disabled_user_no_link(
    disabled_mixed_case_client: TestClient,
) -> None:
    """#670: case-insensitive match of a DISABLED user must not render a link."""
    resp = disabled_mixed_case_client.post(
        "/login",
        data={"email": "devuser@test-host.local"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "auth/magic-callback" not in resp.text, (
        "disabled user with mixed-case id incorrectly received a magic link"
    )


# ---- #675: narrow exception types in case-insensitive fallback ----


def test_login_case_insensitive_file_not_found_returns_no_link(
    mixed_case_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#675: FileNotFoundError from user_store.list() → no link, no warning logged.

    normalize_user_id made FileUserStore.get() case-insensitive, so the
    mixed-case user now resolves at get() before the #670 list()-based fallback
    runs. To still exercise that fallback's exception handling we force get()
    to UserNotFound — the exact state the fallback was built for."""
    from iam_jit.users_store import FileUserStore, UserNotFound

    monkeypatch.setattr(FileUserStore, "get", lambda *a, **kw: (_ for _ in ()).throw(UserNotFound("x")))
    monkeypatch.setattr(FileUserStore, "list", lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("users.yaml")))
    resp = mixed_case_client.post(
        "/login",
        data={"email": "devuser@test-host.local"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "auth/magic-callback" not in resp.text


def test_login_case_insensitive_permission_error_returns_no_link(
    mixed_case_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#675: PermissionError from user_store.list() → no link, no warning logged."""
    from iam_jit.users_store import FileUserStore, UserNotFound

    monkeypatch.setattr(FileUserStore, "get", lambda *a, **kw: (_ for _ in ()).throw(UserNotFound("x")))
    monkeypatch.setattr(FileUserStore, "list", lambda *a, **kw: (_ for _ in ()).throw(PermissionError("permission denied")))
    resp = mixed_case_client.post(
        "/login",
        data={"email": "devuser@test-host.local"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "auth/magic-callback" not in resp.text


def test_login_case_insensitive_unexpected_error_logs_warning(
    mixed_case_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """#675: unexpected exception from user_store.list() → no link, WARNING logged."""
    import logging

    from iam_jit.users_store import FileUserStore, UserNotFound

    monkeypatch.setattr(FileUserStore, "get", lambda *a, **kw: (_ for _ in ()).throw(UserNotFound("x")))
    monkeypatch.setattr(FileUserStore, "list", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("disk full")))
    with caplog.at_level(logging.WARNING, logger="iam_jit.login"):
        resp = mixed_case_client.post(
            "/login",
            data={"email": "devuser@test-host.local"},
            follow_redirects=False,
        )
    assert resp.status_code == 200
    assert "auth/magic-callback" not in resp.text
    warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("disk full" in str(m) for m in warning_messages), (
        f"expected a warning mentioning the error reason; got: {warning_messages}"
    )


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
    """Stage 4 [[no-nl-synthesis]]: 'Generate a new role' card removed
    along with the NL synthesis path; only the Paste card remains."""
    resp = as_dev.get("/requests/new")
    assert resp.status_code == 200
    assert "Paste a role" in resp.text
    # The Generate card was deleted; chooser is paste-only now
    assert "Generate a new role" not in resp.text


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
