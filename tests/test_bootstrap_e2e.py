"""End-to-end bootstrap → first-admin → register account → submit
request.

This file proves the contract documented in `docs/BOOTSTRAP.md`:
a freshly-deployed iam-jit (empty user store, empty accounts store,
empty request store) can be bootstrapped to fully working state
through the API alone, the way an agent / IaC pipeline would.

We exercise both bootstrap paths end-to-end:

  - **Email path**: IAM_JIT_ADMIN_BOOTSTRAP_EMAIL set; on app
    startup the admin record is seeded; the user signs in via the
    magic-link callback; once logged in they can add other users
    and register accounts.

  - **Random-fallback path**: IAM_JIT_ALLOW_RANDOM_BOOTSTRAP=1 set;
    on startup a random admin is created and a sign-in URL is
    written to a state file; the URL works and lands the operator
    as admin.

For each path we then walk the canonical post-bootstrap journey:
add a second admin, add a requester, register a destination
account, dev submits, approver approves, role lands as active.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_jit import auth as auth_mod
from iam_jit.accounts_store import InMemoryAccountStore
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import User, UserNotFound


_SECRET = "test-bootstrap-e2e-secret-aaaaaaaaa"


# ---------------------------------------------------------------------------
# Writable user store — production uses DynamoDBUserStore. Tests use this.
# ---------------------------------------------------------------------------


class _WritableUserStore:
    name = "memory-rw"

    def __init__(self) -> None:
        self.users: dict[str, User] = {}

    def get(self, user_id: str) -> User:
        if user_id not in self.users:
            raise UserNotFound(user_id)
        return self.users[user_id]

    def list(self, *, include_disabled: bool = False) -> list[User]:
        return [u for u in self.users.values() if include_disabled or u.enabled]

    def put(self, user: User) -> None:
        self.users[user.id] = user

    def delete(self, user_id: str) -> None:
        self.users.pop(user_id, None)


# ---------------------------------------------------------------------------
# Fresh-deployment fixtures — empty stores, env vars governing bootstrap.
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_user_store() -> _WritableUserStore:
    return _WritableUserStore()


@pytest.fixture
def fresh_env(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    """Set the env vars iam-jit reads at startup. The bootstrap-email
    one is left UNSET — individual tests set it (or set the
    random-fallback opt-in) before they call create_app."""
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _SECRET)
    monkeypatch.setenv("IAM_JIT_BOOTSTRAP_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", raising=False)


def _build_fresh_app(user_store: _WritableUserStore) -> FastAPI:
    """Construct the app with empty stores, just like a Lambda
    cold-start hitting an empty DynamoDB table."""
    return create_app(
        request_store=FilesystemStore(pathlib.Path("/tmp/iam-jit-e2e-requests")),
        user_store=user_store,
        api_tokens_store=InMemoryAPITokenStore(),
        accounts_store=InMemoryAccountStore(),
    )


# ===========================================================================
# Path 1 — email bootstrap
# ===========================================================================


def test_email_bootstrap_seeds_admin_at_startup(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "founder@example.com")
    _build_fresh_app(empty_user_store)
    seeded = empty_user_store.users.get("email:founder@example.com")
    assert seeded is not None
    assert "admin" in seeded.roles
    assert seeded.enabled is True


def test_email_bootstrap_admin_can_sign_in_via_magic_link(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full sign-in dance against a freshly-bootstrapped instance."""
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "founder@example.com")
    app = _build_fresh_app(empty_user_store)
    client = TestClient(app)

    # Request a magic link.
    r = client.post("/login", data={"email": "founder@example.com"})
    assert r.status_code == 200
    # In dev-mode (IAM_JIT_DEV_INSECURE_SECRET=1) the link is rendered.
    assert "/auth/magic-callback?token=" in r.text
    # Pull the token out of the rendered link.
    token_idx = r.text.index("/auth/magic-callback?token=")
    snippet = r.text[token_idx:]
    end = snippet.index('"')
    href = snippet[:end].replace("&amp;", "&")

    # Follow it.
    cb = client.get(href, follow_redirects=False)
    assert cb.status_code == 303
    assert cb.cookies.get("iam_jit_session")


def test_email_bootstrap_admin_lifecycle_end_to_end(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """The full canonical journey: bootstrap → sign in →
    add an approver + a dev → register an account → dev submits
    → approver approves → state=active."""
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "founder@example.com")
    # Use a per-test request dir so tests don't share request state.
    monkeypatch.setenv("IAM_JIT_REQUESTS_DIR", str(tmp_path / "requests"))
    app = create_app(
        user_store=empty_user_store,
        api_tokens_store=InMemoryAPITokenStore(),
        accounts_store=InMemoryAccountStore(),
        request_store=FilesystemStore(tmp_path / "requests"),
    )

    def _client_as(user_id: str) -> TestClient:
        c = TestClient(app)
        c.cookies.set("iam_jit_session", auth_mod.sign_session(_SECRET, user_id))
        return c

    admin = _client_as("email:founder@example.com")

    # 1. confirm /api/v1/users/me reflects admin role
    me = admin.get("/api/v1/users/me").json()
    assert "admin" in me["roles"]

    # 2. add an approver and a requester
    for new_user in [
        {"id": "email:second-admin@example.com", "roles": ["admin"], "display_name": "Second Admin"},
        {"id": "email:approver@example.com", "roles": ["approver"], "display_name": "Approver"},
        {"id": "email:dev@example.com", "roles": ["requester"], "display_name": "Dev"},
    ]:
        r = admin.post("/api/v1/users", json=new_user)
        assert r.status_code == 201, r.text

    # 3. register a destination account
    r = admin.post(
        "/api/v1/accounts",
        json={
            "account_id": "060392206767",
            "alias": "omise-dev",
            "provisioning_mode": "classic_iam",
            "provisioner_role_arn": "arn:aws:iam::060392206767:role/iam-jit-provisioner",
            "provisioner_external_id": "iam-jit-060392206767",
        },
    )
    assert r.status_code == 201, r.text

    listed = admin.get("/api/v1/accounts").json()
    assert any(a["account_id"] == "060392206767" for a in listed["accounts"])

    # 4. dev submits a request
    dev = _client_as("email:dev@example.com")
    submit = dev.post(
        "/api/v1/requests",
        json={
            "apiVersion": "iam-jit.dev/v1alpha1",
            "kind": "RoleRequest",
            "metadata": {
                "requester": {
                    "name": "Dev",
                    "email": "dev@example.com",
                    "principal_arn": "arn:aws:iam::060392206767:user/dev",
                }
            },
            "spec": {
                "description": "bootstrap e2e fixture: read s3 in dev",
                "access_type": "read-only",
                "accounts": [{"account_id": "060392206767"}],
                "duration": {"duration_hours": 24},
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": ["arn:aws:s3:::ex/*"],
                        }
                    ],
                },
            },
        },
    )
    assert submit.status_code == 201, submit.text
    rid = submit.json()["request"]["metadata"]["id"]

    # 5. approver approves; provisioning is stubbed below so no AWS calls
    from iam_jit import provision as provision_mod

    def _stub(req, *, accounts_store, sts_client=None, iam_client_factory=None):
        return provision_mod.ProvisioningResult(
            role_arn="arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-" + rid,
            role_name="iam-jit-grant-" + rid,
            account_id="060392206767",
            assumer_principal_arn="arn:aws:iam::060392206767:user/dev",
            expires_at="2099-01-01T00:00:00Z",
            external_id="iam-jit-060392206767",
            session_name="iam-jit-provision-" + rid,
            tags={"managed-by": "iam-jit"},
        )

    monkeypatch.setattr(provision_mod, "provision", _stub)

    approver = _client_as("email:approver@example.com")
    approve = approver.post(f"/api/v1/requests/{rid}/approve")
    assert approve.status_code == 200, approve.text
    assert approve.json()["request"]["status"]["state"] == "active"


def test_email_bootstrap_is_idempotent_across_cold_starts(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-creating the app (simulating a Lambda cold-start) doesn't
    overwrite the existing admin's mutated state."""
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "founder@example.com")
    _build_fresh_app(empty_user_store)
    rec = empty_user_store.users["email:founder@example.com"]
    # Operator promotes themselves to multi-role.
    empty_user_store.users["email:founder@example.com"] = dataclasses.replace(
        rec, roles=("admin", "approver"), display_name="Founder, Promoted"
    )
    # Cold-start again.
    _build_fresh_app(empty_user_store)
    after = empty_user_store.users["email:founder@example.com"]
    assert after.display_name == "Founder, Promoted"
    assert "approver" in after.roles


# ===========================================================================
# Path 2 — random-fallback bootstrap (the dev escape-hatch)
# ===========================================================================


def test_random_fallback_writes_link_file_at_startup(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    _build_fresh_app(empty_user_store)
    link_file = tmp_path / "iam-jit-bootstrap-link.txt"
    assert link_file.exists()
    body = link_file.read_text()
    assert "/auth/magic-callback?token=" in body
    # Random admin user actually got seeded.
    randoms = [
        u for u in empty_user_store.users.values()
        if u.id.startswith("email:bootstrap-") and "iam-jit.local" in u.id
    ]
    assert len(randoms) == 1
    assert "admin" in randoms[0].roles


def test_random_fallback_link_signs_user_in(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """The URL written to disk lands the operator as admin."""
    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    app = _build_fresh_app(empty_user_store)
    body = (tmp_path / "iam-jit-bootstrap-link.txt").read_text()
    # Pull the URL.
    url_line = next(
        line for line in body.splitlines()
        if line.startswith("http://") or line.startswith("https://")
    )
    parsed = urlparse(url_line)
    token = parse_qs(parsed.query)["token"][0]

    client = TestClient(app)
    r = client.get(f"/auth/magic-callback?token={token}", follow_redirects=False)
    assert r.status_code == 303
    assert r.cookies.get("iam_jit_session")

    # And the resulting session has admin privileges.
    me = client.get("/api/v1/users/me").json()
    assert "admin" in me["roles"]
    assert me["id"].startswith("email:bootstrap-")


def test_random_fallback_skipped_when_email_bootstrap_set(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Email path takes precedence — random link file is NOT written."""
    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "real@example.com")
    _build_fresh_app(empty_user_store)
    assert not (tmp_path / "iam-jit-bootstrap-link.txt").exists()
    assert "email:real@example.com" in empty_user_store.users
    assert not any(
        u.id.startswith("email:bootstrap-")
        for u in empty_user_store.users.values()
    )


def test_random_fallback_off_by_default(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    tmp_path: pathlib.Path,
) -> None:
    """No env vars set → no admin seeded, no link file. The deployment
    is unreachable until the operator picks a bootstrap path."""
    _build_fresh_app(empty_user_store)
    assert empty_user_store.users == {}
    assert not (tmp_path / "iam-jit-bootstrap-link.txt").exists()


def test_random_fallback_skipped_when_store_already_has_users(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Pre-existing admin → random fallback never fires."""
    empty_user_store.users["email:already@example.com"] = User(
        id="email:already@example.com",
        roles=("admin",),
        enabled=True,
    )
    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    _build_fresh_app(empty_user_store)
    assert not (tmp_path / "iam-jit-bootstrap-link.txt").exists()


def test_random_fallback_admin_can_complete_full_lifecycle(
    empty_user_store: _WritableUserStore,
    fresh_env: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Random-bootstrap admin signs in, adds real users + an account,
    a dev submits a request and the bootstrap admin approves it."""
    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    monkeypatch.setenv("IAM_JIT_REQUESTS_DIR", str(tmp_path / "requests"))
    app = create_app(
        user_store=empty_user_store,
        api_tokens_store=InMemoryAPITokenStore(),
        accounts_store=InMemoryAccountStore(),
        request_store=FilesystemStore(tmp_path / "requests"),
    )

    body = (tmp_path / "iam-jit-bootstrap-link.txt").read_text()
    url_line = next(
        line for line in body.splitlines()
        if line.startswith("http")
    )
    token = parse_qs(urlparse(url_line).query)["token"][0]

    bootstrap = TestClient(app)
    r = bootstrap.get(f"/auth/magic-callback?token={token}", follow_redirects=False)
    assert r.status_code == 303

    # 1. Add a dev user
    r = bootstrap.post(
        "/api/v1/users",
        json={
            "id": "email:dev@example.com",
            "display_name": "Dev",
            "roles": ["requester"],
        },
    )
    assert r.status_code == 201, r.text

    # 2. Register an account
    r = bootstrap.post(
        "/api/v1/accounts",
        json={
            "account_id": "060392206767",
            "alias": "omise-dev",
            "provisioning_mode": "classic_iam",
            "provisioner_role_arn": "arn:aws:iam::060392206767:role/iam-jit-provisioner",
            "provisioner_external_id": "iam-jit-060392206767",
        },
    )
    assert r.status_code == 201, r.text

    # 3. Dev submits
    dev = TestClient(app)
    dev.cookies.set(
        "iam_jit_session",
        auth_mod.sign_session(_SECRET, "email:dev@example.com"),
    )
    submit = dev.post(
        "/api/v1/requests",
        json={
            "apiVersion": "iam-jit.dev/v1alpha1",
            "kind": "RoleRequest",
            "metadata": {
                "requester": {
                    "name": "Dev",
                    "email": "dev@example.com",
                    "principal_arn": "arn:aws:iam::060392206767:user/dev",
                }
            },
            "spec": {
                "description": "random-bootstrap e2e fixture: read s3",
                "access_type": "read-only",
                "accounts": [{"account_id": "060392206767"}],
                "duration": {"duration_hours": 24},
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": ["arn:aws:s3:::ex/*"],
                        }
                    ],
                },
            },
        },
    )
    assert submit.status_code == 201, submit.text
    rid = submit.json()["request"]["metadata"]["id"]

    # 4. Bootstrap admin approves (they're admin so approver scope OK).
    from iam_jit import provision as provision_mod

    def _stub(req, *, accounts_store, sts_client=None, iam_client_factory=None):
        return provision_mod.ProvisioningResult(
            role_arn="arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-" + rid,
            role_name="iam-jit-grant-" + rid,
            account_id="060392206767",
            assumer_principal_arn="arn:aws:iam::060392206767:user/dev",
            expires_at="2099-01-01T00:00:00Z",
            external_id="iam-jit-060392206767",
            session_name="iam-jit-provision-" + rid,
            tags={"managed-by": "iam-jit"},
        )

    monkeypatch.setattr(provision_mod, "provision", _stub)

    approve = bootstrap.post(f"/api/v1/requests/{rid}/approve")
    assert approve.status_code == 200, approve.text
    assert approve.json()["request"]["status"]["state"] == "active"

    # 5. Optionally clean up the random bootstrap user.
    bootstrap_user_id = next(
        u.id for u in empty_user_store.users.values()
        if u.id.startswith("email:bootstrap-")
    )
    # Need to add a real admin first, then the bootstrap user can be deleted.
    bootstrap.post(
        "/api/v1/users",
        json={"id": "email:real-admin@example.com", "roles": ["admin"]},
    )
    real_admin = TestClient(app)
    real_admin.cookies.set(
        "iam_jit_session",
        auth_mod.sign_session(_SECRET, "email:real-admin@example.com"),
    )
    deleted = real_admin.delete(f"/api/v1/users/{bootstrap_user_id}")
    assert deleted.status_code == 200
    assert bootstrap_user_id not in empty_user_store.users
