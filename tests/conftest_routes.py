"""Shared fixtures for route tests.

Each persona fixture (`as_admin`, `as_dev`, etc.) returns its OWN TestClient
that shares the underlying FastAPI app (and therefore the underlying stores)
with all other personas. That way one test can use multiple personas without
their session cookies stomping on each other.
"""

from __future__ import annotations

import pathlib
from typing import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_jit import auth as auth_mod
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore


_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin
    roles: [admin]
  - id: email:approver@example.com
    display_name: Approver
    roles: [approver]
  - id: email:dev@example.com
    display_name: Dev
    roles: [requester]
  - id: email:dev2@example.com
    display_name: Dev2
    roles: [requester]
  - id: email:disabled@example.com
    display_name: Disabled
    roles: [requester]
    enabled: false
"""

_DEV_SECRET = "test-secret-for-route-tests-aaaaaaaaa"


@pytest.fixture(autouse=True)
def _reset_global_singletons() -> None:
    """Module-level singletons (rate limiter, bans) leak
    state between tests. Reset them before each test so one test's
    activity can't throttle/ban a fixture user in the next test."""
    from iam_jit import (
        bans as _bans,
        cidr_store as _cidrs,
        llm_budget as _llmb,
        magic_link_nonces as _nonces,
        rate_limit as _rl,
        scoring_feedback as _fb,
        session_revocation as _sr,
        settings_store as _settings,
    )

    _rl.reset_default_limiter_for_tests()
    _bans.reset_default_store_for_tests()
    _nonces.reset_default_store_for_tests()
    _cidrs.reset_default_store_for_tests()
    _settings.reset_default_store_for_tests()
    _sr.reset_default_store_for_tests()
    _fb.reset_default_store_for_tests()
    _llmb.reset_default_store_for_tests()
    # The /api/v1/score endpoint has its own per-IP limiter.
    from iam_jit.routes import score as _score_route
    _score_route._reset_limiter_for_tests()
    # POST /api/v1/auth/magic-link has its own per-IP limiter.
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()


@pytest.fixture
def client_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)


@pytest.fixture
def stub_provisioning(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace provision.provision() with a stub that always succeeds.

    Route tests don't have moto-backed STS/IAM, and they don't want to —
    the unit-level provisioning flow has dedicated tests in
    test_provision.py. Here we just want to verify the lifecycle wiring
    works (approve → mark_provisioned → state=active), so we skip the
    actual AWS calls.
    """
    from iam_jit import provision as provision_mod

    def _stub(req, *, accounts_store, sts_client=None, iam_client_factory=None):
        spec = req.get("spec") or {}
        accounts = spec.get("accounts") or [{}]
        account_id = accounts[0].get("account_id") or "000000000000"
        request_id = (req.get("metadata") or {}).get("id") or "rq-test"
        return provision_mod.ProvisioningResult(
            role_arn=f"arn:aws:iam::{account_id}:role/iam-jit/iam-jit-grant-{request_id}",
            role_name=f"iam-jit-grant-{request_id}",
            account_id=account_id,
            assumer_principal_arn="arn:aws:iam::000000000000:user/stub",
            expires_at="2030-01-01T00:00:00Z",
            external_id=f"iam-jit-{account_id}",
            session_name=f"iam-jit-provision-{request_id}",
            tags={"managed-by": "iam-jit"},
        )

    monkeypatch.setattr(provision_mod, "provision", _stub)


@pytest.fixture
def shared_app(
    tmp_path: pathlib.Path, client_env: None, stub_provisioning: None
) -> FastAPI:
    requests_dir = tmp_path / "requests"
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    return create_app(
        request_store=FilesystemStore(requests_dir),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )


@pytest.fixture
def make_client(shared_app: FastAPI) -> Callable[[str | None], TestClient]:
    """Factory that returns an independent TestClient on each call.

    All TestClients share the underlying FastAPI app instance (and so its
    in-memory stores), but cookies and headers are independent per client.
    """

    def _factory(
        user_id: str | None = None,
        client: tuple[str, int] = ("127.0.0.1", 50000),
    ) -> TestClient:
        c = TestClient(
            shared_app,
            raise_server_exceptions=True,
            client=client,
        )
        if user_id is not None:
            cookie = auth_mod.sign_session(_DEV_SECRET, user_id)
            c.cookies.set("iam_jit_session", cookie)
        return c

    return _factory


@pytest.fixture
def client(make_client) -> TestClient:
    return make_client(None)


@pytest.fixture
def tokens_store(shared_app: FastAPI) -> InMemoryAPITokenStore:
    return shared_app.state.api_tokens_store


@pytest.fixture
def as_admin(make_client) -> TestClient:
    return make_client("email:admin@example.com")


@pytest.fixture
def as_approver(make_client) -> TestClient:
    return make_client("email:approver@example.com")


@pytest.fixture
def as_dev(make_client) -> TestClient:
    return make_client("email:dev@example.com")


@pytest.fixture
def as_dev2(make_client) -> TestClient:
    return make_client("email:dev2@example.com")


@pytest.fixture
def with_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force review.is_review_enabled() to return True for this test.

    Use when a test specifically exercises the AI-feature surface (risk
    scoring, LLM narrative). Without it, tests run in NoAI mode by default.
    """
    from iam_jit import review

    monkeypatch.setattr(review, "is_review_enabled", lambda: True)


@pytest.fixture
def request_payload() -> dict:
    """A minimal valid request payload (read-only S3 access)."""
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
        "spec": {
            "description": "Read S3 config files for service X.",
            "access_type": "read-only",
            "task_intent": {"services": ["s3"], "actions": ["read", "list"]},
            "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
            "duration": {"duration_hours": 24},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": "arn:aws:s3:::example-config",
                    }
                ],
            },
            "provisioning": {"mode": "identity_center"},
        },
    }
