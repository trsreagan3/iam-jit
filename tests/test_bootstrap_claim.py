"""Tests for the no-email `/setup` bootstrap-claim flow.

Two layers:

  * Pure-function tests of `bootstrap_claim.evaluate_and_claim`
    (no FastAPI, no HTTP) — covers the decision matrix and the
    single-use marker write.

  * Route tests of `GET/POST /setup` — covers rate limiting, the
    503/403/redirect surfaces, and end-to-end claim → session cookie.

The route tests stand up their own FastAPI app with a writable
`_FakeUserStore` so they can pre-seed the bootstrap admin record
and assert single-use semantics across two calls.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit import bootstrap_claim
from iam_jit.app import create_app
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.store import FilesystemStore
from iam_jit.users_store import User, UserNotFound


class _FakeUserStore:
    """Writable in-memory user store, contract-compatible with the
    `UserStore` Protocol. Used by both layers of tests."""

    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.put_failures = 0

    def get(self, user_id: str) -> User:
        if user_id not in self.users:
            raise UserNotFound(user_id)
        return self.users[user_id]

    def list(self, *, include_disabled: bool = False) -> list[User]:
        if include_disabled:
            return list(self.users.values())
        return [u for u in self.users.values() if u.enabled]

    def put(self, user: User) -> None:
        if self.put_failures > 0:
            self.put_failures -= 1
            raise RuntimeError("simulated transient DDB error")
        self.users[user.id] = user

    def delete(self, user_id: str) -> None:
        self.users.pop(user_id, None)


_ADMIN_EMAIL = "founder@example.com"
_ADMIN_ID = f"email:{_ADMIN_EMAIL}"
_GOOD_KEY = "a" * 64  # any constant-time-comparable value works


def _seed_bootstrap_admin(store: _FakeUserStore, *, notes: str | None = None) -> None:
    store.put(
        User(
            id=_ADMIN_ID,
            roles=("admin",),
            enabled=True,
            display_name="Bootstrap admin",
            notes=notes,
        )
    )


# ---- evaluate_and_claim: decision matrix ----


def test_claim_success_marks_user_as_claimed() -> None:
    store = _FakeUserStore()
    _seed_bootstrap_admin(store)
    decision = bootstrap_claim.evaluate_and_claim(
        submitted_email=_ADMIN_EMAIL,
        submitted_key=_GOOD_KEY,
        admin_bootstrap_email=_ADMIN_EMAIL,
        bootstrap_setup_key=_GOOD_KEY,
        user_store=store,
    )
    assert decision.success is True
    assert decision.reason == "success"
    assert decision.user_id == _ADMIN_ID
    assert "[claimed at " in (store.users[_ADMIN_ID].notes or "")


def test_claim_normalizes_submitted_email_casing_and_whitespace() -> None:
    store = _FakeUserStore()
    _seed_bootstrap_admin(store)
    decision = bootstrap_claim.evaluate_and_claim(
        submitted_email="  FOUNDER@EXAMPLE.COM  ",
        submitted_key=_GOOD_KEY,
        admin_bootstrap_email=_ADMIN_EMAIL,
        bootstrap_setup_key=_GOOD_KEY,
        user_store=store,
    )
    assert decision.success is True


def test_claim_invalid_key_refused_constant_time() -> None:
    store = _FakeUserStore()
    _seed_bootstrap_admin(store)
    decision = bootstrap_claim.evaluate_and_claim(
        submitted_email=_ADMIN_EMAIL,
        submitted_key="wrong-key",
        admin_bootstrap_email=_ADMIN_EMAIL,
        bootstrap_setup_key=_GOOD_KEY,
        user_store=store,
    )
    assert decision.success is False
    assert decision.reason == "invalid_key"
    # User record was NOT written (no claim marker).
    assert store.users[_ADMIN_ID].notes in (None, "")


def test_claim_email_mismatch_refused() -> None:
    store = _FakeUserStore()
    _seed_bootstrap_admin(store)
    decision = bootstrap_claim.evaluate_and_claim(
        submitted_email="someone-else@example.com",
        submitted_key=_GOOD_KEY,
        admin_bootstrap_email=_ADMIN_EMAIL,
        bootstrap_setup_key=_GOOD_KEY,
        user_store=store,
    )
    assert decision.success is False
    assert decision.reason == "email_mismatch"


def test_claim_no_admin_configured() -> None:
    store = _FakeUserStore()
    decision = bootstrap_claim.evaluate_and_claim(
        submitted_email=_ADMIN_EMAIL,
        submitted_key=_GOOD_KEY,
        admin_bootstrap_email="",
        bootstrap_setup_key=_GOOD_KEY,
        user_store=store,
    )
    assert decision.success is False
    assert decision.reason == "no_admin_configured"


def test_claim_no_secret_configured() -> None:
    store = _FakeUserStore()
    _seed_bootstrap_admin(store)
    decision = bootstrap_claim.evaluate_and_claim(
        submitted_email=_ADMIN_EMAIL,
        submitted_key=_GOOD_KEY,
        admin_bootstrap_email=_ADMIN_EMAIL,
        bootstrap_setup_key="",
        user_store=store,
    )
    assert decision.success is False
    assert decision.reason == "no_secret_configured"


def test_claim_bootstrap_user_missing() -> None:
    store = _FakeUserStore()  # empty
    decision = bootstrap_claim.evaluate_and_claim(
        submitted_email=_ADMIN_EMAIL,
        submitted_key=_GOOD_KEY,
        admin_bootstrap_email=_ADMIN_EMAIL,
        bootstrap_setup_key=_GOOD_KEY,
        user_store=store,
    )
    assert decision.success is False
    assert decision.reason == "bootstrap_user_missing"


def test_claim_already_claimed_is_single_use() -> None:
    store = _FakeUserStore()
    _seed_bootstrap_admin(store)
    first = bootstrap_claim.evaluate_and_claim(
        submitted_email=_ADMIN_EMAIL,
        submitted_key=_GOOD_KEY,
        admin_bootstrap_email=_ADMIN_EMAIL,
        bootstrap_setup_key=_GOOD_KEY,
        user_store=store,
    )
    assert first.success is True
    second = bootstrap_claim.evaluate_and_claim(
        submitted_email=_ADMIN_EMAIL,
        submitted_key=_GOOD_KEY,
        admin_bootstrap_email=_ADMIN_EMAIL,
        bootstrap_setup_key=_GOOD_KEY,
        user_store=store,
    )
    assert second.success is False
    assert second.reason == "already_claimed"


def test_claim_store_write_failure_surfaces_as_reason() -> None:
    store = _FakeUserStore()
    _seed_bootstrap_admin(store)
    store.put_failures = 1  # next put() raises
    decision = bootstrap_claim.evaluate_and_claim(
        submitted_email=_ADMIN_EMAIL,
        submitted_key=_GOOD_KEY,
        admin_bootstrap_email=_ADMIN_EMAIL,
        bootstrap_setup_key=_GOOD_KEY,
        user_store=store,
    )
    assert decision.success is False
    assert decision.reason == "store_write_failed"


def test_claim_url_has_no_secret() -> None:
    url = bootstrap_claim.claim_url(base_url="https://abc123.lambda-url.us-east-1.on.aws/")
    assert url == "https://abc123.lambda-url.us-east-1.on.aws/setup"
    assert _GOOD_KEY not in url


# ---- /setup route tests ----


@pytest.fixture
def setup_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> tuple[Any, _FakeUserStore]:
    """Stand up a fresh FastAPI app wired to a writable in-memory user
    store. Each test gets its own app so rate-limit + claim state are
    isolated."""
    from iam_jit import (
        bans as _bans,
        cidr_store as _cidrs,
        magic_link_nonces as _nonces,
        rate_limit as _rl,
    )
    _rl.reset_default_limiter_for_tests()
    _bans.reset_default_store_for_tests()
    _nonces.reset_default_store_for_tests()
    _cidrs.reset_default_store_for_tests()

    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", "x" * 40)
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", _ADMIN_EMAIL)
    monkeypatch.setenv("IAM_JIT_BOOTSTRAP_SETUP_KEY", _GOOD_KEY)
    # Allow inseure cookie (TestClient is http://) so the redirect
    # actually carries a Set-Cookie we can assert on.
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")

    store = _FakeUserStore()
    _seed_bootstrap_admin(store)

    app = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=store,
        api_tokens_store=InMemoryAPITokenStore(),
    )
    return app, store


def test_setup_get_renders_form(setup_app) -> None:
    app, _ = setup_app
    client = TestClient(app)
    r = client.get("/setup")
    assert r.status_code == 200
    assert "Bootstrap setup" in r.text
    assert "BootstrapSetupKey" in r.text


def test_setup_post_success_sets_session_and_redirects(setup_app) -> None:
    app, store = setup_app
    client = TestClient(app, follow_redirects=False)
    r = client.post("/setup", data={"email": _ADMIN_EMAIL, "key": _GOOD_KEY})
    assert r.status_code == 303
    assert r.headers["location"] == "/admin/network"
    assert "iam_jit_session" in r.cookies
    assert "[claimed at " in (store.users[_ADMIN_ID].notes or "")


def test_setup_post_is_single_use(setup_app) -> None:
    app, _ = setup_app
    client = TestClient(app, follow_redirects=False)
    r1 = client.post("/setup", data={"email": _ADMIN_EMAIL, "key": _GOOD_KEY})
    assert r1.status_code == 303
    # Fresh client so the first call's session cookie doesn't auto-redirect.
    client2 = TestClient(app, follow_redirects=False)
    r2 = client2.post("/setup", data={"email": _ADMIN_EMAIL, "key": _GOOD_KEY})
    assert r2.status_code == 200  # form re-rendered with error
    assert "already consumed" in r2.text


def test_setup_post_invalid_key_uniform_error(setup_app) -> None:
    app, _ = setup_app
    client = TestClient(app, follow_redirects=False)
    r = client.post("/setup", data={"email": _ADMIN_EMAIL, "key": "wrong"})
    assert r.status_code == 200
    assert "rejected" in r.text
    # Make sure the body doesn't leak which gate failed.
    assert "email_mismatch" not in r.text
    assert "invalid_key" not in r.text


def test_setup_post_email_mismatch_uniform_error(setup_app) -> None:
    app, _ = setup_app
    client = TestClient(app, follow_redirects=False)
    r = client.post(
        "/setup",
        data={"email": "someone-else@example.com", "key": _GOOD_KEY},
    )
    assert r.status_code == 200
    assert "rejected" in r.text


def test_setup_post_no_secret_configured_returns_503(monkeypatch: pytest.MonkeyPatch, setup_app) -> None:
    app, _ = setup_app
    monkeypatch.setenv("IAM_JIT_BOOTSTRAP_SETUP_KEY", "")
    client = TestClient(app, follow_redirects=False)
    r = client.post("/setup", data={"email": _ADMIN_EMAIL, "key": _GOOD_KEY})
    assert r.status_code == 503
    assert "not available" in r.text


def test_setup_post_rate_limited(monkeypatch: pytest.MonkeyPatch, setup_app) -> None:
    """Burst of invalid posts should trip the per-IP setup rate limiter
    before the claim logic burns through tries. The route uses the
    shared default limiter; install a tight-capped one so the assertion
    doesn't depend on production thresholds."""
    app, _ = setup_app
    from iam_jit import rate_limit as _rl

    monkeypatch.setenv("IAM_JIT_CHAT_RATE_SOFT_CAP", "1")
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_HARD_CAP", "2")
    _rl.reset_default_limiter_for_tests()
    client = TestClient(app, follow_redirects=False)
    statuses = [
        client.post("/setup", data={"email": _ADMIN_EMAIL, "key": "x"}).status_code
        for _ in range(5)
    ]
    assert 429 in statuses
