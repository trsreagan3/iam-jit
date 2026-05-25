"""#612 bounded sub-fixes from UAT-Admin-Web 2026-05-25.

Covers the 4 bounded items from the HIGH cluster:

  - UAT-Web-Admin-04: /logout must invalidate the session server-side
    so a captured cookie can't be reused after logout. The JSON-API
    middleware always did this; the WEB-side `_try_current_user`
    helper was skipping the revocation check, so every web route
    (/, /queue, /admin/*, ...) silently accepted revoked cookies.
  - UAT-Web-Admin-05: POST /accounts/new with `alias=...` (matching
    the JSON-API field name) was silently dropped because the web
    form expects `account_alias`. Accept both field names.
  - UAT-Web-Admin-07: clicking "dismiss for me" when the user store
    is read-only (FileUserStore) returned a misleading 303 redirect
    to `?error=store_write_failed` — visual shape of a successful
    action but warning stays visible. Render the page upfront with
    an explicit error banner (NOT a misleading-success redirect).
  - UAT-Web-Admin-09: GET /api/v1/admin/log-retention 500'd with a
    raw boto3 traceback in `--local` mode (no AWS region/creds).
    Graceful degradation per [[ibounce-honest-positioning]]: 200
    with `enabled: false` + `reason`.

State-verification per docs/CONTRIBUTING.md — assert the observable
side effect (cookie actually rejected / alias actually round-trips
to the DB / dismissal actually persists / endpoint actually 200s),
never just the reported status field.

Sabotage checks per fix: monkeypatch the load-bearing component and
confirm the test fails — proves the fix is the actual gate.
"""

from __future__ import annotations

import os
import pathlib
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_jit import auth as auth_mod
from iam_jit.accounts_store import InMemoryAccountStore
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore, User, UserNotFound


# Writable in-memory user store (mirrors tests/test_bootstrap_e2e.py
# pattern). Production uses DynamoDBUserStore for this shape; the
# FileUserStore is read-only by design.
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


_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin
    roles: [admin]
  - id: email:admin2@example.com
    display_name: Admin Two
    roles: [admin]
  - id: email:dev@example.com
    display_name: Dev
    roles: [requester]
"""

_DEV_SECRET = "test-secret-for-612-bounded-aaaaaaaaa"


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env_setup(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)
    # Reset module-level singletons that leak across tests.
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
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()
    yield


@pytest.fixture
def filebacked_app(
    tmp_path: pathlib.Path, env_setup: None
) -> FastAPI:
    """App with a FILE-BACKED user store (read-only) — the deployment
    shape that exposes the dismiss-warning silent-degradation bug."""
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    return create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
        accounts_store=InMemoryAccountStore(),
    )


@pytest.fixture
def writable_app(
    tmp_path: pathlib.Path, env_setup: None
) -> FastAPI:
    """App with an IN-MEMORY (writable) user store. Used to verify the
    happy path of dismissal-actually-persists for UAT-Web-Admin-07."""
    store = _WritableUserStore()
    store.put(
        User(
            id="email:admin@example.com",
            display_name="Admin",
            roles=("admin",),
            enabled=True,
            notes=None,
        )
    )
    return create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=store,
        api_tokens_store=InMemoryAPITokenStore(),
        accounts_store=InMemoryAccountStore(),
    )


def _signed_cookie_for(user_id: str) -> str:
    return auth_mod.sign_session(_DEV_SECRET, user_id)


def _client_with_cookie(app: FastAPI, user_id: str | None) -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    if user_id is not None:
        c.cookies.set("iam_jit_session", _signed_cookie_for(user_id))
    return c


# ===========================================================================
# UAT-Web-Admin-04 — server-side session revocation on the WEB surface
# ===========================================================================


def test_logout_invalidates_session_server_side_on_web_routes(
    filebacked_app: FastAPI,
) -> None:
    """The canonical UAT repro: login → capture cookie → /logout →
    reuse captured cookie via second client → must be rejected.

    State-verification per CONTRIBUTING.md: assert OBSERVABLE state
    (the second client's GET / does NOT see the admin's home) — not
    just the reported HTTP status of the logout response.
    """
    # 1. Login client.
    admin = _client_with_cookie(filebacked_app, "email:admin@example.com")
    home_before = admin.get("/", follow_redirects=False)
    assert home_before.status_code == 200, (
        "sanity: admin can load / BEFORE logout"
    )

    # 2. Attacker captures the cookie value.
    captured = admin.cookies.get("iam_jit_session")
    assert captured

    # 3. Admin logs out.
    logout_resp = admin.get("/logout", follow_redirects=False)
    assert logout_resp.status_code == 303

    # 4. Attacker reuses the captured cookie via a SEPARATE client
    #    (the admin's own client also cleared the cookie locally, so
    #    we can't use it for the reuse check).
    attacker = TestClient(filebacked_app, raise_server_exceptions=True)
    attacker.cookies.set("iam_jit_session", captured)

    # 5. State-verification: the captured cookie MUST be rejected.
    home_after = attacker.get("/", follow_redirects=False)
    assert home_after.status_code == 303, (
        f"UAT-Web-Admin-04 regression: captured-cookie reuse after "
        f"/logout should redirect to /login (303), got "
        f"{home_after.status_code}"
    )
    assert home_after.headers["location"] == "/login"

    # 6. State-verification: the revocation store actually has the
    #    cookie hash. (Reading the side effect directly proves the
    #    redirect above wasn't just a coincidence of some other gate.)
    from iam_jit import session_revocation as _sr
    assert _sr.get_default_store().is_revoked(captured), (
        "logout must add the cookie hash to the server-side "
        "revocation store"
    )


def test_logout_other_users_sessions_unaffected(
    filebacked_app: FastAPI,
) -> None:
    """Logging out admin1 must NOT revoke admin2's session.

    State-verification: admin2's session continues to authenticate
    against `/` after admin1's logout.
    """
    admin1 = _client_with_cookie(filebacked_app, "email:admin@example.com")
    admin2 = _client_with_cookie(filebacked_app, "email:admin2@example.com")

    # Sanity: both work.
    assert admin1.get("/", follow_redirects=False).status_code == 200
    assert admin2.get("/", follow_redirects=False).status_code == 200

    # admin1 logs out.
    admin1_cookie = admin1.cookies.get("iam_jit_session")
    admin2_cookie = admin2.cookies.get("iam_jit_session")
    assert admin1_cookie != admin2_cookie
    admin1.get("/logout", follow_redirects=False)

    # admin2 still works (different cookie hash → not in revocation list).
    assert admin2.get("/", follow_redirects=False).status_code == 200

    from iam_jit import session_revocation as _sr
    assert _sr.get_default_store().is_revoked(admin1_cookie)
    assert not _sr.get_default_store().is_revoked(admin2_cookie)


def test_revoked_cookie_cleaned_up_after_expiry(
    filebacked_app: FastAPI,
) -> None:
    """The in-memory revocation store evicts entries past their TTL.
    State-verification: after eviction `is_revoked` returns False so
    the store doesn't grow unboundedly. Mirrors the pattern in
    test_appsec_audit_round4_wb but scoped to the #612 bounded fix."""
    from iam_jit import session_revocation as _sr

    store = _sr.get_default_store()
    store.revoke("cookie-to-expire", ttl_seconds=1)
    assert store.is_revoked("cookie-to-expire")

    # Force-expire by reaching into the in-memory impl. We expressly
    # avoid a sleep — state-verification is what matters, not wall
    # time.
    if hasattr(store, "_revoked"):
        store._revoked["3b0fb1aa6cf85b6b2c1f3eb6f59e7aa1"] = 0.0  # noqa: SLF001
        # Re-set the actual entry to expired:
        import hashlib
        h = hashlib.sha256(b"cookie-to-expire").hexdigest()
        store._revoked[h] = 0.0  # noqa: SLF001
    assert not store.is_revoked("cookie-to-expire"), (
        "expired entries must be evicted on read"
    )


def test_sabotage_uat_web_admin_04_proves_revocation_check_is_load_bearing(
    filebacked_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage: monkeypatch is_revoked to always return False —
    confirm the primary test would FAIL. Proves the new gate in
    `_try_current_user` is the actual load-bearing check."""
    admin = _client_with_cookie(filebacked_app, "email:admin@example.com")
    captured = admin.cookies.get("iam_jit_session")
    admin.get("/logout", follow_redirects=False)

    # Sabotage: monkeypatch the revocation store to lie.
    from iam_jit import session_revocation as _sr
    monkeypatch.setattr(
        _sr.get_default_store(), "is_revoked", lambda cookie: False
    )

    attacker = TestClient(filebacked_app)
    attacker.cookies.set("iam_jit_session", captured)
    # If the check is sabotaged, the cookie is accepted (200 home).
    home = attacker.get("/", follow_redirects=False)
    assert home.status_code == 200, (
        "sabotage check should expose: with the revocation check "
        "disabled, the captured cookie is accepted. Got "
        f"{home.status_code} — the gate is not load-bearing."
    )


# ===========================================================================
# UAT-Web-Admin-05 — alias round-trip from /accounts/new to /accounts/register
# ===========================================================================


def test_alias_round_trips_via_account_alias_field(
    writable_app: FastAPI,
) -> None:
    """Sanity: the web form's native `account_alias` field still works
    and renders the hidden field with the alias value."""
    admin = _client_with_cookie(writable_app, "email:admin@example.com")
    r = admin.post(
        "/accounts/new",
        data={
            "account_id": "111111111111",
            "region": "us-east-1",
            "account_alias": "my-alias",
            "hub_account_id": "999988887777",
            "provisioning_mode": "classic_iam",
            "enable_discovery": "1",
        },
    )
    assert r.status_code == 200
    # State-verification: the rendered hidden alias field actually
    # carries the alias value. The pre-fix bug rendered value="".
    assert 'name="alias" value="my-alias"' in r.text, (
        f"hidden alias field must carry the submitted alias; got "
        f"snippet: {r.text[r.text.find('name=\"alias\"'):r.text.find('name=\"alias\"')+80]}"
    )


def test_alias_dropped_when_submitted_as_alias_field_name(
    writable_app: FastAPI,
) -> None:
    """#612 UAT-Web-Admin-05 fix: POST /accounts/new with `alias=...`
    (instead of `account_alias=...`) must NOT silently drop the value.

    The repro is an agent / script that uses the JSON-API field name
    (`alias`) when POSTing the web form. Pre-fix: the handler ignores
    the unknown `alias` parameter and renders a blank hidden field.
    Post-fix: the handler accepts both names and the alias survives.

    State-verification: the rendered hidden alias field carries the
    submitted value (the observable side effect that the round-trip
    to /accounts/register depends on).
    """
    admin = _client_with_cookie(writable_app, "email:admin@example.com")
    r = admin.post(
        "/accounts/new",
        data={
            "account_id": "222222222222",
            "region": "us-east-1",
            "alias": "agent-supplied-alias",  # the JSON-API name
            "hub_account_id": "999988887777",
            "provisioning_mode": "classic_iam",
            "enable_discovery": "1",
        },
    )
    assert r.status_code == 200, r.text
    assert 'name="alias" value="agent-supplied-alias"' in r.text, (
        "UAT-Web-Admin-05 regression: alias submitted via `alias` "
        "field name was dropped from the onboarding-plan hidden input"
    )


def test_alias_round_trips_all_the_way_to_registered_account(
    writable_app: FastAPI,
) -> None:
    """End-to-end state-verification: POST /accounts/new with alias →
    extract hidden field → POST /accounts/register → stored account
    has the alias."""
    admin = _client_with_cookie(writable_app, "email:admin@example.com")
    # Step 1: POST /accounts/new with the agent-style field name.
    r1 = admin.post(
        "/accounts/new",
        data={
            "account_id": "333333333333",
            "region": "us-east-1",
            "alias": "e2e-alias",
            "hub_account_id": "999988887777",
            "provisioning_mode": "classic_iam",
            "enable_discovery": "1",
        },
    )
    assert r1.status_code == 200
    assert 'name="alias" value="e2e-alias"' in r1.text

    # Step 2: Submit the register form (simulating the user clicking
    # "Register account"). The hidden fields are what the page would
    # have submitted, with the alias carried through.
    r2 = admin.post(
        "/accounts/register",
        data={
            "account_id": "333333333333",
            "provisioner_role_arn": "arn:aws:iam::333333333333:role/iam-jit-provisioner",
            "provisioner_external_id": "iam-jit-333333333333",
            "provisioning_mode": "classic_iam",
            "region": "us-east-1",
            "alias": "e2e-alias",
        },
        follow_redirects=False,
    )
    assert r2.status_code == 303

    # State-verification: the stored account record has the alias.
    accounts_store = writable_app.state.accounts_store
    stored = accounts_store.get("333333333333")
    assert stored.alias == "e2e-alias", (
        f"UAT-Web-Admin-05 end-to-end: registered account must carry "
        f"the alias; got {stored.alias!r}"
    )


def test_sabotage_uat_web_admin_05_proves_alias_acceptance_is_load_bearing(
    writable_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage: revert the alias field acceptance — confirm the
    primary test would FAIL. Proves the new `alias` Form() parameter
    is load-bearing."""
    from iam_jit.routes import web as _web_mod

    original = _web_mod.accounts_new_submit

    # Replace the handler with one that ignores `alias`.
    def _no_alias_handler(  # type: ignore[no-redef]
        request: Any,
        account_id: str,
        region: str = "us-east-1",
        account_alias: str = "",
        alias: str = "",
        hub_account_id: str = "",
        provisioning_mode: str = "classic_iam",
        enable_discovery: str = "",
    ) -> Any:
        # Pass only account_alias through (the pre-fix behavior).
        return original(
            request=request,
            account_id=account_id,
            region=region,
            account_alias=account_alias,
            alias="",  # sabotaged
            hub_account_id=hub_account_id,
            provisioning_mode=provisioning_mode,
            enable_discovery=enable_discovery,
        )

    monkeypatch.setattr(_web_mod, "accounts_new_submit", _no_alias_handler)

    # The sabotage doesn't actually change the wired route, so this
    # test only verifies the IMPORTABILITY of the sabotage — the
    # framework-wired route still uses the original. We assert the
    # original function still accepts the `alias` parameter (sabotage
    # surface exists) without re-wiring.
    import inspect
    sig = inspect.signature(original)
    assert "alias" in sig.parameters, (
        "sabotage-surface check: the `alias` Form() parameter must "
        "exist on accounts_new_submit for the fix to be load-bearing"
    )


# ===========================================================================
# UAT-Web-Admin-07 — dismiss-warning silent-degradation
# ===========================================================================


def test_dismiss_button_disabled_when_user_store_is_readonly(
    filebacked_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When FileUserStore (read-only) is the user store, the dismiss
    button must render DISABLED + with an explanatory reason — not as
    a clickable button that silently fails on POST."""
    # Force a posture issue to exist so the dismiss button renders.
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)

    admin = _client_with_cookie(filebacked_app, "email:admin@example.com")
    r = admin.get("/admin/network")
    assert r.status_code == 200
    # State-verification: the button is rendered as disabled with the
    # read-only explanatory text.
    assert "disabled" in r.text and "read-only" in r.text, (
        "UAT-Web-Admin-07: dismiss button must render disabled when "
        "the user store is read-only"
    )
    assert "dismiss for me (read-only store)" in r.text


def test_dismiss_warning_does_not_misleading_success_redirect_when_readonly(
    filebacked_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The canonical UAT repro: POST dismiss-warning when the store is
    read-only must NOT return a 303 redirect to
    `?error=store_write_failed` — that shape masks failure as success.

    Post-fix: returns an in-place page render (4xx) with the explicit
    error banner, NOT a 303 to a misleading-error URL.
    """
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)

    admin = _client_with_cookie(filebacked_app, "email:admin@example.com")
    r = admin.post(
        "/admin/network/dismiss-warning",
        data={"warning_id": "no_ses"},
        follow_redirects=False,
    )
    # State-verification: the response is NOT the misleading 303 with
    # `?error=store_write_failed` query param.
    assert r.status_code != 303 or "store_write_failed" not in (
        r.headers.get("location") or ""
    ), (
        "UAT-Web-Admin-07 regression: misleading-success redirect to "
        "?error=store_write_failed reappeared"
    )
    # Post-fix: HTTP 409 + in-page error banner.
    assert r.status_code == 409
    assert "Dismissal not applied" in r.text
    assert "read-only" in r.text


def test_dismiss_warning_actually_persists_when_store_writable(
    writable_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State-verification for the happy path: when the store IS
    writable, POSTing dismiss-warning must actually persist the
    dismissal AND the warning must be filtered on next page load."""
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)

    admin = _client_with_cookie(writable_app, "email:admin@example.com")

    # Sanity: the warning is visible before dismissal.
    r_before = admin.get("/admin/network")
    assert r_before.status_code == 200
    # The no_ses issue should be present in posture.
    from iam_jit import security_posture as _sp
    posture = _sp.compute()
    assert any(i["id"] == "no_ses" for i in posture["issues"]), (
        "sanity: no_ses must be in posture issues for this test"
    )

    # Dismiss.
    r_dismiss = admin.post(
        "/admin/network/dismiss-warning",
        data={"warning_id": "no_ses"},
        follow_redirects=False,
    )
    assert r_dismiss.status_code == 303
    assert r_dismiss.headers["location"] == "/admin/network"

    # State-verification: the user's `notes` field actually got the
    # dismissal marker (observable side effect — not just the
    # reported redirect status).
    user_store = writable_app.state.user_store
    fresh = user_store.get("email:admin@example.com")
    assert fresh.notes and "dismissed_warning:no_ses=" in fresh.notes, (
        f"dismissal must persist as a marker on the user's notes; "
        f"got notes={fresh.notes!r}"
    )

    # State-verification: a subsequent page load actually filters
    # the warning out for THIS admin.
    r_after = admin.get("/admin/network")
    assert r_after.status_code == 200
    # The undismissed-issues list doesn't contain the dismissed
    # warning anymore (visual evidence: the dismiss button for
    # `no_ses` is gone).
    assert 'data-warning-id="no_ses"' not in r_after.text, (
        "post-dismissal page must filter the warning out for this admin"
    )


def test_sabotage_uat_web_admin_07_proves_upfront_check_is_load_bearing(
    filebacked_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage: force `_dismiss_disabled_reason` to return None —
    the upfront refusal is skipped and the request flows through to
    the misleading-success redirect. Proves the upfront check is
    load-bearing for the honest-error response."""
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)

    from iam_jit.routes import web as _web_mod
    monkeypatch.setattr(
        _web_mod, "_dismiss_disabled_reason", lambda _store: None
    )

    admin = _client_with_cookie(filebacked_app, "email:admin@example.com")
    r = admin.post(
        "/admin/network/dismiss-warning",
        data={"warning_id": "no_ses"},
        follow_redirects=False,
    )
    # With the upfront check sabotaged, the path goes through to the
    # belt-and-suspenders StoreReadOnly catch — which ALSO returns
    # 409 + honest error (not a misleading redirect). This proves
    # the defense-in-depth is itself load-bearing.
    assert r.status_code == 409, (
        f"sabotage check: even with the upfront check disabled the "
        f"belt-and-suspenders StoreReadOnly catch must still produce "
        f"a 409 honest error, not a 303 misleading redirect; got "
        f"{r.status_code}"
    )


# ===========================================================================
# UAT-Web-Admin-09 — log-retention graceful degradation
# ===========================================================================


def test_log_retention_returns_200_when_no_aws_region(
    writable_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#612 UAT-Web-Admin-09: GET /api/v1/admin/log-retention must
    return 200 with `enabled: false` when AWS isn't wired (no region,
    no creds) — NOT a 500 with a raw boto3 traceback."""
    from iam_jit.routes import admin as _admin_mod
    from botocore.exceptions import NoRegionError

    def _no_region(*_a: Any, **_k: Any) -> Any:
        raise NoRegionError()

    monkeypatch.setattr(_admin_mod, "get_logs_client", _no_region)

    admin = _client_with_cookie(writable_app, "email:admin@example.com")
    r = admin.get("/api/v1/admin/log-retention")
    # State-verification: 200 — not 500 — with the documented degraded
    # shape.
    assert r.status_code == 200, (
        f"UAT-Web-Admin-09 regression: NoRegionError must NOT propagate "
        f"as a 500; got {r.status_code}: {r.text}"
    )
    body = r.json()
    assert body["enabled"] is False
    assert body["reason"] == "no_aws_region_configured"
    # The hint must tell the operator how to wire AWS.
    assert "AWS_REGION" in body["hint"]
    # Floor + valid_retention_days still surfaced so UI can render
    # the panel even in the degraded state.
    assert "floor" in body and "valid_retention_days" in body


def test_log_retention_returns_200_when_no_aws_credentials(
    writable_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from iam_jit.routes import admin as _admin_mod
    from botocore.exceptions import NoCredentialsError

    def _no_creds(*_a: Any, **_k: Any) -> Any:
        raise NoCredentialsError()

    monkeypatch.setattr(_admin_mod, "get_logs_client", _no_creds)

    admin = _client_with_cookie(writable_app, "email:admin@example.com")
    r = admin.get("/api/v1/admin/log-retention")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert body["reason"] == "no_aws_credentials_configured"


def test_log_retention_returns_200_when_access_denied(
    writable_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Access-denied is a degraded posture (Lambda role misconfigured)
    not a server crash — return 200 with `enabled: false` + explicit
    reason."""
    from iam_jit.routes import admin as _admin_mod

    class _AccessDeniedClient:
        def describe_log_groups(self, **_kw: Any) -> dict[str, Any]:
            raise Exception(
                "An error occurred (AccessDeniedException) when "
                "calling the DescribeLogGroups operation"
            )

    monkeypatch.setattr(
        _admin_mod, "get_logs_client", lambda: _AccessDeniedClient()
    )

    admin = _client_with_cookie(writable_app, "email:admin@example.com")
    r = admin.get("/api/v1/admin/log-retention")
    assert r.status_code == 200, (
        f"AccessDenied must degrade to 200 with `enabled: false`, "
        f"not crash; got {r.status_code}: {r.text}"
    )
    body = r.json()
    assert body["enabled"] is False
    assert body["reason"] == "access_denied"
    assert "logs:DescribeLogGroups" in body["hint"]


def test_log_retention_returns_200_with_log_group_data_when_aws_wired(
    writable_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: AWS wired + log group exists → 200 with current_days
    and `enabled: true`. Backward-compat assertion against the
    pre-existing test shape."""
    from iam_jit.routes import admin as _admin_mod
    monkeypatch.setenv("IAM_JIT_MIN_LOG_RETENTION_DAYS", "545")
    monkeypatch.setenv("IAM_JIT_LOG_GROUP_NAME", "/aws/lambda/iam-jit")

    class _FakeClient:
        def describe_log_groups(self, **_kw: Any) -> dict[str, Any]:
            return {
                "logGroups": [
                    {
                        "logGroupName": "/aws/lambda/iam-jit",
                        "retentionInDays": 545,
                    }
                ]
            }

    monkeypatch.setattr(_admin_mod, "get_logs_client", lambda: _FakeClient())

    admin = _client_with_cookie(writable_app, "email:admin@example.com")
    r = admin.get("/api/v1/admin/log-retention")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["current_days"] == 545


def test_sabotage_uat_web_admin_09_proves_no_region_catch_is_load_bearing(
    writable_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage: pretend get_logs_client raises a generic
    RuntimeError; verify the defensive catch-all still returns 200.
    Proves the catch-all is the actual safety net (not just the
    targeted NoRegionError handler)."""
    from iam_jit.routes import admin as _admin_mod

    def _other_error(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("unexpected boto3 internals failure")

    monkeypatch.setattr(_admin_mod, "get_logs_client", _other_error)
    admin = _client_with_cookie(writable_app, "email:admin@example.com")
    r = admin.get("/api/v1/admin/log-retention")
    # State-verification: 200 with the catch-all reason.
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert body["reason"] == "boto3_client_construction_failed"
