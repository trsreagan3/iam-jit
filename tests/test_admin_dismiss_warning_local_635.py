"""#635 — POST /api/v1/admin/dismiss-warning returns 409 (not 500)
in local mode when FileUserStore is read-only.

Symptom: user_store.put() raises StoreReadOnly (FileUserStore is
intentionally read-only at runtime); the exception was unhandled →
generic 500. Fix: catch StoreReadOnly, return 409 with a helpful
FileUserStore explanation. Mirrors _dismiss_disabled_reason() in
web.py:1717 per [[cross-product-agent-parity]].

State-verification per CONTRIBUTING.md:
  * POST dismiss-warning in local-mode (FileUserStore) → 409 with message.
  * Detail must mention FileUserStore or "read-only" or DynamoDB.
  * Sabotage check: monkeypatch the catch to no-op → 500 returns,
    proving the catch is the load-bearing gate.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_jit import auth as auth_mod
from iam_jit.accounts_store import InMemoryAccountStore
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore, StoreReadOnly


_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin
    roles: [admin]
"""

_DEV_SECRET = "test-secret-for-635-dismiss-aaaa"

# A known warning_id that security_posture.compute() will return in our
# monkeypatched version — avoids ALB env-var gymnastics.
_FAKE_WARNING_ID = "test_posture_issue_635"


@pytest.fixture
def env_setup(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)
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


@pytest.fixture
def filebacked_app(tmp_path: pathlib.Path, env_setup: None) -> FastAPI:
    """App backed by FileUserStore (read-only at runtime)."""
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    return create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
        accounts_store=InMemoryAccountStore(),
    )


def _admin_client(app: FastAPI) -> TestClient:
    c = TestClient(app, raise_server_exceptions=False)
    c.cookies.set(
        "iam_jit_session",
        auth_mod.sign_session(_DEV_SECRET, "email:admin@example.com"),
    )
    return c


# ---------------------------------------------------------------------------
# #635 core: 409 with helpful message in local mode
# ---------------------------------------------------------------------------


def test_dismiss_warning_local_mode_returns_409_not_500(
    filebacked_app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /api/v1/admin/dismiss-warning in local (FileUserStore) mode
    MUST return 409 with a helpful explanation — not an opaque 500.

    State-verification: assert status == 409 and the detail mentions
    the read-only store constraint."""
    # Monkeypatch security_posture.compute() to return a known warning.
    from iam_jit import security_posture as _sp
    monkeypatch.setattr(
        _sp,
        "compute",
        lambda: {
            "issues": [
                {
                    "id": _FAKE_WARNING_ID,
                    "severity": "warn",
                    "title": "test issue 635",
                    "detail": "synthetic posture issue for test",
                    "fix": "n/a",
                }
            ]
        },
    )

    admin = _admin_client(filebacked_app)
    resp = admin.post(
        "/api/v1/admin/dismiss-warning",
        json={"warning_id": _FAKE_WARNING_ID},
    )
    assert resp.status_code == 409, (
        f"#635 regression: expected 409, got {resp.status_code}. "
        f"Body: {resp.text[:300]}"
    )
    detail = resp.json().get("detail", "")
    hint_text = detail if isinstance(detail, str) else str(detail)
    assert any(
        kw in hint_text.lower()
        for kw in ("fileuser", "read-only", "dynamodb", "writable")
    ), (
        f"#635: 409 detail must mention the FileUserStore/read-only "
        f"constraint; got: {hint_text!r}"
    )


# ---------------------------------------------------------------------------
# Sabotage check — proves the catch is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_without_catch_dismiss_warning_returns_500(
    filebacked_app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the StoreReadOnly catch is removed (sabotaged), the exception
    propagates → 500. This proves the catch in #635 is the load-bearing gate.

    Sabotage: monkeypatch FileUserStore.put to still raise StoreReadOnly,
    but monkeypatch the route handler's catch block to re-raise instead of
    returning 409. We approximate this by patching the exception class that
    the route catches to be a different exception the catch won't match."""
    from iam_jit import security_posture as _sp
    monkeypatch.setattr(
        _sp,
        "compute",
        lambda: {
            "issues": [
                {
                    "id": _FAKE_WARNING_ID,
                    "severity": "warn",
                    "title": "test issue 635",
                    "detail": "synthetic posture issue for sabotage test",
                    "fix": "n/a",
                }
            ]
        },
    )

    # Monkeypatch _StoreReadOnly (the imported alias) in the admin route
    # module to a NEW exception class so the `except _StoreReadOnly` won't
    # catch the real StoreReadOnly that FileUserStore.put raises.
    from iam_jit.routes import admin as _admin_mod

    class _NeverRaised(Exception):
        """Stand-in that will never be raised, so the except block won't fire."""

    monkeypatch.setattr(_admin_mod, "_StoreReadOnly", _NeverRaised)

    admin = _admin_client(filebacked_app)
    resp = admin.post(
        "/api/v1/admin/dismiss-warning",
        json={"warning_id": _FAKE_WARNING_ID},
    )
    # With the catch sabotaged, the StoreReadOnly propagates → 500.
    assert resp.status_code == 500, (
        f"Sabotage check: without the StoreReadOnly catch, status must be "
        f"500, got {resp.status_code} — the catch may no longer be using "
        f"_StoreReadOnly; investigate admin.py dismiss_warning handler"
    )
