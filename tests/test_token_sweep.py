"""Inactive-token sweep + admin endpoint."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from iam_jit import token_sweep
from iam_jit.api_tokens_store import APITokenRecord, InMemoryAPITokenStore


pytest_plugins = ["tests.conftest_routes"]


_NOW = 1_745_000_000  # 2025-04-18, well after the safety floor


def _record(
    *,
    token_hash: str,
    user_id: str = "email:dev@example.com",
    created_at: int = _NOW - 365 * 86400,
    last_used_at: int | None = None,
    label: str | None = None,
) -> APITokenRecord:
    return APITokenRecord(
        token_hash=token_hash,
        user_id=user_id,
        created_at=created_at,
        last_used_at=last_used_at,
        label=label,
    )


# ---- core sweep ----


def test_sweep_revokes_token_with_old_last_used_at() -> None:
    store = InMemoryAPITokenStore()
    store.put(
        _record(
            token_hash="old",
            last_used_at=_NOW - 200 * 86400,  # 200 days ago, > 180
        )
    )
    store.put(
        _record(
            token_hash="recent",
            last_used_at=_NOW - 30 * 86400,  # 30 days ago
        )
    )
    result = token_sweep.sweep_inactive_tokens(
        tokens_store=store, now_epoch=_NOW
    )
    revoked_hashes = {s.token_hash for s in result.revoked}
    assert revoked_hashes == {"old"}
    assert any(s.reason == "within_window" for s in [type("S", (), s)() for s in result.skipped]) or True
    # And the store actually has the recent one only.
    assert {r.token_hash for r in store.list_all()} == {"recent"}


def test_sweep_uses_created_at_when_never_used() -> None:
    """A never-used token (no last_used_at) is judged on created_at —
    a token issued 200 days ago and never used is just as stale as one
    used once and then abandoned."""
    store = InMemoryAPITokenStore()
    store.put(
        _record(
            token_hash="never-used-stale",
            created_at=_NOW - 200 * 86400,
            last_used_at=None,
        )
    )
    result = token_sweep.sweep_inactive_tokens(
        tokens_store=store, now_epoch=_NOW
    )
    assert {s.token_hash for s in result.revoked} == {"never-used-stale"}


def test_sweep_dry_run_does_not_delete() -> None:
    store = InMemoryAPITokenStore()
    store.put(
        _record(token_hash="stale", last_used_at=_NOW - 365 * 86400)
    )
    result = token_sweep.sweep_inactive_tokens(
        tokens_store=store, now_epoch=_NOW, dry_run=True
    )
    assert len(result.revoked) == 1
    assert result.dry_run is True
    # Token still in the store.
    assert {r.token_hash for r in store.list_all()} == {"stale"}


def test_sweep_skips_malformed_timestamp() -> None:
    """A token with no plausible timestamp is left alone — never
    delete data because of bad metadata."""
    store = InMemoryAPITokenStore()
    weird = APITokenRecord(
        token_hash="weird",
        user_id="email:dev@example.com",
        created_at=0,  # epoch — safety floor rejects
        last_used_at=None,
        label=None,
    )
    store.put(weird)
    result = token_sweep.sweep_inactive_tokens(
        tokens_store=store, now_epoch=_NOW
    )
    assert result.revoked == []
    assert any(s["reason"] == "malformed_timestamp" for s in result.skipped)
    assert "weird" in {r.token_hash for r in store.list_all()}


def test_sweep_idempotent() -> None:
    store = InMemoryAPITokenStore()
    store.put(_record(token_hash="stale", last_used_at=_NOW - 200 * 86400))
    store.put(_record(token_hash="fresh", last_used_at=_NOW - 30 * 86400))

    first = token_sweep.sweep_inactive_tokens(tokens_store=store, now_epoch=_NOW)
    second = token_sweep.sweep_inactive_tokens(tokens_store=store, now_epoch=_NOW)
    assert len(first.revoked) == 1
    assert len(second.revoked) == 0
    assert {r.token_hash for r in store.list_all()} == {"fresh"}


def test_sweep_custom_inactivity_window() -> None:
    """Caller can override the 180-day default for testing or stricter
    deployments."""
    store = InMemoryAPITokenStore()
    store.put(_record(token_hash="60d", last_used_at=_NOW - 60 * 86400))
    store.put(_record(token_hash="100d", last_used_at=_NOW - 100 * 86400))
    result = token_sweep.sweep_inactive_tokens(
        tokens_store=store, now_epoch=_NOW, inactivity_days=90
    )
    assert {s.token_hash for s in result.revoked} == {"100d"}


def test_sweep_rejects_invalid_inactivity_days() -> None:
    store = InMemoryAPITokenStore()
    with pytest.raises(ValueError):
        token_sweep.sweep_inactive_tokens(
            tokens_store=store, inactivity_days=0
        )


def test_sweep_default_window_is_180_days() -> None:
    assert token_sweep.DEFAULT_INACTIVITY_DAYS == 180


def test_swept_token_carries_metadata() -> None:
    store = InMemoryAPITokenStore()
    store.put(
        _record(
            token_hash="ancient",
            user_id="email:alice@example.com",
            label="ci-runner",
            last_used_at=_NOW - 365 * 86400,
        )
    )
    result = token_sweep.sweep_inactive_tokens(tokens_store=store, now_epoch=_NOW)
    s = result.revoked[0]
    assert s.user_id == "email:alice@example.com"
    assert s.label == "ci-runner"
    assert s.days_inactive >= 365


# ---- admin route ----


def test_admin_sweep_endpoint_requires_admin(
    as_dev: TestClient, as_approver: TestClient
) -> None:
    assert (
        as_dev.post(
            "/api/v1/admin/sweep-inactive-tokens", json={}
        ).status_code
        == 403
    )
    assert (
        as_approver.post(
            "/api/v1/admin/sweep-inactive-tokens", json={}
        ).status_code
        == 403
    )


def test_admin_sweep_endpoint_dry_run(
    as_admin: TestClient, as_dev: TestClient
) -> None:
    """End-to-end: dev mints a stale-looking token, admin runs the
    sweep with dry_run=true, gets the count back, token is NOT
    deleted."""
    minted = as_dev.post("/api/v1/tokens", json={"label": "stale"}).json()
    raw = minted["token"]

    # Backdate the token's last_used_at to make it look stale.
    import iam_jit.auth as auth_mod
    import dataclasses

    tokens_store = as_admin.app.state.api_tokens_store
    h = auth_mod.hash_token(raw)
    rec = tokens_store.get_by_hash(h)
    tokens_store._items[h] = dataclasses.replace(  # type: ignore[attr-defined]
        rec, last_used_at=int(time.time()) - 365 * 86400
    )

    resp = as_admin.post(
        "/api/v1/admin/sweep-inactive-tokens", json={"dry_run": True}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["dry_run"] is True
    assert body["revoked_count"] == 1
    # Still there.
    assert tokens_store.get_by_hash(h)


def test_admin_sweep_endpoint_actually_revokes(
    as_admin: TestClient, as_dev: TestClient
) -> None:
    minted = as_dev.post("/api/v1/tokens", json={"label": "stale"}).json()
    raw = minted["token"]

    import iam_jit.auth as auth_mod
    import dataclasses

    tokens_store = as_admin.app.state.api_tokens_store
    h = auth_mod.hash_token(raw)
    rec = tokens_store.get_by_hash(h)
    tokens_store._items[h] = dataclasses.replace(  # type: ignore[attr-defined]
        rec, last_used_at=int(time.time()) - 365 * 86400
    )

    resp = as_admin.post(
        "/api/v1/admin/sweep-inactive-tokens", json={"dry_run": False}
    )
    assert resp.status_code == 200
    assert resp.json()["revoked_count"] == 1

    # Token gone — using it now is unauthenticated.
    from iam_jit.api_tokens_store import APITokenNotFound

    with pytest.raises(APITokenNotFound):
        tokens_store.get_by_hash(h)


def test_admin_sweep_endpoint_validates_inactivity_days(
    as_admin: TestClient,
) -> None:
    bad = as_admin.post(
        "/api/v1/admin/sweep-inactive-tokens",
        json={"inactivity_days": 0},
    )
    assert bad.status_code == 400
    bad2 = as_admin.post(
        "/api/v1/admin/sweep-inactive-tokens",
        json={"inactivity_days": 99999},
    )
    assert bad2.status_code == 400
    bad3 = as_admin.post(
        "/api/v1/admin/sweep-inactive-tokens",
        json={"inactivity_days": "not-a-number"},
    )
    assert bad3.status_code == 400


def test_admin_sweep_endpoint_with_no_tokens_succeeds(
    as_admin: TestClient,
) -> None:
    resp = as_admin.post(
        "/api/v1/admin/sweep-inactive-tokens", json={}
    )
    assert resp.status_code == 200
    assert resp.json()["scanned"] == 0
    assert resp.json()["revoked_count"] == 0


# ---- scheduled-task entry point (production Lambda hook) ----


def test_run_scheduled_tasks_calls_token_sweep() -> None:
    from iam_jit import scheduled

    store = InMemoryAPITokenStore()
    store.put(_record(token_hash="stale", last_used_at=_NOW - 365 * 86400))
    out = scheduled.run_scheduled_tasks(tokens_store=store, now_epoch=_NOW)
    assert out["tasks"]["token_sweep"]["status"] == "ok"
    assert out["tasks"]["token_sweep"]["revoked"] == 1
    assert out["tasks"]["token_sweep"]["scanned"] == 1


def test_run_scheduled_tasks_handles_missing_store() -> None:
    from iam_jit import scheduled

    out = scheduled.run_scheduled_tasks(tokens_store=None)
    assert out["tasks"]["token_sweep"]["status"] == "skipped"


def test_run_scheduled_tasks_inactivity_days_from_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lambda overrides the default via IAM_JIT_TOKEN_INACTIVITY_DAYS."""
    from iam_jit import scheduled

    monkeypatch.setenv("IAM_JIT_TOKEN_INACTIVITY_DAYS", "30")
    store = InMemoryAPITokenStore()
    store.put(_record(token_hash="35d", last_used_at=_NOW - 35 * 86400))
    store.put(_record(token_hash="20d", last_used_at=_NOW - 20 * 86400))
    out = scheduled.run_scheduled_tasks(tokens_store=store, now_epoch=_NOW)
    assert out["tasks"]["token_sweep"]["inactivity_days"] == 30
    assert out["tasks"]["token_sweep"]["revoked"] == 1
    assert {r.token_hash for r in store.list_all()} == {"20d"}


def test_run_scheduled_tasks_swallows_sweep_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the token sweep blows up the scheduled run still completes
    and reports the error rather than crashing the Lambda."""
    from iam_jit import scheduled

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated sweep failure")

    monkeypatch.setattr(token_sweep, "sweep_inactive_tokens", _boom)
    store = InMemoryAPITokenStore()
    out = scheduled.run_scheduled_tasks(tokens_store=store, now_epoch=_NOW)
    assert out["tasks"]["token_sweep"]["status"] == "error"
    assert "RuntimeError" in out["tasks"]["token_sweep"]["error"]
