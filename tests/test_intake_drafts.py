"""Intake draft store tests.

Covers both the in-memory and filesystem backends + the resume / TTL
contract that the route layer depends on.
"""

from __future__ import annotations

import datetime as _dt
import time

import pytest

from iam_jit import intake_drafts


# ---- happy path ----


def test_save_and_get_most_recent_round_trip() -> None:
    store = intake_drafts.InMemoryIntakeDraftStore()
    draft = store.save(
        user_id="email:dev@example.com",
        history=[{"role": "user", "content": "hi"}],
        parse_error_count=0,
    )
    assert draft.user_id == "email:dev@example.com"
    assert draft.history == [{"role": "user", "content": "hi"}]
    again = store.get_most_recent("email:dev@example.com")
    assert again is not None
    assert again.draft_id == draft.draft_id


def test_save_consecutive_updates_same_draft() -> None:
    """Two saves in quick succession for the same user should update
    the existing draft, not create a second one."""
    store = intake_drafts.InMemoryIntakeDraftStore()
    a = store.save(
        user_id="email:dev@example.com",
        history=[{"role": "user", "content": "1"}],
        parse_error_count=0,
    )
    b = store.save(
        user_id="email:dev@example.com",
        history=[
            {"role": "user", "content": "1"},
            {"role": "assistant", "content": "ok"},
        ],
        parse_error_count=0,
    )
    assert a.draft_id == b.draft_id
    assert len(b.history) == 2


def test_per_user_isolation() -> None:
    store = intake_drafts.InMemoryIntakeDraftStore()
    store.save(
        user_id="email:a@example.com",
        history=[{"role": "user", "content": "alpha"}],
        parse_error_count=0,
    )
    store.save(
        user_id="email:b@example.com",
        history=[{"role": "user", "content": "beta"}],
        parse_error_count=0,
    )
    a = store.get_most_recent("email:a@example.com")
    b = store.get_most_recent("email:b@example.com")
    assert a is not None and a.history[0]["content"] == "alpha"
    assert b is not None and b.history[0]["content"] == "beta"


# ---- TTL ----


def test_expired_drafts_return_none() -> None:
    store = intake_drafts.InMemoryIntakeDraftStore(ttl_hours=1)
    draft = store.save(
        user_id="email:dev@example.com",
        history=[{"role": "user", "content": "x"}],
        parse_error_count=0,
    )
    # Backdate the timestamp.
    draft.last_updated_at = "2020-01-01T00:00:00Z"
    assert store.get_most_recent("email:dev@example.com") is None
    assert store.get(draft.draft_id) is None


def test_cleanup_expired_removes_old_drafts() -> None:
    store = intake_drafts.InMemoryIntakeDraftStore(ttl_hours=1)
    old = store.save(
        user_id="email:a@example.com",
        history=[{"role": "user", "content": "old"}],
        parse_error_count=0,
    )
    old.last_updated_at = "2020-01-01T00:00:00Z"
    store.save(
        user_id="email:b@example.com",
        history=[{"role": "user", "content": "fresh"}],
        parse_error_count=0,
    )
    removed = store.cleanup_expired(ttl_hours=1)
    assert removed == 1
    assert store.get_most_recent("email:b@example.com") is not None
    assert store.get_most_recent("email:a@example.com") is None


# ---- payload size cap ----


def test_oversized_history_truncates_to_last_n() -> None:
    """A 30-turn chat that exceeds MAX_DRAFT_BYTES is truncated to last 20."""
    store = intake_drafts.InMemoryIntakeDraftStore()
    big = [
        {"role": "user", "content": "x" * 50_000} for _ in range(30)
    ]
    saved = store.save(
        user_id="email:dev@example.com",
        history=big,
        parse_error_count=0,
    )
    assert len(saved.history) == 20  # last 20 only


# ---- filesystem backend ----


def test_filesystem_backend_persists_across_instances(tmp_path) -> None:
    s1 = intake_drafts.FilesystemIntakeDraftStore(tmp_path)
    saved = s1.save(
        user_id="email:dev@example.com",
        history=[{"role": "user", "content": "fs test"}],
        parse_error_count=0,
    )
    # Fresh instance pointing at the same dir → still there.
    s2 = intake_drafts.FilesystemIntakeDraftStore(tmp_path)
    again = s2.get_most_recent("email:dev@example.com")
    assert again is not None
    assert again.history == [{"role": "user", "content": "fs test"}]
    assert again.draft_id == saved.draft_id


def test_filesystem_delete_removes_file(tmp_path) -> None:
    store = intake_drafts.FilesystemIntakeDraftStore(tmp_path)
    saved = store.save(
        user_id="email:dev@example.com",
        history=[{"role": "user", "content": "x"}],
        parse_error_count=0,
    )
    assert (tmp_path / f"{saved.draft_id}.json").exists()
    store.delete(saved.draft_id)
    assert not (tmp_path / f"{saved.draft_id}.json").exists()


# ---- defensive checks ----


def test_save_rejects_empty_user_id() -> None:
    store = intake_drafts.InMemoryIntakeDraftStore()
    with pytest.raises(ValueError):
        store.save(user_id="", history=[], parse_error_count=0)


def test_get_nonexistent_returns_none() -> None:
    store = intake_drafts.InMemoryIntakeDraftStore()
    assert store.get("drft-nope") is None
    assert store.get_most_recent("email:nobody@example.com") is None


def test_default_store_is_in_memory_when_no_env(monkeypatch) -> None:
    monkeypatch.delenv("IAM_JIT_INTAKE_DRAFTS_DIR", raising=False)
    intake_drafts.reset_default_store_for_tests()
    store = intake_drafts.get_default_store()
    assert isinstance(store, intake_drafts.InMemoryIntakeDraftStore)


def test_default_store_uses_filesystem_when_env_set(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("IAM_JIT_INTAKE_DRAFTS_DIR", str(tmp_path))
    intake_drafts.reset_default_store_for_tests()
    store = intake_drafts.get_default_store()
    assert isinstance(store, intake_drafts.FilesystemIntakeDraftStore)
