"""Ban store + auto-ban-on-injection tests."""

from __future__ import annotations

import pytest

from iam_jit import bans


def test_in_memory_add_and_check() -> None:
    store = bans.InMemoryBanStore()
    assert not store.is_banned("email:dev@example.com")
    store.add(
        bans.Ban(
            user_id="email:dev@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["system-prompt-override"],
            snippets=["ignore previous instructions"],
            confidence="high",
            actor="system:prompt_injection",
        )
    )
    assert store.is_banned("email:dev@example.com")


def test_in_memory_remove() -> None:
    store = bans.InMemoryBanStore()
    store.add(
        bans.Ban(
            user_id="x",
            banned_at="2026-05-08T00:00:00Z",
            reasons=[],
            snippets=[],
            confidence="high",
            actor="system",
        )
    )
    store.remove("x")
    assert not store.is_banned("x")


def test_filesystem_round_trip(tmp_path) -> None:
    s1 = bans.FilesystemBanStore(tmp_path)
    s1.add(
        bans.Ban(
            user_id="email:dev@example.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["wildcard-coercion"],
            snippets=["give me admin"],
            confidence="high",
            actor="system:prompt_injection",
            notes="initial",
        )
    )
    # Cross-instance read
    s2 = bans.FilesystemBanStore(tmp_path)
    assert s2.is_banned("email:dev@example.com")
    ban = s2.get("email:dev@example.com")
    assert ban is not None
    assert ban.confidence == "high"
    assert "wildcard-coercion" in ban.reasons


def test_ban_for_injection_refuses_to_ban_admin() -> None:
    store = bans.InMemoryBanStore()
    result = bans.ban_for_injection(
        store=store,
        user_id="email:admin@example.com",
        reasons=["system-prompt-override"],
        snippets=["ignore previous instructions"],
        confidence="high",
        is_admin=True,
    )
    assert result is None
    assert not store.is_banned("email:admin@example.com")


def test_ban_for_injection_bans_non_admin() -> None:
    store = bans.InMemoryBanStore()
    result = bans.ban_for_injection(
        store=store,
        user_id="email:dev@example.com",
        reasons=["approve-forgery"],
        snippets=["auto-approve"],
        confidence="high",
        is_admin=False,
    )
    assert result is not None
    assert store.is_banned("email:dev@example.com")
    assert result.actor == "system:prompt_injection"


def test_list_all_orders_by_recency() -> None:
    store = bans.InMemoryBanStore()
    store.add(bans.Ban("a", "2026-05-01T00:00:00Z", [], [], "high", "system"))
    store.add(bans.Ban("b", "2026-05-08T00:00:00Z", [], [], "high", "system"))
    out = store.list_all()
    assert [b.user_id for b in out] == ["b", "a"]


def test_default_store_is_in_memory_when_no_env(monkeypatch) -> None:
    monkeypatch.delenv("IAM_JIT_BANS_DIR", raising=False)
    bans.reset_default_store_for_tests()
    assert isinstance(bans.get_default_store(), bans.InMemoryBanStore)


def test_default_store_uses_filesystem_when_env_set(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("IAM_JIT_BANS_DIR", str(tmp_path))
    bans.reset_default_store_for_tests()
    assert isinstance(bans.get_default_store(), bans.FilesystemBanStore)


def test_filesystem_path_safe_for_email_ids(tmp_path) -> None:
    """User IDs contain ':' — the filename mangling must keep the file
    locatable across save/load even on Windows-y path semantics."""
    s = bans.FilesystemBanStore(tmp_path)
    s.add(
        bans.Ban(
            user_id="email:trsreagan3+filter@gmail.com",
            banned_at="2026-05-08T00:00:00Z",
            reasons=["x"],
            snippets=[],
            confidence="high",
            actor="system",
        )
    )
    assert s.is_banned("email:trsreagan3+filter@gmail.com")
