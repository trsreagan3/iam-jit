"""Per-user chat rate limiting + DDoS auto-ban."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from iam_jit import rate_limit


pytest_plugins = ["tests.conftest_routes"]


@pytest.fixture(autouse=True)
def reset_state() -> None:
    from iam_jit import bans

    rate_limit.reset_default_limiter_for_tests()
    bans.reset_default_store_for_tests()


@pytest.fixture(autouse=True)
def force_ai_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from iam_jit import review

    monkeypatch.setattr(review, "is_review_enabled", lambda: True)


# ---- core limiter ----


def test_limiter_allows_under_soft_cap() -> None:
    limiter = rate_limit.InMemoryRateLimiter(soft_cap=5, hard_cap=10)
    for _ in range(5):
        d = limiter.check("u")
        assert d.allowed
        assert not d.over_soft
        assert not d.over_hard


def test_limiter_blocks_at_soft_cap() -> None:
    limiter = rate_limit.InMemoryRateLimiter(soft_cap=3, hard_cap=10)
    for _ in range(3):
        assert limiter.check("u").allowed
    d = limiter.check("u")
    assert not d.allowed
    assert d.over_soft
    assert not d.over_hard
    assert d.retry_after_seconds > 0


def test_limiter_escalates_at_hard_cap() -> None:
    """Pre-populate the bucket directly to confirm hard-cap detection."""
    from collections import deque

    limiter = rate_limit.InMemoryRateLimiter(soft_cap=3, hard_cap=5)
    bucket = limiter._buckets.setdefault(("u", "chat"), deque())
    for _ in range(5):
        bucket.append(time.time())
    d = limiter.check("u")
    assert not d.allowed
    assert d.over_hard
    assert not d.over_soft


def test_limiter_isolates_by_user() -> None:
    limiter = rate_limit.InMemoryRateLimiter(soft_cap=2, hard_cap=10)
    assert limiter.check("a").allowed
    assert limiter.check("a").allowed
    assert not limiter.check("a").allowed  # over soft for a
    # Different user is fresh.
    assert limiter.check("b").allowed
    assert limiter.check("b").allowed


def test_limiter_isolates_by_kind() -> None:
    """Chat and intake-turn quotas are separate buckets per user."""
    limiter = rate_limit.InMemoryRateLimiter(soft_cap=2, hard_cap=10)
    assert limiter.check("u", kind="chat").allowed
    assert limiter.check("u", kind="chat").allowed
    # chat is exhausted
    assert not limiter.check("u", kind="chat").allowed
    # intake-turn still has its own headroom
    assert limiter.check("u", kind="intake-turn").allowed


def test_limiter_window_slides() -> None:
    limiter = rate_limit.InMemoryRateLimiter(
        soft_cap=2, hard_cap=10, window_seconds=1
    )
    assert limiter.check("u").allowed
    assert limiter.check("u").allowed
    assert not limiter.check("u").allowed
    time.sleep(1.1)
    assert limiter.check("u").allowed  # window slid


def test_limiter_empty_user_id_does_not_throttle() -> None:
    limiter = rate_limit.InMemoryRateLimiter(soft_cap=1, hard_cap=2)
    for _ in range(50):
        assert limiter.check("").allowed


def test_limiter_corrects_misordered_caps() -> None:
    """If hard <= soft was passed, the limiter must still produce two
    distinct thresholds."""
    limiter = rate_limit.InMemoryRateLimiter(soft_cap=10, hard_cap=5)
    assert limiter.hard_cap > limiter.soft_cap


def test_limiter_reset_clears_user() -> None:
    limiter = rate_limit.InMemoryRateLimiter(soft_cap=1, hard_cap=10)
    assert limiter.check("u").allowed
    assert not limiter.check("u").allowed
    limiter.reset("u")
    assert limiter.check("u").allowed


# ---- route-level integration ----


def test_chat_post_429_after_soft_cap(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Soft cap is configurable via env. Tighten it to verify the
    route layer surfaces 429 + Retry-After."""
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_SOFT_CAP", "3")
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_HARD_CAP", "100")
    rate_limit.reset_default_limiter_for_tests()

    from iam_jit import intake as intake_mod

    monkeypatch.setattr(
        intake_mod,
        "take_turn",
        lambda h, b: intake_mod.IntakeTurn(ask="ok", complete=False, fields={}),
    )

    # 3 allowed
    for _ in range(3):
        r = as_dev.post(
            "/requests/new/chat",
            data={"conversation": "", "message": "I need s3 read in dev"},
        )
        assert r.status_code == 200
    # 4th hits 429
    r = as_dev.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "another message"},
    )
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_chat_post_hard_cap_bans_user(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Crossing the hard cap auto-bans via the bans store.

    We pre-populate the deque directly (not via check()) so refused
    calls don't artificially block us from reaching the hard threshold."""
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_SOFT_CAP", "3")
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_HARD_CAP", "5")
    rate_limit.reset_default_limiter_for_tests()

    from iam_jit import bans, intake as intake_mod

    monkeypatch.setattr(
        intake_mod,
        "take_turn",
        lambda h, b: intake_mod.IntakeTurn(ask="ok", complete=False, fields={}),
    )

    limiter = rate_limit.get_default_limiter()
    # Stuff 5 timestamps directly into the bucket; the next route call
    # will be the 6th, which exceeds hard_cap=5.
    now = time.time()
    bucket = limiter._buckets.setdefault(
        ("email:dev@example.com", "chat"),
        type(limiter)._buckets.fget if False else __import__("collections").deque(),
    )
    for _ in range(5):
        bucket.append(now)

    r = as_dev.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "msg"},
    )
    assert r.status_code == 403
    assert bans.get_default_store().is_banned("email:dev@example.com")


def test_admin_not_banned_on_hard_cap(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Admin accounts are exempt from the auto-ban path."""
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_SOFT_CAP", "2")
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_HARD_CAP", "3")
    rate_limit.reset_default_limiter_for_tests()

    from iam_jit import bans, intake as intake_mod
    from collections import deque

    monkeypatch.setattr(
        intake_mod,
        "take_turn",
        lambda h, b: intake_mod.IntakeTurn(ask="ok", complete=False, fields={}),
    )

    limiter = rate_limit.get_default_limiter()
    bucket = limiter._buckets.setdefault(
        ("email:admin@example.com", "chat"), deque()
    )
    for _ in range(3):
        bucket.append(time.time())

    r = as_admin.post(
        "/requests/new/chat",
        data={"conversation": "", "message": "msg"},
    )
    # Admin still gets 403 (their request is refused), but not banned.
    assert r.status_code == 403
    assert not bans.get_default_store().is_banned("email:admin@example.com")


def test_chat_stream_rate_limited(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pre-fill the bucket; the next /chat/stream call must 429."""
    from collections import deque

    monkeypatch.setenv("IAM_JIT_CHAT_RATE_SOFT_CAP", "1")
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_HARD_CAP", "5")
    rate_limit.reset_default_limiter_for_tests()
    limiter = rate_limit.get_default_limiter()
    bucket = limiter._buckets.setdefault(
        ("email:dev@example.com", "chat-stream"), deque()
    )
    bucket.append(time.time())  # already at soft cap of 1

    r = as_dev.post(
        "/requests/new/chat/stream",
        data={"conversation": "", "message": "second"},
    )
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_intake_turn_429_after_soft_cap(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_SOFT_CAP", "2")
    monkeypatch.setenv("IAM_JIT_CHAT_RATE_HARD_CAP", "10")
    rate_limit.reset_default_limiter_for_tests()

    from iam_jit import intake as intake_mod

    monkeypatch.setattr(
        intake_mod,
        "take_turn",
        lambda h, b: intake_mod.IntakeTurn(ask="ok", complete=False, fields={}),
    )

    body = {"conversation": [{"role": "user", "content": "s3 read in dev"}]}
    r1 = as_dev.post("/api/v1/intake/turn", json=body)
    r2 = as_dev.post("/api/v1/intake/turn", json=body)
    r3 = as_dev.post("/api/v1/intake/turn", json=body)
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
