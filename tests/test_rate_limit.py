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
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
def test_chat_post_hard_cap_bans_user(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
def test_admin_not_banned_on_hard_cap(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
def test_chat_stream_rate_limited(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
def test_intake_turn_429_after_soft_cap(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
