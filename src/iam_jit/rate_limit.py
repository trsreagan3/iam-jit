"""Per-user request rate limiting.

A small in-memory sliding-window counter keyed by user_id. Used to
throttle the LLM-facing endpoints (chat POST, chat stream, intake API)
which represent both real cost (LLM tokens) and abuse potential.

Two thresholds:

  - **soft** (default 30/min): the normal "you're typing too fast"
    cap. Exceeding it returns 429 Too Many Requests with a
    Retry-After header. No ban — legitimate users hit this when their
    network retries a stuck request.

  - **hard** (default 100/min): a sustained-attack cap. Crossing it
    means the user has accepted the soft 429s and kept hammering —
    treated as adversarial. Caller is expected to ban the user
    through the existing `bans` store.

The window is sliding (not fixed) — a 60-second deque of timestamps
per user, trimmed on every check. Memory cost is O(N_active_users *
hard_cap). For deployments past the in-memory limit, swap the store
for a Redis or DynamoDB-backed implementation behind the same
Protocol; this module is the contract, not the implementation choice.
"""

from __future__ import annotations

import collections
import os
import threading
import time
from dataclasses import dataclass
from typing import Protocol


_DEFAULT_WINDOW_SECONDS = 60
_DEFAULT_SOFT_CAP = 30
_DEFAULT_HARD_CAP = 100


def _read_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


@dataclass(frozen=True)
class RateDecision:
    """Outcome of one `check` call."""

    allowed: bool
    over_soft: bool  # rate exceeds soft cap (429-worthy)
    over_hard: bool  # rate exceeds hard cap (ban-worthy)
    count: int  # current count within the window
    window_seconds: int
    retry_after_seconds: int  # 0 if allowed
    soft_cap: int
    hard_cap: int


class RateLimiter(Protocol):
    def check(self, user_id: str, *, kind: str = "chat") -> RateDecision: ...

    def reset(self, user_id: str | None = None) -> None: ...


class InMemoryRateLimiter:
    """Single-process sliding-window limiter.

    Thread-safe (one lock for the entire store — fine for low-QPS
    iam-jit traffic; higher-QPS workloads would want per-user
    sharding).
    """

    def __init__(
        self,
        *,
        soft_cap: int | None = None,
        hard_cap: int | None = None,
        window_seconds: int = _DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self.soft_cap = soft_cap if soft_cap is not None else _read_int_env(
            "IAM_JIT_CHAT_RATE_SOFT_CAP", _DEFAULT_SOFT_CAP
        )
        self.hard_cap = hard_cap if hard_cap is not None else _read_int_env(
            "IAM_JIT_CHAT_RATE_HARD_CAP", _DEFAULT_HARD_CAP
        )
        if self.hard_cap <= self.soft_cap:
            # Caller misconfigured; ensure hard > soft so the two
            # thresholds remain distinct.
            self.hard_cap = self.soft_cap * 3
        self.window_seconds = window_seconds
        self._buckets: dict[tuple[str, str], collections.deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, user_id: str, *, kind: str = "chat") -> RateDecision:
        if not user_id:
            # No per-user identity — don't rate limit. Anonymous
            # endpoints have their own controls.
            return RateDecision(
                allowed=True,
                over_soft=False,
                over_hard=False,
                count=0,
                window_seconds=self.window_seconds,
                retry_after_seconds=0,
                soft_cap=self.soft_cap,
                hard_cap=self.hard_cap,
            )
        now = time.time()
        cutoff = now - self.window_seconds
        key = (user_id, kind)
        with self._lock:
            dq = self._buckets.setdefault(key, collections.deque())
            while dq and dq[0] < cutoff:
                dq.popleft()
            count_after = len(dq) + 1
            over_hard = count_after > self.hard_cap
            over_soft = count_after > self.soft_cap and not over_hard
            allowed = not (over_soft or over_hard)
            if allowed:
                dq.append(now)
            else:
                # Don't append a timestamp for refused calls — that
                # would let an attacker push the window forward by
                # spamming refused requests. Keep the deque snapshot
                # clean.
                pass

            if dq:
                oldest = dq[0]
                retry_after = max(0, int(oldest + self.window_seconds - now))
            else:
                retry_after = 0

        return RateDecision(
            allowed=allowed,
            over_soft=over_soft,
            over_hard=over_hard,
            count=count_after,
            window_seconds=self.window_seconds,
            retry_after_seconds=retry_after,
            soft_cap=self.soft_cap,
            hard_cap=self.hard_cap,
        )

    def reset(self, user_id: str | None = None) -> None:
        with self._lock:
            if user_id is None:
                self._buckets.clear()
                return
            for key in list(self._buckets.keys()):
                if key[0] == user_id:
                    self._buckets.pop(key, None)


_GLOBAL: RateLimiter | None = None


def get_default_limiter() -> RateLimiter:
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = InMemoryRateLimiter()
    return _GLOBAL


def reset_default_limiter_for_tests() -> None:
    global _GLOBAL
    _GLOBAL = None
