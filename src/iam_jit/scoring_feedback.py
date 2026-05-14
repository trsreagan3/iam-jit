"""Customer-facing scoring-feedback channel.

The calibration discipline is what makes iam-jit defensible: the
1,489/1,489 + 203/217 numbers are credible because they're
test-pinned. To keep that discipline alive past launch, customers
need a frictionless way to flag scoring they disagree with.

This module is the storage + ingestion layer. The companion route
in `routes/feedback.py` exposes it as a POST endpoint.

Rate limiting:
- Authenticated submitters: 10/day
- Anonymous IP submitters:    3/day
- Deployment-wide ceiling:  100/hour

The rate limits prevent (a) malicious flooding of the admin queue,
(b) accidental DoS via a buggy CI integration, (c) billing
amplification via audit-log writes.

The feedback flows:
  1. Customer submits via POST /api/v1/feedback/scoring
  2. Store records the submission with an FB-<id>
  3. Admin sees the queue at /admin/feedback/scoring
  4. Admin marks "valid + add to corpus" → exports a YAML
     fixture under `tests/calibration_corpus/community/`
  5. Next adversarial-loop round picks it up
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from typing import Any, Protocol


# Default rate limits — env-overridable.
_DEFAULT_AUTHED_DAILY_CAP = 10
_DEFAULT_ANON_DAILY_CAP = 3
_DEFAULT_DEPLOYMENT_HOURLY_CAP = 100


def _authed_daily_cap() -> int:
    raw = (os.environ.get("IAM_JIT_FEEDBACK_AUTHED_DAILY_CAP") or "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return _DEFAULT_AUTHED_DAILY_CAP


def _anon_daily_cap() -> int:
    raw = (os.environ.get("IAM_JIT_FEEDBACK_ANON_DAILY_CAP") or "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return _DEFAULT_ANON_DAILY_CAP


def _deployment_hourly_cap() -> int:
    raw = (
        os.environ.get("IAM_JIT_FEEDBACK_DEPLOYMENT_HOURLY_CAP") or ""
    ).strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return _DEFAULT_DEPLOYMENT_HOURLY_CAP


@dataclasses.dataclass(frozen=True)
class FeedbackSubmission:
    """One customer-submitted disagreement-with-score."""

    feedback_id: str           # FB-<8-hex-chars>
    submitted_at: str          # ISO-8601 UTC
    submitter_id: str | None   # customer user_id, or None if anon
    submitter_ip: str          # source IP for the submission
    policy: dict[str, Any]     # the policy the caller had scored
    our_score: int             # what iam-jit returned
    expected_score: int | None # optional — what the caller thinks
    category: str              # false-positive | false-negative | missing-factor
    explanation: str           # caller's short note (≤2000 chars)
    review_status: str         # new | reviewed | added_to_corpus | dismissed
    reviewer_notes: str        # admin-side notes (empty until reviewed)


class FeedbackStore(Protocol):
    def submit(
        self,
        *,
        submitter_id: str | None,
        submitter_ip: str,
        policy: dict[str, Any],
        our_score: int,
        expected_score: int | None,
        category: str,
        explanation: str,
    ) -> FeedbackSubmission: ...

    def list_recent(self, *, limit: int = 100) -> list[FeedbackSubmission]: ...

    def mark_reviewed(
        self,
        feedback_id: str,
        *,
        status: str,
        reviewer_notes: str = "",
    ) -> FeedbackSubmission | None: ...

    def reset_for_tests(self) -> None: ...


class RateLimitError(Exception):
    """Raised when the submitter / deployment exceeds the cap."""

    def __init__(self, scope: str, retry_after_seconds: int) -> None:
        super().__init__(f"rate-limited at scope={scope}")
        self.scope = scope
        self.retry_after_seconds = retry_after_seconds


def _new_feedback_id() -> str:
    return "FB-" + secrets.token_hex(4)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class InMemoryFeedbackStore:
    """Single-process feedback store + rate limiter.

    Suitable for single-instance dev / RC=1 deployments. Multi-
    instance production should use a DDB-backed implementation
    (left as a follow-up; the Protocol is the contract).
    """

    _VALID_CATEGORIES = {"false-positive", "false-negative", "missing-factor"}

    def __init__(self) -> None:
        self._submissions: list[FeedbackSubmission] = []
        # Per-submitter daily counters (resets on day-boundary check).
        self._authed_counter: dict[str, tuple[str, int]] = {}
        self._anon_counter: dict[str, tuple[str, int]] = {}
        # Deployment-wide hourly counter (sliding window).
        self._deployment_recent: deque[float] = deque()
        self._lock = threading.Lock()

    @staticmethod
    def _today_utc() -> str:
        return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%d")

    def submit(
        self,
        *,
        submitter_id: str | None,
        submitter_ip: str,
        policy: dict[str, Any],
        our_score: int,
        expected_score: int | None,
        category: str,
        explanation: str,
    ) -> FeedbackSubmission:
        if category not in self._VALID_CATEGORIES:
            raise ValueError(
                f"category must be one of {sorted(self._VALID_CATEGORIES)}; "
                f"got {category!r}"
            )
        explanation = (explanation or "").strip()[:2000]
        with self._lock:
            self._enforce_rate_limits(submitter_id, submitter_ip)
            submission = FeedbackSubmission(
                feedback_id=_new_feedback_id(),
                submitted_at=_now_iso(),
                submitter_id=submitter_id,
                submitter_ip=submitter_ip,
                policy=dict(policy),
                our_score=int(our_score),
                expected_score=(
                    int(expected_score) if expected_score is not None else None
                ),
                category=category,
                explanation=explanation,
                review_status="new",
                reviewer_notes="",
            )
            self._submissions.append(submission)
            self._tick_counters(submitter_id, submitter_ip)
            return submission

    def _enforce_rate_limits(
        self, submitter_id: str | None, submitter_ip: str
    ) -> None:
        # Per-submitter daily cap.
        if submitter_id is not None:
            today, count = self._authed_counter.get(
                submitter_id, (self._today_utc(), 0)
            )
            if today != self._today_utc():
                count = 0
            if count >= _authed_daily_cap():
                raise RateLimitError(
                    scope="authed-daily", retry_after_seconds=24 * 3600
                )
        else:
            today, count = self._anon_counter.get(
                submitter_ip, (self._today_utc(), 0)
            )
            if today != self._today_utc():
                count = 0
            if count >= _anon_daily_cap():
                raise RateLimitError(
                    scope="anon-daily", retry_after_seconds=24 * 3600
                )
        # Deployment-wide hourly ceiling (sliding window).
        now = time.time()
        cutoff = now - 3600
        while self._deployment_recent and self._deployment_recent[0] < cutoff:
            self._deployment_recent.popleft()
        if len(self._deployment_recent) >= _deployment_hourly_cap():
            oldest = self._deployment_recent[0]
            retry = int(oldest + 3600 - now) + 1
            raise RateLimitError(
                scope="deployment-hourly", retry_after_seconds=max(1, retry)
            )

    def _tick_counters(
        self, submitter_id: str | None, submitter_ip: str
    ) -> None:
        today = self._today_utc()
        if submitter_id is not None:
            _, count = self._authed_counter.get(submitter_id, (today, 0))
            self._authed_counter[submitter_id] = (today, count + 1)
        else:
            _, count = self._anon_counter.get(submitter_ip, (today, 0))
            self._anon_counter[submitter_ip] = (today, count + 1)
        self._deployment_recent.append(time.time())

    def list_recent(self, *, limit: int = 100) -> list[FeedbackSubmission]:
        with self._lock:
            return list(self._submissions[-limit:])

    def mark_reviewed(
        self,
        feedback_id: str,
        *,
        status: str,
        reviewer_notes: str = "",
    ) -> FeedbackSubmission | None:
        valid_statuses = {"new", "reviewed", "added_to_corpus", "dismissed"}
        if status not in valid_statuses:
            raise ValueError(
                f"status must be one of {sorted(valid_statuses)}; got {status!r}"
            )
        with self._lock:
            for i, s in enumerate(self._submissions):
                if s.feedback_id == feedback_id:
                    self._submissions[i] = dataclasses.replace(
                        s,
                        review_status=status,
                        reviewer_notes=(reviewer_notes or "")[:2000],
                    )
                    return self._submissions[i]
        return None

    def reset_for_tests(self) -> None:
        with self._lock:
            self._submissions.clear()
            self._authed_counter.clear()
            self._anon_counter.clear()
            self._deployment_recent.clear()


_GLOBAL: FeedbackStore | None = None


def get_default_store() -> FeedbackStore:
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = InMemoryFeedbackStore()
    return _GLOBAL


def reset_default_store_for_tests() -> None:
    global _GLOBAL
    _GLOBAL = None
