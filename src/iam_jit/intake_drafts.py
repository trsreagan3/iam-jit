"""Per-user persisted intake drafts for session-loss resilience.

Problem: the chat surface keeps the conversation in a signed token in
the form. If the user closes the tab, refreshes, or their session
expires, the token is gone and they restart from scratch — frustrating
when they were 5 turns deep into describing a tricky permission set.

Solution: an additional, server-side stash keyed by user_id. After
every chat turn (and after the SSE generator finishes), we save the
current history + parse_error_count under a draft id. On the next page
load (or after re-auth), the page checks `most_recent(user_id)` and
offers "resume your last draft from N min ago?".

This is best-effort, not a contract. Drafts expire after a TTL
(default 4h). The signed token in the form is still authoritative
during a single session; the draft is just a recovery seam.

Backends:
  - **InMemoryIntakeDraftStore** — fine for dev / single-process Lambda
    (drafts are scoped to one container's lifetime).
  - **FilesystemIntakeDraftStore** — survives `iam-jit serve` restarts.
    Used in dev when IAM_JIT_INTAKE_DRAFTS_DIR is set.

Production note: a serverless deployment running on Lambda would prefer
DynamoDB with TTL set on the row. We don't add that here yet — the
in-memory store is enough until someone hits the limit. Adding a
DynamoDB backend later is mechanical: implement the same Protocol.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import pathlib
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol


logger = logging.getLogger("iam_jit.intake_drafts")

DEFAULT_TTL_HOURS = 4
MAX_DRAFT_BYTES = 256 * 1024  # 256 KiB — chat history shouldn't be this big


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _isoformat_z(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class IntakeDraft:
    draft_id: str
    user_id: str
    history: list[dict[str, str]] = field(default_factory=list)
    parse_error_count: int = 0
    created_at: str = ""
    last_updated_at: str = ""

    def expired(self, *, ttl_hours: int = DEFAULT_TTL_HOURS, now: _dt.datetime | None = None) -> bool:
        now = now or _now()
        try:
            ts = _dt.datetime.strptime(
                self.last_updated_at.rstrip("Z"), "%Y-%m-%dT%H:%M:%S"
            ).replace(tzinfo=_dt.UTC)
        except (ValueError, AttributeError):
            return True
        return (now - ts) > _dt.timedelta(hours=ttl_hours)


class IntakeDraftStore(Protocol):
    def save(
        self, *, user_id: str, history: list[dict[str, str]], parse_error_count: int
    ) -> IntakeDraft: ...

    def get_most_recent(self, user_id: str) -> IntakeDraft | None: ...

    def get(self, draft_id: str) -> IntakeDraft | None: ...

    def delete(self, draft_id: str) -> None: ...

    def cleanup_expired(self, *, ttl_hours: int = DEFAULT_TTL_HOURS) -> int: ...


def _new_draft_id() -> str:
    return "drft-" + secrets.token_urlsafe(8).lower().replace("_", "").replace("-", "")[:10]


class InMemoryIntakeDraftStore:
    """Single-process draft store. Sufficient for dev and single-Lambda
    deployments. Lost on restart — that's the trade-off."""

    def __init__(self, *, ttl_hours: int = DEFAULT_TTL_HOURS) -> None:
        self._drafts: dict[str, IntakeDraft] = {}
        self._lock = threading.Lock()
        self._ttl_hours = ttl_hours

    def save(
        self, *, user_id: str, history: list[dict[str, str]], parse_error_count: int
    ) -> IntakeDraft:
        if not user_id:
            raise ValueError("user_id is required to save an intake draft")
        # Cap payload defensively — a runaway loop shouldn't be able to
        # fill the store with megabytes per user.
        approx_size = sum(
            len(m.get("content") or "") for m in history
        )
        if approx_size > MAX_DRAFT_BYTES:
            history = history[-20:]  # last 20 turns is plenty for resume
        now = _isoformat_z(_now())
        with self._lock:
            existing = self._most_recent_locked(user_id)
            if existing and not existing.expired(ttl_hours=self._ttl_hours):
                draft = existing
                draft.history = list(history)
                draft.parse_error_count = parse_error_count
                draft.last_updated_at = now
            else:
                draft = IntakeDraft(
                    draft_id=_new_draft_id(),
                    user_id=user_id,
                    history=list(history),
                    parse_error_count=parse_error_count,
                    created_at=now,
                    last_updated_at=now,
                )
                self._drafts[draft.draft_id] = draft
        return draft

    def _most_recent_locked(self, user_id: str) -> IntakeDraft | None:
        candidates = [d for d in self._drafts.values() if d.user_id == user_id]
        if not candidates:
            return None
        candidates.sort(key=lambda d: d.last_updated_at, reverse=True)
        return candidates[0]

    def get_most_recent(self, user_id: str) -> IntakeDraft | None:
        with self._lock:
            d = self._most_recent_locked(user_id)
            if d is None:
                return None
            if d.expired(ttl_hours=self._ttl_hours):
                self._drafts.pop(d.draft_id, None)
                return None
            return d

    def get(self, draft_id: str) -> IntakeDraft | None:
        with self._lock:
            d = self._drafts.get(draft_id)
            if d is None:
                return None
            if d.expired(ttl_hours=self._ttl_hours):
                self._drafts.pop(draft_id, None)
                return None
            return d

    def delete(self, draft_id: str) -> None:
        with self._lock:
            self._drafts.pop(draft_id, None)

    def cleanup_expired(self, *, ttl_hours: int = DEFAULT_TTL_HOURS) -> int:
        removed = 0
        with self._lock:
            for did, d in list(self._drafts.items()):
                if d.expired(ttl_hours=ttl_hours):
                    self._drafts.pop(did, None)
                    removed += 1
        return removed


class FilesystemIntakeDraftStore:
    """File-backed draft store. One JSON file per draft.

    Scope: dev only. Production deployments should prefer DynamoDB with
    TTL — files don't auto-cleanup unless `cleanup_expired` runs."""

    def __init__(
        self, root: pathlib.Path | str, *, ttl_hours: int = DEFAULT_TTL_HOURS
    ) -> None:
        self._root = pathlib.Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._ttl_hours = ttl_hours
        self._lock = threading.Lock()

    def _path_for(self, draft_id: str) -> pathlib.Path:
        return self._root / f"{draft_id}.json"

    def save(
        self, *, user_id: str, history: list[dict[str, str]], parse_error_count: int
    ) -> IntakeDraft:
        if not user_id:
            raise ValueError("user_id is required to save an intake draft")
        approx_size = sum(len(m.get("content") or "") for m in history)
        if approx_size > MAX_DRAFT_BYTES:
            history = history[-20:]
        now = _isoformat_z(_now())
        with self._lock:
            existing = self._most_recent_locked(user_id)
            if existing and not existing.expired(ttl_hours=self._ttl_hours):
                draft = existing
                draft.history = list(history)
                draft.parse_error_count = parse_error_count
                draft.last_updated_at = now
            else:
                draft = IntakeDraft(
                    draft_id=_new_draft_id(),
                    user_id=user_id,
                    history=list(history),
                    parse_error_count=parse_error_count,
                    created_at=now,
                    last_updated_at=now,
                )
            self._write(draft)
        return draft

    def _write(self, draft: IntakeDraft) -> None:
        path = self._path_for(draft.draft_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "draft_id": draft.draft_id,
                    "user_id": draft.user_id,
                    "history": draft.history,
                    "parse_error_count": draft.parse_error_count,
                    "created_at": draft.created_at,
                    "last_updated_at": draft.last_updated_at,
                },
                separators=(",", ":"),
            )
        )
        tmp.replace(path)

    def _read(self, path: pathlib.Path) -> IntakeDraft | None:
        try:
            data = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        return IntakeDraft(
            draft_id=data.get("draft_id", path.stem),
            user_id=data.get("user_id", ""),
            history=data.get("history") or [],
            parse_error_count=int(data.get("parse_error_count") or 0),
            created_at=data.get("created_at", ""),
            last_updated_at=data.get("last_updated_at", ""),
        )

    def _most_recent_locked(self, user_id: str) -> IntakeDraft | None:
        candidates: list[IntakeDraft] = []
        for path in self._root.glob("drft-*.json"):
            d = self._read(path)
            if d is None or d.user_id != user_id:
                continue
            candidates.append(d)
        if not candidates:
            return None
        candidates.sort(key=lambda d: d.last_updated_at, reverse=True)
        return candidates[0]

    def get_most_recent(self, user_id: str) -> IntakeDraft | None:
        with self._lock:
            d = self._most_recent_locked(user_id)
            if d is None:
                return None
            if d.expired(ttl_hours=self._ttl_hours):
                try:
                    self._path_for(d.draft_id).unlink(missing_ok=True)
                except OSError:
                    pass
                return None
            return d

    def get(self, draft_id: str) -> IntakeDraft | None:
        with self._lock:
            d = self._read(self._path_for(draft_id))
            if d is None:
                return None
            if d.expired(ttl_hours=self._ttl_hours):
                self._path_for(draft_id).unlink(missing_ok=True)
                return None
            return d

    def delete(self, draft_id: str) -> None:
        with self._lock:
            try:
                self._path_for(draft_id).unlink(missing_ok=True)
            except OSError:
                logger.exception("delete draft %s failed", draft_id)

    def cleanup_expired(self, *, ttl_hours: int = DEFAULT_TTL_HOURS) -> int:
        removed = 0
        with self._lock:
            for path in self._root.glob("drft-*.json"):
                d = self._read(path)
                if d is None or d.expired(ttl_hours=ttl_hours):
                    try:
                        path.unlink(missing_ok=True)
                        removed += 1
                    except OSError:
                        pass
        return removed


_GLOBAL_STORE: IntakeDraftStore | None = None


def get_default_store() -> IntakeDraftStore:
    """Module-level singleton used by the web routes when no store is
    explicitly injected. In production this would be wired through
    `app.state` instead — the singleton is just a dev convenience."""
    global _GLOBAL_STORE
    if _GLOBAL_STORE is None:
        import os

        local = os.environ.get("IAM_JIT_INTAKE_DRAFTS_DIR")
        if local:
            _GLOBAL_STORE = FilesystemIntakeDraftStore(local)
        else:
            _GLOBAL_STORE = InMemoryIntakeDraftStore()
    return _GLOBAL_STORE


def reset_default_store_for_tests() -> None:
    """Test helper — drop the singleton so each test gets a fresh store."""
    global _GLOBAL_STORE
    _GLOBAL_STORE = None
