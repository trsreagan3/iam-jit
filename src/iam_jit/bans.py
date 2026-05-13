"""User-ban store.

A separate, lightweight store of users blocked from interacting with
iam-jit. Lives outside the UserStore (which is YAML/Dynamo-backed and
admin-edited) because bans are auto-driven by detected attacks and
shouldn't require an admin commit to take effect.

Effect of a ban:
  - the auth middleware refuses every authenticated request from a
    banned user with 403 (banned-user middleware fires before any
    route handler) — they cannot submit, edit, comment, or chat.
  - admins remain unbannable: the ban-on-detection path explicitly
    refuses to ban an admin (defense against an admin's session being
    used to inject — that escalation is a different attack class
    handled separately).

Stores: in-memory + filesystem, mirroring the intake_drafts pattern.
DynamoDB backend can be added later — bans are low-cardinality, so a
single-row config file works for most deployments.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import pathlib
import threading
from dataclasses import dataclass
from typing import Any, Protocol


logger = logging.getLogger("iam_jit.bans")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Ban:
    user_id: str
    banned_at: str
    reasons: list[str]
    snippets: list[str]
    confidence: str  # 'high' | 'medium'
    actor: str  # 'system:prompt_injection' or 'admin:<id>'
    notes: str = ""


class BanStore(Protocol):
    def is_banned(self, user_id: str) -> bool: ...

    def get(self, user_id: str) -> Ban | None: ...

    def add(self, ban: Ban) -> None: ...

    def remove(self, user_id: str) -> None: ...

    def list_all(self) -> list[Ban]: ...


class InMemoryBanStore:
    def __init__(self) -> None:
        self._bans: dict[str, Ban] = {}
        self._lock = threading.Lock()

    def is_banned(self, user_id: str) -> bool:
        with self._lock:
            return user_id in self._bans

    def get(self, user_id: str) -> Ban | None:
        with self._lock:
            return self._bans.get(user_id)

    def add(self, ban: Ban) -> None:
        with self._lock:
            self._bans[ban.user_id] = ban

    def remove(self, user_id: str) -> None:
        with self._lock:
            self._bans.pop(user_id, None)

    def list_all(self) -> list[Ban]:
        with self._lock:
            return sorted(
                self._bans.values(),
                key=lambda b: b.banned_at,
                reverse=True,
            )


class FilesystemBanStore:
    """One JSON file per banned user. `iam-jit serve`-friendly."""

    def __init__(self, root: pathlib.Path | str) -> None:
        self._root = pathlib.Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path_for(self, user_id: str) -> pathlib.Path:
        # Replace path-unsafe chars: user IDs are 'email:...' or
        # 'iam:arn:...', neither of which are filesystem-safe as-is.
        safe = (
            user_id.replace("/", "_")
            .replace("\\", "_")
            .replace(":", "_")
            .replace(" ", "_")
        )
        return self._root / f"{safe}.json"

    def is_banned(self, user_id: str) -> bool:
        return self.get(user_id) is not None

    def get(self, user_id: str) -> Ban | None:
        with self._lock:
            try:
                data = json.loads(self._path_for(user_id).read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                return None
            return Ban(
                user_id=data["user_id"],
                banned_at=data["banned_at"],
                reasons=list(data.get("reasons") or []),
                snippets=list(data.get("snippets") or []),
                confidence=data.get("confidence", "medium"),
                actor=data.get("actor", "system"),
                notes=data.get("notes", ""),
            )

    def add(self, ban: Ban) -> None:
        with self._lock:
            self._path_for(ban.user_id).write_text(
                json.dumps(
                    {
                        "user_id": ban.user_id,
                        "banned_at": ban.banned_at,
                        "reasons": list(ban.reasons),
                        "snippets": list(ban.snippets),
                        "confidence": ban.confidence,
                        "actor": ban.actor,
                        "notes": ban.notes,
                    },
                    separators=(",", ":"),
                )
            )

    def remove(self, user_id: str) -> None:
        with self._lock:
            try:
                self._path_for(user_id).unlink(missing_ok=True)
            except OSError:
                logger.exception("remove ban %s failed", user_id)

    def list_all(self) -> list[Ban]:
        out: list[Ban] = []
        with self._lock:
            for path in self._root.glob("*.json"):
                try:
                    data = json.loads(path.read_text())
                except (FileNotFoundError, json.JSONDecodeError):
                    continue
                out.append(
                    Ban(
                        user_id=data["user_id"],
                        banned_at=data["banned_at"],
                        reasons=list(data.get("reasons") or []),
                        snippets=list(data.get("snippets") or []),
                        confidence=data.get("confidence", "medium"),
                        actor=data.get("actor", "system"),
                        notes=data.get("notes", ""),
                    )
                )
        out.sort(key=lambda b: b.banned_at, reverse=True)
        return out


def ban_for_injection(
    *,
    store: BanStore,
    user_id: str,
    reasons: list[str],
    snippets: list[str],
    confidence: str,
    is_admin: bool,
) -> Ban | None:
    """Apply an automatic ban for detected prompt injection.

    Refuses to ban an admin — admin sessions are a different threat
    class (a compromised admin can't be "fixed" by banning; they'd
    just unban themselves). Surface that to the audit log instead.

    Returns the Ban that was added, or None if the ban was skipped.
    """
    if is_admin:
        logger.warning(
            "prompt_injection detected from admin user %s; NOT banning. "
            "reasons=%s",
            user_id,
            reasons,
        )
        return None
    ban = Ban(
        user_id=user_id,
        banned_at=_now_iso(),
        reasons=list(reasons),
        snippets=list(snippets),
        confidence=confidence,
        actor="system:prompt_injection",
    )
    store.add(ban)
    return ban


_GLOBAL_STORE: BanStore | None = None


def get_default_store() -> BanStore:
    global _GLOBAL_STORE
    if _GLOBAL_STORE is None:
        import os

        local = os.environ.get("IAM_JIT_BANS_DIR")
        if local:
            _GLOBAL_STORE = FilesystemBanStore(local)
        else:
            _GLOBAL_STORE = InMemoryBanStore()
    return _GLOBAL_STORE


def reset_default_store_for_tests() -> None:
    global _GLOBAL_STORE
    _GLOBAL_STORE = None
