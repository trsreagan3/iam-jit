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
            path = self._path_for(user_id)
            try:
                data = json.loads(path.read_text())
            except FileNotFoundError:
                return None
            except json.JSONDecodeError as e:
                # BAN-STORE-CORRUPT-FILE-UNBAN closure: a corrupt
                # JSON file on disk MUST NOT silently un-ban the
                # user. The audit log is the durable record of who
                # is banned; if the on-disk copy is truncated or
                # tampered with, fail closed (raise) so the caller
                # (middleware) treats it as a store outage and
                # responds 503 instead of 200.
                logger.error(
                    "FilesystemBanStore: corrupt ban file for %s at %s: %s",
                    user_id, path, e,
                )
                raise
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


class DynamoDBBanStore:
    """DynamoDB-backed ban store. Atomic across Lambda instances.

    Schema:
      table: <IAM_JIT_BANS_TABLE>
      partition key: `user_id` (String)
      attribute: `ban_json` (String — JSON-serialized Ban record)
    """

    def __init__(self, table_name: str, *, client: object | None = None) -> None:
        self._table_name = table_name
        if client is not None:
            self._client = client
        else:
            import boto3

            self._client = boto3.client("dynamodb")

    def add(self, ban: "Ban") -> None:
        import dataclasses
        import json

        payload = json.dumps(dataclasses.asdict(ban), separators=(",", ":"))
        self._client.put_item(
            TableName=self._table_name,
            Item={
                "user_id": {"S": ban.user_id},
                "ban_json": {"S": payload},
            },
        )

    def is_banned(self, user_id: str) -> bool:
        return self.get(user_id) is not None

    def get(self, user_id: str) -> "Ban | None":
        try:
            resp = self._client.get_item(
                TableName=self._table_name,
                Key={"user_id": {"S": user_id}},
                ConsistentRead=True,
            )
        except Exception:
            # BAN-CHECK-FAIL-OPEN closure: fail CLOSED on DDB errors.
            # A transient ddb outage shouldn't allow a banned user
            # back in. The caller (middleware) treats None as "not
            # banned"; we raise instead so the middleware can decide
            # whether to 503 or fail closed by ban-by-default.
            raise
        item = resp.get("Item") if isinstance(resp, dict) else None
        if not item:
            return None
        import json

        try:
            data = json.loads(item["ban_json"]["S"])
        except Exception:
            return None
        return Ban(
            user_id=data.get("user_id", user_id),
            banned_at=data.get("banned_at", ""),
            reasons=list(data.get("reasons") or []),
            snippets=list(data.get("snippets") or []),
            confidence=data.get("confidence", "med"),
            actor=data.get("actor", "system"),
        )

    def remove(self, user_id: str) -> None:
        self._client.delete_item(
            TableName=self._table_name,
            Key={"user_id": {"S": user_id}},
        )

    def list_all(self) -> list["Ban"]:
        # Scans are fine here — ban list is small (< 1000 in any
        # realistic deployment) and used only by the admin UI.
        out: list[Ban] = []
        last_key = None
        while True:
            kwargs: dict = {"TableName": self._table_name}
            if last_key is not None:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self._client.scan(**kwargs)
            for item in resp.get("Items", []) or []:
                import json

                try:
                    data = json.loads(item["ban_json"]["S"])
                except Exception:
                    continue
                out.append(
                    Ban(
                        user_id=data.get("user_id", ""),
                        banned_at=data.get("banned_at", ""),
                        reasons=list(data.get("reasons") or []),
                        snippets=list(data.get("snippets") or []),
                        confidence=data.get("confidence", "med"),
                        actor=data.get("actor", "system"),
                    )
                )
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return out


_GLOBAL_STORE: BanStore | None = None


def get_default_store() -> BanStore:
    global _GLOBAL_STORE
    if _GLOBAL_STORE is None:
        import os

        table = (os.environ.get("IAM_JIT_BANS_TABLE") or "").strip()
        if table:
            _GLOBAL_STORE = DynamoDBBanStore(table)
        else:
            local = os.environ.get("IAM_JIT_BANS_DIR")
            if local:
                _GLOBAL_STORE = FilesystemBanStore(local)
            else:
                _GLOBAL_STORE = InMemoryBanStore()
    return _GLOBAL_STORE


def reset_default_store_for_tests() -> None:
    global _GLOBAL_STORE
    _GLOBAL_STORE = None
