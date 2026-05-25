"""User configuration store.

Two backends matching the SAM `UserConfigSource` parameter:

  - `FileUserStore`: read-only at runtime; reloads from a YAML file (in S3
    or local disk). The YAML matches `schemas/users.schema.json`. Includes
    a 60-second in-memory cache with ETag-based refresh on the S3 path.
    File-mode admin updates happen by uploading a new version of the file.

  - `DynamoDBUserStore`: read/write; admin operations write to DynamoDB.
    The Lambda's IAM role grants only the access patterns this store
    actually uses.

Both stores expose the same `User` model.
"""

from __future__ import annotations

import dataclasses
import io
import json
import pathlib
import time
from typing import Any, Protocol

import jsonschema
from ruamel.yaml import YAML

_yaml = YAML(typ="safe")


@dataclasses.dataclass(frozen=True)
class User:
    """A user record, normalized across both stores."""

    id: str  # 'email:<email>' or 'iam:<arn>'
    roles: tuple[str, ...]
    enabled: bool = True
    display_name: str | None = None
    notes: str | None = None
    last_action: str | None = None  # ISO-8601 of last user action
    # #613 — per-user override of the outstanding-request cap. When
    # None, the deployment falls back to the env var
    # IAM_JIT_MAX_OUTSTANDING_PER_USER (or the built-in default of 20).
    # See iam_jit._outstanding_request_cap.
    outstanding_request_cap: int | None = None

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles

    @property
    def is_approver(self) -> bool:
        return "approver" in self.roles or self.is_admin

    @property
    def is_requester(self) -> bool:
        return "requester" in self.roles or self.is_approver


class UserNotFound(Exception):
    """Raised when a lookup id doesn't match any user."""


class UserStore(Protocol):
    """Operations the auth middleware needs."""

    def get(self, user_id: str) -> User: ...

    def list(self, *, include_disabled: bool = False) -> list[User]: ...

    def put(self, user: User) -> None: ...

    def delete(self, user_id: str) -> None: ...


# Loaded once for fast validation; reloaded per-test by tests that need it.
from . import _resources

_USERS_SCHEMA_PATH = _resources.find("schemas", "users.schema.json")


def _users_schema() -> dict[str, Any]:
    return json.loads(_USERS_SCHEMA_PATH.read_text())


def _user_from_dict(d: dict[str, Any]) -> User:
    return User(
        id=d["id"],
        roles=tuple(d["roles"]),
        enabled=bool(d.get("enabled", True)),
        display_name=d.get("display_name"),
        notes=d.get("notes"),
        outstanding_request_cap=d.get("outstanding_request_cap"),
    )


class FileUserStore:
    """Read-only-at-runtime store backed by a YAML file.

    The file location can be a local path (for `iam-jit serve` dev mode)
    or an `s3://bucket/key` URL (for the deployed Lambda). Updates happen
    out-of-band by editing/uploading the file; this class re-reads with a
    short TTL.
    """

    name = "file"

    def __init__(
        self,
        location: str,
        *,
        cache_ttl_seconds: int = 60,
        s3_client: Any = None,
        expected_auth_mode: str | None = None,
    ) -> None:
        self.location = location
        self.cache_ttl_seconds = cache_ttl_seconds
        self.expected_auth_mode = expected_auth_mode
        self._cache: dict[str, User] | None = None
        self._cache_at: float = 0.0
        self._cache_etag: str | None = None
        if location.startswith("s3://"):
            if s3_client is None:
                import boto3

                s3_client = boto3.client("s3")
            self._s3 = s3_client
            without_scheme = location[len("s3://") :]
            self._bucket, _, self._key = without_scheme.partition("/")
        else:
            self._s3 = None
            self._bucket = ""
            self._key = ""

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if self._cache is not None and now - self._cache_at < self.cache_ttl_seconds:
            return
        try:
            raw, etag = self._read()
        except FileNotFoundError:
            self._cache = {}
            self._cache_at = now
            return
        if etag and etag == self._cache_etag and self._cache is not None:
            self._cache_at = now
            return
        try:
            data = _yaml.load(io.BytesIO(raw))
            jsonschema.Draft202012Validator(_users_schema()).validate(data)
        except Exception:
            # On malformed file, keep last-good cache. Don't lock everyone out.
            if self._cache is None:
                self._cache = {}
            self._cache_at = now
            return
        if (
            self.expected_auth_mode
            and data.get("auth_mode")
            and data["auth_mode"] != self.expected_auth_mode
        ):
            # Wrong-mode file uploaded — refuse it gracefully.
            if self._cache is None:
                self._cache = {}
            self._cache_at = now
            return
        users: dict[str, User] = {}
        for entry in data.get("users") or []:
            user = _user_from_dict(entry)
            users[user.id] = user
        self._cache = users
        self._cache_at = now
        self._cache_etag = etag

    def _read(self) -> tuple[bytes, str | None]:
        if self._s3 is not None:
            try:
                resp = self._s3.get_object(Bucket=self._bucket, Key=self._key)
            except Exception as e:
                raise FileNotFoundError(self.location) from e
            return resp["Body"].read(), resp.get("ETag")
        path = pathlib.Path(self.location)
        if not path.exists():
            raise FileNotFoundError(self.location)
        return path.read_bytes(), None

    def get(self, user_id: str) -> User:
        self._maybe_reload()
        assert self._cache is not None
        if user_id not in self._cache:
            raise UserNotFound(user_id)
        return self._cache[user_id]

    def list(self, *, include_disabled: bool = False) -> list[User]:
        self._maybe_reload()
        assert self._cache is not None
        users = list(self._cache.values())
        if not include_disabled:
            users = [u for u in users if u.enabled]
        return sorted(users, key=lambda u: u.id)

    def put(self, user: User) -> None:
        raise StoreReadOnly(
            "FileUserStore is read-only at runtime. Edit the YAML file and re-upload."
        )

    def delete(self, user_id: str) -> None:
        raise StoreReadOnly(
            "FileUserStore is read-only at runtime. Edit the YAML file and re-upload."
        )


class StoreReadOnly(Exception):
    """Raised when an admin operation is attempted on a read-only store."""


class DynamoDBUserStore:
    """Read/write store backed by a DynamoDB table.

    Schema:
      - HASH key: user_id (S) — 'email:<email>' or 'iam:<arn>'
      - other attrs: roles (SS), enabled (BOOL), display_name (S), notes (S)
    """

    name = "dynamodb"

    def __init__(self, table_name: str, dynamodb_resource: Any = None) -> None:
        self.table_name = table_name
        if dynamodb_resource is None:
            import boto3

            dynamodb_resource = boto3.resource("dynamodb")
        self.table = dynamodb_resource.Table(table_name)

    @staticmethod
    def _to_item(user: User) -> dict[str, Any]:
        item: dict[str, Any] = {
            "user_id": user.id,
            "roles": list(user.roles),
            "enabled": user.enabled,
        }
        if user.display_name:
            item["display_name"] = user.display_name
        if user.notes:
            item["notes"] = user.notes
        # #613 — persist the per-user outstanding cap when set.
        if user.outstanding_request_cap is not None:
            item["outstanding_request_cap"] = int(user.outstanding_request_cap)
        return item

    @staticmethod
    def _from_item(item: dict[str, Any]) -> User:
        return User(
            id=item["user_id"],
            roles=tuple(item.get("roles") or []),
            enabled=bool(item.get("enabled", True)),
            display_name=item.get("display_name"),
            notes=item.get("notes"),
            outstanding_request_cap=item.get("outstanding_request_cap"),
        )

    def get(self, user_id: str) -> User:
        resp = self.table.get_item(Key={"user_id": user_id})
        item = resp.get("Item")
        if item is None:
            raise UserNotFound(user_id)
        return self._from_item(item)

    def list(self, *, include_disabled: bool = False) -> list[User]:
        users: list[User] = []
        last_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {}
            if last_key is not None:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self.table.scan(**kwargs)
            for item in resp.get("Items") or []:
                u = self._from_item(item)
                if include_disabled or u.enabled:
                    users.append(u)
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return sorted(users, key=lambda u: u.id)

    def put(self, user: User) -> None:
        # #161 + [[user-count-soft-cap]]: gate NEW user creation on
        # the Free-tier soft cap (default 25; raised by signed
        # Enterprise license). Updates to existing users are NOT
        # gated — only new creations. Race-tolerant: this is a soft
        # cap by design, not an atomic constraint.
        #
        # WB31 HIGH-31-03 closure: distinguish "definitively not
        # found" from "couldn't tell because DDB is throttling /
        # timing out / temporarily unavailable." Misclassifying the
        # latter as a creation makes the cap gate erroneously reject
        # UPDATES to existing users during an availability incident
        # — exactly when admins most need to mutate user roles.
        existing: dict | None = None
        existing_known = False
        try:
            existing = self.table.get_item(Key={"user_id": user.id}).get("Item")
            existing_known = True
        except Exception as e:
            # If this is a transient DDB-side failure (throttling /
            # service unavailable / timeout), we CAN'T tell whether
            # this is a create or an update. Surface the underlying
            # error rather than misclassifying as a create and
            # firing the cap gate. Caller can retry.
            err_code = ""
            resp = getattr(e, "response", None)
            if isinstance(resp, dict):
                err_code = resp.get("Error", {}).get("Code", "")
            transient_codes = {
                "ProvisionedThroughputExceededException",
                "RequestTimeoutException",
                "InternalServerError",
                "ServiceUnavailableException",
                "ThrottlingException",
            }
            if err_code in transient_codes:
                raise
            # Genuine "not found" surfaces of get_item don't raise;
            # they return an empty dict. Any other exception is
            # something we don't recognize — fail loud rather than
            # silently misclassifying.
            raise

        if existing_known and existing is None:
            from . import license as _license_mod
            current_count = self._count_users()
            _license_mod.enforce_user_creation_cap(
                current_user_count=current_count,
            )
        self.table.put_item(Item=self._to_item(user))

    def _count_users(self) -> int:
        """Count users (including disabled). Used by the cap gate.
        Scan-based — acceptable up to a few thousand users; above
        that, replace with a maintained counter."""
        count = 0
        last_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {"Select": "COUNT"}
            if last_key is not None:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self.table.scan(**kwargs)
            count += int(resp.get("Count", 0))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return count

    def delete(self, user_id: str) -> None:
        self.table.delete_item(Key={"user_id": user_id})
