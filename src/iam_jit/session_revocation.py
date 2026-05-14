"""Server-side session revocation list.

The session cookie is a signed user_id with a 24-hour TTL. Once
issued, the cookie value alone is sufficient to authenticate — no
server-side state. That's elegant but it means `/logout` and
`/api/v1/auth/logout` can only CLEAR the cookie in the caller's
browser; an attacker who exfiltrated the value before logout
keeps using it for the remainder of the TTL.

This module adds the missing server-side primitive: a revocation
list keyed by `sha256(cookie_value)`. On logout, the route inserts
the hash. On every authenticated request, the middleware checks
the list and refuses if found. The hash is the lookup key (never
the raw cookie) so even compromise of the revocation store doesn't
hand the attacker a list of valid bearer tokens.

Multi-instance posture: the DynamoDB-backed implementation uses
`PutItem` (idempotent) for revocation and `GetItem(ConsistentRead=
True)` for the check. Falls back to a process-local in-memory
store when `IAM_JIT_SESSION_REVOCATION_TABLE` is unset (suitable
for single-instance dev / RC=1 deployments).
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Protocol


_DEFAULT_SESSION_TTL_SECONDS = 24 * 60 * 60


def _cookie_hash(cookie_value: str) -> str:
    return hashlib.sha256(cookie_value.encode("utf-8")).hexdigest()


class SessionRevocationStore(Protocol):
    def revoke(self, cookie_value: str, *, ttl_seconds: int) -> None: ...

    def is_revoked(self, cookie_value: str) -> bool: ...

    def reset_for_tests(self) -> None: ...


class InMemorySessionRevocationStore:
    def __init__(self) -> None:
        self._revoked: dict[str, float] = {}
        self._lock = threading.Lock()

    def revoke(self, cookie_value: str, *, ttl_seconds: int) -> None:
        expires_at = time.time() + ttl_seconds
        h = _cookie_hash(cookie_value)
        with self._lock:
            self._revoked[h] = expires_at

    def is_revoked(self, cookie_value: str) -> bool:
        h = _cookie_hash(cookie_value)
        now = time.time()
        with self._lock:
            expires_at = self._revoked.get(h)
            if expires_at is None:
                return False
            if expires_at <= now:
                self._revoked.pop(h, None)
                return False
            return True

    def reset_for_tests(self) -> None:
        with self._lock:
            self._revoked.clear()


class DynamoDBSessionRevocationStore:
    """DDB-backed revocation list — multi-instance safe.

    Schema:
      table: <IAM_JIT_SESSION_REVOCATION_TABLE>
      partition key: `cookie_hash` (String — sha256 hex of cookie)
      TTL attribute: `expires_at` (Number — unix seconds; the table
        MUST have TimeToLiveSpecification enabled on `expires_at`)
    """

    def __init__(self, table_name: str, *, client: object | None = None) -> None:
        self._table_name = table_name
        if client is not None:
            self._client = client
        else:
            import boto3

            self._client = boto3.client("dynamodb")

    def revoke(self, cookie_value: str, *, ttl_seconds: int) -> None:
        expires_at = int(time.time() + ttl_seconds)
        h = _cookie_hash(cookie_value)
        self._client.put_item(
            TableName=self._table_name,
            Item={
                "cookie_hash": {"S": h},
                "expires_at": {"N": str(expires_at)},
            },
        )

    def is_revoked(self, cookie_value: str) -> bool:
        h = _cookie_hash(cookie_value)
        resp = self._client.get_item(
            TableName=self._table_name,
            Key={"cookie_hash": {"S": h}},
            ConsistentRead=True,
        )
        item = resp.get("Item") if isinstance(resp, dict) else None
        if not item:
            return False
        try:
            expires_at = int(item["expires_at"]["N"])
        except (KeyError, ValueError):
            return False
        if expires_at <= int(time.time()):
            return False
        return True

    def reset_for_tests(self) -> None:
        return None


_GLOBAL: SessionRevocationStore | None = None


def get_default_store() -> SessionRevocationStore:
    global _GLOBAL
    if _GLOBAL is None:
        table = (
            os.environ.get("IAM_JIT_SESSION_REVOCATION_TABLE") or ""
        ).strip()
        if table:
            _GLOBAL = DynamoDBSessionRevocationStore(table)
        else:
            _GLOBAL = InMemorySessionRevocationStore()
    return _GLOBAL


def reset_default_store_for_tests() -> None:
    global _GLOBAL
    _GLOBAL = None
