"""Single-use enforcement for magic-link tokens.

Magic-link tokens are signed + time-bounded (15 min TTL). Without a
server-side record of "used" tokens, a token leaked via browser
history, proxy log, email-archive scanning, or referer can be replayed
during its TTL.

This store records every token that has been consumed, keyed by its
`hashlib.sha256` digest (we never persist the raw token — it's
sensitive until its TTL expires). On callback we:

  1. Verify signature + TTL
  2. Compute token hash
  3. If the hash is in the store, refuse: 'token already used'
  4. Otherwise, add to the store and proceed

Entries are cleaned up after 2× the TTL — at that point the token
itself is invalid via the signature step, so the entry is no longer
load-bearing.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Protocol


_TOKEN_TTL_SECONDS = 15 * 60
_STORE_TTL_SECONDS = 2 * _TOKEN_TTL_SECONDS  # margin for clock skew


class TokenAlreadyUsed(Exception):
    """The magic-link nonce was already consumed."""


class MagicLinkNonceStore(Protocol):
    def consume_or_reject(self, token_hash: str) -> None: ...

    def reset_for_tests(self) -> None: ...


class InMemoryMagicLinkNonceStore:
    def __init__(self) -> None:
        self._consumed: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume_or_reject(self, token_hash: str) -> None:
        now = time.time()
        with self._lock:
            # Sweep expired entries opportunistically — bounded since
            # we only enter on token use, which is naturally rate-
            # limited by user count.
            cutoff = now - _STORE_TTL_SECONDS
            for h in list(self._consumed.keys()):
                if self._consumed[h] < cutoff:
                    self._consumed.pop(h, None)
            if token_hash in self._consumed:
                raise TokenAlreadyUsed(
                    "magic-link token has already been used; request a new one"
                )
            self._consumed[token_hash] = now

    def reset_for_tests(self) -> None:
        with self._lock:
            self._consumed.clear()


class DynamoDBMagicLinkNonceStore:
    """DynamoDB-backed single-use enforcement, atomic across Lambda
    instances.

    Schema:
      table: <IAM_JIT_MAGIC_LINK_NONCES_TABLE>
      partition key: `token_hash` (String)
      TTL attribute: `expires_at` (Number — unix seconds; the table
        MUST have TimeToLiveSpecification enabled on `expires_at`)

    The `consume_or_reject` operation is a single PutItem with
    `ConditionExpression="attribute_not_exists(token_hash)"`. The
    conditional check fails atomically if any other instance already
    consumed the same token; we raise TokenAlreadyUsed in that case.
    """

    def __init__(self, table_name: str, *, client: object | None = None) -> None:
        self._table_name = table_name
        if client is not None:
            self._client = client
        else:
            import boto3

            self._client = boto3.client("dynamodb")

    def consume_or_reject(self, token_hash: str) -> None:
        expires_at = int(time.time() + _STORE_TTL_SECONDS)
        try:
            self._client.put_item(
                TableName=self._table_name,
                Item={
                    "token_hash": {"S": token_hash},
                    "expires_at": {"N": str(expires_at)},
                },
                ConditionExpression="attribute_not_exists(token_hash)",
            )
        except Exception as e:
            # Conditional check failed → another instance already
            # consumed this token. Centralized detector handles both
            # the structured-response and string-match shapes.
            from .ddb_utils import is_conditional_check_failed

            if is_conditional_check_failed(e):
                raise TokenAlreadyUsed(
                    "magic-link token has already been used; request a new one"
                )
            raise

    def reset_for_tests(self) -> None:
        # No-op for the DDB backend — table cleanup is operator-managed.
        return None


_GLOBAL: MagicLinkNonceStore | None = None


def get_default_store() -> MagicLinkNonceStore:
    global _GLOBAL
    if _GLOBAL is None:
        table = (
            os.environ.get("IAM_JIT_MAGIC_LINK_NONCES_TABLE") or ""
        ).strip()
        if table:
            _GLOBAL = DynamoDBMagicLinkNonceStore(table)
        else:
            _GLOBAL = InMemoryMagicLinkNonceStore()
    return _GLOBAL


def reset_default_store_for_tests() -> None:
    global _GLOBAL
    _GLOBAL = None
