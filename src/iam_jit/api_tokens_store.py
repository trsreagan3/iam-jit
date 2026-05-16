"""API token storage.

Tokens are HMAC-keyed bearer credentials issued per-user. We never store
the raw token; only its sha256 hash. Lookup at request time happens by
hashing the bearer header and reading the matching row.

Two implementations:
  - InMemoryAPITokenStore: for tests and local dev.
  - DynamoDBAPITokenStore: for production. Schema matches the SAM
    template's ApiTokensTable (HASH key: token_hash; GSI by user_id).
"""

from __future__ import annotations

import dataclasses
from typing import Any, Protocol


@dataclasses.dataclass(frozen=True)
class APITokenRecord:
    token_hash: str
    user_id: str
    created_at: int
    label: str | None
    last_used_at: int | None = None
    # Epoch seconds at which the human authorizer's MFA was asserted
    # when this token was minted. Per [[mfa-compliance-strategy]]
    # agents are system accounts under PCI §8.6 — the human's MFA
    # at issuance satisfies the requirement, and the per-action MFA
    # gate checks freshness against THIS field for bearer-token
    # requests (vs the iam_jit_session_mfa cookie for browser/session
    # requests). None = legacy token issued before this tracking
    # shipped; treated as "no MFA evidence" by the freshness gate.
    mfa_at_issuance: int | None = None


class APITokenNotFound(Exception):
    pass


class APITokenStore(Protocol):
    def put(self, record: APITokenRecord) -> None: ...

    def get_by_hash(self, token_hash: str) -> APITokenRecord: ...

    def list_for_user(self, user_id: str) -> list[APITokenRecord]: ...

    def list_all(self) -> list[APITokenRecord]: ...

    def delete(self, token_hash: str) -> None: ...

    def touch_last_used(self, token_hash: str, *, epoch_seconds: int) -> None: ...


class InMemoryAPITokenStore:
    name = "memory"

    def __init__(self) -> None:
        self._items: dict[str, APITokenRecord] = {}

    def put(self, record: APITokenRecord) -> None:
        self._items[record.token_hash] = record

    def get_by_hash(self, token_hash: str) -> APITokenRecord:
        if token_hash not in self._items:
            raise APITokenNotFound(token_hash)
        return self._items[token_hash]

    def list_for_user(self, user_id: str) -> list[APITokenRecord]:
        return sorted(
            (r for r in self._items.values() if r.user_id == user_id),
            key=lambda r: r.created_at,
        )

    def list_all(self) -> list[APITokenRecord]:
        return sorted(self._items.values(), key=lambda r: r.created_at)

    def delete(self, token_hash: str) -> None:
        self._items.pop(token_hash, None)

    def touch_last_used(self, token_hash: str, *, epoch_seconds: int) -> None:
        existing = self._items.get(token_hash)
        if existing is None:
            return
        self._items[token_hash] = dataclasses.replace(existing, last_used_at=epoch_seconds)


class DynamoDBAPITokenStore:
    name = "dynamodb"

    def __init__(self, table_name: str, dynamodb_resource: Any = None) -> None:
        self.table_name = table_name
        if dynamodb_resource is None:
            import boto3

            dynamodb_resource = boto3.resource("dynamodb")
        self.table = dynamodb_resource.Table(table_name)

    @staticmethod
    def _to_item(r: APITokenRecord) -> dict[str, Any]:
        item: dict[str, Any] = {
            "token_hash": r.token_hash,
            "user_id": r.user_id,
            "created_at": r.created_at,
        }
        if r.label:
            item["label"] = r.label
        if r.last_used_at is not None:
            item["last_used_at"] = r.last_used_at
        if r.mfa_at_issuance is not None:
            item["mfa_at_issuance"] = r.mfa_at_issuance
        return item

    @staticmethod
    def _from_item(item: dict[str, Any]) -> APITokenRecord:
        return APITokenRecord(
            token_hash=item["token_hash"],
            user_id=item["user_id"],
            created_at=int(item["created_at"]),
            label=item.get("label"),
            last_used_at=int(item["last_used_at"]) if item.get("last_used_at") is not None else None,
            mfa_at_issuance=(
                int(item["mfa_at_issuance"])
                if item.get("mfa_at_issuance") is not None else None
            ),
        )

    def put(self, record: APITokenRecord) -> None:
        self.table.put_item(Item=self._to_item(record))

    def get_by_hash(self, token_hash: str) -> APITokenRecord:
        resp = self.table.get_item(Key={"token_hash": token_hash})
        item = resp.get("Item")
        if item is None:
            raise APITokenNotFound(token_hash)
        return self._from_item(item)

    def list_for_user(self, user_id: str) -> list[APITokenRecord]:
        resp = self.table.query(
            IndexName="by-user",
            KeyConditionExpression="user_id = :uid",
            ExpressionAttributeValues={":uid": user_id},
        )
        return sorted(
            (self._from_item(item) for item in resp.get("Items") or []),
            key=lambda r: r.created_at,
        )

    def list_all(self) -> list[APITokenRecord]:
        """Full Scan of the tokens table.

        Used by the inactivity sweep, which is meant to run on a low-
        frequency schedule (daily, not per-request). For a token table
        that grows past tens of thousands the Scan throughput needs
        attention; at iam-jit's scale this is fine.
        """
        out: list[APITokenRecord] = []
        last_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self.table.scan(**kwargs)
            for item in resp.get("Items") or []:
                out.append(self._from_item(item))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        out.sort(key=lambda r: r.created_at)
        return out

    def delete(self, token_hash: str) -> None:
        self.table.delete_item(Key={"token_hash": token_hash})

    def touch_last_used(self, token_hash: str, *, epoch_seconds: int) -> None:
        try:
            self.table.update_item(
                Key={"token_hash": token_hash},
                UpdateExpression="SET last_used_at = :ts",
                ExpressionAttributeValues={":ts": epoch_seconds},
                ConditionExpression="attribute_exists(token_hash)",
            )
        except Exception:
            # last_used is best-effort metadata; never fail a request because we couldn't update it.
            pass
