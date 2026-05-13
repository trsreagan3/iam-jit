"""Destination-account registry.

Stores the accounts iam-jit is allowed to provision into. iam-jit cannot
add itself to a new account — the privileged bootstrap (CloudFormation
deploy of ProvisionerRole/DiscoveryRole) is run by a human or agent
holding admin in the destination account. This store records the result
of that bootstrap so iam-jit knows which accounts to trust as targets.

Two backends, mirroring the user store:

  - `FileAccountStore`: read-only at runtime; YAML on local disk or S3.
    Updates happen by editing/uploading the file. ETag-based refresh.

  - `DynamoDBAccountStore`: read/write; admin operations write to DDB.

Both expose the same `Account` model.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import io
import json
import pathlib
import time
from typing import Any, Protocol

import jsonschema
from ruamel.yaml import YAML

_yaml = YAML(typ="safe")


@dataclasses.dataclass(frozen=True)
class Account:
    """A registered destination account."""

    account_id: str  # "123456789012"
    provisioner_role_arn: str
    provisioner_external_id: str
    provisioning_mode: str  # "classic_iam" | "identity_center" | "both"
    alias: str | None = None
    regions: tuple[str, ...] = ()
    discovery_role_arn: str | None = None
    discovery_external_id: str | None = None
    registered_at: str | None = None
    registered_by: str | None = None
    notes: str | None = None
    enabled: bool = True

    @property
    def id(self) -> str:
        """Use account_id as the primary key."""
        return self.account_id

    @property
    def has_discovery(self) -> bool:
        return bool(self.discovery_role_arn)


class AccountNotFound(Exception):
    """Raised when an account_id lookup misses."""


class AccountAlreadyExists(Exception):
    """Raised when registering an account that's already in the store."""


class AccountStoreReadOnly(Exception):
    """Raised when an admin operation is attempted on a read-only store."""


class AccountStore(Protocol):
    """Operations the routes need."""

    def get(self, account_id: str) -> Account: ...

    def list(self, *, include_disabled: bool = False) -> list[Account]: ...

    def put(self, account: Account) -> None: ...

    def delete(self, account_id: str) -> None: ...


from . import _resources

_ACCOUNTS_SCHEMA_PATH = _resources.find("schemas", "accounts.schema.json")


def _accounts_schema() -> dict[str, Any]:
    return json.loads(_ACCOUNTS_SCHEMA_PATH.read_text())


def _account_from_dict(d: dict[str, Any]) -> Account:
    return Account(
        account_id=d["account_id"],
        provisioner_role_arn=d["provisioner_role_arn"],
        provisioner_external_id=d["provisioner_external_id"],
        provisioning_mode=d["provisioning_mode"],
        alias=d.get("alias"),
        regions=tuple(d.get("regions") or ()),
        discovery_role_arn=d.get("discovery_role_arn"),
        discovery_external_id=d.get("discovery_external_id"),
        registered_at=d.get("registered_at"),
        registered_by=d.get("registered_by"),
        notes=d.get("notes"),
        enabled=bool(d.get("enabled", True)),
    )


def _account_to_dict(a: Account) -> dict[str, Any]:
    out: dict[str, Any] = {
        "account_id": a.account_id,
        "provisioner_role_arn": a.provisioner_role_arn,
        "provisioner_external_id": a.provisioner_external_id,
        "provisioning_mode": a.provisioning_mode,
        "enabled": a.enabled,
    }
    if a.alias:
        out["alias"] = a.alias
    if a.regions:
        out["regions"] = list(a.regions)
    if a.discovery_role_arn:
        out["discovery_role_arn"] = a.discovery_role_arn
    if a.discovery_external_id:
        out["discovery_external_id"] = a.discovery_external_id
    if a.registered_at:
        out["registered_at"] = a.registered_at
    if a.registered_by:
        out["registered_by"] = a.registered_by
    if a.notes:
        out["notes"] = a.notes
    return out


def utcnow_iso() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class FileAccountStore:
    """Read-only-at-runtime store backed by a YAML file."""

    name = "file"

    def __init__(
        self,
        location: str,
        *,
        cache_ttl_seconds: int = 60,
        s3_client: Any = None,
    ) -> None:
        self.location = location
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, Account] | None = None
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
            jsonschema.Draft202012Validator(_accounts_schema()).validate(data)
        except Exception:
            if self._cache is None:
                self._cache = {}
            self._cache_at = now
            return
        accounts: dict[str, Account] = {}
        for entry in data.get("accounts") or []:
            account = _account_from_dict(entry)
            accounts[account.id] = account
        self._cache = accounts
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

    def get(self, account_id: str) -> Account:
        self._maybe_reload()
        assert self._cache is not None
        if account_id not in self._cache:
            raise AccountNotFound(account_id)
        return self._cache[account_id]

    def list(self, *, include_disabled: bool = False) -> list[Account]:
        self._maybe_reload()
        assert self._cache is not None
        accounts = list(self._cache.values())
        if not include_disabled:
            accounts = [a for a in accounts if a.enabled]
        return sorted(accounts, key=lambda a: a.account_id)

    def put(self, account: Account) -> None:
        raise AccountStoreReadOnly(
            "FileAccountStore is read-only at runtime. Edit the YAML file and re-upload."
        )

    def delete(self, account_id: str) -> None:
        raise AccountStoreReadOnly(
            "FileAccountStore is read-only at runtime. Edit the YAML file and re-upload."
        )


class InMemoryAccountStore:
    """Process-local store for tests and `iam-jit serve` development."""

    name = "memory"

    def __init__(self) -> None:
        self._items: dict[str, Account] = {}

    def get(self, account_id: str) -> Account:
        if account_id not in self._items:
            raise AccountNotFound(account_id)
        return self._items[account_id]

    def list(self, *, include_disabled: bool = False) -> list[Account]:
        accounts = list(self._items.values())
        if not include_disabled:
            accounts = [a for a in accounts if a.enabled]
        return sorted(accounts, key=lambda a: a.account_id)

    def put(self, account: Account) -> None:
        self._items[account.account_id] = account

    def delete(self, account_id: str) -> None:
        if account_id not in self._items:
            raise AccountNotFound(account_id)
        del self._items[account_id]


class DynamoDBAccountStore:
    """Read/write store backed by a DynamoDB table.

    Schema:
      - HASH key: account_id (S) — 12-digit AWS account ID
      - other attrs: provisioner_role_arn (S), provisioner_external_id (S),
        discovery_role_arn (S), discovery_external_id (S),
        provisioning_mode (S), regions (SS), alias (S), enabled (BOOL),
        registered_at (S), registered_by (S), notes (S)
    """

    name = "dynamodb"

    def __init__(self, table_name: str, dynamodb_resource: Any = None) -> None:
        self.table_name = table_name
        if dynamodb_resource is None:
            import boto3

            dynamodb_resource = boto3.resource("dynamodb")
        self.table = dynamodb_resource.Table(table_name)

    @staticmethod
    def _to_item(a: Account) -> dict[str, Any]:
        item: dict[str, Any] = {
            "account_id": a.account_id,
            "provisioner_role_arn": a.provisioner_role_arn,
            "provisioner_external_id": a.provisioner_external_id,
            "provisioning_mode": a.provisioning_mode,
            "enabled": a.enabled,
        }
        if a.alias:
            item["alias"] = a.alias
        if a.regions:
            item["regions"] = list(a.regions)
        if a.discovery_role_arn:
            item["discovery_role_arn"] = a.discovery_role_arn
        if a.discovery_external_id:
            item["discovery_external_id"] = a.discovery_external_id
        if a.registered_at:
            item["registered_at"] = a.registered_at
        if a.registered_by:
            item["registered_by"] = a.registered_by
        if a.notes:
            item["notes"] = a.notes
        return item

    @staticmethod
    def _from_item(item: dict[str, Any]) -> Account:
        return Account(
            account_id=item["account_id"],
            provisioner_role_arn=item["provisioner_role_arn"],
            provisioner_external_id=item["provisioner_external_id"],
            provisioning_mode=item["provisioning_mode"],
            alias=item.get("alias"),
            regions=tuple(item.get("regions") or ()),
            discovery_role_arn=item.get("discovery_role_arn"),
            discovery_external_id=item.get("discovery_external_id"),
            registered_at=item.get("registered_at"),
            registered_by=item.get("registered_by"),
            notes=item.get("notes"),
            enabled=bool(item.get("enabled", True)),
        )

    def get(self, account_id: str) -> Account:
        resp = self.table.get_item(Key={"account_id": account_id})
        item = resp.get("Item")
        if item is None:
            raise AccountNotFound(account_id)
        return self._from_item(item)

    def list(self, *, include_disabled: bool = False) -> list[Account]:
        accounts: list[Account] = []
        last_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {}
            if last_key is not None:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self.table.scan(**kwargs)
            for item in resp.get("Items") or []:
                a = self._from_item(item)
                if include_disabled or a.enabled:
                    accounts.append(a)
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return sorted(accounts, key=lambda a: a.account_id)

    def put(self, account: Account) -> None:
        self.table.put_item(Item=self._to_item(account))

    def delete(self, account_id: str) -> None:
        self.table.delete_item(Key={"account_id": account_id})
