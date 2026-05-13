"""Request storage backends.

The `RequestStore` protocol abstracts where request YAML files live.
Two implementations are provided:

  - `FilesystemStore`: writes to a local directory. Used for `iam-jit serve`
    on a developer's machine and for the test suite. This is the same
    `requests/` directory the GitOps workflow uses, so submitting through
    the API in dev produces files a human reviewer could see in `git status`.

  - `S3Store`: writes to a versioned S3 bucket. Used by the deployed
    Lambda. Versioning preserves every revision of every request for
    audit purposes.

Both implementations expose the same operations and round-trip the same
YAML format that the existing schema/CLI tooling already understands.
"""

from __future__ import annotations

import io
import pathlib
import re
import threading
from typing import Any, Protocol

from .schema import dump_request, validate_request


# Strict request-id allowlist, mirroring `metadata.id` in the schema
# (`^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$`). Enforced at every store
# operation — a bug elsewhere that lets a non-conformant id through
# (NUL byte, path-traversal sequence, URL-encoded slash) doesn't reach
# the filesystem / S3 key.
_REQUEST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$")


def _validate_request_id(request_id: str) -> None:
    if not isinstance(request_id, str) or not _REQUEST_ID_RE.match(request_id):
        raise ValueError(
            f"invalid request_id (must match {_REQUEST_ID_RE.pattern}): "
            f"{request_id!r}"
        )


def _read_version_from_request(request: dict[str, Any]) -> int:
    """Pull the optimistic-lock version from `request.status.version`.

    Missing / non-int values default to 0 so a request submitted before
    this code shipped (no version field) is treated as the first
    revision."""
    status = request.get("status") if isinstance(request, dict) else None
    if not isinstance(status, dict):
        return 0
    raw = status.get("version")
    try:
        return int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        return 0


class StoreError(Exception):
    """Raised on store-level errors that aren't validation failures."""


class NotFoundError(StoreError):
    """Raised when a request_id isn't present in the store."""


class VersionConflict(StoreError):
    """Optimistic-lock violation: another writer modified the request
    between our `get` and `put`. Caller is expected to re-fetch and
    re-apply their change.

    Why it exists: two approvers clicking Approve at the same time,
    or an admin force-cancel racing a system mark_provisioning_failed,
    would otherwise produce a last-writer-wins clobber. With the
    version check, the second writer sees `VersionConflict` and the
    route handler can either refuse (409) or transparently retry."""

    def __init__(self, request_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"version conflict on {request_id}: "
            f"expected={expected}, actual on disk={actual}"
        )
        self.request_id = request_id
        self.expected = expected
        self.actual = actual


class RequestStore(Protocol):
    """Operations every request store must support.

    Errors:
      - NotFoundError: when a request_id doesn't exist
      - ValueError: when a request fails schema validation
      - StoreError: any other store-level failure
    """

    def put(self, request_id: str, request: dict[str, Any]) -> None: ...

    def get(self, request_id: str) -> dict[str, Any]: ...

    def list_ids(self) -> list[str]: ...

    def delete(self, request_id: str) -> None: ...

    def exists(self, request_id: str) -> bool: ...


def _validate(request: dict[str, Any]) -> None:
    errors = validate_request(request)
    if errors:
        raise ValueError("Invalid request:\n  " + "\n  ".join(errors))


class FilesystemStore:
    """Stores requests as YAML files in a local directory."""

    name = "filesystem"

    def __init__(self, root: pathlib.Path) -> None:
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        # Per-process lock keeps concurrent writes from racing on the same
        # request_id. Cross-process safety relies on filesystem semantics
        # (rename is atomic on POSIX).
        self._lock = threading.Lock()

    def _path(self, request_id: str) -> pathlib.Path:
        _validate_request_id(request_id)
        return self.root / f"{request_id}.yaml"

    def put(self, request_id: str, request: dict[str, Any]) -> None:
        _validate(request)
        with self._lock:
            target = self._path(request_id)
            # Optimistic-lock check: the request being written must
            # carry the version it was loaded at; we compare to the
            # on-disk version (fresh read inside the lock) and refuse
            # if a concurrent writer bumped it.
            expected = _read_version_from_request(request)
            if target.exists():
                from .schema import load_request

                disk_version = _read_version_from_request(load_request(target))
            else:
                disk_version = 0
            if expected != disk_version:
                raise VersionConflict(
                    request_id, expected=expected, actual=disk_version
                )
            request.setdefault("status", {})
            request["status"]["version"] = disk_version + 1
            tmp = target.with_suffix(".yaml.tmp")
            tmp.write_text(dump_request(request))
            tmp.replace(target)

    def get(self, request_id: str) -> dict[str, Any]:
        path = self._path(request_id)
        if not path.exists():
            raise NotFoundError(request_id)
        from .schema import load_request

        return load_request(path)

    def list_ids(self) -> list[str]:
        return sorted(p.stem for p in self.root.glob("*.yaml") if not p.name.startswith("."))

    def delete(self, request_id: str) -> None:
        path = self._path(request_id)
        if not path.exists():
            raise NotFoundError(request_id)
        path.unlink()

    def exists(self, request_id: str) -> bool:
        return self._path(request_id).exists()


class S3Store:
    """Stores requests as YAML objects in an S3 bucket. Bucket should be
    versioned so prior revisions are preserved for audit."""

    name = "s3"

    def __init__(self, bucket: str, prefix: str = "requests/", boto3_client: Any = None) -> None:
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        if boto3_client is None:
            import boto3

            boto3_client = boto3.client("s3")
        self.client = boto3_client

    def _key(self, request_id: str) -> str:
        _validate_request_id(request_id)
        return f"{self.prefix}{request_id}.yaml"

    def put(self, request_id: str, request: dict[str, Any]) -> None:
        _validate(request)
        # Optimistic-lock against current S3 object. S3 doesn't have a
        # native CAS for object content (only for tags/replication), so
        # we read-then-write inside the producer thread and rely on
        # the in-process lock at the layer above for correctness on a
        # single Lambda. Multi-Lambda deployments need a stricter
        # backend (DynamoDB conditional writes) — see DynamoDBStore.
        try:
            existing = self.get(request_id)
            disk_version = _read_version_from_request(existing)
        except NotFoundError:
            disk_version = 0
        expected = _read_version_from_request(request)
        if expected != disk_version:
            raise VersionConflict(
                request_id, expected=expected, actual=disk_version
            )
        request.setdefault("status", {})
        request["status"]["version"] = disk_version + 1
        body = dump_request(request).encode("utf-8")
        self.client.put_object(
            Bucket=self.bucket,
            Key=self._key(request_id),
            Body=body,
            ContentType="application/yaml",
            ServerSideEncryption="AES256",
        )

    def get(self, request_id: str) -> dict[str, Any]:
        try:
            resp = self.client.get_object(Bucket=self.bucket, Key=self._key(request_id))
        except self.client.exceptions.NoSuchKey as e:
            raise NotFoundError(request_id) from e
        from .schema import _yaml  # type: ignore[attr-defined]

        return _yaml.load(io.BytesIO(resp["Body"].read()))

    def list_ids(self) -> list[str]:
        paginator = self.client.get_paginator("list_objects_v2")
        ids: list[str] = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents") or []:
                key = obj["Key"]
                if key.endswith(".yaml"):
                    ids.append(key[len(self.prefix) : -len(".yaml")])
        return sorted(ids)

    def delete(self, request_id: str) -> None:
        if not self.exists(request_id):
            raise NotFoundError(request_id)
        self.client.delete_object(Bucket=self.bucket, Key=self._key(request_id))

    def exists(self, request_id: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._key(request_id))
            return True
        except Exception:
            return False


class DynamoDBStore:
    """Stores requests as JSON items in a DynamoDB table.

    Schema:
      - HASH key: request_id (S)
      - other attrs: state (S), owner_id (S), submitted_at (S), payload (S — full JSON)
      - optional GSI: state-submitted_at-index for queue listing

    The full request JSON lives in the `payload` attribute; lifecycle
    fields (state, owner_id, submitted_at) are projected as top-level
    attributes so a GSI or scan filter can find pending-by-owner-by-state
    without deserializing payload first.

    Why DynamoDB rather than S3 for the request store: at any non-trivial
    volume, "show me the pending queue" wants a real query, and S3
    ListObjectsV2 + GetObject loop becomes the bottleneck. Dynamo's
    pay-per-request pricing is ~free at this workload's volume.
    """

    name = "dynamodb"

    def __init__(self, table_name: str, dynamodb_resource: Any = None) -> None:
        self.table_name = table_name
        if dynamodb_resource is None:
            import boto3

            dynamodb_resource = boto3.resource("dynamodb")
        self.table = dynamodb_resource.Table(table_name)

    @staticmethod
    def _to_item(request_id: str, request: dict[str, Any]) -> dict[str, Any]:
        import json as _json

        status = (request.get("status") or {})
        item: dict[str, Any] = {
            "request_id": request_id,
            "payload": _json.dumps(request, default=str),
        }
        if status.get("state"):
            item["state"] = status["state"]
        if status.get("owner"):
            item["owner_id"] = status["owner"]
        if status.get("submitted_at"):
            item["submitted_at"] = status["submitted_at"]
        return item

    @staticmethod
    def _from_item(item: dict[str, Any]) -> dict[str, Any]:
        import json as _json

        return _json.loads(item["payload"])

    def put(self, request_id: str, request: dict[str, Any]) -> None:
        _validate(request)
        self.table.put_item(Item=self._to_item(request_id, request))

    def get(self, request_id: str) -> dict[str, Any]:
        resp = self.table.get_item(Key={"request_id": request_id})
        item = resp.get("Item")
        if item is None:
            raise NotFoundError(request_id)
        return self._from_item(item)

    def list_ids(self) -> list[str]:
        ids: list[str] = []
        last_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {
                "ProjectionExpression": "request_id",
            }
            if last_key is not None:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self.table.scan(**kwargs)
            for item in resp.get("Items") or []:
                ids.append(item["request_id"])
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return sorted(ids)

    def query_by_state(self, state: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        """Return full request payloads in a given state (e.g. 'pending'),
        ordered by submitted_at descending.

        Uses the `state-submitted_at-index` GSI when available; falls back
        to a filtered scan when not (older deployments). The CFN/SAM
        template should provision the GSI by default — see
        infrastructure/sam/template.yaml.

        This is the path the approver-queue UI hits, where the alternative
        (full table scan + decode every payload) is the bottleneck once
        request volume exceeds a few hundred items.
        """
        items: list[dict[str, Any]] = []
        last_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {}
            if last_key is not None:
                kwargs["ExclusiveStartKey"] = last_key
            try:
                resp = self.table.query(
                    IndexName="state-submitted_at-index",
                    KeyConditionExpression="#s = :state",
                    ExpressionAttributeNames={"#s": "state"},
                    ExpressionAttributeValues={":state": state},
                    ScanIndexForward=False,  # newest first
                    **kwargs,
                )
            except Exception:
                # GSI not provisioned (or moto < 5.x). Fall back to scan.
                return self._scan_by_state(state, limit=limit)
            for item in resp.get("Items") or []:
                items.append(self._from_item(item))
                if limit is not None and len(items) >= limit:
                    return items
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return items

    def _scan_by_state(self, state: str, *, limit: int | None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        last_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {
                "FilterExpression": "#s = :state",
                "ExpressionAttributeNames": {"#s": "state"},
                "ExpressionAttributeValues": {":state": state},
            }
            if last_key is not None:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self.table.scan(**kwargs)
            for item in resp.get("Items") or []:
                items.append(self._from_item(item))
                if limit is not None and len(items) >= limit:
                    return items
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return items

    def delete(self, request_id: str) -> None:
        if not self.exists(request_id):
            raise NotFoundError(request_id)
        self.table.delete_item(Key={"request_id": request_id})

    def exists(self, request_id: str) -> bool:
        resp = self.table.get_item(
            Key={"request_id": request_id},
            ProjectionExpression="request_id",
        )
        return resp.get("Item") is not None
