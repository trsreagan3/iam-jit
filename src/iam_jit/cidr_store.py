"""Runtime-mutable CIDR allowlist.

The SAM `AllowedSourceCidrs` parameter is the deploy-time floor. This
store is the runtime overlay: admins can add / remove CIDRs through
the UI or API without redeploying, and on a fresh deploy the
bootstrap admin's first-sign-in IP gets auto-seeded so they're not
locked out.

Resolution order at request time (see `network_acl.evaluate`):

  1. If the runtime store has any entries, those are the allowlist.
  2. Else fall back to the env var (`IAM_JIT_ALLOWED_SOURCE_CIDRS`).
  3. Else no enforcement (default-open).

Backends: in-memory + filesystem (dev) + DynamoDB (production). The
production-prod path uses a single config-style item in the existing
users table, keyed `__network_acl__`, to avoid creating a new table
for a few rows.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import logging
import os
import pathlib
import threading
import time
from typing import Any, Protocol


logger = logging.getLogger("iam_jit.cidr_store")


@dataclasses.dataclass(frozen=True)
class CIDREntry:
    cidr: str
    """Normalized via ipaddress.ip_network — e.g. '203.0.113.0/24'
    or '203.0.113.5/32'."""
    note: str
    """Operator-supplied label so future-them remembers why this is
    here. e.g. 'corp VPN egress', 'office WAN', 'GH Actions'."""
    added_by: str
    added_at: int
    """Epoch seconds for tooling — not for security; trust the audit
    log for security-relevant timestamps."""


def normalize_cidr(raw: str) -> str | None:
    """Accept either a bare IP (auto-promoted to /32 or /128) or a
    CIDR. Returns the canonical text form, or None if not valid."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return None
        net = ipaddress.ip_network(
            f"{text}/{32 if addr.version == 4 else 128}",
            strict=False,
        )
    return str(net)


class CIDRStore(Protocol):
    def list(self) -> list[CIDREntry]: ...

    def add(self, entry: CIDREntry) -> None: ...

    def remove(self, cidr: str) -> bool: ...
    """True if removed, False if not present."""

    def clear(self) -> None: ...


class InMemoryCIDRStore:
    name = "memory"

    def __init__(self) -> None:
        self._entries: dict[str, CIDREntry] = {}
        self._lock = threading.Lock()

    def list(self) -> list[CIDREntry]:
        with self._lock:
            return sorted(self._entries.values(), key=lambda e: e.added_at)

    def add(self, entry: CIDREntry) -> None:
        norm = normalize_cidr(entry.cidr)
        if norm is None:
            raise ValueError(f"invalid CIDR: {entry.cidr!r}")
        with self._lock:
            self._entries[norm] = dataclasses.replace(entry, cidr=norm)

    def remove(self, cidr: str) -> bool:
        norm = normalize_cidr(cidr)
        if norm is None:
            return False
        with self._lock:
            return self._entries.pop(norm, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


class FilesystemCIDRStore:
    """JSON file at `<state_dir>/network_cidrs.json`. Used for
    `iam-jit serve` dev and as the local-mode fallback."""

    name = "filesystem"

    def __init__(self, root: pathlib.Path | str) -> None:
        self._root = pathlib.Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._path = self._root / "network_cidrs.json"
        self._lock = threading.Lock()

    def _load(self) -> list[CIDREntry]:
        if not self._path.exists():
            return []
        try:
            data = json.loads(self._path.read_text())
        except Exception:
            return []
        out: list[CIDREntry] = []
        for item in data if isinstance(data, list) else []:
            try:
                out.append(
                    CIDREntry(
                        cidr=item["cidr"],
                        note=item.get("note", ""),
                        added_by=item.get("added_by", "unknown"),
                        added_at=int(item.get("added_at", 0)),
                    )
                )
            except Exception:
                continue
        return out

    def _save(self, entries: list[CIDREntry]) -> None:
        tmp = self._path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps([dataclasses.asdict(e) for e in entries]))
        tmp.replace(self._path)

    def list(self) -> list[CIDREntry]:
        with self._lock:
            return sorted(self._load(), key=lambda e: e.added_at)

    def add(self, entry: CIDREntry) -> None:
        norm = normalize_cidr(entry.cidr)
        if norm is None:
            raise ValueError(f"invalid CIDR: {entry.cidr!r}")
        with self._lock:
            entries = self._load()
            # Replace any existing entry with the same CIDR.
            entries = [e for e in entries if e.cidr != norm]
            entries.append(dataclasses.replace(entry, cidr=norm))
            self._save(entries)

    def remove(self, cidr: str) -> bool:
        norm = normalize_cidr(cidr)
        if norm is None:
            return False
        with self._lock:
            entries = self._load()
            before = len(entries)
            entries = [e for e in entries if e.cidr != norm]
            if len(entries) == before:
                return False
            self._save(entries)
            return True

    def clear(self) -> None:
        with self._lock:
            self._save([])


class DynamoDBCIDRStore:
    """DynamoDB-backed runtime CIDR store.

    The runtime CIDR allowlist used to live only in Lambda memory,
    which meant every cold-start reset it to empty — admin-added
    entries vanished on the next Lambda replacement. This backend
    persists each entry as a row in `iam-jit-cidrs`, keyed by the
    canonical normalized CIDR string. Reads use a single Scan
    (small table — at most a few dozen rows in practice), so cold-
    start latency is ~50ms regardless of entry count.

    Schema: `cidr` (S, partition key) + standard attribute fields.
    """

    name = "dynamodb"

    def __init__(self, table_name: str, client: Any = None) -> None:
        import boto3
        self._table_name = table_name
        self._client = client or boto3.client("dynamodb")
        self._lock = threading.Lock()

    def _row_to_entry(self, row: dict[str, Any]) -> CIDREntry:
        return CIDREntry(
            cidr=row["cidr"]["S"],
            note=row.get("note", {}).get("S", ""),
            added_by=row.get("added_by", {}).get("S", "unknown"),
            added_at=int(row.get("added_at", {}).get("N", 0)),
        )

    def list(self) -> list[CIDREntry]:
        with self._lock:
            paginator = self._client.get_paginator("scan")
            entries: list[CIDREntry] = []
            for page in paginator.paginate(TableName=self._table_name):
                for row in page.get("Items", []):
                    try:
                        entries.append(self._row_to_entry(row))
                    except Exception:
                        continue
            return sorted(entries, key=lambda e: e.added_at)

    def add(self, entry: CIDREntry) -> None:
        norm = normalize_cidr(entry.cidr)
        if norm is None:
            raise ValueError(f"invalid CIDR: {entry.cidr!r}")
        with self._lock:
            self._client.put_item(
                TableName=self._table_name,
                Item={
                    "cidr": {"S": norm},
                    "note": {"S": entry.note or ""},
                    "added_by": {"S": entry.added_by or "unknown"},
                    "added_at": {"N": str(int(entry.added_at))},
                },
            )

    def remove(self, cidr: str) -> bool:
        norm = normalize_cidr(cidr)
        if norm is None:
            return False
        with self._lock:
            resp = self._client.delete_item(
                TableName=self._table_name,
                Key={"cidr": {"S": norm}},
                ReturnValues="ALL_OLD",
            )
            return "Attributes" in resp

    def clear(self) -> None:
        # Used by tests; we issue per-row deletes. Production callers
        # should rarely use this — admin UI removes one at a time.
        with self._lock:
            for entry in self.list():
                self._client.delete_item(
                    TableName=self._table_name,
                    Key={"cidr": {"S": entry.cidr}},
                )


_GLOBAL: CIDRStore | None = None


def get_default_store() -> CIDRStore:
    """Pick the CIDR-store backend based on env config.

    Priority:
      1. `IAM_JIT_CIDRS_TABLE` set → DynamoDB-backed. Required for
         production deploys so the allowlist survives Lambda cold-
         starts and stack updates.
      2. `IAM_JIT_CIDR_STATE_DIR` set → filesystem JSON. Used by
         `iam-jit serve` dev mode.
      3. Otherwise → in-memory. Tests + dev shell only.
    """
    global _GLOBAL
    if _GLOBAL is None:
        ddb_table = os.environ.get("IAM_JIT_CIDRS_TABLE")
        local = os.environ.get("IAM_JIT_CIDR_STATE_DIR")
        if ddb_table:
            _GLOBAL = DynamoDBCIDRStore(ddb_table)
        elif local:
            _GLOBAL = FilesystemCIDRStore(local)
        else:
            _GLOBAL = InMemoryCIDRStore()
    return _GLOBAL


def reset_default_store_for_tests() -> None:
    global _GLOBAL
    _GLOBAL = None


def auto_seed_for_bootstrap(
    *,
    source_ip: str,
    user_id: str,
    now_epoch: int | None = None,
) -> CIDREntry | None:
    """Called by the magic-callback the first time a bootstrap admin
    signs in. Adds `<their_ip>/32` to the runtime allowlist IF the
    allowlist is currently empty AND the env-var allowlist is also
    empty (i.e., the deployment is wide-open and the admin's first
    sign-in is the moment to lock it down).

    Returns the entry that was added, or None if no seeding happened.
    """
    if not source_ip:
        return None
    norm = normalize_cidr(source_ip)
    if norm is None:
        return None
    store = get_default_store()
    if store.list():
        return None  # already locked down
    if os.environ.get("IAM_JIT_ALLOWED_SOURCE_CIDRS", "").strip():
        return None  # env var has it; runtime overlay isn't needed yet
    entry = CIDREntry(
        cidr=norm,
        note=f"auto-seeded on first bootstrap-admin sign-in",
        added_by=user_id,
        added_at=int(now_epoch if now_epoch is not None else time.time()),
    )
    try:
        store.add(entry)
        logger.warning(
            "auto-seeded CIDR allowlist with %s based on bootstrap-admin "
            "sign-in by %s — add more ranges via /admin/network or "
            "POST /api/v1/admin/network/cidrs",
            norm,
            user_id,
        )
        return entry
    except Exception:
        logger.exception("auto-seed CIDR failed")
        return None
