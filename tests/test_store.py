from __future__ import annotations

import pathlib
from typing import Any

import pytest

from iam_jit.store import FilesystemStore, NotFoundError


def _valid_request(rid: str = "abc-123") -> dict[str, Any]:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": rid,
            "requester": {"name": "Alice", "email": "alice@example.com"},
        },
        "spec": {
            "description": "ten-plus-character description",
            "task_intent": {"services": ["s3"], "actions": ["read"]},
            "accounts": [{"account_id": "111111111111"}],
            "duration": {"duration_hours": 1},
        },
    }


def test_filesystem_put_get_round_trip(tmp_path: pathlib.Path) -> None:
    store = FilesystemStore(tmp_path / "requests")
    request = _valid_request("rt-1")
    store.put("rt-1", request)
    fetched = store.get("rt-1")
    assert fetched["metadata"]["id"] == "rt-1"
    assert fetched["spec"]["description"].startswith("ten-plus")


def test_filesystem_get_missing_raises_notfound(tmp_path: pathlib.Path) -> None:
    store = FilesystemStore(tmp_path)
    with pytest.raises(NotFoundError):
        store.get("nope")


def test_filesystem_list_returns_sorted_ids(tmp_path: pathlib.Path) -> None:
    store = FilesystemStore(tmp_path)
    store.put("zzz", _valid_request("zzz"))
    store.put("aaa", _valid_request("aaa"))
    store.put("mmm", _valid_request("mmm"))
    assert store.list_ids() == ["aaa", "mmm", "zzz"]


def test_filesystem_delete(tmp_path: pathlib.Path) -> None:
    store = FilesystemStore(tmp_path)
    store.put("delete-me", _valid_request("delete-me"))
    assert store.exists("delete-me")
    store.delete("delete-me")
    assert not store.exists("delete-me")


def test_filesystem_put_invalid_request_raises(tmp_path: pathlib.Path) -> None:
    store = FilesystemStore(tmp_path)
    bad = _valid_request()
    bad["spec"]["accounts"] = [{"account_id": "not-numeric"}]
    with pytest.raises(ValueError):
        store.put("bad", bad)


def test_filesystem_rejects_path_traversal(tmp_path: pathlib.Path) -> None:
    store = FilesystemStore(tmp_path)
    with pytest.raises(ValueError):
        store.put("../escape", _valid_request())
    with pytest.raises(ValueError):
        store.get(".hidden")
