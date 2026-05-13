"""F33: optimistic-lock at the request store.

Proves the version field on `status` increments on every put, refuses
writes when stale, and round-trips for the common read-modify-write
pattern.
"""

from __future__ import annotations

import pathlib

import pytest

from iam_jit.store import (
    FilesystemStore,
    NotFoundError,
    VersionConflict,
    _read_version_from_request,
)


def _request(rid: str = "rq-lock-test") -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"id": rid, "requester": {"name": "Dev", "email": "dev@example.com"}},
        "spec": {
            "description": "optimistic-lock fixture request body",
            "access_type": "read-only",
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 24},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::ex/*"],
                    }
                ],
            },
        },
        "status": {"state": "pending", "owner": "email:dev@example.com"},
    }


def test_first_put_initializes_version_to_1(tmp_path: pathlib.Path) -> None:
    store = FilesystemStore(tmp_path)
    req = _request()
    store.put("rq-lock-test", req)
    loaded = store.get("rq-lock-test")
    assert _read_version_from_request(loaded) == 1


def test_subsequent_put_increments_version(tmp_path: pathlib.Path) -> None:
    store = FilesystemStore(tmp_path)
    store.put("rq-lock-test", _request())

    loaded = store.get("rq-lock-test")
    loaded["status"]["state"] = "needs_changes"
    store.put("rq-lock-test", loaded)

    loaded2 = store.get("rq-lock-test")
    assert _read_version_from_request(loaded2) == 2
    assert loaded2["status"]["state"] == "needs_changes"


def test_concurrent_writes_second_writer_gets_version_conflict(
    tmp_path: pathlib.Path,
) -> None:
    """Two callers each get() the same request, both modify, both
    put(). The first put bumps the version; the second put sees the
    bumped version and refuses with VersionConflict."""
    store = FilesystemStore(tmp_path)
    store.put("rq-lock-test", _request())

    # Both readers fetch independently — they hold the same version.
    r_a = store.get("rq-lock-test")
    r_b = store.get("rq-lock-test")

    # Writer A goes first, succeeds.
    r_a["status"]["state"] = "needs_changes"
    store.put("rq-lock-test", r_a)

    # Writer B's view is stale. Refused.
    r_b["status"]["state"] = "cancelled"
    with pytest.raises(VersionConflict) as excinfo:
        store.put("rq-lock-test", r_b)
    assert excinfo.value.expected == 1
    assert excinfo.value.actual == 2


def test_writer_b_re_reads_then_succeeds(tmp_path: pathlib.Path) -> None:
    """Standard remediation pattern: on conflict, re-fetch and retry."""
    store = FilesystemStore(tmp_path)
    store.put("rq-lock-test", _request())
    r_a = store.get("rq-lock-test")
    r_b = store.get("rq-lock-test")
    r_a["status"]["state"] = "needs_changes"
    store.put("rq-lock-test", r_a)
    with pytest.raises(VersionConflict):
        store.put("rq-lock-test", r_b)
    # Re-read and apply our intended change on top of the latest state.
    r_b_fresh = store.get("rq-lock-test")
    r_b_fresh["status"]["state"] = "cancelled"
    store.put("rq-lock-test", r_b_fresh)

    final = store.get("rq-lock-test")
    assert final["status"]["state"] == "cancelled"
    assert _read_version_from_request(final) == 3


def test_legacy_request_without_version_treated_as_zero(
    tmp_path: pathlib.Path,
) -> None:
    """A request that already exists in the store without a version
    field (older deployments) reads as version=0; a writer carrying
    version=0 succeeds and the on-disk version becomes 1. This keeps
    the upgrade non-breaking."""
    store = FilesystemStore(tmp_path)
    req = _request()
    # First put initializes version=1 normally.
    store.put("rq-lock-test", req)

    # Simulate a legacy file by stripping the version after first write
    # and re-saving via a non-checking write path. Use the underlying
    # path directly.
    from iam_jit.schema import dump_request, load_request

    raw = load_request(tmp_path / "rq-lock-test.yaml")
    raw.get("status", {}).pop("version", None)
    (tmp_path / "rq-lock-test.yaml").write_text(dump_request(raw))

    # Subsequent legitimate read-modify-write picks up version=0,
    # writes version=1, and works.
    fresh = store.get("rq-lock-test")
    assert _read_version_from_request(fresh) == 0
    fresh["status"]["state"] = "needs_changes"
    store.put("rq-lock-test", fresh)
    after = store.get("rq-lock-test")
    assert _read_version_from_request(after) == 1


def test_version_conflict_carries_expected_and_actual(
    tmp_path: pathlib.Path,
) -> None:
    store = FilesystemStore(tmp_path)
    store.put("rq-lock-test", _request())
    r_a = store.get("rq-lock-test")
    r_b = store.get("rq-lock-test")
    store.put("rq-lock-test", r_a)
    try:
        store.put("rq-lock-test", r_b)
    except VersionConflict as e:
        assert e.request_id == "rq-lock-test"
        assert e.expected == 1
        assert e.actual == 2
        assert "rq-lock-test" in str(e)
    else:
        pytest.fail("expected VersionConflict")
