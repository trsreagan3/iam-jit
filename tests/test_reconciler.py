"""Tests for the orphan-request reconciler (#698 LOW-2).

Validates that `reconcile_once`:
  - Walks every active request.
  - Probes iam:GetRole against the provisioned role.
  - Transitions to `revoked` ONLY when NoSuchEntity is raised.
  - Skips non-active requests / unregistered accounts / partial provisioning.
  - Never raises on per-request failures.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest

from iam_jit import reconciler


# ---------------------------------------------------------------------------
# Test scaffolding — minimal in-memory stubs for store / accounts / iam.
# ---------------------------------------------------------------------------


class _FakeStore:
    """Minimal RequestStore-shaped stub: holds dicts in memory."""

    def __init__(self) -> None:
        self._items: dict[str, dict] = {}

    def list_ids(self) -> list[str]:
        return list(self._items)

    def get(self, rid: str) -> dict:
        return self._items[rid]

    def put(self, rid: str, req: dict) -> None:
        self._items[rid] = req


class _FakeAccountsStore:
    """Minimal AccountStore stub."""

    def __init__(self) -> None:
        self._accounts: dict[str, Any] = {}

    def register(self, account_id: str, account_obj: Any) -> None:
        self._accounts[account_id] = account_obj

    def get(self, account_id: str) -> Any:
        if account_id not in self._accounts:
            raise KeyError(account_id)
        return self._accounts[account_id]


def _active_request(
    rid: str = "req-test",
    role_name: str = "iam-jit-grant-req-test",
    role_arn: str = "arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-req-test",
    account_id: str = "060392206767",
) -> dict:
    """Build a minimal active request dict for the reconciler to walk."""
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"id": rid, "requester": {"email": "d@x.com"}},
        "spec": {
            "accounts": [{"account_id": account_id}],
            "duration": {"duration_hours": 1},
            "policy": {"Version": "2012-10-17", "Statement": []},
        },
        "status": {
            "state": "active",
            "history": [
                {"action": "submit", "by": "user:d"},
                {"action": "approve", "by": "user:a"},
                {"action": "active", "by": "system"},
            ],
            "provisioned": {
                "role_arn": role_arn,
                "role_name": role_name,
                "account_id": account_id,
            },
        },
    }


def _no_such_entity_error() -> Exception:
    """Build the kind of exception boto3 raises for iam:GetRole when the
    role doesn't exist. The reconciler string-matches on 'NoSuchEntity'
    for portability across botocore versions."""
    return Exception(
        "An error occurred (NoSuchEntity) when calling the GetRole "
        "operation: Role iam-jit-grant-req-test cannot be found."
    )


# ---------------------------------------------------------------------------
# reconcile_once — core behavior
# ---------------------------------------------------------------------------


def test_reconcile_transitions_active_to_revoked_when_role_missing() -> None:
    """The headline behavior: active request whose IAM role no longer
    exists transitions to revoked with the canonical reason string."""
    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    store = _FakeStore()
    accounts = _FakeAccountsStore()
    store.put("req-1", _active_request("req-1"))
    accounts.register("060392206767", mock.MagicMock(
        provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
        provisioner_external_id="ext-id",
    ))

    iam = mock.MagicMock()
    iam.get_role.side_effect = _no_such_entity_error()

    with mock.patch.object(
        _provision, "_assume_provisioner_role",
        return_value={"aws_access_key_id": "k", "aws_secret_access_key": "s",
                     "aws_session_token": "t"},
    ):
        stats = reconciler.reconcile_once(
            store=store,
            accounts_store=accounts,
            provision_mod=_provision,
            lifecycle=_lifecycle,
            sts_client=mock.MagicMock(),
            iam_client_factory=lambda creds: iam,
        )

    assert stats["checked"] == 1
    assert stats["revoked"] == 1
    assert stats["errors"] == 0

    req = store.get("req-1")
    assert req["status"]["state"] == "revoked"
    rev = req["status"]["revocation"]
    assert "RECONCILED" in rev["reason"]
    assert "IAM role no longer exists" in rev["reason"]
    assert rev["revoked_by"] == "system:reconciler"
    assert rev["role_existed"] is False


def test_reconcile_leaves_existing_role_alone() -> None:
    """When iam:GetRole succeeds (role exists), the request stays active."""
    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    store = _FakeStore()
    accounts = _FakeAccountsStore()
    store.put("req-ok", _active_request("req-ok"))
    accounts.register("060392206767", mock.MagicMock(
        provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
        provisioner_external_id="ext-id",
    ))

    iam = mock.MagicMock()
    iam.get_role.return_value = {"Role": {"RoleName": "iam-jit-grant-req-ok"}}

    with mock.patch.object(
        _provision, "_assume_provisioner_role",
        return_value={"aws_access_key_id": "k", "aws_secret_access_key": "s",
                     "aws_session_token": "t"},
    ):
        stats = reconciler.reconcile_once(
            store=store,
            accounts_store=accounts,
            provision_mod=_provision,
            lifecycle=_lifecycle,
            sts_client=mock.MagicMock(),
            iam_client_factory=lambda creds: iam,
        )

    assert stats["checked"] == 1
    assert stats["revoked"] == 0
    assert store.get("req-ok")["status"]["state"] == "active"


def test_reconcile_skips_non_active_requests() -> None:
    """Pending / cancelled / revoked / expired requests are not probed."""
    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    store = _FakeStore()
    accounts = _FakeAccountsStore()

    pending = _active_request("req-pending")
    pending["status"]["state"] = "pending"
    pending["status"].pop("provisioned", None)
    store.put("req-pending", pending)

    cancelled = _active_request("req-cancelled")
    cancelled["status"]["state"] = "cancelled"
    store.put("req-cancelled", cancelled)

    iam = mock.MagicMock()
    iam.get_role.side_effect = _no_such_entity_error()

    stats = reconciler.reconcile_once(
        store=store,
        accounts_store=accounts,
        provision_mod=_provision,
        lifecycle=_lifecycle,
        sts_client=mock.MagicMock(),
        iam_client_factory=lambda creds: iam,
    )
    # No active requests → nothing checked, nothing revoked.
    assert stats["checked"] == 0
    assert stats["revoked"] == 0
    # iam_client_factory never invoked because we skipped before assume.
    iam.get_role.assert_not_called()


def test_reconcile_skips_active_request_without_provisioned_block() -> None:
    """Defensive: an `active` request that somehow lacks the
    provisioned block (pre-#698 data, partial state) is skipped — we
    will NOT mark-revoked without knowing the role to verify."""
    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    store = _FakeStore()
    accounts = _FakeAccountsStore()
    req = _active_request("req-partial")
    req["status"]["provisioned"] = {}  # missing role_arn/role_name/account
    store.put("req-partial", req)

    stats = reconciler.reconcile_once(
        store=store,
        accounts_store=accounts,
        provision_mod=_provision,
        lifecycle=_lifecycle,
    )
    assert stats["checked"] == 1
    assert stats["skipped"] == 1
    assert stats["revoked"] == 0
    assert store.get("req-partial")["status"]["state"] == "active"


def test_reconcile_skips_when_account_deregistered() -> None:
    """If the destination account was deregistered after provisioning,
    we can't assume → can't probe. Skip, don't revoke."""
    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    store = _FakeStore()
    accounts = _FakeAccountsStore()
    store.put("req-deact", _active_request("req-deact"))
    # NO accounts.register() — deregistered

    stats = reconciler.reconcile_once(
        store=store,
        accounts_store=accounts,
        provision_mod=_provision,
        lifecycle=_lifecycle,
    )
    assert stats["checked"] == 1
    assert stats["skipped"] == 1
    assert stats["revoked"] == 0


def test_reconcile_per_request_failure_does_not_break_others() -> None:
    """A failure on one request must not skip the rest of the pass."""
    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    store = _FakeStore()
    accounts = _FakeAccountsStore()
    store.put("req-1-throws", _active_request("req-1-throws"))
    store.put("req-2-ok", _active_request("req-2-ok"))
    accounts.register("060392206767", mock.MagicMock(
        provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
        provisioner_external_id="ext-id",
    ))

    iam = mock.MagicMock()
    iam.get_role.side_effect = _no_such_entity_error()

    # Make assume_role raise for req-1 but succeed for req-2.
    call_count = {"n": 0}

    def _assume(*args, **kwargs):
        call_count["n"] += 1
        if "req-1-throws" in (kwargs.get("session_name") or ""):
            raise Exception("simulated assume failure")
        return {
            "aws_access_key_id": "k", "aws_secret_access_key": "s",
            "aws_session_token": "t",
        }

    with mock.patch.object(
        _provision, "_assume_provisioner_role", side_effect=_assume,
    ):
        stats = reconciler.reconcile_once(
            store=store,
            accounts_store=accounts,
            provision_mod=_provision,
            lifecycle=_lifecycle,
            sts_client=mock.MagicMock(),
            iam_client_factory=lambda creds: iam,
        )

    # Both requests were checked; one revoked, one errored.
    assert stats["checked"] == 2
    assert stats["revoked"] == 1
    assert stats["errors"] == 1
    # req-2 transitioned, req-1 didn't.
    assert store.get("req-1-throws")["status"]["state"] == "active"
    assert store.get("req-2-ok")["status"]["state"] == "revoked"


def test_reconcile_non_nosuchentity_iam_error_does_not_revoke() -> None:
    """An IAM error OTHER than NoSuchEntity (throttling, access denied,
    network) must NOT trigger a false revoke. The role might still be
    there; we just can't see it. Skip + retry next pass."""
    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    store = _FakeStore()
    accounts = _FakeAccountsStore()
    store.put("req-throttle", _active_request("req-throttle"))
    accounts.register("060392206767", mock.MagicMock(
        provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
        provisioner_external_id="ext-id",
    ))

    iam = mock.MagicMock()
    iam.get_role.side_effect = Exception("Throttling: Rate exceeded")

    with mock.patch.object(
        _provision, "_assume_provisioner_role",
        return_value={"aws_access_key_id": "k", "aws_secret_access_key": "s",
                     "aws_session_token": "t"},
    ):
        stats = reconciler.reconcile_once(
            store=store,
            accounts_store=accounts,
            provision_mod=_provision,
            lifecycle=_lifecycle,
            sts_client=mock.MagicMock(),
            iam_client_factory=lambda creds: iam,
        )

    assert stats["checked"] == 1
    assert stats["revoked"] == 0
    assert stats["errors"] == 1
    # Request stays active — throttling is transient.
    assert store.get("req-throttle")["status"]["state"] == "active"


def test_reconcile_empty_store_returns_zero_stats() -> None:
    """Defensive: no requests at all → clean zero stats."""
    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    stats = reconciler.reconcile_once(
        store=_FakeStore(),
        accounts_store=_FakeAccountsStore(),
        provision_mod=_provision,
        lifecycle=_lifecycle,
    )
    assert stats == {"checked": 0, "revoked": 0, "skipped": 0, "errors": 0}


# ---------------------------------------------------------------------------
# reconcile_loop — interval honoring + disabled behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reconcile_loop_disabled_when_interval_zero() -> None:
    """interval=0 returns immediately without invoking reconcile_once."""
    import asyncio

    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    called = {"n": 0}

    def _fake_once(**kwargs):
        called["n"] += 1
        return {"checked": 0, "revoked": 0, "skipped": 0, "errors": 0}

    with mock.patch.object(reconciler, "reconcile_once", _fake_once):
        await asyncio.wait_for(
            reconciler.reconcile_loop(
                store=_FakeStore(),
                accounts_store=_FakeAccountsStore(),
                provision_mod=_provision,
                lifecycle=_lifecycle,
                interval_seconds=0,
            ),
            timeout=1.0,
        )
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_reconcile_loop_invokes_reconcile_once_at_least_once() -> None:
    """Loop runs at least one pass before honoring the stop event."""
    import asyncio

    from iam_jit import lifecycle as _lifecycle
    from iam_jit import provision as _provision

    called = {"n": 0}

    def _fake_once(**kwargs):
        called["n"] += 1
        return {"checked": 0, "revoked": 0, "skipped": 0, "errors": 0}

    stop = asyncio.Event()

    with mock.patch.object(reconciler, "reconcile_once", _fake_once):
        task = asyncio.create_task(
            reconciler.reconcile_loop(
                store=_FakeStore(),
                accounts_store=_FakeAccountsStore(),
                provision_mod=_provision,
                lifecycle=_lifecycle,
                interval_seconds=60,
                stop_event=stop,
            )
        )
        # Give the first pass a moment to run.
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, timeout=1.0)

    assert called["n"] >= 1
