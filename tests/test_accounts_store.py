"""Accounts store backends."""

from __future__ import annotations

import pathlib

import pytest

from iam_jit.accounts_store import (
    Account,
    AccountNotFound,
    AccountStoreReadOnly,
    FileAccountStore,
    InMemoryAccountStore,
    utcnow_iso,
)


def _account(account_id: str = "123456789012", **kw) -> Account:
    base = dict(
        account_id=account_id,
        provisioner_role_arn=f"arn:aws:iam::{account_id}:role/iam-jit-provisioner",
        provisioner_external_id=f"iam-jit-{account_id}",
        provisioning_mode="classic_iam",
    )
    base.update(kw)
    return Account(**base)


def test_in_memory_put_get_list_delete() -> None:
    store = InMemoryAccountStore()
    a1 = _account("111111111111", alias="a1")
    a2 = _account("222222222222", alias="a2", enabled=False)
    store.put(a1)
    store.put(a2)
    assert store.get("111111111111").alias == "a1"
    # default: enabled only
    listed = store.list()
    assert [a.account_id for a in listed] == ["111111111111"]
    listed_all = store.list(include_disabled=True)
    assert [a.account_id for a in listed_all] == ["111111111111", "222222222222"]
    store.delete("111111111111")
    with pytest.raises(AccountNotFound):
        store.get("111111111111")


def test_in_memory_delete_missing_raises() -> None:
    store = InMemoryAccountStore()
    with pytest.raises(AccountNotFound):
        store.delete("999999999999")


def test_file_store_reads_yaml(tmp_path: pathlib.Path) -> None:
    yaml_path = tmp_path / "accounts.yaml"
    yaml_path.write_text(
        """\
apiVersion: iam-jit.dev/v1alpha1
kind: AccountList
accounts:
  - account_id: "111111111111"
    alias: alpha
    provisioner_role_arn: arn:aws:iam::111111111111:role/iam-jit-provisioner
    provisioner_external_id: iam-jit-111111111111
    provisioning_mode: classic_iam
    enabled: true
  - account_id: "222222222222"
    alias: beta
    provisioner_role_arn: arn:aws:iam::222222222222:role/iam-jit-provisioner
    provisioner_external_id: iam-jit-222222222222
    discovery_role_arn: arn:aws:iam::222222222222:role/iam-jit-discovery
    discovery_external_id: iam-jit-discovery-222222222222
    provisioning_mode: both
    enabled: true
"""
    )
    store = FileAccountStore(str(yaml_path))
    accounts = store.list()
    assert {a.account_id for a in accounts} == {"111111111111", "222222222222"}
    beta = store.get("222222222222")
    assert beta.has_discovery
    assert beta.discovery_role_arn.endswith("/iam-jit-discovery")
    assert beta.provisioning_mode == "both"


def test_file_store_is_read_only(tmp_path: pathlib.Path) -> None:
    yaml_path = tmp_path / "accounts.yaml"
    yaml_path.write_text(
        "apiVersion: iam-jit.dev/v1alpha1\nkind: AccountList\naccounts: []\n"
    )
    store = FileAccountStore(str(yaml_path))
    with pytest.raises(AccountStoreReadOnly):
        store.put(_account())
    with pytest.raises(AccountStoreReadOnly):
        store.delete("111111111111")


def test_file_store_invalid_yaml_keeps_last_good(tmp_path: pathlib.Path) -> None:
    yaml_path = tmp_path / "accounts.yaml"
    yaml_path.write_text(
        """\
apiVersion: iam-jit.dev/v1alpha1
kind: AccountList
accounts:
  - account_id: "111111111111"
    provisioner_role_arn: arn:aws:iam::111111111111:role/iam-jit-provisioner
    provisioner_external_id: iam-jit-111111111111
    provisioning_mode: classic_iam
"""
    )
    store = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
    assert len(store.list()) == 1
    yaml_path.write_text("not: a: valid: schema:::")
    # Should NOT crash and should keep last-good cache
    accounts = store.list()
    assert isinstance(accounts, list)


def test_file_store_missing_file_returns_empty(tmp_path: pathlib.Path) -> None:
    store = FileAccountStore(str(tmp_path / "does-not-exist.yaml"))
    assert store.list() == []
    with pytest.raises(AccountNotFound):
        store.get("111111111111")
