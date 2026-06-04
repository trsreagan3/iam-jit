from __future__ import annotations

import pathlib

import pytest

from iam_jit.users_store import (
    FileUserStore,
    StoreReadOnly,
    User,
    UserNotFound,
)


_LOCAL_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:alice@example.com
    display_name: Alice
    roles: [admin]
  - id: email:bob@example.com
    display_name: Bob
    roles: [approver]
  - id: email:charlie@example.com
    display_name: Charlie
    roles: [requester]
  - id: email:dave@example.com
    display_name: Dave
    roles: [requester]
    enabled: false
"""


def test_file_store_loads_users(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "users.yaml"
    p.write_text(_LOCAL_USERS_YAML)
    store = FileUserStore(str(p))
    alice = store.get("email:alice@example.com")
    assert alice.is_admin
    assert alice.is_approver
    assert alice.is_requester
    bob = store.get("email:bob@example.com")
    assert bob.is_approver
    assert not bob.is_admin
    charlie = store.get("email:charlie@example.com")
    assert charlie.is_requester
    assert not charlie.is_approver


def test_file_store_excludes_disabled_by_default(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "users.yaml"
    p.write_text(_LOCAL_USERS_YAML)
    store = FileUserStore(str(p))
    enabled_ids = {u.id for u in store.list()}
    assert "email:dave@example.com" not in enabled_ids
    all_ids = {u.id for u in store.list(include_disabled=True)}
    assert "email:dave@example.com" in all_ids


def test_file_store_get_missing_raises(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "users.yaml"
    p.write_text(_LOCAL_USERS_YAML)
    store = FileUserStore(str(p))
    with pytest.raises(UserNotFound):
        store.get("email:nobody@example.com")


def test_file_store_is_read_only(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "users.yaml"
    p.write_text(_LOCAL_USERS_YAML)
    store = FileUserStore(str(p))
    with pytest.raises(StoreReadOnly):
        store.put(User(id="email:eve@example.com", roles=("requester",)))
    with pytest.raises(StoreReadOnly):
        store.delete("email:bob@example.com")


def test_file_store_handles_missing_file_gracefully(tmp_path: pathlib.Path) -> None:
    store = FileUserStore(str(tmp_path / "does-not-exist.yaml"))
    assert store.list() == []
    with pytest.raises(UserNotFound):
        store.get("email:anyone@example.com")


def test_file_store_invalid_yaml_keeps_last_good(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "users.yaml"
    p.write_text(_LOCAL_USERS_YAML)
    store = FileUserStore(str(p), cache_ttl_seconds=0)
    initial = store.get("email:alice@example.com")
    assert initial.is_admin
    # Corrupt the file
    p.write_text("schema_version: 999\nusers: this is not a list\n")
    # Should NOT crash; should keep last-good cache.
    again = store.get("email:alice@example.com")
    assert again.is_admin


def test_file_store_rejects_wrong_auth_mode(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "users.yaml"
    p.write_text(_LOCAL_USERS_YAML)
    store = FileUserStore(str(p), expected_auth_mode="aws_iam")
    # The local-mode file shouldn't load when the deployment is aws_iam.
    assert store.list() == []


def test_user_role_helpers() -> None:
    requester = User(id="email:r@example.com", roles=("requester",))
    approver = User(id="email:a@example.com", roles=("approver",))
    admin = User(id="email:adm@example.com", roles=("admin",))
    assert requester.is_requester and not requester.is_approver and not requester.is_admin
    assert approver.is_requester and approver.is_approver and not approver.is_admin
    assert admin.is_requester and admin.is_approver and admin.is_admin


# --- regression: hostname/email case-insensitivity (E2E dogfood 2026-06-05) ---
# A fresh `serve --local` on a mixed-case-hostname mac seeds users.yaml with
# email:user@Host.local but mints tokens for email:user@host.local (lowercased),
# which used to 403 every grant request. user-ids for emails must match
# case-insensitively; iam: ARNs must NOT be altered.

_MIXED_CASE_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:reagan@reagans-MacBook-Air.local
    display_name: Local admin
    roles: [admin, approver, requester]
  - id: iam:arn:aws:iam::590519617224:role/Some-MixedCase-Role
    display_name: A role principal
    roles: [requester]
"""


def test_normalize_user_id_lowercases_email_not_arn() -> None:
    from iam_jit.users_store import normalize_user_id
    assert normalize_user_id("email:reagan@reagans-MacBook-Air.local") == "email:reagan@reagans-macbook-air.local"
    # ARN ids are case-sensitive — must be left untouched.
    arn = "iam:arn:aws:iam::590519617224:role/Some-MixedCase-Role"
    assert normalize_user_id(arn) == arn


def test_file_store_email_lookup_is_case_insensitive(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "users.yaml"
    p.write_text(_MIXED_CASE_YAML)
    store = FileUserStore(str(p))
    # seeded mixed-case; looked up with the lowercased token id -> must resolve.
    u = store.get("email:reagan@reagans-macbook-air.local")
    assert u.is_admin
    # original casing still resolves too.
    assert store.get("email:reagan@reagans-MacBook-Air.local").is_admin
    # ARN id preserved exactly (case-sensitive).
    assert store.get("iam:arn:aws:iam::590519617224:role/Some-MixedCase-Role").is_requester
    # a genuinely-unknown user still raises.
    with pytest.raises(UserNotFound):
        store.get("email:nobody@example.com")
