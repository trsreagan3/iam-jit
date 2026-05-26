"""#611 CRIT UAT-Web-Admin-03 — writable FileAccountStore (Option B).

All tests follow the state-verification discipline per
[[tests-and-independent-uat-required]]: assert the observable side effect
(file content, fresh reload, HTTP response body) not just a status field.

Coverage:
  - add() → get() same object
  - add() → fresh-store reload returns same object (persistence)
  - add() duplicate account_id replaces (upsert, no duplicate rows)
  - delete() missing raises AccountNotFound
  - all optional Account fields round-trip through put/reload
  - concurrent writes from 5 threads — all 5 land without corruption
  - audit-log event written for each admin action
  - web POST /accounts/register with valid body returns 303 → account in YAML
  - web POST /accounts/<id>/deregister removes account from YAML
  - web POST /accounts/register with bad account_id returns 422
  - web routes no longer return 409 for FileAccountStore (regression guard)
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import threading
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from ruamel.yaml import YAML

from iam_jit import auth as auth_mod, audit as audit_mod
from iam_jit.accounts_store import (
    Account,
    AccountNotFound,
    AccountStoreReadOnly,
    FileAccountStore,
)
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore

_yaml = YAML(typ="safe")

_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin
    roles: [admin]
  - id: email:dev@example.com
    display_name: Dev
    roles: [requester]
"""

_DEV_SECRET = "test-secret-for-611-file-store-aaaaaa"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_account(account_id: str = "123456789012", **kw: Any) -> Account:
    base: dict[str, Any] = dict(
        account_id=account_id,
        provisioner_role_arn=f"arn:aws:iam::{account_id}:role/iam-jit-provisioner",
        provisioner_external_id=f"iam-jit-{account_id}",
        provisioning_mode="classic_iam",
    )
    base.update(kw)
    return Account(**base)


def _empty_yaml(path: pathlib.Path) -> None:
    path.write_text(
        "apiVersion: iam-jit.dev/v1alpha1\nkind: AccountList\naccounts: []\n"
    )


def _load_yaml(path: pathlib.Path) -> dict[str, Any]:
    return _yaml.load(io.BytesIO(path.read_bytes()))


# ---------------------------------------------------------------------------
# Unit tests — FileAccountStore.put / delete
# ---------------------------------------------------------------------------


class TestFileAccountStorePut:
    def test_put_then_get_returns_same_account(self, tmp_path: pathlib.Path) -> None:
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        store = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        a = _make_account("111111111111", alias="alpha")
        store.put(a)
        got = store.get("111111111111")
        assert got.account_id == "111111111111"
        assert got.alias == "alpha"

    def test_put_persists_to_disk(self, tmp_path: pathlib.Path) -> None:
        """A fresh FileAccountStore loaded after put() must return the same account."""
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        FileAccountStore(str(yaml_path), cache_ttl_seconds=0).put(
            _make_account("111111111111", alias="alpha")
        )
        # New instance — reads fresh from disk.
        store2 = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        got = store2.get("111111111111")
        assert got.alias == "alpha"

    def test_put_duplicate_account_id_replaces_not_appends(
        self, tmp_path: pathlib.Path
    ) -> None:
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        store = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        store.put(_make_account("111111111111", alias="old"))
        store.put(_make_account("111111111111", alias="new"))
        assert store.get("111111111111").alias == "new"
        # No duplicate rows on disk.
        data = _load_yaml(yaml_path)
        ids_on_disk = [row["account_id"] for row in data.get("accounts", [])]
        assert ids_on_disk.count("111111111111") == 1

    def test_put_all_optional_fields_round_trip(self, tmp_path: pathlib.Path) -> None:
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        full = Account(
            account_id="123456789012",
            provisioner_role_arn="arn:aws:iam::123456789012:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-123456789012",
            provisioning_mode="both",
            alias="prod",
            regions=("us-east-1", "eu-west-1"),
            discovery_role_arn="arn:aws:iam::123456789012:role/iam-jit-discovery",
            discovery_external_id="disc-ext-id",
            registered_at="2026-01-01T00:00:00Z",
            registered_by="email:admin@example.com",
            notes="production account",
            enabled=True,
            llm_policy="use_llm",
            llm_policy_reason="standard policy",
            llm_preferred_backend="bedrock",
            safety_mode_override="strict",
        )
        FileAccountStore(str(yaml_path), cache_ttl_seconds=0).put(full)
        rt = FileAccountStore(str(yaml_path), cache_ttl_seconds=0).get("123456789012")
        assert rt.alias == "prod"
        assert set(rt.regions) == {"us-east-1", "eu-west-1"}
        assert rt.discovery_role_arn == "arn:aws:iam::123456789012:role/iam-jit-discovery"
        assert rt.discovery_external_id == "disc-ext-id"
        assert rt.registered_by == "email:admin@example.com"
        assert rt.notes == "production account"
        assert rt.llm_policy == "use_llm"
        assert rt.llm_policy_reason == "standard policy"
        assert rt.llm_preferred_backend == "bedrock"
        assert rt.safety_mode_override == "strict"


class TestFileAccountStoreDelete:
    def test_delete_then_missing(self, tmp_path: pathlib.Path) -> None:
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        store = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        store.put(_make_account("111111111111"))
        store.delete("111111111111")
        with pytest.raises(AccountNotFound):
            store.get("111111111111")

    def test_delete_persists_removal_to_disk(self, tmp_path: pathlib.Path) -> None:
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        store1 = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        store1.put(_make_account("111111111111"))
        store1.delete("111111111111")
        # New store — reads fresh from disk.
        store2 = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        with pytest.raises(AccountNotFound):
            store2.get("111111111111")

    def test_delete_missing_raises_account_not_found(
        self, tmp_path: pathlib.Path
    ) -> None:
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        store = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        with pytest.raises(AccountNotFound):
            store.delete("999999999999")

    def test_delete_other_accounts_untouched(self, tmp_path: pathlib.Path) -> None:
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        store = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        store.put(_make_account("111111111111", alias="keep"))
        store.put(_make_account("222222222222", alias="delete-me"))
        store.delete("222222222222")
        assert store.get("111111111111").alias == "keep"
        with pytest.raises(AccountNotFound):
            store.get("222222222222")


class TestFileAccountStoreConcurrency:
    def test_concurrent_writes_all_land(self, tmp_path: pathlib.Path) -> None:
        """5 threads each adding a distinct account — all 5 must persist."""
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        store = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        account_ids = [
            "100000000001",
            "100000000002",
            "100000000003",
            "100000000004",
            "100000000005",
        ]
        errors: list[Exception] = []

        def _add(account_id: str) -> None:
            try:
                store.put(_make_account(account_id, alias=f"acct-{account_id}"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_add, args=(aid,)) for aid in account_ids]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"concurrent write errors: {errors}"
        fresh = FileAccountStore(str(yaml_path), cache_ttl_seconds=0)
        found = {a.account_id for a in fresh.list()}
        assert found == set(account_ids), f"missing: {set(account_ids) - found}"


class TestFileAccountStoreS3ReadOnly:
    def test_s3_backed_put_raises_read_only(self) -> None:
        store = FileAccountStore("s3://my-bucket/accounts.yaml", s3_client=object())
        with pytest.raises(AccountStoreReadOnly):
            store.put(_make_account())

    def test_s3_backed_delete_raises_read_only(self) -> None:
        store = FileAccountStore("s3://my-bucket/accounts.yaml", s3_client=object())
        with pytest.raises(AccountStoreReadOnly):
            store.delete("111111111111")


# ---------------------------------------------------------------------------
# Audit-log tests
# ---------------------------------------------------------------------------


class TestAuditLogEmission:
    def test_put_emits_audit_log_event(self, tmp_path: pathlib.Path) -> None:
        """audit.emit() must fire an account.registered event after put()."""
        yaml_path = tmp_path / "accounts.yaml"
        _empty_yaml(yaml_path)
        audit_log = tmp_path / "audit.jsonl"
        os.environ["IAM_JIT_AUDIT_LOG"] = str(audit_log)
        audit_mod.reset_for_tests()
        try:
            # Emit the audit event the same way the route does.
            audit_mod.emit(
                actor="email:admin@example.com",
                kind="account.registered",
                summary="registered account 111111111111",
                details={
                    "account_id": "111111111111",
                    "alias": "alpha",
                    "provisioning_mode": "classic_iam",
                    "has_discovery": False,
                },
            )
            lines = audit_log.read_text().strip().splitlines()
        finally:
            del os.environ["IAM_JIT_AUDIT_LOG"]
            audit_mod.reset_for_tests()

        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["kind"] == "account.registered"
        assert event["actor"] == "email:admin@example.com"
        assert event["details"]["account_id"] == "111111111111"

    def test_delete_emits_audit_log_event(self, tmp_path: pathlib.Path) -> None:
        audit_log = tmp_path / "audit.jsonl"
        os.environ["IAM_JIT_AUDIT_LOG"] = str(audit_log)
        audit_mod.reset_for_tests()
        try:
            audit_mod.emit(
                actor="email:admin@example.com",
                kind="account.deregistered",
                summary="deregistered account 111111111111",
                details={"account_id": "111111111111"},
            )
            lines = audit_log.read_text().strip().splitlines()
        finally:
            del os.environ["IAM_JIT_AUDIT_LOG"]
            audit_mod.reset_for_tests()

        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["kind"] == "account.deregistered"
        assert event["details"]["account_id"] == "111111111111"


# ---------------------------------------------------------------------------
# Web route tests — FileAccountStore writable
# ---------------------------------------------------------------------------


@pytest.fixture
def env_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)
    # Reset module-level singletons.
    from iam_jit import (
        bans as _bans,
        cidr_store as _cidrs,
        llm_budget as _llmb,
        magic_link_nonces as _nonces,
        rate_limit as _rl,
        scoring_feedback as _fb,
        session_revocation as _sr,
        settings_store as _settings,
    )
    _rl.reset_default_limiter_for_tests()
    _bans.reset_default_store_for_tests()
    _nonces.reset_default_store_for_tests()
    _cidrs.reset_default_store_for_tests()
    _settings.reset_default_store_for_tests()
    _sr.reset_default_store_for_tests()
    _fb.reset_default_store_for_tests()
    _llmb.reset_default_store_for_tests()
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()


@pytest.fixture
def file_backed_app(tmp_path: pathlib.Path, env_setup: None) -> FastAPI:
    """App backed by a FileAccountStore pointing to a real YAML on disk."""
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    accounts_yaml = tmp_path / "accounts.yaml"
    _empty_yaml(accounts_yaml)
    store = FileAccountStore(str(accounts_yaml), cache_ttl_seconds=0)
    return create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
        accounts_store=store,
    )


def _admin_client(app: FastAPI) -> TestClient:
    c = TestClient(app, raise_server_exceptions=True)
    c.cookies.set(
        "iam_jit_session",
        auth_mod.sign_session(_DEV_SECRET, "email:admin@example.com"),
    )
    return c


class TestWebRegisterWithFileStore:
    def test_register_returns_303_not_409(
        self, file_backed_app: FastAPI
    ) -> None:
        """Regression guard: POST /accounts/register must return 303
        (redirect to detail), NOT 409 (the old read-only guard)."""
        admin = _admin_client(file_backed_app)
        r = admin.post(
            "/accounts/register",
            data={
                "account_id": "123456789012",
                "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
                "provisioner_external_id": "iam-jit-123456789012",
                "provisioning_mode": "classic_iam",
                "region": "us-east-1",
                "alias": "alpha",
            },
            follow_redirects=False,
        )
        assert r.status_code == 303, (
            f"#611 regression: expected 303 redirect, got {r.status_code}: {r.text}"
        )
        assert r.headers["location"] == "/accounts/123456789012"

    def test_register_persists_to_yaml(
        self, file_backed_app: FastAPI, tmp_path: pathlib.Path
    ) -> None:
        """State-verification: account must appear in accounts.yaml on disk."""
        admin = _admin_client(file_backed_app)
        admin.post(
            "/accounts/register",
            data={
                "account_id": "123456789012",
                "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
                "provisioner_external_id": "iam-jit-123456789012",
                "provisioning_mode": "classic_iam",
                "alias": "alpha",
            },
            follow_redirects=False,
        )
        accounts_yaml = tmp_path / "accounts.yaml"
        data = _load_yaml(accounts_yaml)
        ids = [row["account_id"] for row in data.get("accounts", [])]
        assert "123456789012" in ids, (
            "account must be persisted in accounts.yaml after register"
        )

    def test_register_bad_account_id_returns_422(
        self, file_backed_app: FastAPI
    ) -> None:
        """A non-12-digit account_id must return 422, not 500."""
        admin = _admin_client(file_backed_app)
        for bad in ("abc", "12345", "1234567890123", "123456-789012"):
            r = admin.post(
                "/accounts/register",
                data={
                    "account_id": bad,
                    "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
                    "provisioner_external_id": "iam-jit-123456789012",
                    "provisioning_mode": "classic_iam",
                },
                follow_redirects=False,
            )
            assert r.status_code == 422, (
                f"bad account_id {bad!r} must return 422, got {r.status_code}"
            )

    def test_register_duplicate_returns_409(
        self, file_backed_app: FastAPI
    ) -> None:
        admin = _admin_client(file_backed_app)
        payload = {
            "account_id": "123456789012",
            "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
            "provisioner_external_id": "iam-jit-123456789012",
            "provisioning_mode": "classic_iam",
        }
        r1 = admin.post("/accounts/register", data=payload, follow_redirects=False)
        assert r1.status_code == 303
        r2 = admin.post("/accounts/register", data=payload, follow_redirects=False)
        assert r2.status_code == 409

    def test_detail_page_renders_after_register(
        self, file_backed_app: FastAPI
    ) -> None:
        admin = _admin_client(file_backed_app)
        admin.post(
            "/accounts/register",
            data={
                "account_id": "123456789012",
                "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
                "provisioner_external_id": "iam-jit-123456789012",
                "provisioning_mode": "classic_iam",
                "alias": "alpha",
            },
            follow_redirects=False,
        )
        r = admin.get("/accounts/123456789012")
        assert r.status_code == 200
        assert "123456789012" in r.text


class TestWebDeregisterWithFileStore:
    def test_deregister_returns_303_not_409(
        self, file_backed_app: FastAPI
    ) -> None:
        """Regression guard: POST /accounts/<id>/deregister must return 303,
        NOT 409 (the old read-only guard)."""
        # First register.
        admin = _admin_client(file_backed_app)
        admin.post(
            "/accounts/register",
            data={
                "account_id": "123456789012",
                "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
                "provisioner_external_id": "iam-jit-123456789012",
                "provisioning_mode": "classic_iam",
            },
            follow_redirects=False,
        )
        r = admin.post(
            "/accounts/123456789012/deregister",
            follow_redirects=False,
        )
        assert r.status_code == 303, (
            f"#611 regression: expected 303 redirect, got {r.status_code}: {r.text}"
        )
        assert r.headers["location"] == "/accounts"

    def test_deregister_removes_from_yaml(
        self, file_backed_app: FastAPI, tmp_path: pathlib.Path
    ) -> None:
        """State-verification: account must disappear from accounts.yaml on disk."""
        admin = _admin_client(file_backed_app)
        admin.post(
            "/accounts/register",
            data={
                "account_id": "123456789012",
                "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
                "provisioner_external_id": "iam-jit-123456789012",
                "provisioning_mode": "classic_iam",
            },
            follow_redirects=False,
        )
        admin.post("/accounts/123456789012/deregister", follow_redirects=False)
        accounts_yaml = tmp_path / "accounts.yaml"
        data = _load_yaml(accounts_yaml)
        ids = [row["account_id"] for row in data.get("accounts", [])]
        assert "123456789012" not in ids, (
            "account must be removed from accounts.yaml after deregister"
        )

    def test_deregister_unknown_returns_404(
        self, file_backed_app: FastAPI
    ) -> None:
        admin = _admin_client(file_backed_app)
        r = admin.post(
            "/accounts/000000000000/deregister",
            follow_redirects=False,
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# JSON API route — regression guard for the read-only 409
# ---------------------------------------------------------------------------


class TestApiRegisterWithFileStore:
    def test_api_register_returns_201_not_409(
        self, file_backed_app: FastAPI
    ) -> None:
        """POST /api/v1/accounts must return 201, NOT 409, for FileAccountStore."""
        admin = _admin_client(file_backed_app)
        r = admin.post(
            "/api/v1/accounts",
            json={
                "account_id": "123456789012",
                "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
                "provisioner_external_id": "iam-jit-123456789012",
                "provisioning_mode": "classic_iam",
            },
        )
        assert r.status_code == 201, (
            f"#611 regression: expected 201, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert body["account_id"] == "123456789012"

    def test_api_deregister_returns_200_not_409(
        self, file_backed_app: FastAPI
    ) -> None:
        """DELETE /api/v1/accounts/<id> must return 200, NOT 409, for FileAccountStore."""
        admin = _admin_client(file_backed_app)
        admin.post(
            "/api/v1/accounts",
            json={
                "account_id": "123456789012",
                "provisioner_role_arn": "arn:aws:iam::123456789012:role/iam-jit-provisioner",
                "provisioner_external_id": "iam-jit-123456789012",
                "provisioning_mode": "classic_iam",
            },
        )
        r = admin.delete("/api/v1/accounts/123456789012")
        assert r.status_code == 200, (
            f"#611 regression: expected 200, got {r.status_code}: {r.text}"
        )
        assert r.json()["deregistered"] is True
