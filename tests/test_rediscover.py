"""Tests for the cross-account rediscovery module + force-delete safety gate.

Coverage:
  - happy path: registered accounts list correctly, AWS roles bucketed
    into known / stale / orphan / zombie correctly
  - lost-access: an account where AssumeRole or ListRoles raises
    AccessDenied is reported in `errors` and `inaccessible_accounts`
    with a remediation hint, and buckets are flagged incomplete
  - safety gate: force_delete refuses any role failing name OR tag check
  - safety gate: force_delete proceeds when both pass, idempotent on
    already-gone roles
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

import pytest
from botocore.exceptions import ClientError

from iam_jit import rediscover
from iam_jit.accounts_store import Account, InMemoryAccountStore
from iam_jit.store import FilesystemStore


def _access_denied(op: str) -> ClientError:
    return ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": f"User: ... is not authorized to perform: {op}",
            }
        },
        op,
    )


def _no_such_entity() -> ClientError:
    return ClientError(
        {"Error": {"Code": "NoSuchEntity", "Message": "Role not found"}},
        "DeleteRole",
    )


class _FakeIAM:
    """Configurable in-memory IAM mock keyed by account_id (simulates
    being a different IAM client per assumed-role session)."""

    def __init__(self, account_id: str, *, deny: set[str] | None = None) -> None:
        self.account_id = account_id
        self.deny = deny or set()
        self.roles: dict[str, dict[str, Any]] = {}
        self.tags_by_role: dict[str, dict[str, str]] = {}
        self.policies: dict[str, dict[str, dict[str, Any]]] = {}

    def add_role(
        self,
        name: str,
        *,
        path: str = "/iam-jit/",
        tags: dict[str, str] | None = None,
        inline: dict[str, dict[str, Any]] | None = None,
    ) -> str:
        arn = f"arn:aws:iam::{self.account_id}:role{path}{name}"
        self.roles[name] = {"RoleName": name, "Arn": arn, "Path": path}
        self.tags_by_role[name] = dict(tags or {})
        self.policies[name] = dict(inline or {})
        return arn

    def list_roles(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:ListRoles" in self.deny:
            raise _access_denied("iam:ListRoles")
        prefix = kwargs.get("PathPrefix") or "/"
        out = [r for r in self.roles.values() if r["Path"] == prefix]
        return {"Roles": out, "IsTruncated": False}

    def list_role_tags(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:ListRoleTags" in self.deny:
            raise _access_denied("iam:ListRoleTags")
        rn = kwargs["RoleName"]
        return {
            "Tags": [
                {"Key": k, "Value": v}
                for k, v in self.tags_by_role.get(rn, {}).items()
            ]
        }

    def list_role_policies(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:ListRolePolicies" in self.deny:
            raise _access_denied("iam:ListRolePolicies")
        rn = kwargs["RoleName"]
        if rn not in self.roles:
            raise _no_such_entity()
        return {"PolicyNames": list(self.policies.get(rn, {}).keys())}

    def delete_role_policy(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:DeleteRolePolicy" in self.deny:
            raise _access_denied("iam:DeleteRolePolicy")
        rn, pn = kwargs["RoleName"], kwargs["PolicyName"]
        self.policies.setdefault(rn, {}).pop(pn, None)
        return {}

    def delete_role(self, **kwargs: Any) -> dict[str, Any]:
        if "iam:DeleteRole" in self.deny:
            raise _access_denied("iam:DeleteRole")
        rn = kwargs["RoleName"]
        if rn not in self.roles:
            raise _no_such_entity()
        self.roles.pop(rn, None)
        self.tags_by_role.pop(rn, None)
        self.policies.pop(rn, None)
        return {}


class _FakeSTS:
    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "Credentials": {
                "AccessKeyId": "AK",
                "SecretAccessKey": "SK",
                "SessionToken": "ST",
                "Expiration": "2099-01-01T00:00:00Z",
            }
        }


@pytest.fixture
def two_account_store() -> InMemoryAccountStore:
    s = InMemoryAccountStore()
    s.put(
        Account(
            account_id="111111111111",
            provisioner_role_arn="arn:aws:iam::111111111111:role/iam-jit-provisioner",
            provisioner_external_id="ext-1",
            provisioning_mode="classic_iam",
            alias="acct-a",
        )
    )
    s.put(
        Account(
            account_id="222222222222",
            provisioner_role_arn="arn:aws:iam::222222222222:role/iam-jit-provisioner",
            provisioner_external_id="ext-2",
            provisioning_mode="classic_iam",
            alias="acct-b",
        )
    )
    return s


@pytest.fixture
def request_store(tmp_path) -> FilesystemStore:
    return FilesystemStore(tmp_path)


# ---- discover_roles_in_account ----


def test_discover_filters_to_managed_by_iam_jit(
    two_account_store: InMemoryAccountStore,
) -> None:
    iam = _FakeIAM("111111111111")
    iam.add_role(
        "iam-jit-grant-rq-aaa",
        tags={"managed-by": "iam-jit", "request-id": "rq-aaa"},
    )
    iam.add_role(
        "iam-jit-someones-other-tool",  # under iam-jit path BUT not tagged
        tags={"managed-by": "other-tool"},
    )
    out = rediscover.discover_roles_in_account(
        account=two_account_store.get("111111111111"),
        sts_client=_FakeSTS(),
        iam_client_factory=lambda creds: iam,
    )
    names = {r.role_name for r in out}
    assert "iam-jit-grant-rq-aaa" in names
    assert "iam-jit-someones-other-tool" not in names


def test_discover_access_denied_raises_destination_access_denied(
    two_account_store: InMemoryAccountStore,
) -> None:
    iam = _FakeIAM("111111111111", deny={"iam:ListRoles"})
    with pytest.raises(rediscover.DestinationAccessDenied):
        rediscover.discover_roles_in_account(
            account=two_account_store.get("111111111111"),
            sts_client=_FakeSTS(),
            iam_client_factory=lambda creds: iam,
        )


# ---- reconcile ----


def _make_request_in_store(
    store: FilesystemStore,
    rid: str,
    *,
    state: str,
    role_arn: str,
    expires_at: str = "",
    account_id: str = "111111111111",
) -> None:
    spec_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::ex/*"],
            }
        ],
    }
    req = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": rid,
            "requester": {"name": "Dev", "email": "dev@example.com"},
        },
        "spec": {
            "description": "rediscovery fixture request",
            "access_type": "read-only",
            "accounts": [{"account_id": account_id}],
            "duration": {"duration_hours": 24},
            "policy": spec_policy,
        },
        "status": {
            "state": state,
            "owner": "dev@example.com",
            "submitted_at": "2026-05-01T00:00:00Z",
            "last_updated_at": "2026-05-01T00:00:00Z",
            "history": [],
            "provisioned": {
                "role_arn": role_arn,
                "role_name": role_arn.rsplit("/", 1)[-1],
                "account_id": account_id,
                "expires_at": expires_at or "2099-01-01T00:00:00Z",
            },
        },
    }
    store.put(rid, req)


def _make_clients(per_account: dict[str, _FakeIAM]):
    """Returns a (sts, factory) pair where factory returns the right
    fake IAM client based on the account assumed into. Since our
    _FakeSTS doesn't carry account info through creds, we pull from a
    counter — sufficient for tests that hit the accounts in order."""
    iter_ = iter(per_account.values())

    def factory(creds: dict[str, str]) -> _FakeIAM:
        return next(iter_)

    return _FakeSTS(), factory


def test_reconcile_buckets_known_orphan_zombie(
    two_account_store: InMemoryAccountStore, request_store: FilesystemStore
) -> None:
    # Account A: has rq-known and rq-orphan
    iam_a = _FakeIAM("111111111111")
    iam_a.add_role(
        "iam-jit-grant-rq-known",
        tags={
            "managed-by": "iam-jit",
            "request-id": "rq-known",
            "expires-at": "2099-01-01T00:00:00Z",
            "iam-jit-deployment": "default",
        },
    )
    iam_a.add_role(
        "iam-jit-grant-rq-orphan",
        tags={
            "managed-by": "iam-jit",
            "request-id": "rq-orphan",
            "expires-at": "2099-01-01T00:00:00Z",
            "iam-jit-deployment": "default",
        },
    )
    # Account B: empty
    iam_b = _FakeIAM("222222222222")

    # Store: rq-known matches A, rq-zombie claims active+provisioned but
    # AWS shows no role.
    _make_request_in_store(
        request_store,
        "rq-known",
        state="active",
        role_arn="arn:aws:iam::111111111111:role/iam-jit/iam-jit-grant-rq-known",
        expires_at="2099-01-01T00:00:00Z",
    )
    _make_request_in_store(
        request_store,
        "rq-zombie",
        state="active",
        role_arn="arn:aws:iam::111111111111:role/iam-jit/iam-jit-grant-rq-zombie",
        expires_at="2099-01-01T00:00:00Z",
    )

    sts, factory = _make_clients({"a": iam_a, "b": iam_b})
    report = rediscover.reconcile(
        accounts_store=two_account_store,
        request_store=request_store,
        sts_client=sts,
        iam_client_factory=factory,
    )

    known_ids = {k["request_id"] for k in report.known}
    orphan_arns = {o["role_arn"] for o in report.orphans}
    zombie_ids = {z["request_id"] for z in report.zombies}

    assert "rq-known" in known_ids
    assert any("iam-jit-grant-rq-orphan" in a for a in orphan_arns)
    assert "rq-zombie" in zombie_ids


def test_reconcile_marks_stale_when_past_expires_at(
    two_account_store: InMemoryAccountStore, request_store: FilesystemStore
) -> None:
    """Role still exists in AWS past its expires-at → stale bucket."""
    yesterday = (
        _dt.datetime.now(_dt.UTC) - _dt.timedelta(days=2)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    iam_a = _FakeIAM("111111111111")
    iam_a.add_role(
        "iam-jit-grant-rq-stale",
        tags={
            "managed-by": "iam-jit",
            "request-id": "rq-stale",
            "expires-at": yesterday,
            "iam-jit-deployment": "default",
        },
    )
    iam_b = _FakeIAM("222222222222")
    _make_request_in_store(
        request_store,
        "rq-stale",
        state="active",
        role_arn="arn:aws:iam::111111111111:role/iam-jit/iam-jit-grant-rq-stale",
        expires_at=yesterday,
    )
    sts, factory = _make_clients({"a": iam_a, "b": iam_b})
    report = rediscover.reconcile(
        accounts_store=two_account_store,
        request_store=request_store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    stale_ids = {s.get("request_id") for s in report.stale}
    assert "rq-stale" in stale_ids
    assert not any(k["request_id"] == "rq-stale" for k in report.known)


def test_reconcile_handles_lost_access_per_account(
    two_account_store: InMemoryAccountStore, request_store: FilesystemStore
) -> None:
    """Account A returns AccessDenied — report must mark it inaccessible
    and surface the remediation hint without crashing."""
    iam_a = _FakeIAM("111111111111", deny={"iam:ListRoles"})
    iam_b = _FakeIAM("222222222222")
    iam_b.add_role(
        "iam-jit-grant-rq-ok",
        tags={"managed-by": "iam-jit", "request-id": "rq-ok"},
    )
    sts, factory = _make_clients({"a": iam_a, "b": iam_b})

    report = rediscover.reconcile(
        accounts_store=two_account_store,
        request_store=request_store,
        sts_client=sts,
        iam_client_factory=factory,
    )

    # Account A: marked inaccessible, error captured
    assert any(
        e["account_id"] == "111111111111" for e in report.errors
    ), report.errors
    assert any(
        ia["account_id"] == "111111111111" for ia in report.inaccessible_accounts
    )
    remediation = report.inaccessible_accounts[0]["remediation"]
    assert "rediscover" in remediation.lower()
    assert "access" in remediation.lower()

    # Account B: still scanned successfully
    assert any(
        a.account_id == "222222222222" and a.success for a in report.accounts
    )


# ---- safety gate ----


def test_validate_role_for_cleanup_requires_both_name_and_tag() -> None:
    """Both checks must pass — neither alone is sufficient."""
    good_arn = "arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-rq-aaa"
    good_name = "iam-jit-grant-rq-aaa"
    good_tags = {"managed-by": "iam-jit", "request-id": "rq-aaa"}
    rediscover.validate_role_for_cleanup(
        role_arn=good_arn, role_name=good_name, tags=good_tags
    )

    # Good name, missing tag
    with pytest.raises(rediscover.CleanupSafetyError) as e1:
        rediscover.validate_role_for_cleanup(
            role_arn=good_arn, role_name=good_name, tags={}
        )
    assert "managed-by=iam-jit" in str(e1.value)

    # Wrong-tag value
    with pytest.raises(rediscover.CleanupSafetyError):
        rediscover.validate_role_for_cleanup(
            role_arn=good_arn,
            role_name=good_name,
            tags={"managed-by": "other-tool"},
        )

    # Tag present but name doesn't match
    with pytest.raises(rediscover.CleanupSafetyError) as e3:
        rediscover.validate_role_for_cleanup(
            role_arn="arn:aws:iam::060392206767:role/some-other-role",
            role_name="some-other-role",
            tags={"managed-by": "iam-jit"},
        )
    assert "iam-jit-grant" in str(e3.value)

    # Both fail
    with pytest.raises(rediscover.CleanupSafetyError):
        rediscover.validate_role_for_cleanup(
            role_arn="arn:aws:iam::060392206767:role/foo",
            role_name="foo",
            tags={"foo": "bar"},
        )


def test_force_delete_refuses_unsafe_role(
    two_account_store: InMemoryAccountStore,
) -> None:
    with pytest.raises(rediscover.CleanupSafetyError):
        rediscover.force_delete_stale_role(
            account=two_account_store.get("111111111111"),
            role_name="random-role",
            role_arn="arn:aws:iam::111111111111:role/random-role",
            tags={"managed-by": "iam-jit"},
            sts_client=_FakeSTS(),
            iam_client_factory=lambda creds: _FakeIAM("111111111111"),
        )


def test_force_delete_acts_when_safety_gate_passes(
    two_account_store: InMemoryAccountStore,
) -> None:
    iam = _FakeIAM("111111111111")
    iam.add_role(
        "iam-jit-grant-rq-fd",
        tags={"managed-by": "iam-jit", "request-id": "rq-fd"},
        inline={"iam-jit-grant-rq-fd": {}},
    )
    out = rediscover.force_delete_stale_role(
        account=two_account_store.get("111111111111"),
        role_name="iam-jit-grant-rq-fd",
        role_arn="arn:aws:iam::111111111111:role/iam-jit/iam-jit-grant-rq-fd",
        tags={"managed-by": "iam-jit"},
        sts_client=_FakeSTS(),
        iam_client_factory=lambda creds: iam,
    )
    assert out["deleted"] is True
    assert "iam-jit-grant-rq-fd" not in iam.roles


def test_force_delete_idempotent_when_role_already_gone(
    two_account_store: InMemoryAccountStore,
) -> None:
    iam = _FakeIAM("111111111111")
    out = rediscover.force_delete_stale_role(
        account=two_account_store.get("111111111111"),
        role_name="iam-jit-grant-rq-gone",
        role_arn="arn:aws:iam::111111111111:role/iam-jit/iam-jit-grant-rq-gone",
        tags={"managed-by": "iam-jit"},
        sts_client=_FakeSTS(),
        iam_client_factory=lambda creds: iam,
    )
    assert out["deleted"] is False
    assert out.get("note") == "role already gone before delete"


def test_is_safe_iam_jit_arn_strict() -> None:
    assert rediscover.is_safe_iam_jit_arn(
        "arn:aws:iam::111111111111:role/iam-jit/iam-jit-grant-rq-abc123"
    )
    # Wrong path
    assert not rediscover.is_safe_iam_jit_arn(
        "arn:aws:iam::111111111111:role/iam-jit-grant-rq-abc"
    )
    # Wrong name pattern
    assert not rediscover.is_safe_iam_jit_arn(
        "arn:aws:iam::111111111111:role/iam-jit/manual-role"
    )
    # Wrong service
    assert not rediscover.is_safe_iam_jit_arn(
        "arn:aws:s3:::iam-jit-grant-bucket"
    )
