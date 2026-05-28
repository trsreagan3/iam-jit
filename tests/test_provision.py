"""Provisioning module tests against moto."""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Iterator
from typing import Any

import pytest

from iam_jit import provision
from iam_jit.accounts_store import (
    Account,
    AccountStoreReadOnly,
    InMemoryAccountStore,
)


@pytest.fixture
def moto_sts_iam(mock_aws_env: None) -> Iterator[Any]:
    """Yield a (sts_client, iam_client_factory) pair backed by moto."""
    from moto import mock_aws

    with mock_aws():
        import boto3

        sts = boto3.client("sts", region_name="us-east-1")

        def factory(creds: dict[str, str]) -> Any:
            # moto ignores the temporary creds (its STS doesn't actually
            # mint usable session tokens), but we still create the IAM
            # client per-call so the production code path is exercised.
            return boto3.client("iam", region_name="us-east-1")

        yield sts, factory


@pytest.fixture
def store() -> InMemoryAccountStore:
    s = InMemoryAccountStore()
    s.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-060392206767",
            provisioning_mode="classic_iam",
            alias="dev-account",
        )
    )
    return s


def _request(
    rid: str = "rq-abc",
    *,
    account_id: str = "060392206767",
    duration_hours: int = 24,
    assume_principal: str | None = None,
    requester_arn: str | None = "arn:aws:iam::060392206767:user/dev",
    policy: dict | None = None,
    tags: dict | None = None,
) -> dict:
    spec: dict[str, Any] = {
        "description": "read s3 config files",
        "access_type": "read-only",
        "accounts": [{"account_id": account_id}],
        "duration": {"duration_hours": duration_hours},
        "policy": policy
        or {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::ex", "arn:aws:s3:::ex/*"],
                }
            ],
        },
        "provisioning": {"mode": "classic_iam"},
    }
    if assume_principal:
        spec["assume_by"] = {"principal_arn": assume_principal}
    if tags is not None:
        spec["tags"] = tags
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": rid,
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                **({"principal_arn": requester_arn} if requester_arn else {}),
            },
        },
        "spec": spec,
    }


# ---- happy path ----


def test_provision_creates_role_with_locked_trust_policy(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-001", assume_principal="arn:aws:iam::060392206767:role/ci"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert result.role_arn.endswith("/iam-jit-grant-rq-001")
    assert result.assumer_principal_arn == "arn:aws:iam::060392206767:role/ci"
    assert result.external_id == "iam-jit-060392206767"

    iam = factory({})
    role = iam.get_role(RoleName=result.role_name)["Role"]
    trust = role["AssumeRolePolicyDocument"]
    assert trust["Statement"][0]["Principal"]["AWS"] == "arn:aws:iam::060392206767:role/ci"


def test_provision_uses_login_principal_when_marker_set(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request(
            "rq-002",
            assume_principal="__from_login__",
            requester_arn="arn:aws:iam::060392206767:user/dev",
        ),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert result.assumer_principal_arn == "arn:aws:iam::060392206767:user/dev"


def test_provision_falls_back_to_requester_when_no_assume_by(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-003", assume_principal=None),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert result.assumer_principal_arn == "arn:aws:iam::060392206767:user/dev"


def test_provision_attaches_inline_policy_with_time_condition(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-004"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    iam = factory({})
    pol = iam.get_role_policy(RoleName=result.role_name, PolicyName=f"iam-jit-grant-rq-004")
    doc = pol["PolicyDocument"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    statement = doc["Statement"][0]
    assert "Condition" in statement
    assert "DateLessThan" in statement["Condition"]
    assert "aws:CurrentTime" in statement["Condition"]["DateLessThan"]


def test_provision_trust_policy_has_time_condition(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-005"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    iam = factory({})
    role = iam.get_role(RoleName=result.role_name)["Role"]
    trust = role["AssumeRolePolicyDocument"]
    cond = trust["Statement"][0].get("Condition") or {}
    assert "DateLessThan" in cond
    # Time condition matches the result's expires_at.
    assert cond["DateLessThan"]["aws:CurrentTime"] == result.expires_at


def test_provision_tags_include_request_id_and_expiry(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-006"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    iam = factory({})
    role = iam.get_role(RoleName=result.role_name)["Role"]
    tags = {t["Key"]: t["Value"] for t in role.get("Tags") or []}
    assert tags["managed-by"] == "iam-jit"
    assert tags["request-id"] == "rq-006"
    assert tags["requester"] == "dev@example.com"
    assert tags["expires-at"] == result.expires_at


def test_provision_tags_include_full_audit_set(
    moto_sts_iam, store: InMemoryAccountStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every iam-jit role should be discoverable via the standard
    audit-tag query patterns. The tag set is the contract."""
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_NAME", "team-platform")
    sts, factory = moto_sts_iam
    req = _request("rq-tags-full")
    req["status"] = {
        "history": [
            {"action": "submit", "by": "email:dev@example.com"},
            {"action": "approve", "by": "email:approver@example.com"},
        ]
    }
    result = provision.provision(
        req, accounts_store=store, sts_client=sts, iam_client_factory=factory
    )
    iam = factory({})
    role = iam.get_role(RoleName=result.role_name)["Role"]
    tags = {t["Key"]: t["Value"] for t in role.get("Tags") or []}

    # Required for "is this an iam-jit role?" question
    assert tags["managed-by"] == "iam-jit"
    # Required for "which deployment owns this?"
    assert tags["iam-jit-deployment"] == "team-platform"
    # Required for "what code rev produced this?"
    assert "iam-jit-version" in tags
    # Required for ownership queries
    assert tags["request-id"] == "rq-tags-full"
    assert tags["requester"] == "dev@example.com"
    assert tags["approver"] == "email:approver@example.com"
    # Required for expiry sweeps + auditor "what's still active?" queries
    assert tags["expires-at"] == result.expires_at
    assert "provisioned-at" in tags
    # Required for "show me all read-write grants" audits
    assert tags["access-type"] == "read-only"


# ---------------------------------------------------------------------------
# #698 MED-5 — operator-supplied tags via spec.tags. iam-jit's own tags
# take precedence on key collision; operator tags survive on every key
# that doesn't collide.
# ---------------------------------------------------------------------------


def test_provision_merges_operator_supplied_tags(
    moto_sts_iam, store: InMemoryAccountStore,
) -> None:
    """spec.tags = {cost-center: ..., team: ...} → both appear on the
    provisioned role alongside iam-jit's own tags."""
    sts, factory = moto_sts_iam
    req = _request("rq-tags-ops", tags={
        "cost-center": "platform-eng",
        "team": "data-warehouse",
        "data-classification": "internal",
    })
    result = provision.provision(
        req, accounts_store=store, sts_client=sts, iam_client_factory=factory,
    )
    iam = factory({})
    role = iam.get_role(RoleName=result.role_name)["Role"]
    tags = {t["Key"]: t["Value"] for t in role.get("Tags") or []}
    # Operator-supplied tags appear verbatim.
    assert tags["cost-center"] == "platform-eng"
    assert tags["team"] == "data-warehouse"
    assert tags["data-classification"] == "internal"
    # iam-jit's standard tags still present.
    assert tags["managed-by"] == "iam-jit"
    assert tags["request-id"] == "rq-tags-ops"


def test_provision_iam_jit_tags_win_on_collision(
    moto_sts_iam, store: InMemoryAccountStore,
) -> None:
    """Operator tries to overwrite the audit-trail tags. iam-jit's
    values MUST win — managed-by=iam-jit is the cross-deployment
    invariant every iam-jit reader depends on."""
    sts, factory = moto_sts_iam
    req = _request("rq-tags-coll", tags={
        "managed-by": "operator-spoof",  # attempted overwrite
        "request-id": "fake-id",         # attempted overwrite
        "iam-jit-version": "0.0.0",      # attempted overwrite
        "approver": "operator-spoof",    # attempted overwrite
        "kept-key": "kept-value",        # legit, not a collision
    })
    result = provision.provision(
        req, accounts_store=store, sts_client=sts, iam_client_factory=factory,
    )
    iam = factory({})
    role = iam.get_role(RoleName=result.role_name)["Role"]
    tags = {t["Key"]: t["Value"] for t in role.get("Tags") or []}
    # iam-jit's tags retain their canonical values regardless of operator attempt.
    assert tags["managed-by"] == "iam-jit"
    assert tags["request-id"] == "rq-tags-coll"
    assert tags["iam-jit-version"] != "0.0.0"
    # Non-colliding operator tag survives.
    assert tags["kept-key"] == "kept-value"


def test_provision_tags_omitted_when_no_operator_tags(
    moto_sts_iam, store: InMemoryAccountStore,
) -> None:
    """No spec.tags → iam-jit's tag set is unchanged from pre-#698."""
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-tags-none"),
        accounts_store=store, sts_client=sts, iam_client_factory=factory,
    )
    iam = factory({})
    role = iam.get_role(RoleName=result.role_name)["Role"]
    tags = {t["Key"]: t["Value"] for t in role.get("Tags") or []}
    assert tags["managed-by"] == "iam-jit"
    assert "cost-center" not in tags  # no operator tags leaked


def test_build_tags_clamps_long_values() -> None:
    """AWS tag values are capped at 256 chars; longer operator values
    are silently clamped (per the existing convention for iam-jit's
    own tags)."""
    out = provision._build_tags(
        request_id="rq-1",
        requester_email="dev@example.com",
        approver_id=None,
        expires_at="2026-01-01T00:00:00Z",
        provisioned_at="2026-01-01T00:00:00Z",
        access_type="read-only",
        operator_tags={"long": "x" * 500},
    )
    assert len(out["long"]) == 256


def test_build_tags_rejects_non_string_operator_values() -> None:
    """Non-string operator tag values are dropped silently (the route-
    level schema validator already rejected this shape; _build_tags is
    the defensive last line)."""
    out = provision._build_tags(
        request_id="rq-1",
        requester_email="dev@example.com",
        approver_id=None,
        expires_at="2026-01-01T00:00:00Z",
        provisioned_at="2026-01-01T00:00:00Z",
        access_type="read-only",
        operator_tags={
            "ok": "yes",
            "bad-int": 42,
            "bad-list": ["a", "b"],
            "": "empty-key-dropped",
        },
    )
    assert out["ok"] == "yes"
    assert "bad-int" not in out
    assert "bad-list" not in out
    assert "" not in out


def test_role_name_format_is_globally_unique() -> None:
    """The full ARN — `arn:aws:iam::<account>:role/iam-jit/iam-jit-grant-<rid>` —
    is globally unique because the account ID is part of it, and the
    request_id keeps the local-account name unique. No two iam-jit
    deployments writing to the same destination account would collide
    in practice (12 chars of base64 entropy in request_id)."""
    name = provision._role_name("rq-abc123def4")
    assert name == "iam-jit-grant-rq-abc123def4"
    # Path is always /iam-jit/ so the destination ProvisionerRole policy
    # can scope CreateRole/DeleteRole to roles iam-jit owns.
    assert provision._resource_path("rq-abc123def4") == "/iam-jit/"


def test_deployment_name_default_and_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_DEPLOYMENT_NAME", raising=False)
    assert provision._deployment_name() == "default"
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_NAME", "team-platform")
    assert provision._deployment_name() == "team-platform"
    # Long names are clamped to AWS tag-value limit.
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_NAME", "x" * 200)
    assert len(provision._deployment_name()) == 64


def test_last_approver_extracts_from_history() -> None:
    req = {
        "status": {
            "history": [
                {"action": "submit", "by": "email:dev@example.com"},
                {"action": "request_changes", "by": "email:approver1@example.com"},
                {"action": "edit", "by": "email:dev@example.com"},
                {"action": "approve", "by": "email:approver2@example.com"},
            ]
        }
    }
    assert provision._last_approver(req) == "email:approver2@example.com"


def test_last_approver_none_when_not_yet_approved() -> None:
    req = {"status": {"history": [{"action": "submit", "by": "email:dev@example.com"}]}}
    assert provision._last_approver(req) is None


def test_provision_role_uses_iam_jit_path(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    """Path-prefixing under /iam-jit/ lets the destination account's
    ProvisionerRole policy scope CreateRole/DeleteRole to that prefix."""
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-007"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    iam = factory({})
    role = iam.get_role(RoleName=result.role_name)["Role"]
    assert role["Path"] == "/iam-jit/"
    assert "/iam-jit/" in result.role_arn


# ---- errors ----


def test_provision_unregistered_account_raises(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    with pytest.raises(provision.AccountNotRegistered):
        provision.provision(
            _request("rq-008", account_id="999999999999"),
            accounts_store=store,
            sts_client=sts,
            iam_client_factory=factory,
        )


def test_provision_disabled_account_raises(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    store.put(
        Account(
            account_id="999999999999",
            provisioner_role_arn="arn:aws:iam::999999999999:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-999999999999",
            provisioning_mode="classic_iam",
            enabled=False,
        )
    )
    with pytest.raises(provision.AccountNotRegistered, match="disabled"):
        provision.provision(
            _request("rq-009", account_id="999999999999"),
            accounts_store=store,
            sts_client=sts,
            iam_client_factory=factory,
        )


def test_provision_no_assumer_principal_raises(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    with pytest.raises(provision.AssumerPrincipalMissing):
        provision.provision(
            _request("rq-010", assume_principal=None, requester_arn=None),
            accounts_store=store,
            sts_client=sts,
            iam_client_factory=factory,
        )


def test_provision_empty_policy_raises(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    with pytest.raises(provision.ProvisioningError, match="empty"):
        provision.provision(
            _request("rq-011", policy={"Version": "2012-10-17", "Statement": []}),
            accounts_store=store,
            sts_client=sts,
            iam_client_factory=factory,
        )


# ---- expires_at resolution ----


def test_resolve_expires_at_from_duration_hours() -> None:
    spec = {"duration": {"duration_hours": 4}}
    out = provision._resolve_expires_at(spec)
    expected = _dt.datetime.now(_dt.UTC) + _dt.timedelta(hours=4)
    parsed = _dt.datetime.strptime(out, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.UTC)
    delta = abs((parsed - expected).total_seconds())
    assert delta < 5


def test_resolve_expires_at_uses_explicit_not_after() -> None:
    spec = {"duration": {"not_after": "2030-01-01T00:00:00Z"}}
    assert provision._resolve_expires_at(spec) == "2030-01-01T00:00:00Z"


# ---- policy augmentation ----


def test_augment_policy_adds_time_condition_to_each_statement() -> None:
    pol = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::a/*"},
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::a"},
        ],
    }
    out = provision._augment_policy_with_time_condition(pol, "2030-01-01T00:00:00Z")
    for s in out["Statement"]:
        assert s["Condition"]["DateLessThan"]["aws:CurrentTime"] == "2030-01-01T00:00:00Z"


def test_augment_policy_preserves_existing_conditions() -> None:
    pol = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": "us-east-1"},
                },
            }
        ],
    }
    out = provision._augment_policy_with_time_condition(pol, "2030-01-01T00:00:00Z")
    cond = out["Statement"][0]["Condition"]
    assert cond["StringEquals"]["aws:RequestedRegion"] == "us-east-1"
    assert cond["DateLessThan"]["aws:CurrentTime"] == "2030-01-01T00:00:00Z"


def test_augment_policy_does_not_overwrite_existing_time_condition() -> None:
    """If a caller already set a tighter aws:CurrentTime, leave it."""
    pol = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {"aws:CurrentTime": "2025-01-01T00:00:00Z"},
                },
            }
        ],
    }
    out = provision._augment_policy_with_time_condition(pol, "2030-01-01T00:00:00Z")
    assert (
        out["Statement"][0]["Condition"]["DateLessThan"]["aws:CurrentTime"]
        == "2025-01-01T00:00:00Z"
    )
