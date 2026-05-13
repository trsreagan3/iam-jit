"""Tests for the pre-approval CLI preview.

`provision.preview()` is the no-AWS sibling of `provision.provision()`:
same trust + inline + tag rendering, no STS, no IAM. Used to surface
"if approved, this is what will run" on the request detail page so
reviewers can audit the exact commands before clicking Approve.
"""

from __future__ import annotations

import json
import shlex

import pytest

from iam_jit import provision
from iam_jit.accounts_store import Account, InMemoryAccountStore


@pytest.fixture
def store() -> InMemoryAccountStore:
    s = InMemoryAccountStore()
    s.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-060392206767",
            provisioning_mode="classic_iam",
        )
    )
    return s


def _request(rid: str = "rq-prev", policy: dict | None = None, **overrides) -> dict:
    spec = {
        "description": "preview test",
        "access_type": "read-only",
        "accounts": [{"account_id": "060392206767"}],
        "duration": {"duration_hours": 4},
        "policy": policy
        or {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::ex",
                }
            ],
        },
        "provisioning": {"mode": "classic_iam"},
    }
    spec.update(overrides.get("spec_overrides", {}))
    requester = {
        "name": "Dev",
        "email": "dev@example.com",
        "principal_arn": "arn:aws:iam::060392206767:user/dev",
    }
    requester.update(overrides.get("requester", {}))
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"id": rid, "requester": requester},
        "spec": spec,
    }


def test_preview_emits_same_cli_shape_as_provision(store: InMemoryAccountStore) -> None:
    p = provision.preview(_request(), accounts_store=store)
    assert len(p.aws_cli_replay) == 2
    assert shlex.split(p.aws_cli_replay[0])[2] == "create-role"
    assert shlex.split(p.aws_cli_replay[1])[2] == "put-role-policy"


def test_preview_role_arn_matches_what_provision_would_create(
    store: InMemoryAccountStore,
) -> None:
    p = provision.preview(_request("rq-arn"), accounts_store=store)
    assert p.role_arn == "arn:aws:iam::060392206767:role/iam-jit/iam-jit-grant-rq-arn"


def test_preview_includes_time_condition_in_trust_and_policy(
    store: InMemoryAccountStore,
) -> None:
    p = provision.preview(_request(), accounts_store=store)
    create = shlex.split(p.aws_cli_replay[0])
    flags = _flags(create)
    trust = json.loads(flags["--assume-role-policy-document"])
    assert "DateLessThan" in trust["Statement"][0]["Condition"]
    put = shlex.split(p.aws_cli_replay[1])
    inline = json.loads(_flags(put)["--policy-document"])
    for stmt in inline["Statement"]:
        assert "DateLessThan" in stmt["Condition"]


def test_preview_blocking_issue_unregistered_account(
    store: InMemoryAccountStore,
) -> None:
    """Account not in registry → preview reports it instead of raising,
    so the UI can render the warning even before a clean approve."""
    req = _request()
    req["spec"]["accounts"] = [{"account_id": "999999999999"}]
    p = provision.preview(req, accounts_store=store)
    assert any("999999999999" in i and "not registered" in i for i in p.blocking_issues)


def test_preview_blocking_issue_disabled_account(
    store: InMemoryAccountStore,
) -> None:
    store.put(
        Account(
            account_id="111111111111",
            provisioner_role_arn="arn:aws:iam::111111111111:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-111111111111",
            provisioning_mode="classic_iam",
            enabled=False,
        )
    )
    req = _request()
    req["spec"]["accounts"] = [{"account_id": "111111111111"}]
    p = provision.preview(req, accounts_store=store)
    assert any("disabled" in i for i in p.blocking_issues)


def test_preview_blocking_issue_no_assumer_principal(
    store: InMemoryAccountStore,
) -> None:
    req = _request()
    # Strip both possible sources of a principal so the resolver fails.
    req["metadata"]["requester"].pop("principal_arn", None)
    req["spec"].pop("assume_by", None)
    p = provision.preview(req, accounts_store=store)
    assert any("assume_by" in i or "assumer" in i.lower() for i in p.blocking_issues)


def test_preview_blocking_issue_empty_policy(store: InMemoryAccountStore) -> None:
    req = _request(policy={"Version": "2012-10-17", "Statement": []})
    p = provision.preview(req, accounts_store=store)
    assert any("empty" in i or "malformed" in i for i in p.blocking_issues)


def test_preview_no_blocking_issues_for_clean_request(
    store: InMemoryAccountStore,
) -> None:
    p = provision.preview(_request("clean"), accounts_store=store)
    assert p.blocking_issues == []


def test_preview_does_not_call_aws() -> None:
    """No AWS clients required — the preview is purely computed from
    the request + accounts_store. Verify by NOT setting up moto."""
    store = InMemoryAccountStore()
    store.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-060392206767",
            provisioning_mode="classic_iam",
        )
    )
    p = provision.preview(_request(), accounts_store=store)
    # If preview() called STS or IAM, this would have raised
    # NoCredentialsError or similar against the un-mocked boto3.
    assert p.role_arn
    assert p.aws_cli_replay


def _flags(parts: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    i = 3
    while i < len(parts):
        if parts[i].startswith("--") and i + 1 < len(parts):
            j = i + 1
            vals: list[str] = []
            while j < len(parts) and not parts[j].startswith("--"):
                vals.append(parts[j])
                j += 1
            if len(vals) == 1:
                out[parts[i]] = vals[0]
            i = j
        else:
            i += 1
    return out
