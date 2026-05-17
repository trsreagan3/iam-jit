"""Unit tests for Phase 1 (AWS discovery).

Covers:
  - DiscoveredEnv serialization shape (the API surface the
    proposal prompt + audit row both consume)
  - Caller-account fallback when Organizations is denied
  - OIDC role filter — only roles whose trust doc names an
    `oidc-provider/...` survive
  - Bedrock probe captures the reachable/unreachable state
  - EKS + ECS enumeration paginates and tolerates DescribeCluster
    failures without crashing
  - Per-service failure is recorded onto `errors`, not raised

Uses moto where possible (IAM + STS); other services are
mocked with lightweight fake clients because moto's Bedrock /
EKS / ECS / Organizations coverage varies by version.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from iam_jit.enterprise.discovery import (
    AccountSummary,
    BedrockAvailability,
    ClusterSummary,
    DiscoveredEnv,
    DiscoveryError,
    RoleSummary,
    _trust_doc_oidc_providers,
    discover,
)


# ---------------------------------------------------------------------------
# DiscoveredEnv shape + serialization
# ---------------------------------------------------------------------------


def _sample_env() -> DiscoveredEnv:
    return DiscoveredEnv(
        discovered_at="2026-05-18T00:00:00Z",
        caller_account_id="111111111111",
        caller_arn="arn:aws:iam::111111111111:user/admin",
        caller_region="us-east-1",
        accounts=(
            AccountSummary(account_id="111111111111", is_caller_account=True),
            AccountSummary(
                account_id="222222222222", alias="prod",
                tags={"env": "prod"},
            ),
        ),
        oidc_roles=(
            RoleSummary(
                role_name="gha-deployer",
                role_arn="arn:aws:iam::111111111111:role/gha-deployer",
                account_id="111111111111",
                trusts_oidc_provider=True,
                trusted_oidc_providers=(
                    "arn:aws:iam::111111111111:oidc-provider/"
                    "token.actions.githubusercontent.com",
                ),
            ),
        ),
        bedrock=BedrockAvailability(
            region="us-east-1",
            bedrock_reachable=True,
            anthropic_model_ids=("anthropic.claude-opus-4-7-v1:0",),
        ),
        eks_clusters=(
            ClusterSummary(
                cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/prod",
                cluster_name="prod",
                account_id="111111111111",
                region="us-east-1",
                kind="eks",
            ),
        ),
        ecs_clusters=(),
        errors=(),
    )


def test_discovered_env_to_dict_round_trips_via_json() -> None:
    env = _sample_env()
    payload = env.to_dict()
    # Required top-level keys — these are the API surface that the
    # proposal prompt + audit row both read from.
    assert set(payload.keys()) == {
        "discovered_at", "caller", "accounts", "oidc_roles",
        "bedrock", "eks_clusters", "ecs_clusters", "errors",
        "deferred_services",
    }
    assert payload["caller"] == {
        "account_id": "111111111111",
        "arn": "arn:aws:iam::111111111111:user/admin",
        "region": "us-east-1",
    }
    # JSON-round-trip — proves no non-serializable types leaked in.
    text = env.to_json(indent=None)
    reloaded = json.loads(text)
    assert reloaded == payload


def test_discovered_env_lists_deferred_services_explicitly() -> None:
    """Per the report-back template + [[recommender-context-boundary]]:
    we want the OUT-OF-SCOPE services surfaced so the operator
    knows what's not in the proposal."""
    env = _sample_env()
    # Validate the expected v1.0 deferral list — locks the contract.
    assert "kms" in env.deferred_services
    assert "secretsmanager" in env.deferred_services
    assert "identity-center-permission-sets" in env.deferred_services


# ---------------------------------------------------------------------------
# Trust-doc OIDC parsing
# ---------------------------------------------------------------------------


def test_trust_doc_oidc_providers_dict_form() -> None:
    doc = {
        "Statement": [{
            "Principal": {
                "Federated": "arn:aws:iam::111111111111:oidc-provider/"
                             "token.actions.githubusercontent.com",
            },
        }],
    }
    trusts, providers = _trust_doc_oidc_providers(doc)
    assert trusts is True
    assert providers == (
        "arn:aws:iam::111111111111:oidc-provider/"
        "token.actions.githubusercontent.com",
    )


def test_trust_doc_oidc_providers_string_form() -> None:
    doc = json.dumps({
        "Statement": [{
            "Principal": {
                "Federated": [
                    "arn:aws:iam::111111111111:oidc-provider/example.com",
                    "arn:aws:iam::111111111111:oidc-provider/other.example",
                ],
            },
        }],
    })
    trusts, providers = _trust_doc_oidc_providers(doc)
    assert trusts is True
    assert set(providers) == {
        "arn:aws:iam::111111111111:oidc-provider/example.com",
        "arn:aws:iam::111111111111:oidc-provider/other.example",
    }


def test_trust_doc_oidc_providers_no_oidc_returns_empty() -> None:
    doc = {
        "Statement": [{"Principal": {"AWS": "arn:aws:iam::111111111111:root"}}],
    }
    trusts, providers = _trust_doc_oidc_providers(doc)
    assert trusts is False
    assert providers == ()


def test_trust_doc_oidc_providers_handles_malformed_input() -> None:
    assert _trust_doc_oidc_providers(None) == (False, ())
    assert _trust_doc_oidc_providers("not json") == (False, ())
    assert _trust_doc_oidc_providers(["not", "a", "dict"]) == (False, ())


# ---------------------------------------------------------------------------
# Fake clients for the discover() orchestration test
# ---------------------------------------------------------------------------


class _FakeSTS:
    def __init__(self, account: str, arn: str) -> None:
        self._account = account
        self._arn = arn

    def get_caller_identity(self) -> dict[str, Any]:
        return {"Account": self._account, "Arn": self._arn}


class _FakeIAM:
    def __init__(self, roles: list[dict[str, Any]]) -> None:
        self._roles = roles

    def get_paginator(self, name: str):
        if name != "list_roles":
            raise ValueError(f"unexpected paginator: {name}")
        roles = self._roles

        class _P:
            def paginate(self, **kw):  # type: ignore[no-untyped-def]
                yield {"Roles": roles}

        return _P()


class _FakeOrganizationsDenied:
    """Simulates SCP denial of organizations:ListAccounts."""

    def get_paginator(self, name: str):
        raise RuntimeError("SCP denies organizations:ListAccounts")


class _FakeOrganizationsOK:
    def __init__(self, accounts: list[dict[str, Any]]) -> None:
        self._accounts = accounts

    def get_paginator(self, name: str):
        accounts = self._accounts
        if name == "list_accounts":
            class _P:
                def paginate(self, **kw):  # type: ignore[no-untyped-def]
                    yield {"Accounts": accounts}
            return _P()
        if name == "list_tags_for_resource":
            class _P:
                def paginate(self, **kw):  # type: ignore[no-untyped-def]
                    yield {"Tags": []}
            return _P()
        raise ValueError(name)


class _FakeBedrockOK:
    def list_foundation_models(self, byProvider: str) -> dict[str, Any]:
        return {
            "modelSummaries": [
                {"modelId": "anthropic.claude-opus-4-7-v1:0"},
                {"modelId": "anthropic.claude-sonnet-4-6-v1:0"},
            ],
        }


class _FakeBedrockUnreachable:
    def list_foundation_models(self, byProvider: str):
        raise RuntimeError("bedrock not enabled in this region")


class _FakeEKS:
    def __init__(self, names: list[str], describe_fails: bool = False) -> None:
        self._names = names
        self._describe_fails = describe_fails

    def get_paginator(self, name: str):
        if name != "list_clusters":
            raise ValueError(name)
        names = self._names

        class _P:
            def paginate(self, **kw):  # type: ignore[no-untyped-def]
                yield {"clusters": names}
        return _P()

    def describe_cluster(self, name: str):  # type: ignore[no-untyped-def]
        if self._describe_fails:
            raise RuntimeError("describe failed")
        return {
            "cluster": {
                "arn": f"arn:aws:eks:us-east-1:111111111111:cluster/{name}",
                "endpoint": f"https://{name}.example.com",
            },
        }


class _FakeECS:
    def __init__(self, arns: list[str]) -> None:
        self._arns = arns

    def get_paginator(self, name: str):
        if name != "list_clusters":
            raise ValueError(name)
        arns = self._arns

        class _P:
            def paginate(self, **kw):  # type: ignore[no-untyped-def]
                yield {"clusterArns": arns}
        return _P()


# ---------------------------------------------------------------------------
# Orchestration tests
# ---------------------------------------------------------------------------


def test_discover_happy_path_collects_all_services() -> None:
    iam_role = {
        "RoleName": "gha-deployer",
        "Arn": "arn:aws:iam::111111111111:role/gha-deployer",
        "AssumeRolePolicyDocument": {
            "Statement": [{
                "Principal": {
                    "Federated": (
                        "arn:aws:iam::111111111111:oidc-provider/"
                        "token.actions.githubusercontent.com"
                    ),
                },
            }],
        },
    }
    non_oidc_role = {
        "RoleName": "lambda-exec",
        "Arn": "arn:aws:iam::111111111111:role/lambda-exec",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Principal": {"Service": "lambda.amazonaws.com"}}],
        },
    }

    env = discover(
        region="us-east-1",
        sts_client=_FakeSTS("111111111111", "arn:aws:iam::111111111111:user/admin"),
        iam_client=_FakeIAM([iam_role, non_oidc_role]),
        organizations_client=_FakeOrganizationsOK([
            {"Id": "111111111111", "Name": "caller", "Email": "x@example.com", "Status": "ACTIVE"},
            {"Id": "222222222222", "Name": "prod", "Email": "y@example.com", "Status": "ACTIVE"},
        ]),
        eks_client=_FakeEKS(["prod-eks"]),
        ecs_client=_FakeECS([
            "arn:aws:ecs:us-east-1:111111111111:cluster/batch",
        ]),
        bedrock_client_factory=lambda r: _FakeBedrockOK(),
    )

    assert env.caller_account_id == "111111111111"
    assert len(env.accounts) == 2
    # OIDC filter: only the GHA role survives.
    assert len(env.oidc_roles) == 1
    assert env.oidc_roles[0].role_name == "gha-deployer"
    assert env.bedrock.bedrock_reachable is True
    assert len(env.bedrock.anthropic_model_ids) == 2
    assert len(env.eks_clusters) == 1
    assert env.eks_clusters[0].cluster_arn.endswith("cluster/prod-eks")
    assert len(env.ecs_clusters) == 1
    assert env.errors == ()


def test_discover_falls_back_to_single_account_when_orgs_denied() -> None:
    env = discover(
        region="us-east-1",
        sts_client=_FakeSTS("111111111111", "arn:aws:iam::111111111111:role/Admin"),
        iam_client=_FakeIAM([]),
        organizations_client=_FakeOrganizationsDenied(),
        eks_client=_FakeEKS([]),
        ecs_client=_FakeECS([]),
        bedrock_client_factory=lambda r: _FakeBedrockUnreachable(),
    )
    # Falls back to caller-only.
    assert len(env.accounts) == 1
    assert env.accounts[0].account_id == "111111111111"
    assert env.accounts[0].is_caller_account is True
    # Records the org failure as an error.
    assert any("organizations:ListAccounts" in e for e in env.errors)
    # Bedrock unreachable surfaced too.
    assert env.bedrock.bedrock_reachable is False
    assert any("bedrock" in e.lower() for e in env.errors)


def test_discover_raises_only_when_sts_fails() -> None:
    class _BadSTS:
        def get_caller_identity(self):
            raise RuntimeError("expired token")
    with pytest.raises(DiscoveryError) as exc:
        discover(
            region="us-east-1",
            sts_client=_BadSTS(),
            iam_client=_FakeIAM([]),
            organizations_client=_FakeOrganizationsOK([]),
            eks_client=_FakeEKS([]),
            ecs_client=_FakeECS([]),
            bedrock_client_factory=lambda r: _FakeBedrockOK(),
        )
    assert "GetCallerIdentity" in str(exc.value)


def test_discover_tolerates_describe_cluster_failure() -> None:
    env = discover(
        region="us-east-1",
        sts_client=_FakeSTS("111111111111", "arn:aws:iam::111111111111:role/Admin"),
        iam_client=_FakeIAM([]),
        organizations_client=_FakeOrganizationsOK([
            {"Id": "111111111111", "Name": "caller", "Email": "x@example.com", "Status": "ACTIVE"},
        ]),
        eks_client=_FakeEKS(["mystery-cluster"], describe_fails=True),
        ecs_client=_FakeECS([]),
        bedrock_client_factory=lambda r: _FakeBedrockOK(),
    )
    # Cluster still surfaces with synthesized ARN despite describe failure.
    assert len(env.eks_clusters) == 1
    assert env.eks_clusters[0].cluster_name == "mystery-cluster"
    assert any("DescribeCluster" in e for e in env.errors)


# ---------------------------------------------------------------------------
# moto-backed smoke test (uses the existing moto_iam fixture from tests/conftest.py)
# ---------------------------------------------------------------------------


def test_discover_against_moto_iam_picks_up_real_oidc_role(moto_iam) -> None:
    """End-to-end through real boto3 → moto for the IAM portion.

    The other services (Bedrock/EKS/ECS/Organizations) are stubbed —
    moto coverage of those services varies by version and is not
    relevant to validating the IAM trust-doc parser path.
    """
    # Create an OIDC provider + a role trusting it.
    moto_iam.create_open_id_connect_provider(
        Url="https://token.actions.githubusercontent.com",
        ClientIDList=["sts.amazonaws.com"],
        ThumbprintList=["1111111111111111111111111111111111111111"],
    )
    providers = moto_iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]
    oidc_arn = providers[0]["Arn"]
    moto_iam.create_role(
        RoleName="gha-deployer",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": oidc_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
            }],
        }),
    )
    moto_iam.create_role(
        RoleName="non-oidc",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )

    env = discover(
        region="us-east-1",
        sts_client=_FakeSTS("123456789012", "arn:aws:iam::123456789012:user/admin"),
        iam_client=moto_iam,
        organizations_client=_FakeOrganizationsDenied(),
        eks_client=_FakeEKS([]),
        ecs_client=_FakeECS([]),
        bedrock_client_factory=lambda r: _FakeBedrockUnreachable(),
    )
    oidc_names = {r.role_name for r in env.oidc_roles}
    assert "gha-deployer" in oidc_names
    assert "non-oidc" not in oidc_names
