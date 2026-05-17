"""Phase 1: deterministic AWS-API discovery.

Reads ONLY from AWS APIs the operator's admin session can reach.
Never reads source code, never calls iam-jit-the-company, never
mutates anything.

Service coverage (v1.0):

  - Organizations: list_accounts (if SCP allows; otherwise fall back
    to the single caller account from STS)
  - IAM: list_roles + filter for AssumeRolePolicyDocument trusting
    an OIDC provider (the iam-jit-native anchor shape)
  - Bedrock: list_foundation_models filtered to Anthropic providers,
    plus a probe for whether the current region has Bedrock enabled
  - EKS: list_clusters → describe_cluster for each (ARN + endpoint)
  - ECS: list_clusters (ARN only)

Deferred to v1.1 (not silently — caller surfaces this list):

  - KMS keys (large, customer rarely wants ALL)
  - Secrets Manager secrets (high cardinality + sensitive names)
  - RDS / DynamoDB / S3 inventories (separate "resource scan" feature)
  - Identity Center permission sets (separate onboarding flow already
    handles this; see src/iam_jit/onboarding.py)

Every call is wrapped in a `_safe_call` helper that returns an empty
collection + records the error on the DiscoveredEnv. Bootstrap should
never crash mid-discovery; the operator sees a complete-but-partial
picture and decides whether to proceed.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
from typing import Any


class DiscoveryError(Exception):
    """Raised only for unrecoverable preconditions (e.g. boto3
    missing, no AWS credentials at all). Per-service failures are
    captured on `DiscoveredEnv.errors` instead of raising."""


@dataclasses.dataclass(frozen=True)
class AccountSummary:
    """One AWS account visible to the bootstrap session."""

    account_id: str
    alias: str | None = None
    email: str | None = None
    status: str | None = None
    tags: dict[str, str] = dataclasses.field(default_factory=dict)
    is_caller_account: bool = False


@dataclasses.dataclass(frozen=True)
class RoleSummary:
    """An IAM role discovered in the caller's account, with just the
    fields the bootstrap proposal needs. We intentionally do NOT
    capture the full permissions policy here — scoring/recommendation
    is downstream; discovery just inventories."""

    role_name: str
    role_arn: str
    account_id: str
    trusts_oidc_provider: bool
    trusted_oidc_providers: tuple[str, ...]
    # The role's own description (admin-set), useful as context
    description: str | None = None


@dataclasses.dataclass(frozen=True)
class BedrockAvailability:
    """Whether the caller can use Bedrock + which Anthropic models
    are listed as available in the probed region."""

    region: str
    bedrock_reachable: bool
    anthropic_model_ids: tuple[str, ...]
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class ClusterSummary:
    """An EKS or ECS cluster the customer might want iam-jit to
    treat as a workload anchor (for k8s-bouncer composition, IRSA
    role discovery, etc.)."""

    cluster_arn: str
    cluster_name: str
    account_id: str
    region: str
    kind: str  # "eks" | "ecs"
    endpoint: str | None = None


@dataclasses.dataclass(frozen=True)
class DiscoveredEnv:
    """The structured output of Phase 1.

    Serializable; tests + the proposal prompt + the audit row all
    read from this same shape.
    """

    discovered_at: str
    caller_account_id: str
    caller_arn: str
    caller_region: str
    accounts: tuple[AccountSummary, ...]
    oidc_roles: tuple[RoleSummary, ...]
    bedrock: BedrockAvailability
    eks_clusters: tuple[ClusterSummary, ...]
    ecs_clusters: tuple[ClusterSummary, ...]
    errors: tuple[str, ...] = ()
    # Services we intentionally did NOT scan in v1.0 — surfaced so
    # the operator + the LLM proposal know what's out-of-scope.
    deferred_services: tuple[str, ...] = (
        "kms",
        "secretsmanager",
        "rds",
        "dynamodb",
        "s3-buckets",
        "identity-center-permission-sets",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "discovered_at": self.discovered_at,
            "caller": {
                "account_id": self.caller_account_id,
                "arn": self.caller_arn,
                "region": self.caller_region,
            },
            "accounts": [
                {
                    "account_id": a.account_id,
                    "alias": a.alias,
                    "email": a.email,
                    "status": a.status,
                    "tags": dict(a.tags),
                    "is_caller_account": a.is_caller_account,
                }
                for a in self.accounts
            ],
            "oidc_roles": [
                {
                    "role_name": r.role_name,
                    "role_arn": r.role_arn,
                    "account_id": r.account_id,
                    "trusts_oidc_provider": r.trusts_oidc_provider,
                    "trusted_oidc_providers": list(r.trusted_oidc_providers),
                    "description": r.description,
                }
                for r in self.oidc_roles
            ],
            "bedrock": {
                "region": self.bedrock.region,
                "bedrock_reachable": self.bedrock.bedrock_reachable,
                "anthropic_model_ids": list(self.bedrock.anthropic_model_ids),
                "error": self.bedrock.error,
            },
            "eks_clusters": [
                {
                    "cluster_arn": c.cluster_arn,
                    "cluster_name": c.cluster_name,
                    "account_id": c.account_id,
                    "region": c.region,
                    "kind": c.kind,
                    "endpoint": c.endpoint,
                }
                for c in self.eks_clusters
            ],
            "ecs_clusters": [
                {
                    "cluster_arn": c.cluster_arn,
                    "cluster_name": c.cluster_name,
                    "account_id": c.account_id,
                    "region": c.region,
                    "kind": c.kind,
                    "endpoint": c.endpoint,
                }
                for c in self.ecs_clusters
            ],
            "errors": list(self.errors),
            "deferred_services": list(self.deferred_services),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_call(label: str, errors: list[str], thunk):  # type: ignore[no-untyped-def]
    """Run `thunk()` and capture exceptions onto `errors`. Returns
    the thunk's result or None on failure. We never let a single
    service's outage break the whole bootstrap."""
    try:
        return thunk()
    except Exception as e:  # noqa: BLE001 — discovery is best-effort
        errors.append(f"{label}: {type(e).__name__}: {e}")
        return None


def _trust_doc_oidc_providers(trust_doc: Any) -> tuple[bool, tuple[str, ...]]:
    """Inspect an AssumeRolePolicyDocument and return
    (trusts_oidc, tuple_of_provider_arns).

    The doc can be either a JSON string (boto3 returns it as a dict
    on newer versions but old SDKs sometimes deliver a string).
    """
    if trust_doc is None:
        return False, ()
    if isinstance(trust_doc, str):
        try:
            trust_doc = json.loads(trust_doc)
        except json.JSONDecodeError:
            return False, ()
    if not isinstance(trust_doc, dict):
        return False, ()
    statements = trust_doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    providers: list[str] = []
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal") or {}
        if not isinstance(principal, dict):
            continue
        federated = principal.get("Federated")
        if federated is None:
            continue
        if isinstance(federated, str):
            federated_list = [federated]
        elif isinstance(federated, list):
            federated_list = [f for f in federated if isinstance(f, str)]
        else:
            continue
        for f in federated_list:
            # OIDC provider ARNs look like
            # arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com
            if ":oidc-provider/" in f:
                providers.append(f)
    return (len(providers) > 0, tuple(sorted(set(providers))))


def _discover_caller(sts_client) -> tuple[str, str]:  # type: ignore[no-untyped-def]
    """Call sts:GetCallerIdentity. Raises DiscoveryError if it fails
    — without a caller identity the bootstrap can't continue."""
    try:
        resp = sts_client.get_caller_identity()
    except Exception as e:  # noqa: BLE001
        raise DiscoveryError(
            f"sts:GetCallerIdentity failed: {e}. Bootstrap requires an "
            "active AWS admin session in the current shell."
        ) from e
    account = resp.get("Account")
    arn = resp.get("Arn")
    if not account or not arn:
        raise DiscoveryError(
            "sts:GetCallerIdentity returned an empty Account/Arn; "
            "bootstrap cannot continue."
        )
    return account, arn


def _discover_accounts(
    organizations_client,  # type: ignore[no-untyped-def]
    caller_account_id: str,
    errors: list[str],
) -> tuple[AccountSummary, ...]:
    """List Organizations accounts; fall back to single-account view
    if AWSOrganizationsNotInUseException or SCP denies."""
    result = _safe_call(
        "organizations:ListAccounts", errors,
        lambda: list(_paginate(
            organizations_client, "list_accounts", "Accounts",
        )),
    )
    if not result:
        # Fallback: caller account is the only one we know about.
        return (AccountSummary(
            account_id=caller_account_id,
            is_caller_account=True,
        ),)
    accounts: list[AccountSummary] = []
    for raw in result:
        acct_id = raw.get("Id")
        if not acct_id:
            continue
        tags = _safe_call(
            f"organizations:ListTagsForResource({acct_id})", errors,
            lambda aid=acct_id: {
                t["Key"]: t["Value"]
                for t in _paginate(
                    organizations_client, "list_tags_for_resource",
                    "Tags", ResourceId=aid,
                )
                if t.get("Key") and t.get("Value") is not None
            },
        ) or {}
        accounts.append(AccountSummary(
            account_id=acct_id,
            alias=raw.get("Name"),
            email=raw.get("Email"),
            status=raw.get("Status"),
            tags=tags,
            is_caller_account=(acct_id == caller_account_id),
        ))
    return tuple(accounts)


def _discover_oidc_roles(
    iam_client,  # type: ignore[no-untyped-def]
    caller_account_id: str,
    errors: list[str],
) -> tuple[RoleSummary, ...]:
    """List IAM roles whose trust policy trusts an OIDC provider.
    These are iam-jit's natural anchor shapes (GitHub Actions OIDC,
    EKS IRSA, etc.)."""
    raw_roles = _safe_call(
        "iam:ListRoles", errors,
        lambda: list(_paginate(iam_client, "list_roles", "Roles")),
    ) or []
    summaries: list[RoleSummary] = []
    for r in raw_roles:
        name = r.get("RoleName")
        arn = r.get("Arn")
        if not name or not arn:
            continue
        trusts_oidc, providers = _trust_doc_oidc_providers(
            r.get("AssumeRolePolicyDocument")
        )
        if not trusts_oidc:
            continue
        summaries.append(RoleSummary(
            role_name=name,
            role_arn=arn,
            account_id=caller_account_id,
            trusts_oidc_provider=True,
            trusted_oidc_providers=providers,
            description=r.get("Description"),
        ))
    return tuple(summaries)


def _discover_bedrock(
    bedrock_client_factory,  # type: ignore[no-untyped-def]
    region: str,
    errors: list[str],
) -> BedrockAvailability:
    """Probe Bedrock for Anthropic model availability in `region`.
    Per [[per-account-llm-policy]], this signals to the proposal
    which accounts can be tagged use_llm vs deterministic_only by
    default."""
    try:
        client = bedrock_client_factory(region)
    except Exception as e:  # noqa: BLE001
        msg = f"bedrock:client({region}): {type(e).__name__}: {e}"
        errors.append(msg)
        return BedrockAvailability(
            region=region, bedrock_reachable=False,
            anthropic_model_ids=(), error=msg,
        )
    try:
        resp = client.list_foundation_models(byProvider="anthropic")
    except Exception as e:  # noqa: BLE001
        msg = f"bedrock:ListFoundationModels: {type(e).__name__}: {e}"
        errors.append(msg)
        return BedrockAvailability(
            region=region, bedrock_reachable=False,
            anthropic_model_ids=(), error=msg,
        )
    summaries = resp.get("modelSummaries") or []
    ids = tuple(sorted({
        m.get("modelId") for m in summaries if m.get("modelId")
    }))
    return BedrockAvailability(
        region=region, bedrock_reachable=True,
        anthropic_model_ids=ids, error=None,
    )


def _discover_eks_clusters(
    eks_client,  # type: ignore[no-untyped-def]
    caller_account_id: str,
    region: str,
    errors: list[str],
) -> tuple[ClusterSummary, ...]:
    names = _safe_call(
        "eks:ListClusters", errors,
        lambda: list(_paginate(eks_client, "list_clusters", "clusters")),
    ) or []
    out: list[ClusterSummary] = []
    for n in names:
        if not isinstance(n, str):
            continue
        desc = _safe_call(
            f"eks:DescribeCluster({n})", errors,
            lambda nn=n: eks_client.describe_cluster(name=nn).get("cluster") or {},
        ) or {}
        arn = desc.get("arn") or f"arn:aws:eks:{region}:{caller_account_id}:cluster/{n}"
        endpoint = desc.get("endpoint")
        out.append(ClusterSummary(
            cluster_arn=arn,
            cluster_name=n,
            account_id=caller_account_id,
            region=region,
            kind="eks",
            endpoint=endpoint,
        ))
    return tuple(out)


def _discover_ecs_clusters(
    ecs_client,  # type: ignore[no-untyped-def]
    caller_account_id: str,
    region: str,
    errors: list[str],
) -> tuple[ClusterSummary, ...]:
    arns = _safe_call(
        "ecs:ListClusters", errors,
        lambda: list(_paginate(ecs_client, "list_clusters", "clusterArns")),
    ) or []
    out: list[ClusterSummary] = []
    for arn in arns:
        if not isinstance(arn, str) or ":cluster/" not in arn:
            continue
        name = arn.split(":cluster/", 1)[-1]
        out.append(ClusterSummary(
            cluster_arn=arn,
            cluster_name=name,
            account_id=caller_account_id,
            region=region,
            kind="ecs",
            endpoint=None,
        ))
    return tuple(out)


def _paginate(client, op_name: str, key: str, **kwargs):  # type: ignore[no-untyped-def]
    """Generic boto3 paginator wrapper. Yields items from `key`.
    Falls back to a single non-paginated call if the operation
    isn't registered as paginatable."""
    try:
        paginator = client.get_paginator(op_name)
    except Exception:
        op = getattr(client, op_name)
        resp = op(**kwargs)
        for item in (resp.get(key) or []):
            yield item
        return
    for page in paginator.paginate(**kwargs):
        for item in (page.get(key) or []):
            yield item


def discover(
    *,
    boto3_session=None,  # type: ignore[no-untyped-def]
    region: str | None = None,
    iam_client=None,  # type: ignore[no-untyped-def]
    sts_client=None,  # type: ignore[no-untyped-def]
    organizations_client=None,  # type: ignore[no-untyped-def]
    eks_client=None,  # type: ignore[no-untyped-def]
    ecs_client=None,  # type: ignore[no-untyped-def]
    bedrock_client_factory=None,  # type: ignore[no-untyped-def]
) -> DiscoveredEnv:
    """Run Phase 1 against the caller's admin AWS session.

    All client arguments are injectable for testability; in
    production the CLI passes None and we build clients from a
    fresh boto3 session.

    `bedrock_client_factory` is a callable `region -> client` so we
    can probe Bedrock per-region without instantiating a global
    client (Bedrock availability varies by region).
    """
    if boto3_session is None:
        import boto3 as _boto3
        boto3_session = _boto3.session.Session()

    resolved_region = (
        region
        or boto3_session.region_name
        or "us-east-1"
    )

    sts_client = sts_client or boto3_session.client("sts", region_name=resolved_region)
    iam_client = iam_client or boto3_session.client("iam", region_name=resolved_region)

    errors: list[str] = []
    caller_account_id, caller_arn = _discover_caller(sts_client)

    organizations_client = organizations_client or boto3_session.client(
        "organizations", region_name=resolved_region,
    )
    accounts = _discover_accounts(
        organizations_client, caller_account_id, errors,
    )

    oidc_roles = _discover_oidc_roles(iam_client, caller_account_id, errors)

    if bedrock_client_factory is None:
        def _default_factory(r: str):  # type: ignore[no-untyped-def]
            return boto3_session.client("bedrock", region_name=r)
        bedrock_client_factory = _default_factory
    bedrock = _discover_bedrock(bedrock_client_factory, resolved_region, errors)

    eks_client = eks_client or boto3_session.client("eks", region_name=resolved_region)
    eks_clusters = _discover_eks_clusters(
        eks_client, caller_account_id, resolved_region, errors,
    )

    ecs_client = ecs_client or boto3_session.client("ecs", region_name=resolved_region)
    ecs_clusters = _discover_ecs_clusters(
        ecs_client, caller_account_id, resolved_region, errors,
    )

    return DiscoveredEnv(
        discovered_at=_now_iso(),
        caller_account_id=caller_account_id,
        caller_arn=caller_arn,
        caller_region=resolved_region,
        accounts=accounts,
        oidc_roles=oidc_roles,
        bedrock=bedrock,
        eks_clusters=eks_clusters,
        ecs_clusters=ecs_clusters,
        errors=tuple(errors),
    )
