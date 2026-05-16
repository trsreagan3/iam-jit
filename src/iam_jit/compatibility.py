"""iam-jit applicability framework — answer "can iam-jit help here?".

Per [[iam-jit-inapplicable-cases]]: iam-jit-the-issuer's model is
"create a new short-lived role" (per [[creates-never-mutates]]).
Many real environments require a SPECIFIC pre-existing role:
- K8s IRSA / EKS Pod Identity (role baked into pod spec)
- EC2 instance profile (attached at launch; not swappable)
- Lambda execution role (set at function creation)
- Pre-existing cross-account trust relationships
- Org SCP denying `iam:CreateRole`
- Compliance requiring named/audited roles

Without a clear "iam-jit can't help" signal, agents waste cycles
retrying iam-jit → fail → reach for "disable iam-jit, give me
admin." Same failure mode [[agent-friendly-not-bypassable]] guards
against, at a different layer: the agent didn't bypass — iam-jit
ITSELF was the wrong tool, and the agent had no way to know.

This module is the FOUNDATION for that signal:
- `Compatibility` enum — four verdicts (proceed / use-existing /
  use-bouncer / cannot-help)
- `WorkloadType` enum — what's making the AWS call
- `CompatibilityIntent` — the input shape an agent provides
- `CompatibilityResult` — the verdict + reasoning + next-action hint
- `check_compatibility()` — the pure decision function

The decision sources stack in this order:
1. Admin allowlist (per-account/per-workload "use this existing role")
   — added in Slice 2.
2. Known-incompatible catalog (k8s IRSA, EC2 IP, etc.) — this slice.
3. Service-specific reasoning — this slice.
4. Default: PROCEED with iam-jit-the-issuer.

Per [[agent-friendly-not-bypassable]]: the response is always
SELF-DESCRIBING. If the verdict is anything other than PROCEED,
the response includes the existing role ARN (if known), why iam-jit
can't issue, and what the agent should do INSTEAD — never a vague
"can't help."
"""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any


class Compatibility(str, Enum):
    """The four verdicts the checker returns."""

    PROCEED = "proceed"
    """iam-jit-the-issuer can create + scope a JIT role for this case."""

    USE_EXISTING = "use_existing"
    """A specific pre-existing role MUST be used (k8s IRSA, EC2 instance
    profile, etc.). iam-jit can't issue; agent assumes the existing role
    directly."""

    USE_BOUNCER = "use_bouncer"
    """iam-jit-the-issuer can't help (the workload uses a fixed role),
    but iam-jit-the-bouncer CAN gate the AWS calls regardless of how
    creds were obtained. Recommended fallback for k8s pods, agent dev
    workflows, etc."""

    CANNOT_HELP = "cannot_help"
    """Neither iam-jit product helps this case. Rare — usually means
    org-policy prohibits iam:CreateRole AND the workload's existing
    role is admin-class with no scoping possible. Agent should escalate
    to the human to handle out-of-band."""


class WorkloadType(str, Enum):
    """What's making the AWS API call. Distinct workloads have
    distinct compatibility profiles.

    Per [[recommender-context-boundary]]: this is workload classification
    only — iam-jit does NOT inspect source code or external systems to
    determine the workload. The agent declares it; the checker uses it.
    """

    K8S_POD = "k8s_pod"
    """Pod running in EKS / a self-managed K8s cluster. Bound to an
    IRSA role at pod creation; can't choose another."""

    EKS_POD_IDENTITY = "eks_pod_identity"
    """EKS Pod Identity (the newer EKS-specific mechanism). Same
    can't-choose-role shape as IRSA."""

    EC2_INSTANCE = "ec2_instance"
    """Code running directly on an EC2 instance with an attached
    instance profile."""

    LAMBDA_FUNCTION = "lambda_function"
    """AWS Lambda execution context. Function definition pins the
    execution role; can't swap at runtime."""

    ECS_TASK = "ecs_task"
    """ECS task with a Task Role (similar to IRSA but ECS-shaped)."""

    CI_RUNNER = "ci_runner"
    """CI/CD job (GitHub Actions, GitLab CI, Buildkite, etc.). OIDC-
    federated; iam-jit CAN typically issue here (the OIDC trust
    policy is something we control)."""

    AGENT_LOCAL_DEV = "agent_local_dev"
    """Claude Code / Cursor / etc. running on a developer's laptop.
    Per [[agent-safety-adoption-play]] this is iam-jit's killer
    bottoms-up adoption case; PROCEED unless overridden."""

    HUMAN_CLI = "human_cli"
    """Human at a terminal running aws-cli / boto3 directly. iam-jit
    can issue; bouncer can gate."""

    OTHER = "other"
    """Catch-all when the agent doesn't know or the case doesn't fit.
    Checker defaults to PROCEED with a 'workload-unknown' note."""


@dataclasses.dataclass(frozen=True)
class CompatibilityIntent:
    """The shape an agent passes to `check_compatibility`. All fields
    optional except workload — the checker degrades gracefully when
    less info is provided.
    """

    workload: WorkloadType
    target_account_id: str | None = None
    target_services: tuple[str, ...] = ()
    description: str | None = None
    # If the agent already knows about an existing role (e.g. reading
    # the pod spec, the Lambda function definition), it can pass the
    # ARN. The checker echoes it back in USE_EXISTING verdicts so the
    # agent has a single response to act on.
    existing_role_hint: str | None = None


@dataclasses.dataclass(frozen=True)
class CompatibilityResult:
    """The verdict + reasoning + next-action hint. Per
    [[agent-friendly-not-bypassable]]: never returns a vague
    answer. Every non-PROCEED verdict comes with a path forward."""

    verdict: Compatibility
    reasoning: str
    existing_role_arn: str | None = None
    matched_pattern: str | None = None  # which catalog entry / allowlist rule fired
    next_action_hint: str | None = None  # what the agent should do INSTEAD
    bouncer_recommended: bool = False  # USE_BOUNCER or USE_EXISTING-with-bouncer-fallback

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reasoning": self.reasoning,
            "existing_role_arn": self.existing_role_arn,
            "matched_pattern": self.matched_pattern,
            "next_action_hint": self.next_action_hint,
            "bouncer_recommended": self.bouncer_recommended,
        }


# ---------------------------------------------------------------------------
# Curated known-incompatible catalog
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class CatalogEntry:
    """One curated rule in the known-incompatible patterns catalog."""

    id: str
    workloads: tuple[WorkloadType, ...]
    verdict: Compatibility
    reasoning: str
    next_action_hint: str
    bouncer_recommended: bool = False


CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        id="k8s-irsa-fixed-role",
        workloads=(WorkloadType.K8S_POD, WorkloadType.EKS_POD_IDENTITY),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "K8s pods are bound to a specific IAM role at pod creation via "
            "IRSA (the service account's OIDC trust) or EKS Pod Identity. "
            "The running pod cannot choose a different role at runtime, so "
            "iam-jit cannot mint a usable JIT role for this workload."
        ),
        next_action_hint=(
            "Use the role ARN from the pod's service-account annotation "
            "`eks.amazonaws.com/role-arn` (IRSA) or its EKS Pod Identity "
            "association. The pod's own AWS SDK calls will pick it up "
            "automatically. iam-jit-the-bouncer can gate these calls if "
            "you need scoped enforcement — see docs/IAM-JIT-BOUNCER.md."
        ),
        bouncer_recommended=True,
    ),
    CatalogEntry(
        id="ec2-instance-profile-fixed",
        workloads=(WorkloadType.EC2_INSTANCE,),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "EC2 instances use the IAM role attached at launch time via "
            "their instance profile. A running instance cannot swap "
            "instance profiles for the role it's currently using, so "
            "iam-jit cannot issue a usable JIT role for code running "
            "directly on the instance."
        ),
        next_action_hint=(
            "Use the existing instance profile role. If you need scoped "
            "gating, run iam-jit-the-bouncer locally and configure your "
            "AWS SDK with AWS_ENDPOINT_URL pointing at it."
        ),
        bouncer_recommended=True,
    ),
    CatalogEntry(
        id="lambda-execution-role-fixed",
        workloads=(WorkloadType.LAMBDA_FUNCTION,),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "AWS Lambda functions use the execution role set at function "
            "creation. The running function cannot swap roles, so iam-jit "
            "cannot issue a usable JIT role for code running inside the "
            "Lambda. (You CAN use iam-jit at function DEPLOY time to scope "
            "the execution role you create — but not from inside the "
            "function's runtime.)"
        ),
        next_action_hint=(
            "From inside the Lambda runtime: use the existing execution "
            "role. At deploy time: use iam-jit to scope the role you set "
            "on the function definition."
        ),
        bouncer_recommended=False,  # bouncer doesn't make sense inside Lambda runtime
    ),
    CatalogEntry(
        id="ecs-task-role-fixed",
        workloads=(WorkloadType.ECS_TASK,),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "ECS tasks use the Task Role specified in the task definition. "
            "A running task cannot swap roles, so iam-jit cannot issue a "
            "usable JIT role for code running inside an ECS task."
        ),
        next_action_hint=(
            "Use the existing task role. At task-definition deploy time, "
            "iam-jit can scope the role you set on the definition."
        ),
        bouncer_recommended=True,
    ),
    CatalogEntry(
        id="ci-runner-oidc",
        workloads=(WorkloadType.CI_RUNNER,),
        verdict=Compatibility.PROCEED,
        reasoning=(
            "CI/CD runners typically authenticate via OIDC federation to "
            "an IAM role under our control. iam-jit can issue a JIT role "
            "with a trust policy that includes the OIDC provider, scoped "
            "to the specific repo/branch/workflow."
        ),
        next_action_hint=(
            "Proceed with iam-jit. Request the appropriate template; "
            "iam-jit issues the role + assume snippet for the OIDC "
            "session token."
        ),
    ),
    CatalogEntry(
        id="agent-local-dev-proceed",
        workloads=(WorkloadType.AGENT_LOCAL_DEV,),
        verdict=Compatibility.PROCEED,
        reasoning=(
            "Agents running locally on a developer's laptop are iam-jit's "
            "primary use case (per [[agent-safety-adoption-play]]). The "
            "agent has full control over which role it assumes; iam-jit "
            "can issue a scoped, time-limited role and return the assume "
            "snippet."
        ),
        next_action_hint=(
            "Proceed with iam-jit. Pair with iam-jit-the-bouncer for "
            "in-process gating of individual AWS calls under the issued "
            "session."
        ),
        bouncer_recommended=True,
    ),
    CatalogEntry(
        id="human-cli-proceed",
        workloads=(WorkloadType.HUMAN_CLI,),
        verdict=Compatibility.PROCEED,
        reasoning=(
            "A human at a terminal can assume any role they're permitted "
            "to. iam-jit can issue a JIT role scoped to the task; the "
            "human runs the printed assume snippet."
        ),
        next_action_hint="Proceed with iam-jit.",
    ),
)


_CATALOG_BY_WORKLOAD: dict[WorkloadType, CatalogEntry] = {}
for _entry in CATALOG:
    for _w in _entry.workloads:
        # First-match-wins: the catalog is ordered by specificity, so
        # the first entry mentioning a workload is the canonical answer.
        _CATALOG_BY_WORKLOAD.setdefault(_w, _entry)


# ---------------------------------------------------------------------------
# The decision function
# ---------------------------------------------------------------------------


def check_compatibility(intent: CompatibilityIntent) -> CompatibilityResult:
    """Pure decision: given an intent, return the verdict + reasoning
    + next-action hint.

    Sources consulted (Slice 1 — Slice 2 will add admin allowlist):
    1. Known-incompatible catalog (workload-keyed)
    2. Default: PROCEED with a generic note

    The function is intentionally simple in this slice: every workload
    has a canonical catalog entry. Admin allowlist + per-account
    overrides land in Slice 2.
    """
    entry = _CATALOG_BY_WORKLOAD.get(intent.workload)
    if entry is None:
        # OTHER / unknown workload: degrade to PROCEED but flag that
        # we couldn't classify.
        return CompatibilityResult(
            verdict=Compatibility.PROCEED,
            reasoning=(
                f"Workload {intent.workload.value!r} not in the known-"
                "incompatible catalog; defaulting to PROCEED. If iam-jit "
                "issuance fails, the workload may have a fixed-role "
                "constraint not captured here — fall back to the "
                "existing role + iam-jit-the-bouncer for gating."
            ),
            next_action_hint=(
                "Proceed with iam-jit. If it returns 'no permission to "
                "create role' or similar, switch to the workload's "
                "existing role + bouncer."
            ),
            bouncer_recommended=True,
        )

    # Catalog hit. Echo the existing-role hint back to the caller if
    # they gave us one — saves an MCP round-trip.
    existing_role_arn: str | None = None
    if entry.verdict == Compatibility.USE_EXISTING:
        existing_role_arn = intent.existing_role_hint

    return CompatibilityResult(
        verdict=entry.verdict,
        reasoning=entry.reasoning,
        existing_role_arn=existing_role_arn,
        matched_pattern=entry.id,
        next_action_hint=entry.next_action_hint,
        bouncer_recommended=entry.bouncer_recommended,
    )


def list_catalog() -> list[dict[str, Any]]:
    """Return the catalog as a list of dicts for MCP / CLI display."""
    return [
        {
            "id": e.id,
            "workloads": [w.value for w in e.workloads],
            "verdict": e.verdict.value,
            "reasoning": e.reasoning,
            "next_action_hint": e.next_action_hint,
            "bouncer_recommended": e.bouncer_recommended,
        }
        for e in CATALOG
    ]
