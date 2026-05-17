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
import re
from enum import Enum
from typing import Any, Protocol


# WB24 MED-24-02 closure: IAM role ARN format validator. Covers all
# four AWS partitions (aws / aws-us-gov / aws-cn / aws-iso/iso-b).
# Role-name charset per AWS docs: alphanumeric + `_+=,.@/-`.
_IAM_ROLE_ARN_RE = re.compile(
    r"^arn:aws(?:-[a-z-]+)?:iam::\d{12}:role/[\w+=,.@/-]+$"
)


def _validate_existing_role_hint(hint: str | None) -> tuple[str | None, bool]:
    """Return (cleaned_hint_or_None, was_invalid_input). WB24 MED-24-02
    closure. The cleaned value is the trimmed ARN or None; the flag
    is True when the caller passed a non-empty string that didn't
    match the IAM role ARN regex (so the caller can surface
    'we ignored your hint because it didn't parse')."""
    if hint is None:
        return None, False
    stripped = hint.strip()
    if not stripped:
        return None, False
    if not _IAM_ROLE_ARN_RE.match(stripped):
        return None, True
    return stripped, False


class ConfigEventSink(Protocol):
    """WB24 MED-24-01 closure: optional sink that records compatibility-
    check calls to an audit log. The MCP handler / Slice 3 intake
    plumb in a real sink (the bouncer's `config_events` table, or a
    new top-level iam-jit table); the pure `check_compatibility`
    function takes the sink as a parameter so it stays
    dependency-free for tests.
    """

    def record(
        self,
        *,
        kind: str,
        actor: str,
        summary: str,
        detail: dict[str, Any] | None = None,
    ) -> None: ...


class Compatibility(str, Enum):
    """The verdicts the checker returns.

    Slice 1 reachable: PROCEED, USE_EXISTING.
    Slice 2 will add reachable paths for USE_BOUNCER (admin allowlist
    can declare "prefer-bouncer-only for this account") and CANNOT_HELP
    (admin allowlist can declare "iam-jit explicitly not supported for
    this account/workload — escalate to human"). Per WB24 MED-24-04
    they're kept in the enum so agent integrations write switch
    statements over the full surface from day one rather than break
    when Slice 2 lands.
    """

    PROCEED = "proceed"
    """iam-jit-the-issuer can create + scope a JIT role for this case."""

    USE_EXISTING = "use_existing"
    """A pre-existing role should be used (k8s IRSA, EC2 instance
    profile, etc.). The workload's BASE identity is the pre-existing
    role; using iam-jit would require the workload to make an explicit
    sts:AssumeRole hop, which most workloads don't need. The
    `existing_role_arn` field carries the role to use; the
    `bouncer_recommended` flag indicates whether the bouncer can gate
    calls made under that role."""

    USE_BOUNCER = "use_bouncer"
    """[Slice 2 reserved] The workload has a valid role already; the
    recommendation is "don't issue a new role, just gate the calls
    via iam-jit-the-bouncer." Slice 2's admin allowlist can declare
    "for this account / workload, prefer the bouncer over issuing new
    roles." Slice 1's catalog never returns this; the equivalent is
    USE_EXISTING + bouncer_recommended=True."""

    CANNOT_HELP = "cannot_help"
    """[Slice 2 reserved] Neither iam-jit product helps this case.
    Slice 2's admin allowlist can mark accounts / workloads as
    explicitly out-of-scope ("compliance environment; named-role-only;
    bouncer not deployable"). Agent should escalate to a human.
    Slice 1's catalog never returns this."""


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
    """ECS task with a Task Role (similar to IRSA but ECS-shaped).
    Fargate tasks specifically have BOTH a Task Role (used by container
    code) AND an Execution Role (used by the Fargate agent to pull
    images / write logs); both fixed at task launch."""

    CODEBUILD_PROJECT = "codebuild_project"
    """AWS CodeBuild build executes under the project's service role,
    set at project creation. WB24 LOW-24-01."""

    STEP_FUNCTIONS = "step_functions"
    """Step Functions state machine executes under the SM's role.
    Per-state Task integrations can call AssumeRole but the SM's base
    identity is fixed."""

    GLUE_JOB = "glue_job"
    """AWS Glue jobs execute under the IAM role on the job definition."""

    SAGEMAKER = "sagemaker"
    """SageMaker training jobs / notebook instances / processing jobs
    execute under their per-resource execution role."""

    APP_RUNNER = "app_runner"
    """AWS App Runner services use the instance role on the service
    definition."""

    BATCH_JOB = "batch_job"
    """AWS Batch jobs execute under the job role on the job definition."""

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
    # WB24 MED-24-02 closure: surface when the caller's existing_role_hint
    # didn't parse as a valid IAM role ARN so the agent learns "we
    # ignored your hint" rather than silently dropping it.
    existing_role_hint_invalid: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reasoning": self.reasoning,
            "existing_role_arn": self.existing_role_arn,
            "matched_pattern": self.matched_pattern,
            "next_action_hint": self.next_action_hint,
            "bouncer_recommended": self.bouncer_recommended,
            "existing_role_hint_invalid": self.existing_role_hint_invalid,
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
            "The pod's BASE identity — what the AWS SDK uses when no role "
            "is explicitly assumed — cannot be swapped at runtime. Pod "
            "code CAN call sts:AssumeRole into a different role (subject "
            "to that role's trust policy), but this adds an explicit hop "
            "that the pod author has to write; iam-jit cannot transparently "
            "substitute. For most workloads, using the pod's IRSA role "
            "directly is simpler than wiring an iam-jit AssumeRole step."
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
            "their instance profile. The BASE identity for code on the "
            "instance — what IMDS hands out by default — cannot be "
            "swapped while the instance is running. Code on the instance "
            "CAN call sts:AssumeRole into another role (subject to that "
            "role's trust policy), but the instance profile is fixed. "
            "For most workloads, using the instance profile role directly "
            "is simpler than wiring an iam-jit AssumeRole hop."
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
            "creation. The function's BASE identity is the execution role "
            "and cannot be changed at runtime. Function code CAN call "
            "sts:AssumeRole to switch into another role mid-invocation "
            "(subject to that role's trust policy), but for most "
            "workloads the execution role is what the function should use "
            "directly. (You CAN use iam-jit at function DEPLOY time to "
            "scope the execution role you create — separate flow from "
            "issuing a role at runtime.)"
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
            "The task's BASE identity is the Task Role and cannot be "
            "changed mid-task. Task code CAN call sts:AssumeRole into a "
            "different role (subject to that role's trust policy), but "
            "for most workloads using the Task Role directly is simpler. "
            "Note: Fargate tasks have TWO roles — the Task Role (used "
            "by container code; this entry) and the Execution Role (used "
            "by the Fargate agent to pull images / write logs); both are "
            "fixed at task launch."
        ),
        next_action_hint=(
            "Use the existing task role. At task-definition deploy time, "
            "iam-jit can scope the role you set on the definition."
        ),
        bouncer_recommended=True,
    ),
    CatalogEntry(
        id="codebuild-service-role-fixed",
        workloads=(WorkloadType.CODEBUILD_PROJECT,),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "AWS CodeBuild builds run under the project's service role, "
            "set at project creation. The build's BASE identity is the "
            "service role and cannot be changed mid-build. Buildspec code "
            "CAN call sts:AssumeRole to switch into another role, but "
            "the service role is fixed."
        ),
        next_action_hint=(
            "Use the existing CodeBuild service role. At project-create "
            "time, iam-jit can scope the service role you set on the "
            "project definition."
        ),
        bouncer_recommended=False,
    ),
    CatalogEntry(
        id="step-functions-role-fixed",
        workloads=(WorkloadType.STEP_FUNCTIONS,),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "Step Functions state machines execute under the role set on "
            "the state machine definition. Individual Task states can "
            "call other services that themselves use roles, but the SM's "
            "base identity is fixed at SM creation."
        ),
        next_action_hint=(
            "Use the existing state-machine role. At SM-create time, "
            "iam-jit can scope the role you set on the definition."
        ),
        bouncer_recommended=False,
    ),
    CatalogEntry(
        id="glue-job-role-fixed",
        workloads=(WorkloadType.GLUE_JOB,),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "AWS Glue jobs execute under the IAM role specified on the "
            "job definition. The job's base identity is fixed; job code "
            "can call sts:AssumeRole into a different role but the "
            "assigned role is the default."
        ),
        next_action_hint=(
            "Use the existing Glue job role. At job-create time, "
            "iam-jit can scope the role you set on the definition."
        ),
        bouncer_recommended=False,
    ),
    CatalogEntry(
        id="sagemaker-execution-role-fixed",
        workloads=(WorkloadType.SAGEMAKER,),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "SageMaker training jobs, processing jobs, and notebook "
            "instances each have their own execution role set at "
            "resource creation. Code in the resource can call "
            "sts:AssumeRole but the execution role is the base identity."
        ),
        next_action_hint=(
            "Use the existing SageMaker execution role. At resource-"
            "create time, iam-jit can scope the role you set."
        ),
        bouncer_recommended=False,
    ),
    CatalogEntry(
        id="app-runner-instance-role-fixed",
        workloads=(WorkloadType.APP_RUNNER,),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "AWS App Runner services use the instance role configured "
            "on the service definition. The service's base identity is "
            "fixed at service-create time."
        ),
        next_action_hint=(
            "Use the existing App Runner instance role. At service-"
            "create time, iam-jit can scope the role you set."
        ),
        bouncer_recommended=False,
    ),
    CatalogEntry(
        id="batch-job-role-fixed",
        workloads=(WorkloadType.BATCH_JOB,),
        verdict=Compatibility.USE_EXISTING,
        reasoning=(
            "AWS Batch jobs execute under the job role specified on the "
            "job definition. The job's base identity is fixed; the "
            "underlying compute (ECS / EKS / Fargate) has its own role "
            "layer as well."
        ),
        next_action_hint=(
            "Use the existing Batch job role. At job-definition-create "
            "time, iam-jit can scope the role you set."
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


def check_compatibility(
    intent: CompatibilityIntent,
    *,
    audit_sink: ConfigEventSink | None = None,
    actor: str | None = None,
) -> CompatibilityResult:
    """Pure decision: given an intent, return the verdict + reasoning
    + next-action hint.

    Sources consulted (Slice 1 — Slice 2 will add admin allowlist):
    1. Known-incompatible catalog (workload-keyed)
    2. Default: PROCEED with a generic note

    The function stays dependency-free for tests; the optional
    `audit_sink` lets the MCP handler / Slice 3 intake plumb in a real
    audit-log writer per WB24 MED-24-01 closure. When provided, every
    check produces a `compatibility_check` event with the workload +
    verdict + matched_pattern so post-incident review can answer "did
    the agent know iam-jit said use_existing for this workload?"
    """
    # WB24 MED-24-02 closure: validate the agent's role-ARN hint
    # BEFORE the catalog lookup so it surfaces in both PROCEED and
    # USE_EXISTING paths.
    cleaned_hint, hint_was_invalid = _validate_existing_role_hint(
        intent.existing_role_hint
    )

    entry = _CATALOG_BY_WORKLOAD.get(intent.workload)
    if entry is None:
        result = CompatibilityResult(
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
            existing_role_hint_invalid=hint_was_invalid,
        )
    else:
        # Catalog hit. Echo the existing-role hint back to the caller
        # if they gave us a valid one — saves an MCP round-trip.
        existing_role_arn: str | None = None
        if entry.verdict == Compatibility.USE_EXISTING:
            existing_role_arn = cleaned_hint
        result = CompatibilityResult(
            verdict=entry.verdict,
            reasoning=entry.reasoning,
            existing_role_arn=existing_role_arn,
            matched_pattern=entry.id,
            next_action_hint=entry.next_action_hint,
            bouncer_recommended=entry.bouncer_recommended,
            existing_role_hint_invalid=hint_was_invalid,
        )

    if audit_sink is not None:
        # WB24 MED-24-01 closure: log the call so the audit chain
        # captures "agent asked iam-jit if it could help; iam-jit
        # answered X." Best-effort: don't raise if the sink fails.
        try:
            audit_sink.record(
                kind="compatibility_check",
                actor=actor or "unknown",
                summary=(
                    f"workload={intent.workload.value} verdict={result.verdict.value}"
                ),
                detail={
                    "workload": intent.workload.value,
                    "target_account_id": intent.target_account_id,
                    "target_services": list(intent.target_services),
                    "description": intent.description,
                    "verdict": result.verdict.value,
                    "matched_pattern": result.matched_pattern,
                    "existing_role_arn": result.existing_role_arn,
                    "existing_role_hint_invalid": result.existing_role_hint_invalid,
                },
            )
        except Exception:
            pass

    return result


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
