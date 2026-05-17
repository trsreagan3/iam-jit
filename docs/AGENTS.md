# AGENTS.md — using iam-jit from inside an IDE agent

> If you're building a Claude Code / Cursor / custom-agent integration with iam-jit, read this doc.
> If you're a human about to use iam-jit's web UI, **also read this doc** — the recommended workflow runs through an agent even for human-driven sessions.

## The core idea

iam-jit is **scorer + catalog + gate**. It does NOT author IAM policies. The agent (with its codebase context + LLM) does the authoring; iam-jit evaluates and gates the result.

This is the architectural choice that lets iam-jit be small, reliable, and fast. The agent has information iam-jit deliberately doesn't have (source code, customer infrastructure context, the user's literal request). The agent's LLM does the narrowing reasoning. iam-jit's deterministic scorer evaluates the output honestly — no LLM in the gate, no flexible interpretation.

## When iam-jit can / can't help (call `check_iam_jit_compatibility` FIRST)

**Always start by calling `check_iam_jit_compatibility`** with the workload type you're running in. It returns one of four verdicts so you don't waste cycles trying iam-jit where it fundamentally can't help:

| Verdict | Meaning | What you do |
|---|---|---|
| `proceed` | iam-jit-the-issuer can mint a JIT role for this case | Continue with the normal flow below. |
| `use_existing` | The workload requires a fixed pre-existing role (k8s IRSA, EC2 instance profile, Lambda exec role, etc.) | Use the role declared in `existing_role_arn` (echoed back if you provided `existing_role_hint`). Don't try to mint a new one — the workload won't accept it. |
| `use_bouncer` | iam-jit-the-issuer can't help, but iam-jit-the-bouncer can | Run the local bouncer proxy (`iam-jit-bouncer`) to gate calls made via whichever role you ended up using. |
| `cannot_help` | Neither iam-jit product applies | Escalate to a human; iam-jit isn't the right tool here. |

Every non-PROCEED response includes `reasoning` + `next_action_hint` so you have a concrete path forward, not a vague error. This is the **agent-friendly-not-bypassable** contract: easy to configure for your use case, impossible to silently bypass.

### Workload types

When calling `check_iam_jit_compatibility`, classify yourself accurately:

| Workload | Typical verdict | Why |
|---|---|---|
| `k8s_pod` / `eks_pod_identity` | `use_existing` | Pod's BASE identity (the IRSA role) is fixed at pod creation. Pod code CAN call sts:AssumeRole into a different role, but that adds an explicit hop; using the IRSA role directly is simpler. |
| `ec2_instance` | `use_existing` | Code on EC2 uses the instance profile role as its BASE identity. sts:AssumeRole into other roles still works; the instance profile is what IMDS hands out by default. |
| `lambda_function` | `use_existing` | Function's BASE identity is the execution role. Function code can sts:AssumeRole mid-invocation, but the execution role is the default. |
| `ecs_task` | `use_existing` | Task's BASE identity is the Task Role. Fargate tasks have TWO roles (Task Role + Execution Role); both fixed at task launch. |
| `codebuild_project` / `step_functions` / `glue_job` / `sagemaker` / `app_runner` / `batch_job` | `use_existing` | Service-managed compute with a per-resource role pinned at resource creation. |
| `ci_runner` | `proceed` | CI runners are OIDC-federated; iam-jit can issue here. |
| `agent_local_dev` | `proceed` | Local agent on a dev laptop — iam-jit's primary case. |
| `human_cli` | `proceed` | Human at a terminal can assume any role they're permitted to. |
| `other` | `proceed` (with fallback note) | Unknown workload; iam-jit tries, with bouncer as fallback. |

Pass `target_account_id`, `target_services`, and `existing_role_hint` (if you know the existing role) for a more precise answer.

### Composition: when workloads nest

Real environments compose. Common cases:

| Composed case | Classify as | Why |
|---|---|---|
| CI runner running ON EC2 (self-hosted GitHub Actions / Buildkite runner) | `ec2_instance` | The OUTER hosting constraint wins. The runner can't escape the EC2 instance profile without an explicit AssumeRole hop. |
| Agent (Claude Code / Cursor) running IN a k8s pod | `k8s_pod` | Same rule — the pod's IRSA role is the constraint iam-jit can't change. |
| Containerized self-hosted runner on ECS / Fargate | `ecs_task` | Outer constraint wins. |
| CI job on Lambda-based ephemeral runner | `lambda_function` | Same. |
| Lambda calling another Lambda | `lambda_function` | The calling function's execution role is the constraint. |

**Rule of thumb:** classify by the OUTER hosting environment — that's the constraint iam-jit can't change. When in doubt, pick the workload type that's the BASE identity of the AWS API call (what would show up as `userIdentity.sessionContext.sessionIssuer.userName` in CloudTrail if you made the call right now).

### Admin allowlist overrides

Your org's admin may have configured per-account / per-workload overrides via the compatibility allowlist (`docs/COMPATIBILITY-ALLOWLIST.md`). When that's the case, `check_iam_jit_compatibility` returns the admin verdict (which may differ from the catalog default) and sets `matched_pattern` to `allowlist:<rule_id>` so you can tell. Read what your org has configured via the `list_compatibility_overrides` MCP tool. Agents can READ the allowlist but cannot mutate it — only admins, via CLI.

### Why this matters

iam-jit's whole model is "create a NEW short-lived role" (per [[creates-never-mutates]]). For workloads where the role is fixed at creation time (k8s IRSA, EC2 IP, Lambda exec, CodeBuild, Glue, etc.), the BASE identity can't be swapped at runtime — though sts:AssumeRole into a different role is technically possible. The practical answer for most workloads is "use the fixed role directly; add an iam-jit hop only when you specifically need scoping the base identity doesn't provide."

Without the compatibility check, an agent would waste cycles trying iam-jit, fail mysteriously, and eventually reach for "disable iam-jit, give me admin" — exactly the failure mode iam-jit is designed to prevent. **Always check first.** If you're also calling `submit_policy`, pass the same `workload` argument — `submit_policy` re-runs the check and refuses USE_EXISTING workloads with a clear redirect (per WB24 HIGH-24-01 closure). Omitting `workload` from `submit_policy` is bypass-able but audit-logged as `submit_without_compatibility_check` so admins can spot it.

## The four MCP tools

| Tool | Purpose | Returns |
|---|---|---|
| `list_templates` | Browse the catalog | `{templates: [{name, arn, source, summary, services, access_type}, …]}` |
| `get_template` | Fetch a template's policy shape | `{name, arn, policy, …}` |
| `score_iam_policy` | Rate any policy 1–10 with factor detail | `{score, tier, factors: [{name, contribution, suggested_remedy}], recommended_action}` |
| `submit_policy` | Submit a policy for grant issuance | `{request_id, score, status, review_url, …}` |

That's the complete agent-facing surface. There is no `generate_iam_policy`, no `narrow_for_me`, no `suggest_reductions`. The agent does the work; iam-jit scores and gates.

## The decision at intake — known vs. unknown

Before the reduction loop, the agent makes one decision:

**Are the needed resources specific and known?**

- **YES** → use a **parameterized task template** from the catalog.
  Examples: `update-one-secret(arn)`, `download-one-file(bucket, key)`,
  `invoke-one-lambda(arn)`, `read-one-cloudwatch-log-group(arn)`.
  Fill in the ARN(s), submit. Resulting policy scores 1-3 and
  almost always auto-approves. **No reduction loop needed.**

- **NO / not yet known** (investigation, exploration, multi-resource
  work) → use a **broad baseline** and reduce from there:
  - Read-only / investigation → `ExploreReadOnlyWithSensitiveExclusions`
  - Write / admin-class → `AdminLikeWithSensitiveExclusions`
  - Run the reduction loop below to narrow toward auto-approval.

Pick the path that matches the task. Don't run the full loop on
"update this one secret" — that's wasted iterations. Don't try
to use a parameterized template for "investigate why X is broken" —
you can't enumerate the resources up front.

## The reduction loop (for the "unknown" path)

```
1. Pick a starting point
   - User describes the task in natural language
   - Agent reads source code to infer scope (which services, which
     resources, which account, which region)
   - Agent calls list_templates() to see what's available
   - Agent picks the broad baseline appropriate to the task class

2. Score
   - Agent calls score_iam_policy(<policy>)
   - Returns { score, factors: [...] }

3. Reduce (the core of the loop)
   - Agent reads the factor breakdown
   - For each factor that's pushing the score up, agent decides:
     - drop a service?     → add Deny on <service>:*
     - narrow resources?   → replace Resource: "*" with explicit ARNs
     - drop action class?  → strip Create*/Put*/Update*/Delete* from Allow
     - scope region/account? → add aws:RequestedRegion / sts:ExternalId
   - The agent uses ITS CODEBASE CONTEXT to know what's safe to drop
   - iam-jit doesn't see source code; only the agent can do this well

4. Re-score
   - Agent calls score_iam_policy(<reduced policy>) again
   - If score < threshold: submit
   - Else: repeat step 3

5. Submit
   - Agent calls submit_policy(<final policy>)
   - iam-jit gates: auto-approves if score < threshold AND safety mode allows
   - If not auto-approved: returns review_url for human approval
```

## A worked example

User: "investigate why the wallet-svc is throwing 500s after the v2.4 deploy"

```
1. PICK
Agent reads source: wallet-svc lives in account 123, uses
ECS + CloudWatch logs + DynamoDB. Doesn't touch RDS, secrets,
or sensitive S3.

Agent → list_templates(access_type="read-only")
        → returns [ReadOnlyAccess, ExploreReadOnly..., SecurityAudit,
                   AmazonECS-ReadOnly, ...]

Agent picks ExploreReadOnlyWithSensitiveExclusions as the baseline
because it's an investigation task with broad-but-bounded read.

Agent → get_template("ExploreReadOnlyWithSensitiveExclusions")
        → returns full policy shape

2. SCORE
Agent → score_iam_policy(<that policy>)
        → score=7, factors=[
            {name: "broad_resource", contribution: 3,
             suggested_remedy: "narrow Resource ARNs"},
            {name: "cross_service", contribution: 2,
             suggested_remedy: "drop services not needed for the task"},
            {name: "explicit_deny_credit", contribution: -1, …}
          ]

3. REDUCE
Agent reasons (using codebase context):
- "wallet-svc doesn't touch RDS — drop it"  → adds Deny rds:*
- "we only care about account 123" → adds aws:RequestedAccount
  condition
- "we only need us-east-1" → adds aws:RequestedRegion

4. RE-SCORE
Agent → score_iam_policy(<reduced policy>)
        → score=4

5. SUBMIT
Agent → submit_policy(<reduced policy>)
        → AUTO-APPROVED (score < threshold of 5)
        → returns STS credentials

User sees: nothing. Investigation proceeds. Audit log shows
"based on ExploreReadOnlyWithSensitiveExclusions, narrowed by
[deny rds:*, account 123, region us-east-1], score 4, auto-approved".
```

## Three axes of reduction

Per [aws-managed-baseline-strategy](#) and the templates docs:

| Axis | Mechanism | Example |
|---|---|---|
| **Service-level** | Add `Deny <service>:*` | "wallet-svc doesn't touch RDS" → deny rds |
| **Action-class** | Strip Create/Put/Update/Delete from Allow | "this task is read-only" → strip write verbs |
| **ARN narrowing** | Replace `Resource: "*"` with explicit ARNs + region/account conditions | "only account 123, only us-east-1" → conditions |

The agent picks any combination based on what its codebase context tells it.

## Writes — the asymmetric gate

iam-jit defaults to read-only per [the read-only-default contract](./recipes/agent-safety-mode.md). When the agent needs writes:

- Submit a SEPARATE policy with `access_type: read-write`
- iam-jit scores writes more aggressively than reads (smaller blast radius for the same factors)
- Default safety mode (`read_write_swap`) prompts the user the first time a write goes through; subsequent writes in the same session pass without prompt if mode is set to auto-elevate
- Strict mode requires per-write user approval — opt-in for compliance environments

This is the asymmetry that matters: ~80% of agent operations are reads with near-zero blast radius; ~20% writes carry ~all the risk. Don't fight the friction asymmetry — embrace it.

## Anti-patterns

- ❌ **Don't ask iam-jit to generate a policy from the user's natural-language request.** The deterministic NL synthesis path was measured and removed when it didn't deliver. You (the agent) have codebase context iam-jit doesn't; you do the narrowing.

- ❌ **Don't loop on `score_iam_policy` blindly trying random reductions.** Read the factor breakdown; pick the highest-contribution factor; address it specifically. Each call costs ~50ms; ~3 iterations is a reasonable budget. **Better: group changes** — apply service-list narrowing + account-condition + region-condition in a single revised policy, then re-score once. Faster than asking the user one question per round.

- ❌ **Don't request `access_type: read-write` by default.** Reads first. Elevate explicitly when the user has stated they want a state-changing operation.

- ❌ **Don't paper over a low-but-insufficient score.** If the policy scores 4 but actually can't do the task, that's worse than a 6 that works — the user will hit a permission error mid-task. Better to score honestly and have the user approve.

- ❌ **Don't store the issued STS credentials beyond their TTL.** The audit log expects them to be ephemeral.

## Human users with no agent: the fallback path

The reduction loop is designed for agents because agents have codebase context. If a human user is at the iam-jit web UI with no agent and no policy in hand, the UI offers exactly one fallback recommendation:

> **`AdminLikeWithSensitiveExclusions`** — broad authority with secrets / KMS-decrypt / sensitive S3 buckets / audit-infra destruction explicitly denied. Score: high (will need approval). Audit chain: "based on `AdminLikeWithSensitiveExclusions`, submitted by alice without further narrowing."

The UI does NOT have:
- A "describe what you want to do" text box (no NL synthesis)
- A "narrow this for me" button (no iam-jit-side reasoning over the policy)
- An LLM that drafts/edits the policy on iam-jit's side

iam-jit recommends a known-good starting point and gets out of the way. The user can:

1. **Submit as-is** → goes to human approval (score will be high)
2. **Edit manually** → modify the JSON, re-score, re-submit
3. **Pull up their agent** → ask Claude / Cursor / etc. to reduce it for them against their codebase context, per the loop above

Option 3 is the recommended path even for "I'm just using the web UI" users. The agent doesn't need to drive the whole session — just the reduction step. The agent reads the user's repo, knows what services this team's workloads actually touch, and produces a narrowed policy. The user takes that JSON back to the iam-jit UI and submits.

This is why the docs encourage agents EVEN FOR human-driven sessions: they're the only place where codebase context lives, and codebase context is what makes narrowing tractable.

**Pro-tier option (planned):** for agentless users who don't want to edit JSON, iam-jit's Pro tier offers a conversational LLM-guided reduction walkthrough in the web UI. The UX is a single "which of these do you NOT need" multi-select checklist — ~8-12 curated high-impact items (NOT an exhaustive AWS service list). Defaults pre-checked for the sensible-defaults deny set (secrets, KMS decrypt, sensitive-pattern S3, audit-infra destruction). User adjusts, picks accounts/regions, submits in one shot. The LLM acts as UX, not as policy author — user's answers drive deterministic modifications, which go through the same scorer. Different category from the NL synthesis we removed. Checklist items are CURATED by score-impact (presence/absence shifts the scorer by ≥1 point) and customer-configurable per Pro+ org. See `project_ui_guided_reduction_pro_tier` memo for the full design.

## Strict-mode considerations

In `strict` safety mode (compliance environments):
- Action wildcards (`s3:*`, `*:Describe*`) are rejected at the gate
- Admin-fallback (the "if all else fails, ask a human" escape) is disabled
- Per-operation approval is required for writes
- Most reductions need to be narrower than the lean-permissive defaults

If the agent's first reduction round produces an action-wildcard policy and the gate rejects, the agent should respond by listing the specific actions explicitly (e.g., `s3:GetObject + s3:ListBucket + s3:GetObjectVersion` instead of `s3:Get*`).

## Where to find more

- [README.md](../README.md) — top-level overview
- [docs/RECOMMENDER-API-SPEC.md](./RECOMMENDER-API-SPEC.md) — API spec
- [docs/recipes/agent-safety-mode.md](./recipes/agent-safety-mode.md) — local-mode safety pattern
- [docs/calibration/100-prompt-sufficiency-loop.md](./calibration/100-prompt-sufficiency-loop.md) — calibration measurement that informed the architectural decision not to author policies
- [docs/ROADMAP-V1.1.md](./ROADMAP-V1.1.md) — post-launch scope
