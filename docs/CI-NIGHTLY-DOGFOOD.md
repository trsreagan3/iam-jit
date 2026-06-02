# Nightly CI dogfood

**Status:** spec (2026-05-28); implementation in progress.

**Purpose:** catch the class of bug that took 19 findings to surface across two manual dogfood passes this week (#691 + #699). Per the [process audit](./PROCESS-AUDIT-2026-05-28.md), a single recurring CI job exercising the full chain on a real AWS account would have caught most of those findings at commit time instead of at the next manual UAT.

This document is the **contract** the CI workflow + companion sweeper enforce. Any change to the contract — new fail conditions, new stacks, new cleanup rules — goes through this doc.

## Scope

What the nightly run does, every night, regardless of whether anyone is watching:

1. **Bootstrap** — fresh venv install of iam-jit; assert imports work; assert `upstream_resolver` (#687) module loads; assert `_resources.find('infrastructure','cloudformation','destination-account-roles.yaml')` succeeds (#692 regression guard).
2. **Three stacks**, each running the full chain:
   - **Stack 1 (VPC + EC2)** — exercises HIGH-1 (plan-capture XML), MED-4 (apigateway parser stays clean), MED-5 (operator tags), HIGH-2 (verify-role).
   - **Stack 2 (Lambda + API Gateway)** — exercises MED-4 (apigateway action names), HIGH-3 (solo MFA threshold), HIGH-4 (JSON round-trip), MED-5.
   - **Stack 3 (S3 + IAM)** — exercises HIGH-5 (token API on-behalf-of), LOW-2 (reconciler).
3. **Per stack sub-phases** (deterministic, no LLM agent involved at CI time):
   - plan-capture (boto3 calls through ibounce-in-plan-capture-mode; no AWS state changes)
   - iam-jit request submission (auto-approve at low risk score)
   - role provisioned (IAM resource — zero $$$ but real AWS state)
   - `iam-jit verify-role` (SimulatePrincipalPolicy with auto-injected `aws:CurrentTime`)
   - accuracy cross-check (AssumeRole + 1-2 read-only Describe calls return real data — proves the simulator isn't lying)
   - negative-perm test (action NOT in captured plan → AccessDenied)
   - cleanup via `iam-jit remote revoke` (NOT raw curl — exercises the new CLI path)
4. **Schema drift guard** — runs `tests/test_packaged_data_in_sync.py`; fails CI on any new drift between canonical and shipped data files.
5. **Final reconciliation** — after cleanup, verify zero tagged resources remain via `resourcegroupstaggingapi`.

**Out of scope:** real-cost resources (EC2 RunInstances, RDS, real Lambda invocations, real S3 uploads). The dogfood proves the *control plane* works (capture → request → role → simulate → verify); cost-incurring data-plane operations stay in human-triggered UATs.

## Cost contract

- **$0 expected** per nightly run. IAM roles + policies are free; SimulatePolicy is free; Describe calls are free.
- **CloudWatch budget alarm** on the test account: `>$5/day` on the `Project=iam-jit-ci-nightly` tag triggers a Slack/email notification (configured separately — see setup steps).
- **Hard kill** at 30 min wall-clock per run. The workflow `timeout-minutes: 30` is the outer fence; the script's per-stack `time.monotonic()` budget is the inner.

## Fail conditions

Each is a CI failure (script exit non-zero). Order matters — first-fail-stops:

| # | Check | Regresses if... |
|---|---|---|
| F1 | Fresh `pip install /Users/reagan/repos/iam-roles` succeeds | #692 returns OR setuptools breaks |
| F2 | `from iam_jit.onboarding import OnboardingPlan` succeeds | #692 returns |
| F3 | `from iam_jit.bouncer import upstream_resolver; assert canonical_aws_endpoint('sts','us-east-1') == 'sts.us-east-1.amazonaws.com'` | #687 returns |
| F4 | `iam-jit verify-role --help` exits 0 | HIGH-2 CLI removed |
| F5 | `iam-jit remote revoke --help` exits 0 | MED-2 CLI removed |
| F6 | `iam-jit serve --local --help \| grep account-id` succeeds | MED-1 flag removed |
| F7 | `pytest tests/test_packaged_data_in_sync.py` passes | New schema drift |
| F8 | Per stack: plan-capture script runs through without `botocore.parsers.ResponseParserError` | HIGH-1 returns |
| F9 | Per stack: `iam-jit remote submit` response → `json.loads(response.text)` succeeds | HIGH-4 returns |
| F10 | Per stack: provisioned role has BOTH operator tag (`RunId=<gh_run_id>`) AND iam-jit's `managed-by` tag | MED-5 returns OR provisioning tags wrong |
| F11 | Per stack: `iam-jit verify-role <arn>` returns `allowed` for every captured action | HIGH-2 returns OR provisioned policy too narrow |
| F12 | Per stack: AssumeRole + read-only Describe returns real data (accuracy cross-check) | Role's policy missing perms OR trust policy wrong |
| F13 | Per stack: assumed-role call to out-of-scope action (e.g. `iam:ListUsers`) returns AccessDenied | Role over-scoped |
| F14 | Stack 2 specific: audit log shows `apigateway:CreateRestApi` (NOT `apigateway:POST`) | MED-4 returns |
| F15 | Stack 2 specific: low-risk-score request auto-approves in solo mode | HIGH-3 MFA threshold regression |
| F16 | Stack 3 specific: Token API admin-on-behalf-of works + non-admin → 403 | HIGH-5 returns |
| F17 | Reconciler scenario: manually delete provisioned IAM role; wait 15s; assert request transitions to `revoked` with `reason="RECONCILED..."` | LOW-2 returns |
| F18 | Per stack: cleanup (`iam-jit remote revoke`) succeeds AND IAM role deleted | Revoke or provisioner broken |
| F19 | After all cleanup: `aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=iam-jit-ci-nightly` returns ZERO resources for the current run | Orphan leak |

**New findings added later go here.** Every dogfood finding becomes a fail condition. This is the regression vault.

## Cleanup contract

Every resource the dogfood creates is tagged with **three** tags, all required:

- `Project=iam-jit-ci-nightly` (constant — identifies as dogfood-owned)
- `RunId=<github_run_id>` (per-run unique)
- `CreatedAt=<ISO8601 UTC>` (for age-based sweeper)

**Per-run cleanup** (in the dogfood script):

- `try`/`finally` block around every stack — finally runs even if assertions fail mid-flight.
- Cleanup uses `iam-jit remote revoke` (exercises the MED-2 path); falls back to raw `aws iam delete-role-policy && aws iam delete-role` if revoke fails (so a broken revoke doesn't leak).
- Verifies role gone via `aws iam get-role` → expect `NoSuchEntity`.

**Orphan sweeper** (separate workflow):

- Runs every 4 hours independently.
- Queries `resourcegroupstaggingapi` for `Project=iam-jit-ci-nightly`.
- For each result: if `CreatedAt` > 6 hours ago, delete it.
- Sweeper fires Slack alarm if it had work to do (means a per-run teardown leaked — should be investigated, even if the sweep cleaned up).

## AWS setup (one-time, founder action — automated)

One command, idempotent + reversible:

```bash
AWS_PROFILE=iam-jit AWS_REGION=us-east-1 scripts/deploy-ci-dogfood-iam.sh
```

The script deploys [`infrastructure/cloudformation/ci-nightly-dogfood.yaml`](../infrastructure/cloudformation/ci-nightly-dogfood.yaml), which provisions:

- **IAM role** `iam-jit-ci-nightly` in the deploying account, with a trust policy scoped to GitHub OIDC for `repo:trsreagan3/iam-jit:ref:refs/heads/main`, `repo:trsreagan3/iam-jit:pull_request`, and `repo:trsreagan3/iam-jit:ref:refs/tags/*`.
- **Inline permissions** — the minimum required by the 19 F-conditions:
  - `iam:CreateRole/DeleteRole/PutRolePolicy/DeleteRolePolicy/GetRole/GetRolePolicy/ListRolePolicies/ListAttachedRolePolicies/TagRole/UntagRole/ListRoleTags` scoped by ARN pattern to `iam-jit/*`, `iam-jit-grant-*`, and `iam-jit-local-provisioner` — for the iam-jit provisioning + verification flow.
  - `iam:SimulatePrincipalPolicy` + `iam:SimulateCustomPolicy` (F11 authorization checks).
  - `sts:AssumeRole` scoped to the same grant-role ARN patterns (F12 accuracy cross-check) + `sts:GetCallerIdentity`.
  - `tag:GetResources` (F19 + sweeper).
  - Read-only Describe/List for the services the stacks use: `ec2:Describe*`, `lambda:ListFunctions/GetFunction/ListLayers`, `apigateway:GET`, `s3:ListAllMyBuckets/GetBucketLocation/GetBucketTagging`, `dynamodb:ListTables/DescribeTable`.
- **GitHub OIDC provider** — created if not already present; reused if the script's pre-flight check finds an existing one (AWS permits exactly one per issuer URL per account).
- **AWS Budget** `iam-jit-ci-nightly-cost-guard` — $10/day kill-switch with email notification at 100% threshold.

The script:
1. Validates `aws sts get-caller-identity` succeeds + prints the account ID before any change lands.
2. Probes existing OIDC providers + applies a **stack-ownership check** (#709): if the found OIDC ARN is already managed by THIS stack, the script clears `ExistingOidcProviderArn` before calling CFN (keeping CFN ownership).  Only passes the ARN to CFN when the provider is owned by a different stack or created externally.  See `tests/integration/SCRIPT-DEPLOY-OIDC-SCENARIOS.md` for the full scenario matrix.
3. Runs `aws cloudformation deploy --no-fail-on-empty-changeset` (idempotent).
4. Verifies the role exists post-deploy + warns if the workflow YAML's `role-to-assume` doesn't match the deployed ARN.

> **Re-deploy safety (fixed in #709):** It is safe to re-run this script at any time. Before the fix, re-deploying when the OIDC provider was CFN-managed would silently delete it (causing the next CI run to fail). The ownership check prevents this: a re-deploy where the stack owns the OIDC keeps CFN in control and makes no destructive changes.

Reverse with `aws cloudformation delete-stack --stack-name iam-jit-ci-nightly --region us-east-1`.

The workflow uses GitHub OIDC; **no long-lived AWS keys in repo secrets**.

### Optional: Slack failure notifications

Add `SLACK_DOGFOOD_WEBHOOK` to repo secrets if you want the workflow to post failures to Slack. Without it, the workflow still fails the build — Slack is for low-latency notification, not gating.

## Schedule

- **Nightly**: `cron: '0 2 * * *'` (02:00 UTC — low cost, doesn't compete with US work hours).
- **On every push to main**: catches commits before they bake in.
- **`workflow_dispatch`**: manual trigger for ad-hoc verification.

## File layout

```
.github/workflows/
  dogfood-nightly.yml          ← the recurring run
  dogfood-orphan-sweeper.yml   ← every 4h, separate workflow
tests/integration/
  dogfood_real_aws.py          ← deterministic script the workflow runs
  dogfood_real_aws_test.py     ← pytest wrapper for local dev
  dogfood_stacks/
    stack_1_vpc_ec2.py
    stack_2_lambda_apigw.py
    stack_3_s3_iam.py
  dogfood_cleanup.py           ← shared finally-block helpers
docs/
  CI-NIGHTLY-DOGFOOD.md        ← this file
  PROCESS-AUDIT-2026-05-28.md  ← context for why this exists
```

The script is **deterministic Python**, not an LLM agent. CI runs are debuggable, reproducible, version-controlled. Adding a new finding to the regression vault is a code commit + PR review — not a new agent brief.

## Maintenance

- Every new finding from a future manual UAT pass becomes a fail condition here (a new `F<N>` row in the table + an assertion in the script).
- Schema drift guard (`test_packaged_data_in_sync.py`) is part of the F-list (F7) — new mirror pairs must be added there too.
- Per-stack stack scripts grow when new AWS surface needs coverage (e.g. RDS, CloudWatch).
- Cost ceiling tightens over time — the budget alarm should never fire; if it does, investigate.

## Open questions deferred

- **Multi-region**: today only us-east-1. If iam-jit ever ships region-specific behavior, the matrix grows.
- **Multi-account**: today only the founder's account 590519617224. Cross-account provisioning (the canonical iam-jit prod shape) would need a second account.
- **Multi-LLM**: when classifier LLM backend matters for scoring, run the dogfood across backends.

These are post-v1.0 expansions, not v1.0 blockers.

## Running locally

The dogfood is plain Python; no Docker required. From the repo root:

```bash
# Bootstrap-only — no AWS calls. F1..F8 + F19 verified; F9..F18 SKIP.
# Safe on any machine with the venv installed.
.venv/bin/python tests/integration/dogfood_real_aws.py --dry-run

# Full run against the founder's account. F1..F19 all exercised.
AWS_PROFILE=<your-profile> \
AWS_DEFAULT_REGION=us-east-1 \
IAM_JIT_CI_ACCOUNT_ID=590519617224 \
IAM_JIT_CI_RUN_ID=local-$(date +%s) \
.venv/bin/python tests/integration/dogfood_real_aws.py

# Or via pytest (skipped by default; -m integration unlocks):
.venv/bin/python -m pytest tests/integration/dogfood_real_aws_test.py -m integration
```

**Port collision risk on dev boxes**: the script binds `127.0.0.1:18765`
(serve) + `127.0.0.1:18767` (ibounce). If those are already in use the
script aborts with a clear error before touching AWS. In CI both ports
are fresh, so no collision; locally, kill any prior `iam-jit serve`
(`lsof -ti :18765 | xargs kill`) before re-running.

**Add `--keep-state`** to retain the temp data dir on exit (useful for
debugging a failing F-check by inspecting the audit DB the script wrote).

## Done definition

This spec is "done" when:

1. ✅ This doc exists (you are reading it).
2. ✅ `tests/integration/dogfood_real_aws.py` exists + runs `--dry-run` end-to-end locally (F1..F8 + F19 verified).
3. ✅ `.github/workflows/dogfood-nightly.yml` exists with OIDC + 30-min timeout + cron + push + dispatch triggers.
4. ✅ `.github/workflows/dogfood-orphan-sweeper.yml` exists with 4-hour cron + dispatch + OIDC sweep.
5. ⬜ The 19 fail conditions are all asserted in the script + verified to fire on first real CI run (founder action: dispatch + induce one regression as smoke test).

The dogfood script asserts F1..F19 in order; see the F-checklist at
the bottom of every run for which checks PASSED / FAILED / SKIPPED.

#691 + #699 surfaced 19 production bugs over two manual passes. The job of this contract is to make pass #3 onward catch them at commit time.
