# Round 24 audit — applicability framework Slice 1 (#166)

Commit under review: `340e26b` (`feat(applicability): Slice 1 — compatibility checker + curated catalog + MCP tools (#166)`).

Scope (Slice 1 only — Slices 2-4 ship in subsequent commits):
- `src/iam_jit/compatibility.py` (new, 372 LOC)
- `src/iam_jit/mcp_server.py` (2 new MCP tools + handlers, +158 LOC)
- `tests/test_compatibility.py` (new, 321 LOC; 29 tests)
- `docs/AGENTS.md` (added top-level "When iam-jit can / can't help" section, +34 lines)

Read-only audit. Per [[audit-cadence-discipline]].

Regression: **2313 passed**, 29 skipped, 14 deselected (87.6s, excluding `tests/e2e/*` which needs `playwright`, and `tests/test_calibration_corpus.py` which has the well-known pre-existing failures). Matches the audit-prompt baseline (2313) exactly. No regressions caused by Slice 1.

## Headline

11 findings: **0 CRIT, 2 HIGH, 4 MED, 5 LOW.**

The two HIGH findings are the same trust-gap shape WB21/WB22/WB23 keep finding. **HIGH-24-01**: the MCP tool description tells agents to "call FIRST when in an unfamiliar environment" and AGENTS.md says "Always start by calling `check_iam_jit_compatibility`" — but `submit_policy`, `score_iam_policy`, and the rest of iam-jit's MCP surface do NOT check that compatibility was ever called. Grep confirms zero downstream consumers of the verdict inside `src/iam_jit/`. An agent that ignores the doc submits a policy for a `k8s_pod` workload, iam-jit issues a JIT role, the pod can't use it, and the agent reaches for "disable iam-jit, give me admin" — exactly the failure mode the [[iam-jit-inapplicable-cases]] memo says this feature exists to prevent. Same pattern as WB22 (UI guided reduction's "we recommend" with no enforcement) and WB23 LOW-23-04 (`iam-jit bouncer` discoverability gap). **HIGH-24-02**: the catalog reasoning text for `k8s_pod`, `ec2_instance`, `lambda_function`, and `ecs_task` is technically wrong about the AWS IAM semantics — it says "the running pod/instance/function cannot choose a different role at runtime," but all four can call `sts:AssumeRole` to switch into a different role mid-execution (the BASE identity is fixed; the assume-chain isn't). Agents reading this catalog will believe iam-jit-issued roles fundamentally CAN'T be used from inside these workloads, which is false. The practical recommendation (use the workload's built-in role; don't add an iam-jit AssumeRole hop unless you specifically want one) is sound; the IAM-semantics CLAIM is wrong; fixing the claim while keeping the recommendation is a docs change in `compatibility.py:CATALOG`.

The four MEDs: **MED-24-01** — `check_compatibility` is PURE; no audit-log entry is written. Per [[agent-friendly-not-bypassable]] Lens B (uncircumventable) every config-shape decision iam-jit makes should be auditable; a compatibility check that returns USE_EXISTING and then the agent goes off and assumes some random role has zero record on the iam-jit side ("did the agent even ASK us first?"). Should write a config_event row (Slice 2 territory; flag now). **MED-24-02** — `existing_role_hint` is echoed back to the caller verbatim with ZERO ARN-format validation. An agent (or a prompt-injected agent) could pass `"haha not a real ARN"` and Slice 3's DEFER_TO_EXISTING outcome integration could trust it. Verified: `existing_role_hint='haha not a real ARN'` → `existing_role_arn='haha not a real ARN'` in the dict. **MED-24-03** — workload classification edge cases are unaddressed in code AND in docs: a CI runner running INSIDE an EC2 instance (very common — self-hosted GitHub Actions runner on EC2) classifies as one or the other; `ci_runner` says PROCEED and `ec2_instance` says USE_EXISTING; whichever the agent picks wins, but neither AGENTS.md nor `compatibility.py` warns about composition. Same for "agent in a k8s pod," "containerized self-hosted runner on ECS," etc. **MED-24-04** — `CANNOT_HELP` and `USE_BOUNCER` verdicts are defined in the enum but NO catalog entry returns either. Verified by enumerating every WorkloadType: only `proceed` and `use_existing` ever come out. Two of the four documented verdicts are dead.

The five LOWs: catalog is materially incomplete (no entries for Step Functions, CodeBuild, App Runner, Glue jobs, Fargate task-vs-execution split, EventBridge — each is a USE_EXISTING shape the catalog should grow to cover) — flagged as incomplete-not-wrong; the `description` field on `CompatibilityIntent` is wholly unused (zero references in the module; `ast.walk` confirms) and dropped silently by both the checker and the MCP handler — dead field; the "first-match-wins" comment in `compatibility.py:301-302` describes a discipline that isn't exercised (every workload appears in exactly ONE catalog entry; the first-match path can't fire) and has no test that would catch a future contributor reordering entries; `docs/IAM-JIT-BOUNCER.md` does NOT mention being the fallback for fixed-role workloads, even though the compatibility-checker's `next_action_hint` text repeatedly points at it — cross-doc asymmetry; MCP tool input validation accepts `target_account_id="not-an-account-id"` (no 12-digit-string check), `target_services=["not-a-real-service"]` (no AWS service-prefix check), and `existing_role_hint="not-an-arn"` (no ARN-format check) — not security bugs (the checker is read-only) but they're agent-UX issues that lead to confident-but-wrong responses, plus they propagate into Slice 3 / future audit logs.

Verified clean (no findings): the inputSchema `enum` list in the MCP tool definition matches the `WorkloadType` enum exactly (8 fixed-role + OTHER); the `to_dict` shape is consistent with the MCP `structuredContent` plumbing; every catalog entry has a non-empty `next_action_hint` (test enforced); `bouncer_recommended=False` for Lambda is correctly the documented exception; the per-workload verdict tests cover every WorkloadType.

## Closure status

| Finding | Status |
|---|---|
| HIGH-24-01 MCP tool description ("call FIRST") not enforced by any other tool; `submit_policy` / `score_iam_policy` don't check that compatibility was called; pure honor system | OPEN |
| HIGH-24-02 Catalog reasoning text for k8s/EC2/Lambda/ECS overstates the IAM-semantics claim ("cannot choose a different role at runtime"); these workloads CAN call sts:AssumeRole — the BASE identity is fixed, not the assume chain | OPEN |
| MED-24-01 `check_compatibility` writes no audit-log entry; per [[agent-friendly-not-bypassable]] Lens B the question "did the agent ask iam-jit before doing X?" is unanswerable; Slice 2/3 will need this for the DEFER_TO_EXISTING outcome integration anyway | OPEN |
| MED-24-02 `existing_role_hint` is echoed to caller verbatim with ZERO ARN-format validation; "haha not a real ARN" → `existing_role_arn="haha not a real ARN"`; Slice 3's DEFER_TO_EXISTING outcome integration may trust this | OPEN |
| MED-24-03 Workload-composition edge cases (CI runner ON EC2, agent IN k8s pod, ECS task that IS a CI runner) are unaddressed in code OR docs; agent picks whichever classification it picks; results diverge | OPEN |
| MED-24-04 `Compatibility.CANNOT_HELP` and `Compatibility.USE_BOUNCER` defined in enum but no catalog entry returns either; two of the four advertised verdicts are dead from the checker's surface | OPEN |
| LOW-24-01 Catalog incomplete: no entries for Step Functions, CodeBuild, App Runner, Fargate (task vs execution split), Glue jobs, EventBridge, Batch — each is a likely USE_EXISTING shape | OPEN |
| LOW-24-02 `CompatibilityIntent.description` field unreferenced anywhere in the module (verified via `ast.walk`); accepted by MCP handler but dropped silently | OPEN |
| LOW-24-03 "First-match-wins" comment at `compatibility.py:301-302` describes a discipline not exercised by any current entry (each workload appears in exactly 1 entry) and no test catches future reordering / duplicate-workload entries | OPEN |
| LOW-24-04 `docs/IAM-JIT-BOUNCER.md` does NOT mention being the fixed-role-workload fallback; the compatibility-checker's `next_action_hint` text repeatedly points there but the bouncer doc itself is silent about the role | OPEN |
| LOW-24-05 MCP input validation accepts nonsense (`target_account_id="not-an-account-id"`, `target_services=["not-a-real-service"]`, `existing_role_hint="not-an-arn"`); agent gets confident-looking response on garbage input | OPEN |

## HIGH findings

### HIGH-24-01 — MCP tool description claims "call FIRST"; no other tool enforces this

- Files:
  - `src/iam_jit/mcp_server.py:651-663` (tool description: "Call this FIRST when you're about to use iam-jit in an unfamiliar environment")
  - `docs/AGENTS.md:14` ("**Always start by calling `check_iam_jit_compatibility`** with the workload type")
  - `src/iam_jit/mcp_server.py:1768-1980` (`_submit_policy_for_mcp` — no compatibility check)
  - `src/iam_jit/mcp_server.py` `_score_for_mcp`, every other tool handler — none check

- Issue: the MCP tool's `description` field and `docs/AGENTS.md`'s top-level new section both tell the agent that `check_iam_jit_compatibility` is the FIRST thing it should call. The promise is concrete and load-bearing — the whole reason Slice 1 exists per the commit message is to give agents a "clear iam-jit can't help here signal BEFORE submitting a request so they don't waste cycles → reach for 'disable iam-jit, give me admin.'" But:
  - `submit_policy` accepts and processes any policy regardless of whether `check_iam_jit_compatibility` was ever called.
  - `score_iam_policy` likewise.
  - The result of the compatibility check is NOT stored anywhere iam-jit can retrieve later (Lens B audit-log gap — see MED-24-01).
  - No session/request id is threaded from `check_iam_jit_compatibility` into subsequent calls.

  Verified: `grep -rn "compatibility\|check_iam_jit_compat" src/iam_jit/ | grep -v "compatibility.py\|mcp_server.py"` returns ONLY incidental matches in `review.py` (NFKC normalization, unrelated). No other module reads the verdict.

  So an agent that ignores the doc and goes straight to `submit_policy` for a `k8s_pod` workload submits a policy → iam-jit issues a JIT role → the pod can't actually USE that role (its identity is bound to the IRSA role baked into its spec at pod creation) → agent fails mysteriously and concludes "iam-jit is broken." Which is exactly the failure mode [[iam-jit-inapplicable-cases]] (cited in the commit message) says this feature exists to prevent.

- Why HIGH (not CRIT): the feature still works for agents that DO call the checker (the docs path). And no security boundary is breached — failing the wrong way doesn't grant extra access. But the feature's stated value — "saves cycles trying iam-jit where it fundamentally can't help" — is moot if iam-jit doesn't notice when the cycles are skipped. This is the same trust-gap shape that WB21/WB22/WB23 found in their respective features (guided-reduction recommendation not enforced, live-action-tail subscription not gated, `iam-jit bouncer` discoverability missing). Pattern: a Lens-A (agent-friendly) docstring without a Lens-B (uncircumventable) enforcement.

- Fix options:
  1. **Best**: `submit_policy` accepts an optional `workload` arg; if provided, runs `check_compatibility` and BLOCKS with "this workload requires use_existing — request a different shape" when the verdict is USE_EXISTING / CANNOT_HELP. Default behavior (no workload provided) prints a one-line note in the response: "no workload declared; if you're in a fixed-role environment (k8s, EC2, Lambda) call `check_iam_jit_compatibility` first." Either path makes the contract concrete.
  2. **Acceptable**: thread a `compatibility_check_id` from the checker through subsequent calls. The checker writes a config_event with an id; `submit_policy` accepts (optionally) the id and includes it in its own audit-log entry. Doesn't BLOCK, but makes the chain auditable.
  3. **Minimum**: add a warning string to `submit_policy`'s return shape when the (newly-added) `workload` arg is absent, AND a unit test that imports both tools and asserts the cross-tool wiring exists.

  Recommend option 1 for Slice 2 (gates the easy-to-miss-with-DEFER_TO_EXISTING flow that ships next anyway). Option 2 is the right shape if the team prefers no-blocking.

### HIGH-24-02 — Catalog reasoning overstates IAM semantics for k8s/EC2/Lambda/ECS

- Files: `src/iam_jit/compatibility.py:184-187` (k8s-irsa), `:202-208` (ec2-instance-profile), `:220-227` (lambda-execution-role), `:240-243` (ecs-task-role); also `docs/AGENTS.md:29-32` (mirrors the claims).

- Issue: each fixed-role catalog entry says the workload "cannot choose a different role at runtime." Verbatim:
  - k8s: "The running pod cannot choose a different role at runtime"
  - EC2: "A running instance cannot swap instance profiles for the role it's currently using"
  - Lambda: "The running function cannot swap roles"
  - ECS: "A running task cannot swap roles"

  This is technically wrong. What's fixed is the BASE identity. Code running in any of these environments can call `sts:AssumeRole` with the base identity's credentials and get back credentials for a DIFFERENT role (subject to that role's trust policy permitting the base identity). This is the standard cross-account / cross-role pattern.

  Concretely:
  ```python
  # Inside a k8s pod with IRSA role 'pod-base-role':
  sts = boto3.client('sts')  # signs with the IRSA creds
  assumed = sts.assume_role(
      RoleArn='arn:aws:iam::222222222222:role/iam-jit-issued-role',
      RoleSessionName='from-pod',
  )
  # 'assumed.Credentials' now contains creds for iam-jit-issued-role
  s3 = boto3.client('s3',
      aws_access_key_id=assumed['Credentials']['AccessKeyId'],
      aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
      aws_session_token=assumed['Credentials']['SessionToken'])
  s3.get_object(...)  # acts as iam-jit-issued-role, NOT pod-base-role
  ```
  Works identically for EC2 instance profile, Lambda execution role, ECS task role. All four are BASE identities; all four can chain into other roles via AssumeRole.

  So an agent reading the catalog comes away believing iam-jit-issued roles fundamentally can't be used from inside these workloads, which is false. The practical recommendation (use the workload's built-in role for most cases; don't add an iam-jit AssumeRole hop unless you specifically need scoping the base identity doesn't provide) IS sound — but the SEMANTICS CLAIM that backs the recommendation is wrong.

  Consequences:
  - Agents that DO want fine-grained scoping (the legitimate iam-jit use case in these environments) read "the pod cannot choose a different role" and skip iam-jit entirely.
  - When iam-jit eventually does want to support the "issue a role for a pod to AssumeRole into" pattern (which is a real Pro-tier story per [[agent-access-use-case]]), the catalog reasoning will need to be unwound from the wrong claim.
  - Customer who's read the docs argues with support: "your own docs say my pod can't use iam-jit; why is your sales deck saying it can?"

- Why HIGH (not MED): the catalog's reasoning text is the load-bearing user-facing artifact for this feature — it's literally the explanation an agent reads to understand WHY iam-jit can't help. Getting the AWS-IAM-semantics claim wrong in the explanation undermines trust in iam-jit's IAM expertise broadly. Per [[scorer-is-ground-truth]] iam-jit's whole pitch is "we understand AWS IAM correctly" — a wrong claim in the canonical docs about a basic IAM primitive (AssumeRole from a base identity) is a credibility hit.

- Fix: rewrite each catalog entry's `reasoning` to distinguish BASE identity (fixed) from assumed-role chain (still available). Example for k8s:
  ```
  reasoning=(
      "K8s pods are bound to a specific IAM role at pod creation via "
      "IRSA / EKS Pod Identity. The pod's BASE identity (what its AWS "
      "SDK uses for unconfigured calls) cannot be swapped at runtime. "
      "Pod code CAN call sts:AssumeRole into a different role, but "
      "this adds an explicit hop the pod author has to write — iam-jit "
      "cannot transparently substitute. For most workloads, using the "
      "pod's IRSA role directly is simpler than adding an iam-jit "
      "AssumeRole step."
  )
  ```
  Same shape for EC2 / Lambda / ECS. Keeps the verdict (USE_EXISTING) and the next_action_hint, but stops claiming AssumeRole isn't possible.

  Also update `docs/AGENTS.md:29-32` to mirror the corrected claim.

  Optional bonus: add a fifth verdict `PROCEED_WITH_ASSUME` for the "yes you can use iam-jit but you'll need an explicit AssumeRole hop" case. Slice 3 or later — not blocking on this fix.

## MED findings

### MED-24-01 — `check_compatibility` writes no audit-log entry

- File: `src/iam_jit/compatibility.py:311-357` (the function is pure; never imports any store).

- Issue: every other iam-jit MCP tool that produces a decision (`submit_policy`, the bouncer's `bouncer_add_rule` / `bouncer_apply_preset` / `bouncer_decide --record`) writes an audit-log row. `check_compatibility` writes nothing. The agent calls it; gets a verdict; iam-jit retains zero record of having been asked.

  Per the bouncer's WB23 closure work (the `config_events` table at `bouncer/store.py:156-167`), every config-shape decision now writes an event so the question "did the agent ask iam-jit before doing X?" is auditable. Compatibility checks are EXACTLY that shape of decision — the agent is asking "should I use iam-jit for this workload?" and iam-jit's answer affects whether the agent submits a policy at all (or skips us and reaches for admin).

  Without the log:
  - Post-incident: "did the agent know iam-jit said 'use_existing' for this k8s pod, then submit anyway?" — no way to answer.
  - Calibration: "what fraction of agents reach the compatibility checker, get USE_EXISTING, and then go fall back to bouncer vs reach for admin?" — no signal.
  - Trust gap pair to HIGH-24-01: if `submit_policy` accepts cases the checker said no to (which it does today), and there's no log of either call, the chain breaks at both layers.

- Why MED (not HIGH): the immediate consequence is "missing-but-helpful audit data" not "broken security boundary." But the data IS the point — Slice 3's DEFER_TO_EXISTING outcome integration NEEDS this log to function (the intake has to be able to ask "did we already tell this agent to defer for this workload?"). Slice 1 setting up the data model without the audit hook means Slice 3 will need to add the hook anyway; better to wire it at the foundation layer.

- Fix: add an optional `config_event` write in `check_compatibility`, parallel to how the bouncer writes one when a preset is applied:
  ```python
  def check_compatibility(
      intent: CompatibilityIntent,
      *,
      audit_sink: ConfigEventSink | None = None,
  ) -> CompatibilityResult:
      result = ...  # existing logic
      if audit_sink is not None:
          audit_sink.record(
              kind="compatibility_check",
              actor=_current_actor(),
              detail={
                  "workload": intent.workload.value,
                  "target_account_id": intent.target_account_id,
                  "target_services": list(intent.target_services),
                  "verdict": result.verdict.value,
                  "matched_pattern": result.matched_pattern,
                  "existing_role_hint": intent.existing_role_hint,
              },
          )
      return result
  ```
  The MCP handler then plumbs whichever audit sink is configured (the bouncer's `config_events` table, or a new top-level iam-jit `compatibility_checks` table). Either works for Slice 2.

  Test invariant: `test_check_compatibility_writes_audit_event` — pass a fake sink, assert one event recorded with the right verdict.

### MED-24-02 — `existing_role_hint` echoed back verbatim with zero ARN validation

- File: `src/iam_jit/compatibility.py:346-348` (`existing_role_arn = intent.existing_role_hint`), `src/iam_jit/mcp_server.py:1248-1250` (MCP handler type-checks string but not ARN format).

- Issue: an agent can pass any string as `existing_role_hint` and it's echoed back as `existing_role_arn` in the result dict. No format validation. Verified repro:
  ```python
  >>> check_compatibility(CompatibilityIntent(
  ...     workload=WorkloadType.K8S_POD,
  ...     existing_role_hint='haha not a real ARN',
  ... )).existing_role_arn
  'haha not a real ARN'

  >>> check_compatibility(CompatibilityIntent(
  ...     workload=WorkloadType.K8S_POD,
  ...     existing_role_hint='',
  ... )).existing_role_arn
  ''   # empty-string is echoed too, not normalized to None
  ```

  And via MCP:
  ```python
  >>> _check_compatibility_for_mcp({'workload': 'k8s_pod', 'existing_role_hint': 'not-an-arn-at-all'})['existing_role_arn']
  'not-an-arn-at-all'
  ```

- Impact today: low — the checker is purely advisory; nothing downstream consumes the field. But Slice 3's DEFER_TO_EXISTING outcome (per the commit message: "Slices 2-4 add ... DEFER_TO_EXISTING outcome integration with intake") explicitly threads this verdict + role ARN into the intake flow. If intake trusts the echoed string as a real ARN and Slice 3 ships before this is validated, an agent (or prompt-injected agent) can submit:
  - garbage strings that crash intake's ARN-parser on the receiving end
  - lookalike strings (`arn:aws:iam::222222222222:role/admin-PRODUCTION` typoed as `arn:aws:iam::222222222222:role/admin-PR0DUCTION` with a zero) that DEFER_TO_EXISTING happily logs as the role-of-record
  - empty strings that pass `if existing_role_arn:` checks but break downstream lookups

  This is the same shape as WB20 CRIT-20-01 (reduction primitives accepting unvalidated input that propagated downstream).

- Why MED (not HIGH): no current consumer trusts the value. The harm is staged in Slice 3 — but Slice 1 is the LAYER where the validation belongs, and Slice 3 shouldn't need to re-validate at every consumer. Fix at the foundation.

- Fix:
  ```python
  import re
  _ARN_RE = re.compile(r"^arn:aws[a-zA-Z-]*:iam::\d{12}:role/[\w+=,.@/-]+$")

  def _validate_existing_role_hint(hint: str | None) -> str | None:
      if hint is None:
          return None
      hint = hint.strip()
      if not hint:
          return None
      if not _ARN_RE.match(hint):
          # Don't crash — return None and the caller can decide.
          # But surface the invalid input via a separate field.
          return None
      return hint
  ```
  Wire into `check_compatibility`:
  ```python
  if entry.verdict == Compatibility.USE_EXISTING:
      existing_role_arn = _validate_existing_role_hint(intent.existing_role_hint)
  ```
  And surface in `CompatibilityResult` a new field `existing_role_hint_invalid: bool = False` so the agent learns "we couldn't use the hint you gave us, here's why" rather than silent drop. Same field reflected in `to_dict`.

  Add tests for: valid IAM role ARN, valid IAM-GovCloud ARN (`arn:aws-us-gov:...`), valid China-region ARN (`arn:aws-cn:...`), empty string, garbage string, ARN missing role part, ARN with wrong account-id length. The regex above handles all four AWS partitions.

### MED-24-03 — Workload-composition edge cases unaddressed in code OR docs

- Files: `src/iam_jit/compatibility.py:72-117` (WorkloadType definitions; no composition awareness), `docs/AGENTS.md:21-32` (workload classification table; no composition note).

- Issue: the 9-workload set treats each workload as discrete, but real environments compose:
  - **CI runner on EC2** — self-hosted GitHub Actions / Buildkite runner inside an EC2 instance. The runner's job IS the CI runner; the host IS an EC2 instance. `ci_runner` says PROCEED; `ec2_instance` says USE_EXISTING. Whichever the agent classifies as, wins. No guidance.
  - **Agent in k8s pod** — Claude Code (or another agent) running inside a k8s pod (e.g. a developer's k8s-based dev environment). `agent_local_dev` says PROCEED; `k8s_pod` says USE_EXISTING. Different answer.
  - **Containerized self-hosted runner on ECS** — runner-as-a-container on ECS Fargate. `ci_runner` PROCEED; `ecs_task` USE_EXISTING.
  - **CI runner on Lambda (lambda-based ephemeral runners)** — exists; some shops do this. `ci_runner` PROCEED; `lambda_function` USE_EXISTING.
  - **Lambda calling another Lambda** — both classify as `lambda_function`.

  The current `check_compatibility(intent)` looks up exactly one workload and returns its catalog entry. No way for an agent to say "I'm a CI runner ON EC2" and get a composed answer.

  Practical consequence: the agent picks one classification (probably the one that gets it what it wants — the agent that wants PROCEED picks `ci_runner`; the agent being honest picks `ec2_instance`). The "easy to misuse" failure mode (per [[agent-friendly-not-bypassable]] Lens B) — give two interpretations and the agent picks the laxer one — is wired in.

- Why MED (not HIGH): the docstring/docs hand the failure to the agent rather than enabling a security bypass. A motivated attacker who controls the agent's classification doesn't really need this — they have many other paths. But for HONEST agents that genuinely don't know which classification applies (the CI-runner-on-EC2 case is super common), the docs give no guidance.

- Fix options:
  1. **Best**: add an optional `host_environment` field to `CompatibilityIntent`:
     ```python
     workload: WorkloadType
     host_environment: WorkloadType | None = None  # e.g. ec2_instance for CI-on-EC2
     ```
     If `host_environment` is set AND it's a fixed-role workload, return USE_EXISTING regardless of the primary workload's verdict — the OUTER constraint wins. Add a catalog entry / branching logic for `ci_runner + ec2_instance` → USE_EXISTING (because the runner can't get out of the EC2's IMDS-credential gravity well without explicit AssumeRole).
  2. **Acceptable**: document the rule in AGENTS.md: "When workloads compose (CI runner on EC2, agent in k8s pod), classify by the OUTER hosting environment — that's the constraint iam-jit can't change." Add a section "Composition" with worked examples.
  3. **Worst**: leave silent; let agents guess.

  Recommend option 2 for Slice 1 closure (cheap; covers the honest agent), option 1 for Slice 3 when the data model is being touched anyway.

### MED-24-04 — `CANNOT_HELP` and `USE_BOUNCER` enum values are never returned

- File: `src/iam_jit/compatibility.py:48-69` (the `Compatibility` enum), `:178-295` (the entire CATALOG); verified by enumerating every WorkloadType:
  ```python
  >>> seen = {check_compatibility(CompatibilityIntent(workload=w)).verdict.value for w in WorkloadType}
  {'proceed', 'use_existing'}
  ```

- Issue: the enum advertises 4 verdicts (PROCEED / USE_EXISTING / USE_BOUNCER / CANNOT_HELP). The MCP tool description tells agents about all 4. AGENTS.md has a 4-row table documenting all 4. But the checker only ever returns 2 of them.

  - `USE_BOUNCER` ("issuance doesn't apply but the local proxy does"): no catalog entry sets this verdict. The 5 fixed-role entries return USE_EXISTING (with bouncer_recommended=True as a secondary flag). The closest semantic match — "iam-jit can't issue, you should use the bouncer instead" — is buried in the `bouncer_recommended` boolean on a USE_EXISTING verdict, not a primary verdict of USE_BOUNCER.
  - `CANNOT_HELP` ("neither iam-jit product helps; escalate to human"): no entry sets this either. The OTHER catch-all degrades to PROCEED rather than CANNOT_HELP — a sensible UX choice but it means the verdict is unreachable.

  An agent reading the docs comes away expecting four possible answers and gets two. The docstring "Per [[agent-friendly-not-bypassable]]: never returns a vague answer" is technically true (every response has reasoning) but the surface advertised vs. surface delivered is mismatched.

- Why MED (not LOW): API surface vs. behavior mismatch is a trust-gap shape that matters at the integration layer — agents (or downstream tools) will write switch statements / if-chains assuming all 4 verdicts can fire, then never exercise the dead branches; the dead branches will rot. Same shape as WB18 LOW-18-04 (preset library declared `kind="experimental"` that no entry used).

- Fix options:
  1. **Best**: prune the unused enum values now. If Slice 2's admin allowlist needs `USE_BOUNCER` as a verdict (e.g. an admin allowlist that says "for this account, use the bouncer instead of iam-jit"), add it back when Slice 2 introduces it. Don't ship dead enum values.
  2. **Acceptable**: keep the values, add at least one catalog entry that returns each (or a special-case path in `check_compatibility`). For CANNOT_HELP, the catch-all could be split — "OTHER + target_services intersects with org-deny list" → CANNOT_HELP. For USE_BOUNCER, an explicit `bouncer_only` workload type (or per-account override) could return it.
  3. **Worst**: leave as-is; document the dead branches.

  Recommend option 1 for Slice 1 hygiene, option 2 if Slice 2 has concrete uses planned.

## LOW findings

### LOW-24-01 — Catalog incomplete: Step Functions / CodeBuild / App Runner / Fargate / Glue / EventBridge / Batch

- File: `src/iam_jit/compatibility.py:178-295` (CATALOG).

- Issue: the 5 fixed-role workloads + 3 PROCEED workloads cover the common cases but several known-USE_EXISTING shapes are absent:
  - **Step Functions** — each state machine has an execution role; can call AssumeRole; primary classification USE_EXISTING.
  - **CodeBuild projects** — service role per project; USE_EXISTING.
  - **App Runner services** — instance role; USE_EXISTING.
  - **Fargate tasks** — currently lumped into ECS_TASK but Fargate splits into TWO roles (task role for the container; execution role for the agent that pulls the image / writes logs). Both are USE_EXISTING; the catalog's `ecs_task` entry mentions only "Task Role" and doesn't distinguish.
  - **Glue jobs** — IAM role per job; USE_EXISTING.
  - **EventBridge rules / Lambda destinations** — invokes-as-role pattern; USE_EXISTING.
  - **AWS Batch jobs** — job role on the job definition; USE_EXISTING.
  - **SageMaker training jobs / notebook instances** — execution role per resource; USE_EXISTING.
  - **EMR clusters** — service role + EC2 instance profile + auto-scaling role; USE_EXISTING.

  Each is a workload an agent will encounter and have no catalog entry for. The current behavior is: classify as `other` → degrade to PROCEED → agent tries iam-jit → fails for the same reason iam-jit can't help k8s pods → reach for admin.

- Why LOW: this is Slice 1; coverage expansion is explicitly an ongoing project per the commit message. Flagged so subsequent slices know the list. Not a bug — incomplete-not-wrong.

- Fix: extend `WorkloadType` and CATALOG over slices 2-4. Suggested priority order based on AWS-shop prevalence:
  1. Fargate (split task vs. execution; currently misrepresented)
  2. CodeBuild
  3. Step Functions
  4. Glue
  5. SageMaker
  6. App Runner
  7. Batch / EMR / EventBridge

  Add a test that walks `WorkloadType` and asserts every value (except OTHER) has at least one catalog entry — see LOW-24-03 for the structural shape.

### LOW-24-02 — `CompatibilityIntent.description` field is unreferenced

- File: `src/iam_jit/compatibility.py:129` (declaration), `src/iam_jit/mcp_server.py:1245-1247` (accepted by MCP handler), `:1257` (passed into the intent), then never read.

- Issue: `ast.walk` confirms zero references to `intent.description` anywhere in `compatibility.py`. The MCP handler accepts it (with a type-check), constructs `CompatibilityIntent(description=description, ...)`, the dataclass stores it, and nothing ever reads it. Doc string at `:121-124` says "All fields optional except workload — the checker degrades gracefully when less info is provided." The description field exists for... what?

  The audit chain comment elsewhere (mcp_server.py:1247) says "audit log only" — but no audit log is written (MED-24-01).

- Why LOW: dead field; no immediate harm. But two-step issue:
  1. Field is documented as something it isn't (it's not used "for audit log" because no audit log exists yet).
  2. A future contributor adding audit-log writes (MED-24-01 fix) won't know to plumb `description` through unless they read this audit doc.

- Fix options:
  1. **Best**: drop the field now; re-add in Slice 2 when audit-log writes land and the field will actually be used.
  2. **Acceptable**: keep the field; add a code comment explaining it's a "reserved for Slice 2 audit-log writes" placeholder; ensure MED-24-01's fix plumbs it through.
  3. **Worst**: leave undocumented; bites the next contributor.

### LOW-24-03 — "First-match-wins" comment describes discipline not exercised by current entries

- File: `src/iam_jit/compatibility.py:298-303`:
  ```python
  _CATALOG_BY_WORKLOAD: dict[WorkloadType, CatalogEntry] = {}
  for _entry in CATALOG:
      for _w in _entry.workloads:
          # First-match-wins: the catalog is ordered by specificity, so
          # the first entry mentioning a workload is the canonical answer.
          _CATALOG_BY_WORKLOAD.setdefault(_w, _entry)
  ```

- Issue: the comment promises that ordering matters ("ordered by specificity, so the first entry"). But the current catalog has each workload in EXACTLY ONE entry — verified:
  ```python
  >>> Counter(w for e in CATALOG for w in e.workloads)
  Counter({'k8s_pod': 1, 'eks_pod_identity': 1, ..., 'human_cli': 1})
  ```
  So the `setdefault` first-match logic never actually fires — no entry currently competes with another for the same workload.

  Two failure modes:
  1. A future contributor adds a second entry for an existing workload (intending to add a specific override) and puts it AFTER the original. The override silently doesn't fire. No test catches this because no test exists for the "specificity ordering" invariant.
  2. A future contributor inadvertently duplicates a workload across entries (e.g. typo). Same silent fall-through. No invariant test that says "each workload appears in exactly one entry" OR "if multiple, first wins is deliberate."

  Comment-driven semantics not enforced by tests = WB22 LOW shape ("docs promise an invariant code doesn't keep").

- Why LOW: no current behavior is wrong; this is hardening against future drift.

- Fix options:
  1. **Best**: add a structural test:
     ```python
     def test_catalog_no_workload_duplicate_unless_intentional():
         from collections import Counter
         counts = Counter(w for e in CATALOG for w in e.workloads)
         duplicates = {w: c for w, c in counts.items() if c > 1}
         # If you intentionally duplicate (specificity-override), update
         # the EXPECTED_DUPLICATES set below with a comment explaining.
         EXPECTED_DUPLICATES: set[WorkloadType] = set()
         assert set(duplicates) == EXPECTED_DUPLICATES
     ```
     Plus add a test that walks the lookup map and asserts every workload (except OTHER) has an entry — closes the "new WorkloadType added without catalog entry" gap from the audit-prompt question.
  2. **Acceptable**: drop the "first-match-wins" comment until the discipline is actually used.

### LOW-24-04 — `docs/IAM-JIT-BOUNCER.md` doesn't mention being the fixed-role fallback

- Files: `docs/IAM-JIT-BOUNCER.md` (no occurrence of "compatibility", "use_existing", "fixed-role", "k8s", "IRSA", "Lambda", "EC2 instance profile", "ECS task"); `src/iam_jit/compatibility.py:191-194, :209-213, :243-247` (every USE_EXISTING `next_action_hint` points at the bouncer).

- Issue: the compatibility-checker's `next_action_hint` text repeatedly directs agents to use iam-jit-the-bouncer as the gating fallback for k8s / EC2 / ECS workloads:
  ```
  "iam-jit-the-bouncer can gate these calls if you need scoped
   enforcement — see docs/IAM-JIT-BOUNCER.md."
  ```
  But `docs/IAM-JIT-BOUNCER.md` itself says nothing about being a "fallback for fixed-role workloads." The doc focuses on local-dev agent safety (per the bouncer's primary positioning), not on this k8s/EC2 use case. An agent that follows the link gets bouncer docs that read as if the bouncer is for laptops, not pods.

  Cross-doc asymmetry: one doc promises X; the other doc, when read, doesn't deliver X.

- Why LOW: doc-only; doesn't break anything functional. But it's a discoverability dead-end — agent reads "see IAM-JIT-BOUNCER.md," reads the doc, comes away thinking "this isn't relevant to my pod."

- Fix: add a section to `docs/IAM-JIT-BOUNCER.md` named "Use case: fixed-role workloads (k8s, EC2, Lambda, ECS)" explaining:
  - When `check_iam_jit_compatibility` returns USE_EXISTING the agent uses the workload's built-in role
  - The bouncer can still gate the calls that role makes (run as sidecar / DaemonSet / per-instance)
  - Setup pointers for each environment (links to whatever Stage 2's per-environment install docs say)

  Even a 10-line stub closes the asymmetry; full content can land alongside Stage 2's HTTP proxy when there's actually a sidecar deployment doc to point at.

### LOW-24-05 — MCP input validation accepts nonsense for account ID / service prefix / ARN

- File: `src/iam_jit/mcp_server.py:1232-1250` (the validation block in `_check_compatibility_for_mcp`).

- Issue: the handler type-checks every field as `str` / `list[str]` but doesn't validate semantically:
  - `target_account_id`: any string passes. `"not-an-account-id"`, `""`, `"42"`, `"1234567890123"` (13 digits) — all accepted.
  - `target_services`: any list of strings passes. `["not-a-real-service"]`, `["s3 ", " dynamodb"]` (with whitespace) — accepted.
  - `existing_role_hint`: any string passes (covered in MED-24-02 — this LOW is just the MCP-layer mirror).

  Verified:
  ```python
  >>> _check_compatibility_for_mcp({'workload': 'k8s_pod', 'target_account_id': 'not-an-account-id'})
  {'verdict': 'use_existing', ...}   # accepted, no error
  ```

- Why LOW: the checker is read-only and the values aren't load-bearing for Slice 1. The bouncer doesn't see them, the recommender doesn't see them, nothing currently cares. But:
  - Slice 3's DEFER_TO_EXISTING outcome integration will start using these (per commit message). At that point garbage values propagate.
  - Agent UX: an agent passes `target_account_id="dev account"` (typo); gets a "use_existing" response that looks confident; agent acts on it. The mistake stays silent.

- Fix:
  ```python
  import re
  _ACCOUNT_RE = re.compile(r"^\d{12}$")
  _SERVICE_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")

  if target_account_id is not None:
      if not isinstance(target_account_id, str):
          return {"error": "target_account_id must be a string if provided"}
      if not _ACCOUNT_RE.match(target_account_id.strip()):
          return {"error": "target_account_id must be 12 digits"}
      target_account_id = target_account_id.strip()

  if target_services:
      for item in target_services:
          if not isinstance(item, str) or not _SERVICE_RE.match(item.strip().lower()):
              return {"error": f"target_services contains invalid service prefix: {item!r}"}
      target_services = [s.strip().lower() for s in target_services]
  ```
  Plus the ARN validator from MED-24-02. Tests: each invalid shape returns an error; valid shapes pass through.

## Verified clean

The following were probed per the audit prompt and found no issues:

- **inputSchema enum matches WorkloadType enum**: verified programmatically — both contain exactly `{k8s_pod, eks_pod_identity, ec2_instance, lambda_function, ecs_task, ci_runner, agent_local_dev, human_cli, other}`. No drift today. Note that the match is by hand-copy, not generation — drift risk for future enum additions is real but currently zero (flagged as part of the auditor's concern but no current finding).

- **`to_dict` shape matches MCP `structuredContent` plumbing**: the dispatcher at `mcp_server.py:2022-2033` wraps the payload as `content: [{type: text, text: json.dumps(...)}]` + `structuredContent: <payload>`. The 6 keys in `CompatibilityResult.to_dict` (verdict / reasoning / existing_role_arn / matched_pattern / next_action_hint / bouncer_recommended) are JSON-serializable. The test `test_dispatch_check_iam_jit_compatibility` exercises the full round-trip including structuredContent extraction. Verified clean.

- **`next_action_hint` non-empty on every catalog entry**: test `test_every_catalog_entry_has_next_action_hint` enforces this; verified by reading every entry's text. Also verified via the OTHER fallback path — the `check_compatibility` function ALWAYS returns a non-None `next_action_hint`, including the unknown-workload branch. Per [[agent-friendly-not-bypassable]] this contract holds.

- **`bouncer_recommended=False` for Lambda**: correct documented exception. Test `test_fixed_role_workloads_recommend_bouncer_or_explain_why_not` enforces. The reasoning (bouncer doesn't make sense inside Lambda runtime — no local process to run it in) is sound.

- **Per-workload verdict tests cover every WorkloadType**: `test_k8s_pod_returns_use_existing`, `test_eks_pod_identity_returns_use_existing`, `test_ec2_instance_returns_use_existing_with_bouncer`, `test_lambda_returns_use_existing_no_bouncer`, `test_ecs_task_returns_use_existing`, `test_ci_runner_returns_proceed`, `test_agent_local_dev_returns_proceed`, `test_human_cli_returns_proceed`, `test_other_workload_degrades_to_proceed_with_fallback_note` — all 9 covered.

- **OTHER catch-all correctness**: verified `bouncer_recommended=True` is set on the OTHER-path response (`compatibility.py:341`), which matches the documented claim "iam-jit tries, with bouncer as fallback" in AGENTS.md. The test `test_other_workload_degrades_to_proceed_with_fallback_note` also asserts the reasoning mentions "fall back" or "switch to."

- **AGENTS.md mentions every WorkloadType**: programmatically verified — all 9 workload values appear in the doc. No current drift; LOW-24-03's structural test recommendation would protect against future drift.

- **CatalogEntry dataclass is frozen**: `@dataclasses.dataclass(frozen=True)` on `CatalogEntry`, `CompatibilityIntent`, `CompatibilityResult`. Reasonable hardening against mutation; tuple types on the WorkloadType collection prevent list-mutation pitfalls.

- **No `boto3` / no `iam:*` AWS API calls**: grep confirms — `compatibility.py` imports only `dataclasses`, `enum`, `typing.Any`, `__future__.annotations`. Pure module. Per [[creates-never-mutates]] this is the right shape; the checker is purely advisory and doesn't touch AWS state.

- **Test imports compatibility module from public surface**: `from iam_jit.compatibility import ...` — no private-symbol imports. Acceptable forward-compat shape for the test surface.

- **No `1.8%` mentions**: grep confirms zero `1.8%` mentions in `compatibility.py`, `mcp_server.py` diff, `test_compatibility.py`, or the AGENTS.md additions. Per [[no-one-eight-percent-mention]] — clean.

- **`[[creates-never-mutates]]` cited correctly**: the AGENTS.md addition at line 44 cites the memo accurately ("iam-jit's whole model is 'create a NEW short-lived role'"). The compatibility module's docstring at `:14-15` cites [[agent-friendly-not-bypassable]] correctly. Cross-memo references are consistent with the actual memo content.

- **Tool descriptions are stable English (no `f"..."` interpolation of mutable values)**: the MCP tool description strings are plain literals; no risk of injection or test-order-dependent variability. Clean.

- **`description` field type-check rejects non-strings**: test `test_mcp_check_non_string_description` exercises this; verified the handler returns the right error shape. (The field's UNUSED-ness is LOW-24-02.)

- **Schema migration / store impact**: zero. Slice 1 doesn't touch any SQLite store. The MED-24-01 (audit-log gap) discussion is about adding a write, not about an existing store being wrong.

- **Test count delta matches commit message**: commit message claims +29 new tests (was 2284, now 2313). Verified: `pytest -q tests/test_compatibility.py` collects 29 tests; the overall delta is +29 (was 2284 → now 2313). No silent regressions in other test files.

- **`existing_role_hint` not echoed when verdict is PROCEED**: verified via `test_existing_role_hint_not_echoed_when_proceed` and by code path inspection — `compatibility.py:346-348` only assigns `existing_role_arn` when verdict is USE_EXISTING. The PROCEED-path drop is silent (the auditor's question — should the agent be told "we ignored your hint" — is answered NO, this is fine: PROCEED means iam-jit will issue a new role, the hint is irrelevant).

## Regression check

Command run: `cd /Users/reagan/repos/iam-roles && .venv/bin/python -m pytest --no-header -q --ignore=tests/test_calibration_corpus.py --ignore=tests/e2e 2>&1 | tail -5`

Result:
```
2313 passed, 29 skipped, 14 deselected, 2 warnings in 87.60s (0:01:27)
```

Matches the audit-prompt baseline (2313). All 29 new tests pass. No regressions in any of the 2284 pre-existing tests.

## Summary

**0 CRIT, 2 HIGH, 4 MED, 5 LOW.** Slice 1 ships a clean data model + curated catalog + pure decision function + 2 MCP tools, with strong unit-test coverage at the in-module level (29 tests, all the shape invariants and per-workload verdicts enforced). The bug pattern is the same trust-gap shape WB21/WB22/WB23 found: the docstrings + tool descriptions + AGENTS.md collectively promise behavior the code doesn't enforce.

The 2 HIGHs are the most-impactful:
- **HIGH-24-01** (no enforcement that compatibility was checked before `submit_policy`) is the same Lens-A-without-Lens-B failure mode the bouncer's WB23 closure addressed for `config_events`; should land in Slice 2 alongside the admin allowlist work.
- **HIGH-24-02** (catalog reasoning text is wrong about AssumeRole semantics) is a credibility hit on iam-jit's "we understand AWS IAM correctly" pitch and should be fixed before any customer reads the catalog.

The 4 MEDs cluster around the foundation-layer gaps that Slices 2-4 will hit:
- audit-log writes (MED-24-01) — needed by Slice 2 anyway
- ARN validation on `existing_role_hint` (MED-24-02) — needed by Slice 3's DEFER_TO_EXISTING anyway
- workload composition (MED-24-03) — docs-only fix for Slice 1; code fix for Slice 3+
- dead enum values (MED-24-04) — prune or wire up before Slice 2's verdict surface lands

The 5 LOWs are: catalog coverage gaps (ongoing work; flagged), dead `description` field (drop or wire), first-match-wins comment without enforcement (add test), bouncer-doc asymmetry (add a section), MCP input validation accepts nonsense (mirror the ARN validator).

Recommended closure-commit fix sequence:

1. **HIGH-24-02**: rewrite the 4 fixed-role catalog `reasoning` strings to distinguish BASE identity (fixed) from assume-chain (still available); mirror in AGENTS.md. ~30 min; pure docs.
2. **HIGH-24-01**: add `workload` (optional) to `submit_policy`'s schema; when provided, run `check_compatibility` and either BLOCK on USE_EXISTING/CANNOT_HELP or warn with a structured response. Test the cross-tool wiring. ~2 hr.
3. **MED-24-02**: add ARN validator to `existing_role_hint`; add `existing_role_hint_invalid` field to result. ~1 hr.
4. **MED-24-04**: prune `CANNOT_HELP` and `USE_BOUNCER` from the enum (or wire them up). ~30 min for prune; longer for wire-up.
5. **MED-24-01**: add `config_event` audit-write on each compatibility check; pipe through the bouncer's existing `config_events` table for now (or a new table — call in Slice 2). ~2 hr including tests.
6. **MED-24-03**: add "Composition" section to AGENTS.md with worked CI-on-EC2 / agent-in-k8s examples; defer code fix to Slice 3. ~30 min docs.
7. **LOW-24-02**: drop `description` field (or annotate as Slice-2-placeholder). ~10 min.
8. **LOW-24-03**: add structural tests for catalog (`no_workload_duplicate_unless_intentional`, `every_non_other_workload_has_catalog_entry`). ~30 min.
9. **LOW-24-05**: add MCP input validators for `target_account_id` / `target_services` (12-digit AWS account ID regex; lowercase AWS service-prefix regex). ~1 hr including tests.
10. **LOW-24-04**: add "fixed-role workload fallback" section to `docs/IAM-JIT-BOUNCER.md`. ~30 min docs.
11. **LOW-24-01**: catalog-coverage expansion (Fargate split, CodeBuild, Step Functions, Glue, SageMaker, App Runner, Batch). ~2 hr per workload; can defer to Slices 2-4 as a steady-state task.

After fixes ship, re-run audit (Round 25) — recommended scope: Slice 2 (admin allowlist + per-account overrides) plus a re-probe of HIGH-24-01 to confirm `submit_policy`'s compatibility check actually fires.

The foundation is well-shaped at the data-model + pure-function layer (zero findings there). The trust-gap concentration in HIGH-24-01 + MED-24-01 is the same lesson WB21/WB22/WB23 keep teaching: when iam-jit ships a Lens-A (agent-friendly) docstring or doc claim, the matching Lens-B (uncircumventable) enforcement layer needs to ship in the same commit or one immediately after. Slices 2-4 will get the chance.
