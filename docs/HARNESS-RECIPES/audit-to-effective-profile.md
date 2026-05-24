# Audit → effective profile — the lean-permissive loop (with progressive tightening)

**For the operator's agent.** Walks the full path from "discovery
period is complete" to "enforce mode is on without breaking the
workflow." Implements `[[safety-mode-lean-permissive]]`'s "err on
allowing, but block adversarial shapes" via the design in
[PROFILE-GENERATION-DESIGN.md](../PROFILE-GENERATION-DESIGN.md).

Sequences the now-shipped Phase 1–5 MCP tools per Phase 6 of the
design:
`bounce_profile_generate_from_audit` →
`bounce_simulate_profile` →
`bounce_grade_profile_for_workflow` →
`bounce_profile_save`. The 4-tier overall verdict
(`MEANINGFUL` / `PARTIAL` / `THEATER` / `NEGATIVE-VALUE`) at the
grade step is the deterministic branch point the recipe pivots on.

Per `[[bouncer-zero-llm-when-agent-in-loop]]` iam-jit provides the
MCP tools + recipe + heuristic rubric. **Your agent does all the
reasoning.** No iam-jit-side LLM credits required. The recipe
sequences the MCP-tool calls + provides decision rubrics at each step.

Per `[[ibounce-honest-positioning]]` the profile is a deterrent +
dev-loop scope, not a cryptographic boundary. The actual security
boundary is the IAM role / RBAC / DB grants the agent runs under;
the profile is the local fast-iteration layer on top.

## Prerequisites

* Bouncers installed in discovery mode (the
  `[[discovery-first-default]]` post-pivot default).
* At least a few hours of legitimate-traffic audit observations. More
  is better — a week of representative observations produces a much
  better profile than 30 minutes of one task.
* iam-jit + the operator's agent (Claude Code / Cursor / Codex / Devin
  / custom) with the iam-jit MCP server reachable.
* (Optional) operator-set friction budget in `.iam-jit.yaml` (default
  is 3 legit-denies/day, 10/week).

## The 15-step loop

Steps 1–13 cover initial profile generation + post-install monitoring.
Steps 14–15 add the periodic progressive-tightening + suspect-pattern
review cycle per PROFILE-GENERATION-DESIGN.md §10 + §11.

**Tool sequence at a glance** (per Phase 6 of the design — sequencing
the now-shipped Phase 1–5 MCP tools):

```
discovery (step 1) →
  bounce_query_audit_long_range / bounce_extract_permissions_from_audit (step 2) →
  bounce_profile_generate_from_audit (step 4, lean_permissive=true) →
  bounce_simulate_profile (step 5) →
    [over_budget loop → step 6 → back to step 4]
  bounce_grade_profile_for_workflow (step 7) →
    [overall != MEANINGFUL → branch per verdict → back to step 4 / 6]
  bounce_profile_save (step 8, gated on MEANINGFUL) →
  bounce profile install (step 9) →
  monitor + classify + improve (steps 10–12) →
  weekly bounce_grade_profile_for_workflow re-run (step 13) →
  periodic iam_jit_consider_tightening (steps 14–15)
```

Each step has a stable MCP surface + `structuredContent` payload; the
4-tier overall verdict (`MEANINGFUL` / `PARTIAL` / `THEATER` /
`NEGATIVE-VALUE`) at step 7 is the **deterministic branch point** the
recipe pivots on.

### Step 1 — Confirm the discovery period is complete

Discovery is "complete" when the agent has confidence the recent
audit window covers the legitimate workflow patterns. There is no
hard signal — the agent uses operator-supplied context ("we ran the
weekly migration", "we exercised the agent's full incident-response
runbook", etc.) to decide.

If unsure, call `bounce_query_audit_long_range` with `since=7d` and
ask the operator: "I see N events across the last week, spanning K
distinct services. Is this representative of the workload you want to
pin a profile for?"

### Step 2 — Extract the permission set

```
bounce_extract_permissions_from_audit
  bouncer: ibounce          # or kbounce / dbounce / gbounce
  since: 7d                 # representative window
```

Returns the aggregated `{action, resources, count, action_class,
first_seen, last_seen, allow_count}` per observed permission, plus
the `observed_scope` (account_ids + regions).

**Decision point:** if `events_analyzed == 0`, discovery is not
complete or the bouncer isn't observing — fall back to
`bounce_query_audit_long_range` to check whether events exist at all.
Surface to operator: "the bouncer has seen 0 events in the last 7d;
either the workload didn't run or the bouncer isn't intercepting."

### Step 3 — Apply the lean-permissive heuristic context

Before generating, the agent considers per-action-class disposition
(see PROFILE-GENERATION-DESIGN.md §2):

* **read** (`Get*` / `List*` / `Describe*` / `SELECT` / `GET` /
  kubectl `get|list|watch`) — broad allow OK if observed across 2+
  resources with 5+ count
* **write-data** (`Put*` / `Update*` / `INSERT` / `UPDATE` / `POST` /
  kubectl `apply|update|patch`) — tight: exact action + exact
  resource
* **admin / network / IAM** (`iam:*` / `GRANT` / `REVOKE` / `DROP` /
  RBAC verbs / IMDS / SSRF targets) — very tight; require 3+
  observations + flag for review
* **destructive-data** (`Delete*` / `DROP TABLE` / `DELETE FROM` /
  `kubectl delete deployment`) — tight even if observed 100× (high
  blast radius)

`KNOWN_ADVERSARIAL_PATTERNS` always denied regardless of observation.

### Step 4 — Generate the profile

```
bounce_profile_generate_from_audit
  events: <from step 2>
  bouncers: [ibounce]       # or whichever applies
  add_safety_denies: true
  lean_permissive: true     # NEW per the design
  name: "weekly-ops-2026-05-24"
```

Returns a bundle. Bundle includes per-bouncer `allows` / `denies` /
`flagged_for_review` / `skipped` sections plus the
`observed_scope`-derived `only_account_ids` / `only_regions` / etc.

### Step 5 — Simulate against recent audit history

This is the dogfood variant-A pre-mortem. Phase 4 shipped (commit
4c1bee3): the simulator replays your audit events against the
generator-shape profile + emits per-event verdicts.

```
bounce_simulate_profile
  profile: <generator-shape dict from step 4 — {bouncer, allows, denies, ...}>
  events: <OCSF events from step 2>
  bouncer_kind: "ibounce"     # or "kbouncer" / "kbounce" / "dbounce" / "gbounce"
  friction_budget: {
    max_legitimate_denies_per_day: 3,
    max_legitimate_denies_per_week: 10
  }
```

Returns a `SimulationVerdicts` with:

* `verdicts[]` — per-event `{event_idx, verdict: allow|deny|abstain,
  reason, matched_rule}`
* `summary` — `{allow, deny, abstain, total}`
* `friction_metrics` — `{budget_max_denies_per_week,
  actual_denies_in_window, estimated_weekly_denies, over_budget,
  over_budget_factor, observation_span_days}` (empty when
  `friction_budget` omitted)
* `provenance` — `{engine: "simulation-python", engine_version,
  production_parity: false, warnings: [...]}`

**HONEST PROVENANCE — surface to operator** (per
`[[ibounce-honest-positioning]]`): `provenance.production_parity` is
ALWAYS `false`. The simulator is pure-Python over the generator-shape
profile dict; it is NOT the production rule engine for any of the 4
bouncers. `provenance.warnings` enumerates the divergence shapes
(ibounce: no `allow_baseline` / `deny_keywords` / conditional-deny;
kbouncer/dbounce/gbouncer: never head-to-head compared with the Go
engines). The recipe consumes these verdicts as a useful approximation,
NOT as ground truth.

**Decision tree** (read off `friction_metrics`):

* `over_budget == false` + `summary.deny == 0` → audit window had
  nothing the profile would block. Possible reasons: profile is
  near-admin, OR audit window is unrepresentative. Surface to
  operator: "the profile would block nothing in the last 7d — is the
  audit window representative? Consider tightening or expanding the
  window."
* `over_budget == false` + `summary.deny > 0` → proceed to step 7 +
  step 8 (the profile constrains something).
* `over_budget == true` → iterate to step 6 (widen).

### Step 6 — Widen if needed (loop)

If `friction_metrics.over_budget == true`:

* Inspect `verdicts[]` and filter where `verdict == "deny"`. Group by
  `matched_rule` to identify the top deny patterns by count.
* For each top deny: classify the action per step 3's rubric
  (read / write-data / admin / destructive-data).
  * If the deny is on `read` class and operator confirms legit →
    widening is safe; propose allow rule.
  * If the deny is on `write-data` / `admin` / `destructive-data`
    class → widening trades safety for friction. Surface to operator:
    "the profile would deny X legitimate {action_class} operations
    against {resource}; widening allow to {sibling-pattern} would
    bring friction under budget. Approve widening?"
  * If operator declines: accept the friction; the safety floor is
    load-bearing.
* If operator approves: emit additional allow rule, regenerate
  profile (back to step 4), re-simulate (back to step 5).

Iteration converges in 1–3 rounds for typical workloads. Note
`provenance.production_parity == false` still applies — the
friction estimate is approximate.

### Step 7 — Grade the profile against the rubric

Phase 5 shipped (commit 4c1bee3): `bounce_grade_profile_for_workflow`
scores the profile against the 5-flag rubric + emits an overall
verdict in the canonical
`MEANINGFUL / PARTIAL / THEATER / NEGATIVE-VALUE` taxonomy borrowed
from `[[role-effectiveness-corpus]]`.

```
bounce_grade_profile_for_workflow
  profile: <generator-shape dict from step 4>
  events: <same OCSF events from step 2>
  bouncer_kind: "ibounce"
  friction_budget: 10        # int = max legit denies / week,
                             # OR dict per step 5 shape
```

Returns a `GradingReport`:

* `overall` — one of `"MEANINGFUL"` / `"PARTIAL"` / `"THEATER"` /
  `"NEGATIVE-VALUE"` (hyphen, not underscore — exact taxonomy spelling)
* `flags[]` — list of 5 `{name, pass_, rationale, evidence[]}` in
  canonical order:
  1. `blocks_known_risk_shapes` — did the profile deny every event
     matching `KNOWN_ADVERSARIAL_PATTERNS`? (Vacuously passes when
     no adversarial shapes are in the window — rationale surfaces N/A.)
  2. `under_friction_budget` — was estimated weekly deny rate at or
     under `friction_budget`? (N/A when budget omitted.)
  3. `allows_too_broad` — does any allow rule pair `target='*'` with
     a write-class / admin-class / destructive-class action? (Fails
     if yes.)
  4. `schema_parses` — does the generator-shape dict validate?
     (Short-circuits other flag accuracy when it fails — see
     `provenance.warnings`.)
  5. `narrows_vs_admin_baseline` — does the profile deny at least
     one event the admin baseline would allow?
* `simulation_summary` — mirrors Phase 4 `SimulationVerdicts.summary`
* `provenance` — `{grading_version, simulator_engine,
  simulator_engine_version, simulator_production_parity, warnings}`

**Verdict thresholds** (deterministic, per `_compute_overall`):

| Flags passed | Overall verdict |
|---|---|
| 5 of 5 | `MEANINGFUL` |
| 3 or 4 of 5 | `PARTIAL` |
| 1 or 2 of 5 | `THEATER` |
| 0 of 5 | `NEGATIVE-VALUE` |

**Deterministic branch point on `overall`** (per
`[[scorer-is-ground-truth]]` — do NOT bypass with "exception cases"):

* `"MEANINGFUL"` → proceed to step 8 (save). All 5 flags passed; this
  is the install-ready state.
* `"PARTIAL"` → surface failed flags to operator. Agent narrates:
  "your profile has X but lacks Y; here are the failed flags +
  rationale: {flag_list}". Loop back to step 4 (regenerate with
  operator feedback) OR step 6 (widen) depending on which flag
  failed. Specifically:
  * `under_friction_budget` fail → widen via step 6
  * `allows_too_broad` fail → tighten via regenerate with narrower
    heuristic (step 4 with `lean_permissive: false` for the offending
    rule) OR scope-down the offending allow
  * `blocks_known_risk_shapes` fail → add deny rule for the
    adversarial pattern (step 4 with explicit deny)
  * `narrows_vs_admin_baseline` fail → profile is essentially
    "allow everything we saw" — regenerate with `lean_permissive:
    true` AND a narrower window
* `"THEATER"` → most flags failed. Surface flag failures; agent
  recommends `lean_permissive: true` regenerate (or scope adjustment).
  Loop back to step 4 with explicit narrowing. Do NOT save.
* `"NEGATIVE-VALUE"` → HALT. Flag profile as actively dangerous; show
  diff vs admin baseline; require explicit operator override before
  proceeding. Per `[[scorer-is-ground-truth]]` this halt is
  load-bearing — the recipe does NOT have an "override automatically"
  path; the operator's agent must explicitly surface "all 5 flags
  failed; recommended action: discard this profile + restart from
  step 1 with a fresh discovery window."

**HONEST PROVENANCE — surface to operator** (per
`[[ibounce-honest-positioning]]`): if
`provenance.simulator_production_parity == false` (always true today),
the agent MUST echo: "GRADING DEPENDS ON SIMULATOR ACCURACY. The
simulator is pure-Python over the profile dict, not the production
engine. The verdict reflects intent under the simulator's matching
rules; actual production behavior may differ per
`provenance.warnings`."

If `provenance.warnings` contains the schema-parse warning ("profile
schema_parses flag FAILED — other flags were evaluated against the
best-effort parse"), surface this BEFORE acting on the overall
verdict — the verdict accuracy is suspect.

### Step 8 — Save the profile (only on `MEANINGFUL`)

Gate: step 7's `overall == "MEANINGFUL"`. Other verdicts loop back
to step 4 or step 6 first.

```
bounce_profile_save
  yaml: <profile YAML string — serialize the generator-shape dict>
  name: "weekly-ops-2026-05-24"
```

Returns `{path, sha256, name}` on success. Path is
`~/.iam-jit/generated-profiles/<name>/profile.yaml` (override via
`IAM_JIT_GENERATED_PROFILES_DIR`).

Per `[[creates-never-mutates]]` save refuses to overwrite an existing
non-empty bundle dir of the same name. If the operator wants to update
an existing profile, the recipe is "save under new name → diff →
install new → uninstall old."

**Byte-equal sanity** (per `[[creates-never-mutates]]`): after save,
the agent SHOULD read back `<path>` and confirm `sha256` matches the
returned digest. Detects any silent write-side mutation.

### Step 9 — Install + switch from discovery → enforce

Use `bounce profile install` (CLI) or `iam_jit_setup_from_config`
(MCP, if running ambient autonomous protection per
`[[ambient-autonomous-protection]]`). Then switch the bouncer's mode
from discovery to enforce.

**Honest framing**: per `[[ambient-value-prop-and-friction-framing]]`
surface this to operator as "Your bouncer is now actively protecting
{workload}. Recent friction estimate: {N/day}. If you see denials of
legitimate work, run step 12."

### Step 10 — Monitor friction events

Use `iam-jit audit tail --filter verdict=deny` or
`bounce_denies_recent` MCP tool. Each deny is a signal.

The friction budget makes "expected denies" inspectable. If the
post-install rate of legit-denies tracks the simulator's
`friction_estimate_per_day`, the profile is behaving as designed.

### Step 11 — Classify each friction event

When a deny fires:

```
iam_jit_classify_deny
  deny_event: <event from step 10>
```

Returns `appears_legitimate` / `ambiguous` / `appears_adversarial`
with confidence + reasoning.

* `appears_adversarial` → log + alert; this is the value the profile
  delivers. No widen.
* `appears_legitimate` → check budget; if under, log + continue. If
  over, go to step 12.
* `ambiguous` → surface to operator. The classifier prefers
  ambiguous-over-legitimate when uncertain per the
  `[[ibounce-honest-positioning]]` discipline.

### Step 12 — Widen on repeated legitimate deny

If the same legitimate-deny pattern fires 3× within a week (or per
`profile_friction_budget.auto_widen_on_repeat_deny`):

```
iam_jit_improve_profile
  bouncer: ibounce
  cadence: per_session
  threshold: 0.30
  events: <last 7d>
  friction_budget: <operator's config>
  posture: ambient
```

Returns the proposed change (add-allow rule). Surface to operator:
"This pattern legitimately fired 3 times this week and is over your
friction budget. Proposed widening: {rule}. Approve?"

`auto_install: true` skips the prompt if the operator has explicitly
opted into autonomous widening. Default is to require approval per
`[[safety-mode-lean-permissive]]` watch-out #3.

### Step 13 — Weekly re-grade

Periodically (suggested cadence: weekly), re-run
`bounce_grade_profile_for_workflow` against the last-7d audit using
the same shape as step 7. The 4-tier verdict is the deterministic
branch point:

```
bounce_grade_profile_for_workflow
  profile: <currently installed generator-shape dict>
  events: <last-7d OCSF events>
  bouncer_kind: "ibounce"
  friction_budget: <operator's config>
```

* `"MEANINGFUL"` — no action.
* `"PARTIAL"` — surface failed flags; act per the same branch logic
  as step 7 (widen / tighten / restart).
* `"THEATER"` — significant drift; surface to operator; recommend
  regenerate from a more-representative window.
* `"NEGATIVE-VALUE"` — HALT installed profile via
  `iam-jit profile phase reset` per
  `[[ambient-mode-progressive-tightening]]`; treat as production
  incident; restart from step 1.

The simulator's `production_parity: false` caveat (step 5) applies
to every re-grade. Surface it on each cycle so it doesn't become
silent background noise.

### Step 14 — Periodic progressive-tightening review

Per PROFILE-GENERATION-DESIGN.md §10 + `[[ambient-mode-progressive-tightening]]`:
profiles evolve through phases as more history accumulates. Suggested
cadence: weekly (Phase 1) → monthly (Phase 2+) once stable.

```
iam_jit_consider_tightening
  current_profile: <currently installed YAML>
  bouncer: ibounce
  audit_window: {since: 14d}
  operator_signals: {
    workflow_declarations: [...],
    role_declaration: "backend-dev",     # or null
    always_allow_flags: [...]
  }
  friction_budget: <operator's config>
```

Returns either a `TighteningProposal` (with both `narrowing_proposals[]`
AND `suspect_patterns[]` — see step 15) or `NoChange` (with the
`gates_failed[]` list).

**Decision tree for `narrowing_proposals[]`** (the §10 dimension):

* `TighteningProposal.proposed_phase != current_phase` → phase
  transition recommended. Surface to operator: "Profile has been stable
  in {phase} for {N} days; ready to advance to {proposed_phase}.
  Proposed narrowings: {list}. Approve?"
* `TighteningProposal.proposed_phase == current_phase` AND
  `narrowing_proposals` non-empty → in-phase tightening. Surface
  proposed rules; operator approves per-rule.
* `NoChange` with `gates_failed` listed → no action. Surface the
  reason ("pattern stability gate failed — 14 new action shapes in last
  7d, profile would cause friction if narrowed now") so operator
  understands why tightening is paused.

**Operator approval is required** for every narrowing per
`[[safety-mode-lean-permissive]]` watch-out #3. `auto_install: true`
on `iam_jit_consider_tightening` is OPT-IN only and is intentionally
not the default. The phase-transition audit log is operator-visible
per `[[ibounce-honest-positioning]]`.

**Honest framing**: per `[[ambient-mode-progressive-tightening]]`
tightening is OPTIONAL — for highly variable operators (sysadmin role,
exploration work) `NoChange` indefinitely is the correct response, not
a failure mode.

### Step 15 — Suspect-pattern triage (when present)

Per PROFILE-GENERATION-DESIGN.md §11 + `[[progressive-tightening-as-injection-detector]]`:
the same `iam_jit_consider_tightening` call surfaces a parallel
`suspect_patterns[]` block alongside narrowing proposals. Triage as
soon as the call returns — DON'T wait for the next tightening cycle.

For each `SuspectPattern` in the response, route by
`recommended_action`:

| `recommended_action` | Agent action |
|---|---|
| `INVESTIGATE_NOW` | Surface to operator immediately. Provide `shape`, `confidence`, the `events[]` that triggered, `mitre_atlas_tag`, and rationale. Frame as "your bouncer noticed X" per `[[ambient-value-prop-and-friction-framing]]` — not as an error or alert. Operator decides if real or workflow change. |
| `BLOCK_PROACTIVELY` | Fires ONLY on `KNOWN_ADVERSARIAL_PATTERNS` matches; the safety floor (PROFILE-GENERATION-DESIGN.md §2.3) already blocks these. Surface as confirmation: "your bouncer blocked X (known adversarial pattern); evidence recorded." |
| `LOG_AND_OBSERVE` | Log to the audit stream. Revisit next tightening cycle. No operator interruption — these are observations, not events. |

**Honest framing** (per PROFILE-GENERATION-DESIGN.md §11.5 +
`[[ibounce-honest-positioning]]`): the agent MUST frame these as
SUSPECT activity, not CONFIRMED injection. Specifically:

* Use language like "this looks unusual; investigate" — NOT
  "prompt injection detected"
* `suspect_patterns` surfaces SIGNALS; only operator judgment can
  distinguish "workflow change" from "compromised agent"
* High-variability operators will see many false positives;
  that's expected — the noise floor stays high for them

**Don't**:

* Don't auto-block on a single `suspect_patterns` hit (except the
  `KNOWN_ADVERSARIAL_PATTERNS` safety floor, which already blocks
  pre-step-14)
* Don't conflate detection (surfaces signal) with diagnosis (confirms
  intent) — the operator's agent is the diagnostician
* Don't claim "prompt-injection-PROOF" — claim "prompt-injection-AWARE
  through pattern-drift signals" per
  `[[prompt-injection-protection-positioning]]`

## Decision-rubric cheat sheet

| Situation | Action |
|---|---|
| Simulator `summary.deny == 0` + `over_budget == false` | Surface to operator: window may be unrepresentative; consider widening window or tightening heuristic. |
| Simulator `over_budget == true` | Loop step 6 (widen) with operator approval. |
| Simulator `over_budget == false` + `summary.deny > 0` | Proceed to step 7 (grade). |
| Grade `overall == "MEANINGFUL"` (5/5 flags) | Proceed to step 8 (save) + step 9 (install). |
| Grade `overall == "PARTIAL"` (3-4/5 flags) | Surface failed flags; branch per failed flag (widen / tighten / add-deny / regenerate). Loop back to step 4 or 6. |
| Grade `overall == "THEATER"` (1-2/5 flags) | Recommend `lean_permissive: true` regenerate + narrower window. Do NOT save. |
| Grade `overall == "NEGATIVE-VALUE"` (0/5 flags) | HALT. Surface as actively dangerous; require explicit operator override. Do NOT save without override. |
| Grade `provenance.warnings` contains schema warning | Fix schema FIRST; verdict accuracy is suspect until then. |
| Grade `provenance.simulator_production_parity == false` (always today) | Surface caveat to operator on every grade output. |
| Post-install deny classified `appears_legitimate` + under budget | Log + continue. |
| Post-install deny classified `appears_legitimate` + over budget | Auto-widen via `iam_jit_improve_profile` (with approval). |
| Post-install deny classified `appears_adversarial` | Log + alert; this is value. |
| Post-install deny classified `ambiguous` | Surface to operator for triage. |
| Weekly re-grade verdict drifted | Branch as step 13. |
| `iam_jit_consider_tightening` returns `TighteningProposal.proposed_phase != current_phase` | Surface phase transition proposal to operator; wait for approval. |
| `iam_jit_consider_tightening` returns `NoChange` with `gates_failed` | Surface reason to operator; no action this cycle. |
| `suspect_patterns[]` entry with `recommended_action == "INVESTIGATE_NOW"` | Surface to operator immediately (don't wait for next cycle); frame as "your bouncer noticed X." |
| `suspect_patterns[]` entry with `recommended_action == "BLOCK_PROACTIVELY"` | Already blocked by §2.3 safety floor; surface as confirmation. |
| `suspect_patterns[]` entry with `recommended_action == "LOG_AND_OBSERVE"` | Log; revisit next cycle. |
| Operator's role / workflow shape changed materially | Reset profile state to `lean-permissive` via `iam-jit profile phase reset`; rebuild confidence. |

## What this recipe doesn't do

* **Doesn't call any LLM iam-jit-side.** The agent (you) does all
  reasoning with its own LLM credits per
  `[[bouncer-zero-llm-when-agent-in-loop]]`.
* **Doesn't mutate the IAM role / RBAC / DB grants.** Per
  `[[creates-never-mutates]]` — the profile is a layered scope on top
  of the existing role, not a replacement.
* **Doesn't guarantee zero false-positive denies.** Per
  `[[ibounce-honest-positioning]]` — the friction budget is the
  honest framing; the profile aims to keep friction under budget,
  not eliminate it entirely. The weekly grade + improve cycle handle
  drift.
* **Doesn't claim "minimal" / "compliant" / "PCI-ready".** The
  profile is a STARTING POINT per the existing PROFILE-GENERATION.md
  discipline. Compliance is the operator's call.

## Honest caveats

The 5+ observation threshold, the 3/day friction budget, and the
HIGH-uninstall-risk threshold (>5 denies/day) are intuition-derived
**guesses pending calibration** per `[[calibration-quality-bar]]`.
The grading corpus (Phase 10 of the design doc) is the gate before
these thresholds appear in marketing claims. Today they are
defensible defaults; tomorrow they should be evidence-backed.

Steps 14–15 add MORE guesses: the confidence-gate thresholds (§10.2),
phase time floors (§10.1), `SuspectPattern` confidence scores (§11.2),
`sudden_friction_spike` 5× baseline multiplier (§11.3), and
`attack_chain_signature` sequence window (§11.3). All await
Phase 18 UAT + a follow-up grading-corpus effort before any
quantitative claim appears in marketing copy. See
PROFILE-GENERATION-DESIGN.md §9.1.

Per `[[ibounce-honest-positioning]]`: step 15 surfaces **suspect
activity, not confirmed injection**. Marketing language is
"prompt-injection-AWARE through pattern-drift signals" — NEVER
"prompt-injection-PROOF." The IAM role / RBAC / DB grant remains the
actual security boundary; `suspect_patterns` is observability
extension on top.

## Worked example — `reports/` reader profile for ibounce

Synthetic example; **no real account IDs / ARNs / bucket names**. All
shapes mirror `tests/llm/test_grading.py::test_grade_meaningful_profile`
so this example is testable as well as copy-pasteable.

**Setup** (steps 1–2): operator ran a 7-day discovery period for an
agent that reads quarterly reports from S3 + occasionally tries to
create IAM access keys (the latter MUST be denied). Audit query
returned 3 OCSF events:

```yaml
events:
  - _bouncer: ibounce
    time: 1716412800000   # day 0
    api:
      service: {name: s3}
      operation: GetObject
      resources: [{name: "arn:aws:s3:::reports/q1.csv"}]
  - _bouncer: ibounce
    time: 1716499200000   # day 1
    api:
      service: {name: s3}
      operation: GetObject
      resources: [{name: "arn:aws:s3:::sensitive-payroll/data"}]
  - _bouncer: ibounce
    time: 1717017600000   # day 7
    api:
      service: {name: iam}
      operation: CreateAccessKey
      resources: [{name: "arn:aws:iam::111122223333:user/bot"}]
```

**Step 4** — `bounce_profile_generate_from_audit` with
`lean_permissive: true` emits a generator-shape profile:

```yaml
bouncer: ibounce
profile_name: reports-reader-2026-05-24
allows:
  - target: "arn:aws:s3:::reports/*"
    actions: ["s3:GetObject"]
    reason: "narrow read on reports bucket"
denies:
  - target: "arn:aws:s3:::sensitive-*"
    actions: ["s3:GetObject"]
    reason: "sensitive bucket protection (lean-permissive heuristic)"
# safety floor (KNOWN_ADVERSARIAL_PATTERNS) auto-layered:
# iam:CreateAccessKey + iam:AttachRolePolicy + ec2:RunInstances + ...
```

**Step 5** — `bounce_simulate_profile` with `friction_budget: 100`
(weekly):

```yaml
summary: {allow: 1, deny: 2, abstain: 0, total: 3}
friction_metrics:
  budget_max_denies_per_week: 100
  actual_denies_in_window: 2
  estimated_weekly_denies: ~2.0
  over_budget: false
provenance:
  engine: "simulation-python"
  production_parity: false   # <-- ALWAYS surface
  warnings:
    - "ibounce production engine also consults allow_baseline + deny_keywords + deny_actions_with_condition; simulator does not replay these"
```

Agent narrates: "Simulator: 1 allow + 2 denies (1 sensitive-bucket
deny + 1 safety-floor deny on iam:CreateAccessKey). Under friction
budget. Note: simulator is pure-Python; not the production engine."

**Step 7** — `bounce_grade_profile_for_workflow` with the same
`profile` + `events` + `friction_budget: 100`:

```yaml
overall: "MEANINGFUL"
flags:
  - {name: blocks_known_risk_shapes, pass_: true, rationale: "iam:CreateAccessKey adversarial event hit safety floor + denied"}
  - {name: under_friction_budget, pass_: true, rationale: "~2 weekly denies under 100 budget"}
  - {name: allows_too_broad, pass_: true, rationale: "no target='*' + write/admin/destructive pair"}
  - {name: schema_parses, pass_: true, rationale: "generator-shape valid"}
  - {name: narrows_vs_admin_baseline, pass_: true, rationale: "denies sensitive-payroll/data which admin baseline would allow"}
simulation_summary: {allow: 1, deny: 2, abstain: 0, total: 3}
provenance:
  simulator_production_parity: false
  warnings: ["...same as step 5..."]
```

5/5 flags → `MEANINGFUL` → proceed to step 8.

**Step 8** — `bounce_profile_save` with `yaml: <serialized step-4
output>`, `name: "reports-reader-2026-05-24"`. Returns
`{path: "~/.iam-jit/generated-profiles/reports-reader-2026-05-24/profile.yaml", sha256: "...", name: "reports-reader-2026-05-24"}`.

**Step 9** — `bounce profile install` + switch ibounce from
discovery → enforce.

Steps 10–13 monitor + re-grade. If the agent's workflow shifts (e.g.
starts touching `arn:aws:s3:::reports-archive/*`), step 13's weekly
re-grade catches the drift via `simulation_summary.deny` climbing +
operator-classified `appears_legitimate` denies — triggering step 12
widen.

## Composability sidebar

This recipe composes with the rest of the iam-jit suite:

* **`[[ambient-mode-progressive-tightening]]`** — the recipe runs at
  the Phase 1 → Phase 2 transition (when lean-permissive output gets
  tightened by accumulated context). Step 14's
  `iam_jit_consider_tightening` is the mechanism for the transition;
  the verdict-gated branch in step 7 is the safety check that prevents
  premature tightening.
* **`[[bouncer-zero-llm-when-agent-in-loop]]`** — the recipe assumes
  the operator's agent runs the MCP calls + reasons over the output.
  iam-jit emits no LLM tokens for any step in this recipe; the agent's
  own LLM credits drive the reasoning. The deterministic branch at
  step 7 means agents can act on the verdict without a follow-up LLM
  call.
* **`[[create-not-assume-pattern]]`** — the saved profile from step 8
  becomes the spec for short-lived role issuance. iam-jit CREATES the
  role with the profile's allows/denies baked in; the agent assumes
  the new role directly. No held credentials, no profile mutation.
* **`[[ibounce-honest-positioning]]`** — every step surfaces provenance
  warnings honestly: `production_parity: false` at step 5 + 7 + 13;
  `safety floor is deterrent not boundary` at step 9 install; suspect
  patterns are SIGNALS not CONFIRMED INJECTION at step 15. The IAM
  role / RBAC / DB grant remains the actual security boundary
  throughout.
* **`[[discovery-first-default]]`** — step 1's discovery period is
  the post-pivot default mode for all bouncers; this recipe is what
  takes you OUT of discovery and INTO enforce.
* **`[[scorer-is-ground-truth]]`** — the 4-tier overall verdict at
  step 7 is the deterministic branch point. The recipe does NOT add
  exception cases that bypass the `NEGATIVE-VALUE` halt; operator
  override is explicit + audit-logged.

## See also

* [PROFILE-GENERATION-DESIGN.md](../PROFILE-GENERATION-DESIGN.md) —
  the full design + implementation phase plan
* [PROFILE-GENERATION.md](../PROFILE-GENERATION.md) — existing
  generator docs
* [bouncer-history-to-config-pattern.md](bouncer-history-to-config-pattern.md)
  — sibling recipe (long-range history → per-target config)
* [bouncer-to-role-pattern.md](bouncer-to-role-pattern.md) — sibling
  recipe (bouncer audit → IAM role per Phase E)
* [claude-code.md](claude-code.md) / [cursor.md](cursor.md) /
  [codex.md](codex.md) / [devin.md](devin.md) /
  [custom-harness.md](custom-harness.md) — per-harness wiring of this
  recipe
