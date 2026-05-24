# Audit → effective profile — the lean-permissive loop (with progressive tightening)

**For the operator's agent.** Walks the full path from "discovery
period is complete" to "enforce mode is on without breaking the
workflow." Implements `[[safety-mode-lean-permissive]]`'s "err on
allowing, but block adversarial shapes" via the design in
[PROFILE-GENERATION-DESIGN.md](../PROFILE-GENERATION-DESIGN.md).

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

This is the dogfood variant-A pre-mortem.

```
bounce_simulate_profile
  profile_yaml: <bundle from step 4>
  bouncer: ibounce
  window: {since: 7d}
  friction_budget: {max_legitimate_denies_per_day: 3, max_legitimate_denies_per_week: 10}
```

Returns the verdict tally + `friction_estimate_per_day` +
`estimated_uninstall_risk` + `recommended_action`.

**Decision tree** (per `recommended_action`):

* `INSTALL_AS_IS` → proceed to step 8.
* `WIDEN_BEFORE_INSTALL` → iterate to step 6.
* `RECONSIDER` → surface to operator with the rationale: "this
  profile blocks nothing useful — should we tighten the heuristic or
  is the audit window not representative?"

### Step 6 — Widen if needed (loop)

If `friction_estimate_per_day > budget.max_legitimate_denies_per_day`:

* Inspect `would_deny_breakdown`. Identify the top-3 deny patterns by
  count.
* For each: is the deny on a write-data / admin / destructive
  classification? If so, widening is the cost of safety — surface to
  operator: "the profile would deny X (count) legitimate writes to
  resource Y; widening allow to {sibling-resource-pattern} would
  bring friction under budget. Approve widening?"
* If operator approves: emit additional allow rule, regenerate
  profile, re-simulate (back to step 5).
* If operator declines: accept the friction; the safety floor is
  load-bearing.

Iteration converges in 1–3 rounds for typical workloads.

### Step 7 — Sanity-check safety floor

If `safety_floor_violations_caught == []`:

* The profile may be too permissive even AFTER heuristic. Surface to
  operator: "the recent audit window contained no adversarial-pattern
  attempts; this is normal but means we have no direct evidence the
  profile would block what it claims to block. The
  `KNOWN_ADVERSARIAL_PATTERNS` floor still applies + would still fire
  if any of those actions are attempted post-install."

### Step 8 — Save the profile

```
bounce_profile_save
  yaml: <profile from step 4>
  name: "weekly-ops-2026-05-24"
```

Per `[[creates-never-mutates]]` save refuses to overwrite. If the
operator wants to update an existing profile, the recipe is "save
under new name → diff → install new → uninstall old."

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

### Step 13 — Weekly re-simulation

Periodically (suggested cadence: weekly), re-run
`bounce_simulate_profile` against the last-7d audit. If friction has
dropped near zero, recommend tightening — the profile may now
over-permit. If friction is steadily climbing, re-evaluate whether
the workflow has changed enough to warrant a new profile generation.

```
bounce_grade_profile_for_workflow
  profile_yaml: <currently installed>
  bouncer: ibounce
  audit_window: {since: 7d}
```

Returns `PROFILE_MEANINGFUL` / `OVER_PERMISSIVE` / `OVER_TIGHT` /
`NEGATIVE_VALUE` / `SCHEMA_INVALID` + rationale + recommended_action.

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
| Simulator says `INSTALL_AS_IS` | Save + install + switch mode. |
| Simulator says `WIDEN_BEFORE_INSTALL` | Loop step 6 with operator approval. |
| Simulator says `RECONSIDER` (blocks nothing) | Surface to operator; consider tighter heuristic or expand audit window. |
| Post-install deny classified `appears_legitimate` + under budget | Log + continue. |
| Post-install deny classified `appears_legitimate` + over budget | Auto-widen via `iam_jit_improve_profile` (with approval). |
| Post-install deny classified `appears_adversarial` | Log + alert; this is value. |
| Post-install deny classified `ambiguous` | Surface to operator for triage. |
| Weekly grade `OVER_TIGHT` | Widen the most-friction-causing pattern. |
| Weekly grade `OVER_PERMISSIVE` | Tighten (regenerate from a narrower window). |
| Weekly grade `NEGATIVE_VALUE` | Surface as launch-blocker to operator; revisit profile from scratch. |
| Weekly grade `SCHEMA_INVALID` | Bug — file via `iam-jit diagnostics bundle`. |
| Weekly grade `PROFILE_MEANINGFUL` | No action. |
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
