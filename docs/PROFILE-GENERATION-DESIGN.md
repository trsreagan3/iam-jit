# Profile-generation design — lean-permissive heuristic + simulation + grading

**Date:** 2026-05-24. **Author:** design agent (no implementation).
**Closes:** UC-17 design gap surfaced in
[MRR-1-USE-CASE-AUDIT-2026-05-24.md](MRR-1-USE-CASE-AUDIT-2026-05-24.md)
(top blocker #1: audit → agent generates profile → install → enforce →
iterate composition never E2E-tested; dogfood variant-A "every legitimate
write denied — uninstall on day 1" symptom).

**Status:** DESIGN ONLY. No code or test changes in this commit. Section 7
enumerates implementation tasks for the parent agent to file.

## Why this is the killer UX

The flow from `[[discovery-first-default]]` + `[[bouncer-informs-agent-informs-iam-jit]]`
+ `[[ambient-autonomous-protection]]` is canonical:

1. Operator installs bouncers in discovery mode.
2. Bouncers observe legitimate traffic; everything passes, everything is
   audit-logged.
3. After a discovery period (hours, a day, a week) the operator (or
   their agent) asks "what should the profile look like?"
4. iam-jit emits a profile bundle from the audit window.
5. Operator switches to enforce mode.
6. Future runs use the pinned profile; out-of-pattern attempts deny.
7. Operator (or agent) iterates as new legitimate patterns surface.

This is the load-bearing pitch of the suite. It is also the surface that
produced the **dogfood variant-A risk**: every legitimate write was
denied; the operator's lived experience was "the bouncer broke my
workflow." That's the uninstall-on-day-1 territory.

**Founder direction 2026-05-24** (verbatim):

> "Once the discovery period is complete, how do we help users/agents
> parse the logs and develop good policy/policies for the bouncers?
> This detail will be very important, and we should err on the side
> of allowing unless directed otherwise — but not so much that it
> isn't useful or isn't blocking anything. How much can be
> blocked/secured will be dependent on each user and their habits."

This design implements that direction. It is anchored to four standing
memos:

* `[[safety-mode-lean-permissive]]` — block rarely; scope + audit + time
  do the real work; block-happy = uninstalled.
* `[[ibounce-honest-positioning]]` — the bouncer is a deterrent + dev
  loop, not a cryptographic boundary. The deterministic floor on
  `KNOWN_ADVERSARIAL_PATTERNS` is the only thing the profile contributes
  that the role itself doesn't.
* `[[bouncer-zero-llm-when-agent-in-loop]]` — iam-jit provides MCP
  tools, recipes, rubrics, heuristics, taxonomy. Operator's LLM does
  the reasoning. This design adds NO LLM calls to iam-jit.
* `[[calibration-quality-bar]]` — any feature shipping a judgment
  claim must have its own corpus. Where this design proposes thresholds
  pending calibration, they are labelled as guesses.

## 1. Tool survey + gap analysis

The pipeline that supports UC-17 today is composed of eight MCP tools.
Per-tool: current behavior, what's missing for lean-permissive use,
proposed extension.

| Tool | Current signature (relevant args) | What's missing for lean-permissive use | Proposed extension |
|---|---|---|---|
| `bounce_query_audit_long_range` | `since` / `until` / `scope_filter` / `bouncer` / `limit` | None for this flow. Already returns OCSF events; agent can group by action prefix. | No change. |
| `bounce_extract_permissions_from_audit` | `since` / `until` / `bouncer` / `limit` → `{permissions: [{action, resources, count}], observed_scope}` | **Critical gap**: does not separate read / write / admin actions. Heuristic in §2 requires that classification. Returns flat list with `count` only — no `first_seen` / `last_seen` / verdict breakdown (allow vs would-deny-in-enforce). | Add `action_class` per entry (read / write / admin / destructive). Add `first_seen` / `last_seen`. Add `allow_count` / `deny_count` (when underlying events were verdict-stamped). Cf. `src/iam_jit/audit_extract/extractor.py:176`. |
| `bounce_profile_generate_from_audit` | `events` / `time_range` / `bouncers` / `add_safety_denies` / `name` / `preferred_backend` | No `lean_permissive` flag — generator currently narrows ALWAYS (every observed resource is exact-match per the strict prompt). That's the dogfood variant-A trigger. Also no friction-budget input. | Add `lean_permissive: bool = false` flag. When `true`: apply §2 heuristic at deterministic-fallback layer (so it works with `[[bouncer-zero-llm-when-agent-in-loop]]` zero-LLM default). Add `friction_budget` passthrough so the deterministic fallback can target it. |
| `bounce_profile_save` | `yaml` / `name` | None for lean-permissive directly. Already refuses overwrite per `[[creates-never-mutates]]`. | No change. Operator-/agent-facing recipe in §5 instructs to call `bounce_simulate_profile` BEFORE save. |
| `iam_jit_improve_profile` | `bouncer` / `cadence` / `threshold` / `posture` / `events` / `auto_install` / ... | Currently runs widen / tighten cycles based on bouncer's recent denies. No coupling to friction budget. No "this deny is legitimate but exceeds budget → widen" path. | Add `friction_budget` input (per-day + per-week thresholds). When a legitimate-deny pattern repeats above budget: surface as `widening_recommended` with concrete proposed allow rule. Today the cycle is one-directional (improve = widen via add-allow); explicit friction-budget input makes the trigger inspectable. |
| `iam_jit_classify_deny` | `deny_event` → `{classification, confidence, reasoning}` | None for lean-permissive directly. Already does legit / ambiguous / adversarial. | No change. But §3 simulation tool depends on `KNOWN_ADVERSARIAL_PATTERNS` being callable as a pure predicate; extract that to a public predicate (`src/iam_jit/deny_classifier/classifier.py:_is_known_adversarial` → public). |
| `iam_jit_handle_deny` | `deny_event` → `{next_action}` | None for this flow. | No change. |
| `iam_jit_request_role_from_synthesis` | `permissions` / `evidence` → role-request | None for this flow specifically (it's downstream — IAM-role-issuance, not bouncer profile). | No change. |

**Two new MCP tools** spec'd below — `bounce_simulate_profile` (§3) and
`bounce_grade_profile_for_workflow` (§4).

## 2. Lean-permissive heuristic

The heuristic codifies "err on allowing unless directed otherwise; but
not so much that it isn't useful or isn't blocking anything." It runs
when `bounce_profile_generate_from_audit` is called with
`lean_permissive=true`. It runs entirely deterministically — it never
calls an LLM (per `[[bouncer-zero-llm-when-agent-in-loop]]`).

### 2.1 Action classification

Every observed `service:Action` (or kbouncer verb, dbouncer SQL, gbouncer
method+path) is classified into one of four classes. The classifier is a
pure prefix / pattern match — auditable, deterministic, snapshot-testable.

| Class | Examples (per-bouncer) | Default disposition |
|---|---|---|
| **read** | ibounce: `s3:Get*`, `s3:List*`, `s3:Head*`, `*:Describe*`, `*:Get*`, `*:List*`. kbouncer: `get`, `list`, `watch`. dbouncer: `SELECT`. gbouncer: `GET`, `HEAD`, `OPTIONS`. | **Allow broadly** — service-level wildcard permitted (`s3:Get*` on `*`) when 5+ observations across 2+ resources. |
| **write-data** | ibounce: `*:Put*`, `*:Update*`, `*:Modify*`, `*:Tag*`, `s3:CopyObject`. kbouncer: `update`, `patch`, `apply`. dbouncer: `INSERT`, `UPDATE`. gbouncer: `POST`, `PUT`, `PATCH`. | **Tight** — exact action + exact resource ARN (or tightest covering pattern). |
| **admin / network / IAM** | ibounce: `iam:Create*`, `iam:Delete*`, `iam:Put*Policy`, `iam:Attach*`, `ec2:Authorize*`, `ec2:Revoke*`, `route53:Change*`, anything in `KNOWN_ADVERSARIAL_PATTERNS`. kbouncer: `rbac.authorization.k8s.io/*`, `create clusterrolebinding`, `delete namespace`. dbouncer: `GRANT`, `REVOKE`, `DROP`, `TRUNCATE`, `ALTER USER`. gbouncer: `CONNECT` to IMDS / `*.aws.amazon.com/sts`. | **Very tight** — exact action + exact resource + observed count must be 3+; otherwise `flagged_for_review`. Adversarial-pattern matches NEVER auto-include even if observed (intentional separation: agent could be exploited). |
| **destructive-data** | ibounce: `s3:DeleteObject`, `dynamodb:DeleteItem`, `*:DeleteBucket`, `rds:DeleteDBInstance`. kbouncer: `delete deployment`, `delete pod`. dbouncer: `DELETE FROM`, `DROP TABLE`. gbouncer: `DELETE` method. | **Tight even if observed 100×** — exact action + exact resource (no widening). High-blast-radius. |

Where these classes are derived (one source of truth): a new
`src/iam_jit/profile_heuristic/classify.py` module (proposed Phase 1 task
in §7) with per-bouncer prefix tables. Pure data, no service call.

### 2.2 Confidence-weighted include / exclude

Per-action observation count drives auto-include vs review-flag:

| Signal | Heuristic | Action |
|---|---|---|
| Strong | `count >= 5` AND across `>= 2` distinct resources | Auto-include per class disposition |
| Medium | `count` between 2 and 4 | Include with `flagged_for_review: "low-confidence pattern (N observations)"` |
| Weak | `count == 1` | Read: include + flag. Write / admin / destructive: SKIP + record in `skipped` block with reason. |
| Not observed but adjacent | Same resource ARN, sibling action prefix (e.g., observed `s3:GetObject` on bucket X, `s3:ListBucket` not observed) | Read: include silently. Write / admin: do not include. |

The thresholds (`5`, `2`) are **guesses pending calibration** per
`[[calibration-quality-bar]]`. They produce reasonable behavior on
synthetic data but need a real-traffic corpus to defend. The grading
rubric in §4 is the corpus framework that closes this gap.

### 2.3 Anti-theater safety floor (NEVER opt-out)

Regardless of observations, certain rules ALWAYS apply when
`add_safety_denies=true` (the default per the post-pivot playbook):

* All `KNOWN_ADVERSARIAL_PATTERNS` from
  `src/iam_jit/deny_classifier/prompts.py:28` are emitted as denies.
* Adversarial-shape combinations are denied even if individually observed.
  Example: `iam:PutRolePolicy` + `iam:CreateAccessKey` together on
  same session → both denied as a privilege-escalation pair.
* On-account-modify actions never observed are NEVER speculatively
  included (no "you observed `iam:GetRole`, here's `iam:CreateRole` too").
* Per-bouncer `_SAFETY_FLOOR_DENIES` (existing,
  `src/iam_jit/llm/profile_generator.py:666`) stays.

The safety floor is hardcoded — not a config knob. Per
`[[safety-mode-lean-permissive]]` watch-out #2: "a customer who can
configure away the floor has defeated the entire point."

### 2.4 Rationale

The split between READ-broad / WRITE-tight is the same intuition
operators apply manually. It maximizes the lean-permissive direction
where the blast radius is small (read) and applies tight scope where
the blast radius is large (write / admin / destructive). It does NOT
attempt to be cleverer than the deterministic classifier — every choice
is auditable, no LLM judgment involved.

This is consistent with `[[scorer-is-ground-truth]]`: the deterministic
scorer is the calibration anchor; profile-generation is downstream
commentary informed by audit observations. The heuristic does not score
risk — it shapes scope based on observed-vs-not-observed and a fixed
per-class disposition.

## 3. Simulation preview MCP tool — `bounce_simulate_profile` (NEW)

**Purpose:** preview the friction the profile would produce against
recent audit history BEFORE saving / installing. Closes the dogfood
variant-A pre-mortem. Operator's agent calls this between
`bounce_profile_generate_from_audit` and `bounce_profile_save`.

### 3.1 Signature

```python
def bounce_simulate_profile(args: dict) -> dict:
    """
    args:
      profile_yaml: str            # the profile to simulate
      bouncer: str                 # which bouncer profile applies to
      window:
        since: str                 # ISO 8601 or short form (1h, 1d, 7d)
        until: str | None
      friction_budget: dict | None # see §4.1; default LOW
      simulate_against_token: str | None  # bouncer audit-events token

    returns SimulationResult — see schema below.
    """
```

### 3.2 Result schema

```jsonc
{
  "status": "ok",
  "profile_id": "<sha256 of profile_yaml>",
  "bouncer": "ibounce",
  "window": {"from": "2026-05-17T00:00Z", "to": "2026-05-24T00:00Z"},
  "total_decisions": 12847,
  "would_allow": 12791,
  "would_deny": 56,
  "would_deny_breakdown": {
    "s3:": [{"action": "s3:PutObject", "resource": "arn:...", "count": 12, "observed_count_in_window": 14}],
    "iam:": [{"action": "iam:CreateRole", "resource": "*", "count": 1, "classified_as": "appears_adversarial"}]
  },
  "friction_estimate_per_day": 8.0,
  "friction_estimate_per_week": 56.0,
  "estimated_uninstall_risk": "HIGH",
  "safety_floor_violations_caught": ["iam:CreateAccessKey on iam:::user/bot — KNOWN_ADVERSARIAL_PATTERNS"],
  "recommended_action": "WIDEN_BEFORE_INSTALL",
  "notes": [
    "S3 writes denied (12/day) — heuristic classified as write-tight; recent traffic shows writes on this bucket are routine. Consider widening allow to s3:PutObject on bucket pattern.",
    "iam:CreateRole denied — matches KNOWN_ADVERSARIAL_PATTERNS; profile correctly blocks."
  ]
}
```

### 3.3 Recommended-action rubric

| Inputs | Recommended action |
|---|---|
| `friction_estimate_per_day <= friction_budget.max_legitimate_denies_per_day` AND `safety_floor_violations_caught != []` | `INSTALL_AS_IS` |
| `friction_estimate_per_day > friction_budget.max_legitimate_denies_per_day` AND `safety_floor_violations_caught != []` | `WIDEN_BEFORE_INSTALL` |
| `safety_floor_violations_caught == []` AND `would_deny == 0` | `RECONSIDER` — "this profile blocks nothing useful; the audit window may have already been pre-filtered or the heuristic was too permissive" |
| `safety_floor_violations_caught == []` AND `friction_estimate_per_day > budget` | `RECONSIDER` — "denies friction without blocking anything dangerous" |

### 3.4 `estimated_uninstall_risk` heuristic

* **LOW**: `friction_estimate_per_day <= 1`.
* **MED**: `friction_estimate_per_day` in `(1, 5]`.
* **HIGH**: `friction_estimate_per_day > 5`.

The 1 / 5 thresholds are **guesses pending calibration**. The grading
corpus from §4 should validate that "HIGH" predicts actual uninstall
patterns before the rubric is marketed as quantitative.

### 3.5 Acceptance criteria

1. Pure function — no I/O beyond optional audit-events fetch.
2. Deterministic — same inputs, identical output (no clock-dependent
   state inside the simulation core).
3. State-verification test shape (per CONTRIBUTING.md): assert (a) the
   tool returns the schema; (b) the `would_deny` count matches a
   hand-counted independent re-run of the rules engine over the same
   events; (c) `recommended_action` matches the rubric table.
4. `KNOWN_ADVERSARIAL_PATTERNS` matching uses the same predicate as
   `iam_jit_classify_deny` — no copy-paste of the pattern list.
5. Honest-degradation: if no audit window provided, returns
   `status: "needs_window"` with explanation, not silent allow.

### 3.6 Why this is design-only

The simulation engine REUSES the bouncer's existing rule-evaluation
core. Implementing this is a wiring task, not a new engine — the bouncer
already decides per-event in enforce mode. The work is exposing that
decision as a callable that takes a profile + an event stream and
returns the verdict tally. Phase 2 task in §7.

## 4. Friction budget + `bounce_grade_profile_for_workflow` (NEW)

### 4.1 Operator-set friction budget

Per `[[safety-mode-lean-permissive]]` watch-out #4: "track the
fallback-to-admin rate ... if it exceeds ~20% of grants ... investigation
needed." Same shape, profile-side.

Operator declares budget in `.iam-jit.yaml`:

```yaml
iam-jit:
  profile_friction_budget:
    max_legitimate_denies_per_day: 3   # default LOW-friction
    max_legitimate_denies_per_week: 10
    auto_widen_on_repeat_deny: true    # if same legit deny fires 3×/week, propose widening
```

Defaults are LOW-friction (3 / day, 10 / week) per the founder
direction "lean permissive." Operators with high-security postures can
set lower (`0` = "never deny legit work — only deny adversarial
patterns") or higher.

The budget is consumed by:

* `bounce_simulate_profile` — produces `recommended_action`
* `iam_jit_improve_profile` — drives auto-widen when budget exceeded
* `bounce_grade_profile_for_workflow` — input to grade

### 4.2 Grading rubric MCP tool

**Purpose:** grade a profile against an audit window + a friction budget
on five dimensions. Borrows the shape of
`[[role-effectiveness-corpus]]`'s `MEANINGFUL / PARTIAL / THEATER /
NEGATIVE-VALUE` rubric.

```python
def bounce_grade_profile_for_workflow(args: dict) -> dict:
    """
    args:
      profile_yaml: str
      bouncer: str
      audit_window: {since, until}
      friction_budget: dict | None  # uses operator default if absent
      simulate_against_token: str | None

    returns:
      {
        "grade": "PROFILE_MEANINGFUL"  # or OVER_PERMISSIVE / OVER_TIGHT / SCHEMA_INVALID / NEGATIVE_VALUE
        "rationale": {
          "blocks_known_risk_shapes": bool,
          "blocks_known_risk_shapes_evidence": [...],   # specific KNOWN_ADVERSARIAL_PATTERNS matched
          "under_friction_budget": bool,
          "actual_friction_per_day": float,
          "allows_too_broad": [...],   # write-tight class with wildcard
          "schema_parses": bool,
          "narrows_vs_admin_baseline": bool,
          "narrows_evidence": "..."
        },
        "recommended_action": "INSTALL" | "WIDEN" | "TIGHTEN" | "RECONSIDER" | "FIX_SCHEMA"
      }
    """
```

### 4.3 Grade definitions

| Grade | Means | Trigger |
|---|---|---|
| `PROFILE_MEANINGFUL` | Blocks ≥1 risk shape; under friction budget; narrows vs admin baseline | All four rationale flags true |
| `OVER_PERMISSIVE` | Friction OK; but doesn't block risk shapes that should be blocked (`safety_floor_violations_caught == []`) | `blocks_known_risk_shapes = false` |
| `OVER_TIGHT` | Denies legit work over budget | `actual_friction_per_day > budget.max_legitimate_denies_per_day` |
| `SCHEMA_INVALID` | Profile YAML doesn't parse / install | `schema_parses = false` (short-circuits other checks) |
| `NEGATIVE_VALUE` | Would cause more harm than help (e.g., denies essential audit-write but allows admin-creation) | Heuristic: `over_tight AND over_permissive_for_a_KNOWN_ADVERSARIAL_pattern` |

### 4.4 Calibration honesty

The grade meanings are inspectable per-dimension (rationale block) so
operators / auditors can disagree with the headline grade and see why.
The 5-grade taxonomy is itself a **guess pending validation against a
corpus**. Phase 3 task in §7 is "build the grading corpus" — 20–30
profile + audit-window pairs across the 4 bouncers, graded by a
human, with the tool's output compared. Same shape as
`[[role-effectiveness-corpus]]`.

### 4.5 Operator UX

The grade is the headline; the rationale is the explainer; the
recommended_action is the next-step. This matches the
`[[ambient-value-prop-and-friction-framing]]` rule: every surface
frames "your bouncer caught X; here's how to react" — not "ERROR."

## 5. Canonical recipe

The operator-facing flow is in a separate doc at
[HARNESS-RECIPES/audit-to-effective-profile.md](HARNESS-RECIPES/audit-to-effective-profile.md).
It walks the operator's agent through the full lean-permissive loop
end-to-end. Per `[[bouncer-zero-llm-when-agent-in-loop]]` the agent
does all reasoning; the recipe provides MCP-tool sequence + decision
rubric.

## 6. Implementation phase plan

Ordered. Parent agent files as individual tasks against the
`launch-readiness` epic per the existing convention (`§B**` slot in the
README, or sub-task of `§A92` since this is UC-17 design).

1. **Phase 1 — heuristic module.** New
   `src/iam_jit/profile_heuristic/classify.py`: per-bouncer
   action-classification tables + pure-function classifier. Unit
   tests covering each class per bouncer.
   *State-verification:* assert classifier output is stable across
   `(action, bouncer) → class` pairs in a golden fixture.
2. **Phase 2 — extend `bounce_extract_permissions_from_audit`.** Add
   `action_class` / `first_seen` / `last_seen` / `allow_count` /
   `deny_count` to `PermissionAggregate`. Backward-compatible (existing
   fields stay; new fields additive). Update
   `_bounce_extract_permissions_from_audit_for_mcp` to emit them.
3. **Phase 3 — `lean_permissive` flag on `bounce_profile_generate_from_audit`.**
   Add the heuristic to the deterministic-fallback path
   (`_deterministic_fallback_profile`). Behind a flag so existing
   callers don't shift. New flag defaults to `false`; the recipe and
   the new MCP tool spec recommend `true`.
4. **Phase 4 — simulator core extraction.** Refactor the bouncer's
   rule-evaluation core into a callable
   `evaluate_profile_against_events(profile, events) -> Verdicts`.
   This is the engine the new `bounce_simulate_profile` MCP tool wraps.
   Reuses existing rule-evaluation logic.
5. **Phase 5 — `bounce_simulate_profile` MCP tool.** Wire the simulator
   into `mcp_server.py`. Per §3 spec. State-verification test +
   schema test.
6. **Phase 6 — friction-budget config.** Add
   `profile_friction_budget` block to the `.iam-jit.yaml` loader.
   Default = LOW (3/day, 10/week). Surface via `iam-jit doctor`.
7. **Phase 7 — `bounce_grade_profile_for_workflow` MCP tool.** Per §4
   spec. Reuses the simulator from Phase 4.
8. **Phase 8 — `iam_jit_improve_profile` friction-budget input.** Pipe
   the friction budget into the improve cycle so widen-recommendations
   are budget-aware.
9. **Phase 9 — `audit-to-effective-profile.md` recipe linked from
   per-harness docs.** Adds the recipe to `claude-code.md`,
   `cursor.md`, `codex.md`, `devin.md`, `custom-harness.md`.
10. **Phase 10 — grading corpus.** Build 20–30 profile + audit-window
    fixtures; have a human grade each; compare tool output. Same shape
    as `[[role-effectiveness-corpus]]`. Surfaces in
    `tests/dogfood/profile-grading.md` (NEW).
11. **Phase 11 — UC-17 E2E test (#528).** Test that runs the WHOLE
    flow against actual bouncer binaries: discovery → audit → extract
    → generate → simulate → save → install → enforce → iterate. Closes
    the MRR-1 #1 blocker.
12. **Phase 12 — independent-agent UAT.** Per
    `[[tests-and-independent-uat-required]]` — different agent than
    Phases 1–11 implementer runs the recipe against a real bouncer and
    grades it MEANINGFUL / PARTIAL / THEATER / NEGATIVE-VALUE.

Estimated effort: 4–6 agent-days across Phases 1–9; +1.5 days Phase 10
(corpus); +0.5 day Phase 11; +0.5 day Phase 12. Total **6.5–8.5 agent-days**
(rough; calibrate after Phase 2 lands).

### 6.1 Progressive-tightening + suspect-pattern extension (Phases 13–18)

Per §10 + §11. Builds on Phases 1–12 — assumes the simulator core
(Phase 4) + heuristic module (Phase 1) + extended extract output
(Phase 2) + friction-budget config (Phase 6) are in place.

13. **Phase 13 — `iam_jit_consider_tightening` MCP tool.** Per §10.3 +
    §11.2. Single tool surface; emits both `narrowing_proposals[]`
    (§10) AND `suspect_patterns[]` (§11) blocks alongside
    `ConfidenceMetrics`. Wires into `mcp_server.py`. State-verification
    test + schema test. **~1.5 agent-days.**
14. **Phase 14 — confidence-metrics aggregator.** Implements
    `pattern_stability_score`, `friction_consumption_rate`,
    `days_in_current_phase`, `operator_widen_rules_added_recent`,
    `distinct_patterns_observed`, `unprecedented_actions_count` per
    §10.4. Pure-function deterministic aggregator over the audit window
    + profile state. Unit tests per metric. **~1 agent-day.**
15. **Phase 15 — phase-transition state machine.** Persists
    `.iam-jit/profile_state.json` per §10.5. Append-only audit log of
    every transition. CLI surface (`iam-jit profile phase show` /
    `iam-jit profile phase reset`). Transition rules enforced
    deterministically (operator-triggered downgrades only; no automatic
    downgrades). **~1 agent-day.**
16. **Phase 16 — suspect-pattern detector helpers.** Implements one
    helper per `SuspectPattern.shape` per §11.3. Reuses Phase H
    z-score primitives for `velocity_anomaly` / `time_of_day_anomaly`.
    Reuses `KNOWN_ADVERSARIAL_PATTERNS` predicate (extracted in §1
    Phase 1 + §7.2). Calibration corpus is **deferred to Phase 18 UAT
    + a follow-up Phase 10-style grading effort** — guesses pending
    calibration per `[[calibration-quality-bar]]`. **~2 agent-days.**
17. **Phase 17 — E2E test for the tightening + suspect-pattern loop.**
    Synthetic audit window covering 3 phase transitions (lean-permissive
    → confidence-tightened → habit-trained) + 3 suspect-pattern shapes
    (`sudden_friction_spike`, `unprecedented_action`,
    `known_adversarial_pattern_match`). Asserts tool output shape +
    operator-visible audit log entries. **~1 agent-day.**
18. **Phase 18 — independent-agent UAT.** Per
    `[[tests-and-independent-uat-required]]` — different agent than
    Phases 13–17 implementer runs the tightening loop end-to-end across
    a multi-week synthetic audit window + grades both
    `narrowing_proposals` and `suspect_patterns` output as MEANINGFUL /
    PARTIAL / THEATER / NEGATIVE-VALUE per
    `[[role-effectiveness-corpus]]` taxonomy. **~separate task.**

**Extension total**: ~6.5 agent-days on top of Phases 1–12. Grand
total: **~13–15 agent-days** end-to-end.

Phases 13–18 are STRICTLY downstream of Phases 1–12. Don't start them
until at least Phases 1, 2, 4, and 6 have landed — they depend on the
heuristic module, extended extract output, simulator core, and
friction-budget config respectively.

## 7. Anti-theater safeguards

1. **Heuristic thresholds are inspectable.** Every choice
   (`5+ observations`, `friction_budget = 3/day`,
   `uninstall_risk = HIGH > 5/day`) is in a config-visible table, not
   hardcoded inside an LLM prompt.
2. **`KNOWN_ADVERSARIAL_PATTERNS` matching is a pure predicate** —
   shared between `iam_jit_classify_deny`, `bounce_simulate_profile`,
   and `bounce_grade_profile_for_workflow`. No drift between the three
   surfaces.
3. **Safety floor is hardcoded.** Per `[[safety-mode-lean-permissive]]`
   watch-out #2 the `_SAFETY_FLOOR_DENIES` block + the
   `KNOWN_ADVERSARIAL_PATTERNS` block stay out of operator-config reach.
4. **Grading rubric distinguishes "blocks nothing" from "blocks
   correctly."** `OVER_PERMISSIVE` grade fires when `would_deny == 0`
   AND `safety_floor_violations_caught == []` — preventing the
   "perfect profile that catches nothing" theater outcome.
5. **All four bouncer classes covered by the heuristic.** ibounce
   (action prefixes), kbouncer (verb + resource), dbouncer (statement
   class), gbouncer (method + host). Single source-of-truth per-bouncer
   table; cross-product parity per `[[cross-product-agent-parity]]`.
6. **No NL synthesis path.** The lean-permissive flag drives the
   DETERMINISTIC fallback, not the LLM path. Per
   `[[no-nl-synthesis]]` + `[[bouncer-zero-llm-when-agent-in-loop]]`
   the heuristic is data-table-driven, not prompt-driven. (The LLM path
   still exists for non-lean-permissive use, opt-in via
   `IAM_JIT_ENABLE_SIDE_LLM`.)
7. **Honest framing surfaces.** `recommended_action: "RECONSIDER"` +
   notes like "this profile blocks nothing useful" surface
   theater-shape outcomes; the operator's agent can act on them.

## 8. Cross-cutting composition

| Existing piece | How this design composes with it |
|---|---|
| `iam_jit_classify_deny` (Phase H is downstream) | Same `KNOWN_ADVERSARIAL_PATTERNS` predicate; classifier triages denies POST-install; widen-vs-stay is informed by classification. |
| `iam_jit_improve_profile` | Phase 8 adds friction-budget input. Cycle becomes: simulate (pre-install) → install → observe → on-friction-event classify → if legit + over-budget widen via improve_profile. |
| Phase H anomaly detection (`anomaly_detection/`) | Monitors behavioral anomalies POST-profile-install. Complementary, not overlapping — Phase H detects deviation from observed BASELINE; this design generates the INITIAL profile that determines baseline. |
| `[[discovery-first-default]]` | This design is the bridge from "discovery observes everything" → "enforce blocks correctly without breaking workflow." Without this design the bridge is undocumented and untested (= MRR-1 #1). |
| `[[ambient-autonomous-protection]]` Phase E (`[[bouncer-informs-agent-informs-iam-jit]]`) | Phase E is the audit → role-request flow (IAM role issuance). This design is the audit → bouncer-profile flow. Both use `bounce_extract_permissions_from_audit` as the upstream primitive; Phase E feeds `iam_jit_request_role_from_synthesis`, this design feeds `bounce_profile_generate_from_audit`. |
| `[[role-effectiveness-corpus]]` | Phase 10 corpus uses the same MEANINGFUL / PARTIAL / THEATER / NEGATIVE-VALUE grade taxonomy + the same scorer-corpus discipline. Two corpora, same framework. |
| `[[calibration-quality-bar]]` | Three thresholds in this design (`5+ observations`, `3/day budget`, `>5/day = HIGH risk`) are guesses pending calibration. Phase 10 corpus is the gate before any marketing claim quantifies them. |
| `[[scorer-is-ground-truth]]` | This design does NOT change scorer behavior. The scorer remains the calibration anchor; profile-generation is downstream commentary informed by audit observations. |
| MRR-1 #1 (UC-17 CRIT) | Phase 11 E2E test closes this blocker. The whole-loop test against real bouncer binaries IS the composition-gap close. |
| MRR-1 #2 (UC-20 CRIT — `iam_jit_setup_from_config`) | Indirect: a properly-graded profile is a sensible default for setup-from-config to install initially; reduces the "first profile installed via ambient autonomous protection is wrong" risk. |
| MRR-2 (error-path audit) | The simulator + grading tools must produce agent-actionable errors ("widen these allows" / "reconsider — blocks nothing"), not silent degradation. Cross-link MRR-2's actionable-error rubric. |
| MRR-5 (in-flight monitoring) | Friction-budget exceeded events become a monitored signal. If a bouncer is exceeding budget post-install, monitoring fires; auto-widen or operator intervention follows. |

## 9. Honest "what's a guess pending calibration"

Explicit per `[[ibounce-honest-positioning]]`:

1. **Observation-count thresholds** (`5+` = strong; `2–4` = medium; `1`
   = weak). Pulled from intuition + the `[[role-effectiveness-corpus]]`
   shape. Need real-traffic corpus to defend; Phase 10 closes.
2. **Friction-budget defaults** (`3/day`, `10/week`). Pulled from
   `[[safety-mode-lean-permissive]]`'s "once an hour = uninstall; once
   a week = fine" range. Defensible as defaults but the
   recommended-action rubric will need calibration before marketing.
3. **`estimated_uninstall_risk` thresholds** (`HIGH > 5/day`). The
   highest-confidence claim is qualitative ("if X happens, operator
   uninstalls"). Quantitative thresholds will need correlation
   evidence (does HIGH actually predict uninstall?) before they appear
   in marketing copy.
4. **Per-bouncer class prefix tables** — initial pass derived from
   inspection of AWS / K8s / SQL / HTTP common verbs. Coverage gaps
   likely; deferring to the grading corpus (Phase 10) is how they
   surface.
5. **`OVER_PERMISSIVE` vs `OVER_TIGHT` boundary** — derived from
   `friction_budget`. A profile that crosses both flips to
   `NEGATIVE_VALUE`. Boundary cases need corpus validation.

All five guesses are labelled in the doc; none should appear in
marketing copy until Phase 10 produces validation evidence.

### 9.1 Additional guesses from §10 + §11 (progressive tightening + suspect patterns)

6. **Confidence-gate thresholds** (§10.2) — "X new unique
   patterns/week" floor, "N days without operator widen-rule" floor,
   ">X observations of each pattern being narrowed" floor. All guesses;
   need a multi-week real-traffic corpus to defend before any auto-
   tightening fires unattended. Phase 18 UAT is the first calibration
   data point.
7. **Phase time floors** (§10.1) — `7d` lean-permissive → confidence-
   tightened; `+23d` → habit-trained; `+30d` → stable. Pulled from
   `[[ambient-mode-progressive-tightening]]` shape; intuitions about
   "enough time to observe a workflow cycle." Need correlation evidence
   (do tighter floors cause friction storms? do longer floors leave
   value on the table?) before quantitative claims.
8. **`SuspectPattern` confidence scores** (§11.2) — per-shape
   `confidence: float` field is uncalibrated at design time. Phase 16
   helpers must produce a number; what range corresponds to
   `INVESTIGATE_NOW` vs `LOG_AND_OBSERVE` is itself a calibration
   question. Don't market quantitative confidence claims (e.g. "94%
   accurate detection") until corpus validates.
9. **`sudden_friction_spike` "5× baseline" threshold** (§11.3) —
   chosen for being clearly above natural variation, not from
   measurement. Need real legitimate-traffic baselines per bouncer to
   defend the multiplier.
10. **`attack_chain_signature` "N minutes" sequence window** (§11.3) —
    needs threat-model calibration: real adversarial chains have
    timing characteristics; the window must be wide enough to catch
    them without flagging legitimate sequential-task work.

Guesses 6–10 join 1–5 on the "no marketing claim until calibrated"
list. Phase 18 UAT + a follow-up grading-corpus effort (mirror of
Phase 10) is the gate.

## 10. Progressive tightening over time

Per `[[ambient-mode-progressive-tightening]]` (founder direction 2026-05-24):
the profile shape generated by §2 is the **Phase 1 starting point**, not the
terminal state. Profiles evolve through five phases as (a) more audit
history accumulates and (b) more operator-supplied context arrives.
Tightening is **optional** per the founder qualifier "if possible" —
operators with highly variable habits stay permissive forever, and that
is correct behavior.

This section composes with §1–§9 by adding a time dimension. The
heuristic in §2 produces the Phase 1 profile; this section specifies how
it tightens (or doesn't) afterward.

### 10.1 The five-phase trajectory

| Phase | Window | Profile shape | Tightening signal |
|---|---|---|---|
| **0. Discovery** | Day 0 → N days | Pass-through; observe only; never deny except `KNOWN_ADVERSARIAL_PATTERNS` safety floor | n/a (still building baseline) |
| **1. Lean-permissive enforce** | Day N → +7d | Generated per design §2 heuristic | "discovery period complete" — operator (or operator's agent) confirms switch |
| **2. Confidence-tightened** | Day N+7 → +30d | Reduce read-broad to observed services only; tighten observed-margin where confidence is high | Auto-trigger when same patterns recur >X times AND no new pattern shapes in last 7d AND friction stays under budget |
| **3. Habit-trained** | Month 2+ | Tight; minimal observed-margin; explicit per-task widening operator-driven only | Auto-trigger when profile stable + operator hasn't added widening rules in 14d + friction well under budget |
| **4. Stable** | Month 3+ | No further auto-tightening unless operator signals "I'm doing more of X now" | Operator-driven only |

Phases 0 → 1 is already covered by §1–§9 (discovery → lean-permissive
generation → simulate → install). Phases 1 → 2 → 3 → 4 are the new
trajectory this section adds.

### 10.2 Confidence-gate — all five must hold

A phase transition (or in-phase narrowing) requires **ALL** of:

1. **Time floor**: ≥7d in current phase (don't whiplash on a single quiet week)
2. **Pattern stability**: same audit-shape recurring; <X new unique patterns/week
3. **Friction budget**: legitimate denies under operator's configured budget per §4.1
4. **Confidence threshold**: >X observations of each pattern being narrowed (per §2.2 confidence-weighted heuristic)
5. **Operator signal**: either explicit "go ahead and tighten" OR implicit (no operator widen-rules added in N days)

If ANY fails → stay at current phase. The defaults for "X" thresholds
are **guesses pending calibration** per `[[calibration-quality-bar]]` —
see §9.1 for the explicit guesses list; Phase 18 UAT (§6.1) + a
follow-up grading-corpus effort (mirror of Phase 10) are the
calibration gate before any quantitative claim is marketed.

### 10.3 New MCP tool — `iam_jit_consider_tightening`

**Purpose:** the agent invokes this periodically (suggested: weekly) or
on-demand. Returns either a `TighteningProposal` (with concrete
narrowing proposals + suspect_patterns per §11) or `NoChange` (with
which gate failed). Per `[[bouncer-zero-llm-when-agent-in-loop]]` the
tool is deterministic — it surfaces signals; the operator's agent
reasons over them.

```python
def iam_jit_consider_tightening(args: dict) -> dict:
    """
    args:
      current_profile: str         # YAML of currently-installed profile
      bouncer: str
      audit_window: {since, until}
      operator_signals: dict | None  # workflow declarations, role
                                     # declarations, friction tolerance,
                                     # always-allow flags
      friction_budget: dict | None   # uses operator default if absent

    returns TighteningProposal | NoChange (see schemas below).
    """
```

```python
@dataclass
class TighteningProposal:
    current_phase: Literal["lean-permissive", "confidence-tightened",
                           "habit-trained", "stable"]
    proposed_phase: str  # may equal current_phase (narrow within phase)
                         # or advance to next phase
    narrowing_proposals: list[NarrowingProposal]  # concrete tighten rules
    suspect_patterns: list[SuspectPattern]        # see §11
    operator_attention_required: bool
    confidence_metrics: ConfidenceMetrics  # see §10.4
    rationale: str  # operator-readable narration

@dataclass
class NoChange:
    current_phase: str
    gates_failed: list[Literal["time_floor", "pattern_stability",
                               "friction_budget", "confidence_threshold",
                               "operator_signal"]]
    rationale: str  # e.g. "pattern_stability gate failed — 14 new
                    # action shapes observed in last 7d; profile would
                    # cause friction if narrowed now"
```

### 10.4 `ConfidenceMetrics` aggregator

Surfaced for operator inspection (per `[[ibounce-honest-positioning]]`
no hidden tightening):

```python
@dataclass
class ConfidenceMetrics:
    pattern_stability_score: float  # 0-1; 1 = no new shapes in window
    friction_consumption_rate: float  # legit-denies/day / budget/day
    days_in_current_phase: int
    operator_widen_rules_added_recent: int  # last 14d
    distinct_patterns_observed: int
    unprecedented_actions_count: int  # this informs §11 too
```

### 10.5 Phase-transition state machine

The phase state lives in `.iam-jit/profile_state.json` alongside the
profile bundle. Transitions are **append-only audit log** — every
transition is operator-visible per `[[ibounce-honest-positioning]]`.

Allowed transitions:

* `discovery → lean-permissive` — operator confirms after §1–§9 flow
* `lean-permissive → confidence-tightened` — confidence-gate passes
* `confidence-tightened → habit-trained` — confidence-gate passes again
* `habit-trained → stable` — confidence-gate passes again
* **Any → lean-permissive** — operator-triggered "reset" (e.g. role change)
* **Any → discovery** — operator-triggered "fresh start"

No automatic downgrades. If friction spikes mid-`stable` the response is
to **widen via `iam_jit_improve_profile`** (§4) — not to silently
downgrade the phase.

### 10.6 Context inputs from operator

Explicit operator signals that inform tightening (separate from passive
audit history):

* **Workflow declarations**: "I'm doing X kind of work this week" →
  temporarily widen for that workflow without changing phase
* **Role declarations**: "I'm a backend dev, never touch IAM" → tighten
  IAM-class actions faster (Phase 2 jumps to admin-very-tight on
  shorter time floor)
* **Friction tolerance**: per-operator `max_legitimate_denies_per_week`
  from §4.1
* **Always-allow flags**: operator marks specific patterns as "always
  allow, never narrow"
* **Block-now requests**: operator explicitly says "block X" → tight
  immediately (skips confidence-gate; operator intent is the signal)

### 10.7 Anti-patterns to avoid

Per `[[ambient-mode-progressive-tightening]]`:

* **Calendar-only triggers** — "it's been 14 days, tighten" without
  confidence-gate causes friction storms
* **Auto-removing operator widen-rules** — operator added them for a
  reason; respect them
* **Tightening across role changes** — needs operator-triggered reset
  to lean-permissive, not silent narrowing
* **Hidden tightening** — every transition emits an audit log entry +
  optional notification per `[[ibounce-honest-positioning]]`
* **Tightening that breaks Phase H anomaly baseline** — if anomaly
  detection is enabled, narrowing shouldn't invalidate the baseline
  without explicit reset

### 10.8 Honest framing

Per `[[ibounce-honest-positioning]]`: this section MUST be marketed
with the **"if possible"** qualifier verbatim. Specifically:

* Don't claim "auto-tightens over time" without the qualifier
* Don't claim "stable phase = secure" — stable just means no auto-changes
* For highly variable operators (sysadmin role, exploration work),
  staying in Phase 1 forever is **correct behavior, not failure**
* The deterministic safety floor (§2.3) carries the load regardless of
  phase — tightening is layered on top, not foundational to safety

## 11. Same process surfaces prompt-injection-suspect signals

Per `[[progressive-tightening-as-injection-detector]]` (founder
insight 2026-05-24): the data flow that drives §10's tightening
proposals also produces the model needed for prompt-injection signal
surfacing. Not separate features — same observability work, second
output dimension.

### 11.1 Why these are the same problem

Process artifacts from §10 that DOUBLE as prompt-injection signals:

| Artifact (from §10) | PI signal |
|---|---|
| Friction-budget tracking (§4.1) | Sudden spike = behavior outside trained pattern |
| Confidence-weighted patterns (§2.2) | Action with `confidence = 0` = unprecedented |
| Resource-pattern observation (§2.1) | Resource never touched = suspicious |
| Phase H z-score baseline (existing) | Time-of-day / velocity anomalies |
| `KNOWN_ADVERSARIAL_PATTERNS` (§2.3) | Direct pattern match |
| `pattern_stability_score` (§10.4) | Discontinuity = something changed |
| Sequence audit log | Attack-chain pattern (recon → escalate → exfil) |

The MORE the profile-tightening matures, the BETTER the PI
signal-to-noise. They co-evolve.

### 11.2 Extension to `iam_jit_consider_tightening` response

The MCP tool defined in §10.3 returns `suspect_patterns[]` alongside
`narrowing_proposals[]`. Same call, two output dimensions, operator's
agent reasons over both per `[[bouncer-zero-llm-when-agent-in-loop]]`.

```python
@dataclass
class SuspectPattern:
    shape: Literal[
        "sudden_friction_spike",         # legit-deny rate jumped 5x baseline
        "unprecedented_action",          # action with confidence=0
        "resource_pattern_drift",        # resource never touched before
        "known_adversarial_pattern_match",  # direct KNOWN_ADVERSARIAL match
        "velocity_anomaly",              # actions/min outside historical
        "time_of_day_anomaly",           # activity outside historical hours
        "attack_chain_signature"         # recon → escalate → exfil sequence
    ]
    confidence: float                    # 0-1; calibration TBD
    events: list[AuditEvent]             # the specific events that triggered
    recommended_action: Literal[
        "INVESTIGATE_NOW",               # surface to operator immediately
        "LOG_AND_OBSERVE",               # log; revisit next cycle
        "BLOCK_PROACTIVELY"              # only when KNOWN_ADVERSARIAL match
    ]
    mitre_atlas_tag: str                 # per Phase H F.5 catalog
    rationale: str                       # operator-readable explanation
```

### 11.3 Per-shape detection sketches

Implementation reuses Phase H z-score primitives where possible:

| Shape | Detection |
|---|---|
| `sudden_friction_spike` | Rolling-7d legit-deny rate; current window > 5× baseline → fire |
| `unprecedented_action` | Action absent from `bounce_extract_permissions_from_audit` historical window → fire |
| `resource_pattern_drift` | Resource ARN / path / table never observed for this action → fire |
| `known_adversarial_pattern_match` | Reuses `iam_jit_classify_deny` `KNOWN_ADVERSARIAL_PATTERNS` predicate (§2.3, §7.2) — no copy-paste |
| `velocity_anomaly` | Reuses Phase H z-score baseline for actions/min |
| `time_of_day_anomaly` | Reuses Phase H z-score baseline for hour-of-day distribution |
| `attack_chain_signature` | Sequence match: 2+ KNOWN_ADVERSARIAL_PATTERNS within N minutes on same session |

The `mitre_atlas_tag` per detection allows operators to map signals to
their existing threat-model frameworks per Phase H F.5.

### 11.4 Mapping to 3-tier prompt-injection framing

Per `[[prompt-injection-protection-positioning]]`:

| Tier | Progressive-tightening phase (§10) | PI signal-to-noise |
|---|---|---|
| **Tier 1** (casual ambient) | Phase 0–1: Discovery → Lean-permissive | Coarse; signals noisy; high false-positive rate |
| **Tier 2** (production managed) | Phase 2: Confidence-tightened | S/N improves with history; usable for triage |
| **Tier 3** (highly-secure strict) | Phase 3–4: Habit-trained → Stable | Any deviation IS a signal; lowest noise floor |

This is the same composition story as §10.1: the protection improves
as the profile matures, but the maturation is operator-paced and
optional.

### 11.5 HONEST FRAMING — AWARE not PROOF

Per `[[ibounce-honest-positioning]]` + `[[prompt-injection-protection-positioning]]`:

**Marketing claim shape**: *prompt-injection-AWARE* through
pattern-drift signals.

**Marketing claim shape MUST NOT be**: *prompt-injection-PROOF*,
*prompt-injection-PROTECTED*, *prompt-injection-IMMUNE*, or any
variant that implies prevention or guaranteed detection.

#### What this DOES deliver

* **Early warning** — deviation from baseline surfaces before damage compounds
* **Blast-radius bounding** — actions still constrained to profile (the
  IAM role / RBAC / DB grant remains the actual boundary per
  `[[ibounce-honest-positioning]]`)
* **Investigation prompts** — operator gets "here's what changed,
  investigate" not "your bouncer broke"

#### What this DOES NOT deliver

* **Confirmed injection diagnosis** — `suspect_patterns` can't
  distinguish "operator changed workflow" from "agent compromised by
  injection"; that's a human-judgment call
* **Prevention of all PI** — a sophisticated attacker crafts
  normal-looking actions inside the trained envelope; signals will
  miss it by design
* **Adversarial-intent labels** — `recommended_action: "BLOCK_PROACTIVELY"`
  fires ONLY on `KNOWN_ADVERSARIAL_PATTERNS` matches; everything else
  is "investigate" or "log" — needs operator judgment
* **Uniform signal quality across operators** — for highly variable
  operators (sysadmin role, exploration work) the noise floor stays
  high; `unprecedented_action` fires constantly and is mostly false
  positives

These limits are NOT bugs — they are the architecture per
`[[ibounce-honest-positioning]]`. The bouncer is a deterrent + dev loop;
the IAM role is the boundary. `suspect_patterns` is observability
extension, not a security boundary upgrade.

### 11.6 Anti-patterns

Per `[[progressive-tightening-as-injection-detector]]`:

* **Don't auto-block on single `suspect_patterns` hit** — false-positive
  risk; needs operator review except for `KNOWN_ADVERSARIAL_PATTERNS`
  safety floor (which already blocks at §2.3)
* **Don't market "detection" without the SUSPECT-ACTIVITY qualifier** —
  surfaces signals, doesn't confirm intent
* **Don't conflate detection (surfaces signal) with diagnosis (confirms
  adversarial intent)** — confidence scores carry uncertainty
* **Don't claim signal-to-noise improves uniformly** — highly variable
  operators stay in the noisy regime forever
* **Don't ship `suspect_patterns` surfacing without grading rubric** —
  Phase 16 (§6) extension is calibration corpus; without it operators
  can't act on noise

## 12. Out of scope

* Implementation of any new MCP tool — separate phase tasks per §6
  (Phases 1–12) and §6.1 (Phases 13–18).
* Modification of existing code — design only.
* Scorer behavior — `[[scorer-is-ground-truth]]` discipline.
* Test changes — Phase 11 / 12 / 17 / 18 file tests when implementation lands.
* Pro-tier LLM-augmented variants of the heuristic — out of v1.0 scope
  per `[[bouncer-zero-llm-when-agent-in-loop]]`; the heuristic is
  intentionally deterministic.
* **Phase 13–18 calibration corpus** — out of this design's scope; a
  follow-up grading-corpus effort (mirror of Phase 10) is the
  calibration gate before any quantitative `suspect_patterns` or
  `confidence-gate` thresholds appear in marketing copy.

## See also

* [HARNESS-RECIPES/audit-to-effective-profile.md](HARNESS-RECIPES/audit-to-effective-profile.md) — operator-agent-facing walkthrough (extended with steps 14–15 for §10 + §11)
* [PROFILE-GENERATION.md](PROFILE-GENERATION.md) — existing generator docs (`bounce_profile_generate_from_audit` MCP tool)
* [MRR-1-USE-CASE-AUDIT-2026-05-24.md](MRR-1-USE-CASE-AUDIT-2026-05-24.md) — top blocker #1 (UC-17)
* [HARNESS-RECIPES/bouncer-history-to-config-pattern.md](HARNESS-RECIPES/bouncer-history-to-config-pattern.md) — the Phase G recipe shape this design mirrors
* `[[safety-mode-lean-permissive]]` — direction memo
* `[[bouncer-zero-llm-when-agent-in-loop]]` — architectural memo
* `[[calibration-quality-bar]]` — discipline memo
* `[[role-effectiveness-corpus]]` — corpus framework this design mirrors for Phase 10 + Phase 18
* `[[ambient-mode-progressive-tightening]]` — §10 source memo (time-evolution trajectory)
* `[[progressive-tightening-as-injection-detector]]` — §11 source memo (suspect_patterns dimension)
* `[[ibounce-honest-positioning]]` — §11.5 "AWARE not PROOF" framing source
* `[[prompt-injection-protection-positioning]]` — §11.4 3-tier framing source
* `[[tests-and-independent-uat-required]]` — Phase 18 UAT discipline
