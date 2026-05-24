# Profile-generation calibration corpus (v1.0.0)

Phase 10 calibration corpus for the profile-generation 5-flag grading
rubric (`src/iam_jit/llm/grading.py`) + 4-tier overall verdict per
`docs/PROFILE-GENERATION-DESIGN.md` §6 Phase 10 + §8 acceptance.

This corpus is **separate** from the iam-jit scorer corpus
(`tests/calibration_corpus/`) per `[[calibration-quality-bar]]`:
profile-generation grading consumes simulator output + a 5-flag rubric,
not the AWS IAM policy scorer; it needs its own calibration anchor.

## File shape

Each YAML scenario carries:

```yaml
name: <kebab-case slug — also the file stem>
description: |
  Plain-English description: operator role, workflow, bouncer kind,
  what rubric edge this scenario calibrates.
metadata:
  scenario_type: <happy_path | narrow_legitimate | adversarial_mixed | edge_case>
  bouncer_kind: <ibounce|kbounce|dbounce|gbounce>
  friction_budget: <int|null>          # weekly cap; null = N/A
  expected_overall: <MEANINGFUL|PARTIAL|THEATER|NEGATIVE-VALUE>
  expected_flags:
    blocks_known_risk_shapes: <bool>
    under_friction_budget: <bool>
    allows_too_broad: <bool>           # PASS = not too broad
    schema_parses: <bool>
    narrows_vs_admin_baseline: <bool>
  rationale: |
    Why this scenario should grade as <expected_overall>:
    per-flag justification + implementation-reality note where the
    grader's actual answer guided the expected (per
    [[scorer-is-ground-truth]]).
input:
  mode: <generated|supplied>
  # When mode=generated:
  events: [<list of OCSF audit events>]
  lean_permissive: <bool>              # passed to generate_from_audit
  time_range: <string>                 # passed to generate_from_audit
  # When mode=supplied:
  profile: <generator-shape profile dict>
  events: [<list of OCSF audit events>]  # used for simulation
```

## What "calibrated" means here

When all 10 scenarios pass:

* The grader's 5-flag rubric produces stable expected verdicts across
  rubric edges (narrow read / narrow write / adversarial / mixed /
  too-broad / empty-window / per-bouncer floors).
* The `bounce_grade_profile_for_workflow` provenance flag
  `calibration_corpus_validated` lifts from absent to `True` with
  version `1.0.0`.

## What "calibrated" does NOT mean

Per `[[ibounce-honest-positioning]]`:

* The corpus does NOT validate production parity — the simulator core
  remains pure-Python; head-to-head validation against the Go bouncers
  is downstream work.
* The 10 scenarios span rubric edges, not the full operator-traffic
  space. Real-world calibration extension is queued for post-launch
  per the Phase 10 + Phase 12 UAT discipline.
* Per `[[scorer-is-ground-truth]]`: expected fields match
  implementation reality. Implementation gaps surfaced during corpus
  construction are filed as follow-ups, not silently tuned around.

## How to add a scenario

1. Create `scenario-NN-<slug>.yaml` (NN = next available number).
2. Run `pytest tests/llm/test_profile_generation_calibration.py
   -k scenario-NN` to see the actual grader output.
3. If the implementation is correct but expected was wrong: tune
   expected; document why in rationale.
4. If the implementation is wrong: file a follow-up; mark the
   expected to match CURRENT (broken) behaviour with a TODO comment
   citing the follow-up issue. Per `[[scorer-is-ground-truth]]`.

## Synthetic data discipline

Per `[[push-policy-public-repo]]`: events use synthetic ARNs / account
IDs only — canonical `111122223333` account, `reports` / `staging` /
`payroll` bucket names, no real-tenant identifiers.
