# Calibration corpus

Data-driven calibration examples that pin scorer behavior. Each
file is a YAML record of (policy + request → expected verdict).

The parameterized loader in `tests/test_calibration_corpus.py`
reads every `.yaml` file in this tree and runs it through
`review.analyze_policy()`. CI fails if any example moves outside
its declared expected range.

## Directory layout

  - `low_risk/`     — score ≤ 3 expected (auto-approve at default threshold)
  - `medium_risk/`  — score 4-5 expected (boundary cases)
  - `high_risk/`    — score 6-10 expected (must route to human review)
  - `bug_regressions/` — examples that were once incorrectly scored and
                         the fix that made them score right. Naming:
                         `nn-short-description-of-bug.yaml`.

## File format

```yaml
name: short-stable-id-for-this-example
description: |
  One paragraph explaining what this example tests AND why the
  expected score is what it is. Future-you needs this when the
  test fails and you've forgotten the context.

policy:
  Version: "2012-10-17"
  Statement:
    - Effect: Allow
      Action: ["service:Action"]
      Resource: ["arn:..."]

# Request shape passed to analyze_policy alongside the policy.
# Defaults: access_type=read-only, duration_hours=1, no
# resource_constraints. Override fields as needed.
request:
  spec:
    access_type: read-only      # or read-write
    duration:
      duration_hours: 1
    resource_constraints: []    # optional list of {service, arns}

# Expected verdict the scorer must produce. CI fails if any of
# these constraints is violated.
expected:
  score_min: 1
  score_max: 3
  # Substrings that must appear in at least one risk_factor entry.
  # Use this to pin "the SCORER explained the right thing", not
  # just "the score happened to be right." Without this, a scorer
  # change could right-score for the wrong reason.
  required_factors_containing: []
  # Optional: substrings that must NOT appear. Useful for
  # regression-protecting "this used to be falsely flagged" cases.
  forbidden_factors_containing: []
  # Optional: at the default auto-approve threshold of 5, must
  # this example auto-approve (true) or NOT (false)? Leave null
  # to skip the check.
  must_auto_approve: null

# Optional admin context to pass through to the scorer. Use this
# for examples that verify the additional_sensitive_services /
# additional_high_impact_actions extension points.
admin_context:
  additional_sensitive_services: []
  additional_high_impact_actions: []
```

## Adding examples

1. Pick the tier directory (low/medium/high/bug_regressions).
2. Drop a new YAML file. Naming: `nn-short-description.yaml` where
   `nn` is a 2-digit serial within the tier (just for ordering).
3. Run `make calibrate` — confirm your new example passes (or fails
   intentionally if it's a regression test you're filing for later
   fix).
4. Commit. The CI run will block any future change that breaks
   this example.

## Promoting an adversarial finding to a regression test

When `scripts/generate-adversarial-policies.py` finds a real
scorer disagreement:

1. Take the qwen-generated policy + the disagreement note
2. Save as `bug_regressions/NN-description.yaml` with the
   CURRENT (wrong) score in a comment for reference
3. Set `expected.score_min/max` to the CORRECT range
4. Confirm the test FAILS (the scorer is wrong)
5. Fix `src/iam_jit/review.py` so the test passes
6. Commit code + new corpus entry together

This is the rachet: every blind spot found becomes a permanent
test. The scorer can't regress on patterns once-fixed.
