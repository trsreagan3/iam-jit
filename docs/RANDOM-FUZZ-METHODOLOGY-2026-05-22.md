# Random-policy-fuzz methodology — 2026-05-22

- **Slice date:** 2026-05-22
- **Scorer commit tested:** current `main` HEAD (see commit SHA in CHANGELOG)
- **Corpus root:** `tests/calibration_corpus/random_composites/`
- **Source corpus:** `tests/calibration_corpus/aws_managed/` (1,489 hand-graded AWS-managed policies)
- **Initial batch:** 100 composites at `seed=42`
- **Generator:** `scripts/random_policy_fuzz.py`
- **Oracle prompt:** `scripts/random_policy_fuzz_oracle_prompt.md`
- **Comparison script (post-oracle):** `scripts/random_policy_fuzz_compare.py`

## Motivation

The aws_managed corpus pins per-policy scorer behavior. Real-world
roles almost never carry a single AWS-managed policy — they carry
multiple, often layered. The composite shape is where calibration
drifts most: factor recognition is per-statement, but human risk
intuition reasons over the combined surface. The realworld_composite
cluster has 50% pass rate (3/6 failing) per the 2026-05-19 sweep —
the smallest cluster on the bench and the one signaling the largest
delta to human grading.

This slice creates a **methodologically defensible** way to
generate composite test cases at volume without hand-grading each
one. The recipe is:

1. **Generate** N composites by sampling AWS-managed policies
   uniformly at random + concatenating their `Statement` blocks
   (this script).
2. **Score deterministically** with `iam_jit.review.analyze_policy`
   (this script).
3. **Score with Opus** as an independent oracle in a separate
   Claude Max session, using `scripts/random_policy_fuzz_oracle_prompt.md`.
4. **Compare** the two scores per `scripts/random_policy_fuzz_compare.py`.
   Classify each composite per the rubric:

   | |score gap| | classification |
   |---|---|
   | ≤ 1 | CALIBRATED |
   | = 2 | DRIFT |
   | = 3 | UNDER_FLAG or OVER_FLAG (per direction) |
   | ≥ 4 | LIKELY_BUG |

5. **Promote** LIKELY_BUG cases to `bug_regressions/` only after
   the founder confirms each is genuine signal — per
   `[[scorer-is-ground-truth]]` the scorer is NOT auto-tuned to
   match Opus, and per `[[deliberate-feature-completion]]` no
   blanket addition to the regression bench.

## What this slice does NOT do

- Does NOT call any LLM (founder is on Claude Max — no API burn)
- Does NOT modify `src/iam_jit/review.py` — scorer untouched
- Does NOT auto-promote composites to `bug_regressions/`
- Does NOT auto-add composites to the regression suite — that's
  a deliberate add after Opus judgment lands and the founder
  reviews each candidate

## Sampling strategy

Cohort distribution (per founder direction):

| Cohort size k | Share | This batch |
|---|---|---|
| 2 (pair) | 50% | 38 |
| 3 (triple) | 30% | 41 |
| 4 (quad) | 15% | 16 |
| 5 (pentuple) | 5% | 5 |

Sampling uses Python's `random.Random(seed).sample(...)` without
replacement within a single composite (no policy appears twice in
the same composite). A single seed drives both the cohort-size
draw and the AWS-managed-policy selection at each step, so:

- Same seed + same count + same source corpus → byte-identical
  output. Regression-tested in
  `tests/scripts/test_random_policy_fuzz.py::test_seed_and_count_are_deterministic`.
- Different seeds explore different regions of the source space.

## Dedupe

Each composite carries a `source_hash`: the first 16 hex chars of
`sha256(sorted source filenames)`. Two composites with the same
sorted source-policy tuple share the same hash. On every run the
script reads existing `source_hash` values from the output dir and
**skips collisions** — the same source-tuple never produces two
composite files, even across runs with different seeds.

Statement-level dedupe is also applied: when two source policies
contain a byte-identical `Statement` (ignoring `Sid`), the
duplicate is dropped from the composite policy. This stops a
single-action statement from inflating risk just because two AWS-
managed policies happened to include the same Resource:*  read.

Regression-tested in
`tests/scripts/test_random_policy_fuzz.py::test_dedupe_skips_repeated_source_tuples`.

## Request-context randomization

Each composite gets a sampled `(user, justification, duration)`
triple. Pools are intentionally small + readable so the oracle
phase can interpret each context at a glance:

- 10 fixed `(user, justification)` pairs covering CI bots, dev
  debug, SRE incident, agent (Claude scoped tool), auditor,
  contractor — common request shapes iam-jit serves
- Duration drawn from `[1, 1, 1, 2, 4, 8]` hours (weighted toward
  short, with a tail to 8h for SRE incidents + contractor work)

The request context is recorded on each composite YAML but does
NOT enter the deterministic score (the current scorer reads only
`request["spec"]`). Opus's oracle prompt is shown the
`user` + `justification` + `duration` so it can apply
context-aware risk judgment — that delta is itself part of what
this methodology surfaces.

## Distribution of the 100-composite batch (seed=42)

### Cohort distribution

| k | files |
|---|---|
| 2 | 38 |
| 3 | 41 |
| 4 | 16 |
| 5 | 5 |
| **total** | **100** |

### Deterministic score distribution

| det_score | files |
|---|---|
| 1 | 0 |
| 2 | 0 |
| 3 | 0 |
| 4 | 0 |
| 5 | 0 |
| 6 | 4 |
| 7 | 1 |
| 8 | 44 |
| 9 | 51 |
| 10 | 0 |
| **total** | **100** |

The 100% concentration in scores 6-9 is itself a finding worth
flagging to the oracle:

- Concatenating ≥2 AWS-managed policies systematically lands in
  the high-risk band per the deterministic scorer
- This is plausibly correct (composites are categorically broader
  than any single policy) but the **shape** of the distribution
  is what the oracle phase will calibrate against
- The hand-graded aws_managed corpus has a much wider score
  distribution (per `docs/CALIBRATION-SWEEP-2026-05-19.md`)

### Source-policy distribution

- **261 unique** AWS-managed policies referenced across the 100 composites
  (out of 1,489 available — 17.5% of the source corpus touched)
- **235 / 261** sources appear exactly once → low collision floor;
  larger batches would broaden coverage substantially
- Top duplication is `AWSS3OnOutpostsServiceRolePolicy.yaml` at 3
  appearances; everything else ≤ 2

## Three sample composites (inline, verbatim)

### Sample 1 — `composite-0012-42.yaml` (det_score = 6, pair)

```yaml
name: composite-0012-42
source_policies:
- aws_managed/AWSMarketplaceGetEntitlements.yaml
- aws_managed/KeyspacesCDCServiceRolePolicy.yaml
source_hash: 689dd76b2f1692db
policy:
  Version: '2012-10-17'
  Statement:
  - Sid: AWSMarketplaceGetEntitlements
    Effect: Allow
    Action:
    - aws-marketplace:GetEntitlements
    Resource: '*'
  - Sid: KeyspacesPutMetricDataPermission
    Effect: Allow
    Action:
    - cloudwatch:PutMetricData
    Resource: '*'
    Condition:
      StringEquals:
        cloudwatch:namespace: AWS/Cassandra
request:
  spec:
    access_type: read-write
    duration:
      duration_hours: 8
    resource_constraints: []
  user: sre-carol
  justification: scale-out emergency for us-east-1 outage
scores:
  det_score: 6
  det_factors:
  - 'Resource: `*` for aws-marketplace (broad cross-resource read/access)'
  - 'State-changing action `cloudwatch:PutMetricData` on Resource: `*` (IAM access level: Write)'
  - 'Resource: `*` for cloudwatch (broad cross-resource read/access)'
  opus_score: null
  opus_factors: null
  opus_reasoning: null
  gap_classification: pending
```

Hypothesis pre-oracle: marketplace entitlement read + cloudwatch
metric write with namespace constraint is genuinely low-medium
risk. A human grader would likely score this 3-5. The det_score
of 6 may be over-flagging the `Resource: *` patterns when the
Condition narrows the effective scope.

### Sample 2 — `composite-0043-42.yaml` (det_score = 8, pair with explicit Deny)

```yaml
name: composite-0043-42
source_policies:
- aws_managed/AWSXrayFullAccess.yaml
- aws_managed/AWSDenyAll.yaml
source_hash: c607374983b417cb
policy:
  Version: '2012-10-17'
  Statement:
  - Sid: AWSXrayFullAccess
    Effect: Allow
    Action:
    - xray:*
    Resource:
    - '*'
  - Sid: DenyAll
    Effect: Deny
    Action:
    - '*'
    Resource: '*'
request:
  spec:
    access_type: read-write
    duration:
      duration_hours: 1
    resource_constraints: []
  user: dev-bob
  justification: 'reproduce customer ticket #4422 locally'
scores:
  det_score: 8
  det_factors:
  - '`xray:*` grants every action in `xray`'
  - 'Resource: `*` for xray (broad cross-resource read/access)'
  opus_score: null
  opus_factors: null
  opus_reasoning: null
  gap_classification: pending
```

This is a known scorer limitation: per IAM evaluation logic the
`Deny *` overrides every `Allow`, so the effective permission
is **nothing**. Human grade ≈ 1. Det_score = 8.  Expected
LIKELY_BUG classification — but flagging it via the oracle phase
makes the gap explicit + ratchet-able rather than tribal
knowledge.

### Sample 3 — `composite-0001-42.yaml` (det_score = 9, triple)

```yaml
name: composite-0001-42
source_policies:
- aws_managed/AWSApplicationAutoscalingLambdaConcurrencyPolicy.yaml
- aws_managed/AWSRoboMakerServicePolicy.yaml
- aws_managed/AWSPrivateCAPrivilegedUser.yaml
```

(38 statements, 39 risk factors; full content in
`tests/calibration_corpus/random_composites/composite-0001-42.yaml`.)

This composite combines lambda provisioned-concurrency control,
RoboMaker service automation, and PrivateCA privileged operations
— a deliberately implausible junior-engineer role assemblage. A
human grader would correctly call this 9-10. Det_score = 9.
Expected CALIBRATED classification.

## Reproducibility

```bash
# Re-generate the same 100 composites byte-for-byte
.venv/bin/python scripts/random_policy_fuzz.py --count 100 --seed 42

# Generate a fresh non-colliding batch (dedupe across runs honored)
.venv/bin/python scripts/random_policy_fuzz.py --count 100 --seed 17
```

## Tests

- `tests/scripts/test_random_policy_fuzz.py::test_seed_and_count_are_deterministic`
  — same seed + count → identical YAMLs
- `tests/scripts/test_random_policy_fuzz.py::test_dedupe_skips_repeated_source_tuples`
  — same source-tuple → exactly one composite on disk
- `tests/scripts/test_random_policy_fuzz.py::test_det_score_populated_on_every_composite`
  — `scores.det_score` is a valid 1-10 int on every output;
    Opus fields seeded null + `gap_classification: pending`

## Next steps (separate phases)

1. **Oracle phase:** Founder pastes batches into a Claude Max
   session using `scripts/random_policy_fuzz_oracle_prompt.md`,
   captures Opus scores into each composite YAML's
   `scores.opus_*` fields. Manual triage; this slice does not
   automate the Claude session.
2. **Comparison phase:** Run `scripts/random_policy_fuzz_compare.py`
   to classify gaps + produce `docs/RANDOM-FUZZ-RESULTS-{date}.md`
   with per-class counts + top 10 LIKELY_BUG cases.
3. **Promotion phase (deliberate):** For each LIKELY_BUG the
   founder confirms is real signal, hand-author a
   `bug_regressions/NN-...yaml` per the existing ratchet
   workflow (`tests/calibration_corpus/README.md`).

## Constraints honored

- `[[scorer-is-ground-truth]]` — comparison surfaces gaps; does
  NOT auto-tune the scorer
- `[[creates-never-mutates]]` — script reads from `aws_managed/`,
  writes only to `random_composites/`
- `[[deliberate-feature-completion]]` — generation + det-scoring
  shipped in this slice; oracle phase + promotion phase are
  separate
- `[[calibration-quality-bar]]` — dedupe + reproducibility +
  source-distribution stats are recorded so any future sweep can
  be compared against this baseline
- No API calls — pure local generation + iam-jit deterministic
  scorer
