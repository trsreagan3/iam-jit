# Curated policy examples

A small, hand-picked library of IAM policies organized by score
band. Each example has a sidecar `.expected.yaml` documenting:

- The expected `risk_score` range from iam-jit's deterministic scorer
- WHY the policy lands in that band
- WHAT the example is meant to teach (one shape per file)
- (For dangerous) FIX patterns or real-world incident references

## Why a curated library

These examples serve three purposes:

1. **Calibration anchors.** Each `.expected.yaml` declares a score
   range. The CI corpus check uses these as additional signal
   alongside the larger calibration corpus. If the engine drifts
   on a curated example, it's a louder failure than drifting on
   one of 1500+ corpus entries — these are the canonical
   "this is what shape X should score" assertions.

2. **Demo + recipe content.** The launch posts, landing pages,
   and the canonical recipes link to specific examples so readers
   can see the shape without copy-paste-from-screenshot. Each
   example is self-contained valid JSON.

3. **Educational.** A new operator can browse `dangerous/` to
   build intuition for what gets flagged and why. The sidecar
   `gotcha:` and `real_world:` fields point at the actual
   incident chains where these shapes mattered.

## Layout

```
policies/
├── safe/         # expected score 1-3; auto-approves under any mode
├── borderline/   # expected score 4-6; the judgement-call band
└── dangerous/    # expected score 7-10; never auto-approves
```

## Sidecar schema

Every `.json` policy file has a sibling `.expected.yaml`:

```yaml
name: short-kebab-case-id        # matches the filename stem
category: safe | borderline | dangerous
expected_score_min: 1            # inclusive
expected_score_max: 3            # inclusive
why: |
  One paragraph explaining the score reasoning.
demonstrates: |
  The shape / pattern this file teaches.
gotcha: |                        # optional
  Subtleties operators commonly miss.
fix_pattern: |                   # optional, dangerous-only
  How to narrow this policy.
real_world: |                    # optional, dangerous-only
  Linked incident or breach reference.
```

## Adding a new example

1. Pick the smallest possible policy that exhibits the shape.
   One Statement per file unless the bug is in cross-Statement
   composition.
2. Write the `.expected.yaml` sidecar BEFORE running the scorer.
   If the scorer disagrees, treat it as a calibration question:
   maybe your expected band is wrong, or maybe the scorer needs
   adjustment. Either way it's a real signal — don't paper over.
3. Send a PR. Adversarial-loop process applies (see
   `docs/ADVERSARIAL-LOOP-PROCESS.md`).

## Don't tailor to a specific customer's policies

Per `[[dont-tailor-to-lighthouse]]` memo: this library reflects
the general shape of AWS IAM use, not any one company's infra.
If you have a customer-specific shape that exposes a calibration
gap, generalize it before adding here.
