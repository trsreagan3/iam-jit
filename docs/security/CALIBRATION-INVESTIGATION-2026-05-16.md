# Calibration corpus investigation — 89 failing examples

*Investigation-only report. No scoring engine changes proposed
in this doc. Per `[[adversarial-loop-process]]`, calibration
fixes follow a separate discipline; this report exists to make
the gap legible so a future fix is informed.*

## Headline

**89 of 2153 calibration corpus examples fail in isolation
(4.1%). All 89 are UNDER-scores — the engine returns a value
BELOW the expected minimum. Zero over-scores.** This is a
systematic calibration regression, not a noise-level drift.

## Distribution of the under-score gap

| Actual → Expected | Count |
|---|---|
| 6 → ≥7 | 26 |
| 7 → ≥8 | 12 |
| 5 → ≥7 | 5 |
| 1 → ≥4 | 5 |
| 1 → ≥3 | 5 |
| 8 → ≥9 | 4 |
| 6 → ≥8 | 4 |
| 4 → ≥5 | 4 |
| 3 → ≥5 | 4 |
| 5 → ≥6 | 2 |
| 4 → ≥7 | 2 |
| 4 → ≥6 | 2 |
| 3 → ≥7 | 2 |
| 1 → ≥6 | 2 |
| (other 1-count) | 10 |

Two failure tiers stand out:

1. **Off-by-one cluster** (~50 of 89): scored 6 expected 7;
   scored 7 expected 8; etc. Suggests one or two scoring
   rules need a +1 nudge for a specific pattern.
2. **Catastrophic cluster** (~15 of 89): scored 1, expected
   4–6. Suggests the scorer is treating something as
   "negligible" that the corpus authors thought deserved
   borderline-or-above. Most likely Condition narrowing being
   given too much credit.

## Sources

| Sub-corpus | Failures | Total | %  |
|---|---:|---:|---:|
| `agent_discovered/` | 73 | ~ | — |
| `research_patterns/` | 16 | ~ | — |

Both are adversarial-loop-discovered corpora — exactly the
inputs the scorer is supposed to be most aggressive against.
This is the canon failing, not edge cases.

## Pattern clusters (named by the failing example slugs)

### Cluster A: Condition-key edge cases (8 examples)

`agent-156-conditionkey-stringlike-degenerate`,
`agent-193-conditionkey-sourcevpce-typo`,
`agent-235-condition-kms-viaservice-missing`,
`agent-302-condition-arnlike-vacuous-principal`,
`agent-303-condition-bool-coerced-string-inverted-deny`,
`agent-327-policy-variable-injection-condition-value`,
`agent-328-condition-boolifexists-mfa-deny-bypass`,
`agent-424-condition-operator-typo`.

**Pattern:** policies that LOOK constrained by a Condition
but the condition is degenerate / inverted / typo'd / using
an operator that makes it tautological. The scorer is giving
narrowing credit to a Condition that doesn't actually narrow.

**Suggested investigation direction:** add a "Condition
fitness check" step in `review.py` that recognizes the
degenerate shapes (StringLike with only `*`, BoolIfExists
on never-set keys, ArnLike with bare `*`, etc.) and
withholds the narrowing credit they currently get.

### Cluster B: Wildcard edge cases (13 examples)

`agent-176-assumerole-saml-webidentity-wildcard`,
`agent-227-kms-key-collection-wildcard`,
`agent-417-region-wildcard-on-secret`,
`agent-419-iam-multi-segment-path-wildcard`,
`agent-516-iam-pass-glob`,
`agent-604-trust-google-aud-stringequals-wildcard`,
`agent-605-trust-service-wildcard-suffix`,
`agent-607-kms-key-wildcard-resource`,
`agent-614-stringequals-literal-wildcard-region`,
`agent-628-sns-topic-bare-wildcard`,
`agent-811-stringlike-oidc-repo-wildcard`,
`research-10-7-question-mark-glob`,
`research-13-14-s3-star-alternative-surfaces`.

**Pattern:** wildcards that are NOT the canonical `*` —
question-mark globs, multi-segment IAM path wildcards, bare
wildcards inside StringEquals (which AWS treats as literal,
not wildcard, but the writer probably intended otherwise),
wildcards on the trust-policy-side of an AssumeRole.

**Suggested investigation direction:** the scorer's wildcard
detector probably only fires on `Action`/`Resource` literal
`*`. The canonical reference is the `_has_wildcard()` helper
in `review.py:1037` — it checks for `*` and `?` but the
relevant tests show this is missed in trust policies, in
StringLike condition values, and in non-Action/Resource
positions.

### Cluster C: STS / AssumeRole / federation (10 examples)

`agent-175-sts-federation-token-scp-escape`,
`agent-183-assumerole-saml-narrow-admin`,
`agent-188-scarleteel-cross-account-assume`,
`agent-619-sts-tagsession-abac`,
`agent-804-iam-recon-narrow-assumerole`,
`agent-819-pacu-organizations-assume`,
`research-02-5-pacu-organizations-assume-role`, etc.

**Pattern:** sts:GetFederationToken / sts:AssumeRole /
sts:TagSession patterns that allow privilege escalation by
chaining identity assumption. Famous incident classes:
SCARLETEEL, Pacu's organizations-assume.

**Suggested investigation direction:** sts: actions are in
the default `required_service_blocklist` (per Floors), so
they should never auto-approve. But the SCORE itself appears
to under-rate them. Add a `sts_chain_amplifier` rule:
if the policy uses any sts: action AND has cross-account
trust (`*` in trust principal), add 2 to the score floor.

### Cluster D: Service surfaces missing from action-impact table

`agent-518-omics-create-workflow`,
`agent-519-iotsitewise-access-policy`,
`agent-520-ssm-incidents-response-plan`,
`agent-522-mq-create-user`,
`agent-523-ec2-copy-image-exfil`,
`agent-508-bedrock-agent-runtime-rag-exfil`.

**Pattern:** newer / lesser-known AWS services (Omics,
IoTSiteWise, SSM Incidents, MQ, Bedrock Agent Runtime) where
specific actions have outsized blast radius but aren't in
the scorer's known-impact tables.

**Suggested investigation direction:** the existing impact
tables in `review.py` (around line 76, the
"create or execute code" set; and the catastrophic-actions
table elsewhere) need extension. This is essentially a
coverage problem — the AWS service surface grew faster than
the impact table.

## What this means for launch

- **Not a release blocker** by itself. The scorer is
  permissive (under-scores) — agents using iam-jit will get
  AUTO-APPROVED on some shapes that the corpus says deserve
  human review. No grants are being WRONGLY BLOCKED.
- **Is a "trust me" blocker** for security-conscious early
  adopters. The convergence numbers / accuracy claim on the
  landing page becomes weaker if 4% of the canon fails.
- **Pre-launch fix scope** should be Cluster A (the degenerate
  Condition cases) since those are the highest-leverage
  conceptual bug — the scorer is being fooled by syntactic
  patterns it should be skeptical of. Clusters B/C/D are
  table-extension work that scales linearly with effort.

## What NOT to do

- **Don't** silently widen corpus expected ranges to make
  tests pass — that's calibration drift in the worst direction
  per `[[calibration-quality-bar]]`.
- **Don't** add LLM-tier compensation logic ("the LLM will
  catch it") — the deterministic scorer is the FREE tier
  product surface; LLM is a Pro+ supplement.
- **Don't** comment out failing tests — they're the canon.

## What TO do (in order)

1. Pick one cluster (recommend A — degenerate Conditions).
2. For each example in the cluster, hand-trace the score
   via `review.py` to confirm the under-score reason.
3. Propose ONE scoring rule change. Score the entire corpus
   (passing + failing) before/after to confirm the change
   doesn't introduce new failures elsewhere.
4. Land with a regression test pinning the cluster's
   examples to their expected bands.
5. Repeat for the next cluster.

## Cross-references

- `docs/ADVERSARIAL-LOOP-PROCESS.md` — the discipline
- `[[adversarial-loop-process]]` memo — strategic framing
- `[[calibration-quality-bar]]` memo — what NOT to ship
- `[[dogfooding-findings]]` memo — two false-positive cases
  found during dogfooding (Condition-scoped wildcards,
  bedrock:InvokeModel misclassification) which are
  consistent with Cluster A + Cluster D patterns above
- `examples/policies/safe/03-dynamodb-tagged-read.expected.yaml`
  + `examples/policies/borderline/02-secretsmanager-path-read.expected.yaml`
  — curated examples that flag the same drift in
  `known_calibration_issue:` fields

---

*Investigation complete. Fix work tracked under task #99.*
