# iam-jit v1.1 Roadmap

*Last updated 2026-05-16.*

## Current contents: nothing

After the 2026-05-16 v1.0-scope alignment, **no features are
currently deferred to v1.1**.

The earlier draft of this doc deferred ~5 features ("plan-capture
HTTP producer", "MFA full OAuth proxy", "scoring-feedback
persistence + export", "LLM Pro tier", "preset library org tier")
based on multi-week build estimates and speculative demand. That
deferral criterion was too loose:

- **Bar for legitimate deferral:** the feature has been tried,
  measured, and proven to not deliver value (e.g., natural-language
  policy synthesis at 1.8% joint sufficiency rate — see
  [docs/calibration/100-prompt-sufficiency-loop.md] and
  `docs/calibration/feature-reality-check.md`).
- **NOT valid deferral reasons:** multi-week build, complex admin
  UX, speculative demand, blocked on AWS account verification.
  Those are scheduling problems; they extend the launch timeline
  but don't move features off the launch list.

The only feature legitimately removed from launch scope is the
**deterministic natural-language policy generator** — measured,
failed, dropped. See `src/iam_jit/aws_managed_catalog.py`
deletion path in task #149.

## What this implies for v1.0 scope

Everything else in the open task queue is in-scope for v1.0:

- #132 Plan-capture HTTP producer (the proxy that auto-captures
  `terraform plan` / `cdk synth` / boto3 calls)
- MFA full OAuth proxy (was "Phase 3 follow-up")
- Scoring-feedback persistence (DDB-backed store) + corpus
  export pipeline (`iam-jit feedback export`)
- #115 + #116 CloudFormation onboarding (create-not-assume pattern)
- #119 Full enforcement-proxy mode
- #102 iam-jit-configures-itself
- #104 EKS template-role recipe
- #145 Plan-capture proxy read→write switch UX
- #149 NL deprecation
- #150 Preset library (full scope: personal + org-curated tiers,
  stale detection, versioning)
- #154 AdminLikeWithSensitiveExclusions baseline
- #155 Reduction UX on templates

Per [[deliberate-feature-completion]], the queue is worked
sequentially — one feature fully closed (code + tests + audit +
e2e validation + docs + marketing) before the next starts. Per
[[v1-scope-bar]], the queue doesn't get truncated to fit a
timeline; it gets worked through.

## What to put here

When a feature is genuinely *tried, measured, and found not to
deliver*, add it here with:

- One sentence: what was tried
- One paragraph: what measurement showed
- A link to the calibration / audit doc that recorded the
  decision
- (Optional) what could revive the work later — what would
  need to change for the attempt to make sense again

Anything else stays in v1.0.
