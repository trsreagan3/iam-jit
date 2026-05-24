# iam-risk-score documentation

A 1–10 risk score for any AWS IAM policy in under 100ms.
**Deterministic, regression-tested, free + open source at v1.0.**

> v1.0 ships fully free + open source under Apache-2.0. Consulting
> available for production deployments, custom integration, and
> compliance audits. No paid tier at v1.0.

```bash
$ pip install iam-risk-score

$ iam-risk-score --offline my-policy.json
IAM Policy Risk Score
  Score:     7/10 (high)
  Threshold: 5 (FAIL)
  Analyzer:  deterministic
```

## Where to start

<div class="grid cards" markdown>

-   __:material-rocket-launch: Getting started__

    ---

    Install the CLI, score your first policy, integrate via API or
    GitHub Action.

    [:octicons-arrow-right-24: Quickstart](getting-started.md)

-   __:material-api: API reference__

    ---

    `POST /api/v1/score` — request/response schema, status codes,
    rate limits, authentication.

    [:octicons-arrow-right-24: API docs](api-reference.md)

-   __:material-console: CLI reference__

    ---

    `iam-risk-score` command flags, exit codes, output formats,
    offline vs hosted mode.

    [:octicons-arrow-right-24: CLI docs](cli-reference.md)

-   __:material-github: GitHub Action__

    ---

    `trsreagan3/iam-risk-score-action@v1` — inputs, outputs,
    common workflow patterns.

    [:octicons-arrow-right-24: Action docs](github-action.md)

</div>

## How the scoring works

The numeric score is fully deterministic — 50+ calibrated rules
across service sensitivity, action breadth, resource scope,
destructive verbs, access-type mismatch detection, IAM PassRole
patterns, NotAction/NotResource handling, and grant-duration
amplification.

An optional LLM backend (configured per deployment) contributes a
plain-English narrative explanation. By explicit safety contract,
**the LLM never lowers the deterministic score** — verified by the
`test_score_matches_calibration_corpus` regression test.

[:octicons-arrow-right-24: Calibration model deep-dive](calibration.md)

## Three deployment shapes

1. **Offline CLI** (default) — `pip install iam-jit`. Runs the
   deterministic engine locally; no network call. Free + unlimited.
2. **Python library** — `from iam_jit import review` and call
   `review.analyze_policy(...)` directly. Embed into your agent
   runtime, IDE plugin, or custom IaC checker.
3. **GitHub Action** — drop
   [`trsreagan3/iam-risk-score-action@v1`](github-action.md) into any
   workflow. Scores every IAM diff on PRs, blocks destructive merges,
   emits SARIF for GitHub Code Scanning.

> **No hosted API.** The previously-documented
> `api.iam-risk-score.com` endpoint was dropped on 2026-05-24 to
> restore `[[no-hosted-saas]]` to 100%. The scorer is the moat; the
> offline CLI + library are the supported access surface.

## v1.0 — free + open source

iam-risk-score v1.0 ships fully free + open source under Apache-2.0.
Every scoring feature is included: numeric 1–10 score, per-factor
breakdown, suggestions, offline CLI, Python library, GitHub Action,
SARIF output. No tier comparison; no feature gates.

Consulting engagements are available for production deployments,
custom integration, and compliance audits — see
[pricing](pricing.md) for how to engage.
