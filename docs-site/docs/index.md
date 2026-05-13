# iam-risk-score documentation

A 1–10 risk score for any AWS IAM policy in under 100ms.
**Deterministic, regression-tested, free up to 100 requests/month.**

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

The optional LLM (paid tier) contributes a plain-English narrative
explanation. By explicit safety contract, **the LLM never lowers
the deterministic score** — verified by the `test_score_matches_
calibration_corpus` regression test.

[:octicons-arrow-right-24: Calibration model deep-dive](calibration.md)

## Three deployment shapes

1. **Offline CLI** (default) — `pip install iam-risk-score`. Runs the
   deterministic engine locally; no network call. Free.
2. **Hosted API** — `https://api.iam-risk-score.com/api/v1/score`.
   Free for 100 req/month, paid tiers add LLM narrative.
3. **Self-hosted** — deploy the SAM stack into your own AWS account.
   See [self-hosting](self-hosting.md).

## Free vs paid

| Tier | Price | Quota | What you get |
|---|---|---|---|
| Free | $0 | 100/mo per IP | Score, factors, suggestions. Deterministic. |
| Indie | $19/mo | 5K/mo | + API key, no IP rate limit |
| Pro | $99/mo | 50K/mo | + LLM narrative (Claude Opus 4.7) |
| Team | $499/mo | 500K/mo | + admin context API, Slack notifications |
| Enterprise | $2K+/mo | unlimited | + SOC 2 evidence export, SLA |

[:octicons-arrow-right-24: Pricing details](pricing.md)
