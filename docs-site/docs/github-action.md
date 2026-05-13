# GitHub Action

`trsreagan3/iam-risk-score-action@v1` — score IAM policies on every
PR. Block merges, set required reviewers, post structured comments.

Public repo: [trsreagan3/iam-risk-score-action](https://github.com/trsreagan3/iam-risk-score-action).

## Quick start

```yaml
name: IAM Policy Risk Review
on:
  pull_request:
    paths:
      - 'terraform/**/iam*.tf'
      - 'cdk/**/policies/*.json'
      - 'infrastructure/iam/*.json'

jobs:
  risk-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: trsreagan3/iam-risk-score-action@v1
        with:
          policy-file: 'infrastructure/iam/*.json'
          threshold: 5
          comment-on-pr: true
```

## Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `policy-file` | string | required | Path or glob to policy JSON. `infrastructure/**/iam-*.json` is fine. |
| `threshold` | int | 5 | Pass/fail score boundary |
| `api-url` | string | empty (offline) | Hosted API URL; omit for offline mode |
| `api-key` | string | empty | API key for hosted service. Use `${{ secrets.IAM_RISK_SCORE_API_KEY }}` |
| `access-type` | string | `read-write` | `read-only` or `read-write` |
| `duration-hours` | int | 1 | Hypothetical grant duration |
| `comment-on-pr` | bool | false | Post score as PR comment |

## Outputs

| Name | Description |
|---|---|
| `score` | Worst score across all matched policy files (1–10) |
| `tier` | `low` / `medium` / `high` |
| `would_auto_approve` | `'true'` if score < threshold |
| `policy_fingerprint` | sha256 of the worst policy — use for CI caching |

## Common patterns

### Required-reviewers for high-risk PRs

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  id: score
  with:
    policy-file: 'iam/*.json'

- name: Request security team review
  if: steps.score.outputs.tier == 'high'
  uses: actions/github-script@v7
  with:
    script: |
      await github.rest.pulls.requestReviewers({
        ...context.repo,
        pull_number: context.issue.number,
        team_reviewers: ['security-team'],
      });
```

### Block merge on high risk

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  with:
    policy-file: 'iam/*.json'
    threshold: 7  # only block on tier "high"
```

The action exits non-zero on FAIL — wire as a required-status-check
via branch protection rules.

### Auto-approve trivial changes

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  id: score
  with:
    policy-file: 'iam/*.json'
    threshold: 3

- name: Auto-approve if low risk
  if: steps.score.outputs.would_auto_approve == 'true'
  uses: hmarr/auto-approve-action@v4
```

### Comment with the verdict

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  with:
    policy-file: 'iam/*.json'
    comment-on-pr: true
```

Posts a comment showing the score, factors, and suggestions —
visible inline to reviewers.

## Offline vs hosted

**Offline** (default, `api-url` empty): runs the deterministic scorer
on the runner. Fast, no network, no API key. The LLM narrative is
unavailable (only the deterministic score + factors + suggestions
come out).

**Hosted** (`api-url` set): calls the iam-risk-score SaaS. Adds
the LLM narrative. Counts toward your tier quota.

For most CI use cases, offline mode is the right pick — same score
either way, no auth setup, no network dependency.

## Marketplace listing

Pending review. Until then, reference `@v1` directly from the
GitHub repo (works identically to a Marketplace-listed action).
