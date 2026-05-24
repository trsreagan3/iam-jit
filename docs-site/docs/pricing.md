# Pricing

## v1.0 — free + open source

iam-risk-score (and the full iam-jit suite — ibounce / kbounce /
dbounce / gbounce) is free + open source under Apache-2.0.
**Every scoring feature ships in v1.0; no tier comparison, no
feature gates, no signup.**

- **Offline CLI** — `pip install iam-risk-score`. Unlimited.
- **Hosted API** — `https://api.iam-risk-score.com/api/v1/score`.
  Rate-limited to 100 requests/day per source IP (plus 30 req/min
  burst-protect at the Lambda layer).
- **Self-hosted** — deploy the SAM stack in your own AWS account.
  Zero quotas; "your AWS bill" (~$6/mo idle, see [production hardening](production-hardening.md)).

## Consulting available

For production deployments, custom integration, compliance audits,
or dedicated calibration support, we offer paid consulting
engagements outside the open-source release.

What consulting typically covers:

- Production deploy walkthroughs (SAM stack hardening, edge
  protection, log retention tuning, multi-region)
- Custom rule + adversarial-corpus contribution for your sensitive
  services / blacklist patterns
- SOC 2 / PCI / HIPAA / FedRAMP evidence packs aligned with the
  built-in retention defaults + tamper-evident logging
- Integration with existing JIT/SSO/Slack/CI surfaces in your stack
- Migration consulting (from Apono / Opal / Hoop / etc.)

Reach out via the GitHub repo issues or the email on the README to
discuss scope.

## The deterministic safety contract

**The numeric score is identical for every caller.** When the
optional LLM backend produces a narrative, it adds explanation —
by explicit safety contract (regression-tested in CI), the LLM can
never lower the deterministic score. You get explanation as a
narrative; the safety floor is the score itself.

This means a free-tier offline-CLI integration that auto-approves
at threshold 5 catches the same risks any other configuration
would.

## What counts as a request

One scoring call to `/api/v1/score` = one request. Identical
policies (matched by `policy_fingerprint`) hitting CloudFront cache
don't count — only origin hits.

## Hosted API rate limits

The hosted endpoint enforces:

- **30 requests / minute / source IP** — in-Lambda sliding window;
  defense-in-depth against bursts (configurable via
  `IAM_JIT_SCORE_RATE_PER_MINUTE`).
- **~100 requests / day / source IP** — edge-enforced via WAFv2 on
  the hosted deployment; sized to support legitimate sample-and-
  evaluate use without subsidizing scraping. Self-hosted deploys
  remove the daily cap entirely.

For higher throughput, run the offline CLI (`pip install`,
unlimited) or self-host the SAM stack in your own AWS account.
Both paths are zero-cost in software-license terms; the self-host
path is "your AWS bill" (~$6/mo idle).

## Why no paid tier at v1.0

Following the Snyk / Semgrep / Sentry / HashiCorp pattern: v1.0
ships fully free + open source. Adoption first; consulting funds
the work; paid product tier only if/when adoption proves the need
(12-18 months out, when 3+ orgs ask for capabilities that fit a
paid-tier shape).

The OSS scorer is the durable artifact. Every feature that ships
in v1.0 stays free in perpetuity — future paid tiers (if added)
would offer NEW capabilities, never gate v1.0 functionality.
