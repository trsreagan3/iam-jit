# Pricing

## v1.0 — free + open source

iam-risk-score (and the full iam-jit suite — ibounce / kbounce /
dbounce / gbounce) is free + open source under Apache-2.0.
**Every scoring feature ships in v1.0; no tier comparison, no
feature gates, no signup.**

- **Offline CLI** — `pip install iam-jit`. Unlimited, runs locally,
  no network call.
- **Python library** — `from iam_jit import review`. Same engine,
  embedded in your process.
- **GitHub Action** — `trsreagan3/iam-risk-score-action@v1`.
  Unlimited. SARIF output for GitHub Code Scanning.
- **Self-hosted suite** — deploy `infrastructure/cloudformation/
  destination-account-roles.yaml` in your own AWS account; run
  the bouncers + iam-jit local from `pip install`. Zero quotas;
  "your AWS bill" (~$6/mo idle when running the destination-
  account roles, see [production hardening](production-hardening.md)).

> **No hosted scoring API.** The previously-documented
> `api.iam-risk-score.com` endpoint was dropped on 2026-05-24 to
> restore `[[no-hosted-saas]]` to 100%. The scorer is the moat; the
> offline CLI + library + Action are the supported access surface.

## Consulting available

For production deployments, custom integration, compliance audits,
or dedicated calibration support, we offer paid consulting
engagements outside the open-source release.

What consulting typically covers:

- Production deploy walkthroughs (destination-account CFN
  hardening, log retention tuning, multi-region, multi-account)
- Custom rule + adversarial-corpus contribution for your sensitive
  services / blacklist patterns
- SOC 2 / PCI / HIPAA / FedRAMP evidence packs aligned with the
  built-in retention defaults + tamper-evident logging
- Integration with existing JIT/SSO/Slack/CI surfaces in your stack
- Migration consulting (from Apono / Opal / Hoop / etc.)

Reach out via the GitHub repo issues to discuss scope.

## The deterministic safety contract

**The numeric score is identical for every caller.** When the
optional LLM backend produces a narrative, it adds explanation —
by explicit safety contract (regression-tested in CI), the LLM can
never lower the deterministic score. You get explanation as a
narrative; the safety floor is the score itself.

This means an offline-CLI integration that auto-approves at
threshold 5 catches the same risks any other configuration would.

## Why no paid tier at v1.0

Following the Snyk / Semgrep / Sentry / HashiCorp pattern: v1.0
ships fully free + open source. Adoption first; consulting funds
the work; paid product tier only if/when adoption proves the need
(12-18 months out, when 3+ orgs ask for capabilities that fit a
paid-tier shape).

The OSS scorer is the durable artifact. Every feature that ships
in v1.0 stays free in perpetuity — future paid tiers (if added)
would offer NEW capabilities, never gate v1.0 functionality.
