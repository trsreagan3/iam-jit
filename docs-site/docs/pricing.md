# Pricing

| Tier | Price | Quota | What you get |
|---|---|---|---|
| **Free** | $0 | 100 requests/month, by source IP | 1–10 score, factors, suggestions. Deterministic-only. Public API; no signup needed. |
| **Indie** | $19/mo | 5,000 requests/month | + per-API-key auth (no IP rate-limit) |
| **Pro** | $99/mo | 50,000 requests/month | + LLM narrative (Claude Opus 4.7) — plain-English explanation of every score |
| **Team** | $499/mo | 500,000 requests/month | + admin context API (extend the scorer's rule set), Slack notifications, weekly digest |
| **Enterprise** | from $2K/mo | unlimited | + SOC 2 evidence export, dedicated calibration tuning, SLA |

## The deterministic safety contract

**The numeric score is identical in every tier.** The LLM only adds
a plain-English narrative — by explicit safety contract (regression-
tested in CI), the LLM can never lower the deterministic score. You
pay for explanation, not for safety.

This means the **free tier is safety-equivalent to enterprise**.
A free-tier integration that auto-approves at threshold 5 catches
the same risks an enterprise customer would.

## What counts as a request

One scoring call to `/api/v1/score` = one request. Identical
policies (matched by `policy_fingerprint`) hitting CloudFront cache
don't count — only origin hits.

## Free tier limits

Hardcoded: 30 requests / minute / source IP, plus a monthly cap
on the order of 100 (enforced at the edge via WAFv2 for the hosted
API). Self-hosted deploys remove the cap entirely.

## Upgrading

Self-serve via Stripe Checkout (Indie / Pro / Team).
Enterprise: contact the team for setup.

After Checkout, an API key is auto-issued and emailed within
seconds — Stripe webhook → Lambda → API key minted → SES email.
Use the key in the `Authorization: Bearer <key>` header to bypass
the IP rate limit and unlock the LLM narrative on Pro+.

## Self-hosting

If you want to keep traffic in-house, deploy the SAM stack in your
own AWS account. The pricing is "your AWS bill" (~$6/mo idle,
scales with usage — see [production hardening](production-hardening.md)
for breakdown). Free under Apache 2.0.

The hosted offering ($19+/mo) saves you the operational work, gives
you the LLM narrative on the paid tiers, and contributes data
back to the cross-org calibration corpus.
