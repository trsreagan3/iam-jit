# Production hardening

The MVP deploy is functional but doesn't have launch-grade
protection. This page documents the optional tiers you layer on
top, in order of expected impact for a public launch.

Each tier is independent — apply via `sam deploy --parameter-overrides`
without rebuilding the Lambda code.

## Tier 1: Edge protection (CloudFront + WAFv2)

**~$10–20/mo. Highest impact for a public launch.**

The in-Lambda rate limiter is process-local; it resets on cold-start
and is per-Lambda-instance. At AWS scale, a determined caller can
spin up parallel containers and effectively bypass it. The real
rate-limit must be at the edge.

```bash
sam deploy --stack-name iam-jit-prod --parameter-overrides \
  ...existing-params... \
  EnableEdgeProtection=true \
  WafRateLimitPer5Min=2000
```

What you get:

- WAFv2 WebACL with a rate-based rule (per-source-IP, sliding 5-min window)
- CloudFront distribution fronting the Function URL
- AWS-managed cache policy (respects `Cache-Control: s-maxage` from origin → 1-day CDN caching of deterministic scores)
- HTTPS termination + AWS Shield Standard DDoS protection
- CloudWatch alarm on `BlockedRequests > 1000 in 5 min` (likely scraping attack — wire to SNS)
- New `CloudFrontUrl` output — point clients at this

Wait ~15 min for CloudFront edge propagation. Then real callers use
the CloudFront URL; the underlying Function URL stays reachable for
direct testing.

## Tier 2: Bedrock LLM narratives

**Variable cost — Bedrock token spend.**

Adds the LLM-generated explanation of the score (paid-tier feature).

Prereq: enable Anthropic models on Bedrock in your AWS account
(Bedrock console → Model catalog → Anthropic → submit use-case
form. New accounts may need to wait for AWS verification).

```bash
sam deploy --stack-name iam-jit-prod --parameter-overrides \
  ...existing-params... \
  LLMBackend=bedrock \
  BedrockModelId=us.anthropic.claude-opus-4-7
```

**Cost lever**: set the env var `IAM_JIT_LLM_MAX_OUTPUT_TOKENS=256`
to halve Bedrock output spend with negligible narrative-quality
impact. Without this cap, an aggressive caller can burn ~$0.005 per
request on Opus 4.7.

## Tier 3: Custom domain

Replace `*.lambda-url.us-east-1.on.aws` (or `*.cloudfront.net`) with
`api.yourorg.com`.

1. Register the domain (Route 53 Domains or external registrar).
2. Request ACM cert (DNS validation) for `api.yourorg.com` in
   us-east-1 (required for CloudFront).
3. Wire into your CloudFront distribution's `Aliases` +
   `ViewerCertificate` (manual console step or template extension —
   not yet templated).
4. Add a Route 53 ALIAS record from `api.yourorg.com` to the
   CloudFront distribution.

## Tier 4: SES for magic-link emails

Required if you want multi-user admin sign-in (more than just the
bootstrap admin).

```bash
# Verify your sender:
aws ses verify-email-identity --email-address noreply@yourorg.com

# Update stack:
sam deploy --stack-name iam-jit-prod --parameter-overrides \
  ...existing-params... \
  SesSenderAddress=noreply@yourorg.com
```

For external user sign-in, request SES production access (exit
sandbox mode) via AWS support case.

## Tier 5: Stripe billing

Already implemented end-to-end — see `src/iam_jit/stripe_webhook.py`
and the [PUBLISHING.md § Billing](https://github.com/trsreagan3/iam-jit/blob/main/docs/PUBLISHING.md)
section in the source repo.

Set three env vars on the Lambda:

```
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID_TO_TIER={"price_X":"indie","price_Y":"pro"}
STRIPE_KEY_DELIVERY_FROM_EMAIL=billing@yourorg.com
```

Configure the Stripe dashboard webhook endpoint to point at
`https://api.yourorg.com/api/v1/webhooks/stripe`. Done.

## Pre-launch checklist

Before opening the URL to public traffic, verify each:

- [ ] `EnableEdgeProtection=true` (Tier 1 — real rate limit + DDoS protection)
- [ ] `WafRateLimitPer5Min` tuned for expected traffic
- [ ] CloudWatch alarm wired to a paging channel
- [ ] AWS Budget alarm at $50/mo forecast
- [ ] `IAM_JIT_LLM_MAX_OUTPUT_TOKENS=256` if `LLMBackend=bedrock`
- [ ] `LogRetentionDays >= 365` for any compliance scope
- [ ] AWS account is verified (no day-0 service-eligibility gates blocking Bedrock / Route 53 / Function URLs publicly)
- [ ] Custom domain wired (Tier 3)
- [ ] SES production access requested (Tier 4)
- [ ] At least one secondary admin in the users table (don't single-point-of-failure on the bootstrap admin)
- [ ] Stripe billing configured if commercial (Tier 5)

## Cost estimate

| Component | MVP only | + Edge | + LLM @ 10K/mo | + LLM @ 100K/mo |
|---|---|---|---|---|
| Lambda compute | <$1 | <$1 | <$2 | <$5 |
| DynamoDB on-demand + PITR | ~$3 | ~$3 | ~$3 | ~$3 |
| CloudWatch Logs | <$1 | <$1 | <$1 | ~$2 |
| CloudFront + WAF | — | ~$10–15 | ~$10–15 | ~$10–15 |
| Bedrock (Opus 4.7) | — | — | ~$15–40 | ~$150–400 |
| Route 53 + ACM | <$2 | <$2 | <$2 | <$2 |
| **Total / month** | **~$6** | **~$15–25** | **~$30–60** | **~$170–430** |

CloudFront cache on `policy_fingerprint` cuts Bedrock spend
significantly when CI re-runs are common (typical: 60-80% cache hit).
