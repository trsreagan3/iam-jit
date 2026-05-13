# Launch plan — iam-risk-score

The standalone scoring product. Built to be the "API and CLI for
scoring AWS IAM policy risk" — for AI agents submitting policies
before requesting access, for CI pipelines gating PRs that touch
IAM, and for any provisioning system that wants a risk verdict
before granting permissions.

## The product, in one line

**`POST /api/v1/score`** — submit an IAM policy, get back a 1-10
risk score with structured factors, suggestions, and (optionally)
an LLM-generated narrative explanation. Free for the first 100
requests/month per IP.

## The three distribution channels (all shipped)

1. **Hosted API** — `https://api.iam-jit.dev/api/v1/score`
   (or self-hosted equivalent). Free tier + paid tiers.
2. **CLI** — `pip install iam-risk-score`. Works offline OR
   against any API URL. Drop-in for pre-commit hooks.
3. **GitHub Action** — `iam-jit/iam-risk-score-action@v1`. Score
   IAM policies on every PR. Gate merges or post comments.

Each channel ships TODAY; the launch is making them visible.

## Target audience (in priority order)

1. **AI agent platforms** (Cursor, Replit, Anthropic) — their
   users' agents need to request AWS access; iam-jit scores the
   request before grant. Highest urgency, highest willingness to
   pay.

2. **DevSecOps / security teams** at AI-adopting Series B+ — they
   run CI gating on IaC PRs already; iam-jit slots into existing
   workflows as a GitHub Action.

3. **Existing JIT IAM tool customers** (ConductorOne, Britive)
   who want a scoring layer their tool doesn't have.

4. **Anyone using Terraform with IAM** — the GitHub Action is a
   self-serve adoption channel.

## Pricing (proposed, draft)

| Tier | Price | Quota | Features |
|---|---|---|---|
| Free | $0 | 100 requests/month, by IP | Public API, all scoring features, no auth |
| Indie | $19/mo | 5K requests/month | API key, deterministic scoring |
| Pro | $99/mo | 50K requests/month | API key, LLM narrative (Opus), basic dashboard |
| Team | $499/mo | 500K requests/month | + admin context API, Slack notifications, weekly digest |
| Enterprise | $2K+/mo | Unlimited | + SOC 2 evidence export, dedicated calibration, SLA |

Notes on pricing:
- Free tier is generous enough for any solo dev / hobby project
- Indie/Pro pricing matches the indie SaaS market for similar tools
- Enterprise has room to negotiate up based on integration depth

## Pre-launch checklist

### Code
- [x] `POST /api/v1/score` endpoint (16 tests passing)
- [x] CLI: `iam-risk-score` installable from this repo
- [x] GitHub Action: `github-action/action.yml`
- [x] Shadow mode for SaaS deployments
- [x] Calibration corpus (data-driven, 13+ examples)
- [x] Adversarial generator script
- [x] Rollout playbook documented
- [ ] Pricing/billing page (Stripe integration) — TODO
- [ ] Web dashboard for paying customers — TODO (post-launch)

### Hosting infrastructure
- [ ] Production deploy of the scoring API at api.iam-jit.dev
- [ ] CloudFront in front of the ALB for caching same-fingerprint
      requests (deduplicates CI traffic hammering on PR retries)
- [ ] Per-API-key rate limiting (currently per-IP only)
- [ ] Stripe webhook → API key issuance flow
- [ ] Status page (status.iam-jit.dev) — UptimeRobot is fine for v1

### Marketing surface
- [ ] Landing page at iam-jit.dev
  - Hero: "Score AWS IAM policies before you grant access"
  - Three integration paths (API / CLI / GitHub Action)
  - One-line code samples for each
  - Free tier signup CTA
- [ ] Pricing page
- [ ] Docs site (host the markdown docs as docs.iam-jit.dev)
- [ ] Blog: "The IAM policy scorer for AI agents" (technical post
      explaining the deterministic+LLM hybrid model)
- [ ] Demo video (90s): Claude agent requests access, gets
      scored, low-risk auto-approves, high-risk routes to review

### Distribution
- [ ] PyPI: publish `iam-risk-score` package
- [ ] GitHub Marketplace: list the action
- [ ] Show HN post draft (one good post; one shot)
- [ ] LinkedIn announcement (link to landing page + blog post)
- [ ] Twitter/X thread (technical, screenshots of the action)
- [ ] DEV.to article
- [ ] DM 10 friendly devs at AI-using companies for early feedback

## Launch sequence (recommended)

**Week 1 (this week): production deploy + soft launch**

1. Deploy the API to a production AWS account (NOT
   omise-experimental — get a clean account or sub-account)
2. Set up Stripe sandbox + test billing flow
3. Publish CLI to PyPI
4. Publish action to GitHub Marketplace
5. Invite 5-10 friendly devs to try the free tier
6. Iterate on their feedback for 5-7 days

**Week 2: docs + landing site**

1. Polish the landing site
2. Write the technical blog post
3. Record the demo video
4. Set up the docs site
5. Test the full flow (PyPI install → first score → upgrade)

**Week 3: public launch**

1. Show HN post on a Tuesday morning ET
2. LinkedIn / Twitter / DEV.to follow-up posts
3. Reach out to 30+ corp-dev / eng-leader contacts with a "we
   launched, want a demo?" note
4. Monitor for inbound

**Week 4+: iterate**

1. Whatever the first wave of users say
2. Calibration improvements based on early usage data
3. Acquihire conversations if any corp-dev shows interest

## Marketing positioning (the elevator pitch)

> "iam-risk-score is the missing layer between 'an AI agent wants
> AWS access' and 'should we grant it?' We give your CI pipeline,
> your JIT IAM tool, or your AI-agent runtime a 1-10 risk score
> for any IAM policy in under 100ms — with a deterministic engine
> for safety and an LLM narrative for legibility. Used by
> [design partner logo] to gate IAM PRs and by [other logo] to
> approve their AI agents' access requests. Free up to 100
> requests/month; $19/mo for solo dev usage; enterprise SOC 2 +
> SLA available."

## What's NOT in the launch (defer to v2)

- Multi-cloud (GCP, Azure, Snowflake) — AWS-first
- Web dashboard for paying customers (the API + audit log via
  CloudWatch is enough for v1)
- ML-residual scorer model (deterministic + LLM-narrative is
  enough for v1)
- Cross-request pattern detection (Phase 5 of scorer evolution
  roadmap)
- Custom rule packs / marketplace (premature)

Each of these is a real v2 feature, but trying to ship all of
them is how launches slip 6 months.

## How this differs from the existing iam-jit deployment

iam-jit was originally built as a full JIT IAM provisioner —
deploy + bootstrap + provision real AWS roles. That product STILL
EXISTS (everything in this repo). But the launch is about the
**scoring layer**, which is a much smaller, faster-to-adopt
surface.

The full provisioner is the upsell. The scoring API is the
acquisition channel. Customers integrate the API, find the
scorer useful, ask "do you also handle the provisioning?", and
upgrade to the full SaaS.

This is the same playbook Snyk used (vuln database + scanning
library OSS → cloud-hosted scanning SaaS → full DevSecOps
platform). Smaller surface to start. Bigger product as customers
mature into it.

## Success metrics for the first 90 days

| Metric | Target |
|---|---|
| Free-tier signups | 200+ |
| Active CI integrations | 50+ |
| Paid customers | 5-15 |
| MRR | $500-2K |
| GitHub stars on the action repo | 100+ |
| Show HN points (best single post) | 100+ |
| Inbound corp-dev / acquihire conversations | 3-5 |

Hit those and you have an acquihire-able business. Miss them
significantly and the positioning needs work, not the product.
