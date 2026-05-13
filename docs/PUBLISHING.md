# Publishing checklist — iam-risk-score launch

Pre-launch steps to publish the standalone scoring product
across three channels.

## 1. PyPI package (the CLI)

The `iam-risk-score` CLI is currently part of the iam-jit
package. To publish standalone:

### Option A — single package (recommended for v1)

Publish iam-jit to PyPI; the `iam-risk-score` console script
comes with it. One package, two CLI entry points.

```bash
# Verify package builds clean
cd ~/repos/iam-roles
python -m build  # produces dist/iam_jit-X.Y.Z-py3-none-any.whl

# Test install in a fresh venv
python -m venv /tmp/test-venv
/tmp/test-venv/bin/pip install dist/iam_jit-*.whl
/tmp/test-venv/bin/iam-risk-score --version  # should work

# Upload to TestPyPI first (sanity check)
twine upload --repository testpypi dist/*

# Then to real PyPI
twine upload dist/*
```

**Required before publishing:**
- [ ] Pick a final package name (`iam-jit` is taken? `iam-risk-score`? `iam-policy-scorer`?). Check PyPI availability.
- [ ] Bump version in `pyproject.toml`. Use SemVer; 0.1.0 for first launch.
- [ ] Update the `description` field in `pyproject.toml` to be customer-facing.
- [ ] Add `keywords = ["iam", "aws", "security", "risk-scoring", "policy"]` for discoverability.
- [ ] Add `classifiers` for Python version + license + dev status.
- [ ] Set up a PyPI API token (`~/.pypirc`).
- [ ] Write a `CHANGELOG.md` (empty for v0.1.0; framework for future releases).

### Option B — split into two packages (post-launch)

If `iam-jit` is the heavy provisioner package, extract a minimal
`iam-risk-score` package that just contains:

  - `iam_jit.review` module → rename to `iam_risk_score.scorer`
  - `iam_jit.cli_score` → rename to `iam_risk_score.cli`
  - `tests/calibration_corpus/` for self-tests
  - No FastAPI, no DDB, no AWS deps

Two packages: install just the scorer for offline CI use; install
the full iam-jit only if you're running the provisioner.

This is a v2 task. v1 ships as one package.

## 2. GitHub Marketplace (the Action)

The action lives at `github-action/action.yml`. To publish:

### Steps

- [ ] Move the action to its own repo: `github.com/iam-jit/iam-risk-score-action`. Reason: GitHub Marketplace requires the action at the repo root. The action repo will be tiny — just `action.yml` + `README.md` + a `LICENSE` file.
- [ ] In the new repo, the `action.yml` should reference the published PyPI package: `pip install iam-risk-score>=0.1.0` (no `git+https://` fallback).
- [ ] Tag a release `v0.1.0` AND a `v1` floating tag. Marketplace conventions: users reference `@v1`, you push patches via the floating tag.
- [ ] Submit for Marketplace review at github.com/marketplace/new. Requires `branding` block (already in action.yml).
- [ ] After approval, the action shows up in the marketplace search.

### Test the action against a real repo before submitting

- [ ] Create a test repo with a sample IAM policy
- [ ] Add a workflow that uses `iam-jit/iam-risk-score-action@v1` (or your fork during testing)
- [ ] Verify it scores correctly + sets outputs + posts the PR comment
- [ ] Take a screenshot for the marketplace listing

## 3. Hosted API (api.iam-jit.dev)

### Infrastructure

- [ ] **Production AWS account.** Use a clean account (not omise-experimental). Single-purpose: iam-jit production.
- [ ] **Domain.** Register `iam-jit.dev` (or similar). Set up Route 53.
- [ ] **ACM cert** for `api.iam-jit.dev` (and `iam-jit.dev` for the landing site).
- [ ] **Deploy iam-jit SAM stack** with `LLMBackend=bedrock`, `BedrockModelId=us.anthropic.claude-opus-4-7`, `AlbCertificateArn=<the ACM cert>`.
- [ ] **CloudFront** in front of the ALB for caching same-fingerprint requests + HTTPS termination + global edge points. The score for the same policy is deterministic — cache on `policy_fingerprint`.
- [ ] **Route 53 alias** from `api.iam-jit.dev` → CloudFront distribution.
- [ ] **Status page** — UptimeRobot or BetterStack monitoring `/healthz`. Free tier is fine for v1.

### Application config

- [ ] Set `IAM_JIT_SCORE_API_KEY` to a server-issued secret. The score endpoint will require Bearer auth.
- [ ] Set `IAM_JIT_SCORE_RATE_PER_MINUTE` per tier (the API will need to read tier from the API key — see "Billing" below).
- [ ] Set `IAM_JIT_LLM=bedrock` and confirm Opus 4.7 invocation works (see `docs/BEDROCK-TEST-PLAN.md` for the verification flow).

### Billing (Stripe)

- [ ] Set up Stripe account
- [ ] Create products + prices for Free / Indie / Pro / Team / Enterprise tiers
- [ ] Stripe Checkout for the self-serve tiers (Indie/Pro/Team)
- [ ] Stripe webhook → API key issuance: when a Checkout session completes, create an API key in the iam-jit users table associated with the customer's email + tier
- [ ] Stripe Customer Portal for self-service plan changes / card updates
- [ ] Cancellation flow: when a subscription cancels, mark the API key as inactive

This is the biggest chunk of pre-launch infra work. Budget 2-3
days of focused effort. Most of it is Stripe glue, not iam-jit
code changes.

## 4. Documentation site

- [ ] Pick a static site generator (MkDocs Material is the fastest setup)
- [ ] Configure to serve at `docs.iam-jit.dev` (CNAME → Cloudflare Pages or GitHub Pages)
- [ ] Convert the markdown docs to the site nav structure:
  - Getting started (3-step quickstart)
  - API reference (the score endpoint with full schema)
  - CLI reference
  - GitHub Action reference
  - Pricing (link out)
  - Calibration / scoring model explainer
  - Rollout playbook (yes, customer-facing)
  - Compliance (SOC 2 status, security policy)
- [ ] Add a search bar
- [ ] Add Google Analytics (or Plausible if privacy-conscious)

## 5. Landing site

Separate from docs. Pure marketing. Convert visitors → free signups.

- [ ] Pick a framework (Astro / Next.js / Vanilla HTML — Astro is fastest for a static site with good DX)
- [ ] Build from `docs/LANDING-PAGE-COPY.md`
- [ ] Pricing page → links to Stripe Checkout for self-serve tiers
- [ ] Self-serve API key issuance flow (sign in with GitHub OAuth → instantly issued free-tier key)
- [ ] Embed the demo video (90s, the Claude-gets-prod-access narrative)

## 6. Pre-launch security checklist

- [ ] SOC 2 Type 1 audit scoped (Vanta / Drata — sign up, $10-20K for v1)
- [ ] DDoS protection on the API (CloudFront has basic by default; consider AWS Shield Advanced for enterprise tier)
- [ ] Rate limit by API key (currently per-IP; not granular enough for paid tiers)
- [ ] Audit log retention configured (see `docs/security-notes.md` § E5)
- [ ] Privacy policy + Terms of Service drafted (lawyers, ~$500-1500 for boilerplate startup docs)
- [ ] Cookie banner if collecting analytics in EU/UK

## 7. Soft launch (week 1-2)

Don't do the public launch until the soft launch validates:

- [ ] 5-10 friendly devs have used the free tier
- [ ] No critical bugs reported
- [ ] Documentation passes the "stranger can use it" test
- [ ] Stripe billing roundtrip tested end-to-end
- [ ] API uptime > 99.9% over the soft-launch period

## 8. Public launch sequence (one specific day)

Pick a **Tuesday morning ET** (best Show HN timing).

- [ ] T-2 hours: deploy the latest version, smoke-test
- [ ] T-1 hour: tweet/LinkedIn pre-launch teaser (build curiosity)
- [ ] T+0: Show HN post
- [ ] T+5 min: tweet thread with screenshots
- [ ] T+15 min: DEV.to article goes live
- [ ] T+30 min: DM 10 friendly devs ("we just launched, take a look")
- [ ] T+1 hour: corp-dev outreach emails to 20 acquirer-candidate contacts
- [ ] T+2 hours: reply to every Show HN comment so far
- [ ] T+4 hours: reply to every Show HN comment so far (again)
- [ ] T+24 hours: pull metrics, write a "launch retrospective" internal note

## 9. Post-launch (first 30 days)

- [ ] Daily: monitor signups, scan for support requests, reply to Show HN/Twitter mentions
- [ ] Weekly: ship a small improvement based on user feedback
- [ ] Weekly: corp-dev follow-up emails
- [ ] Weekly: run `scripts/generate-adversarial-policies.py` against the prod backend; promote findings to corpus
- [ ] Monthly: usage metrics report; iterate on pricing if conversion is off
