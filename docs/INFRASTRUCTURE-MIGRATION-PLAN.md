# Infrastructure migration plan: Cloudflare + Google Workspace

> **PARTIALLY SUPERSEDED 2026-05-24.** The DNS / domain / Cloudflare
> Pages landing-site / Google Workspace inbox portions of this plan
> are still current — those build the marketing surface, not a
> hosted-SaaS API tier. The references below to hosting an `api.iam-
> risk-score.com` Lambda or any other multi-tenant scoring endpoint
> are HISTORICAL per the restoration of [[no-hosted-saas]] to 100%
> on 2026-05-24: the scorer ships as offline CLI + Python library +
> GitHub Action only, with no operator-deployed scoring API. The
> domain + landing site + email aliases still serve the marketing
> + consulting-funnel motion; just the API-hosting parts are out.

**Context:** AWS Bedrock denied 2026-05-19 for 30-60d. AWS account 590519617224 remains conditionally usable (per #293 AWS-usage builder) but treated as fragile. Original DNS / domain / email plans relied on Route 53 + SES; this plan moves them off AWS entirely so launch doesn't block on re-evaluation.

Per [[self-host-zero-billing-dependency]] and the broader Bedrock-pivot decision: the AWS dependency for our brand infrastructure was always optional. The pivot makes it explicit.

## Goals (in priority order)

1. **Land iam-risk-score.com (and iam-jit.com if available)** with DNS we control, in <1 hour
2. **Stand up security@ / sales@ / support@ inboxes** so launch can list real contact addresses
3. **Host the landing page** on infrastructure that doesn't depend on AWS verification
4. **Get SPF/DKIM/DMARC right** from day 1 so outbound mail isn't flagged as spam
5. **Keep recurring cost under $25/mo** for the brand infrastructure tier (excluding marketplace fees and product hosting)

## Part 1: Domains + DNS — Cloudflare

### Why Cloudflare

- **At-cost domain registration** (no markup) — typically $9-11/yr for .com
- **Free DNS hosting** at any scale
- **Free DDoS + WAF + bot protection** — material since iam-jit gets scraped by security researchers
- **Free Cloudflare Pages** for static landing site hosting (Astro, Hugo, etc.) — replaces the original "S3 + CloudFront" plan
- **Free Cloudflare R2** (S3-compatible) for any static asset hosting, 10 GB/mo egress free — replaces S3 for landing-page assets
- **DNS-only mode** if we want to host elsewhere later (no lock-in)

### Domains to register

| Domain | Purpose | Priority | Notes |
|---|---|---|---|
| `iam-risk-score.com` | Marketing site + landing page | P0 (#64) | Hero domain |
| `iam-jit.com` | Product docs + API endpoint | P0 if available | May be taken; check at registration time |
| `bounce.dev` | Suite brand domain (per [[iam-jit-house-of-bounce]]) | P1 | Useful for `ibounce.bounce.dev` subdomains |
| `iam-risk-score.dev` | Hedge | P2 | Optional — only if .com unavailable |

Order .com first because it's what the landing post + README references already point at. If .com is taken: fall back to `.dev` and update references in a single sweep.

### Setup steps (each takes ~5 min after account created)

1. **Create Cloudflare account** at https://dash.cloudflare.com/sign-up using the founder email (or one of the new Google Workspace addresses once those exist — see Part 2)
2. **Verify email**
3. **Add a payment method** (one-time; debit/credit card)
4. **Register `iam-risk-score.com`**: Dashboard → Domain Registration → Register Domains → search → buy. Use `cloudflare-dns` nameservers (default).
5. **Configure DNS records** (initial — empty record set works for parking):
   ```
   A     @     192.0.2.1      (placeholder; landing will replace)
   A     www   192.0.2.1      (placeholder)
   CNAME api   iam-risk-score.pages.dev    (once Pages site exists)
   ```
6. **Enable security defaults**: SSL/TLS → Full (Strict); Bot Fight Mode → On; Always Use HTTPS → On

### Cost

- `.com` registration: $9.77/yr at-cost (last published Cloudflare rate)
- DNS: $0
- Pages: $0 (free tier supports 500 builds/mo, 100GB bandwidth/mo)
- R2: $0 (10GB egress + 1M Class A ops/mo free)
- **Total Cloudflare: ~$10/yr for the .com**

### Migration from existing references

After purchase + DNS configured, search the repos for any `iam-risk-score.com` references and verify they point at the right path:

```bash
cd ${HOME}/repos
for repo in iam-jit kbouncer dbounce gbounce homebrew-tap helm-charts bounce-profiles; do
  grep -rln "iam-risk-score.com" "$repo/" 2>/dev/null | grep -v ".git/"
done
```

If the landing site lives in `iam-jit/docs-site/` (Astro), Cloudflare Pages will auto-build on push to `main` once the GitHub integration is connected.

### What's NOT in scope for v1 DNS

- Route 53 hosted zone migration — there isn't one; AWS DNS was always notional
- SES domain verification — not needed; we use Google Workspace for inbound + Postmark for outbound (Part 3)
- Cloudflare Workers / Functions — only needed if we want serverless edge logic; landing page is static, so skip

## Part 2: Email — Google Workspace vs Zoho Mail

### Decision needed

| Provider | Cost/user/mo | Storage | Notes |
|---|---|---|---|
| **Google Workspace Business Starter** | $7 | 30 GB | Most familiar UX; integrates with everything; SAML for SSO later |
| **Zoho Mail Lite** | $1 | 5 GB | Cheap; UX is functional but dated; no Google Drive equivalent |
| **Zoho Mail Standard** | $3 | 30 GB | Sweet spot if cost matters more than Google brand |
| **Fastmail Standard** | $5 | 30 GB | Privacy-favored; no Google ad-tech relationship |
| **Self-host (mailcow / Mail-in-a-Box)** | $5-15/mo VPS | unlimited | Maximum control; ~weekend of setup; ongoing maintenance burden |

**Recommendation: Google Workspace Business Starter ($7/user/mo).** Reasons:
- Founder already uses Google Workspace personally; muscle memory + admin console familiarity
- SSO + SAML when needed later (per [[oidc-sso]])
- Best deliverability — Google's IP reputation is the gold standard for outbound
- Calendars + Docs + Drive for free as a side effect
- One-click DKIM key generation that just works

**If $$ matters more than ergonomics: Zoho Mail Standard at $3/user/mo.** Same feature surface, 25% the cost. Reasonable choice if you're optimizing pre-revenue burn.

### Addresses to provision

For Google Workspace, 3 user mailboxes covers it (each is independently billable):
| Address | Type | Who reads it |
|---|---|---|
| `security@iam-risk-score.com` | Real mailbox | Founder (only) |
| `sales@iam-risk-score.com` | Group alias → founder | Founder (only); upgrades to real mailbox when there's a salesperson |
| `support@iam-risk-score.com` | Group alias → founder | Founder (only); upgrades to real mailbox when there's a support person |
| `founder@iam-risk-score.com` OR `reagan@iam-risk-score.com` | Real mailbox | Founder personal under brand |

**Cost shape**: 1 real mailbox + 2 aliases = $7/mo. When sales/support grow into real headcount: $7/mo per added person.

### Setup steps (~30 min total)

1. **Buy Google Workspace** at https://workspace.google.com/business/signup using the founder's existing Google account for admin (or create a new admin account)
2. **Domain verification**: Google gives a TXT record to add to Cloudflare DNS. Paste it. Verification takes ~5 min.
3. **MX records**: Google publishes a list of 5 MX records to add to Cloudflare DNS. Paste them in. Receiving works immediately.
4. **SPF record** (TXT @ in Cloudflare DNS):
   ```
   v=spf1 include:_spf.google.com ~all
   ```
5. **DKIM** (in Google Workspace admin → Apps → Google Workspace → Gmail → Authenticate email → Generate new record). Add the resulting TXT record (`google._domainkey`) to Cloudflare DNS.
6. **DMARC** (TXT `_dmarc` in Cloudflare DNS):
   ```
   v=DMARC1; p=quarantine; rua=mailto:security@iam-risk-score.com; pct=100
   ```
   Start at `p=quarantine` (not `p=reject`) for the first month so legitimate mail isn't dropped if SPF/DKIM is mis-aligned. Upgrade to `p=reject` after 30 days of clean DMARC reports.
7. **Create the 3 addresses** in Workspace admin → Users
8. **Verify with a test send** from each address to your personal email and the founder address

### Receiving vs sending

The above covers RECEIVING mail + SENDING from Google Workspace UI (Gmail). What it does NOT cover:
- **Transactional email sent by the iam-jit application itself** (e.g., scoring-feedback notifications, alert emails)

Per [[self-host-zero-billing-dependency]] + [[opt-in-feedback-pipeline]]: iam-jit doesn't send transactional email today. The audit-export pipeline ships to operator-configured webhooks, not via email. So Part 3 below is optional / "if we ever need it."

## Part 3 (optional): Transactional email — Postmark or Mailgun

### When this matters

ONLY if iam-jit itself sends mail. Today it doesn't. Future cases:
- License-purchase confirmation emails (if we ever ship a self-serve checkout)
- Customer-facing notifications (Slack/webhook is the canonical path; email is fallback)
- Founder-side alerts (e.g., a customer's audit-export channel went silent — but those land in Slack)

### Provider comparison

| Provider | Cost (first 10k/mo) | Setup time | Notes |
|---|---|---|---|
| **Postmark** | $15/mo (free tier 100/mo) | 30 min | Best deliverability; clean ops UX; per-message pricing |
| **Mailgun Flex** | Pay-as-go ($0.80/1k after free tier) | 30 min | Cheaper at low volume; more developer-leaning |
| **AWS SES** | $0.10/1k after free tier | Was the original plan | **Skipped** — AWS dependency we're trying to remove |
| **Resend** | $0/free tier 3k/mo, $20/mo above | 15 min | Newer; React-Email integration; nice UX |

**Recommendation: defer until the first real use case.** When we DO need it: **Resend** ($0 for our likely volume + best DX). If we end up sending high-volume alerts: **Postmark**.

DNS for either: add a `mail._domainkey.iam-risk-score.com` TXT record from the provider; takes 5 min.

## Part 4: Landing page hosting — Cloudflare Pages

The landing page in `iam-jit/docs-site/` (Astro per the README) deploys to Cloudflare Pages for $0 / month.

### Setup (~20 min)

1. In Cloudflare dashboard → Workers & Pages → Create application → Pages → Connect to Git
2. Authorize Cloudflare's GitHub app on the `trsreagan3` org (or the iam-jit repo specifically)
3. Select `iam-jit` repo, branch `main`
4. Build settings:
   - Build command: `cd docs-site && npm install && npm run build` (adjust per the docs-site README)
   - Build output: `docs-site/dist`
   - Root directory: leave blank (Cloudflare auto-detects)
5. First build runs immediately; subsequent builds trigger on push to `main`
6. Once green: Cloudflare provides a `iam-risk-score.pages.dev` URL
7. Custom domain: Pages → custom domain → `iam-risk-score.com`. Cloudflare auto-creates the CNAME and the SSL cert is auto-issued.

### Cost

- $0 for build, hosting, bandwidth (within free tier limits — 500 builds/mo, 100 GB bandwidth/mo)

## Part 5: Cutover sequence (~2 hours total)

Order matters because some steps depend on previous ones:

1. **Buy domain at Cloudflare** (5 min) — unlocks DNS edits + Pages
2. **Buy Google Workspace** (5 min) — unlocks email account creation
3. **Wire up DNS records** (10 min) — Google verification TXT, MX records, SPF, DKIM, DMARC
4. **Verify Google ownership** (5 min) — confirms email starts working
5. **Create 3 user mailboxes** (10 min)
6. **Send 3 test emails** (5 min)
7. **Connect Cloudflare Pages → iam-jit repo** (10 min)
8. **First Pages build runs** (~3 min wait)
9. **Add custom domain to Pages → iam-risk-score.com** (5 min; cert provisioning ~5 min)
10. **Verify the landing site renders at the .com** (5 min)
11. **Update README + docs** any place that says "coming soon" or has placeholder URLs (15 min)
12. **(Optional) Monitor DMARC reports for 7 days, then bump `p=quarantine` → `p=reject`**

Total founder-side wall time: ~2 hours active + 7-day DMARC ramp.

## Part 6: Recurring cost summary

| Line item | Monthly | Yearly |
|---|---|---|
| iam-risk-score.com registration | — | $9.77 |
| Cloudflare DNS + Pages + R2 | $0 | $0 |
| Google Workspace Business Starter × 1 user | $7 | $84 |
| (Optional) iam-jit.com registration if available | — | $9.77 |
| (Optional) bounce.dev registration | — | ~$15 |
| **Minimum viable total** | **$7** | **$94** |
| **If +2 domain + transactional email** | **~$12** | **~$140** |

This is the *brand infrastructure* tier. Product hosting (Lambda/Fargate/whatever) is separate. Per [[self-host-zero-billing-dependency]] the product itself runs on the customer's infrastructure; we don't host anything customer-facing.

## What NOT to do (anti-patterns)

- **Don't buy a domain at GoDaddy or Namecheap then transfer.** Cloudflare's at-cost registration is the cheapest + simplest path; no transfer needed if you buy there directly.
- **Don't enable DMARC `p=reject` on day 1.** Quarantine first, monitor reports for 30 days, then upgrade. Reject day-1 causes legitimate-mail rejections from misconfigured forwarders + auto-responders.
- **Don't put SES IPs in SPF.** Per Bedrock pivot, we're explicitly off AWS for outbound mail. SPF should list Google's senders + (later, if transactional) Postmark/Resend.
- **Don't migrate to Google Workspace using a `@gmail.com` admin.** Use a Google Workspace user as the primary admin to keep account ownership inside the workspace (avoid the personal-Google-account-loses-access-to-business-domain failure mode).
- **Don't enable Cloudflare proxying ("orange cloud") on the MX records.** MX must point at Google's actual mail servers; proxied MX breaks delivery.
- **Don't forget to add `_dmarc` TXT.** Without DMARC, the SPF + DKIM you set up still leaves the domain spoofable.

## Composes with

- [[self-host-zero-billing-dependency]] — none of this brand infrastructure touches customer product paths
- [[push-policy-public-repo]] — all DNS/email config is on cloudflare.com/admin.google.com, not in repos
- [[tech-before-marketing]] — the LANDING SITE deploy is held until the marketing copy slice unlocks; the Cloudflare Pages connection itself is infrastructure (ships now)
- AWS account verification gate — these moves explicitly remove our brand-infrastructure dependency on AWS staying responsive

## Next-action checklist (founder)

- [ ] Sign up for Cloudflare account
- [ ] Register iam-risk-score.com (and iam-jit.com if available) via Cloudflare Registrar
- [ ] Sign up for Google Workspace Business Starter (1 user to start)
- [ ] Add Google domain-verification TXT to Cloudflare DNS
- [ ] Add Google MX records to Cloudflare DNS
- [ ] Add SPF + DKIM + DMARC TXT records to Cloudflare DNS
- [ ] Create security@ + sales@ alias + support@ alias + founder@ mailbox
- [ ] Send 3 test emails to confirm
- [ ] Connect Cloudflare Pages to iam-jit repo
- [ ] Bind iam-risk-score.com to the Pages site
- [ ] Update README references to the live URL
- [ ] (7d later) Bump DMARC `p=quarantine` → `p=reject`
