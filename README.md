# iam-jit · iam-risk-score

> **Don't give Claude your AWS keys.**
> iam-jit issues narrow, time-bound, audited AWS credentials per task — so your AI agent can do real AWS work without standing access.

[![CI](https://img.shields.io/badge/CI-13%20rounds%20BB%2BWB%20audited-brightgreen)](docs/security/) [![Calibration](https://img.shields.io/badge/AWS--managed%20corpus-1489%2F1489-brightgreen)](docs/CONVERGENCE-REPORT-2026-05.md) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

| Corpus | Pass rate |
|---|---:|
| AWS-managed policies (every published one) | **1,489 / 1,489 (100%)** |
| Documented attack patterns (Bishop Fox / Rhino / HackingTheCloud / MITRE) | **203 / 217 (93.5%)** |
| Adversarial audit rounds (BB+WB) | **9 shipped** |

Open corpus, open methodology, open commit history.

---

## Three modes — pick the one that fits

| Mode | What it is | Who it's for | Install |
|---|---|---|---|
| **[iam-risk-score](#iam-risk-score)** | A 1–10 risk score for any AWS IAM policy in <100ms. API + CLI + GitHub Action. Free for the first 100 requests/month. | CI pipelines, IDE plugins, anyone who wants a verdict before granting permissions. | `pip install iam-risk-score` |
| **[iam-jit local](#iam-jit-local)** *(new)* | Local-only safety layer between your AI agent and AWS. Runs on your laptop. Zero SaaS dependency. Your AWS credentials never leave your machine. | Solo devs / individual admins who want Claude bounded. | `pip install iam-jit && iam-jit serve --local` (90 seconds) |
| **[iam-jit self-host](#iam-jit-self-host)** | Full JIT-IAM provisioner: time-bound roles, scoring, approval workflow, Slack approval bot, OIDC SSO (Google + Okta), audit trail, auto-revocation — running in your own AWS account. | Teams + enterprises with shared audit + multi-user + compliance needs. | `git clone` + `sam deploy --guided` |

All three share the same deterministic scoring engine. Open source under Apache 2.0.

> **No multi-tenant hosted SaaS.** iam-jit-the-company does not operate a shared infrastructure tier — running a tool that holds trust roles into many customer AWS accounts would create a SolarWinds-style blast radius we refuse to host. iam-risk-score.com (the stateless scorer) is hosted because no credentials are involved; iam-jit itself runs in your AWS account. Dedicated single-tenant managed Enterprise contracts are available for large customers at high-fee — but each deployment is fully isolated, not shared.

---

## Why this exists

Most agents using AWS today have one of three setups, all bad:

1. **Agent has your admin keys.** Terrifying — one bad prompt and your prod database is gone.
2. **Agent has a too-narrow role.** Frustrating — agent constantly hits permission errors and stalls.
3. **No AWS access.** Loses ~50% of the agent's productive value.

iam-jit's answer: **read-only access by default; writes require your explicit OK.** ~80% of agent operations are reads; the 20% writes are where ~all the risk lives. Asymmetric friction matches asymmetric risk.

The architecture:

- iam-jit issues short-lived (1h default) AWS roles per task
- Reads auto-approve generously; writes get scored + gated
- Every grant is time-bounded, region-scoped, account-scoped, audited
- An agent operating through iam-jit *cannot accidentally* delete prod, pivot to another region, or exceed the user's authority

---

## `iam-risk-score`

> Score AWS IAM policies before you grant access. Deterministic-plus-LLM engine, 1–10 risk score, sub-100ms response.

### 30-second example

```bash
$ pip install iam-risk-score
$ iam-risk-score my-policy.json --offline

IAM Policy Risk Score
  Score:     7/10 (high)
  Threshold: 5 (FAIL)
  Analyzer:  deterministic

Risk factors:
  - Destructive action `s3:DeleteObject` on Resource: `*`
    (blast radius = every resource in this account)
  - Resource: `*` for s3 (broad cross-resource read/access)

Suggestions to reduce risk:
  - Scope `s3:DeleteObject` to specific resource ARNs
```

### Integration paths

- **CLI** — `pip install iam-risk-score`. Works offline (no network call) or against any API URL. Good for pre-commit hooks + CI gates.
- **HTTP API** — `POST https://api.iam-risk-score.com/api/v1/score`. Anonymous + free up to 100 requests/month per IP. Paid tiers add an LLM narrative.
- **GitHub Action** — drops into CI; fails the workflow if a policy scores above your threshold. [Action](https://github.com/trsreagan3/iam-risk-score-action) · [SARIF output](docs/SARIF.md) for code-scanning integrations.

### What gets scored

Every IAM policy structure: action wildcards, narrow vs broad resource ARNs, condition keys, NotAction/NotResource forms, trust policies, permission boundaries, SCPs. Score reflects blast radius if compromised, not just "is this big."

The 1–10 scale is **adversarially calibrated**: every scoring rule is pinned by tests sourced from real attack patterns + the full AWS-managed-policy corpus. See [docs/CONVERGENCE-REPORT-2026-05.md](docs/CONVERGENCE-REPORT-2026-05.md) and [docs/ADVERSARIAL-LOOP-PROCESS.md](docs/ADVERSARIAL-LOOP-PROCESS.md).

### How does this compare to AWS IAM Access Analyzer?

Honest answer: **complementary, not a replacement.** They solve adjacent problems.

| | AWS IAM Access Analyzer | iam-risk-score |
|---|---|---|
| **Cost** | Free, built into AWS | Free (offline CLI / `pip install`); 100/mo free via API; paid tiers above |
| **What it answers** | "What does this policy allow? Is there unused permission? Is anything publicly accessible?" | "If this policy is granted + compromised, how bad is the blast radius? (1–10)" |
| **Output shape** | Findings (pass/warning/error), policy validation, CloudTrail-based refinement suggestions | Numeric score 1–10 + per-factor breakdown |
| **Runs where** | AWS API call from an AWS context | Offline CLI, local API, hosted API, GitHub Action — no AWS account needed |
| **Methodology** | Amazon proprietary | Open calibration corpus + adversarial test suite (1,489 / 1,489 AWS-managed pass rate) |
| **CI integration** | DIY via AWS API + custom wrap | Drop-in GitHub Action + SARIF output |
| **Designed for agents** | No — human-reviewer-oriented | Yes — per-factor breakdown is the iteration signal |
| **CloudTrail-based refinement** | ✅ unique strength (narrows existing roles based on actual usage) | No (and not planned — different problem) |
| **External-access analysis** | ✅ strong (cross-account, public buckets) | Partial (some patterns flagged via scoring factors) |

**Use Access Analyzer for** what it does uniquely well: CloudTrail-based policy refinement, external-access findings, AWS-Organizations-wide analysis. It's free and built-in; there's no reason not to.

**Use iam-risk-score for** pre-grant risk scoring with a numeric scale, CI gates that fail on score thresholds, agent iteration loops where the per-factor breakdown drives narrowing, or any review that needs to happen offline / outside AWS. The open calibration corpus is reusable — you can extend it, audit it, contribute to it.

**Together** they catch different things: Access Analyzer tells you "this policy permits cross-account access you didn't intend"; iam-risk-score tells you "this policy scores 8/10 because it grants `iam:PassRole` on `*` without a Condition." Either alone leaves the other gap.

---

## `iam-jit local`

> The fastest path to agent-safety on AWS. Runs on your laptop. Your AWS credentials never leave your machine. No SaaS account, no AWS Console clicks. ~90 seconds end-to-end.

### Setup

```bash
$ pip install iam-jit
$ iam-jit serve --local
✓ Started on http://localhost:8765
✓ MCP endpoint: http://localhost:8765/mcp
✓ Using ~/.aws/credentials (profile: default)

$ iam-jit mcp install-claude-code
✓ Added iam-jit MCP server to Claude Code config
```

Done. Claude Code now has iam-jit as its AWS access layer.

### What you get

**Read-only by default.** Claude requests `access_type: read-only` per the MCP tool description's behavioral contract. Reads auto-approve generously; writes require explicit elevation per task.

**Region + account scoped.** Every issued credential is bound to the working region + account. Claude cannot pivot to prod by copy-pasting an ARN, cannot accidentally target a different AWS account.

**Time-bounded.** 1-hour default TTL. Compromised credentials have a bounded window of damage.

**Audited.** Every grant is logged locally (SQLite). Weekly review shows exactly what Claude touched — distinguishing read-only access (most of it) from explicit write operations (the few that mattered).

**Egregious-action floor.** Even with the most permissive settings, iam-jit hard-blocks IAM modification, billing changes, MFA settings, cross-account, and `do-not-delete`-tagged resources.

### Trust model

"Trust the binary on your laptop." Same trust model people accept for `aws-cli`, `kubectl`, `terraform`, `aws-vault`. iam-jit local has **zero dependency** on iam-jit-the-company's hosted infrastructure — no phone home, no telemetry, no licensing call-back. Open source binary; auditable.

### How agents use it

iam-jit exposes **four MCP tools** (MCP server v0.3.0). The agent (Claude Code, Cursor, etc.) drives the loop using its own LLM + codebase context; iam-jit scores and gates.

| Tool | Purpose |
|---|---|
| `list_templates` | Browse the catalog (AWS-managed policies + parameterized task templates + your saved team templates) |
| `get_template` | Fetch a template's policy shape |
| `score_iam_policy` | Rate any policy 1–10; returns per-factor breakdown so the agent knows what to narrow |
| `submit_policy` | Submit a policy for grant issuance; gated by score + safety mode |

**The decision at intake — known vs. unknown:**

- **Known resources** (specific ARN, single secret, single bucket+key) → pick a **parameterized task template** (`update-one-secret(arn)`, `download-one-file(bucket, key)`, etc.), fill the ARN, submit. Scores 1-3, auto-approves. No reduction loop needed.
- **Unknown resources** (investigation, exploration, multi-resource work) → pick a **broad baseline** (`ExploreReadOnlyWithSensitiveExclusions` for reads, `AdminLikeWithSensitiveExclusions` for writes) and **reduce from there** using the agent's codebase context. Three reduction axes: drop services, narrow ARNs, drop action classes.

Typical flow:

```
User: "investigate the wallet-svc latency spike"
Claude: [reads source code; knows wallet-svc lives in account 123,
         uses ECS + CloudWatch + DynamoDB, doesn't touch secrets]
Claude → iam-jit: list_templates(access_type="read-only")
        → ReadOnlyAccess, ExploreReadOnly..., SecurityAudit, ...
Claude → iam-jit: get_template("ExploreReadOnlyWithSensitiveExclusions")
        → full policy shape
Claude → iam-jit: score_iam_policy(<that policy>)
        → score=7; factors=[broad_resource, …]
Claude: [adds Deny on rds:*, narrows Resource to account 123 + us-east-1]
Claude → iam-jit: score_iam_policy(<narrowed policy>)
        → score=4
Claude → iam-jit: submit_policy(<narrowed>) → AUTO-APPROVED
        Reading metrics, reading task definitions, reading logs...
        Found: connection pool exhausted on the v2.4 deploy.
        Want me to roll back?
User: "yes"
Claude → iam-jit: submit_policy(<write policy on specific task def ARN>)
        → score=3, AUTO-APPROVED (narrow write)
        Rolling back. Done.
```

User sees ZERO friction prompts in the read-only investigation phase. The single write-elevation prompt is the moment that matters. Audit log shows the read/write split explicitly.

**iam-jit does not synthesize policies from natural-language prompts.** The agent (with its source-code context) writes the JSON, picks templates, and narrows. iam-jit scores and gates — that's the whole job.

---

## `iam-jit` self-host

> The full provisioner — runs in your own AWS account. For teams + enterprises that need shared audit, multi-user, OIDC SSO, Slack approval workflows. No multi-tenant hosted SaaS — each customer's deployment is isolated by design (see two-tier table below).

### What's included

- **Template browser** — three kinds of templates side by side:
  - **Broad baselines** — AWS-managed (`ReadOnlyAccess`, `SecurityAudit`, etc.) + iam-jit's `AdminLikeWithSensitiveExclusions` (broad admin minus secrets/sensitive S3/KMS decrypt/audit-infra destruction)
  - **Parameterized task templates** — narrow shapes like `update-one-secret(arn)`, `download-one-file(bucket, key)`, `invoke-one-lambda(arn)`, `read-one-cloudwatch-log-group(arn)` — score 1-3, almost always auto-approve
  - **Saved templates** — your team's recurring shapes (auto-evolved from re-use) and admin-promoted org-tier templates
- **Agent-driven reduction** — even human-driven web-UI sessions are encouraged to pull up Claude Code / Cursor for the narrowing step. iam-jit's UI never authors policies from natural-language prompts. Free tier: pick a template + fill parameters, OR submit raw JSON. Pro tier: also gets an LLM-guided Q&A walkthrough ("do you need RDS? secrets? which region?") that picks reductions for you — LLM acts as UX, not as author; questions are customer-configurable for tighter fit with your org's reduction patterns
- **Evolving preset library** — your team's recurring shapes get saved automatically after re-use; "based on `payment-incident-triage` template" in the audit trail; per-customer, no cross-tenant learning
- **Multi-user accounts** with role-based access (requester / approver / admin)
- **OIDC SSO** — Google Workspace + Okta out of the box; generic OIDC for Azure AD / Auth0 / others
- **Slack approval bot** — approve/reject + request-changes modal in your existing Slack workspace; signed-request authenticated; team_id + channel pinning available
- **Web UI + JSON API + CLI + MCP server** — all four are equal-class surfaces; agents and humans use the same endpoints
- **Cross-account provisioning** — hub Lambda + destination accounts via cross-account assume-role
- **Time-bounded, scored, audited** — same scoring engine as iam-risk-score; auto-revocation when grants expire
- **Per-account LLM policy** — gate LLM-narrative (scoring explanation) cost by account; iam-jit does not synthesize policies, only narrates scores
- **MFA propagation** — propagates IdP MFA assertion through to `aws:MultiFactorAuthPresent` AWS Conditions
- **Safety modes** — `read_write_swap` (default, lean-permissive) and `strict` (compliance environments); configurable per-deployment, per-account, per-session

### Tiers (two-tier model)

| Tier | What it is | LLM backend | Pricing |
|---|---|---|---|
| **Free** | Self-host the OSS Apache 2.0 core in your own AWS account. Unlimited users (honor-system threshold ~25 users to consider Enterprise). All MCP tools, scoring engine, audit log, OIDC SSO, MFA propagation, Slack approval bot, raw-JSON submission, personal-tier template library. | Customer-chosen (Bedrock / Anthropic / OpenAI / Ollama — any) | $0 |
| **Enterprise** | Free + proprietary plugins (live action tail / org-tier preset library / UI guided reduction) + support contract with SLA + signed release binaries. Self-host in your account OR dedicated-managed (single-tenant in a dedicated AWS account) for large customers. | Customer-chosen for self-host; managed-tier negotiated | Annual contract; typical $25–100K/yr self-host; $200K+/yr dedicated-managed |

**Why no per-seat hosted tier.** A hosted iam-jit would hold cross-account trust into every customer's AWS account — one breach pivots to many customers. We refuse to operate that. The OSS self-host model keeps each customer's blast radius bounded to their own account, the same as their existing IAM tooling.

**LLM-touching features (risk narrative, per-account LLM policy, LLM-augmented suggestions) are FREE in OSS** — you pay the LLM bills directly to your provider; iam-jit-the-company doesn't double-charge to enable features where you do the work. Enterprise pricing only applies to proprietary plugins where iam-jit-the-company maintains real infrastructure on your behalf.

### Self-host quickstart

```bash
$ git clone https://github.com/trsreagan3/iam-jit && cd iam-jit
$ sam build && sam deploy --guided
```

See [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) for the full walkthrough — ~5 minutes to a working MVP deployment.

### Compliance posture

- **MFA chain** — IdP-MFA → ID token `amr` claim → propagated to STS via `aws:MultiFactorAuthPresent` Condition. PCI DSS §8.4, SOC 2 CC6.6, HIPAA §164.312(d) satisfied.
- **Audit log** — every grant, every transition, every approver action; tamper-evident; SOC 2 CC7.2 / HIPAA §164.312(b). (Audit features detailed below.)
- **`creates-never-mutates`** — iam-jit creates new IAM resources; never modifies existing ones the customer owns. Clean CloudTrail attribution.
- **No phone-home** — self-host customers run iam-jit in a sealed AWS account with no external dependencies.

See [docs/security/](docs/security/) for the BB+WB audit history (13 rounds shipped) and [docs/compliance/](docs/compliance/) for the framework mapping.

---

## Audit & observability

Every deployment writes a structured, queryable audit log. The exact storage backend varies by mode but the schema and guarantees are identical.

### What's captured per grant

- **Request:** who requested, when, the natural-language task description (if any), the policy submitted, the template lineage (if based on a catalog entry)
- **Scoring:** the deterministic score (1–10), every risk factor that contributed, the suggestion list returned to the requester
- **Decision:** auto-approved or human-reviewed; if reviewed: who approved/denied, when, with what justification; safety mode + threshold in effect at decision time
- **Issuance:** the IAM role ARN created, the STS session ID, the assume-principal, the TTL
- **Lifecycle transitions:** every state change (pending → approved → issued → expired → revoked) with timestamp + actor
- **Closure:** revocation time, reason (expired vs. manual), role deletion confirmation

### Where the log lives, per mode

| Mode | Backend | Retention | Query |
|---|---|---|---|
| **iam-jit local** (`serve --local`) | SQLite at `~/.iam-jit/audit.db` | Forever (until user prunes) | `iam-jit audit ls`, `iam-jit audit show <id>`, raw SQL |
| **Hosted (SaaS)** | DynamoDB (customer's tenant slice) | Per customer's retention policy (default 7 years for compliance tiers) | Web UI grant-detail page, JSON API `/api/v1/audit/...`, exportable CSV/JSONL |
| **Self-host** | DynamoDB in customer's hub account | Per customer's CloudFormation params | Same as hosted; customer also has raw DDB access |

All modes additionally emit structured logs to stdout/CloudWatch (one-line JSON per event) so existing SIEM pipelines (Datadog, Splunk, Sumo, Wiz) can ingest in real time. No proprietary format.

### Compliance attestation drops out for free

The grant-record fields map 1:1 to common compliance evidence asks:
- **SOC 2 CC6.3** (logical access removal): the issuance + auto-revoke records prove access was time-bound
- **SOC 2 CC7.2** (anomaly detection): the score + factor list is the anomaly-detection signal; scores ≥7 are reviewable
- **PCI DSS §10** (audit trails): every state change is captured with actor, timestamp, before/after
- **HIPAA §164.312(b)** (audit controls): the structured log + tamper-evidence satisfies the "regular review" requirement
- **HIPAA §164.312(d)** (entity authentication): the MFA chain + IdP `amr` propagation is recorded per-grant

See [docs/compliance/](docs/compliance/) for the full framework mapping.

### Live action tail *(Pro+ tier, planned)*

> "What is alice's agent doing right now with the grant I approved 10 minutes ago?"

For grants currently within their TTL window, Pro+ tier surfaces a live stream of CloudTrail events filtered to the JIT-issued role's session ID. Three surfaces:

- **Web UI** — the grant-detail page shows actions as they happen, with `service:Action` + resource ARN per row
- **Slack DM** — opt-in periodic summaries ("alice's grant has executed 47 API calls in the last 5 min: s3:GetObject ×40, cloudwatch:GetMetricData ×7")
- **CLI** — `iam-jit grants tail <request-id>` follows the event stream

Requires CloudTrail-read in the customer's account, wired via the standard CFN onboarding (EventBridge rule filtering on `userIdentity.sessionContext.sessionIssuer.arn` matching iam-jit-created roles). Permission is scoped narrowly — iam-jit can only see events about roles iam-jit created.

The standard post-grant audit log already satisfies most compliance asks ("what did alice's agent do during that 1-hour window?" — answer: query the log later). The live tail is a UX win for the "I want to watch in real time" case, not a compliance prerequisite. See [docs/ROADMAP-V1.1.md](docs/ROADMAP-V1.1.md) for prioritization status.

---

## How it works (60 seconds)

1. **Caller submits a policy** (via MCP / CLI / API / web UI) — either a raw JSON policy, a selection from the template browser, or one drafted by an IDE agent with codebase context. iam-jit scores and gates; it does not synthesize policies from natural-language prompts.
2. **Scoring engine evaluates the policy** on a 1–10 risk scale + per-factor breakdown. Pinned by the calibration corpus.
3. **Iteration (agent-driven)** — the agent reads the factor list, narrows what's not needed (drops services, narrows ARNs, adds explicit Denies), and re-scores. iam-jit doesn't reason about the user's task; the agent does that with its codebase context.
4. **Decision gate** — auto-approve if score < threshold (configurable per deployment / per account / per access_type); else route to human approval via Slack + web UI.
5. **Issue short-lived credentials** — provision the role in the destination account, return STS credentials to the caller. Default 1-hour TTL.
6. **Audit log** — captures who, what, why, when, score, approver, template lineage if any. Retained per the customer's compliance policy.
7. **Auto-revoke at TTL** — role is deleted; credentials expire naturally.

See [docs/AGENTS.md](docs/AGENTS.md) for the agent-driven reduction-loop pattern in detail.

---

## Architecture notes

- **Hub-and-spoke**: iam-jit Lambda runs in a designated hub AWS account; assumes cross-account roles into destination accounts to provision per-grant roles.
- **`creates-never-mutates`** invariant: iam-jit only CREATES new IAM resources; never modifies existing ones the customer already owns. Smaller blast radius if iam-jit is compromised; cleaner audit attribution.
- **Two-channel context boundary**: iam-jit consumes context from AWS state (customer-granted read access) + customer config/prompt. Never source code, never SaaS ingestion, never out-of-band crawling.
- **Self-host = zero billing dependency**: customer's AWS account holds all infrastructure; iam-jit-the-company gets paid for software license + support, not per-call infra.

---

## Documentation

- **[docs/AGENTS.md](docs/AGENTS.md)** — the agent-driven reduction loop in detail (known-vs-unknown intake, four MCP tools, three reduction axes, anti-patterns, human-user fallback)
- **[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)** — first-time deployment walkthrough
- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** — full production-deployment guide; pilot deployment profile; cost-control levers
- **[docs/recipes/](docs/recipes/)** — patterns + integration recipes (agent + Hoop examples, Slack setup, EKS template roles, terraform workflow)
- **[docs/security/](docs/security/)** — BB+WB audit history (13 rounds), security policy, vulnerability disclosure
- **[docs/CONVERGENCE-REPORT-2026-05.md](docs/CONVERGENCE-REPORT-2026-05.md)** — calibration discipline + corpus methodology
- **[docs/calibration/100-prompt-sufficiency-loop.md](docs/calibration/100-prompt-sufficiency-loop.md)** — the calibration measurement that drove the NL synthesis removal
- **[docs/calibration/feature-reality-check.md](docs/calibration/feature-reality-check.md)** — feature-by-feature "claim vs. delivery" audit
- **[docs/ROADMAP-V1.1.md](docs/ROADMAP-V1.1.md)** — post-launch scope (currently empty per [[v1-scope-bar]])

---

## Status

- **iam-risk-score**: launched. Stable schema; CLI + API + GitHub Action shipped. 1,489 / 1,489 AWS-managed-policy corpus pass rate.
- **iam-jit local**: in active development; targeted for v1.0 launch.
- **iam-jit self-host**: in active development; targeted for v1.0 launch with multi-provider OIDC, Slack approval bot, template browser, evolving preset library, agent-driven reduction loop, MFA propagation, safety modes. No multi-tenant hosted SaaS planned; Enterprise customers either self-host or contract for dedicated-managed single-tenant.
- **MCP server**: v0.3.0 — adds `list_templates`, `get_template`, `submit_policy` to the existing `score_iam_policy`. Legacy `generate_iam_policy` is deprecated (removed in 0.4.0) — replaced by the agent-driven workflow per [docs/AGENTS.md](docs/AGENTS.md).

**What's NOT in iam-jit** (intentional, not deferred):
- Natural-language policy synthesis from a free-form prompt. We measured the approach + removed it when it didn't deliver — any iam-jit-side LLM-as-AUTHOR faces the same structural limit (no codebase context). iam-jit is scorer + catalog + gate; the agent (with codebase context + LLM) does the policy authoring.
- *What IS in iam-jit, distinctly:* LLM-as-UX-helper in the Pro-tier UI walkthrough (LLM asks bounded questions about a fixed baseline; user's answers drive deterministic policy modifications; scorer evaluates). Different category — the LLM never invents policy content.

**Pre-launch queue** (each finished fully before the next per *deliberate-feature-completion*):
- ✅ Remarketing pass (claims aligned with shipped reality, v1.1 roadmap collapsed)
- 🔄 NL synthesis deprecation Stage 1 done (`list_templates`/`get_template`/`submit_policy` ship as MCP 0.3.0; legacy `generate_iam_policy` tombstoned); Stages 2–4 to go
- ⏸ Preset library — `save_as_template` + similarity matcher + auto-suggest
- ⏸ `AdminLikeWithSensitiveExclusions` baseline (catalog entry + default presentation)
- ⏸ Reduction UX on templates (three reduction axes + grouped questions + one-shot checklist)
- ⏸ UI guided reduction (Pro tier, LLM-as-UX-helper, customer-configurable questions)
- ⏸ Real-IdP doctor validation (blocked on AWS account verification)

See [CHANGELOG.md](CHANGELOG.md) for release history and [docs/ROADMAP-V1.1.md](docs/ROADMAP-V1.1.md) for post-launch scope.

---

## Contributing

Issues + discussions: [GitHub Issues](https://github.com/trsreagan3/iam-jit/issues). The calibration corpus + adversarial-loop methodology is fully open; contributions of attack patterns + legitimate-policy examples are especially valuable. See [docs/ADVERSARIAL-LOOP-PROCESS.md](docs/ADVERSARIAL-LOOP-PROCESS.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
