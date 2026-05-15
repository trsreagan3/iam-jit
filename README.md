# iam-jit · iam-risk-score

> **Don't give Claude your AWS keys.**
> iam-jit issues narrow, time-bound, audited AWS credentials per task — so your AI agent can do real AWS work without standing access.

[![CI](https://img.shields.io/badge/CI-7%20rounds%20BB%2BWB%20audited-brightgreen)](docs/security/) [![Calibration](https://img.shields.io/badge/AWS--managed%20corpus-1489%2F1489-brightgreen)](docs/CONVERGENCE-REPORT-2026-05.md) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

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
| **[iam-jit hosted / self-host](#iam-jit-hosted--self-host)** | Full JIT-IAM provisioner: time-bound roles, scoring, approval workflow, Slack approval bot, OIDC SSO (Google + Okta), audit trail, auto-revocation. | Teams + enterprises with shared audit + multi-user + compliance needs. | Hosted SaaS ($19–$499/mo) **or** self-host SAM stack (Enterprise). |

All three share the same deterministic scoring engine. Open source under Apache 2.0.

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

```
User: "investigate the wallet-svc latency spike"
Claude: [calls iam-jit MCP, requests read-only on CloudWatch + ECS]
        Reading metrics, reading task definitions, reading logs...
        Found: connection pool exhausted on the v2.4 deploy.
        Want me to roll back?
User: "yes"
Claude: [calls iam-jit MCP, requests read-write on the specific task def ARN]
        Rolling back. Done.
```

User sees ZERO friction prompts in the read-only investigation phase. The single write-elevation prompt is the moment that matters. Audit log shows the read/write split explicitly.

---

## `iam-jit` hosted / self-host

> The full provisioner. For teams + enterprises that need shared audit, multi-user, OIDC SSO, Slack approval workflows, and either hosted convenience or self-host compliance scope.

### What's included

- **Multi-user accounts** with role-based access (requester / approver / admin)
- **OIDC SSO** — Google Workspace + Okta out of the box; generic OIDC for Azure AD / Auth0 / others
- **Slack approval bot** — approve/reject + request-changes modal in your existing Slack workspace; signed-request authenticated; team_id + channel pinning available
- **Web UI + JSON API + CLI + MCP server** — all four are equal-class surfaces; agents and humans use the same endpoints
- **Cross-account provisioning** — hub Lambda + destination accounts via cross-account assume-role
- **Time-bounded, scored, audited** — same scoring engine as iam-risk-score; auto-revocation when grants expire
- **Per-account LLM policy** — gate LLM narrative cost by account ("use LLM on prod, deterministic on dev")
- **MFA propagation** — propagates IdP MFA assertion through to `aws:MultiFactorAuthPresent` AWS Conditions
- **Safety modes** — `read_write_swap` (default, lean-permissive) and `strict` (compliance environments); configurable per-deployment, per-account, per-session

### Tiers

| Tier | Hosting | LLM backend | Pricing |
|---|---|---|---|
| Free | Local-only OR self-host | None | $0 |
| Indie | Hosted SaaS | Sonnet (capped) | $19/mo |
| Pro | Hosted SaaS OR self-host | Sonnet | $99/mo |
| Team | Hosted SaaS OR self-host | Opus | $499/mo |
| Enterprise | Self-host only | Opus (customer's Bedrock) | Annual license + support |

Hosted-SaaS Indie/Pro/Team use a CloudFormation-onboarding pattern — customer applies a one-click stack that creates an IAM role iam-jit-the-company assumes per grant. Trust path is bounded by the customer's permissions boundary policy. Enterprise customers self-host in their own AWS account for full control + compliance scope.

### Self-host quickstart

```bash
$ git clone https://github.com/trsreagan3/iam-jit && cd iam-jit
$ sam build && sam deploy --guided
```

See [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) for the full walkthrough — ~5 minutes to a working MVP deployment.

### Compliance posture

- **MFA chain** — IdP-MFA → ID token `amr` claim → propagated to STS via `aws:MultiFactorAuthPresent` Condition. PCI DSS §8.4, SOC 2 CC6.6, HIPAA §164.312(d) satisfied.
- **Audit log** — every grant, every transition, every approver action; tamper-evident; SOC 2 CC7.2 / HIPAA §164.312(b).
- **`creates-never-mutates`** — iam-jit creates new IAM resources; never modifies existing ones the customer owns. Clean CloudTrail attribution.
- **No phone-home** — self-host customers run iam-jit in a sealed AWS account with no external dependencies.

See [docs/security/](docs/security/) for the BB+WB audit history (9 rounds shipped) and [docs/compliance/](docs/compliance/) for the framework mapping.

---

## How it works (60 seconds)

1. **Caller submits an intent** (via MCP / CLI / API / web UI) describing what they need to do. Example: *"read CloudWatch logs for the payments service for the last hour."*
2. **iam-jit synthesizes a minimum-scope IAM policy** matching that intent. Pattern-based (deterministic) + LLM-augmented for Pro+ tiers.
3. **Scoring engine evaluates the policy** on a 1–10 risk scale. Pinned by the calibration corpus.
4. **Decision gate** — auto-approve if score < threshold (configurable per deployment / per account / per access_type); else route to human approval via Slack + web UI.
5. **Issue short-lived credentials** — provision the role in the destination account, return STS credentials to the caller. Default 1-hour TTL.
6. **Audit log** — captures who, what, why, when, score, approver. Retained per the customer's compliance policy.
7. **Auto-revoke at TTL** — role is deleted; credentials expire naturally.

---

## Architecture notes

- **Hub-and-spoke**: iam-jit Lambda runs in a designated hub AWS account; assumes cross-account roles into destination accounts to provision per-grant roles.
- **`creates-never-mutates`** invariant: iam-jit only CREATES new IAM resources; never modifies existing ones the customer already owns. Smaller blast radius if iam-jit is compromised; cleaner audit attribution.
- **Two-channel context boundary**: iam-jit consumes context from AWS state (customer-granted read access) + customer config/prompt. Never source code, never SaaS ingestion, never out-of-band crawling.
- **Self-host = zero billing dependency**: customer's AWS account holds all infrastructure; iam-jit-the-company gets paid for software license + support, not per-call infra.

---

## Documentation

- **[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)** — first-time deployment walkthrough
- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** — full production-deployment guide; pilot deployment profile; cost-control levers
- **[docs/recipes/](docs/recipes/)** — patterns + integration recipes (agent + Hoop examples, Slack setup, EKS template roles, terraform workflow)
- **[docs/security/](docs/security/)** — BB+WB audit history (9 rounds), security policy, vulnerability disclosure
- **[docs/CONVERGENCE-REPORT-2026-05.md](docs/CONVERGENCE-REPORT-2026-05.md)** — calibration discipline + corpus methodology

---

## Status

- **iam-risk-score**: launched. Stable schema; CLI + API + GitHub Action shipped.
- **iam-jit local**: in active development; targeted for v1 launch.
- **iam-jit hosted / self-host**: in active development; targeted for v1 launch with multi-provider OIDC, Slack approval bot, per-account LLM policy.

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## Contributing

Issues + discussions: [GitHub Issues](https://github.com/trsreagan3/iam-jit/issues). The calibration corpus + adversarial-loop methodology is fully open; contributions of attack patterns + legitimate-policy examples are especially valuable. See [docs/ADVERSARIAL-LOOP-PROCESS.md](docs/ADVERSARIAL-LOOP-PROCESS.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
