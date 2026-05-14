# iam-jit / iam-risk-score

> **A deterministic AWS IAM risk-scoring engine, adversarially calibrated.**
>
> | Corpus | Pass rate |
> |---|---:|
> | AWS-managed policies (every published one) | **1,489 / 1,489 (100%)** |
> | Documented attack patterns (Bishop Fox / Rhino / HackingTheCloud / MITRE) | **203 / 217 (93.5%)** |
> | Adversarial rounds run | **10** (max_gap=0 on the latest white-box round) |
>
> Open corpus, open methodology, open commit history. No competitor publishes
> a comparable metric — most don't expose their scoring rules at all. See
> [docs/CONVERGENCE-REPORT-2026-05.md](docs/CONVERGENCE-REPORT-2026-05.md).

---

Two products from one repo. Pick the one that fits your need.

| Product | What it is | Who it's for | Install |
|---|---|---|---|
| **[iam-risk-score](#iam-risk-score--the-scoring-api-launch-product)** | A 1–10 risk score for any AWS IAM policy in <100ms. API + CLI + GitHub Action. | CI pipelines, AI agents requesting AWS access, any tool that wants a verdict before granting permissions. | `pip install iam-risk-score` · [GitHub Action](https://github.com/trsreagan3/iam-risk-score-action) · [hosted API](https://iam-risk-score.com) |
| **[iam-jit](#iam-jit--the-full-provisioner-upsell-saas)** | The full JIT-IAM provisioner. Time-bound, least-privilege role provisioning into AWS with approval workflow, audit trail, and automatic revocation. | Teams that want to *grant* access, not just score it. AI agents that need actual AWS roles, not advice about them. | Deploy this repo's SAM stack into your AWS account. |

Both products share the same deterministic scoring engine, so the same calibration that protects your provisioning workflow also protects your CI pipelines and AI-agent runtimes. Open source under Apache 2.0.

**Want to deploy the stack?** Jump to **[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)** for a 5-minute MVP deploy (~$6/mo), then layered production-hardening tiers. The doc clearly labels which components are MVP-essential vs production-grade additions, so a fresh user can be live in 5 minutes without committing to the full launch infra.

---

## `iam-risk-score` — the scoring API (launch product)

> **Score AWS IAM policies before you grant access.**
> A deterministic-plus-LLM scoring engine that grades any IAM
> policy 1–10 in under 100ms. Free for the first 100 requests/month.

### How it works in 30 seconds

```bash
$ pip install iam-risk-score
$ iam-risk-score --offline my-policy.json

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

### Three integration paths

**CLI** — `pip install iam-risk-score`. Works offline (no network call) or against any API URL. Designed for pre-commit hooks, CI gates, and ad-hoc terminal use.

**HTTP API** — `POST https://api.iam-risk-score.com/api/v1/score`. Anonymous + free up to 100 requests/month per IP; paid tiers add an LLM narrative. Stateless, idempotent, JSON in / JSON out.

```bash
curl -X POST https://api.iam-risk-score.com/api/v1/score \
  -H "Content-Type: application/json" \
  -d '{"policy": {"Version": "2012-10-17", "Statement": [...]}}'
```

**GitHub Action** — `uses: trsreagan3/iam-risk-score-action@v1`. Score every policy change on every PR; gate merges by configurable threshold; post a structured PR comment. See [the action repo](https://github.com/trsreagan3/iam-risk-score-action).

```yaml
# .github/workflows/iam-review.yml
- uses: trsreagan3/iam-risk-score-action@v1
  with:
    policy-file: 'infrastructure/iam/*.json'
    threshold: 5
    comment-on-pr: true
```

### Free vs paid — the deterministic safety contract

The 1–10 numeric score is **fully deterministic** in every tier. Same input → same score, every time. The deterministic engine runs ~30 calibrated rules covering service sensitivity, action breadth, resource scope, destructive verbs, access-type mismatch, PassRole escalation, NotAction/NotResource tricks, and grant-duration amplification.

| Tier | Price | Quota | What you get |
|---|---|---|---|
| Free | $0 | 100 req/mo by IP | 1–10 score, factors, suggestions. Deterministic-only. Public API. |
| Indie | $19/mo | 5K req/mo | + per-API-key auth, no rate-limit on per-key |
| Pro | $99/mo | 50K req/mo | + **LLM narrative** (Claude Opus 4.7) — a plain-English explanation of the score for human reviewers |
| Team | $499/mo | 500K req/mo | + admin context API, Slack notifications, weekly digest |
| Enterprise | $2K+/mo | unlimited | + SOC 2 evidence export, dedicated calibration, SLA |

**Why this split is honest:** the LLM cannot lower the deterministic score. By explicit safety contract — verified by the `test_score_matches_calibration_corpus` regression test — the optional LLM only contributes narrative + extra suggestions. **A fully-compromised LLM cannot hallucinate a request into auto-approval.** That means the free tier is safety-equivalent to the paid tier; you only pay for the explanation, never the verdict.

### Regression-protected calibration

The scoring engine is gated by **2,600+ test cases**, including:

- **1,489 AWS-managed-policy snapshots** — every `arn:aws:iam::aws:policy/*` policy AWS publishes, scored and pinned with ±1 tolerance. Refactors that significantly shift verdicts on `AdministratorAccess` or `ReadOnlyAccess` fail CI immediately.
- **35 adversarial attack patterns** — privilege-escalation kits, mislabel attacks, NotAction footguns, evidence-destruction (CloudTrail tampering), RCE primitives (UpdateFunctionCode, SendCommand), condition-key bypasses, multi-statement hidden-rule attacks.
- **10 real-world custom-policy snapshots** — CI/CD Lambda update, Terraform state-bucket access, EKS pod S3 reader, ECS task execution. These pin "the scorer doesn't false-alarm on legitimate work."

Want to add a calibration case? Drop a YAML file into `tests/calibration_corpus/<tier>/`. No Python change required.

---

## `iam-jit` — the full provisioner (upsell SaaS)

> Working name. Naming is open — see DESIGN.md.

A self-hosted, **AI-native, agent-first** system for provisioning **time-bound, least-privilege IAM roles** in AWS.

**Built for the agent era.** iam-jit treats AI agents (Claude Code, Cursor, custom internal tooling, autonomous workflows) as primary users — not an afterthought. An agent on a developer's laptop, in CI, or running unattended in a Kubernetes Job can request just-in-time AWS access by describing the task in natural language; iam-jit gathers the missing details through a conversation, drafts a least-privilege policy, runs it through risk review, queues it for human (or — soon — automated) approval, provisions a time-bound role into the destination account, and gives the agent back a copy-paste-ready assume-role snippet. When the timer runs out, the role goes away automatically.

A web UI exists for humans, but it sits on top of the same endpoints the agents use. There's no second-class API. Bundled MCP server, JSON API, web UI, CLI — all four are equal-class surfaces.

**The split of responsibilities is intentional.** The agent on your laptop (or in your pipeline) has access to your repos, your kubeconfigs, your terraform state, your application code — far more context than any centralized service can be trusted with. iam-jit doesn't try to compete on context; it owns the parts that genuinely benefit from being centralized: approval workflow, risk scoring, audit trail, tamper-evident logging, time-bounded provisioning into AWS, automatic revocation. The agent does the thinking; iam-jit does the gating.

**On the roadmap: an Evaluator + EKS/cluster access.** Two named v2 items: (1) an opt-in *Evaluator* companion service that performs automated approvals when a request meets a deployment-defined safety policy (low risk score, read-only, short duration, known-account, services on an allow-list, etc.) — see [`docs/EVALUATOR.md`](docs/EVALUATOR.md); (2) time-bound **Kubernetes / EKS cluster access** — provisioning both the IAM half (EKS Access Entry or aws-auth) and the in-cluster RBAC binding together, expiring them together. Full v2 list in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Why this exists

Existing self-hostable solutions in this space don't fit:

- **Common Fate (Granted Approvals)** — open-sourced in 2022 but the approval-workflow product is no longer actively maintained as OSS after the company pivoted to a SaaS model.
- **Teleport Community Edition** — restricts commercial use to companies with fewer than 100 employees and less than $10M revenue (v16+); the access-request UI and approval rules are Enterprise-only.
- **ConductorOne, Apono, Sym, etc.** — commercial SaaS, not free or self-hostable.
- **AWS-native (Step Functions + Lambda + Identity Center)** — workable but every org rebuilds the same shape from scratch.

This project fills the gap: a free, self-hostable system that does just-in-time IAM-role provisioning with auditable approval and automatic expiry, deployable into your own infrastructure.

## How it works

Three principles:

1. **GitOps for everything.** Role requests, approvals, and provisioning state all live in this repo. The PR is the audit log. The merge is the approval. The Terraform apply is the provision.
2. **LLM-assisted policy authoring.** Users describe their task in plain English; a CLI uses [`policy_sentry`](https://github.com/salesforce/policy_sentry) plus an LLM to draft a least-privilege policy. The user reviews and adjusts before submitting. The LLM is scaffolding — `policy_sentry` is the deterministic backbone.
3. **Time-bound by default.** Every role has a `not_after` timestamp. A scheduled job revokes expired roles. There is no "permanent" mode.

### Lifecycle

```
[user]                                  [reviewer]                       [system]
  │                                          │                                │
  │ describe task                            │                                │
  │ ──────► CLI drafts policy                │                                │
  │ review/edit, open PR ────────────────►  reads diff                        │
  │                                          │ approve & merge ──────────────►│
  │                                                                  provision│
  │                                                                  log to   │
  │                                                                  library  │
  │                                                          (timer) revoke   │
  │                                                                  at expiry│
```

## Agent access: `iam-jit agent-grant` + MCP server

**The fastest way to give an AI agent bounded AWS access for one task.**

When you're running Claude Code, Cursor, Devin, or a custom agent and it
needs AWS access for a specific job — `iam-jit agent-grant` turns a
plain-English task description into a minimum-scope IAM policy, scored
by the same deterministic engine that protects the rest of iam-jit.

```bash
$ iam-jit agent-grant --task "read S3 logs from the prod-logs bucket" \
                      --account 123456789012 --region us-east-1

Matched patterns: s3-read
Confidence: 1/10 (1=high, 10=low)
Risk score: 1/10                      ◀── safe to auto-approve

Policy:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket", ...],
      "Resource": "arn:aws:s3:::prod-logs"
    }
  ]
}
```

The deterministic scorer validates every generated policy. The generator
can propose anything; the scorer rejects what's too broad. An LLM mistake
(in future LLM-backed generation) cannot bypass the safety floor.

**`--bias allow`** (default) includes more actions when the task is
ambiguous — best UX. **`--bias deny`** includes only the explicit subset
— best for fully-autonomous agent loops.

**Iterative refinement** when the result is too broad or too strict:

```bash
$ iam-jit agent-grant -t "deploy lambda" \
                      --exclude-action iam:PassRole \
                      --rationale "code-only deploy"
```

### MCP server: `iam-jit mcp-server`

iam-jit ships a built-in MCP (Model Context Protocol) server so any
MCP-aware agent — Claude Code, Claude Desktop, Cursor, custom Claude
Agent SDK builds — natively requests scoped policies. One-line config:

```json
// ~/.config/claude/mcp_settings.json
{
  "mcpServers": {
    "iam-jit": { "command": "iam-jit", "args": ["mcp-server"] }
  }
}
```

The agent then has a `generate_iam_policy` tool. The flow:

```
agent → "I need to query the prod-orders DynamoDB table"
   ↓
MCP → generate_iam_policy({ task: "...", account_id: "..." })
   ↓
iam-jit → policy + score (2/10) + refinement_hints
   ↓
agent → "OK, score is low; request the JIT grant"
```

**Why this matters beyond convenience:** if the agent (or an MCP server
the agent uses) is compromised, the blast radius is bounded by the
*scope of the requested task*, not the developer's full AWS credentials.
The deterministic scorer + scoped STS credentials together turn "I gave
my agent admin AWS access" into "I gave my agent ten-minute access to
one DynamoDB table."

See **[docs/agent-access.md](docs/agent-access.md)** for the full
pattern library, refinement workflow, and bias semantics.

## Pairing with local AI tools (the primary use case)

iam-jit is designed first for AI agents running on the requester's machine. Tools like [Claude Code](https://claude.com/claude-code), Cursor, or Continue can read your repos and clusters, derive a precise IAM policy with concrete ARNs, and submit it to iam-jit via the JSON HTTP API or the bundled MCP server. The flow:

```
[your laptop]                                            [iam-jit service]
─────────────                                            ────────────────
local AI agent reads:                                    
  - your terraform-live repo (AWS resource ARNs)         
  - your flux-* repos (which services run where)         
  - your k8s manifests (Service accounts, IAM roles)     
  - kubectl / aws CLI for live state                     
  - the application code (which APIs it actually calls)  
                                                         
agent drafts a policy with concrete ARNs ─POST /api/v1/requests─►  validate, score,
                                                                    queue for approval
                                                                    
                       webhook on state change ◄────────────────── approved /
                                                                    needs-changes /
                                                                    expired
agent reacts:                                            
  - approved → assume the role, do the work             
  - needs-changes → refine policy, resubmit             
```

**Why this split:**

- The local agent sees code, manifests, and ARNs that a centralized service by design cannot be trusted with.
- iam-jit owns the parts that genuinely benefit from being centralized: approval workflow, risk scoring, audit trail, time-bounded provisioning, automatic revocation.
- The risk-review step (1–10 scoring + factor analysis) runs server-side on every submission — agent-submitted policies get the same scrutiny as anything authored in the UI.

**Three ways to talk to iam-jit:**

1. **HTTP API** (`POST /api/v1/requests`, `GET /api/v1/requests/{id}`, etc.) — for any agent or tool that speaks JSON over HTTPS.
2. **MCP server** ([bundled `mcp-server/`](./mcp-server/)) — for [Model Context Protocol](https://modelcontextprotocol.io) clients. `pip install ./mcp-server`, drop the resulting `iam-jit-mcp` binary into your Claude Code / Cursor / Continue config, and 13 tools (`submit_role_request`, `list_pending_requests`, `approve_request`, `analyze_policy`, etc.) show up natively in your agent's palette.
3. **Web UI** — for humans who don't want to drive an agent. Same endpoints under the hood.

**Both sides of the loop are agent-callable.** Requester and approver both have first-class agent surfaces — the human UI is a convenience, not the canonical path:

```
Developer (requester)                                      Security / infra (approver)
─────────────────────                                      ───────────────────────────
"Claude, create an IAM role to do X, Y, Z and submit       In a browser:  open the queue,
 it to iam-roles for approval."                            see pending requests with the
                                                           pre-computed risk score + LLM
Claude reads codebase/cluster, drafts policy,              narrative, click Approve / Ask
calls submit_role_request via MCP. Watches for             for changes.
state changes via webhook.
                                                           Or in Claude Code:
On approval → Claude assumes the role, does                 "Show me pending iam-jit
the work.                                                    requests waiting on me."
                                                            "Review request DEVOPS-42 —
On request_changes → Claude reads the feedback,              it asks for s3:* on *. Help
refines the policy, resubmits.                               me draft a comment asking
                                                             them to scope to a bucket."
                                                            "Approve request DEVOPS-43
                                                             with no comment."

                Both sides use the same API + MCP tools as the UI.
```

**Example local-agent prompt:**

> *"Read `~/repos/my-service/`, the matching flux manifest in `~/repos/flux-staging/apps/my-service/`, and the AWS resource ARNs in `~/repos/terraform-live/aws/staging/my-service/`. Derive the minimal IAM policy this service actually needs, with concrete resource ARNs (no `*`). Submit it to iam-jit via the `submit_role_request` MCP tool with a 24-hour duration."*

The agent ends up doing nearly all the work; iam-jit is the trusted gate.

**Future context types.** We plan to make the hosted service understand more inputs natively too — link a GitHub repo, attach a kubectl context, ingest terraform plan output — so even users without a local agent can get richer-than-description context. The architecture treats all input shapes as the same once they reach the policy stage. Issues and PRs welcome on which context types matter most to your workflow.

## Bootstrap (first-time setup)

A freshly-deployed iam-jit instance has zero users — and every API write requires an authenticated admin. The first admin gets seeded one of four ways depending on how you deployed; the SAM template's `AdminBootstrapEmail` parameter is the production default and the CFN `Rules` block refuses to deploy without it. Local-dev gets a `iam-jit seed-admin --email …` CLI subcommand. Full walkthrough: **[`docs/BOOTSTRAP.md`](docs/BOOTSTRAP.md)**.

After the first admin is in, every additional user can be added either via the web UI (`/admin/users`) or programmatically by an agent holding an admin's API token (`POST /api/v1/users`).

When the time comes to remove iam-jit, follow **[`docs/TEARDOWN.md`](docs/TEARDOWN.md)** — drain active grants, tear down each destination-account stack, then the hub. Stack-delete order matters; doing it backwards leaves orphan IAM roles in destination accounts that iam-jit can no longer manage.

## Authenticating to iam-jit

Every iam-jit endpoint requires identity — there are no anonymous paths beyond `/healthz`. There are three ways to authenticate, depending on whether you're a human in a browser or an agent in a terminal.

### As a human in the browser (any auth mode)

```
1. Visit https://<your-iam-jit-url>/login
2. Enter your work email
3. Open the link emailed to you (in dev mode, it's also shown in the response body)
4. You're redirected back to iam-jit with a session cookie set
```

Sessions last 24 hours. Logging out clears the cookie immediately.

### As an agent (CLI, Claude Code, Cursor, custom tools) — `local` mode deployment

You authenticate with a bearer token minted from the UI:

```
1. Sign in to iam-jit in the browser (above)
2. Settings → API Tokens → "New token". Give it a label ("claude-code laptop").
3. Copy the raw token (shown ONCE at creation; format: `iamjit_<random>`).
4. Configure your agent:

   # In your shell:
   export IAM_JIT_API_TOKEN="iamjit_..."
   export IAM_JIT_BASE_URL="https://your-iam-jit.example.com"

   # In Claude Desktop / Claude Code MCP config:
   {
     "mcpServers": {
       "iam-jit": {
         "command": "iam-jit-mcp",
         "env": {
           "IAM_JIT_API_TOKEN": "iamjit_...",
           "IAM_JIT_BASE_URL": "https://your-iam-jit.example.com"
         }
       }
     }
   }

   # Or via raw HTTP:
   curl -H "Authorization: Bearer $IAM_JIT_API_TOKEN" \
        "$IAM_JIT_BASE_URL/api/v1/users/me"
```

The token inherits the user's roles. An agent acting on behalf of an `approver` can call `approve_request`; an agent acting on behalf of a `requester` can only `submit_role_request`, `check_request_status`, and `respond_to_changes`.

Token operations:
- Mint: `POST /api/v1/tokens` with optional `{"label": "..."}` (returns the raw token once)
- List your tokens: `GET /api/v1/tokens` (hashes only, no raw values)
- Revoke: `DELETE /api/v1/tokens/{token_hash}`

### As an agent — `aws_iam` mode deployment

If iam-jit was deployed with `AuthMode: aws_iam`, the Function URL itself enforces SigV4. Agents authenticate by SigV4-signing requests with their AWS credentials — no bearer token needed.

```
# Pre-req: your IAM principal (user or role) is in the iam-jit user list,
# usually as an entry like { "user_id": "iam:arn:aws:iam::111:role/Devops",
# "roles": ["requester"] }.

# Use any AWS-CLI-compatible tool. Example with awscurl:
awscurl --service lambda --region us-east-1 \
        --profile devops \
        "$IAM_JIT_BASE_URL/api/v1/users/me"

# Or in code, use boto3-signers / botocore.auth.SigV4Auth.
```

Identity Center session-assumed roles work the same — the Function URL extracts the role ARN, iam-jit normalizes it (drops the session suffix), and looks up the role in the user table.

### Failure modes worth knowing about

- `401 not authenticated`: no session cookie and no bearer token, OR an invalid/expired one.
- `401 invalid bearer token format`: the token doesn't start with `iamjit_`.
- `401 bearer token not found`: the token has been revoked or never existed.
- `403 user is no longer in the iam-jit user list`: your user record was deleted; ask an admin.
- `403 user is disabled`: your user record exists but `enabled: false`; ask an admin.
- `403 <role> role required`: you're authenticated but lack the role required for this endpoint.

Each error includes a `WWW-Authenticate: Bearer` header on 401s so agents know which scheme to retry with.

## Auditability and compliance posture

iam-jit's architecture is built around an immutable, query-able audit trail — not as an add-on feature, but as a property of the design. The tool itself doesn't certify any standard, but it provides the building blocks that several common compliance regimes care about.

**What gets recorded, where:**

| Event | Recorded in | Retention |
|---|---|---|
| Request submitted (who, what, when, accounts, duration, draft policy) | State bucket (S3 versioned object) + structured Lambda logs | S3 versioning policy (deployer-set) |
| State transitions (approve / reject / cancel / request_changes / edit) | Same versioned S3 object + Lambda logs | Same |
| Comments on a request | Same | Same |
| Risk-review analysis attached at submission and on each edit | `status.review` block in the request | Same |
| Cross-account provisioning (CreateRole, PutRolePolicy, sso-admin assignments) | CloudTrail in the destination account | Account-wide CloudTrail retention |
| Expiry / revocation | Lambda logs + final state bucket version | Same |
| User add / remove / role change | DynamoDB Streams (dynamodb mode) or S3 versioning (file mode) | Stream consumer / versioning policy |
| API token issuance / revocation | Lambda logs + DynamoDB record | Lambda log retention |
| Login (local auth mode) | Lambda logs | Lambda log retention |

Every record is tied to a stable `user_id` (email-based or IAM-ARN-based), so you can answer questions like "everything Alice approved in Q2" or "all grants Bob held in the last 12 months" from the audit trail alone.

**How this maps to common compliance requirements** *(non-exhaustive; this isn't a certification)*:

| Requirement | What iam-jit provides |
|---|---|
| **PCI DSS Req 7** (restrict access to least privilege) | Server-side risk scoring + narrowing flow + paste-mode validation prevent over-broad grants. `access_type: read-only` is enforced through the policy build. Provisioning roles are themselves tag-scoped so the system can't grant beyond `managed-by: iam-jit` resources. |
| **PCI DSS Req 8** (identify and authenticate users) | Every action is tied to a user_id (email or IAM ARN). No anonymous endpoints. Time-bound grants enforce Req 8.1.5 ("revoke access promptly when no longer needed") automatically. |
| **PCI DSS Req 10** (track and monitor access) | Full audit trail per the table above. CloudTrail in destination accounts captures every IAM/sso-admin call iam-jit makes. The state bucket retains every revision of every request. |
| **SOC 2 — Common Criteria CC6.1, CC6.6** (logical access controls) | Role-based authorization, owner-based ownership of requests, immutable audit log. |
| **HIPAA §164.312(b)** (audit controls) | Same audit trail; trails can be shipped to a SIEM via CloudWatch Logs subscription. |
| **ISO 27001 A.9, A.12.4** (access control + logging) | Role-based access; logs in CloudWatch + CloudTrail; separation of approver from requester. |

**Reporting API** *(Phase 1b)*: admin-only endpoints surface the audit data as JSON or CSV for compliance audits, without grepping log files:

```
GET /api/v1/reports/grants?status=active&since=2026-01-01&format=csv
GET /api/v1/reports/grants?account_id=111111111111&format=json
GET /api/v1/reports/activity?user_id=email:alice@example.com&since=2026-01-01
GET /api/v1/reports/approvals?approver_id=email:bob@example.com
GET /api/v1/reports/risk-distribution?since=2026-01-01
```

These endpoints require the `admin` role. Non-admins get `403`. The reports themselves never include the API tokens or session secrets — they only summarize requests, state transitions, provisioned grants, and approver activity. CSV outputs are formatted for direct ingestion by audit tooling.

**What deployers are responsible for** (the non-code parts of compliance):

- Configuring CloudTrail and CloudWatch Logs retention to match their regime.
- Shipping audit logs to a SIEM if their regime requires it.
- Periodic access reviews (the reporting endpoints make this easy but the cadence is a deployer policy).
- Encryption-at-rest configuration on the state bucket and DynamoDB tables (templates default to AES256 / DynamoDB-managed encryption; KMS-CMK is a supported override).
- Network controls (VPN / IAP / WAF) in front of the Function URL.

iam-jit gives you the audit signal; you bring the policy that interprets it.

## Status

Early scaffolding. See [DESIGN.md](./DESIGN.md) for the architecture and [docs/TESTING.md](./docs/TESTING.md) for the three-tier testing system. The project is built so you can run the entire stack locally — no AWS account required to develop, test, or even fully exercise the tool end-to-end.

## Contributing

This project is intended to be useful to anyone who needs JIT IAM access without paying for a SaaS. Issues, PRs, and design discussion all welcome from external organizations. A `CONTRIBUTING.md` will be added when the contribution surface is concrete (schema, CLI, CI workflows). For now, feel free to open issues with use cases or critique of the design doc.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
