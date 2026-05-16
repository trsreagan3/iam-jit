---
title: "What does it mean to be iam-jit native?"
date: 2026-05-16
status: draft
audience: founders, CTOs, security/platform leads
---

> **Draft note (2026-05-16):** working title and outline. To be edited + published around launch week.

## TL;DR

Being **iam-jit native** means your developers, agents, pods, and CI pipelines all get short-lived AWS credentials *per task* — issued, scored, and audited by a single layer that sits on top of standard AWS IAM. No standing admin keys anywhere. No long-lived service accounts. Every action by every principal is traceable to a grant record. It's the same AWS IAM you already know — IRSA, STS, CloudTrail — with the request-and-issue flow automated.

The result: agent safety, compliance evidence as a byproduct, and a posture you can describe to a buyer or an auditor in one sentence.

## The setup — why this matters

Every company building on AWS faces the same access problem:

- **Admin keys in env vars.** Convenient. Terrifying. One leaked `.zshrc`, one phished dev, one prompt-injected agent — and your prod database is gone.
- **Scoped service accounts.** Better, but they're too narrow (constant permission errors that block agents and devs) or too broad (a Lambda execution role with `s3:*` because nobody knew which buckets it'd touch).
- **No access at all.** Some teams just don't let agents touch AWS. Loses ~50% of the agent's productive value.

The pattern that consistently wins: **just-in-time, narrow, time-bound credentials per task.** AWS already gives you the primitives (`sts:AssumeRole`, IRSA, short-lived sessions). What was missing is the layer that automates the *request → score → approve → issue → audit → revoke* loop so it's not a per-task manual ceremony.

That's iam-jit. Being **iam-jit native** means you've built the loop into how your company operates from day one.

## What iam-jit native looks like

Six characteristics. None of them are unique to iam-jit (every one is achievable with hand-rolled AWS plumbing), but together they describe an operating posture that's hard to retrofit and easy to build into a new company.

### 1. Pods + agents request roles at runtime

Concrete operational shape:

- **EKS pods** boot with an IRSA-bound minimal "request from iam-jit" role. The pod's startup script calls iam-jit's MCP API, says "I'm the payments-service worker, here's my task," and gets back STS credentials scoped to *exactly what this pod needs for the next hour*. Aggressive caching: re-request before TTL expiry.
- **Lambda functions** ship with a minimal execution role and call iam-jit at the start of each invocation for the task-scoped role.
- **Agents (Claude Code, Cursor, custom Claude SDK builds)** call iam-jit's MCP tools per task. The agent reads its codebase context, picks a baseline policy from the catalog, narrows it for the specific task, and submits.
- **Long-running services** call iam-jit, cache the short-lived creds for 15–30 minutes, re-request before expiry.

Nothing in this list replaces AWS's primitives. The pod still uses IRSA. The Lambda still has an execution role. The credentials are still STS tokens. iam-jit *automates the per-task request flow on top* of the standard mechanisms.

### 2. No standing AWS credentials anywhere

No long-lived IAM users with access keys. No admin keys in env vars. No service accounts with `PowerUserAccess` sitting in a vault. Every credential is a short-lived STS session, issued because someone (a human OR an agent on a human's behalf) requested it with a specific justification.

The blast radius of any compromise is bounded by:
- The narrowness of the issued policy
- The TTL of the session
- The audit log that captures every action

### 3. All AWS access flows through iam-jit's audit log

Every grant record captures: who requested, when, the task description, the policy submitted, the score and risk factors, the safety mode at decision time, who approved (or which rule auto-approved), the IAM role ARN created, the STS session ID, the TTL, every state transition, the closure (expired vs manual revocation).

If a customer's data is touched, the chain reads: "principal X requested → approved by Y (or auto-approved per rule Z) → issued at T1 → expired at T2." That single chain answers ~90% of incident-response and audit questions.

### 4. Agent workflows are designed around iam-jit from day one

Agents don't get a "Cursor service account with broad access." They get the iam-jit MCP server in their `mcp_settings.json` and they learn the reduction loop:

1. Read the user's request + the codebase
2. Pick a baseline from `list_templates`
3. Narrow it using codebase context
4. Score with `score_iam_policy`
5. Submit with `submit_policy` when sub-threshold

When the agent needs to do something genuinely risky (provision new infra, modify prod data), iam-jit's scorer flags it and the human is in the loop. When the agent's just reading logs to debug an issue, the request auto-approves and the agent gets to work.

### 5. Pipelines route IAM through iam-jit

- Terraform/CDK plans are scored by iam-jit's CI integration before `apply`
- PRs that introduce a high-risk IAM resource (broad action wildcards, missing conditions) fail the workflow
- Plan-capture proxy catches privilege creep in IaC (the access surface area grows over time even when no individual change looks egregious)
- The same scoring engine runs locally for the dev (`iam-jit score policy.json`) and in CI (GitHub Action / SARIF output)

### 6. Compliance evidence drops out as a byproduct

When the auditor asks "show me every privileged access in 2026," the answer is a single query against the iam-jit audit log. Time-bound (the issuance + auto-revoke records). Justified (the task description). Approved (the approver chain). Scored (the risk factors). Tagged with the compliance-framework field that maps to the relevant control.

SOC 2 CC6.3 (logical access removal), SOC 2 CC7.2 (anomaly detection via score), PCI DSS §10 (audit trails), HIPAA §164.312(b) (audit controls) — they all reduce to "show me the iam-jit log."

## Why it's AWS-native, not a replacement

iam-jit-native deployments still use:

- ✅ AWS IAM (for the role definitions iam-jit creates per grant)
- ✅ STS AssumeRole (the standard issuance mechanism)
- ✅ IRSA / instance profiles / Lambda execution roles (for bootstrap identity)
- ✅ CloudTrail (for the post-grant audit trail)
- ✅ EventBridge / SQS (for the optional live action tail)

iam-jit adds:

- ➕ The automation that requests and issues roles per task
- ➕ The scoring + gating before each role gets created
- ➕ The unified audit log across all grant types
- ➕ The catalog + reduction tooling agents use to narrow

Same AWS account. Same AWS APIs. Same compliance posture. Just with iam-jit's automation layered in. There's no proprietary control plane to migrate to, no vendor lock to escape from. You can adopt iam-jit one workload at a time, and you can stop using it just as gradually if you ever decide to.

## How to get there incrementally

You don't need to refactor on day one.

**Week 1 — individual dev safety:** install `iam-jit local` on the laptops of the devs who use Claude Code / Cursor. ~90 seconds setup. Their agents start using iam-jit's MCP server immediately; their existing AWS workflows are unaffected. Audit log builds locally.

**Week 2-4 — CI integration:** drop the iam-jit GitHub Action into the repos that ship IAM changes. Set the threshold conservatively (block scores ≥7); tune as you see what real PRs score.

**Month 2 — hosted deployment for the team:** stand up iam-jit hosted (SaaS or self-host). Migrate the first team's grant requests through it. OIDC SSO + Slack approval flow + shared audit log. Other teams adopt voluntarily as they see the value.

**Month 3+ — pods + Lambda:** apply the bootstrap-IRSA pattern to your EKS pods one workload at a time. Start with non-prod. Pods request their actual scoped role from iam-jit at startup; the long-lived `PowerUserAccess` execution role you used to have gets retired.

By the time you've worked through that incremental adoption, you're iam-jit native. The audit log is comprehensive. The agent workflows are clean. The pipelines are gated. The next dev who joins doesn't need to learn 17 different access patterns — there's one.

## The signal it sends

**To buyers:** "We're iam-jit native, full audit chain on every privileged access" is a stronger answer to "what's your IAM posture?" than "we use AWS IAM."

**To auditors:** the audit report is a query, not a quarter-long evidence-gathering project.

**To new hires:** the access pattern is consistent, learnable, and doesn't require institutional knowledge about which long-lived service account belongs to which workload.

**To founders thinking about the next AWS-incident headline:** the blast radius of any single compromise is bounded structurally. The agent that gets prompt-injected has an hour-long, narrowly-scoped role, not your admin keys.

## Closing

The pattern isn't new — Snowflake-style "everything is a session" thinking has been creeping into infrastructure for years. What's new is making it cheap enough that you can run it for every grant, every pod, every agent invocation, with audit, scoring, and safety as defaults instead of bolt-ons.

iam-jit is the layer that makes "iam-jit native" feasible. Start with one dev, one repo, one cluster — and watch the access posture compound.

---

*iam-jit is open source under Apache 2.0. The scorer, the catalog, and the agent-driven reduction loop are free; hosted SaaS and Pro+ features (LLM-guided UI walkthrough, live action tail, evolving preset library) are how the company stays sustainable. See [github.com/trsreagan3/iam-jit](https://github.com/trsreagan3/iam-jit).*
