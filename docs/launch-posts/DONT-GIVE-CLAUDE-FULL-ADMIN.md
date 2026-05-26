# Don't give Claude full admin

*A draft launch post for the iam-jit + Bounce suite. Target
audiences: infra engineers, founders running agents in production,
SecOps reviewing AI-agent rollouts, security people who saw the
PocketOS / Replit / Cursor / DataTalks.Club incidents and got
nervous.*

---

You probably have a `~/.aws/credentials` file (or an IAM role
with `*:*`, or a cluster-admin kubeconfig, or a DB user with
`SUPERUSER`). You probably let Claude Code read it.

This is the part where the security person at your company
either hasn't noticed yet, or has and is too tired to push back.
Because if you're using an AI agent for real infra work, the
trade is brutal:

- **Option A: scope down your own access.** Now you can't do
  your job either.
- **Option B: give the agent your access.** Now the agent can do
  anything you can do, for as long as your session lives,
  audited by exactly nothing.

The credential SHAPE doesn't change the problem. A long-lived
`AKIA…` key and an assumed IAM role with `Action: *` both grant
the same blast radius — full admin. A cluster-admin kubeconfig
is the same shape against your K8s cluster. A DB user with `DROP
TABLE` rights is the same shape against your database. The
specific anti-pattern, in plain English, is **handing full admin
to an LLM-driven loop and hoping nothing goes wrong**.

PocketOS lost their prod DB AND their backups in 9 seconds (April
2026, Cursor + Claude Opus 4.6). Replit had its DB wiped by an
agent. The Datadog Security team found a read-only-bypass SQL
injection in Anthropic's reference Postgres MCP server while it
was still pulling 21k weekly NPM downloads. These are not edge
cases. The pattern keeps repeating because the easy path for
"give the agent infra access" is "give it admin."

Neither of these is what you'd pick if anyone gave you a third
option. So here's a third option — for AWS, for K8s, for your
database.

## What iam-jit is

iam-jit sits between your AI agent and AWS. When Claude (or
Cursor, or Devin, or any MCP-aware agent) wants AWS access, it
asks iam-jit. iam-jit grades the request, issues a scoped role
for a bounded duration, and writes the whole thing to an audit
log — including the reasoning.

A typical hour with iam-jit looks like:

```
14:22  Claude → "List buckets in prod"
       iam-jit → grant: s3:ListBuckets, 30min, score 2/10
       (auto-approved as read-only, low risk)

14:23  Claude → reads bucket names

14:24  Claude → "Get logs-archive-2023 storage class breakdown"
       iam-jit → grant: s3:ListObjectsV2 + s3:GetBucketLocation
       on logs-archive-2023, 30min, score 2/10
       (auto-approved)

14:31  Claude → "Apply lifecycle: drop objects older than 90d
       on logs-archive-2023-staging"
       iam-jit → grant: s3:PutBucketLifecycleConfiguration
       on logs-archive-2023-staging, 1h, score 4/10
       (WRITE — confirm? [y/N])

       you: y

14:31  iam-jit → grant issued, audit-logged.
```

Notice the asymmetry. Reads auto-approve. Writes ask. That's
not because writes are scarier than reads at every grain — `s3:DeleteBucket`
is much scarier than `s3:GetObject *` — but because, statistically,
~80% of agent operations are reads with near-zero blast radius
and ~20% are writes that carry ~all the risk. Auto-approving
reads is how you make iam-jit not a thing you fight; asking on
writes is how you make iam-jit not a thing you regret.

## Three modes, one trust story

iam-jit ships in two shapes:

1. **Local mode** — `pip install git+https://github.com/trsreagan3/iam-jit.git && iam-jit serve --local`.
   Runs on your laptop, uses your local AWS credentials, audits
   to a SQLite file. Zero iam-jit-the-company involvement. Trust
   model is "trust the binary," same as `aws-cli` and `kubectl`.
   This is the free tier and the recommended way to start.

2. **Enterprise self-host** — deploy iam-jit into your own AWS
   account via SAM. Bedrock/Anthropic/AWS bills route directly
   to your account. No phone-home. Annual license + support.
   Dedicated-managed available for customers who'd rather have
   their managed-services partner run it.

We deliberately do NOT operate a multi-tenant hosted SaaS.
Running a tool that holds trust roles into many customer AWS
accounts would create a SolarWinds-style blast radius we refuse
to take responsibility for. You either run iam-jit on your own
infrastructure or you don't run it.

## The honest list of what it doesn't fix

I built this. I'm telling you what it doesn't fix because the
list of what it does fix is more useful if you trust the list of
what it doesn't.

- **An attacker with shell access on your laptop** can read
  `~/.aws/credentials` directly. iam-jit is a layer between
  agents and AWS, not a key vault.

- **Prompt injection that targets actions inside an
  already-granted scope** still works within that scope.
  iam-jit shrinks the blast radius from "everything you can do
  in AWS" to "the actions in this specific grant for the next
  hour."

- **Bugs in iam-jit itself.** The scorer is calibrated against an
  open adversarial-loop corpus (1500+ examples). We publish the
  corpus, the false-positive rate, and the
  threshold-band convergence numbers on every release.

## What makes it different from $OTHER_TOOL

iam-jit is in the "issue scoped AWS credentials on demand" lane,
not the "approve human access requests" lane (Apono, Opal) or
the "intercept queries at the protocol layer" lane (Hoop,
StrongDM). The closest comparable is: nothing, for agents. The
closest comparable for humans is Apono. We'll write a more
detailed comparison post; for now, the one-sentence version is:

> iam-jit is what Apono would be if it were designed in 2026
> with agents as the primary user and AWS as the only target.

If you've seen Cedar mentioned in the agent-authz space — Cedar
is application-level authorization. iam-jit is at the IAM
credential-issuance layer. They're complementary; you can use
both for different layers.

## The install (90 seconds, no kidding)

```bash
$ pip install git+https://github.com/trsreagan3/iam-jit.git
$ iam-jit init-solo
  Data dir:  /Users/you/.iam-jit
  Admin:     email:you@your-laptop.local
  API token: /Users/you/.iam-jit/cli-token (mode 0600)

Next steps:
  1. iam-jit serve --local
  2. Add this to Claude Code MCP config:
     {"mcpServers": {"iam-jit": {"command": "iam-jit", ...}}}
  3. Ask Claude for what you need.
```

> **Note:** Will switch to `pip install iam-jit` once we publish to PyPI (#235).

The MCP config tells Claude where iam-jit is. The token is the
local API credential — iam-jit-the-company never sees it,
because there is no iam-jit-the-company in this path.

That's the launch. Try it; tell me where it's wrong.

— *trsreagan3*

---

*p.s. — if you're at a company where you can't install a tool
that creates IAM roles in your account, there's a local-proxy
mode on the roadmap that runs iam-jit as an AWS SDK proxy
in-process. CloudTrail still sees your full identity, but
iam-jit enforces the scope client-side. Honest trade-off: it's
an iam-jit-enforced guardrail vs an AWS-enforced boundary.
Email me if you want to be an early tester.*
