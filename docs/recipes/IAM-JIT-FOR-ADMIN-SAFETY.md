# iam-jit for admin safety — the canonical recipe

> **Don't give Claude your AWS keys.** iam-jit issues narrow,
> time-bound, audited AWS credentials per task — so your AI agent
> can do real AWS work without standing access. This is the
> setup recipe + operational playbook.

## Who this is for

- **Solo devs** with their own AWS account who want Claude
  Code / Cursor / Devin to do AWS work safely
- **Infra / SRE admins** at small-to-medium teams who use
  agents to investigate, debug, and operate AWS
- **Anyone** who's looked at giving an agent admin AWS keys
  and felt the dread

## What you'll have when this is done

After ~5 minutes of setup:

- Claude (or any MCP-speaking agent) requests scoped AWS
  credentials per task instead of holding standing keys
- Read-only by default; writes require an explicit elevation
- Every action is region-bounded, account-bounded, time-bounded
  (1h default), and audited locally
- An egregious-action floor that blocks IAM modify / billing
  changes / cross-account / root settings regardless of how
  permissive the rest of the config is
- A weekly audit log showing exactly what Claude touched —
  with a clear read-only vs write split

## Quick install (90 seconds)

```bash
# 1. Install
$ pip install iam-jit

# 2. Start local mode
$ iam-jit serve --local
✓ Started on http://localhost:8765
✓ MCP endpoint: http://localhost:8765/mcp
✓ Using AWS credentials from ~/.aws/credentials (profile: default)
✓ Audit log: ~/.iam-jit/audit.db

# 3. Wire into Claude Code (one command)
$ iam-jit mcp install-claude-code
✓ Added iam-jit MCP server to Claude Code config
✓ Restart Claude Code to pick up the change
```

Done. Next time you start Claude Code, iam-jit is the AWS access
layer.

## How it differs from traditional IAM

| Traditional | iam-jit |
|---|---|
| Standing IAM role with broad permissions | Per-task short-lived credentials with narrow scope |
| You manually scope each role | Agent describes intent; recommender produces a minimum-scope policy |
| Approval friction or no approval | Read-only auto-approves; writes get one explicit moment of confirmation |
| Audit via CloudTrail (after the fact, no context) | Per-grant audit log with reason + score + actor + duration |
| Compromised keys = unbounded blast radius | Compromised credentials = 1h × narrow scope × region/account-bounded |

## The behavioral contract

iam-jit's MCP tool description teaches Claude (and any other
MCP-speaking agent) to follow a convention:

> Always request `access_type: read-only` by default. Only
> request `read-write` when the user has explicitly asked you
> to make a state-changing operation in their current message.

This means:

- Investigation / debugging / log reading / metric checking →
  reads auto-approve generously, you don't see a friction prompt
- "delete this resource" / "update that config" / "rotate this
  secret" → Claude requests write access; you see the
  elevation in chat; it auto-approves under your admin
  authority OR routes to admin review per the scoring engine

You retain full control of your AWS account; you just don't
have to hand Claude the keys.

## Example flow — debugging a production issue

```
You: "investigate why payments are failing for customer 4521"

Claude:
  [calls iam-jit MCP, requests read-only on DynamoDB+CloudWatch+S3]
  ✓ Read-only grant issued, scoring 0.18, valid 1h
  Reading the payments table for customer 4521...
  Reading the recent payment_events for that customer...
  Looking at CloudWatch logs for the payment service...
  
  Found: 3 transactions rejected by upstream gateway with
  TIMEOUT_ERROR. The gateway's connect timeout was reduced
  in the v2.4 config push 2 hours ago. Want me to roll back
  the timeout setting?

You: "yes"

Claude:
  [calls iam-jit MCP, requests write on the specific Parameter Store entry]
  ✓ Write grant issued for ssm:PutParameter on
    `arn:aws:ssm:us-east-1:111122223333:parameter/payments/gateway-timeout`
    scoring 0.35, valid 15min, auto-approved (admin-reduction)
  Restoring previous value...
  Done. Verifying payment flow recovers... ✓ payments succeeding.
```

You saw ZERO friction in the investigation phase. The single
write-elevation prompt was the moment that mattered. The audit
log clearly distinguishes "Claude investigated" from "Claude
changed."

## The audit log

Every grant issued by `iam-jit serve --local` is recorded to the
server's stdout (which uvicorn captures) and surfaced via the
JSON API:

```bash
$ TOKEN=$(cat ~/.iam-jit/cli-token)
$ curl -H "Authorization: Bearer $TOKEN" \
       http://localhost:8765/api/v1/requests
```

Each record includes the issued policy, score, mode, actor, and
the auto-approve decision chain — enough to answer "what did
Claude touch?" without spelunking CloudTrail.

> **Roadmap:** a dedicated SQLite audit store + browsable
> `/admin` UI is on the roadmap. For now, the JSON API and the
> server log are the durable surfaces.

## What it protects against

Concrete examples of attacks / mistakes iam-jit blocks or
bounds:

| Scenario | Without iam-jit | With iam-jit |
|---|---|---|
| Claude accidentally targets prod via copy-pasted ARN | Affects prod | Region-scope mismatch → grant denied |
| Claude's session is compromised by prompt injection | Attacker has admin keys for as long as your session lives | Attacker has 1h × scoped credentials within whatever's currently issued; can't elevate without your explicit OK |
| You leave the laptop unlocked + someone uses Claude | They can do anything you can in AWS | Bounded by per-task grants; audit log shows everything |
| Claude tries to "clean up" by deleting resources it shouldn't | Resources gone | Either: agent has read-only (no delete possible); or write grant scoped narrowly enough that the wrong delete is rejected; or egregious-action floor fires |
| Agent hallucinates an IAM-modifying action | Permission elevation | Egregious-action floor blocks regardless of any score |
| Stale credentials leak | Attacker uses them until manual rotation | Credentials expire in 1h; minimal exposure window |

## What it does NOT protect against

Honest about the limits:

- **Compromise of your laptop's AWS credentials.** iam-jit
  uses YOUR AWS credentials to assume the per-task roles. If
  an attacker has your `~/.aws/credentials`, they don't need
  iam-jit at all — they have your full AWS access. iam-jit
  doesn't make standing credentials safer; it makes the
  *agent's* use of them safer.
- **Prompt injection that makes Claude request something
  legitimate-looking-but-wrong.** iam-jit's gating is
  score-based, not intent-based. A request to "rotate the
  prod database password" scores legitimately; iam-jit
  doesn't know you didn't authorize it. The mitigation is
  the explicit write-elevation moment + the audit log
  catching anomalies.
- **Bugs in Claude / your agent ignoring the read-only
  convention.** The MCP tool description tells Claude to
  default to read-only. If Claude (or a compromised version)
  ignores that and submits `read-write` requests directly,
  iam-jit still gates by score — but the audit log will show
  more write requests than you might expect. Anomaly
  detection on write-grant frequency is your friend here.
- **Compromise of iam-jit itself running locally.** If your
  local iam-jit binary is replaced by malware, all bets are
  off — same caveat as `aws-cli` or `kubectl` malware
  replacement. Pin the version + checksum; install from
  PyPI signed releases when available.

## Tuning for your workflow

### Auto-approve thresholds

```bash
# Set in ~/.iam-jit/config.yaml or via env var
IAM_JIT_AUTO_APPROVE_RISK_BELOW=4     # writes auto-approve at score < 4
IAM_JIT_AUTO_APPROVE_READ_BELOW=9     # reads auto-approve at score < 9 (very permissive)
```

The lean-permissive defaults are intentional — block-happy =
abandoned. Tune up if you're paranoid; tune down if you're
hitting friction.

### Strict mode (for production-critical sessions)

```bash
# Per-session strict mode for a high-stakes task
$ iam-jit serve --local --strict

# Or permanently for a specific AWS account
$ iam-jit account set 111122223333 --safety-mode strict
```

Strict mode:

- Tighter score thresholds (writes need < 2; reads need < 5)
- No action wildcards in synthesized policies
- No admin-fallback escape hatch
- Extended audit retention

For day-to-day dev: use the default `read_write_swap` mode.
For prod-critical operations: opt up to strict explicitly.

### Egregious-action floor (always on)

Regardless of mode or tuning, iam-jit hard-blocks:

- IAM modifications on admin/role resources
- Account / billing operations
- Cross-account access to accounts you don't own
- MFA / root-account settings
- Destructive actions on `do-not-delete`-tagged resources
- Actions in the configured account-level blocklist

These can't be tuned away in safety mode. They're the floor.

## Upgrading your team

When personal use validates the value and you want team-wide
adoption:

1. **Stay on local mode** — each dev runs their own; no
   centralized infrastructure yet
2. **Upgrade to hosted SaaS (Indie / Pro / Team tiers)** —
   shared audit, Slack approval flows, multi-user accounts
   with role-based access. ~5 min setup via CloudFormation
   onboarding.
3. **Move to self-host Enterprise** when you need compliance
   scope, dedicated support, or full operational control

See [`docs/DEPLOYMENT.md`](../DEPLOYMENT.md) for the upgrade
path.

## Troubleshooting

### "Claude isn't using iam-jit"

- Check `iam-jit mcp list` shows the server is registered
- Restart Claude Code (MCP config is read at startup)
- Verify `~/.config/claude-code/config.json` (or platform
  equivalent) has the iam-jit entry

### "I'm getting permission errors even on read-only operations"

- `GET /api/v1/requests` returns the recent grant history with
  scores + risk factors so you can see exactly what tripped the
  scorer
- If you think the score is wrong, use the built-in feedback
  endpoint: `POST /api/v1/feedback/scoring`

### "iam-jit is too slow"

- Local-mode latency is ~50ms per grant. If you're seeing
  much higher, check that you're not configured against the
  hosted endpoint
- For very high-frequency agent loops, consider the
  plan-mode capture proxy (post-launch feature) which can
  batch permissions into a single grant

## Where to next

- **[`docs/recipes/AGENT-IAMJIT-HOOP-EXAMPLES.md`](AGENT-IAMJIT-HOOP-EXAMPLES.md)**
  — six scenarios for agent + iam-jit working through Hoop
  (session proxy + iam-jit credential layer)
- **[`docs/DEPLOYMENT.md`](../DEPLOYMENT.md)** — when you're
  ready to move beyond local mode
- **[`SECURITY.md`](../../SECURITY.md)** — threat model + how
  to report vulnerabilities
- **[`docs/compliance/COMPLIANCE-MAPPING.md`](../compliance/COMPLIANCE-MAPPING.md)**
  — control mapping for compliance audits

---

Last updated: 2026-05-15
