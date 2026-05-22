# Integration: iam-jit Bouncer suite + NanoClaw / OpenClaw

**Status:** ready in v1.0. No modifications needed to NanoClaw or OpenClaw — they respect standard system proxies + env vars, which is the entire integration story.

## The shape

```
┌──────────────────────────────────┐
│ NanoClaw / OpenClaw / Cursor /   │
│ Devin / Claude Code / Codex /    │  ← any agent harness
│ Open Interpreter / ...            │
└──────────────┬───────────────────┘
               │ HTTPS / AWS SDK / K8s API / SQL
               ▼
        ┌─────────────────┐
        │ Bouncer suite    │  ← iam-jit's proxy layer
        │ ibounce kbounce  │     (audit + risk-score + JIT creds)
        │ dbounce gbounce  │
        └─────────┬───────┘
                  │ forwarded after verdict
                  ▼
            AWS / K8s / DB / Internet
```

Existing agent dashboards (openclaw-mission-control, qwibitai/nanoclaw-dashboard, clawmonitor, etc.) show you **what's happening inside your agent**. iam-jit's bouncer suite + audit-stream UIs show you **what your agent is doing to the outside world**. Both layers, complementary visibility.

## What it gets you

| You want to know... | Look at... |
|---|---|
| Which agent session is making which API call right now | bouncer live audit-stream UI (per-product `GET /`) |
| Cross-protocol view of all agent activity | iam-jit unified audit query (`iam-jit audit query`) |
| Whether an agent attempted a dangerous operation | bouncer audit log + risk-score from iam-jit |
| Who approved which JIT grant + why | iam-jit request history + audit log |
| Full session replay across products | `*bounce session list` + `iam-jit session replay` (#285) |

## Setup recipe (every harness, same steps)

### 1. Install the bouncers

```bash
# Python
pip install iam-jit         # ships `ibounce` for AWS gating

# Go-based bouncers
go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest
go install github.com/trsreagan3/dbounce/cmd/dbounce@latest
go install github.com/trsreagan3/gbounce/cmd/gbounce@latest
```

### 2. Start the bouncers in background

```bash
# AWS gating (ibounce on 8767):
ibounce run --port 8767 --upstream https://your-aws-region.amazonaws.com \
  --profile safe-default \
  --audit-log-path ~/.iam-jit/audit/ibounce.jsonl &

# HTTPS observation (gbounce proxy on 8080, UI on 8769):
gbounce run --port 8080 --mgmt-port 8769 --allow-connect \
  --audit-log-path ~/.iam-jit/audit/gbounce.jsonl &

# K8s API gating (kbounce on 8766):
kbounce run --port 8766 \
  --profile safe-default \
  --kubeconfig ~/.kube/config \
  --audit-log-path ~/.iam-jit/audit/kbounce.jsonl &

# SQL gating (dbounce proxy on 5433, mgmt on 8768):
dbounce run --port 5433 --mgmt-port 8768 \
  --upstream postgresql://your-real-db:5432/your-db \
  --profile safe-default \
  --audit-log-path ~/.iam-jit/audit/dbounce.jsonl &
```

### 3. Configure your agent's environment

```bash
# AWS — point all SDK calls at ibounce
export AWS_ENDPOINT_URL=http://127.0.0.1:8767

# HTTPS — point browser-style HTTPS at gbounce
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export NO_PROXY=localhost,127.0.0.1

# K8s — point kubectl/client-go at kbounce
export KUBECONFIG=~/.kube/kbounce-routed-config  # config with cluster server = http://127.0.0.1:8766

# DB — connect to dbounce's wire port, not the real DB
export DATABASE_URL=postgresql://user:pass@127.0.0.1:5433/your-db

# Identity (optional but recommended)
export X_AGENT_NAME="nanoclaw"          # or "openclaw" / "claude-code" / etc.
export X_AGENT_SESSION_ID="$(uuidgen)"   # unique per session
```

### 4. Start your agent

Just start the agent normally. It'll honor the env vars; its outbound traffic flows through the bouncers.

```bash
nanoclaw start    # NanoClaw
openclaw          # OpenClaw
# or whichever harness you use
```

### 5. Open the audit UIs

In your browser:
- `http://127.0.0.1:8767/` — ibounce live AWS audit
- `http://127.0.0.1:8766/` — kbounce live K8s audit
- `http://127.0.0.1:8769/` — gbounce live HTTPS audit
- `http://127.0.0.1:8768/audit/events` — dbounce audit events (JSON; UI on roadmap)

Each refreshes every 2s. Color-coded by verdict. Filter + pause controls. As your agent runs, you see every protocol-level call in real time.

## Per-harness specifics

### NanoClaw

**Positioning**: NanoClaw uses [OneCLI Agent Vault](https://onecli.sh) as its credential gateway — it stores Slack/WhatsApp/Telegram/Gmail/etc. tokens and injects them at network boundary. **We are not a credential vault and do not compete with OneCLI on that axis.** Instead, we add the protocol-aware audit + risk-scoring layer for cloud + DB + general HTTPS — where OneCLI doesn't have coverage. Two complementary integration paths:

**Path A — Chain (zero NanoClaw-side changes):**

Configure OneCLI's upstream HTTP proxy to point at gbounce. OneCLI handles credential injection first; gbounce audits + risk-scores the post-injection request. Each tool plays its native role.

```yaml
# OneCLI config (operator-side; refer to OneCLI docs for exact syntax)
upstream_proxy: http://host.docker.internal:8080  # gbounce
```

**Path B — Parallel (recommended for cloud + messaging mix):**

Different protocols route to different gates: OneCLI for its native scope (messaging credentials); our bouncers for cloud + DB + general HTTPS. Pass these env vars at container start:

```bash
docker run \
  -e HTTPS_PROXY=http://host.docker.internal:8080 \
  -e AWS_ENDPOINT_URL=http://host.docker.internal:8767 \
  -e KUBECONFIG=/path/to/kbounce-routed-config \
  -e DATABASE_URL=postgresql://user@host.docker.internal:5433/db \
  -e X_AGENT_NAME=nanoclaw \
  -e X_AGENT_SESSION_ID="$(uuidgen)" \
  nanoclaw:latest
```

(`host.docker.internal` is Docker Desktop's way to reach the host from inside a container.)

For each protocol, NanoClaw's container honors the standard system env var → traffic routes to OUR bouncer for that protocol. OneCLI keeps handling messaging app credentials as designed.

**What we don't claim:** we don't replace OneCLI's credential vault. We don't store your Slack/Gmail/WhatsApp tokens. NanoClaw + OneCLI keep their full role for messaging APIs; we add audit + risk scoring where they don't have coverage.

**Complementary dashboards:** NanoClaw's existing dashboard at port 7890 (per [qwibitai/nanoclaw-dashboard](https://github.com/qwibitai/nanoclaw-dashboard)) shows agent INTERNAL state (sessions, tokens, memory). Our bouncer UIs (8767, 8766, 8768, 8769) show OUTBOUND protocol calls. Run both side-by-side for full visibility.

### OpenClaw

OpenClaw respects standard system proxies. Set the env vars before `openclaw` starts (in your shell rc, in your launchctl plist, etc.).

For containerized OpenClaw deployments, same docker-internal trick as NanoClaw.

OpenClaw's third-party dashboards ([openclaw-mission-control](https://github.com/willcheung/openclaw-mission-control), [tugcantopaloglu/openclaw-dashboard](https://github.com/tugcantopaloglu/openclaw-dashboard)) show internal agent state + filesystem audit. iam-jit bouncers add the protocol-level audit they don't cover.

Related: [openclaw issue #47876](https://github.com/openclaw/openclaw/issues/47876) (session-monitoring gap in long-lived gateways) — iam-jit's agent-identity attribution (`X-Agent-Session-Id` header per `[[agent-identity-in-audit]]` / #266) addresses exactly that gap.

### Cursor / Claude Code / Codex / Devin

Same shape. These tools all respect system proxy env vars. Set them before launch.

For Claude Code specifically:
```bash
HTTPS_PROXY=http://127.0.0.1:8080 \
HTTP_PROXY=http://127.0.0.1:8080 \
NO_PROXY=localhost,127.0.0.1 \
AWS_ENDPOINT_URL=http://127.0.0.1:8767 \
claude
```

(start a NEW Claude Code session; already-running sessions don't pick up env vars retroactively.)

## What you'll see

Real-time table per bouncer showing:
- Timestamp
- Severity (Info / Medium / High / Critical)
- Event type (DECISION / ADMIN_ACTION / HEARTBEAT / BURST_DETECTED)
- Actor (the agent name + session id from `X-Agent-Name` / `X-Agent-Session-Id` headers)
- Operation (the API call: `s3:GetObject`, `kubectl get pods`, `SELECT *`, etc.)
- Verdict (ALLOWED / DENIED / ADMIN GRANT / HEARTBEAT)

Cross-bouncer correlation via the `agent.session_id` field — if you run an investigation later (`iam-jit audit query --filter agent.session_id=abc123`), you can see every action that one agent session took across all four protocols.

## Cost

Bouncers run locally on your machine. No phone-home (`[[self-host-zero-billing-dependency]]`). No external services billed.

LLM-augmented risk scoring (iam-jit Pro tier) is opt-in + uses whichever LLM you configure — Bedrock, Anthropic API, OpenAI API, or local Ollama (per `[[pluggable-llm-backend-decision]]`).

## What this does NOT do

- **Doesn't see INSIDE TLS tunnels in v1.0.** gbounce in CONNECT mode sees the destination but not the request body (privacy/deployability tradeoff per `[[ibounce-honest-positioning]]`). MITM mode is v1.1+, demand-gated (per `[[don't-tailor-to-lighthouse]]`).
- **Doesn't replace your agent's own internal audit.** NanoClaw's session state + memory log are still useful. iam-jit covers a DIFFERENT layer.
- **Doesn't see file system operations.** OpenClaw mission-control's filesystem audit is its own thing; iam-jit gates network calls, not local IO.

## Composes with

- [openclaw-worked-example] memo — concrete OpenClaw recipe
- [audit-layer-complement-to-agent-harnesses] memo — strategic positioning
- [action-side-guardian-positioning] memo — analyst-category framing
- [agent-identity-in-audit] memo + #266 — the X-Agent-Session-Id header convention

## Reporting issues

If your harness doesn't honor the env vars cleanly OR the audit attribution is missing, that's an iam-jit issue — file at https://github.com/trsreagan3/iam-jit/issues. We can usually fix on our side OR provide a config patch.
