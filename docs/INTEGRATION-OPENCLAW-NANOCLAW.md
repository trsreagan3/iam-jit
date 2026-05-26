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
# Python — upgrade pip first (stock ubuntu:22.04 ships pip 22.0.2; PEP 660
# editable builds need pip >= 22.3; closes #548 from UAT L1 2026-05-24).
python3 -m pip install --upgrade pip
pip install git+https://github.com/trsreagan3/iam-jit.git         # ships `ibounce` for AWS gating

# Go-based bouncers — `go install` lands the binary in $(go env GOPATH)/bin
# (defaults to ~/go/bin). That directory is NOT on the default Ubuntu PATH
# (closes #549 from UAT L1 2026-05-24). Add it once:
#   export PATH="$PATH:$(go env GOPATH)/bin"
#   echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc   # or ~/.zshrc
go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest
go install github.com/trsreagan3/dbounce/cmd/dbounce@latest
go install github.com/trsreagan3/gbounce/cmd/gbounce@latest
```

> **Note:** Will switch to `pip install iam-jit` once we publish to PyPI (#235).

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

**Positioning**: NanoClaw uses [OneCLI Agent Vault](https://onecli.sh) as its credential gateway — it stores Slack/WhatsApp/Telegram/Gmail/etc. tokens and injects them at network boundary. **We are not a credential vault and do not compete with OneCLI on that axis.** We add the protocol-aware audit + risk-scoring layer for cloud + DB + general HTTPS — protocols OneCLI doesn't gate.

**Verified 2026-05-22** against the simulation harness at [`tests/integration/nanoclaw_paths/`](../tests/integration/nanoclaw_paths/) — three integration paths (Chain / Replace / Parallel) tested end-to-end with alpine + curl + aws-cli + the four bouncers + LocalStack + kind + Postgres. All three paths pass; product gaps surfaced are listed under [Surfaced gaps](#surfaced-gaps-2026-05-22) below.

#### The canonical NanoClaw + iam-jit deployment

The expected operator pattern is **not "pick a path"** — it's a single combined config where each bouncer plays its native role:

| Bouncer | Mode | Why |
|---|---|---|
| **gbounce** | **Chain — downstream of OneCLI** | OneCLI is already a messaging-app HTTPS proxy; gbounce sits behind it to audit + risk-score everything OneCLI forwards |
| **ibounce** | **Parallel — independent of OneCLI** | AWS calls never go through OneCLI; they go via `AWS_ENDPOINT_URL` directly to ibounce |
| **kbounce** | **Parallel — independent of OneCLI** | K8s calls go via `KUBECONFIG` pointing at kbounce |
| **dbounce** | **Parallel — independent of OneCLI** | DB calls go via `DATABASE_URL` pointing at dbounce |

So gbounce + OneCLI chain together (Chain pattern); the other bouncers sit alongside (Parallel pattern). Combined config:

```bash
# 1. Configure OneCLI's upstream HTTP proxy to point at gbounce (one-time, per OneCLI's docs)
#    OneCLI handles credential injection FIRST; gbounce audits the post-injection request.

# 2. Start NanoClaw container with env vars for the parallel bouncers (AWS / K8s / DB):
docker run \
  -e AWS_ENDPOINT_URL=http://host.docker.internal:8767 \
  -e KUBECONFIG=/path/to/kbounce-routed-config \
  -e DATABASE_URL=postgresql://user@host.docker.internal:5433/db \
  -e X_AGENT_NAME=nanoclaw \
  -e X_AGENT_SESSION_ID="$(uuidgen)" \
  nanoclaw:latest

# Note: HTTPS_PROXY is NOT set on the container — that's handled inside OneCLI's
# config (the chain pattern). NanoClaw's outbound HTTPS continues to flow through
# OneCLI → gbounce as usual.
```

**Subset deployments** (operator picks what they have):
- Cloud-only org: only set `AWS_ENDPOINT_URL` (ibounce); leave kbounce/dbounce out
- K8s-heavy org: add `KUBECONFIG` (kbounce)
- DB-gated workflow: add `DATABASE_URL` (dbounce)
- ALL of the above: full deployment

**What you do NOT need to change in NanoClaw:** nothing. OneCLI config + container env vars are the only operator surfaces. NanoClaw's `applyContainerConfig()` honors these naturally.

**What we don't claim:** we don't replace OneCLI's credential vault. We don't store Slack/Gmail/WhatsApp tokens. NanoClaw + OneCLI keep their full role for messaging APIs; we add audit + risk scoring where they don't have coverage.

**Complementary dashboards:** NanoClaw's existing dashboard at port 7890 (per [qwibitai/nanoclaw-dashboard](https://github.com/qwibitai/nanoclaw-dashboard)) shows agent INTERNAL state (sessions, tokens, memory). Our bouncer UIs (8767, 8766, 8768, 8769) show OUTBOUND protocol calls. Run both side-by-side for full visibility.

#### Per-path verified commands (2026-05-22)

The three NanoClaw integration paths from [openclaw-nanoclaw-architecture] memo, each verified against the harness:

##### Path A — Chain (lowest control / lowest effort)

`NanoClaw container → OneCLI gateway → gbounce → internet`

Configure OneCLI's upstream HTTP proxy to point at gbounce. OneCLI does its credential injection first; gbounce audits the resulting CONNECT line.

```bash
# 1. gbounce on the host (CONNECT-tunnel mode for chained HTTPS).
gbounce run --port 8080 --mgmt-port 8769 \
  --allow-connect \
  --audit-log-path ~/.iam-jit/audit/gbounce.jsonl &

# 2. In OneCLI Agent Vault config, set the upstream HTTPS proxy to
#    http://host.docker.internal:8080 (Docker Desktop) or your
#    host's LAN IP (Linux). Refer to OneCLI docs for the exact key
#    name; the shape is "HTTP_PROXY-style upstream chain."

# 3. Launch NanoClaw normally; its containers inherit OneCLI's
#    HTTPS_PROXY env var pointing at OneCLI; OneCLI then forwards
#    CONNECT lines to gbounce.
nanoclaw start
```

Verified by `tests/integration/nanoclaw_paths/test_path_a_chain`:
- gbounce receives the CONNECT delivered through OneCLI's chain
- `X-Agent-Session-Id` + `X-Agent-Name` proxy headers (when the inner client supplies them via `curl --proxy-header ...` / SDK equivalent) preserve agent attribution end-to-end — `unmapped.iam_jit.agent.session_id` is populated on gbounce events
- gbounce in CONNECT-tunnel mode sees host+port only, not request bodies (TLS passthrough; for body-level audit use Path B)

##### Path B — Replace (recommended for cloud-heavy workloads)

```
NanoClaw container → gbounce → internet
                  → ibounce → AWS
                  → kbounce → K8s API
                  → dbounce → SQL
```

```bash
# 1. Bouncers on the host.
gbounce run --port 8080 --mgmt-port 8769 --allow-connect \
  --audit-log-path ~/.iam-jit/audit/gbounce.jsonl &

# IAM_JIT_BOUNCER_EXTRA_HOSTS lets ibounce accept the container's
# host.docker.internal Host header (the SigV4 Host inside a container
# isn't an AWS hostname — the CRIT-32-01 allowlist needs this addition
# to forward; without it the event is logged but the client gets 403).
# Env var name kept as IAM_JIT_BOUNCER_* (env contract is stable across
# the ibounce rename; only the binary moved per [[bounce-suite-rename]]).
IAM_JIT_BOUNCER_EXTRA_HOSTS=host.docker.internal \
  ibounce run --port 8767 \
    --upstream https://your-region.amazonaws.com \
    --profile safe-default \
    --audit-log-path ~/.iam-jit/audit/ibounce.jsonl &

kbounce run --port 8766 --profile safe-default \
  --kubeconfig ~/.kube/config \
  --audit-log-path ~/.iam-jit/audit/kbounce.jsonl &

dbounce run --port 5433 --mgmt-port 8768 \
  --upstream postgresql://your-real-db:5432/your-db \
  --profile safe-default \
  --audit-log-path ~/.iam-jit/audit/dbounce.jsonl &

# 2. NanoClaw container with the bouncers as the routing targets.
SID="$(uuidgen)"
docker run --rm \
  -e HTTPS_PROXY=http://host.docker.internal:8080 \
  -e HTTP_PROXY=http://host.docker.internal:8080 \
  -e NO_PROXY=localhost,127.0.0.1 \
  -e AWS_ENDPOINT_URL=http://host.docker.internal:8767 \
  -e X_AGENT_NAME=nanoclaw \
  -e X_AGENT_SESSION_ID="$SID" \
  nanoclaw:latest
```

Verified by `tests/integration/nanoclaw_paths/test_path_b_replace`:
- HTTPS / AWS / K8s / SQL each land in the **right** bouncer
- No cross-contamination (AWS-shaped traffic does NOT show up in gbounce; HTTPS does NOT appear in ibounce)
- gbounce preserves `agent.session_id` end-to-end via `X-Agent-Session-Id` header
- ibounce / kbounce / dbounce events ALSO populate `agent.session_id` from the same headers (#318 closed cross-bouncer parity 2026-05-22); for dbounce the agent supplies `application_name=iam-jit-agent:NAME:SESSIONID` instead of an HTTP header — see `docs/AGENT-ATTRIBUTION.md` §SQL

##### Path C — Parallel (defense in depth)

```
NanoClaw container → OneCLI (for non-cloud APIs)
                  → ibounce (AWS via AWS_ENDPOINT_URL)
                  → kbounce (K8s via KUBECONFIG)
                  → dbounce (SQL via DATABASE_URL)
                  → gbounce (other HTTPS via HTTPS_PROXY)
```

```bash
SID="$(uuidgen)"
docker run --rm \
  -e HTTPS_PROXY=http://host.docker.internal:8080 \
  -e HTTP_PROXY=http://host.docker.internal:8080 \
  -e NO_PROXY=localhost,127.0.0.1,host.docker.internal \
  -e AWS_ENDPOINT_URL=http://host.docker.internal:8767 \
  -e X_AGENT_NAME=nanoclaw \
  -e X_AGENT_SESSION_ID="$SID" \
  nanoclaw:latest
```

The `NO_PROXY=...,host.docker.internal` membership is **load-bearing** for Path C: without it, the SDK respects `HTTPS_PROXY` even for AWS-shaped requests and they end up in gbounce instead of ibounce.

Verified by `tests/integration/nanoclaw_paths/test_path_c_parallel`:
- HTTPS to `example.com` flows through `HTTPS_PROXY` → (OneCLI in production) / OneCLI-mock (in test) → gbounce
- AWS to `s3.amazonaws.com` bypasses `HTTPS_PROXY` via `NO_PROXY` and goes direct to ibounce
- The two protocols **do not cross**

#### Surfaced gaps (2026-05-22)

Three product gaps were surfaced during integration testing; all three CLOSED 2026-05-22 in #318 (cross-bouncer X-Agent-* header parity):

- ibounce, kbounce, and dbounce now read inbound X-Agent-Name + X-Agent-Session-Id (dbounce uses `application_name=iam-jit-agent:NAME:SESSIONID` per [`docs/AGENT-ATTRIBUTION.md`](AGENT-ATTRIBUTION.md) §SQL since it sees the SQL wire protocol, not HTTP).
- All four bouncers now populate `unmapped.iam_jit.agent.{name, session_id, detected_from}` on every OCSF event — including the HTTP `/audit/events` endpoint that powers `iam-jit audit query` (closed via #320 / §A18 on 2026-05-22; pre-§A18 dbounce events were missing the agent block + kbounce events mis-labelled `detected_from` for HTTP-header-detected requests).
- `iam-jit audit query --filter agent.session_id=<UUID>` returns one event per bouncer. As of #320 / §A18 the SHORT-FORM filter alias (`agent.session_id=X`) is supported alongside the canonical long form (`unmapped.iam_jit.agent.session_id=X`); the CLI expands the short form client-side before forwarding so each bouncer's filter parser still sees the canonical OCSF path. The integration tests at `tests/integration/cross_bouncer_session_id_parity_test.py` (JSONL-side, #318) + `tests/integration/audit_events_wire_parity_test.py` (HTTP `/audit/events`-side, #320) are the regression guards.

A fourth honest-positioning note: operational gbounce binaries pre-#308 emit `unmapped.iam_jit.ext.agent_session_id` instead of `unmapped.iam_jit.agent.session_id`. Rebuild gbounce against post-#308 source (which the smoke test confirmed works) so the cross-bouncer correlation query path matches.

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

LLM-augmented risk scoring at v1.0 is **agent-delegated** per `[[bouncer-zero-llm-when-agent-in-loop]]` — the agent in the loop (Claude Code, Cursor, Codex, Devin, etc.) uses its OWN LLM credentials (Max / Plus / Pro / API key / Ollama / etc.). iam-jit ships with zero LLM credentials required for local-dev. For standalone-mode (CI/CD / cron / no-agent-in-loop), an opt-in `--llm-backend anthropic|openai|bedrock|ollama` flag uses whichever backend you configure (per `[[pluggable-llm-backend-decision]]`).

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
