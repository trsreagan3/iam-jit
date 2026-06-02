# MCP recipes for non-Claude-Code clients

The Bounce suite ships MCP servers — `ibounce mcp serve` (AWS gate)
and `kbounce mcp serve` (Kubernetes gate) — that speak standard MCP
over stdio JSON-RPC 2.0. The `install-claude-code`,
`install-cursor`, and `install-codex` subcommands handle the most-
common clients automatically (atomic merge into the client's MCP
config, preserves every other server entry). **This doc is for
everything else.**

If you're on Claude Code, Cursor, or Codex (JSON variant), prefer
the `install-*` shortcut — it's exactly what this doc would walk
you through, with the merge handled for you. See
[`IBOUNCE.md`](IBOUNCE.md) for the canonical install path and
[`SECURITY-POSTURE.md`](SECURITY-POSTURE.md) for what the MCP
server does over the wire.

---

## Claude Code (`install-claude-code`)

`iam-jit mcp install-claude-code` is the canonical one-command path
for Claude Code operators. It does two things atomically:

1. **Writes `~/.claude.json`** (or the detected Claude Code MCP
   config path) — adds the `mcpServers.iam-jit` entry. Existing
   entries for other servers are preserved; the iam-jit entry is
   created or overwritten.

2. **Writes a bouncer env block into `~/.claude/settings.json`** —
   adds `AWS_ENDPOINT_URL`, `HTTP_PROXY`, and `HTTPS_PROXY` for
   whichever bouncers (ibounce / gbounce) are currently running on
   localhost. This is the critical step that routes Claude Code's
   AWS SDK calls through ibounce automatically in every future
   session.

```bash
iam-jit mcp install-claude-code
```

### What gets written to `~/.claude/settings.json`

```json
{
  "env": {
    "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
    "HTTP_PROXY": "http://127.0.0.1:8080",
    "HTTPS_PROXY": "http://127.0.0.1:8080"
  }
}
```

The exact values depend on which bouncers are running when you run
the install command. If no bouncer is running, no env block is
written; start ibounce/gbounce first, then re-run.

### Why a restart is required

Claude Code reads `~/.claude/settings.json` at session start.
Existing tool subprocesses (already-running `claude` windows) do
NOT pick up new env vars — they loaded the env at process start and
it is fixed for that session lifetime. To get the bouncer wiring:

1. Run `iam-jit mcp install-claude-code` (writes the env block).
2. **Restart Claude Code** (`claude` in a new terminal, or
   re-open the Claude Code window).
3. The new session inherits `AWS_ENDPOINT_URL` and routes calls
   through ibounce automatically.

### Immediate wiring without a restart (`iam-jit attach`)

If you can't restart your Claude Code session, use:

```bash
iam-jit attach
```

`iam-jit attach` wires the current session's env vars directly
(suitable for shell-driven agents), so the running session sees the
bouncer endpoints immediately. See `iam-jit attach --help` for the
full surface.

### Version requirement

The env-block write (`--settings-path`, `--no-env-block` flags)
requires **iam-jit v1.0.0 + PR #23** or later. If your installed
binary pre-dates this, `iam-jit mcp install-claude-code` will
silently skip the env-block write.

To check your binary is current:

```bash
iam-jit mcp install-claude-code --help | grep settings-path
```

If `--settings-path` appears, you're on the right version. If not,
upgrade:

```bash
pipx upgrade iam-jit                     # if installed via pipx
pip install --user --upgrade git+https://github.com/trsreagan3/iam-jit.git
pip install --upgrade -e /path/to/iam-roles  # editable install
```

`iam-jit doctor install-check` also checks for the stale-binary
condition and surfaces a WARN row with paste-ready upgrade commands.

---

The canonical snippet:

```json
{
  "mcpServers": {
    "ibounce": {
      "command": "ibounce",
      "args": ["mcp", "serve"],
      "env": {}
    },
    "kbounce": {
      "command": "kbounce",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

If your client supports `mcpServers`-style JSON config — most do —
that snippet is what you want; substitute your client's config
path below.

---

## Cursor (`install-cursor`)

`ibounce mcp install-cursor` is the one-command path for Cursor operators.
Cursor reads its MCP config from `~/.cursor/mcp.json` (user-level,
applies to every workspace) or `<project>/.cursor/mcp.json`
(workspace-level, applies only inside that project root).

```bash
ibounce mcp install-cursor      # writes ~/.cursor/mcp.json
kbounce mcp install-cursor      # idem for kbounce
```

### What gets written to `~/.cursor/mcp.json`

Unlike Claude Code (which has a separate `~/.claude/settings.json` for
process-level env vars), Cursor inherits env vars for tool subprocesses
exclusively from the MCP server's `env` block in `mcp.json`. The installer
therefore writes `AWS_ENDPOINT_URL`, `HTTP_PROXY`, and `HTTPS_PROXY`
**directly into the `mcpServers.ibounce.env` block** alongside the
attribution hints:

```json
{
  "mcpServers": {
    "ibounce": {
      "command": "ibounce",
      "args": ["mcp", "serve"],
      "env": {
        "IBOUNCE_AGENT_NAME": "cursor",
        "IBOUNCE_AGENT_SESSION_ID": "",
        "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
        "HTTP_PROXY": "http://127.0.0.1:8080",
        "HTTPS_PROXY": "http://127.0.0.1:8080"
      }
    }
  }
}
```

The exact port values depend on which bouncers are running when you run
the install command. If no bouncer is running when you install, no routing
vars are written and a warning is emitted — start ibounce/gbounce first,
then re-run.

### Why ibounce's MCP env block carries the routing vars

Claude Code has `~/.claude/settings.json` where it merges an `env` block
into every subprocess it spawns — so routing vars written there cascade
automatically to all tool calls. Cursor does not have this separate
settings file; the MCP server's `env` block is the only per-server
env-injection point. Writing the routing vars here ensures that the
subprocess the MCP server spawns (and any tools that subprocess calls)
inherit `AWS_ENDPOINT_URL` automatically.

### Workspace-level install

Pass `--path <project>/.cursor/mcp.json` to install at the workspace
level instead of the user level. Workspace config applies only within
that project root. The atomic-merge and env-block write semantics are
identical.

### Why a restart is required

Cursor reads `~/.cursor/mcp.json` at session start. Existing sessions do
NOT pick up new env vars — they loaded the env at process start and it is
fixed for that session. To get the bouncer wiring:

1. Run `ibounce mcp install-cursor` (writes the MCP config).
2. **Restart Cursor** (close and re-open).
3. The new session reads the updated MCP config and spawns the ibounce
   MCP server with the routing env vars.

### Skip the env block

Pass `--no-env-block` to write the MCP server entry without routing vars.
Useful when you manage env vars separately (e.g. via your system profile
or a `.envrc`).

**Verify:** restart Cursor; open Settings → MCP; both `ibounce`
and `kbounce` should appear as connected servers. Then ask the
agent to call a low-impact tool — for example,
`ibounce_list_rules` (lists the rule set; pure read) or
`kbounce_list_rules`.

---

## Codex (OpenAI Codex CLI) (`install-codex`)

`ibounce mcp install-codex` handles two cases:

**Case A — JSON config (most operators):** pass `--path` to a JSON MCP
config file and ibounce performs the same atomic merge as `install-cursor`,
including the bouncer routing vars in the server's `env` block.

```bash
ibounce mcp install-codex --path ~/.codex/mcp.json
```

**Case B — no path (TOML / unknown location):** `install-codex` without
`--path` prints a copy-pasteable JSON snippet and the manual-install
instructions. The snippet includes the routing env vars when bouncers
are running.

```bash
ibounce mcp install-codex       # prints snippet + instructions
```

### What the written/printed snippet includes

When bouncers are running, the `env` block in the snippet carries the
routing vars (parity with Cursor):

```json
{
  "mcpServers": {
    "ibounce": {
      "command": "ibounce",
      "args": ["mcp", "serve"],
      "env": {
        "IBOUNCE_AGENT_NAME": "openai-codex",
        "IBOUNCE_AGENT_SESSION_ID": "",
        "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
        "HTTP_PROXY": "http://127.0.0.1:8080",
        "HTTPS_PROXY": "http://127.0.0.1:8080"
      }
    }
  }
}
```

If no bouncer is running, the routing vars are omitted and a warning is
emitted — start ibounce/gbounce first, then re-run.

### TOML note

The Codex CLI stores its config in TOML at `~/.codex/config.toml`. The
Bounce installers do not edit TOML in place (third-party TOML editing
risks corrupting unrelated keys). If your Codex install uses TOML, paste
the snippet from `install-codex` by hand and add an `env` block manually:

```toml
[mcp_servers.ibounce]
command = "ibounce"
args = ["mcp", "serve"]

[mcp_servers.ibounce.env]
IBOUNCE_AGENT_NAME = "openai-codex"
IBOUNCE_AGENT_SESSION_ID = ""
AWS_ENDPOINT_URL = "http://127.0.0.1:8767"
HTTP_PROXY = "http://127.0.0.1:8080"
HTTPS_PROXY = "http://127.0.0.1:8080"
```

### Skip the env block

Pass `--no-env-block` to suppress routing vars in the written/printed
output. Useful when you manage env vars separately.

**Verify:** restart Codex; the MCP server list in your Codex
client should include `ibounce` and `kbounce`.

---

## Devin (`install-devin`)

Devin is a **cloud-hosted agent** (Cognition's sandbox). There is no
local config file for ibounce to write into. Per
`[[ibounce-honest-positioning]]` the installer surfaces this limitation
clearly and prints a recipe instead:

```bash
ibounce mcp install-devin       # prints PATH A + PATH B recipe
```

### PATH A: MCP server (when Devin supports MCP)

Devin's MCP config is configured via the Devin UI (Settings > MCP
Servers or equivalent). Add the snippet from `ibounce mcp show-config`.
Then set these env vars in your Devin task environment (Devin UI > task
env vars or repo config):

```
AWS_ENDPOINT_URL=http://<bouncer-host>:8767
HTTP_PROXY=http://<bouncer-host>:8080
HTTPS_PROXY=http://<bouncer-host>:8080
```

`ibounce mcp install-devin` will print the actual port values when it
detects running bouncers locally.

### PATH B: Pre-session operator setup (today's supported path)

Before starting a Devin session:

1. On a host Devin can reach (NOT `127.0.0.1` — Devin runs in a cloud
   sandbox and cannot see your local loopback):
   ```bash
   iam-jit doctor apply-config
   ```
2. In the Devin UI, set these task env vars to point at that host:
   ```
   AWS_ENDPOINT_URL=http://<bouncer-host>:8767
   HTTP_PROXY=http://<bouncer-host>:8080
   HTTPS_PROXY=http://<bouncer-host>:8080
   ```

### Networking limitation

Devin runs in Cognition's cloud sandbox. A bouncer on `127.0.0.1` is
**NOT visible** to Devin's sandbox — you must run the bouncers on a
host accessible from the Devin sandbox (e.g. a cloud VM, or a
container on a shared network). This is an honest limitation, not a
bug: ibounce never requires root or a transparent proxy; operator-set
task env vars are the correct injection point for cloud agents.

**Verify:** ask the Devin agent to call `ibounce_list_rules` via MCP.
If the tool is visible, the MCP server is wired correctly. If you're
using PATH B (env-only), verify by checking the ibounce `decisions_count`
on your bouncer host after a Devin AWS SDK call.

See `docs/HARNESS-RECIPES/devin.md` for the full recipe including the
`bouncer-informs-agent-informs-iam-jit` pattern for cloud agents.

---

## Custom JSON-RPC stdio clients

The Bounce MCP server speaks plain JSON-RPC 2.0 over stdin / stdout
— there is no transport-specific protocol beyond what the
[Model Context Protocol spec](https://spec.modelcontextprotocol.io)
defines.

To wire it into a custom client:

1. Spawn `ibounce mcp serve` (or `kbounce mcp serve`) as a
   subprocess; capture its stdin and stdout.
2. Write a framed `initialize` JSON-RPC request on stdin. Read the
   response on stdout.
3. Issue subsequent calls — `tools/list`, `tools/call`,
   `resources/list`, etc. — per the MCP spec.
4. The server exits cleanly when its stdin is closed.

For the full tool surface the server exposes, run `ibounce mcp
list-tools --json` or `kbounce mcp list-tools --json` locally; the
output is the same JSON-Schema description a client receives in
response to `tools/list`. The ibounce tool catalog is also
documented in the MCP section of [`IBOUNCE.md`](IBOUNCE.md).

---

## dbounce (SQL bouncer)

`dbounce` ships at v1.0 with the same MCP installer pattern.
Generic config shape:

```json
{
  "mcpServers": {
    "dbounce": {
      "command": "dbounce",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

`dbounce mcp install-*` subcommands mirror the ibounce / kbounce
installer surface. See the "Go Bouncer Tools" section below for the
full tool catalog.

---

## gbounce (HTTP bouncer)

`gbounce` ships at v1.0. Generic config shape:

```json
{
  "mcpServers": {
    "gbounce": {
      "command": "gbounce",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

`gbounce mcp install-*` mirrors the same pattern. See the "Go
Bouncer Tools" section below.

---

## MCP tool catalog (v1.0 Phase A-H surface)

The `iam-jit` MCP server (the iam-jit host process per
`[[ibounce-is-two-jobs-in-one-process]]`) exposes 60+ tools as of
v1.0. The headline catalog operators + agents should know:

### Setup + configuration (Phase A — declarative config)

| Tool | Purpose |
|---|---|
| `iam_jit_setup_from_config` | Apply `.iam-jit.yaml` declarative config; idempotent; reports drift |
| `iam_jit_posture` | Cross-product live state (mode / bouncers / autopilot / threat-feed currency) |

### Profile evolution (Phase C — continuous improvement)

| Tool | Purpose |
|---|---|
| `iam_jit_improve_profile` | Returns recent denies + audit context; agent reasons; agent calls back to install rule |
| `bounce_query_audit_long_range` | Multi-bouncer audit query across configurable time windows |
| `bounce_extract_permissions_from_audit` | Extract observed permissions from audit trail (input to profile generation) |
| `bounce_digest_recent` | "Your bouncer caught X this week" weekly-digest synthesis |

### Bouncer-informs-iam-jit chain (Phase E)

Per `[[bouncer-informs-agent-informs-iam-jit]]`:

| Tool | Purpose |
|---|---|
| `iam_jit_classify_deny` | Classify deny event as legit / ambiguous / adversarial (agent reasons; bouncer surfaces) |
| `iam_jit_handle_deny` | Operator-facing surface for resolving a deny (always-allow / add-to-profile / ignore / request-narrower-role) |
| `iam_jit_resource_map` | Observed resources within a scope, sourced from cross-bouncer audit trails |
| `iam_jit_request_role_from_synthesis` | Canonical use case: based on staging bouncer activity, request a prod-scoped role |

### Anomaly detection (Phase H — ibounce-only at v1.0)

Per `[[ibounce-honest-positioning]]`: Go bouncers ship anomaly
detection in v1.0+1 (#508). For ibounce:

| Tool | Purpose |
|---|---|
| `iam_jit_anomaly_status` | Current z-score baseline state per bouncer |
| `iam_jit_anomaly_recent_events` | Recently fired anomaly events with MITRE ATLAS classification |

### Canonical scoring + role-issuance

| Tool | Purpose |
|---|---|
| `list_templates` | Browse template catalog (AWS-managed + parameterized task + saved) |
| `get_template` | Fetch a template's policy shape |
| `score_iam_policy` | Deterministic 1-10 risk score + per-factor breakdown |
| `submit_policy` | Submit policy for grant issuance; gated by score + safety mode |
| `iam_jit_scope_self_for_task` | Compose JIT role for an agent's declared task scope |

For the full 60+ tool surface use `iam-jit mcp list-tools` (the
authoritative shape your agent would see). Per
`[[bouncer-zero-llm-when-agent-in-loop]]`: every "intelligent work"
tool above delegates LLM reasoning to the agent's own LLM — iam-jit
+ bouncers need ZERO LLM credentials on their side in local-dev mode.

---

## Go Bouncer Tools

Per `[[cross-product-agent-parity]]` the Go bouncers (kbounce /
dbounce / gbounce) expose the same agent-friendly UX surface as
ibounce, with product-specific verbs underneath. Each bouncer's
MCP server speaks its own tool prefix; agents that learn one
bouncer's surface use the others identically (only the prefix
changes).

For the authoritative per-bouncer tool list, run:

```bash
kbounce  mcp list-tools
dbounce  mcp list-tools
gbounce  mcp list-tools
```

### kbounce (K8s API gating)

| Tool | Purpose |
|---|---|
| `kbounce_posture` | Live state — current mode, profile, recent denies, active task |
| `kbounce_active_mode` | Current enforcement mode (cooperative / transparent / observe) |
| `kbounce_active_profile` | Currently-active profile name + source |
| `kbounce_active_task` | Currently-active task scope (if a task is open) |
| `kbounce_recommend_mode_for_task` | Deterministic decision matrix: task description → recommended mode |
| `kbounce_recommend_rules` | Synthesize draft rules from observed traffic over a window (per `[[cross-product-agent-parity]]` recommender parity) |
| `kbounce_profile_allow` | Add an allow rule based on an observed deny (round-trip with `kbounce_denies_recent`) |
| `kbounce_apply_preset` | Apply a curated rule pack (`cluster-admin-minus-destructive`, etc.) |
| `kbounce_denies_recent` | Recent deny events with classification context |
| `kbounce_tail_decisions` | Live tail of K8s-API decisions (compose with `iam_jit_request_role_from_synthesis` when k8s SA ↔ IAM role mapping is needed) |
| `kbounce_scope_self_for_task` | Compose a task-scoped K8s RBAC posture (agent declares task; kbounce narrows) |

### dbounce (SQL bouncer)

| Tool | Purpose |
|---|---|
| `dbounce_posture` | Live state — mode / profile / recent denies / active task |
| `dbounce_active_mode` | Current enforcement mode |
| `dbounce_active_profile` | Currently-active profile name + source |
| `dbounce_active_task` | Currently-active task scope |
| `dbounce_recommend_mode_for_task` | Decision matrix: task → recommended mode |
| `dbounce_profile_allow` | Add an allow rule based on an observed denied SQL statement |
| `dbounce_decide` | Get the deterministic verdict for a candidate SQL statement (dry-run a query without executing) |
| `dbounce_denies_recent` | Recent denied SQL statements (redacted per `[[mitm-beta-pii-pci-concern]]`) |
| `dbounce_tail_decisions` | Live tail of SQL decisions across connections (compose with `iam_jit_request_role_from_synthesis` when DB-role ↔ AWS-role mapping is needed) |
| `dbounce_pending_sync_prompts` | Sync-mode deny prompts awaiting operator answer |
| `dbounce_prompts_bulk_answer` | Resolve multiple pending prompts in one call |

### gbounce (HTTP egress bouncer)

| Tool | Purpose |
|---|---|
| `gbounce_posture` | Live state — mode / active deny rules / recent denies |
| `gbounce_active_mode` | Current enforcement mode |
| `gbounce_recommend_mode_for_task` | Decision matrix: task → recommended mode |
| `gbounce_deny_add` | Add a dynamic deny rule (domain / method / pattern) |
| `gbounce_deny_remove` | Remove a deny rule by ID |
| `gbounce_dynamic_denies_list` | List currently-active deny rules |
| `gbounce_denies_recent` | Recent denied HTTP egress attempts (URL + classification context) |
| `gbounce_profile_allow` | Add an allow rule based on an observed deny |

### Cross-product chain examples

Per `[[bouncer-informs-agent-informs-iam-jit]]`, the canonical
multi-bouncer flow is:

1. `kbounce_tail_decisions` / `dbounce_tail_decisions` /
   `gbounce_denies_recent` — bouncer surfaces evidence
2. Agent reasons over the evidence (agent's own LLM per
   `[[bouncer-zero-llm-when-agent-in-loop]]`)
3. `iam_jit_request_role_from_synthesis` — agent synthesizes the
   role request from observed bouncer activity, iam-jit provisions

Worked example: "Based on the staging-cluster activity my kbounce
caught this week, request a prod-scoped IAM role narrowed to the
exact actions the staging pod actually used."

---

## Verification recipe (no client required)

You can confirm the MCP server is healthy without any client. The
canonical smoke test:

```bash
# Send an MCP initialize handshake on stdin; expect a JSON-RPC
# response on stdout that includes serverInfo.
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0.1"}}}' \
  | ibounce mcp serve \
  | head -1
```

If the server is wired correctly you'll see a single JSON object
containing `"result"` and the server's `serverInfo`. The same shape
works against `kbounce mcp serve`.

For a fuller pass, `ibounce mcp list-tools` (and the kbounce
equivalent) prints the exact tool surface an agent would see —
that's the right command to confirm "what can my agent actually
do through this server."

---

## When to prefer `install-*` over hand-editing

For Claude Code, Cursor, and Codex (JSON variant), the
`install-{claude-code,cursor,codex}` subcommands are the
recommended path — they perform an atomic merge that preserves
every existing `mcpServers` entry and the rest of the config file.
A hand-edit can clobber unrelated entries; the installer cannot.

This doc is for:

- MCP clients **not** covered by the install-* commands (e.g.
  Devin, custom JSON-RPC stdio clients)
- Operators who want to hand-craft the config (e.g. as part of a
  dotfiles-managed setup) and need the snippet shape
- The Codex TOML path, where the installer deliberately prints
  rather than edits in place

For an end-to-end picture of what each MCP tool does and why the
suite ships an MCP surface at all, see
[`IBOUNCE.md`](IBOUNCE.md). For the security properties of the
`mcp serve` subprocess (what it does and does not send over the
network), see [`SECURITY-POSTURE.md`](SECURITY-POSTURE.md).

---

Last reviewed: 2026-06-02.
