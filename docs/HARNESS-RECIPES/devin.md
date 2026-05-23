# Devin — ambient iam-jit setup

Port of [claude-code.md](claude-code.md). Devin's MCP support is
still being announced — this recipe assumes MCP is available; if not,
fall back to the operator-pre-runs path (CLI before the agent starts).

## 1. Where to write the declaration

If Devin reads from `.devin/config.yaml` (their stated convention),
embed the declaration as a top-level YAML mapping:

```yaml
# .devin/config.yaml
agent:
  name: devin
  ...

iam-jit:
  enabled: true
  posture: ambient
  bouncers:
    ibounce: { enabled: true, mode: discovery, profile: auto }
    kbouncer: { enabled: when_kubeconfig_present }
    dbounce: { enabled: when_db_env_present }
    gbounce: { enabled: false }
  improve: { enabled: false }
  notify_on_deny: true
```

OR as a standalone `.iam-jit.yaml` at the repo root — the loader
walks both locations in precedence order so a project-level
`.iam-jit.yaml` overrides whatever's in `.devin/config.yaml`.

## 2. How Devin reads it on session start

**MCP path** (when Devin supports MCP):

Wire `iam-jit` in Devin's MCP config — same shape as Claude Code:

```json
{
  "mcpServers": {
    "iam-jit": {
      "command": "iam-jit",
      "args": ["mcp-server"]
    }
  }
}
```

Add this instruction to your Devin agent prompt template:

> On session start, call `iam_jit_setup_from_config` (no arguments).
> Bouncers declared in `.iam-jit.yaml` will be started; the result
> tells you what env vars to set when invoking subprocesses.

**Pre-session path** (today's fallback):

If Devin's MCP support isn't live in your install, run setup before
handing the session to Devin:

```bash
iam-jit doctor apply-config
# ... start your Devin session
```

## 3. How to override / opt out

Same as Claude Code — set `iam-jit.enabled: false`.

## 4. 30-second smoke test

Same as [claude-code.md](claude-code.md#4-30-second-smoke-test).

## 5. Devin-specific notes

* Devin runs in its own sandboxed environment; the bouncers started
  via `iam-jit doctor apply-config` need to be reachable on the
  loopback the Devin sandbox sees. For container-style Devin
  deployments, ensure the bouncer host + Devin agent share a
  network namespace OR Devin can reach a host-bridge port.
* MCP support status: pending. Last confirmed: 2026-05-23.
