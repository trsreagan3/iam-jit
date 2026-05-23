# Codex — ambient iam-jit setup

Port of [claude-code.md](claude-code.md). Codex reads agent
instructions from `AGENTS.md` (per Codex's documented convention),
so that's where the declaration lives.

## First-run wallpaper

Your iam-jit bouncer audits Codex's tool calls silently. When it
catches something worth your attention you'll see a one-line
"Your bouncer caught X" notification + a structured 403 the agent
can act on. The framing is "caught + here's how to allow if safe"
not "ERROR". See [claude-code.md](claude-code.md#first-run-wallpaper--what-to-expect)
for the cross-surface table.

## 1. Where to write the declaration

Add the fenced YAML codeblock tagged `iam-jit-config` to your repo's
`AGENTS.md`:

````markdown
# Agent rules for this project

## iam-jit setup

Run `iam_jit_setup_from_config` on session start.

```iam-jit-config
iam-jit:
  enabled: true
  posture: ambient
  bouncers:
    ibounce:
      enabled: true
      mode: discovery
      profile: auto
    kbouncer:
      enabled: when_kubeconfig_present
    dbounce:
      enabled: when_db_env_present
    gbounce:
      enabled: false
  improve: { enabled: false }
  notify_on_deny: true
```
````

OR as a standalone `.iam-jit.yaml` at the repo root.

## 2. How Codex reads it on session start

Wire the `iam-jit` MCP server in Codex's MCP config (path varies by
Codex install — check Codex docs for the canonical location of
`mcp_servers.json`):

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

Then add this instruction to `AGENTS.md`:

> On session start, call `iam_jit_setup_from_config` (no arguments).
> The tool auto-discovers the `iam-jit-config` block in this file or
> `.iam-jit.yaml` and starts the declared bouncers.

## 3. How to override / opt out

Same as Claude Code — set `iam-jit.enabled: false`.

## 4. 30-second smoke test

Same as [claude-code.md](claude-code.md#4-30-second-smoke-test).

## 5. Codex-specific notes

* The current Codex CLI ships limited MCP support; verify your install
  exposes `mcpServers` config before adopting Path A. Otherwise use
  Path B (operator pre-runs `iam-jit doctor apply-config`).
* `AGENTS.md` is the open-standard convention; the `iam-jit-config`
  codeblock tag is the same across CLAUDE.md / AGENTS.md /
  .cursorrules so a single declaration document can be cross-linked
  from multiple harness configs.
