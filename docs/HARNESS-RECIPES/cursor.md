# Cursor — ambient iam-jit setup

Port of [claude-code.md](claude-code.md). Same MCP tool, same
declaration shape; Cursor reads it from `.cursorrules` instead of
`CLAUDE.md`.

## First-run wallpaper

Your iam-jit bouncer audits Cursor's tool calls silently. When it
catches something worth your attention you'll see a one-line
"Your bouncer caught X" notification + a structured 403 the agent
can act on. The framing is "caught + here's how to allow if safe"
not "ERROR". See [claude-code.md](claude-code.md#first-run-wallpaper--what-to-expect)
for the cross-surface table.

## 1. Where to write the declaration

Add a fenced YAML codeblock tagged `iam-jit-config` to your repo's
`.cursorrules` (or `.cursor/rules.md` if you use the directory form):

````
# Cursor agent rules for this project

## iam-jit setup

On session start, run `iam_jit_setup_from_config` so the bouncers
below are running.

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

OR as a standalone `.iam-jit.yaml` at the repo root (preferred for
multi-harness teams — the same file feeds Claude Code + Cursor + the
CLI).

## 2. How Cursor reads it on session start

Cursor's MCP support is the path. Configure the `iam-jit` server in
Cursor's MCP settings (Settings > MCP Servers):

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

Then add this line to your `.cursorrules`:

> On session start, call the `iam_jit_setup_from_config` MCP tool
> (no arguments). It will auto-discover the `iam-jit-config` block
> in this file or `.iam-jit.yaml` and start the declared bouncers.

## 3. How to override / opt out

Same as Claude Code — set `iam-jit.enabled: false` to no-op the setup,
or remove the MCP server entry from your Cursor settings.

## 4. 30-second smoke test

Same as [claude-code.md](claude-code.md#4-30-second-smoke-test). The
CLI surface is identical:

```bash
iam-jit doctor apply-config --dry-run
iam-jit doctor apply-config
iam-jit posture
```

## 5. Cursor-specific notes

* Cursor's `.cursorrules` is read on every chat session; placing the
  setup instruction here means the agent re-validates on every fresh
  conversation (cheap — `iam_jit_setup_from_config` short-circuits
  when bouncers are already running).
* Cursor's "Composer Agent" mode honors MCP tools the same way Chat
  does; the recipe works in both surfaces.
