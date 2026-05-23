# Claude Code — ambient iam-jit setup

This is the canonical recipe — the other harness pages are ports of
the same flow with harness-specific tweaks.

## First-run wallpaper — what to expect

> Your iam-jit bouncer will work silently in the background. Most of
> the time you'll never see it. When it catches something worth your
> attention, you'll see a one-line "Your bouncer caught X" notification
> + the agent's request will 403 with a structured payload it can act
> on. The friction is intentional (it's how we catch prompt injection)
> + the framing is "caught + here's how to allow if safe" not "ERROR".

Most operators see fewer than one prompt per day after the first
week of discovery (calibrated post-launch per `[[hit-rate-meaning]]`).
The framing is the same across surfaces:

| Surface | Lead text |
|---|---|
| CLI (`iam-jit denies recent`) | `Your bouncer caught N thing(s)...` |
| stderr notification (autopilot) | `[autopilot] (?) Your ibounce bouncer caught: ...` |
| Webhook (Slack/Discord) | `Your ibounce bouncer caught something.` |
| Agent 403 wire body | `caught_by_bouncer: "ibounce"` + classification |

## 1. Where to write the declaration

Add a fenced YAML codeblock tagged `iam-jit-config` to your repo's
`CLAUDE.md`:

````markdown
# Project notes for Claude

(... your usual CLAUDE.md content ...)

## iam-jit setup

On session start, run `iam_jit_setup_from_config` so the bouncers
declared below are running.

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
      mode: discovery
    dbounce:
      enabled: when_db_env_present
    gbounce:
      enabled: false
  improve:
    enabled: false
  notify_on_deny: true
```
````

OR put the same block at the repo root as `.iam-jit.yaml`:

```yaml
# .iam-jit.yaml
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

The standalone file wins over the codeblock when both are present
(operator intent is more explicit).

## 2. How Claude reads it on session start

Two paths:

### Path A — via MCP autorun (preferred)

Wire `iam_jit_setup_from_config` to autorun. Edit
`~/.claude/mcp_settings.json` (or your equivalent):

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

Then add this single line to the top of your `CLAUDE.md`:

> On session start, call `iam_jit_setup_from_config` with no
> arguments — it will auto-discover the `iam-jit-config` block below
> (or the `.iam-jit.yaml`) and start the bouncers I declared.

Claude will pick this up on the first turn and run the tool. The
result lists the env vars Claude should propagate to its subprocess
calls (e.g., when invoking `aws s3 ls`, `kubectl get pods`, etc.).

### Path B — via CLI before the session

If you'd rather Claude not run setup itself, run it manually:

```bash
iam-jit doctor apply-config       # starts the bouncers
iam-jit posture                   # confirm
```

Now Claude can rely on the bouncers being up + use
`iam_jit_posture` to verify.

## 3. How to override / opt out

* **Disable everything**: set `iam-jit.enabled: false` in the
  declaration. `iam_jit_setup_from_config` becomes a no-op.
* **Disable one bouncer**: set its `enabled: false`.
* **Skip the autorun**: remove the instruction from CLAUDE.md +
  delete the MCP server entry. Claude won't call the tool.

## 4. 30-second smoke test

```bash
# In a fresh directory
mkdir /tmp/ambient-smoke && cd /tmp/ambient-smoke

cat > .iam-jit.yaml <<'EOF'
iam-jit:
  enabled: true
  posture: ambient
  bouncers:
    ibounce: { enabled: true, mode: discovery, profile: auto }
    kbouncer: { enabled: false }
    dbounce: { enabled: false }
    gbounce: { enabled: false }
  improve: { enabled: false }
  notify_on_deny: true
EOF

# Dry-run first
iam-jit doctor apply-config --dry-run

# Real run
iam-jit doctor apply-config

# Verify
iam-jit posture
```

Expected: `iam-jit posture` shows `ibounce: RUNNING on 127.0.0.1:8767`
+ `mode: discovery` after the apply.

## 5. Closing the feedback loop

When Claude (or you) sees a deny:

```bash
iam-jit denies recent           # what got blocked
iam-jit profile allow --target arn:... --action s3:GetObject \
  --reason "agent reads staging cache"
```

Or via MCP, Claude calls `bounce_denies_recent` + `bounce_profile_allow`
directly. The agent-self-grant safety rail (default ON) queues
agent-issued `bounce_profile_allow` for operator approval rather
than auto-applying.

See [`docs/IBOUNCE.md`](../IBOUNCE.md) for the full ibounce reference.

## 6. Using bouncer activity to provision iam-jit roles

Phase E pattern — agent reads bouncer audit, synthesises a role
request through iam-jit. Canonical use case: *"I just did staging
work; generate the equivalent role for prod."* See
[bouncer-to-role-pattern.md](bouncer-to-role-pattern.md) for the
canonical conversation + the REQUIRED evidence-block discipline.
