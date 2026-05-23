# iam-jit ambient setup — per-harness recipes

Phase A of [[ambient-autonomous-protection]] (v1.1, tasks #397-#400).
The operator writes ONE declarative block; the agent reads it on
session start and calls `iam_jit_setup_from_config` to install + start
+ configure the bouncers. After that, the operator never reconfigures.

## The canonical declaration

```yaml
iam-jit:
  enabled: true
  posture: ambient
  bouncers:
    ibounce:
      enabled: true
      mode: discovery       # discovery | cooperative | strict
      profile: auto         # auto | <named profile>
    kbouncer:
      enabled: when_kubeconfig_present
      mode: discovery
    dbounce:
      enabled: when_db_env_present
    gbounce:
      enabled: false
  improve:                  # Phase B (#401) — accepted now, no-op until then
    enabled: false
  notify_on_deny: true
```

Validated against [`schemas/iam-jit-config.schema.json`](../../schemas/iam-jit-config.schema.json).

## Where to write it

You can put the declaration in ANY of the following — `iam-jit doctor
apply-config` (CLI) and `iam_jit_setup_from_config` (MCP) auto-discover
in this precedence order:

1. **Standalone `.iam-jit.yaml`** (preferred for orgs) at repo root —
   easy to commit per project or .gitignore for personal overrides.
2. **YAML codeblock in a context file** — fenced ` ```iam-jit-config`
   inside any of:
   * `CLAUDE.md` (Claude Code)
   * `AGENTS.md` (Codex / generic)
   * `.cursorrules` (Cursor)
   * `.devin/config.yaml` (Devin — when MCP is supported)

Per-harness short pages walk through the exact placement + smoke test:

* [claude-code.md](claude-code.md) — canonical (most detailed)
* [cursor.md](cursor.md)
* [codex.md](codex.md)
* [devin.md](devin.md)
* [custom-harness.md](custom-harness.md) — any MCP-capable agent

## Companion tools

The agent has these MCP tools available alongside
`iam_jit_setup_from_config`:

* `iam_jit_posture` — read current bouncer / role posture (the input
  to setup planning).
* `bounce_profile_allow` — add an allow rule when something legit got
  blocked (§A25 / [[easy-profile-extension-and-deny-visibility]]).
* `bounce_denies_recent` — query what recently got blocked (§A25).

Together these close the feedback loop: setup gets you running; posture
tells you what's running; denies_recent surfaces blocks;
profile_allow unblocks the legit ones.

## Honest behavior — what setup does NOT do

* **Does not restart a bouncer that's already running** — even if the
  config differs. Per [[creates-never-mutates]] the operator must stop
  it manually + re-run. (You'll get a warning explaining what differs.)
* **Does not auto-generate new profiles** — Phase A reuses whatever's
  installed; Phase B (#401) adds `iam_jit_improve_profile`.
* **Does not run as a system service** — Phase B (#403) adds `iam-jit
  autopilot start` for the always-on background daemon.
* **Does not silently skip `enabled: true` bouncers** — every
  conditional resolution is in the result (operator sees what each
  `when_X_present` evaluated to).

## Dry-run first

Always run with `--dry-run` first to see what setup will do:

```
$ iam-jit doctor apply-config --dry-run
iam-jit setup-from-config: DRY-RUN PLAN
  source: /path/to/.iam-jit.yaml
  status: ok

Conditional resolution:
  - ibounce: declared True (explicit)
  - kbouncer: when_kubeconfig_present → ~/.kube/config exists → enabled=True

Bouncers planned (dry-run; not executed):
  - ibounce on port 8767: /usr/local/bin/ibounce run --port 8767

Env vars the agent should set:
  export AWS_ENDPOINT_URL=http://127.0.0.1:8767

(dry-run — re-run without --dry-run to apply)
```
