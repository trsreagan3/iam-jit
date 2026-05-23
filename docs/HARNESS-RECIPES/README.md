# iam-jit ambient setup — per-harness recipes

Phase A of [[ambient-autonomous-protection]] (v1.1, tasks #397-#400).
The operator writes ONE declarative block; the agent reads it on
session start and calls `iam_jit_setup_from_config` to install + start
+ configure the bouncers. After that, the operator never reconfigures.

## What to expect day-to-day

> Your bouncer audits everything your agent does silently in the
> background. Most of the time you'll see nothing. When the bouncer
> catches something worth your attention you'll see a one-line
> notification (and the agent's request 403s) — categorized so you
> can scan high-signal first:
>
> * `(!) likely-adversarial` — investigate, do NOT just allow
> * `(?) ambiguous` — your call; usually a 5-second decision
> * `(*) likely-legit` — paste the suggested allow command if safe
>
> Most operators see fewer than one prompt per day after the first
> week of discovery. We're never silent about catches — the framing
> just leads with "your bouncer caught X" instead of "ERROR".

(The "fewer than one prompt per day" claim is calibrated per
`[[hit-rate-meaning]]` discipline — it's a target we measure post-launch,
not a guarantee.)

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
* `bounce_extract_permissions_from_audit` (Phase E §A58) — extract a
  structured permission set from a bouncer audit window.
* `iam_jit_resource_map` (Phase E §A59) — apply a declared resource
  mapping to translate scope (staging→prod, etc.).
* `iam_jit_request_role_from_synthesis` (Phase E §A60) — synthesis-
  aware role-request seam (REQUIRES evidence block per
  [[ibounce-honest-positioning]]).

Together these close the feedback loop: setup gets you running; posture
tells you what's running; denies_recent surfaces blocks;
profile_allow unblocks the legit ones; the Phase E trio
(extract / map / request) turns bouncer observation into
iam-jit role provisioning via agent synthesis — see
[bouncer-to-role-pattern.md](bouncer-to-role-pattern.md).

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
