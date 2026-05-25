# THIS-machine canary — dogfood operator runbook

The canary is the operator's own machine running iam-jit + one or more
bouncers continuously, redeploying from `origin/main` on each commit
(or on operator demand), capturing issues into a structured log that
the dogfood-window triage reads. It is the dress rehearsal that gates
public-launch readiness per `[[no-announce-until-founder-validates]]`.

This doc is the reference for `iam-jit canary --help` (it points here)
and for operators bringing up a fresh canary or joining one already
running.

## What the canary is

- **A real, long-running deploy.** One machine, real workload, real
  audit chain. Not a synthetic smoke test.
- **A redeploy mechanism.** `iam-jit canary update` performs the
  9-step flow from `[[canary-redeploys-on-every-update]]`: clean-tree
  check → fetch → pull → reinstall → version-check → graceful restart
  → post-update verify → audit-chain continuity → issue-log outcome
  (success OR failure with rollback).
- **An issue-capture surface.** `iam-jit canary file-issue` writes
  one structured row per operator observation into
  `~/.iam-jit/canary/issues.jsonl`. `iam-jit canary report` triages.
- **A monitoring surface.** `iam-jit canary monitor` aggregates the
  11 signals from `docs/MRR-5-MONITORING-RUNBOOK.md` across all
  running bouncers. `iam-jit canary verify-setup` (§A102) checks each
  bouncer matches operator intent (cmdline, healthz, mode).

## Data layout — `~/.iam-jit/canary/`

| File | Written by | Read by |
|------|-----------|---------|
| `status.json` | deploy script + `update` + bouncer lifecycle | `status` / `report` / `monitor` / `verify-setup` |
| `urls.md` | deploy script | `urls` |
| `issues.jsonl` | `file-issue` + `update` (rollback rows) | `report` |
| `notes.md` | operator (text editor) + `report` tail | `report` |
| `.iam-jit.yaml` | deploy script (operator intent) | `verify-setup` / `update` |

`status.json` carries: `canary_day`, `started_at`, `llm_mode`,
`open_issues_count`, `intervention_count_24h`, `denies_24h`,
`improvement_cycles`, `last_issue_ts`, per-bouncer `bouncers` /
`ports` / `pids` / `commits` / `daemon_args`.

## Subcommands

### `iam-jit canary status [--json]`

One-line per top-level field; per-bouncer `bouncers` / `ports` /
`commits`. Use this between report runs to check the current
canary day and refreshed dogfood metrics. `--json` emits the
raw `status.json` (after the best-effort dogfood-metrics refresh
per `docs/MRR-5-MONITORING-RUNBOOK.md` §M4) — agent-readable.

### `iam-jit canary urls`

Prints `urls.md` verbatim. Stable across restarts. Use this as
the canonical pointer set for the running bouncers + their mgmt
ports.

### `iam-jit canary report [--since 24h] [--json]`

Triaged digest. **Read this at session start** when you join the
canary. Shows: open issues by severity + category, recent 10
issues, last 15 lines of `notes.md`, status snapshot. `--since`
accepts `24h` / `7d` / `30m` / `60s` / `all`.

### `iam-jit canary file-issue --severity SEV --note STR [...]`

Append a structured operator observation. Required: `--severity`
(`crit` / `high` / `med` / `low`), `--note`. Optional:
`--category`, `--bouncer`, `--expected`, `--repro-hint`,
`--related-task` (e.g. `#507`). Returns the persisted JSON row
to stdout for piping into agent context.

### `iam-jit canary update [--watch] [--auto-deploy] [--interval 15m] [--dry-run]`

Runs the 9-step redeploy flow. Without flags: one-shot update on
the current `origin/main` HEAD.

`--watch` polls remote git for new commits on `--interval`. By
default `--watch` is **notify-only** per §A101 — new commits emit
a HIGH issue + stdout line; iam-jit does NOT pull / reinstall /
restart. Pass `--auto-deploy` in addition to `--watch` to restore
the pre-§A101 autopilot behavior. A WARN line is logged at
watch-loop start so the autopilot posture is visible in the
terminal.

`--dry-run` reports what would happen without mutating.

Note: `--watch` DOES contact the remote git host. The pre-§A101
"LOCAL only / no phone-home" help text was wrong (issue §A101).

### `iam-jit canary verify-setup [--json]`

Per `[[deliberate-feature-completion]]` §A102 — verifies each
running bouncer matches operator intent declared in
`~/.iam-jit/canary/.iam-jit.yaml` (falls back to `status.json`).

Checks: PID alive, cmdline matches recorded `daemon_args`,
`/healthz` returns 200, general-proxy mode (gbounce upstream is
empty string; ibounce cmdline lacks `--upstream`).

Exit code 0 if all green; non-zero if any check fails.

Catches calibration-drift bug #18 (smoke-test `--upstream` pin
leaking into daily-dev mode).

### `iam-jit canary monitor [--json] [--watch]`

§M1 composite single-pane-of-glass. Aggregates the 11 MRR-5
signals across all canary-running bouncers; emits color-coded
human output OR JSON; supports `--watch` for the founder's
dogfood-window terminal tab.

Closes the MRR-5 acceptance criterion that without this command
the operator must read source to know "is everything ok?".

## When to file an issue

Per `[[ibounce-honest-positioning]]`: file an issue when you
observe behavior that diverges from the documented expectation —
even if you have a working theory of the cause. The issue is
evidence; the cause is hypothesis. Examples:

- A bouncer denied something you expected it to allow (or vice
  versa). Use `--category` `denial` or `false-allow`.
- A CLI command returned exit 0 but the observable state did not
  match (silent-degradation pattern — see #618 #616 #604).
- A doc claim doesn't match the code (calibration drift — also
  surfaces as `[[scorer-is-ground-truth]]` violations).
- A redeploy succeeded but post-update verify shows drift from
  intent.

## Cross-references

- `docs/MRR-5-MONITORING-RUNBOOK.md` — the 11 monitoring signals
  the `monitor` subcommand aggregates
- `docs/MRR-4-HALT-CONDITIONS.md` — halt-condition catalog the
  CRIT thresholds cross-reference
- `docs/MRR-4-ROLLBACK-RUNBOOK.md` — per-halt recovery procedure
- `docs/MRR-4-UNINSTALL.md` — clean teardown
- `[[canary-redeploys-on-every-update]]` — the 9-step update flow
- `[[no-announce-until-founder-validates]]` — why the canary
  exists (gate on public-launch)
