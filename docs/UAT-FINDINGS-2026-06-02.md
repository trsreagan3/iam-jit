# UAT Findings — 2026-06-02

Task: #743 — Cursor / Codex / Devin install-bootstrap parity

Independent UAT agent: Claude Sonnet 4.6

---

## Summary

PR #23 wired bouncer env vars (`AWS_ENDPOINT_URL`, `HTTP_PROXY`, `HTTPS_PROXY`)
into Claude Code via `~/.claude/settings.json`. This UAT verified that the same
routing vars reach Cursor and Codex tool subprocesses via the MCP server's `env`
block, and produced an honest recipe for Devin (cloud agent, no local config).

---

## Findings

### CRIT-1 (FIXED in this PR): Cursor `install-cursor` missing routing env vars

**Status:** FIXED

**Before:** `ibounce mcp install-cursor` wrote `IBOUNCE_AGENT_NAME` and
`IBOUNCE_AGENT_SESSION_ID` into `~/.cursor/mcp.json` but did NOT include
`AWS_ENDPOINT_URL`, `HTTP_PROXY`, or `HTTPS_PROXY`. Cursor inherits env vars
for tool subprocesses exclusively from the MCP server's `env` block — there
is no separate `settings.json` equivalent. So AWS SDK calls from Cursor's
tool subprocesses bypassed ibounce entirely.

**After:** `install-cursor` now calls `_build_bouncer_env_vars_for_mcp()` to
detect live bouncers and merges `AWS_ENDPOINT_URL` + `HTTP_PROXY` +
`HTTPS_PROXY` into the written MCP server env block. Routing env vars appear
alongside attribution hints in `~/.cursor/mcp.json`.

**Parity check:** `TestInstallCursorCli::test_install_cursor_parity_with_claude_code`
asserts that all three routing vars present in Cursor config = PR #23 Claude Code.

### CRIT-2 (FIXED in this PR): Codex `install-codex` missing routing env vars

**Status:** FIXED

**Before:** `ibounce mcp install-codex --path PATH` wrote the MCP entry without
routing vars. The printed snippet (no `--path`) also lacked routing vars.

**After:** Both the `--path` write path and the snippet-print path now include
`AWS_ENDPOINT_URL` + `HTTP_PROXY` + `HTTPS_PROXY` when bouncers are running.
`--no-env-block` suppresses this for operators managing env vars separately.

### INFO-1: `install-devin` command did not exist

**Status:** ADDED in this PR

**Before:** `ibounce mcp --help` mentioned Devin in the group description but
had no `install-devin` subcommand. `show-config` didn't reference Devin.

**After:** `ibounce mcp install-devin` added. It prints PATH A (MCP server via
Devin UI) and PATH B (pre-session operator setup) with the correct env vars,
detects running bouncers locally and shows their actual ports, and surfaces the
Cognition sandbox networking limitation honestly.

### INFO-2: `docs/MCP-RECIPES.md` Cursor/Codex/Devin sections shallow

**Status:** UPDATED in this PR

**Before:** The Cursor section described the MCP install command but said
nothing about the env-block gap. The Devin section told operators to use
`install-cursor --path <devin-config>` (wrong — Devin is a cloud agent with
no local config). The Codex section described TOML but didn't mention the
env block write behavior.

**After:** All three sections updated to PR #23 depth — env-block behavior,
the why, honest limitation notices, verify steps, and skip flags.

---

## Test Results

26 tests in `tests/integration/test_harness_parity_cursor_codex_devin.py`:

| Category | Count | Status |
|---|---|---|
| Unit: `_ibounce_mcp_config_dict` extra_env | 4 | PASS |
| Unit: `_merge_ibounce_entry` extra_env | 3 | PASS |
| Unit: `install-cursor` CLI surface | 4 | PASS |
| Unit: `install-codex` CLI surface | 3 | PASS |
| Unit: `install-devin` CLI surface | 5 | PASS |
| Unit: `_build_bouncer_env_vars_for_mcp` | 4 | PASS |
| Live E2E: Cursor install → subprocess → bouncer ticks | 1 | PASS |
| Live E2E: Codex install → subprocess → bouncer ticks | 1 | PASS |
| Live E2E: Devin PATH B env → subprocess → bouncer ticks | 1 | PASS |

**All 26 pass** (live E2E require ibounce on :8767; skipped when not running).

Pre-existing failures in `test_install_bootstrap_e2e.py` and
`test_pr23_uat_INDEPENDENT.py` (5 tests) are NOT regressions from this PR —
they fail with HTTP 421 because `urllib.request.urlopen` in those tests
respects the `HTTP_PROXY` env var set by gbounce wiring on the founder's
machine. Those tests need the same `ProxyHandler({})` fix applied to our
`_ibounce_decisions_count()` helper.

---

## Architecture Notes

### Why Cursor/Codex take env vars in the MCP server env block

Claude Code has `~/.claude/settings.json` with an `env` block that Claude
Code merges into every tool subprocess env at session start — a process-wide
injection point that means routing vars written once cascade to ALL tool calls.

Cursor has no equivalent settings file. The MCP server's `env` block in
`~/.cursor/mcp.json` is the ONLY per-server env-injection point. Vars written
there are inherited by the spawned MCP server process and any subprocesses it
spawns (tool calls). This is why the fix goes into the MCP server's `env`
block rather than a separate file.

### Why Devin is different

Devin runs in Cognition's cloud sandbox — a different machine from the
developer's laptop. ibounce on `127.0.0.1` is not reachable from Devin's
sandbox. The correct wiring is:
1. Run bouncers on a cloud host Devin can reach (not loopback).
2. Set `AWS_ENDPOINT_URL` + proxy vars in Devin's task environment (Devin UI).

This is not a limitation of ibounce — it's an inherent property of cloud-hosted
agents. ibounce never requires root or a transparent proxy; task env vars are
the correct injection point.

### `--no-env-block` flag parity

Both `install-cursor` and `install-codex` now have `--no-env-block` parity with
`install-claude-code`. Operators who manage env vars separately (e.g. via
`.envrc`, CI env injection, or system profile) can suppress the auto-write.

---

Last reviewed: 2026-06-02.
