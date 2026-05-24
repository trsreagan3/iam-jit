# Linux-support audit — 2026-05-24

Audit of `iam-jit` Python code (focus: `src/iam_jit/cli_canary.py`,
`src/iam_jit/bouncer/proxy.py`, `src/iam_jit/bouncer/audit_export/`,
`src/iam_jit/autopilot/`, `src/iam_jit/ambient_config/`) for
macOS-only assumptions that would break on Linux (CI / Docker
contexts / future Linux work machines).

Companion to issue `#485` (first-60-seconds smoke on clean machines).
This audit specifically covers Linux containerized install + the
canary verify-setup / restart paths the operator runs daily.

## Methodology

Searched for the standard macOS-vs-Linux divergence patterns:

1. `lsof` output format (BSD vs GNU) — usually compatible with the
   flags we use, but `lsof` is often absent in slim Linux containers.
2. `ps -p PID -o args=` vs `ps -p PID -o cmd=` (BSD vs Linux).
3. `/proc/{pid}/cmdline`, `/proc/{pid}/status`, `/proc/{pid}/exe` —
   Linux-only; macOS has no `/proc`.
4. `subprocess.Popen(start_new_session=True)` — works on both.
5. Signal handling — POSIX-portable.
6. `launchd` plist vs `systemd` unit generation — would be Mac-only
   if present in the install path.
7. File-path case sensitivity (macOS case-insensitive by default;
   Linux case-sensitive).
8. `find -E` (BSD) vs `find -regextype posix-extended` (GNU).
9. `sed -i ''` (BSD/macOS) vs `sed -i` (GNU/Linux).
10. `readlink -f` (GNU) vs `readlink` (BSD).
11. `ifconfig` vs `ip` for networking introspection.
12. `$SHELL` defaults (zsh on modern macOS, bash on most Linux).
13. `sudo` differences.
14. Homebrew assumptions (`/opt/homebrew`, `/usr/local/Cellar`).

## Findings table

| # | Site | Severity | What | Status |
|---|------|----------|------|--------|
| 1 | `src/iam_jit/cli_canary.py:1226-1267` (`_restart_bouncers`) | **HIGH** | `lsof` invocation. Works on macOS + Linux when present, BUT `lsof` is NOT installed in slim Linux containers (`python:3.11-slim`, `alpine`). The flow falls back to silent no-op (`check=False`), so a canary `update` on a Linux container without `lsof` would skip SIGTERM + relaunch a SECOND bouncer process (port-bind would then fail). | **FIX**: prefer recorded PIDs from `status.json` (which the verify-setup path already trusts); use `socket.connect_ex` for the wait-for-port-release loop (no external dep). |
| 2 | `src/iam_jit/cli_canary.py:372-400` (`_process_cmdline`) | LOW | Already cross-platform. Linux: `/proc/{pid}/cmdline`. macOS fallback: `ps -p PID -o args=`. Both produce parseable argv. | No change. |
| 3 | `src/iam_jit/bouncer/audit_export/agent_context.py:484-540` (`_ppid`, `_exe_name`) | LOW | Already cross-platform: tries `/proc/{pid}/status` and `/proc/{pid}/exe` first; falls back to `ps -o ppid=` / `ps -o comm=` on BSD. | No change. |
| 4 | `src/iam_jit/cli.py:967-983`, `src/iam_jit/bouncer_cli.py:5784-5800`, `src/iam_jit/bouncer/config_io.py:385-395` (Claude Desktop config path) | LOW | Already platform-aware: Darwin → `~/Library/...`, Windows → `%APPDATA%/...`, else → `~/.config/...`. | No change. |
| 5 | `src/iam_jit/bouncer/proxy.py:4836` (SIGTERM handler comment) | LOW | `loop.add_signal_handler(SIGTERM, ...)` is POSIX-portable. | No change. |
| 6 | `src/iam_jit/autopilot/daemon.py:1350-1370` (detached spawn) | LOW | `subprocess.Popen(start_new_session=True, close_fds=True)` is POSIX-portable. | No change. |
| 7 | `src/iam_jit/ambient_config/setup.py:519-538` (`_start_bouncer` Popen) | LOW | Same shape as autopilot — POSIX-portable. | No change. |
| 8 | `src/iam_jit/threat_feed/signing.py:376` (cosign invocation) | LOW | `cosign` is itself cross-platform; the subprocess call is non-shell. | No change. |
| 9 | `src/iam_jit/enterprise/review.py:92-110` (editor invocation) | LOW | Reads `$EDITOR`, falls back to `vi`. `vi` ships on every POSIX system. | No change. |
| 10 | `src/iam_jit/dynamic_denies/store.py:290,398,428,446` (permissions enforcement) | LOW | Already gated by `platform.system() != "Windows"` for the chmod / stat checks. | No change. |
| 11 | Documentation refs in `docs/HARDENING-AGAINST-PROMPT-INJECTION.md` (launchd plist) | LOW | Doc is explicitly "macOS launchd plist" section + a separate "systemd" section follows in the same doc. Not an install-path assumption. | No change. |
| 12 | Doc examples in `docs/GETTING-STARTED.md` (`brew install python@3.12 ...`) | LOW | Examples; not enforced. Linux users are expected to use their distro's package manager / pyenv. Could add a Linux-specific quickstart block but not launch-blocking. | Out of scope (post-launch doc enhancement). |
| 13 | `pyproject.toml` `requires-python = ">=3.10"` | n/a | Python 3.10+ ships on every modern Linux distro (Ubuntu 22.04+, Debian 12+, RHEL 9+, Alpine 3.18+). | No change. |
| 14 | Go bouncers (`gbounce`, `kbouncer`, `dbounce`) | n/a | Go is cross-platform by default. `gbounce` Dockerfile uses `golang:1.26-alpine`. Note: `go.mod` declares `go 1.26.0`, so the brief's suggested `golang:1.22` image would NOT work — use `golang:1.26` or set `GOTOOLCHAIN=auto`. | Documented gotcha (this doc + container-smoke section). |
| 15 | `lsof` in `_restart_bouncers` wait-for-port loop (finding #1 above, second use site) | HIGH | Same root cause as #1. The wait-for-release loop polls via `lsof`; if `lsof` is missing the loop exits early (empty stdout) and we relaunch on a port that's potentially still bound. | **FIX** as part of #1: pure-Python `socket.connect_ex` check on `127.0.0.1:PORT`. |

## CRIT count: 0
## HIGH count: 2 (rolled up into one fix — see #1 + #15)

The headline gap is that `iam-jit canary update` quietly degrades on
Linux containers without `lsof`. Daily-use `iam-jit canary
verify-setup`, `iam-jit canary status`, and the bouncer install
flow are already Linux-clean.

## Phase 2 — fix plan

Single change to `src/iam_jit/cli_canary.py`:

1. `_restart_bouncers` — replace the two `lsof` invocations with:
   - For PID discovery: trust the `pids` field in `status.json`
     (the same source `verify-setup` reads). Fall back to `lsof`
     ONLY if `pids` is empty (back-compat) and `lsof` is present;
     otherwise emit a clear error so the operator knows to install
     `lsof` (rare) or re-deploy the canary (which repopulates
     `status.json`).
   - For port-release polling: use `socket.create_connection` /
     `socket.connect_ex` to probe `127.0.0.1:PORT` — pure-stdlib,
     no external command.

State-verification per `docs/CONTRIBUTING.md`: the existing healthz
gate in `_relaunch_bouncer` already verifies the new process is
serving traffic, so the success path is observable.

## Phase 3 — container smoke

See section at end of this doc + commit history.

### Python `iam-jit` install in `python:3.11-slim`

PASS. `pip install -e .` succeeds; `iam-jit --version` reports
`1.0.0`; `iam-jit canary --help` lists subcommands; `iam-jit canary
verify-setup` exits non-zero with the expected message
"No canary status yet — run the deploy script first." (no false
positive; correct behavior on a clean container).

### Go `gbounce` install in `golang:1.26-alpine`

PASS. `go install ./...` succeeds; `gbounce --version` reports the
expected version string.

NOTE: The brief mentioned `golang:1.22` but `gbounce` `go.mod`
declares `go 1.26.0`. Either use `golang:1.26-alpine` (matches the
project's Dockerfile) or set `GOTOOLCHAIN=auto` to let `go` auto-
download the right toolchain.

### Container-mode bouncer start + general-proxy verify

PASS. `ibounce` + `gbounce` both start as detached subprocesses,
bind to their respective ports, and respond to `/healthz` with
HTTP 200 in general-proxy mode.

## Linux-specific install gotchas (for future docs)

1. **`lsof` not installed by default** in `python:3.11-slim`,
   `python:3.12-alpine`, or other minimal Linux containers. The
   `iam-jit canary update` flow needs it ONLY in the back-compat
   path (when `status.json` lacks recorded PIDs); post-fix the
   default path is `lsof`-free.
2. **Go toolchain version mismatch.** The Bounce-suite Go modules
   declare `go 1.26.0`. Older `golang:1.2x` images either need
   `GOTOOLCHAIN=auto` (the default since Go 1.21) or should be
   replaced with `golang:1.26-alpine`.
3. **Case-sensitive filesystem.** Linux filesystems (ext4, xfs,
   btrfs) are case-sensitive by default. macOS HFS+/APFS is
   case-insensitive. The codebase already uses consistent
   lowercase + underscore names; no observed case-collision risk.
4. **`/tmp` cleanup semantics.** Linux `systemd-tmpfiles` may
   sweep `/tmp` on a schedule; macOS `launchd` is more
   conservative. The code uses `tempfile.TemporaryDirectory()`
   contexts so this doesn't matter for in-process work; only
   matters if an operator parks something under `/tmp/` between
   sessions.
5. **No `~/Library/Application Support/Claude/...`.** The MCP
   install commands already detect Linux and write to
   `~/.config/Claude/...`. No action needed.

## Out of scope (per brief)

- Bucket D scorer code (`[[scorer-is-ground-truth]]`).
- Linux-only features (e.g., systemd unit file generation) —
  defer to v1.1 if there's demand.
- Go bouncer source — Go is mostly portable; the only gotcha is
  the `golang:1.26` toolchain version (documented above).
- Marketing copy / doc-site updates per `[[tech-before-marketing]]`.

## Sign-off

Audit + fix combined makes `iam-jit` Linux-clean for the install
+ daily-dev + canary-verify path. Containerized smoke (Docker
on colima Linux backend) verifies the end-to-end flow.
