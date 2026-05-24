# MRR-4 — Halt-condition catalog (2026-05-24)

Phase 4 of the Mission Readiness Review (`[[mrr-flight-readiness-program]]`).
Companion to:

- [`MRR-1-USE-CASE-AUDIT-2026-05-24.md`](MRR-1-USE-CASE-AUDIT-2026-05-24.md) — surfaces UC-20 (load-bearing
  partial-install rollback) and #525 (canary update bug shape)
- [`MRR-4-ROLLBACK-RUNBOOK.md`](MRR-4-ROLLBACK-RUNBOOK.md) — per halt condition: recovery procedure
- [`MRR-4-UNINSTALL.md`](MRR-4-UNINSTALL.md) — clean uninstall + tested smoke

Per founder direction 2026-05-24 ("space shuttle launch" discipline): we pre-declare
the halt conditions BEFORE deploy day. When one fires, the operator (or agent) STOPs
+ consults the rollback runbook BEFORE touching anything else. Halt-on-anomaly is the
shuttle-launch discipline — silent-degradation is not.

Per `[[ibounce-honest-positioning]]` — this catalog is honest about which conditions
are **detected today** vs **must be detected by the operator manually** (= MRR-2 / MRR-5
follow-up work).

## How to use this catalog

1. Operator (or agent) hits unexpected behavior during install / update / use.
2. Match the observation to one of the 4 halt-condition categories below.
3. Cross-reference the row's "Detection command" to confirm.
4. Follow the rollback procedure in [`MRR-4-ROLLBACK-RUNBOOK.md`](MRR-4-ROLLBACK-RUNBOOK.md).
5. After rollback: file an `issues.jsonl` entry (CRIT/HIGH) so the canary-loop catches
   the pattern. Per `[[canary-redeploys-on-every-update]]` the canary log is the
   source of truth for update-mechanism failures.

## Category A — Pre-deploy halt conditions

Fire BEFORE any iam-jit / bouncer process starts. Triggered while running
`iam-jit canary deploy`, `iam_jit_setup_from_config` (UC-20), or the
`scripts/deploy-canary.sh` bootstrap.

| # | Condition | What the operator sees | Detection command | Halt action |
|---|---|---|---|---|
| A1 | Disk full at install time | `pip install` fails with `OSError: [Errno 28] No space left`; or `go install` fails with `write: no space left on device` | `df -h /Users/$USER` (macOS) / `df -h ~` (Linux) — confirm <500MB free | STOP install. Free disk to ≥1GB. Re-run. Do NOT partial-install — leaves orphan venv. |
| A2 | Required port already in use (7401 ibounce / 7402 gbounce / 7412 gbounce-mgmt / 8767 ibounce-mgmt) | `bouncer/proxy.py` startup raises `OSError: [Errno 48] Address already in use` | `lsof -nP -iTCP:7401 -sTCP:LISTEN` (macOS); `ss -ltnp 'sport = :7401'` (Linux) | STOP. Either: (a) kill the conflicting process if it's an old bouncer (see RB-A2); (b) re-deploy with `--port` override. Do NOT force-bind. |
| A3 | Python version incompatible (`<3.10` per `pyproject.toml requires-python`) | `pip install -e .` fails with `ERROR: Package 'iam-jit' requires a different Python: ...` | `python3 --version` — confirm ≥3.10 | STOP. Install Python 3.10+. Re-run. |
| A4 | Missing required system dep | `subprocess` calls fail; common: `git`, `curl`, `sqlite3` shim (only optional), `cosign` (only if threat-feed signing) | `command -v git curl` — both should exist | STOP. Install missing dep via package manager. Re-run. |
| A5 | Existing iam-jit install detected (potential conflict) | `~/.iam-jit/` already exists; venv has different Python version OR bouncer process is live | `ls ~/.iam-jit/canary/status.json && cat ~/.iam-jit/canary/status.json \| jq .pids` | STOP. Decide: upgrade (RB-A5a) vs fresh-install (RB-A5b). Never silently overwrite — UC-20 partial-install territory. |
| A6 | Network unreachable during dependency fetch | `pip install` hangs / fails with `WARNING: Retrying ... Could not fetch URL`; `go install` fails with `dial tcp: lookup ... no such host` | `curl -fsSI https://pypi.org/ \| head -1` returns 200 OK | STOP. Confirm network. If air-gapped: pre-download wheels per `docs/AIR-GAPPED.md` (TBD MRR-6). |
| A7 | `.iam-jit.yaml` schema-invalid (ambient config) | `iam_jit_setup_from_config` returns `error: validation_failed` with field list | `iam-jit doctor apply-config --config /path/to/.iam-jit.yaml --dry-run` | STOP. Fix YAML per error fields. Do not run real apply with broken config. |
| A8 | Git repo dirty (canary update only) | `iam-jit canary update` fails: `iam-roles has uncommitted changes — refusing to pull` | `git -C /Users/$USER/repos/iam-roles status --porcelain` — must be empty | STOP. Commit / stash uncommitted changes per `[[push-policy-public-repo]]` (scan diff for secrets first). Re-run update. |
| A9 | Go toolchain absent (gbounce / kbounce / dbounce install) | `go install ./...` reports `command not found: go` | `command -v go && go version` — both succeed | STOP if any Go bouncer is in scope. Install Go ≥1.22. Re-run. |

**Reality check**: A1 / A3 / A4 / A6 / A9 are detected today by the install commands
themselves (pip / go / shell builtin). A2 / A5 / A7 / A8 are detected by iam-jit code
paths (`cli_canary.py:_do_one_update`, `ambient_config/setup.py`, `bouncer/proxy.py`
startup). The detection-command column above is what the operator runs MANUALLY to
confirm a halt — none of these run pre-flight without the operator initiating them.
**Gap** (filed as MRR-6 follow-up): no `iam-jit doctor preflight` command that runs A1..A9
as a single bundle before install. Today the operator self-verifies.

## Category B — During-deploy halt conditions

Fire DURING install — between `pip install -e .` and bouncers reaching healthy
state. UC-20 (partial-install) lives entirely in this category — most rollback
debt is here.

| # | Condition | What the operator sees | Detection command | Halt action |
|---|---|---|---|---|
| B1 | Bouncer startup fails (config-parse) | bouncer process exits within 5s; `canary/ibounce.log` shows `pydantic.ValidationError` or `yaml.YAMLError` | `tail -20 ~/.iam-jit/canary/ibounce.log` | STOP. Fix config (typically `~/.iam-jit/bouncer/profiles.yaml` or `~/.iam-jit/canary/.iam-jit.yaml`). Restart per RB-B1. |
| B2 | `/healthz` never reaches 200 within 30s | `cli_canary.py:_wait_for_health` times out + retries; ibounce shows started but unhealthy | `curl -fsS http://127.0.0.1:7401/healthz` returns non-200 | STOP. Inspect logs (RB-B2). Common: SQLite locked by stale process; port-binding race; missing env var. |
| B3 | Audit chain initialization fails | `bouncer/audit_export/` raises `ChainInitError` on cold-start; bouncer crashes | `tail -30 ~/.iam-jit/canary/ibounce.log \| grep -i 'chain\|audit'` | STOP. Backup audit state per RB-B3, then either restore prior backup OR re-init chain (data-loss risk acknowledged). |
| B4 | Permission denied on `~/.iam-jit/` | `OSError: [Errno 13] Permission denied: '/Users/X/.iam-jit/bouncer/state.db'` | `ls -ld ~/.iam-jit ~/.iam-jit/bouncer; stat -f '%Su %A' ~/.iam-jit` (macOS) | STOP. Confirm ownership: should be `$USER`, mode `700`. Fix with `chown -R $USER ~/.iam-jit && chmod -R u+rwX ~/.iam-jit`. |
| B5 | Anomaly baseline DB can't open | `anomaly-baseline.db` raises `sqlite3.DatabaseError: file is not a database`; bouncer continues (advisory feature) but anomaly detection inactive | `sqlite3 ~/.iam-jit/anomaly-baseline.db '.schema'` errors | DEGRADED, not halt. Anomaly detection optional (Phase H ibounce-only). Reset baseline per RB-B5 if needed. |
| B6 | `iam_jit_setup_from_config` partial-install (UC-20, **LOAD-BEARING**) | Some bouncers installed + started; others failed mid-install; state is mixed | `cat ~/.iam-jit/canary/status.json \| jq '.pids'` — count vs declared bouncers in `.iam-jit.yaml` | **STOP — DO NOT RE-RUN.** Partial-install rollback per RB-B6. This is the UC-20 gap; rollback procedure exists but is operator-driven today. |
| B7 | Wheel build failure (e.g. missing C compiler for a transitive C-extension dep) | `pip install -e .` fails compiling `cryptography` / `aiohttp` / etc. | `pip install -e . 2>&1 \| tail -20` | STOP. Install build deps OR install the wheel from PyPI (`pip install --only-binary=:all: <wheel>`). Re-run. |
| B8 | `go install` produces binary but it crashes on first launch | Go binary at `~/go/bin/gbounce` exists; `gbounce --version` segfaults / panics | `~/go/bin/gbounce --version 2>&1 \| head -5` | STOP. Likely Go version mismatch or stale `go.sum`. RB-B8: re-build with `go install -trimpath ./...`. |

**Reality check**: B1..B4, B6 are *detected by the operator after the fact* — neither
the deploy script nor `iam_jit_setup_from_config` self-checks the full bouncer-lifecycle
in one command. B5 is degraded-not-halt. B6 is the UC-20 load-bearing case from MRR-1.
**Gap** (filed as MRR-5 follow-up): `iam-jit canary verify-setup --deep` should run
B1..B6 verifications post-install + return structured pass/fail.

## Category C — Post-deploy halt conditions

Fire AFTER successful deploy, during daily use. Per the Phase F + Phase H + #525 design.

| # | Condition | What the operator sees | Detection command | Halt action |
|---|---|---|---|---|
| C1 | Disk pressure CRITICAL (Phase F circuit breaker) | bouncer's audit-export pauses; structured log: `disk_pressure_circuit_breaker_tripped` | `df -h ~/.iam-jit` — confirm `<5%` free | HALT writes. Per RB-C1: ship audit to SIEM, truncate retained logs, or migrate `~/.iam-jit` to bigger volume. |
| C2 | Audit chain break detected | `iam-jit audit verify` reports `chain_broken_at: <seq>` | `iam-jit audit verify --since 24h` returns non-zero exit | HALT (data integrity). Per RB-C2: snapshot DB, file CRIT issue, investigate before further use. Per `[[creates-never-mutates]]` rollback never modifies the broken chain — preserves forensic state. |
| C3 | Bouncer process death (any of 4) | `iam-jit canary status` shows missing PID; `/healthz` unreachable | `iam-jit canary status \| jq '.pids'` shows null entry; OR `ps -p <pid>` returns no row | HALT routing through that bouncer. Per RB-C3: inspect last 100 lines of bouncer log; restart with `_restart_bouncers`. If crashes within 60s of restart: file CRIT + don't retry. |
| C4 | `/healthz` reports degraded | bouncer returns 200 with `{"status": "degraded", "reasons": [...]}` | `curl -fsS http://127.0.0.1:7401/healthz \| jq .status` | DO NOT halt all routing; treat as advisory. Inspect `reasons` array. Common: SQLite WAL too large, audit-export backlog. |
| C5 | Manifest signature verification fails (compliance-critical) | profile-install / threat-feed apply reports `signature_verification_failed`; per `[[signed-audit-receipts-v11]]` Ed25519 chain check | check `iam-jit logs tail \| grep signature_verification` for recent failures | **HALT.** Do not accept the unsigned/wrong-signed payload. Per RB-C5 the rollback restores the prior-valid signed state. |
| C6 | Threat-feed signature verification fails | `threat_feed/applier` rejects feed; bouncer keeps prior denies; per `[[threat-feed]]` design | `iam-jit threat-feed status` — confirm last-successful timestamp + last error | DO NOT auto-revert prior denies (they're still valid). Per RB-C6: investigate publisher / key state; if compromised, follow incident-response. |
| C7 | LLM cost-cap breach (per-account or global) | autopilot logs `llm_budget_exhausted`; agent-mediated flows fail with structured error | `iam-jit autopilot status \| jq .llm_spend_24h` | DEGRADED-not-halt. Bouncers fall back to deterministic-only. Per RB-C7: top up budget OR confirm no-LLM ops is acceptable for the deploy window. |
| C8 | SQLite database corruption | `state.db` returns `database disk image is malformed`; bouncer crash-loops | `sqlite3 ~/.iam-jit/bouncer/state.db 'PRAGMA integrity_check;'` returns non-`ok` | HALT bouncer. Per RB-C8: restore from `ibounce backup` (#279) or recreate per Phase F retention policy. |

## Category D — Update halt conditions

Fire during `iam-jit canary update` (#525 / §A102 path). Per
`[[canary-redeploys-on-every-update]]`: the update mechanism IS a tested feature.

| # | Condition | What the operator sees | Detection command | Halt action |
|---|---|---|---|---|
| D1 | `git pull` shows uncommitted local changes | `iam-jit canary update` fails: `iam-roles has uncommitted changes — refusing to pull` | `git -C ~/repos/iam-roles status --porcelain` | STOP (see A8). Commit / stash then re-run. |
| D2 | `pip install -e .` fails during update | `_do_one_update` calls `_fail` with `pip install -e . failed:`; issues.jsonl `category: update_failure`; rollback attempts `git checkout <old_sha>` | `iam-jit canary report --recent` shows `category: update_failure` | Rollback initiated automatically per `_fail` (see `cli_canary.py:1206`). Per RB-D2 verify bouncers are still on OLD sha + restart cleanly. |
| D3 | `go install` fails during update | `_do_one_update` `_fail` with `go install ./... failed:`; same rollback path | Same as D2 | Same as D2 + verify `~/go/bin/gbounce --version` matches old sha. |
| D4 | Version-stamp mismatch (constant didn't bump with release) | bouncer reports version != commit-SHA-just-installed | `iam-jit canary verify-setup` (TBD MRR-5) OR `ibounce --version` vs `git -C ~/repos/iam-roles rev-parse HEAD` | DEGRADED-not-halt. File LOW issue (auto-categorized `calibration_drift`); update proceeds. Per `[[update-release-strategy]]` semver discipline. |
| D5 | Bouncer fails to restart after update | `_restart_bouncers` returns `(False, msg)`; `_fail` invoked; bouncer is DOWN | `iam-jit canary status \| jq .pids` shows null OR `/healthz` unreachable | **HALT.** Rollback attempted automatically (git checkout old sha) but bouncer is NOT relaunched on old sha. Per RB-D5: manually `pip install -e .` against the rolled-back code AND restart bouncer. |
| D6 | Update breaks SQLite schema (data-loss risk) | post-restart bouncer fails to open `state.db` with `no such column` or `migration_failed` | `sqlite3 ~/.iam-jit/bouncer/state.db 'PRAGMA user_version;'` vs expected for the new code | **HALT.** Per RB-D6 do NOT proceed — schema migration broken is a separate severity than runtime crash. Restore previous state.db from backup. |
| D7 | Audit-log sequence gap across restart | `iam-jit audit verify` shows missing sequence numbers around the update window | `iam-jit audit verify --since '<update timestamp>'` | DEGRADED-not-halt for ops; HALT for compliance-critical workloads. RB-D7: file CRIT issue; investigate whether sequences were truly lost or just delayed. |
| D8 | Auto-update polling caught a malicious upstream commit | hypothetical: `git fetch` pulls a commit that breaks installation OR introduces malicious code | inspect `git log <old_sha>..HEAD` per repo BEFORE allowing update | **HALT.** Per `[[canary-redeploys-on-every-update]]` correction-2026-05-23: `--watch` is notify-only by default; `--auto-deploy` is explicit opt-in. If auto-deploy was on + bad commit landed, RB-D8: `git checkout <last-known-good-sha>` + reinstall. |

## Cross-cutting halt principles

1. **Never silently retry a halt-triggering step.** The default `pip install -e .`
   inside `_do_one_update` runs ONCE; if it fails, `_fail` is invoked with rollback.
   Operators should match that discipline in manual ops.

2. **Halt-state should always leave an `issues.jsonl` entry.** Per
   `[[canary-redeploys-on-every-update]]` — silent failures defeat the canary purpose.
   Every condition above maps to a category in the `_CATEGORIES` enum:
   `update_failure` (D2-D8), `bouncer_error` (B1-B8, C3-C4), `anomaly` (C7),
   `calibration_drift` (D4), `operator_friction` (A1-A9, B7).

3. **State preservation over speed.** Per `[[creates-never-mutates]]` — rollback never
   modifies existing IAM resources, and the same discipline applies to local state:
   never delete audit logs or chain history during rollback. Snapshot first, investigate
   second, delete (if at all) third.

4. **Operator visibility is mandatory.** A halt that doesn't surface to the operator
   (e.g. silent SIGTERM, swallowed exception, `_logger.warning` only) violates
   `[[ibounce-honest-positioning]]`. MRR-2 audits these error sites; this catalog flags
   them by reality-check footers.

## Open gaps (filed for MRR-2 / MRR-5 / MRR-6)

- **No `iam-jit doctor preflight` command** (Category A consolidator) — MRR-6 follow-up.
- **No `iam-jit canary verify-setup --deep`** (Category B post-install verifier) — MRR-5
  follow-up.
- **UC-20 partial-install path detection** — today the operator must `jq` `status.json`
  manually; a structured check (`iam_jit_setup_from_config --verify`) is MRR-3 follow-up.
- **Threat-feed compromised-publisher response runbook** — C6 has only the technical
  rollback; the operational (rotate keys, communicate, etc.) is MRR-6 territory.
- **Linux halt-condition parity** — most detection commands above use BSD `lsof` syntax;
  Linux variants noted. Per `LINUX-SUPPORT-AUDIT-2026-05-24.md` the `lsof` fix is already
  in HEAD; broader Linux smoke is MRR-3 follow-up.

End of MRR-4 halt-condition catalog.
