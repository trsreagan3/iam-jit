# MRR-4 — Rollback runbook (2026-05-24)

Phase 4 of the Mission Readiness Review (`[[mrr-flight-readiness-program]]`).
Companion to:

- [`MRR-4-HALT-CONDITIONS.md`](MRR-4-HALT-CONDITIONS.md) — catalog of halt conditions (A1..D8) referenced below
- [`MRR-4-UNINSTALL.md`](MRR-4-UNINSTALL.md) — terminal rollback (full uninstall)

For each halt condition that requires rollback, this doc gives:
**trigger → detection → rollback procedure → verification → re-attempt guidance.**

Per `[[creates-never-mutates]]`: rollback never modifies existing customer IAM. iam-jit's
own short-lived credentials expire on their own — AWS-side rollback typically not needed.
**State-cleanup IS needed** for local files (venv, ~/.iam-jit/, ~/go/bin/<bouncer>).

Per `[[ibounce-honest-positioning]]`: the "automated rollback?" column on each entry is
honest about what `_fail()` does today vs what requires operator hands.

## Rollback severity tiers

| Tier | Definition | Examples |
|---|---|---|
| **Tier 1 — Auto-rollback (in code)** | `_fail()` or equivalent reverts state automatically; operator notified via `issues.jsonl` | D2 / D3 (canary update pip/go failure) |
| **Tier 2 — Runbook-driven, low-risk** | Operator runs a small sequence; idempotent; no data risk | A2 / A5 / B1 / B2 / B5 |
| **Tier 3 — Runbook-driven, data-risk** | Operator runs sequence that touches state.db / audit chain / anomaly baseline; backup required first | B3 / C2 / C8 / D6 / D7 |
| **Tier 4 — Halt + escalate** | No clean rollback exists today; runbook documents the manual investigation path | B6 (UC-20 partial-install) / C5 / D8 (malicious upstream) |

## Pre-rollback discipline (always)

Before ANY rollback that touches state:

```bash
# 1. Snapshot the current bouncer state.db (Tier 3+)
cp ~/.iam-jit/bouncer/state.db \
   ~/.iam-jit/bouncer/state.db.pre-rollback-$(date +%Y%m%dT%H%M%S)

# 2. Snapshot the canary issues + status
cp ~/.iam-jit/canary/issues.jsonl ~/.iam-jit/canary/issues.jsonl.pre-rollback-$(date +%Y%m%dT%H%M%S)
cp ~/.iam-jit/canary/status.json ~/.iam-jit/canary/status.json.pre-rollback-$(date +%Y%m%dT%H%M%S)

# 3. Capture process state
iam-jit canary status > /tmp/canary-status.pre-rollback.json 2>&1 || true
ps -p $(jq -r '.pids | to_entries[] | .value' ~/.iam-jit/canary/status.json 2>/dev/null) > /tmp/canary-procs.pre-rollback.txt 2>&1 || true
```

These snapshots are forensic; never delete them mid-rollback.

---

## RB-A2 — Port already in use

**Trigger**: A2 — port 7401 / 7402 / 7412 / 8767 bound by another process.

**Detection**:
```bash
lsof -nP -iTCP:7401 -sTCP:LISTEN  # macOS
ss -ltnp 'sport = :7401'          # Linux
```

**Rollback procedure**:
1. Identify the conflicting PID + process name from `lsof` / `ss` output.
2. **If it's an old iam-jit / bouncer process** (orphaned from prior install):
   ```bash
   kill -TERM <pid>
   sleep 5  # let it close SQLite cleanly
   # If still alive:
   kill -KILL <pid>
   ```
3. **If it's an unrelated process** (e.g. another tool): re-deploy iam-jit with a
   different port via `--port 17401` or set `IBOUNCE_PORT` / `GBOUNCE_PORT` env vars
   (`cli_canary.py` reads recorded ports from `status.json`).
4. Re-run the install / start command.

**Verification**:
```bash
lsof -nP -iTCP:7401 -sTCP:LISTEN  # should now show the NEW iam-jit pid
curl -fsS http://127.0.0.1:7401/healthz  # 200
```

**Re-attempt**: SAFE to retry once port is free.

**Automated rollback today?** No — operator-driven.

---

## RB-A5 — Existing iam-jit install detected

### RB-A5a — Upgrade (keep state)

**When**: operator wants to upgrade in place, keeping audit history + profiles.

**Procedure**:
1. Confirm pre-update state: `iam-jit canary status > pre.json`
2. SIGTERM running bouncers per RB-C3 procedure.
3. Run `iam-jit canary update` (uses `_do_one_update` with auto-rollback on failure).
4. Per RB-D2 / RB-D3 / RB-D5 if anything fails.

**Verification**: bouncer `/healthz` returns 200; `iam-jit canary status` shows new SHA.

### RB-A5b — Fresh install (discard state)

**When**: operator wants to start over (test machine; corrupted state).

**Procedure**: follow [`MRR-4-UNINSTALL.md`](MRR-4-UNINSTALL.md) end-to-end. Re-install.

**Verification**: post-uninstall checks in MRR-4-UNINSTALL.md.

**Automated rollback today?** No.

---

## RB-B1 — Bouncer startup fails (config-parse)

**Trigger**: B1 — bouncer exits within 5s; `ibounce.log` shows pydantic / yaml error.

**Detection**: `tail -20 ~/.iam-jit/canary/ibounce.log`

**Rollback procedure**:
1. Identify the bad config file from the error message (typically `~/.iam-jit/bouncer/profiles.yaml` or `~/.iam-jit/canary/.iam-jit.yaml`).
2. Snapshot the bad config: `cp <path> <path>.broken-$(date +%s)`
3. Restore prior-known-good config:
   - If profiles.yaml broke: `ibounce profile install --bundle ~/.iam-jit/backups/profiles-last-known-good.yaml` (TBD per #275 backup discipline)
   - If `.iam-jit.yaml` broke: restore from git history if version-controlled; OR re-run `iam-jit init-solo` to regenerate.
4. Re-start bouncer per RB-C3.

**Verification**: `/healthz` 200; profile loaded as expected.

**Re-attempt**: SAFE once config is valid.

**Automated rollback today?** No.

---

## RB-B2 — `/healthz` never reaches 200 within 30s

**Trigger**: B2 — `cli_canary.py:_wait_for_health` timeout.

**Detection**: `curl -fsS http://127.0.0.1:7401/healthz` returns non-200 OR connection refused.

**Rollback procedure**:
1. Inspect last 50 lines of bouncer log: `tail -50 ~/.iam-jit/canary/ibounce.log`
2. Common cause checks:
   - **SQLite locked by stale process**: `fuser ~/.iam-jit/bouncer/state.db` (Linux) / `lsof ~/.iam-jit/bouncer/state.db` (macOS) — kill the orphan; restart.
   - **Port-binding race**: per RB-A2.
   - **Missing env var**: search log for `KeyError` / `Required env`. Set the var; restart.
3. If unclear: file CRIT issue, run `iam-jit diagnostics bundle` (per #277), escalate.

**Verification**: `/healthz` 200 within 30s.

**Re-attempt**: SAFE.

**Automated rollback today?** No.

---

## RB-B3 — Audit chain initialization fails

**Trigger**: B3 — `audit_export/` raises `ChainInitError`.

**Detection**: `tail -30 ~/.iam-jit/canary/ibounce.log | grep -i 'chain\|audit'`

**Rollback procedure** (Tier 3 — data-risk):
1. Pre-rollback snapshot per "Pre-rollback discipline" above.
2. If a prior `ibounce backup` (#279) exists:
   ```bash
   ibounce restore --in ~/.iam-jit/backups/<latest>.db
   ```
3. If no backup: re-init the chain (DATA LOSS — prior audit events become orphan):
   ```bash
   mv ~/.iam-jit/bouncer/state.db ~/.iam-jit/bouncer/state.db.chain-broken-$(date +%s)
   # restart bouncer — it will create fresh state.db with new chain
   ```
4. File CRIT issue with the broken state.db path for forensics.

**Verification**:
```bash
iam-jit audit verify --since 1h  # exit 0 = chain intact
```

**Re-attempt**: SAFE after rollback.

**Automated rollback today?** No.

---

## RB-B5 — Anomaly baseline DB corruption

**Trigger**: B5 — `anomaly-baseline.db` returns malformed-db error.

**Detection**: `sqlite3 ~/.iam-jit/anomaly-baseline.db '.schema'` errors.

**Rollback procedure** (Tier 2 — data-risk minimal; baseline regenerates):
1. Snapshot: `mv ~/.iam-jit/anomaly-baseline.db ~/.iam-jit/anomaly-baseline.db.broken-$(date +%s)`
2. Restart bouncer — anomaly module creates fresh DB.
3. NOTE: baseline must re-mature (14-day window per Phase H) before anomaly detection
   is meaningful again. Per `[[anomaly-detection]]` the operator is in degraded-detection
   mode until baseline matures.

**Verification**:
```bash
sqlite3 ~/.iam-jit/anomaly-baseline.db '.schema'  # shows expected tables
iam-jit anomaly status  # reports "baseline maturing" with day-counter
```

**Re-attempt**: SAFE.

**Automated rollback today?** No.

---

## RB-B6 — `iam_jit_setup_from_config` partial-install (UC-20, LOAD-BEARING)

**Trigger**: B6 — some bouncers installed + started; others failed mid-install. State is mixed.

**Detection** (operator-run):
```bash
# Compare declared bouncers in .iam-jit.yaml vs actually-running pids
jq '.pids' ~/.iam-jit/canary/status.json
jq '.bouncers // {}' ~/.iam-jit/canary/.iam-jit.yaml
# Mismatch indicates partial install.
```

**Rollback procedure** (Tier 4 — no automated path today; load-bearing):

This is the UC-20 gap from MRR-1. The runbook below is honest about what works:

1. **Pre-rollback snapshot** per the discipline at top of this doc.
2. **Identify which bouncers actually started** vs which failed mid-install:
   ```bash
   # For each bouncer declared in .iam-jit.yaml:
   for port in 7401 7402; do
     curl -fsS http://127.0.0.1:$port/healthz && echo "OK :$port" || echo "DOWN :$port"
   done
   ```
3. **Stop the started bouncers** (clean shutdown preserves SQLite state):
   ```bash
   # Use recorded PIDs from status.json:
   for pid in $(jq -r '.pids[]' ~/.iam-jit/canary/status.json); do
     [[ "$pid" != "null" ]] && kill -TERM $pid
   done
   sleep 5
   # If any survive:
   for pid in $(jq -r '.pids[]' ~/.iam-jit/canary/status.json); do
     [[ "$pid" != "null" ]] && kill -0 $pid 2>/dev/null && kill -KILL $pid
   done
   ```
4. **Decide rollback target**:
   - **Roll back to pre-install state** (no iam-jit at all): follow [`MRR-4-UNINSTALL.md`](MRR-4-UNINSTALL.md).
   - **Roll forward** (fix the failing bouncer + retry): inspect log of failed bouncer
     for root cause; fix; re-run `iam_jit_setup_from_config`. **Risk**: re-run is NOT
     idempotent today — may create duplicate state. Per UC-20 audit, file a HIGH issue.
5. **File CRIT** `category: bouncer_error` to `issues.jsonl` so the canary loop captures
   the pattern.

**Verification**:
- Rollback-to-pre-install: per MRR-4-UNINSTALL.md verification.
- Roll-forward: all declared bouncers have PID + /healthz 200; `iam-jit canary status`
  matches declared `.iam-jit.yaml`.

**Re-attempt**: NOT SAFE without operator confirmation. UC-20 is MRR-1 CRIT; the
"composition has never been E2E tested" gap means re-attempt could re-trigger the same
partial-install. Per `[[deliberate-feature-completion]]` — fix the root cause first.

**Automated rollback today?** **No.** This is the load-bearing gap. Filed as CRIT
remediation: `iam_jit_setup_from_config` should accept a `--rollback-on-failure` flag
that uses transaction-style semantics (snapshot pre-install state; restore on any step
failure). Until that exists, this runbook IS the rollback path.

---

## RB-C1 — Disk pressure CRITICAL (Phase F circuit breaker)

**Trigger**: C1 — bouncer audit-export pauses; `disk_pressure_circuit_breaker_tripped`.

**Detection**:
```bash
df -h ~/.iam-jit
iam-jit logs tail | grep disk_pressure
```

**Rollback procedure** (graceful degradation):
1. Verify the trip is real (not a misconfigured threshold):
   ```bash
   du -sh ~/.iam-jit/* | sort -h
   ```
2. Ship retained audit logs to SIEM (if configured):
   ```bash
   iam-jit logs ship-to <vendor> --since <last-shipped> --then-truncate
   ```
3. Or truncate per retention policy:
   ```bash
   iam-jit audit truncate --older-than 7d  # preserves chain integrity
   ```
4. Or move `~/.iam-jit` to bigger volume + symlink:
   ```bash
   systemctl stop iam-jit  # or pkill the bouncers per RB-C3
   mv ~/.iam-jit /bigger/volume/iam-jit
   ln -s /bigger/volume/iam-jit ~/.iam-jit
   ```
5. Restart bouncers per RB-C3.

**Verification**: `df -h ~/.iam-jit` shows ≥10% free; circuit breaker re-armed (no log entries).

**Re-attempt**: SAFE.

**Automated rollback today?** Partial — the circuit breaker itself IS the auto-halt;
recovery is operator-driven.

---

## RB-C2 — Audit chain break detected

**Trigger**: C2 — `iam-jit audit verify` reports `chain_broken_at: <seq>`.

**Detection**: `iam-jit audit verify --since 24h` returns non-zero.

**Rollback procedure** (Tier 3 — data-risk):
1. **DO NOT** delete or rewrite the chain. Per `[[creates-never-mutates]]` discipline:
   preserve broken state for forensics.
2. Pre-rollback snapshot per top of this doc.
3. Capture the break point + surrounding entries:
   ```bash
   iam-jit audit verify --verbose > /tmp/chain-break-$(date +%s).log
   iam-jit audit query --seq-range "<break_seq - 50>:<break_seq + 50>" --json > /tmp/chain-break-events.json
   ```
4. File CRIT issue. Per `[[signed-audit-receipts-v11]]` chain integrity is THE
   compliance claim; a break invalidates the audit trail from break-point forward.
5. If continuing operation is required:
   - Restore from last known-good backup (`ibounce restore`).
   - OR rotate to a fresh chain — but the gap MUST be documented in the audit trail
     for compliance.
6. Investigate root cause: process kill -9 during write? Disk full? Filesystem error?

**Verification**:
```bash
iam-jit audit verify --since 1h  # exit 0
```

**Re-attempt**: SAFE after investigation + rotation/restore.

**Automated rollback today?** No — chain-break recovery is intentionally manual to
preserve forensic state.

---

## RB-C3 — Bouncer process death

**Trigger**: C3 — `iam-jit canary status` shows missing PID.

**Detection**:
```bash
iam-jit canary status | jq '.pids'  # null entries
ps -p <expected_pid>  # no row
```

**Rollback procedure**:
1. Inspect last 100 lines of bouncer log:
   ```bash
   tail -100 ~/.iam-jit/canary/ibounce.log  # or gbounce.log etc.
   ```
2. Look for crash cause: panic, OOM, signal, segfault.
3. Use `_restart_bouncers` via canary tooling:
   ```bash
   iam-jit canary update --dry-run  # show what restart would do
   iam-jit canary update --restart-only  # TBD; today: ad-hoc relaunch via the deploy script
   ```
   Or manual relaunch using recorded `daemon_args` from `.iam-jit.yaml`:
   ```bash
   cat ~/.iam-jit/canary/.iam-jit.yaml | yq '.bouncers.ibounce.daemon_args'
   nohup ~/.iam-jit/venv/bin/ibounce run <args> > ~/.iam-jit/canary/ibounce.log 2>&1 &
   ```
4. Wait for `/healthz` 200 within 30s.

**Verification**:
```bash
curl -fsS http://127.0.0.1:7401/healthz
iam-jit canary status | jq '.pids'  # shows new PID
```

**Re-attempt rule**: if the bouncer crashes AGAIN within 60s of restart, STOP. Do not
loop. File CRIT and investigate.

**Automated rollback today?** Partial — `_restart_bouncers` exists but is invoked
inside `_do_one_update` only; standalone "respawn dead bouncer" is operator-driven.

---

## RB-C5 — Manifest signature verification fails

**Trigger**: C5 — profile-install or threat-feed apply rejects unsigned/wrong-signed payload.

**Detection**: `iam-jit logs tail | grep signature_verification_failed`

**Rollback procedure** (Tier 4 — security-critical):
1. **DO NOT** apply the rejected payload. The verification did its job.
2. Determine if the failure is benign (wrong key, expired cert) or hostile (forged sig):
   ```bash
   iam-jit threat-feed status --verbose  # shows last-good-signature + current-failure
   iam-jit profile show-signature <profile-name>
   ```
3. **If benign**: contact the publisher / IT operator; re-fetch with correct key.
4. **If hostile**: full security-incident response — rotate publisher keys, audit
   downstream consumers, file CRIT + escalate per IT security policy.
5. Bouncer state is unchanged (verification HALT happened before apply); no rollback needed.

**Verification**: `iam-jit threat-feed status` shows healthy last-successful timestamp
after the next signed update.

**Re-attempt**: NOT until root cause confirmed.

**Automated rollback today?** Yes — verification is in-code; the apply never happens.

---

## RB-C6 — Threat-feed signature verification fails

Same shape as RB-C5 for threat-feeds. Critical addendum: prior denies remain in effect
(per `threat_feed/applier` design) — do NOT manually revert prior denies on the
assumption the feed is bad; that would create a false-permissive window.

---

## RB-C7 — LLM cost-cap breach

**Trigger**: C7 — autopilot logs `llm_budget_exhausted`.

**Detection**: `iam-jit autopilot status | jq .llm_spend_24h`

**Rollback procedure** (graceful degradation):
1. Confirm bouncers continue running (deterministic-only). Per
   `[[bouncer-zero-llm-when-agent-in-loop]]` — bouncers never call LLM directly; the
   agent does. The cap is a guard for agent-mediated calls.
2. Either top up budget OR confirm deterministic-only is acceptable for the window:
   ```bash
   iam-jit autopilot config --llm-budget-24h <new-value>
   # OR explicitly disable LLM augmentation:
   iam-jit autopilot config --disable-llm
   ```
3. File LOW issue `category: anomaly` so calibration loop catches the cap-trip pattern.

**Verification**: `iam-jit autopilot status` reports `llm_status: ok` or `disabled`.

**Re-attempt**: SAFE.

**Automated rollback today?** Yes — cost-cap halt is in-code; degradation is automatic.

---

## RB-C8 — SQLite database corruption

**Trigger**: C8 — `database disk image is malformed`; bouncer crash-loops.

**Detection**:
```bash
sqlite3 ~/.iam-jit/bouncer/state.db 'PRAGMA integrity_check;'  # non-'ok'
```

**Rollback procedure** (Tier 3 — data-risk):
1. Pre-rollback snapshot.
2. Stop bouncer (RB-C3 cleanup).
3. Restore from last `ibounce backup`:
   ```bash
   ibounce restore --in ~/.iam-jit/backups/<latest>.db
   ```
4. If no backup: corruption is unrecoverable. Re-init per Phase F retention:
   ```bash
   mv ~/.iam-jit/bouncer/state.db ~/.iam-jit/bouncer/state.db.corrupt-$(date +%s)
   # restart bouncer — fresh DB created
   ```
   Audit history is LOST in this case.
5. File CRIT issue with the corrupt file preserved.

**Verification**:
```bash
sqlite3 ~/.iam-jit/bouncer/state.db 'PRAGMA integrity_check;'  # 'ok'
iam-jit audit verify --since 1h  # exit 0
```

**Re-attempt**: SAFE.

**Automated rollback today?** No — restore is operator-driven; backups must already exist.

---

## RB-D2 — `pip install -e .` fails during canary update

**Trigger**: D2 — `_do_one_update` calls `_fail` with pip error.

**Detection**: `iam-jit canary report --recent | jq '.[-1]'` shows `category: update_failure`.

**Rollback procedure** (Tier 1 — auto-rollback initiated):

Per `cli_canary.py:1206` (`_fail` function), on pip failure:
1. The error message is printed to stderr.
2. `git checkout <pre-update-sha>` is attempted for EACH repo in `_CANARY_REPOS`.
3. `issues.jsonl` gets a CRIT `update_failure` entry.
4. **Bouncers are NOT automatically reinstalled on the rolled-back SHA.**

Operator follow-up required:
1. Confirm git rollback succeeded:
   ```bash
   git -C ~/repos/iam-roles log --oneline -1  # should match pre-update SHA
   git -C ~/repos/gbounce log --oneline -1
   ```
2. Re-run `pip install -e .` to make sure the venv matches the rolled-back code:
   ```bash
   ~/.iam-jit/venv/bin/pip install -e ~/repos/iam-roles
   ```
3. Restart bouncers per RB-C3 if they were SIGTERM'd before the failure step.

**Verification**:
```bash
iam-jit --version  # matches old SHA's version constant
/healthz on 7401, 7402  # 200
```

**Re-attempt**: investigate pip failure root cause (often dependency conflict in
`pyproject.toml` or wheel-build failure per B7); fix; re-run `iam-jit canary update`.

**Automated rollback today?** **Yes for git checkout; NO for venv reinstall.** This
is a partial-automation gap. Filed as MED follow-up: `_fail` should re-run
`pip install -e .` against the rolled-back code.

---

## RB-D3 — `go install` fails during canary update

Same shape as RB-D2 for Go bouncers. Verification: `~/go/bin/gbounce --version`
matches old SHA. The rolled-back git state SHOULD produce the same binary on
re-build; if not, file CRIT (`[[update-release-strategy]]` violation).

---

## RB-D5 — Bouncer fails to restart after update

**Trigger**: D5 — `_restart_bouncers` returns `(False, msg)`; bouncer is DOWN.

**Detection**: `iam-jit canary status | jq .pids` shows null.

**Rollback procedure** (Tier 3 — partial auto + operator hands):

The `_fail` path does git-checkout but does NOT relaunch the bouncer on the old SHA.
Manual recovery:
1. Confirm rollback completed: `git log --oneline -1` per repo matches old SHA.
2. Reinstall venv per RB-D2 step 2.
3. Re-launch each bouncer with recorded `daemon_args`:
   ```bash
   yq '.bouncers' ~/.iam-jit/canary/.iam-jit.yaml
   # For each bouncer, exec with its daemon_args
   ```
4. Wait for `/healthz` 200; verify in `iam-jit canary status`.

If bouncer continues to fail post-rollback: the failure was NOT update-induced. Investigate
per RB-B2.

**Verification**: per RB-C3 verification.

**Re-attempt**: NOT until bouncer is stable on rolled-back SHA.

**Automated rollback today?** Partial (git only, not bouncer relaunch).

---

## RB-D6 — Update breaks SQLite schema

**Trigger**: D6 — post-restart bouncer fails to open `state.db` (schema migration broken).

**Detection**:
```bash
sqlite3 ~/.iam-jit/bouncer/state.db 'PRAGMA user_version;'
# Compare against new code's expected version
grep -r "SCHEMA_VERSION" src/iam_jit/bouncer/store.py | head
```

**Rollback procedure** (Tier 3 — data-risk):
1. Pre-rollback snapshot.
2. Roll back code (per RB-D2 git checkout).
3. Restore state.db from pre-update snapshot OR `ibounce backup`:
   ```bash
   cp ~/.iam-jit/bouncer/state.db.pre-rollback-* ~/.iam-jit/bouncer/state.db
   # OR
   ibounce restore --in ~/.iam-jit/backups/<pre-update>.db
   ```
4. Restart bouncer.

**Verification**:
```bash
sqlite3 ~/.iam-jit/bouncer/state.db 'PRAGMA user_version;'  # matches old code expectation
/healthz 200
```

**Re-attempt**: NOT until schema migration is fixed in code (file CRIT per
`[[update-release-strategy]]` schema-discipline).

**Automated rollback today?** No.

---

## RB-D7 — Audit-log sequence gap across restart

**Trigger**: D7 — `iam-jit audit verify` shows missing seqs around update window.

**Rollback procedure** (Tier 3 — data-risk but ops-continuable):
1. Pre-rollback snapshot.
2. Capture the gap window:
   ```bash
   iam-jit audit query --seq-range "<gap_start>:<gap_end>" --json > /tmp/gap.json
   ```
3. Cross-reference with shipped audit (SIEM) — events may exist in SIEM but not local
   `state.db` (acceptable per `audit-export` design).
4. If shipped: file LOW (degraded local-only; SIEM intact).
5. If lost entirely: file CRIT; restore from `ibounce backup` if pre-gap backup exists.

**Re-attempt**: SAFE after gap reconciled.

**Automated rollback today?** No.

---

## RB-D8 — Malicious upstream commit caught by auto-update

**Trigger**: D8 — `--watch --auto-deploy` pulled a hostile commit OR operator suspects
upstream compromise.

**Rollback procedure** (Tier 4 — security incident):
1. **IMMEDIATELY** disable auto-deploy:
   ```bash
   # Kill the canary watch process
   pkill -f 'iam-jit canary update --watch'
   ```
2. Identify the suspect commit:
   ```bash
   git -C ~/repos/iam-roles log --oneline <last-known-good>..HEAD
   git -C ~/repos/iam-roles show <suspect-sha>
   ```
3. Roll back code to last-known-good:
   ```bash
   git -C ~/repos/iam-roles checkout <last-known-good-sha>
   git -C ~/repos/gbounce checkout <last-known-good-sha>
   ```
4. Reinstall venv + Go binaries per RB-D2 + RB-D3.
5. Restart bouncers per RB-C3.
6. Audit any data exfiltrated during the bad-commit window:
   ```bash
   iam-jit audit query --since '<auto-deploy timestamp>' --json
   ```
7. File CRIT security incident. Per `[[push-policy-public-repo]]` + the founder direction
   on canary auto-deploy: this is exactly the failure mode `--auto-deploy` opt-in was
   designed to fence; if it fired, the fence held but reconsider whether auto-deploy is
   appropriate for the work-machine deploy at all.

**Verification**: `git log -1` per repo matches last-known-good; bouncers running OLD code.

**Re-attempt**: NOT until upstream is verified clean (vendor / repo audit).

**Automated rollback today?** Partial — auto-deploy is opt-in only, so the default
behavior is notify-only (`--watch` alone); the security fence holds by default.

---

## Rollback paths WITHOUT a clean solution today (CRIT findings)

Per the audit, these halt conditions lack a fully-automated rollback path. Each is a
candidate CRIT for MRR-7 / MRR-8 remediation.

| Halt | Why no clean rollback | Remediation proposal |
|---|---|---|
| **B6 (UC-20 partial-install)** | `iam_jit_setup_from_config` is not transactional; pre-install state isn't snapshotted; failure leaves orphan bouncers + mixed config | `--rollback-on-failure` flag that snapshots `~/.iam-jit` + recorded PIDs pre-install; on any step failure, restore snapshot + kill any started bouncers |
| **D5 (bouncer restart fails after update)** | `_fail` does git checkout but doesn't reinstall venv or relaunch bouncer | extend `_fail` to: (1) re-run `pip install -e .` against rolled-back code, (2) call `_restart_bouncers` again on old code |
| **D6 (SQLite schema migration broken)** | no schema-version pre-check before update applies; bouncer crashes only after pip install | extend `_do_one_update` to: probe expected schema-version of NEW code against current DB BEFORE pip install; refuse update if mismatch + manual migration required |
| **C2 (audit chain break)** | intentionally manual per forensic preservation; but operator has no decision-tree for "rotate vs restore" | MRR-6 runbook addition: "chain break decision tree" with compliance-tier guidance |
| **D8 (malicious upstream)** | partial — auto-deploy opt-in fence holds; but no detection of "did anything bad already run between fetch + abort?" | post-deploy audit query auto-runs in `_do_one_update`; surfaces any IAM events during update window |

These are filed as MRR-7 / MRR-8 review candidates. Per the founder's "space shuttle
launch" discipline, B6 + D5 are the most critical (UC-20 is load-bearing per MRR-1).

---

End of MRR-4 rollback runbook.
