# MRR-4 — Clean uninstall runbook (2026-05-24)

Phase 4 of the Mission Readiness Review (`[[mrr-flight-readiness-program]]`).
Companion to:

- [`MRR-4-HALT-CONDITIONS.md`](MRR-4-HALT-CONDITIONS.md) — pre-defined halt conditions
- [`MRR-4-ROLLBACK-RUNBOOK.md`](MRR-4-ROLLBACK-RUNBOOK.md) — per-condition rollback procedure
- [`tests/uninstall_smoke.sh`](../tests/uninstall_smoke.sh) — automated smoke test in Linux container

Per founder direction 2026-05-24 ("space shuttle launch" discipline): the uninstall
path IS the terminal rollback — if everything else fails, the operator must be able to
return the machine to a clean state.

Per `[[ibounce-honest-positioning]]`: this doc is honest about which steps are
**automated** vs **operator-manual**.

**UPDATE 2026-05-24 (#541)**: iam-jit now ships `iam-jit uninstall` — a single
CLI command that implements steps 1-9 end-to-end with auto-detected halt
conditions. The manual 10-step sequence below is preserved as a fallback /
explanatory reference; the canonical path is now:

```bash
# Inspect what would happen (always safe):
iam-jit uninstall --dry-run

# Full purge (with confirmation prompt):
iam-jit uninstall

# Non-interactive purge:
iam-jit uninstall --yes

# Preserve audit chain for compliance:
iam-jit uninstall --yes --keep-audit-logs

# Snapshot everything to a backup dir before removal:
iam-jit uninstall --yes --backup-dir ~/iam-jit-backup-$(date +%s)

# Bypass halt conditions (DANGEROUS — investigate first):
iam-jit uninstall --yes --force
```

Halt conditions per `MRR-4-HALT-CONDITIONS.md` are auto-detected and surface
with severity + reason. Without `--force` the command exits 2 and refuses to
mutate state. Per `[[creates-never-mutates]]` the command DOES NOT touch:

- Shell profiles (`~/.zshrc`, `~/.bashrc`, IDE env vars)
- MCP config entries (`~/.claude.json`, `.mcp.json`)
- Browser / OS-truststore-imported gbounce MITM CAs
- systemd / launchd unit files

These are surfaced as `manual_reminders` in both the human-readable summary
and the `--json` output so the operator knows exactly what to clean up by hand.

## Pre-uninstall checklist

Before running uninstall:

1. **Are you sure?** Uninstalling iam-jit removes the proxy that's been observing
   AWS API calls. After uninstall, agents have unmediated access until you re-install
   or change credentials.
2. **Have you backed up audit history?** Per `[[creates-never-mutates]]` — local
   audit chain in `~/.iam-jit/bouncer/state.db` + `~/.iam-jit/audit.jsonl` is the only
   local forensic record. Ship to SIEM first OR keep `~/.iam-jit/` directory after
   uninstall (step 8 below).
3. **Have you scoped the uninstall?** Two modes:
   - **App-only uninstall** (steps 1-7): removes binaries, preserves state. Safe if
     you plan to re-install.
   - **Full purge** (steps 1-9): removes everything in `~/.iam-jit/`. Operator MUST
     opt in explicitly per step 9.

## The 10-step uninstall sequence

### Step 1 — SIGTERM any running bouncer processes

```bash
# Bouncers ship under these process names per pyproject.toml [project.scripts]
# + Go binary names.
for proc in ibounce gbounce kbounce dbounce iam-jit; do
  pkill -TERM -f "$proc run" 2>/dev/null || true
done
sleep 5  # let bouncers flush SQLite WAL + audit chain
```

**Verification**:
```bash
pgrep -x ibounce  # should return nothing
pgrep -x gbounce
pgrep -x kbounce
pgrep -x dbounce
```

If processes survive after 5s: re-send `SIGTERM`; if still alive after 10s total,
use `kill -KILL <pid>` (RISKS chain-tail loss; per `[[creates-never-mutates]]` accept
forensic value loss only if process is unresponsive to graceful shutdown).

### Step 2 — pip uninstall iam-jit

```bash
# If venv is at the documented location:
~/.iam-jit/venv/bin/pip uninstall -y iam-jit

# If you installed via a different venv / system Python:
pip uninstall -y iam-jit
```

This removes the `iam_jit` package + the console-script shims defined in
`pyproject.toml [project.scripts]`:
- `iam-jit`
- `iam-risk-score`
- `ibounce`
- `iam-jit-bouncer` (deprecation alias)
- `iam-jit-feed-publish`

### Step 3 — verify console scripts are gone

```bash
# Inside the venv:
ls ~/.iam-jit/venv/bin/ | grep -E "^(iam-jit|ibounce|iam-risk-score|iam-jit-feed-publish)$"
# should print nothing

# Outside the venv (if iam-jit was on $PATH globally):
command -v iam-jit ibounce iam-risk-score iam-jit-feed-publish 2>&1
# should print nothing
```

If any script remains: pip uninstall didn't complete; investigate (common: editable
install with `pip install -e .` leaves a stale `.egg-link`; manually delete from
`~/.iam-jit/venv/lib/python*/site-packages/`).

### Step 4 — clean Go binaries

`gbounce`, `kbounce`, `kbouncer`, `dbounce` ship from separate Go repos (per
`[[repo-topology-decision]]`) and `go install` puts them in `$GOBIN` or `~/go/bin`.

```bash
GOBIN="$(go env GOBIN)"
GOBIN="${GOBIN:-$HOME/go/bin}"

for bin in gbounce kbounce kbouncer dbounce; do
  rm -f "$GOBIN/$bin" && echo "removed $GOBIN/$bin" || true
done
```

**Verification**:
```bash
ls "$GOBIN/" | grep -E "^(gbounce|kbounce|kbouncer|dbounce)$"
# should print nothing
```

### Step 5 — verify no orphan bouncer processes

```bash
for proc in ibounce gbounce kbounce dbounce; do
  pgrep -x "$proc" && echo "ORPHAN: $proc still running" || true
done
```

If any orphan reported: send `SIGKILL` after investigating why SIGTERM didn't take.

### Step 6 — verify bouncer ports are free

```bash
# macOS:
for port in 7401 7402 7412 8767; do
  lsof -nP -iTCP:$port -sTCP:LISTEN | grep LISTEN && echo "PORT-IN-USE: $port" || true
done

# Linux:
for port in 7401 7402 7412 8767; do
  ss -ltn "sport = :$port" | grep LISTEN && echo "PORT-IN-USE: $port" || true
done
```

If any port reports in-use: a bouncer process (or unrelated app) is still bound.
Per RB-A2: identify the PID via `lsof` / `ss`, kill it, re-check.

### Step 7 — remove the venv

```bash
rm -rf ~/.iam-jit/venv
```

**Verification**:
```bash
[ -d ~/.iam-jit/venv ] && echo "FAIL: venv still present" || echo "OK"
```

### Step 8 — report on data-bearing files (decision point)

App-only uninstall stops here. State files remain in `~/.iam-jit/`:

```bash
# Inventory what's left:
find ~/.iam-jit -maxdepth 3 -type f -size +0c | xargs -I{} ls -la {}
```

Typical contents after step 7:

| Path | Contents | Why preserved |
|---|---|---|
| `~/.iam-jit/bouncer/state.db` | SQLite audit chain + rules + tasks | Forensic value; SIEM may not have everything |
| `~/.iam-jit/bouncer/state.db-wal`, `state.db-shm` | SQLite WAL files | Required for state.db consistency |
| `~/.iam-jit/audit.jsonl` | append-only audit events | Same as above |
| `~/.iam-jit/anomaly-baseline.db` | 14-day learned baseline | Replays on re-install (saves baseline-maturing window) |
| `~/.iam-jit/canary/issues.jsonl` | canary loop findings | Audit trail for the canary deploy |
| `~/.iam-jit/canary/notes.md` | operator notes | Human notes; manual deletion only |
| `~/.iam-jit/threat_feed/publisher.ed25519.{pem,pub}` | publisher keypair | If you re-install, you keep the same publisher identity |
| `~/.iam-jit/gbounce/ca/` | gbounce MITM CA | Re-issuing requires browser/agent trust reset |

**Operator decision**:
- Re-installing later? **Keep these files** — they make re-install seamless.
- Permanently removing iam-jit? **Proceed to step 9** (full purge).
- Compliance-archive? Move to long-term storage:
  ```bash
  mkdir -p ~/iam-jit-archive
  cp -r ~/.iam-jit/audit.jsonl ~/.iam-jit/bouncer/state.db* ~/iam-jit-archive/
  ```

### Step 9 — (optional, opt-in) full purge

**DESTRUCTIVE.** Removes audit history. Only run if you're sure.

```bash
rm -rf ~/.iam-jit
```

**Verification**:
```bash
[ -d ~/.iam-jit ] && echo "FAIL: ~/.iam-jit still present" || echo "OK"
```

### Step 10 — re-install verification (sanity check)

If you plan to re-install, verify the uninstall didn't leave conflicting state:

```bash
mkdir -p ~/.iam-jit
python3 -m venv ~/.iam-jit/venv
. ~/.iam-jit/venv/bin/activate
pip install -e ~/repos/iam-roles
iam-jit --version
```

Should print `1.0.0` (or current SHA's version). If not: investigate per Phase 2
halt conditions.

## Per-product caveats

### ibounce

- Local-proxy mode: `HTTPS_PROXY=http://127.0.0.1:7401` environment variable
  references must be unset in shell profiles (`.zshrc`, `.bashrc`, IDE settings).
  This runbook does NOT touch shell profiles automatically — operator-manual.

### gbounce

- MITM CA (`~/.iam-jit/gbounce/ca/`) is trusted by browsers / agents that imported it.
  Per `[[mitm-beta-pii-pci-concern]]`: full uninstall MUST include removing the CA from
  every truststore the operator imported it into:
  - macOS Keychain: `security delete-certificate -c "iam-jit gbounce CA"`
  - Firefox / Chrome: manual removal per profile
  - Node.js: `unset NODE_EXTRA_CA_CERTS`

### kbouncer (K8s)

- Per `[[kbouncer-separate-repo]]`: kbouncer ships its own uninstall (`helm uninstall`
  for cluster deployments). This runbook covers the local Go binary only.

### dbounce

- Local Go binary at `~/go/bin/dbounce`. No additional state in `~/.iam-jit/` (dbounce
  state lives in its own `--state-dir`).

## Smoke test (tested 2026-05-24)

The above sequence is **TESTED** end-to-end via `tests/uninstall_smoke.sh` against
`python:3.12-slim-bookworm` Linux container.

**Test result 2026-05-24**: PASS.

```
=== PHASE 1: INSTALL ===
PHASE1-OK

=== PHASE 2: UNINSTALL ===
[step 1] SIGTERM bouncers — OK
[step 2] pip uninstall iam-jit — OK
[step 3] verify console scripts gone — OK (5 scripts removed)
[step 4] clean Go binaries — OK (4 binaries removed)
[step 5] verify no orphan bouncer processes — OK
[step 6] verify bouncer ports free — OK (7401/7402/7412/8767)
[step 7] remove venv (~/.iam-jit/venv) — OK
[step 8] report on data-bearing files — OK (3 files surfaced for operator decision)
[step 9] purge mode: removing all ~/.iam-jit/ — OK
[step 10] re-install verification — OK (iam-jit 1.0.0 back in PATH)
PHASE2-OK

RESULT: PASS — uninstall path verified clean in python:3.12-slim-bookworm
```

To re-run on demand:
```bash
bash tests/uninstall_smoke.sh
```

## Honest gap inventory (per `[[ibounce-honest-positioning]]`)

The smoke PASSED, but the runbook reveals known gaps for v1.0:

| # | Gap | Severity | Mitigation today |
|---|---|---|---|
| ~~U1~~ | **No single `iam-jit uninstall` command.** Operator must run 10 manual steps. | ~~HIGH~~ CLOSED 2026-05-24 (#541) | `iam-jit uninstall` ships in v1.0; this runbook is now a fallback explanatory reference. |
| U2 | **Shell-profile cleanup not automated.** `HTTPS_PROXY` env vars in `.zshrc` / `.bashrc` survive uninstall. | MED | Documented in per-product caveats. Operator-manual. |
| U3 | **gbounce MITM CA truststore cleanup not automated.** Per `[[mitm-beta-pii-pci-concern]]` MITM is BETA. | MED | Documented in per-product caveats; matches the BETA framing. |
| U4 | **`pip install -e .` editable installs may leave stale `.egg-link`.** | LOW | Documented in step 3 troubleshooting. |
| U5 | **No detection of partial uninstall** (e.g. pip uninstall succeeded but bouncer process orphaned). | MED | Step 5 + step 6 catch this if operator runs them; not enforced. |
| U6 | **macOS LaunchAgent / Linux systemd unit cleanup not in scope.** If operator installed via launchd/systemd (per `docs/HARDENING-AGAINST-PROMPT-INJECTION.md`), the unit file must be removed manually. | MED | The canary deploy in scope today does NOT use launchd/systemd; if MRR-6 adds operator-runbook coverage for those, this gap re-opens. |
| U7 | **Backup-before-purge prompt not automated.** Step 9 is destructive; operator must remember to step 8 first. | LOW | Documented prominently in step 8. |

None of U1..U7 are CRIT (the uninstall WORKS, just requires manual sequencing).
All are filed for v1.1 hardening per `[[deliberate-feature-completion]]`.

## Per `[[creates-never-mutates]]` — what uninstall does NOT touch

Uninstall removes **local iam-jit binaries + state** only. It does NOT:

- Modify any AWS IAM resource (per the architectural invariant)
- Revoke previously-issued STS credentials (those expire on their own per session TTL)
- Touch any role iam-jit created in the customer account (those have their own
  expiration via the scheduled expiry sweep)
- Touch any audit trail outside `~/.iam-jit/` (SIEM-shipped events remain in the SIEM)

This is by design. iam-jit's only persistent customer-side artifact is short-lived;
the local state is the operator's audit copy.

## When to use full uninstall vs other paths

| Scenario | Use |
|---|---|
| Re-install with same version (e.g. config reset) | Steps 1-7 + skip steps 8-9; then re-install |
| Upgrade to newer version | Use `iam-jit canary update` instead (not uninstall) |
| Investigate corruption (preserve forensics) | Steps 1-3 only; leave state for investigation |
| Move to different machine | Use `ibounce backup` (#279) + restore on new host |
| Permanent removal | Full 10-step sequence |
| Sandbox / test machine reset | Steps 1-9 + delete `~/repos/iam-roles` + `~/repos/{gbounce,kbouncer,dbounce}` |

---

End of MRR-4 uninstall runbook.
