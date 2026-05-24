# L4 — Update FAILURE recovery

## What this tests

The unhappy path of L3: trigger an update failure mid-cycle (broken
commit, build error, port conflict) → verify rollback works → state
preserved during failed update → CRIT issue filed in `issues.jsonl`.

## Why this matters

The biggest operational risk of auto-update is "update breaks; system
is now half-installed in an unknown state." `[[canary-redeploys-on-every-update]]`
explicitly mandates: "If update FAILS at any step: don't proceed;
roll back; emit `severity: CRIT` issue; surface to operator." This
scenario is the regression for that contract.

## Pass criteria

Three failure-injection variants — each is a separate harness run:

**Variant A — broken commit (Python syntax error introduced post-pull)**

1. Set up Mode A container at known-good `${PRE_SHA}`; activity →
   audit baseline captured.
2. Inject a Python syntax error into a load-bearing module
   (`src/iam_jit/cli.py`) AND commit on a synthetic branch
   `${BROKEN_SHA}`.
3. Run `iam-jit canary update` pointing at `${BROKEN_SHA}`.
4. Update should fail at `pip install -e .` OR at
   `iam-jit --version` post-install.
5. Bouncers continue running at `${PRE_SHA}` (rollback preserved
   process state).
6. State preserved: audit DB intact, profiles loaded, no PID
   churn.
7. `issues.jsonl` has a new line: `category: "update_failure"`,
   `severity: "CRIT"`, with the failed step + recovery taken.

**Variant B — port conflict on restart**

1. Bring up bouncers at `${PRE_SHA}`.
2. Spawn a sentinel process holding the port the bouncer needs
   (use a stub `nc -l ${PORT}`).
3. Run `iam-jit canary update` to `${POST_SHA}`.
4. Update reaches restart; restart fails with port-bind error.
5. Rollback: install reverts (or honestly logs that revert was
   impossible if it can't) + emits CRIT.
6. Operator-visible: stderr mentions port + suggests action.

**Variant C — build error (gbounce go build fails)**

1. Bring up at `${PRE_SHA}`.
2. Inject a Go compile error into `gbounce/cmd/gbounce/main.go`
   on a synthetic `${BROKEN_GO_SHA}`.
3. Run update.
4. `go install` fails; update aborts BEFORE touching the live
   binary (atomic-replace contract).
5. State preserved; CRIT emitted.

## Fail criteria

* Bouncers crash or stop running after the failed update.
* Audit DB corrupted.
* `issues.jsonl` does NOT contain the `update_failure` CRIT line.
* Update proceeds past the failed step (no abort).
* Rollback claims success without actually reverting state.
* Live bouncer binary replaced before build succeeded (Variant C).

## Prerequisites

* L3 PASS preferred (you want the happy path working first).
* Mode A required (failure injection mutates source; must be in
  container).

## Supported isolation modes

* Mode A only.

## Expected duration

~10-15 minutes (3 variants × ~3-5 min each).

## Evidence block schema

```json
{
  "variant": "A|B|C",
  "pre_sha": "...",
  "broken_sha": "...",
  "update_exit_code": 1,
  "failed_at_step": "pip_install|version_check|restart_port_bind|go_install",
  "bouncers_alive_post_failure": true,
  "audit_db_intact": true,
  "profiles_loaded_post_failure": true,
  "issues_jsonl_critical_line_present": true,
  "operator_visible_error_actionable": true
}
```
