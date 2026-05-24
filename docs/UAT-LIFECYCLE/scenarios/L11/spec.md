# L11 — Clean uninstall + verify nothing left

## What this tests

Run uninstall → verify no processes, no orphaned state files, no
system pollution → re-install from clean works.

## Why this matters

Per `[[mrr-flight-readiness-program]]` MRR-4 (abort + rollback
runbook): "Clean uninstall path documented + tested end-to-end."
Per founder-success-criteria: deploying on the work-AWS account
raises blast radius; the operator MUST be able to back out cleanly
if any phase MRR-8 sign-off discovers a blocker.

## **Stage A gap (flagged for follow-up)**

The MRR-1 audit and a scan of `scripts/` did NOT find a
first-class uninstall command. Operators today appear to need to
manually `pip uninstall`, remove `~/.iam-jit/`, stop launchd
agents. Per `[[mrr-flight-readiness-program]]` MRR-4 acceptance
("uninstall command tested end-to-end on clean macOS + Linux
container") this scenario's PASS criteria depend on `iam-jit
uninstall` (or equivalent) being shipped first.

The spec below assumes a future `iam-jit uninstall` exists. If
Stage B starts before the uninstall command ships, this scenario
emits `SKIP` with `reason: "iam-jit uninstall command not shipped;
see MRR-4 dependency"`.

## Pass criteria (assumes `iam-jit uninstall` exists)

1. Start from a populated state: profile installed, dynamic-denies
   present, bouncers running, audit DB with events.
2. Run `iam-jit uninstall --yes`.
3. Verify NO processes left:
   * `pgrep -f ibounce` returns empty.
   * `pgrep -f gbounce` returns empty.
   * No supervisor entries pointing at iam-jit binaries.
4. Verify NO files left:
   * `~/.iam-jit/` removed (or only an empty marker file remains
     per the uninstall contract).
   * No iam-jit launchd plists on macOS / systemd units on Linux.
   * `which iam-jit` returns non-zero (Python package uninstalled).
   * `which gbounce` returns non-zero (Go binary removed).
5. Verify re-install from clean works (chains to L1):
   * `pip install -e .` succeeds.
   * `iam-jit posture` works on a freshly-cleaned system.

## Fail criteria

* Any iam-jit process left running after uninstall.
* Any iam-jit file left in state dir without explicit
  uninstall-contract documentation.
* Re-install fails because of leftover state.
* Uninstall command crashes or leaves partial state.

## Prerequisites

* L1 + L2 PASS (need state to uninstall).
* **Mode B REQUIRED** — Mode A teardown is `docker rm`, which
  doesn't validate host-level uninstall claims. This scenario MUST
  run on a real host (or a Mode A container that lives across the
  uninstall + re-install — but that's still Mode B semantics).

## Supported isolation modes

* Mode B only.

## Expected duration

~5-10 minutes.

## Evidence block schema

```json
{
  "uninstall_command_exists": true,
  "uninstall_exit_code": 0,
  "ibounce_processes_after": 0,
  "gbounce_processes_after": 0,
  "iam_jit_home_removed": true,
  "launchd_plists_removed": true,
  "iam_jit_binary_removed": true,
  "gbounce_binary_removed": true,
  "reinstall_succeeded": true
}
```
