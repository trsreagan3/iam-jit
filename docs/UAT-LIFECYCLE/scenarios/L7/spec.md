# L7 — Crash recovery

## What this tests

SIGKILL a bouncer mid-traffic → restart → SQLite intact → audit chain
continuous → no data loss → no orphaned ports.

## Why this matters

Process crashes happen. The system claim "audit chain is continuous"
is only honest if it survives a hard-kill. Per
`[[canary-redeploys-on-every-update]]` graceful SIGTERM is tested via
L3; this scenario tests the harder SIGKILL path that L3 does NOT
cover.

## Pass criteria

1. Bring up bouncers + drive baseline activity (record audit tail
   sequence N).
2. Start a continuous traffic generator (1 request/sec).
3. SIGKILL the bouncer (NOT SIGTERM — bypasses graceful shutdown).
4. Wait 5 seconds.
5. Restart the bouncer via the supervisor / launchd / `iam-jit
   canary update --restart-only` (whichever the canary uses).
6. Wait for `/healthz` to return 200 (max 30s).
7. Verify post-restart state:
   * SQLite audit DB opens cleanly (no `database is locked` error).
   * Audit chain continuous — sequence N+1 is the next event after
     restart, NO gap. If a gap is unavoidable due to in-flight
     events lost on SIGKILL, the gap must be explicitly logged as a
     `process_killed` event with the missing-sequence range.
   * No orphaned port binding from the pre-crash process (the
     supervisor must clean stale binds).
   * Profile still loaded.

## Fail criteria

* SQLite reports `database is locked` or `malformed` post-restart.
* Audit chain has an UN-logged gap (sequence numbers jump silently).
* Port-bind fails because the pre-crash process's socket wasn't
  cleaned.
* Bouncer fails to restart within 30s.
* Profile not loaded (data-loss-on-restart pattern).

## Prerequisites

* L2 PASS.

## Supported isolation modes

* Mode A preferred (controlled SIGKILL inside container).
* Mode B acceptable.

## Expected duration

~3-5 minutes.

## Evidence block schema

```json
{
  "pre_crash_audit_tail_seq": 42,
  "sigkill_signal_sent": true,
  "restart_duration_sec": 4.1,
  "healthz_returned_200": true,
  "sqlite_opens_cleanly_post_restart": true,
  "audit_chain_continuous": true,
  "audit_gap_logged_if_present": true,
  "post_restart_first_seq": 43,
  "orphaned_port_bind_failure": false,
  "profile_loaded_post_restart": true
}
```
