# L8 — Disk pressure circuit breaker

## What this tests

Disk fill simulation OR direct threshold test → verify breaker fires
→ simulate recovery → verify resumption.

## Why this matters

Per `[[logging-system-comprehensive]]`: "disk-pressure circuit breaker
is THE critical gap (uncaught disk fill = system crash)." An audit
log that writes itself to death takes the whole bouncer with it. The
breaker is the safety net. This scenario regresses it.

The existing unit test
(`tests/bouncer/test_disk_pressure_circuit_breaker.py`) verifies the
threshold logic; this scenario verifies the END-TO-END behaviour:
under simulated pressure, does the bouncer actually stop writing +
emit the right operator-visible signal?

## Pass criteria

Two variants:

**Variant A — threshold simulation (preferred; deterministic)**

1. Bring up bouncer in scenario state dir.
2. Mock the `free_disk_bytes()` syscall (test hook) to return a
   value BELOW the configured threshold (default: 500MB free).
3. Drive 5 audit-event-writing requests.
4. Assert breaker fires:
   * Bouncer log line `disk_pressure_circuit_breaker: TRIPPED` with
     the free-bytes value.
   * Subsequent writes are dropped (or buffered to a tmpfs ring;
     spec-dependent) with explicit operator-visible signal — not
     silent.
   * Bouncer continues serving requests in pass-through mode
     (degraded but alive — better than crashed).
5. Restore mock to ABOVE threshold.
6. Assert breaker resets:
   * Log line `disk_pressure_circuit_breaker: RECOVERED`.
   * Writes resume.
   * If buffered, the buffered events are flushed.

**Variant B — real disk fill (Mode A container only)**

1. Container created with `--tmpfs /root/.iam-jit:size=10m`.
2. Drive writes that fill the tmpfs.
3. Confirm breaker trips before tmpfs is fully exhausted (margin
   is the threshold).
4. Confirm bouncer doesn't crash on the next syscall when there
   IS zero bytes free.

## Fail criteria

* Breaker doesn't fire (writes continue + bouncer crashes on full
  disk).
* Breaker fires silently (no operator-visible signal).
* Breaker fires but bouncer also dies (defeats the purpose).
* Recovery doesn't happen after free-bytes restored.

## Prerequisites

* L2 PASS.
* Test hook for `free_disk_bytes()` (for Variant A) — STAGE-B
  must verify this hook is exported.

## Supported isolation modes

* Variant A: Mode A or Mode B.
* Variant B: Mode A only (needs tmpfs).

## Expected duration

~5-8 minutes (both variants).

## Evidence block schema

```json
{
  "variant": "A|B",
  "free_bytes_below_threshold": true,
  "breaker_tripped_log_emitted": true,
  "writes_dropped_or_buffered": "dropped",
  "bouncer_alive_during_trip": true,
  "pass_through_mode_active": true,
  "free_bytes_above_threshold_recovery": true,
  "breaker_recovered_log_emitted": true,
  "writes_resumed_post_recovery": true
}
```
