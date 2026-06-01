# Soak-Test Harness

**UAT improvement #1** — observer harness for state-honesty invariants.

## The gap it fills

UAT measures actions ("function X returns Y on a fresh fixture").
The bugs that have consistently slipped through are *state-shaped*: after
hours or days of running, `/healthz` says one thing, posture says another,
and the audit log says a third.

Canonical example: **#711** — `decisions_count=93` but zero audit events
written, undetected for 5 days.

This harness periodically samples the **live state** of the operator's
running bouncers, asserts cross-component invariants, and surfaces violations.

## Phase 1 (this harness): observe-only

- Samples ibounce + gbounce on their default mgmt ports
- No spin-up, no destructive ops
- All output in `/tmp/soak-test-2026-06-01/`

## Phase 2 (planned): controlled CI soak

Controlled environment (LocalStack + docker-compose), reproducible fixture,
runs in CI on every PR to `main`.

## Quick start

```bash
# Default: 60-minute soak at 60-second intervals
python tools/soak_test/run.py

# Short smoke run (5 samples, 10 seconds apart ≈ 1 minute)
python tools/soak_test/run.py --interval 10 --duration 1

# Options
python tools/soak_test/run.py --help
```

Output goes to `/tmp/soak-test-2026-06-01/`:

| File | Description |
|------|-------------|
| `samples/<ts>.json` | One JSON file per cycle |
| `timeline.jsonl` | Every sample appended (NDJSON) |
| `violations.md` | Violation report, updated live |
| `summary.md` | Final report written at end of soak |

## Invariants checked

| Code | Name | Description |
|------|------|-------------|
| VIOLATION-1 | silent-audit-gap | `decisions_count > 0` but audit_export not configured + `log_total_events = 0`. Reproduces #711. |
| VIOLATION-2 | audit-configured-not-writing | Audit configured but `log_total_events` stays at 0 while decisions are made. |
| VIOLATION-3 | counter-regression | `decisions_count` or `audit_log_total` decreases between samples. Possible silent restart. |
| VIOLATION-4 | posture-healthz-mismatch | `posture` says bouncer RUNNING but `/healthz` says otherwise (or vice versa). |
| VIOLATION-5 | audit-degraded-mismatch | `posture` and `/healthz` disagree on `audit_log.status = degraded`. |
| VIOLATION-6 | denies-fan-out-missing | A running bouncer is absent from `iam-jit denies recent` fan-out. |
| VIOLATION-7 | audit-queue-stalled | `audit_export.queue_depth > 0` for 5+ consecutive samples. |
| VIOLATION-8 | false-degraded | `/healthz audit_log.status = degraded` but disk_free_pct > 4% AND actual free > 5 GiB. |

## Running the pytest wrapper (CI layer)

```bash
# Synthetic unit tests only (no live bouncers needed):
pytest tests/test_soak_invariants.py -v -m "not live"

# Live bouncer tests (requires ibounce on :8767 + gbounce on :8769):
pytest tests/test_soak_invariants.py -v -m live

# Everything:
pytest tests/test_soak_invariants.py -v
```

The `live` tests collect ONE sample from the running bouncers and run
the invariant checks against it. They catch violations visible in a single
snapshot (V1, V4, V5, V8). Violations that require time to surface (V3
counter regression, V7 queue stall) still need the full 60-minute soak.

## Architecture

```
tools/soak_test/
  run.py          — sample loop, file I/O, CLI entry point
  invariants.py   — invariant engine (pure: sample-in, violations-out)

tests/
  test_soak_invariants.py — pytest wrapper (synthetic + live tests)
```

The invariant engine (`invariants.py`) is intentionally isolated from all
I/O. Any future test can import `check_invariants()` and `SamplePair`
directly to run invariant checks against synthetic fixtures — no live
bouncers needed.

## Standing constraints

- **Never** kill PIDs 86597 (gbounce) or 87794 (ibounce)
- **Never** write to `~/.gbounce/`, `~/.iam-jit/`, `~/.aws/`, etc.
- Read-only access to those directories is fine
- All runtime output goes to `/tmp/soak-test-2026-06-01/`

## Phase 2 plan

1. Add `compose.soak.yaml` with ibounce + gbounce wired to LocalStack
2. Drive synthetic traffic (N decisions, M denies) via the MCP test harness
3. Run the soak for a fixed time window (e.g. 5 minutes)
4. Assert zero VIOLATION-1 through VIOLATION-8 in `summary.md`
5. Add to CI as `make soak-ci`
