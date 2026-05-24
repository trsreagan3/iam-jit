# L9 — Audit log rotation lifecycle

## What this tests

Audit DB grows past hot/warm/cold tier transitions per Phase F →
old data purged per retention policy → chain continuity preserved
across rotation.

## Why this matters

`[[logging-system-comprehensive]]` Phase F mandates "persistent +
UI-queryable + OCSF + forensics-helpful + NEVER fills disk." The
rotation path is the bridge between "audit grows linearly" and
"never fills disk." If rotation breaks the chain, forensics is
broken. If retention deletes wrong data, compliance is broken.

## Pass criteria

1. Seed audit DB with N events spanning the rotation boundaries:
   * `now-30d` events (hot tier)
   * `now-90d` events (warm tier)
   * `now-365d` events (cold tier / purge boundary)
2. Trigger rotation (`iam-jit audit rotate` OR the configured
   scheduler tick).
3. Assert tier transitions:
   * `now-30d` events still in hot tier.
   * `now-90d` events moved to warm tier (separate table or file).
   * `now-365d` events purged OR archived per retention config.
4. Assert chain continuity:
   * Sequence numbers still strictly increasing across tier
     boundaries.
   * Hash chain still verifiable end-to-end via
     `iam-jit audit verify-chain`.
5. Assert query-path covers all tiers:
   * `bounce_query_audit_long_range` with a `now-100d` window
     returns warm-tier events.
6. Assert purged events leave a tombstone (sequence-number gap
   logged with explicit purge reason — same discipline as L7
   crash gap).

## Fail criteria

* Sequence numbers gap silently across tier boundary.
* Hash chain verify fails post-rotation.
* Purged events disappear without tombstone.
* Query path returns warm-tier events but misses cold-tier
  ones in a window that should include both.

## Prerequisites

* L2 PASS.
* `fixtures/audit-events/` generator for seeding multi-tier
  events.

## Supported isolation modes

* Mode A or Mode B.

## Expected duration

~5-10 minutes (seeding the DB dominates).

## Evidence block schema

```json
{
  "seeded_event_count_hot": 100,
  "seeded_event_count_warm": 100,
  "seeded_event_count_cold": 100,
  "rotation_completed": true,
  "hot_count_post": 100,
  "warm_count_post": 100,
  "cold_count_post": 0,
  "chain_verify_passed": true,
  "query_covers_warm_tier": true,
  "purge_tombstone_present": true
}
```
