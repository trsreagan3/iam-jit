# L12 — Cross-bouncer update consistency

## What this tests

Update ibounce + gbounce together (atomic at the canary level) → both
restart cleanly → cross-bouncer audit query works post-update.

## Why this matters

Per `[[canary-redeploys-on-every-update]]` the canary tracks BOTH
ibounce + gbounce. A partial update (one bouncer at PRE_SHA, the
other at POST_SHA) is a real risk if the update mechanism doesn't
coordinate them. Cross-bouncer audit queries (per `[[posture-check-feature]]`)
must continue to function across the version skew.

## Pass criteria

1. Bring up ibounce + gbounce at PRE_SHA for both.
2. Generate cross-bouncer activity (ibounce sees AWS call,
   gbounce sees HTTP request; same task-correlation-id).
3. Snapshot per-bouncer versions + audit tail.
4. Run `iam-jit canary update` (single command, both bouncers).
5. Assert:
   * Both bouncers report POST_SHA via version-check.
   * `iam-jit posture` reports both running.
   * Cross-bouncer audit query (correlate the task-id) returns the
     pre-update events from BOTH bouncers.
6. Generate post-update cross-bouncer activity.
7. Assert post-update events queryable cross-bouncer (i.e., the
   schema didn't break the correlation).
8. Verify a half-failed update is rejected: simulate ibounce
   update success but gbounce failure (variant); assert canary
   rolls BOTH back (atomic-at-canary contract).

## Fail criteria

* Half-update succeeds silently (one bouncer at PRE, other at
  POST).
* Cross-bouncer audit query returns partial results post-update.
* Atomic-rollback variant doesn't roll back ibounce when gbounce
  fails.

## Prerequisites

* L3 PASS (single-bouncer happy path).
* L4 PASS (failure recovery exists).

## Supported isolation modes

* Mode A only (mutates source).

## Expected duration

~10-15 minutes.

## Evidence block schema

```json
{
  "pre_ibounce_sha": "...",
  "pre_gbounce_sha": "...",
  "post_ibounce_sha": "...",
  "post_gbounce_sha": "...",
  "both_version_check_match": true,
  "cross_bouncer_query_pre": 4,
  "cross_bouncer_query_post": 8,
  "atomic_rollback_test_passed": true
}
```
