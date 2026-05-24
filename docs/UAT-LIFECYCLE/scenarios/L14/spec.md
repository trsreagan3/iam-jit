# L14 — AWS credential rotation through ibounce

## What this tests

Daily AWS creds rotate (the normal short-lived-credentials cycle) →
ibounce continues working → no false denies on the cred-refresh
boundary.

## Why this matters

ibounce sits in front of AWS API calls. Real operators rotate creds
hourly, daily, on every assume-role. If ibounce caches the old creds
or fails the refresh boundary call, EVERY agent task fails until
restart. This scenario covers the canonical cred-rotation pain
point.

## Pass criteria

1. Bring up ibounce in front of LocalStack (mock AWS).
2. Configure ibounce with a mock-creds source that returns
   `AKIATEST...` creds with short TTL (5 minutes).
3. Drive 30 requests/sec for 10 minutes (spans 2 rotation
   boundaries).
4. Assert:
   * Zero `InvalidClientTokenId` errors observed in audit (all
     calls used valid-at-the-moment creds).
   * Zero `RequestExpired` errors (no stale signing-time).
   * Audit events span the rotation boundary continuously.
5. Manual rotation:
   * Trigger an explicit rotation mid-window (write new creds to
     the mock source).
   * Assert in-flight requests complete (with EITHER old or new
     creds, not failed).
   * Assert NO requests are denied as a false-positive due to
     the rotation.

## Fail criteria

* Any `InvalidClientTokenId` or `RequestExpired` in the audit
  stream.
* Any request denied as a false-positive at the rotation moment.
* ibounce requires restart to pick up rotated creds.

## Prerequisites

* L2 PASS.
* LocalStack running (Mode A preferred).
* Mock cred-source fixture
  (`fixtures/mock-creds/L14-rotating-creds-source.py`).

## Supported isolation modes

* Mode A only (needs LocalStack + cred-source coordination).

## Expected duration

~12-15 minutes (long traffic window to catch the rotation boundary
deterministically).

## Evidence block schema

```json
{
  "request_count_total": 18000,
  "invalid_token_errors": 0,
  "request_expired_errors": 0,
  "rotation_boundaries_crossed": 2,
  "false_positive_denies_at_rotation": 0,
  "manual_rotation_in_flight_completed": true,
  "restart_required_for_new_creds": false
}
```
