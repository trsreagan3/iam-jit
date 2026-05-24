# L3 — Update mechanism end-to-end

## What this tests

The full `iam-jit canary update` cycle from a known pre-state to a
known post-state: `--dry-run` plan → real update → graceful restart
→ state preserved → version-check confirms new SHA → audit chain
sequence continuous.

## Why this matters

Per `[[canary-redeploys-on-every-update]]`: every merge to main on
iam-roles + gbounce triggers a canary redeploy. The update path is
exercised on every change. This scenario is the canonical regression
test for that loop.

## Pass criteria

1. Bring up bouncers at pre-state commit SHA `${PRE_SHA}`.
2. Generate some activity (pass-through requests → audit log entries).
3. Capture pre-state: bouncer versions, audit-log tail sequence
   number, current PIDs, profile contents.
4. Run `iam-jit canary update --dry-run` — exits 0, prints plan
   showing PRE→POST SHAs, NO state mutation occurs.
5. Run `iam-jit canary update` (real) — exits 0.
6. Verify post-update state:
   * Bouncer versions match expected POST SHA.
   * `*bounce version-check` confirms new SHA (catches
     version-constant-didn't-bump pattern).
   * Audit-log chain continuous — no sequence-number gaps across
     the restart boundary (per §A66c hash-chain wiring).
   * Profiles still loaded.
   * SQLite audit DB still openable + previous events still queryable.
   * `~/.iam-jit/canary/issues.jsonl` has a new line with
     `category: "update_success"`.

## Fail criteria

* `--dry-run` mutates any state.
* Real update exits non-zero (should trigger rollback, which is L4).
* Version-check reports stale version after install (the most common
  release-shipped-wrong-version bug).
* Audit-log chain has a sequence-number gap (chain broken across
  restart).
* SQLite DB unreadable or pre-update events missing.
* No `update_success` line appended.

## Prerequisites

* L1 + L2 PASS (chain).
* Two real commits in the iam-roles repo to update between
  (`${PRE_SHA}` and `${POST_SHA}`). Stage B uses
  `git log --oneline | head -10` to pick a recent pair; the fixture
  records the pair for reproducibility.
* Docker (Mode A) recommended — Mode B will mutate the host's
  iam-roles checkout, which is unsafe during active development.

## Supported isolation modes

* Mode A only (Mode B mutates operator's source tree).

## Expected duration

~5-10 minutes (dominated by pip/go reinstall + restart polling).

## Evidence block schema

```json
{
  "pre_sha": "abc123",
  "post_sha": "def456",
  "dry_run_exit_code": 0,
  "dry_run_mutated_state": false,
  "update_exit_code": 0,
  "ibounce_version_check_match": true,
  "gbounce_version_check_match": true,
  "audit_chain_continuous": true,
  "audit_pre_count": 17,
  "audit_post_count": 17,
  "profile_still_loaded": true,
  "issues_jsonl_appended": true,
  "restart_duration_sec": 12.4
}
```
