# L15 — Dynamic-deny lifecycle

## What this tests

`iam-jit deny add` propagates across bouncers (cross-protocol fan-
out per #324) → verified denying matched traffic at every applicable
bouncer → `iam-jit deny revoke` propagates correctly + the deny
ceases to fire.

## Why this matters

Per `[[dynamic-deny-rules]]` (DECIDED 2026-05-22): "conversational
MCP-tool denies, cross-protocol fan-out, defense-in-depth via
bouncer + role." The marketing claim is "one command denies a target
everywhere it can possibly be reached." This is the lifecycle
regression for that claim.

## Pass criteria

Two variants:

**Variant A — ibounce + gbounce fan-out (URL target with embedded ARN)**

1. Bring up ibounce + gbounce in the scenario state dir.
2. Drive baseline: matching traffic ALLOWED on both bouncers.
3. Run `iam-jit deny add --target 'arn:aws:s3:::test-secret-bucket'
   --duration 1h`.
4. Assert:
   * Exit 0.
   * `~/.iam-jit/dynamic-denies.yaml` contains the new rule.
   * Both bouncers' `/admin/dynamic-denies/reload` was POSTed
     successfully (observable in canary status or audit).
   * Hot-reload completed within 2s.
5. Drive matching traffic again:
   * ibounce: deny event with the rule-id annotated.
   * gbounce: pre-signed URL touching the bucket also denied
     (cross-protocol fan-out).
6. Run `iam-jit deny revoke <RULE_ID>`.
7. Assert:
   * Rule removed from YAML.
   * Both bouncers reloaded.
   * Matching traffic now allowed again.

**Variant B — unreachable bouncer (per the project memory)**

1. Same setup, but stop gbounce before running `iam-jit deny add`.
2. Run `iam-jit deny add ...`.
3. Per the dynamic-deny CLI contract: YAML still written; gbounce
   surfaced as unreachable; CLI still exits 0 (YAML is source of
   truth).
4. Restart gbounce; assert it picks up the rule on next start.

## Fail criteria

* Variant A: rule not present in YAML after `add`.
* Variant A: hot-reload didn't trigger — bouncer keeps allowing.
* Variant A: `revoke` exits 0 but rule still in YAML (#463 shape).
* Variant A: cross-protocol fan-out misses gbounce (rule applies
  to ibounce only).
* Variant B: CLI fails when bouncer is unreachable (contract says
  it should still exit 0 + write the YAML).
* Variant B: restarted bouncer doesn't pick up the rule.

## Prerequisites

* L2 PASS.

## Supported isolation modes

* Mode A preferred. Mode B acceptable.

## Expected duration

~5-8 minutes (both variants).

## Evidence block schema

```json
{
  "variant": "A|B",
  "add_exit_code": 0,
  "yaml_contains_rule": true,
  "hot_reload_count": 2,
  "hot_reload_duration_sec": 1.2,
  "ibounce_denied_matching": true,
  "gbounce_denied_matching": true,
  "revoke_exit_code": 0,
  "yaml_lacks_rule_post_revoke": true,
  "traffic_allowed_post_revoke": true,
  "unreachable_bouncer_handled": true,
  "restarted_bouncer_picked_up_rule": true
}
```
