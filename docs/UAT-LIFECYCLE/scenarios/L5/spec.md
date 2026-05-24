# L5 — Profile lifecycle (discovery → generate → install → enforce → improve → revert)

## What this tests

The full profile lifecycle promised by the marketing copy:

1. Discovery accumulates audit events from real activity.
2. Agent generates a profile from the audit via
   `bounce_profile_generate_from_audit`.
3. `bounce_profile_save` installs it.
4. Mode-switch (discovery → enforce); previously-allowed-now-out-of-
   profile traffic gets denied.
5. `iam_jit_improve_profile` suggests additions based on observed
   denies.
6. Rollback works (revert to previous profile; state restored).

## Why this matters

MRR-1 audit CRIT #1: "audit → profile → install → iterate composition
has NEVER been exercised end-to-end." This scenario IS that
end-to-end exercise. It is the load-bearing claim for ambient
autonomous protection.

## Pass criteria

1. **Discovery accumulation**: bring up bouncer in discovery mode;
   drive synthetic activity (10 distinct HTTP hosts for gbounce, 10
   AWS API calls for ibounce via LocalStack). Confirm 10 distinct
   audit events per bouncer.
2. **Profile generation**: call `bounce_profile_generate_from_audit`
   with the activity window. Tool returns a YAML profile; assert
   non-empty `rules` list AND each rule matches at least one observed
   event.
3. **Profile installation**: call `bounce_profile_save` with the
   generated YAML. Assert (state-verification) the file lands on
   disk at the expected path AND the bouncer hot-reloads it.
4. **Mode switch + enforce**: switch bouncer to `enforce` mode; issue
   a request that is OUT of the generated profile; assert it is
   DENIED at the bouncer with an OCSF-shaped audit event.
5. **Improve suggestion**: with one or more denies in audit, call
   `iam_jit_improve_profile`. Tool returns suggested additions
   matching the denied traffic. Assert structure + matching.
6. **Rollback**: snapshot pre-modification profile; install
   suggested additions; revert via filesystem replace; assert
   bouncer hot-reloads back to original.

## Fail criteria

* Discovery audit count != expected count (events lost).
* Generated profile has zero rules (#326/#448 shape — status
  claimed install but profile empty).
* Hot-reload doesn't pick up the new profile.
* Out-of-profile request is NOT denied in enforce mode.
* `improve_profile` returns suggestions that don't match the
  observed denies.
* Rollback claims success but profile-on-disk still has the
  added rules (#463 shape).

## Prerequisites

* L1, L2 PASS.
* LocalStack available for ibounce variant.
* Synthetic activity fixtures (`fixtures/workflows/`).
* MCP server reachable from the operator's agent.

## Supported isolation modes

* Mode A (preferred — clean per-run state).
* Mode B acceptable for the gbounce variant; ibounce variant
  needs LocalStack which is more reliably containerized.

## Expected duration

~15-20 minutes (multi-step + hot-reload waits).

## Evidence block schema

```json
{
  "discovery_audit_event_count": 10,
  "generated_profile_rules_count": 8,
  "generated_rules_match_observed_events": true,
  "profile_install_persisted_to_disk": true,
  "hot_reload_picked_up_new_profile": true,
  "enforce_mode_denied_out_of_profile": true,
  "improve_profile_suggestions_match_denies": true,
  "rollback_restored_original_profile": true
}
```
