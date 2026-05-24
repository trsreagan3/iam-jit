# L6 — Threat-feed lifecycle

## What this tests

`iam-jit updates pin/list/dry-run/revoke` cycle for the threat-feed
subscription system: Ed25519 signature verification, dry-run plan,
real apply, rule applied + observable in bouncer state, revoke
removes from bouncer state.

## Why this matters

Bug #463 (catalogued in `docs/CONTRIBUTING.md`) was a threat-feed
revoke that claimed `status: revoked` while the rule was still live
in `dynamic-denies.yaml`. The state-verification convention was born
from this. This scenario is the dedicated lifecycle regression for
threat-feed flows.

## Pass criteria

1. **Setup**: signed test payload at
   `fixtures/threat-feed/L6-block-evil-host.signed.json` with the
   accompanying public test key `fixtures/threat-feed/L6-publisher.pub`.
2. **Pin publisher**: `iam-jit updates pin --publisher L6-test`
   adds the publisher to the trust store; observable in
   `~/.iam-jit/threat-feed-state/publishers.yaml`.
3. **List**: `iam-jit updates list` shows the pending feed payload.
4. **Dry-run**: `iam-jit updates dry-run` shows the plan (rules that
   WOULD be added) WITHOUT mutating `dynamic-denies.yaml`. Verify
   file mtime unchanged.
5. **Apply**: `iam-jit updates apply` actually adds the rules.
   Observable in `dynamic-denies.yaml` AND fan-out hot-reload
   triggered on each bouncer's `/admin/dynamic-denies/reload`
   endpoint.
6. **Verify effect**: traffic matching the threat-feed rule is now
   denied at the bouncer.
7. **Revoke**: `iam-jit updates revoke ${RULE_ID}` REMOVES the
   rule. Observable: rule absent from `dynamic-denies.yaml` AND
   ledger records the revoke event.
8. **Verify removal**: traffic previously denied is now allowed
   again (revoke effective).
9. **Tamper**: replay with an invalid signature → apply rejects
   with clear error.

## Fail criteria

* Dry-run mutates `dynamic-denies.yaml` (mtime change).
* `apply` claims success but rule absent from YAML.
* `revoke` claims success but rule still in YAML (#463 shape).
* Tampered payload accepted.
* Hot-reload not triggered after apply.

## Prerequisites

* L1, L2 PASS.
* Signed test payload + test public key in `fixtures/threat-feed/`.
* Bouncers running with `/admin/dynamic-denies/reload` reachable.

## Supported isolation modes

* Mode A preferred. Mode B acceptable.

## Expected duration

~5-8 minutes.

## Evidence block schema

```json
{
  "publisher_pinned_observable": true,
  "list_shows_payload": true,
  "dry_run_mutated_yaml": false,
  "apply_persisted_rule_to_yaml": true,
  "apply_triggered_hot_reload_count": 2,
  "rule_effective_traffic_denied": true,
  "revoke_removed_from_yaml": true,
  "revoke_recorded_in_ledger": true,
  "traffic_allowed_post_revoke": true,
  "tamper_signature_rejected": true
}
```
