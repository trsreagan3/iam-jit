# L2 — Bootstrap declaration → bouncer start in discovery mode

## What this tests

A hand-written `.iam-jit.yaml` declaration → bouncers come up cleanly
in discovery (pass-through) mode → `iam-jit canary verify-setup`
reports GREEN. This is the "one declaration to safety" path per
`[[ambient-autonomous-protection]]` exercised at its honest floor:
without an MCP-driven setup agent.

## Why this matters

The MRR-1 audit flagged use case 20 (`iam_jit_setup_from_config`
never E2E-tested) as a CRIT. This scenario gives the
zero-agent-required baseline: an operator who hand-edits the YAML
should still get a clean bring-up. If hand-bootstrap is broken, the
MCP-driven path is also broken.

## Pass criteria

1. Place a known-good `.iam-jit.yaml` at
   `${IAM_JIT_HOME}/canary/.iam-jit.yaml`.
2. Run `iam-jit canary verify-setup` — exits 0.
3. ibounce + gbounce processes are alive (PIDs in the verify-setup
   output).
4. Both bouncers report `mode: discovery` via their `/admin/posture`
   endpoints OR `iam-jit posture` reflects it.
5. Audit DB is created at `${IAM_JIT_HOME}/audit.db` AND is writable.
6. NO denies fire on a normal pass-through request (e.g.,
   `curl https://example.com` through gbounce in discovery).

## Fail criteria

* `verify-setup` exits non-zero.
* Either bouncer fails to bind to its declared port within 30s.
* Discovery-mode pass-through denies a request that should pass.
* Audit DB not created OR not writable.

## Prerequisites

* L1 PASS (install) — chain dependency.
* `fixtures/canary-yaml/L2-minimal.iam-jit.yaml` present.

## Supported isolation modes

* Mode A (preferred). Mode B acceptable.

## Expected duration

~2-4 minutes.

## Evidence block schema

```json
{
  "verify_setup_exit_code": 0,
  "ibounce_pid": 12345,
  "gbounce_pid": 12346,
  "ibounce_port_bound": true,
  "gbounce_port_bound": true,
  "ibounce_mode": "discovery",
  "gbounce_mode": "discovery",
  "audit_db_exists": true,
  "audit_db_writable": true,
  "pass_through_request_denied": false
}
```
