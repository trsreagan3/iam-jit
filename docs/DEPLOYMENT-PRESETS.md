# Deployment Presets

A **deployment preset** is a named bundle of `run`-command flag values
that activates a common deployment shape with one flag instead of
seven. Presets are SHORTCUTS — every preset value can be set
explicitly; the preset just makes the canonical combinations
discoverable + one-flag for the operator.

This doc covers ibounce; per `[[cross-product-agent-parity]]` the
same preset NAMES + same HARD-vs-SOFT override semantics ship across
**ibounce / kbounce / dbounce / gbounce**. A product may SKIP a
preset setting it doesn't have a subsystem for (e.g. gbounce in
G-Slice 1 has no alert-rules engine), but it will not ERROR on that
setting — the banner annotates `not applicable to this product`.

## The mechanism

A preset is a `(name, description, values)` record where `values` is
a map keyed by run-command parameter with an explicit
**override policy** per entry:

- **HARD** — operator passing the flag with a DIFFERENT value errors.
  The preset's whole point depends on this setting; overriding it
  silently would yield a deployment shape that does not match what
  the operator asked for.
- **SOFT** — operator's value wins; the preset value is the default
  the operator gets when they leave the flag unset.

The preset resolution runs BEFORE downstream validation gates so the
license / SSRF / loopback-bind checks see the preset-resolved values,
not the raw input.

The startup banner names the active preset + lists every derived
setting (with hard/soft annotation) so the operator sees exactly
what changed. Format is identical across all four Bounce products.

### Detecting "operator-supplied" vs default

- Python (ibounce): Click 8+ `ctx.get_parameter_source()` —
  `COMMANDLINE` / `ENVIRONMENT` / `PROMPT` all count as operator-
  supplied; only `DEFAULT` / `DEFAULT_MAP` leave the preset value
  in place.
- Go (kbounce / dbounce / gbounce): `cmd.Flags().Changed("flag-
  name")` returns `true` for any explicit `--flag VALUE` (including
  `--flag=VALUE`) regardless of source.

## Available presets (v1.0)

| Preset | What it activates | When to use |
|---|---|---|
| `security-observe` | transparent mode + JSONL audit + alert-rules defaults + 30s heartbeat + default-policy=allow | Security team gathering data for profile-building per `[[bouncer-mode-selection-for-agents]]`. |

### `security-observe`

The canonical "security-team observation" shape — what a security
team running ibounce/kbounce/dbounce/gbounce for the first time
wants. See `docs/IBOUNCE.md#security-team-observation-preset---preset-security-observe`
for the full ibounce treatment + `docs/SECURITY-TEAM-AUDIT-EXPORT.md`
for the cross-product audit-export memo.

**HARD**: `--mode` (transparent is the whole point)
**SOFT**: `--audit-log-path`, `--alert-rules`, `--heartbeat-interval`, `--default-policy`

## Roadmap (post-v1.0)

The deployment-preset framework is built to add more presets without
schema migrations or breaking-change cycles. Queued presets:

| Preset | Planned shape | Use case |
|---|---|---|
| `dev-loop` | cooperative + safe-default profile + `--prompt-on-deny` | Solo-dev iteration where the operator wants advisory denies + per-call review without enforcement |
| `production-strict` | transparent + strict profile + no overrides + JSONL only | Locked-down production deployments where any preset deviation is an alert-worthy event |
| `compliance-audit` | transparent + all-alerts + per-session recording (#285) | Compliance evidence-gathering shape that maximizes audit fidelity |

These are NOT shipped in #254. Per `[[deliberate-feature-
completion]]` the framework ships with one preset; the next presets
ship when their target use case has a concrete operator asking.

## Cross-product alignment

A single command runs the SAME preset across every Bounce product
that has the relevant subsystem:

```sh
ibounce  run --preset security-observe
kbounce  run --preset security-observe
dbounce  run --preset security-observe
gbounce  run --preset security-observe   # skips alert-rules; banner annotates
```

This is intentional per `[[cross-product-agent-parity]]`: an SRE
runbook that says "spin up the Bounce suite in observation mode"
maps to one flag name regardless of which proxy is in scope.

## Future: custom presets

Not in v1.0. The framework already supports arbitrary preset names;
post-v1.0 we may expose a `~/.iam-jit/presets/<name>.yaml` shape so
operators can author their own org-specific deployment shapes
without code changes. Pre-ship discipline (per `[[v1-scope-bar]]`):
ship `security-observe` first; add the custom-preset surface when
3+ operators ask.
