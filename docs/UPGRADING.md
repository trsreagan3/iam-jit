# Upgrading iam-jit

How to safely upgrade across version boundaries. iam-jit uses
[Semantic Versioning](https://semver.org/) for both the software
and the scorer corpus (tracked separately).

## Versioning model

The software ships as a single semver-tracked package. The
calibration corpus + scorer rules ship pinned to the wheel
version — upgrading the wheel upgrades the scorer too. A
future release may split scorer version from software version
(see `docs/ROADMAP-V1.1.md`); when that lands, this doc will
gain a `Scorer version upgrades` section.

## Software upgrade types

| Version bump | Means | Required action |
|---|---|---|
| PATCH (1.0.X) | Bug fixes, security fixes | `pip install --upgrade iam-jit` or `sam deploy` — no migration |
| MINOR (1.X.0) | New features, backward-compatible | Same as PATCH; read CHANGELOG for new env vars / endpoints |
| MAJOR (X.0.0) | Breaking changes; possible schema migration | Read `docs/UPGRADING-N-to-N+1.md` for the specific transition |

## Standard upgrade procedure

### Self-host (Free OSS or Enterprise self-host)

> **Opt-in version check (not phone-home).** Run `ibounce version-check`
> to compare your installed version against the latest GitHub release.
> It is operator-initiated only — never runs as a side-effect of any
> other subcommand, sends no data about your install, and is short-
> circuited entirely by `IBOUNCE_NO_VERSION_CHECK=1` (or the
> `IAM_JIT_NO_VERSION_CHECK` alias) for airgapped deployments. Result
> is cached for one hour at `~/.iam-jit/bouncer/version_check.json`.

```bash
# 1. Subscribe to releases (one-time)
#    https://github.com/trsreagan3/iam-jit/releases (Watch)

# 2. Pull the new tagged release
git fetch origin --tags
git checkout v1.X.Y

# 3. Review CHANGELOG.md for the version range
#    Look for "BREAKING CHANGES" sections

# 4. For minor/patch: run normal deploy
sam build && sam deploy

# 5. For major: see docs/UPGRADING-N-to-N+1.md
#    Run any migration scripts; deploy; verify

# 6. Verify the upgrade
curl http://127.0.0.1:8765/healthz   # or your deploy URL
# Returns posture; check the iam-jit Lambda's deployed version
# via `aws lambda get-function --function-name iam-jit` for the
# canonical software version.
```

### Enterprise dedicated-managed

Your contract specifies the upgrade SLA. iam-jit notifies the
managing party on disclosure day; they coordinate the patch
with your change window.

Per `feedback_enterprise_self_host_only`: there is no
multi-tenant hosted SaaS. Anyone running iam-jit is running it
on infrastructure they (or their managed-services partner)
control.

## Major-version migrations

When the software MAJOR version increments (X.0.0), look for a
dedicated upgrade guide at `docs/UPGRADING-N-to-N+1.md` (e.g.,
`docs/UPGRADING-1-to-2.md`).

Each major upgrade guide includes:

- A summary of breaking changes
- Required env-var renames or removals
- DDB schema migration steps (when applicable)
- `iam-jit migrate N-to-N+1` CLI subcommand (when available)
- Rollback procedure (you can always roll back the software;
  schema changes may not roll back cleanly)

## Backward-compatibility windows

We commit to:

- **API endpoints**: 2 minor-version deprecation window. The
  endpoint will log a deprecation warning when called, then be
  removed in minor+2.
- **Env vars**: 2 minor-version deprecation window. Old name
  keeps working with a log message; new name takes effect
  immediately.
- **DDB schema**: forward-compatible WITHIN a major version.
  Schema changes that aren't forward-compatible are deferred
  to a major-version boundary.

## Rolling back

### From a PATCH upgrade

Always safe to roll back:

```bash
git checkout v1.X.Y-1   # previous version
sam build && sam deploy
```

### From a MINOR upgrade

Usually safe to roll back, but check the CHANGELOG for any
"new env var" notes — if you started using one, removing it
on rollback may break the deployment.

### From a MAJOR upgrade

Software rollback is mechanical; schema rollback may not be
clean. Each major upgrade guide explicitly documents the
rollback procedure (often: "do NOT roll back the schema; the
new schema is forward-compatible with the old software").

## What to do if you hit issues

1. Check `docs/security/AUDIT-2026-*.md` for known issues in the
   release
2. Check the [GitHub Issues](https://github.com/trsreagan3/iam-jit/issues)
   for similar reports
3. Email `support@iam-jit.dev` (when available — pre-launch:
   `trsreagan3@gmail.com`) with:
   - The version you upgraded FROM and TO
   - Any error messages
   - Lambda CloudWatch logs (last 100 lines)
   - Whether you've tried rolling back

## Pre-launch (v0.x)

iam-jit is currently pre-1.0. Breaking changes can happen at
MINOR boundaries during this phase. Once v1.0 ships:

- Strict semver applies
- Backward-compat windows kick in
- Migration guides are committed for every major

## v1.0 notes — Bounce-suite rename (`iam-jit-bouncer` → `ibounce`)

The bouncer's canonical CLI name + MCP-tool prefix changed in v1.0
to align with the cross-product Bounce family (`ibounce` for AWS;
`kbounce` for K8s; future siblings under the same naming).

| Surface | Old (v0.x) | New (v1.0 canonical) | Backward-compat in v1.0 |
|---|---|---|---|
| Console script | `iam-jit-bouncer` | `ibounce` | `iam-jit-bouncer` keeps working; prints a stderr deprecation banner + forwards to the same entrypoint |
| MCP tools | `bouncer_*` | `ibounce_*` | Both names dispatch to the same handler; `bouncer_*` descriptions carry `(DEPRECATED — use ibounce_* in v1.1)` prefix |
| Profile name (passthrough) | `none` | `full-user` | `--profile none` still resolves; stderr deprecation banner emitted |
| Profile name (state-preservation floor) | `prod-readonly` (v1.0-alpha) → `readonly` (v1.0-alpha-2) | `safe-default` (v1.0 launch) | `--profile prod-readonly` and `--profile readonly` both still resolve to `safe-default`; stderr deprecation banner emitted. The architecture also changed (per `safe_default_is_readonly_admin_minus`): `safe-default` uses a `policy_sentry`-backed Read+List allow-baseline + sensitive-Read subtract list, not enumerated destructive verbs. Closes the Opus audit's CRIT gaps (`sts:AssumeRole`, `lambda:InvokeFunction`, `ssm:SendCommand`, `iam:PassRole`, `iam:Attach*Policy`, etc.) that the deny-verb model missed. |
| Doc file | `docs/IAM-JIT-BOUNCER.md` | `docs/IBOUNCE.md` | `git mv` preserves history |
| Launch post | `DONT-GIVE-CLAUDE-YOUR-AWS-KEYS.md` | `DONT-GIVE-CLAUDE-FULL-ADMIN.md` | `git mv` preserves history |

**Migration:** mechanical — swap `iam-jit-bouncer` → `ibounce` in any
scripts; rename `bouncer_*` → `ibounce_*` in any agent MCP allowlists.
Both old names work in v1.0 and are removed in v1.1.

**Not changed:** the `IAM_JIT_BOUNCER_*` env vars stay as the canonical
names in v1.0 (no `IBOUNCE_*` aliases are added — env-var alignment
happens in v1.1 alongside removal of the deprecation shims). HTTP
response headers `x-iam-jit-bouncer-*` also retain their old prefix
for v1.0 to keep agents + tooling that grep on them unchanged. The
default-active profile remains the passthrough; opt into the
state-preservation floor with `--profile safe-default` or
`export IAM_JIT_BOUNCER_PROFILE=safe-default` (`--profile readonly`
and `--profile prod-readonly` still resolve to `safe-default` in
v1.0 with a stderr deprecation banner; both aliases removed in v1.1).

**Moved community profiles:** the formerly-built-in `dev-only`,
`staging-work`, and `incident-response` profiles moved to
`tools/community-profiles/` (future home: `trsreagan3/bounce-profiles`).
Install them via `ibounce profile install --from URL`. If you depended
on these as built-ins, install them from the bundle before upgrading
to v1.1.

**Reason for the rename:** cross-product naming consistency. The
Bounce family ships `ibounce` (AWS API gating) + `kbounce` (K8s API
gating) + future siblings under one short, memorable, prefix-keyed
naming. The `iam-jit-bouncer` name conflated the umbrella brand
(`iam-jit`) with one specific product; the rename lets each Bounce
product market on its own ergonomics while still composing under the
parent brand.
