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
