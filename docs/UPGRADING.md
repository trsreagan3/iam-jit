# Upgrading iam-jit

How to safely upgrade across version boundaries. iam-jit uses
[Semantic Versioning](https://semver.org/) for both the software
and the scorer corpus (tracked separately).

## Versioning model

- **Software version** (PATCH / MINOR / MAJOR): change to code,
  endpoints, dependencies, schema.
- **Scorer / corpus version** (separate): the calibrated scoring
  rules + corpus. Tracked via `IAM_JIT_SCORER_VERSION` env var
  (`YYYY-MM` format).

You can upgrade software without changing scorer, and vice
versa. This is critical for compliance — customers can patch
CVEs without their scoring policy shifting under them.

## Software upgrade types

| Version bump | Means | Required action |
|---|---|---|
| PATCH (1.0.X) | Bug fixes, security fixes | `pip install --upgrade` or `sam deploy` — no migration |
| MINOR (1.X.0) | New features, backward-compatible | Same as PATCH; read CHANGELOG for new env vars / endpoints |
| MAJOR (X.0.0) | Breaking changes; possible schema migration | Read `docs/UPGRADING-N-to-N+1.md` for the specific transition |

## Standard upgrade procedure

### Hosted SaaS (Indie / Pro / Team)

No customer action. We deploy automatically. Admin UI shows the
current version + last deploy time.

### Self-host (Free / Pro+self-host / Team+self-host / Enterprise)

```bash
# 1. Subscribe to releases (one-time)
#    https://github.com/trsreagan3/iam-jit/releases (Watch)
#    OR email opt-in at releases@iam-jit.dev (when available)

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
curl https://your-iam-jit/api/v1/health/version
# Should show the new version
```

### Partner-hosted deployments

Your partner follows the SLA in their contract. iam-jit notifies
them on disclosure day; they coordinate the patch with your
change window.

## Scorer version upgrades

The scorer version is INDEPENDENT of the software version. To
upgrade the scorer:

```bash
# Set the new scorer version
export IAM_JIT_SCORER_VERSION=2026-06   # for example

# Restart iam-jit (sam deploy with the new env var)
```

Each scorer version ships with a **calibration delta report**
at `docs/scorer-deltas/SCORER-DELTA-{from}-to-{to}.md` showing:

- Rules added / changed / removed
- Sample policies that scored differently between versions
- Adversarial-loop convergence numbers for the new version

**Read the delta report before upgrading the scorer.** A policy
scoring 6/10 today might score 7/10 tomorrow if the scorer
tightens — that may break your auto-approve threshold without
warning.

To pin to the current scorer version (for stability):

```bash
# In your SAM template or Lambda env config
IAM_JIT_SCORER_VERSION=2026-05  # or whatever was current at v1
```

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
