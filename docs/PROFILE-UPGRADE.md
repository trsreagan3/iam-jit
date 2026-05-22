# Profile upgrade runbook (`*bounce profile doctor`)

Status: SHIPPED 2026-05-22 (task #321 / KNOWN-CAVEATS §A19).

Applies to: ibounce, kbouncer, dbounce, gbounce (v1.0 doctor is a no-op
on gbounce per the architectural-honesty note below).

## Updated 2026-05-22 — DEFAULT MODE FLIPPED TO DISCOVERY

Per `[[discovery-first-default]]` (founder direction 2026-05-22) +
KNOWN-CAVEATS §A21 (BREAKING-CHANGE), all 4 bouncers now default to
**discovery mode** (observe + audit + pass-through). The `safe-default`
profile remains first-class but is OPT-IN only.

What this means for the upgrade path:

- **Fresh installs land in discovery mode.** The doctor still ships the
  `safe-default` profile to disk via `EnsureDefaultProfilesFile`, so
  `safe-default` is available to opt into immediately — but no profile
  is auto-applied at runtime.
- **Pre-pivot operators on a build that auto-applied `safe-default`
  silently must explicitly opt in** to keep that behavior post-upgrade:
  - ibounce: `ibounce run --profile safe-default` OR
    `export IAM_JIT_BOUNCER_PROFILE=safe-default`
  - kbouncer: `kbounce run --profile safe-default` OR
    `export KBOUNCER_PROFILE=safe-default`
  - dbounce: `dbounce run --profile safe-default` OR
    `export DBOUNCE_PROFILE=safe-default`
  - gbounce: discovery has always been the default; no migration needed.
    Layer `--deny-host` / `--profile-rules-file` for opt-in denies.
- **The doctor's safety-floor field catalog is unchanged.** Whether or
  not the operator opts into the profile, the doctor still surfaces
  missing fields in `safe-default` so when the operator DOES pin
  `--profile safe-default`, they get the full floor.

`docs/role-effectiveness-grades-post-pivot.md` (under `tests/dogfood/`)
captures the re-grade. The pre-pivot grades remain at
`tests/dogfood/role-effectiveness-grades.md` for historical comparison.

## What this is

Every Bounce product ships a curated `safe-default` profile that
encodes the per-product safety floors (which actions / statements /
verbs / hosts the proxy refuses by construction). On first launch
each bouncer writes its embedded default profile to the operator's
home directory:

- ibounce → `~/.iam-jit/bouncer/profiles.yaml`
- kbouncer → `~/.kbouncer/profiles.yaml`
- dbounce → `~/.dbounce/profiles.yaml`
- gbounce → no shipped profiles.yaml in v1.0 (rules are explicit-file
  via `--profile-rules-file`; see §gbounce-special-case below)

Once that file exists, the bouncer **NEVER** overwrites it. This is
the right default for operator-customized state — your edits survive
upgrades — but it has a sharp edge:

**Sharp edge.** When a new safety floor is added to embedded
defaults in a later version (e.g. dbounce #302 added the
`deny_dcl_targets_public` floor that catches `GRANT * TO PUBLIC`
privilege escalation), operators whose `profiles.yaml` predates that
release silently run **WITHOUT** the floor. The safety claim
("`GRANT ... TO PUBLIC` is blocked under safe-default") becomes
silently false on their install.

`*bounce profile doctor` exists to close that blind spot.

## What it does

The subcommand diff-checks your installed `profiles.yaml` against
the embedded shipped defaults + reports any fields your local file
is missing. **It does NOT auto-overwrite** — you may have customized
fields deliberately, and the bouncer respects that. The doctor only
**reports**; the operator opts into merging via `--apply`.

```
$ ibounce profile doctor

ibounce: profile doctor — your installed profile is missing 1 field(s) that ship in this version (defaults version 2026-05-22-321):

  - profile=safe-default field=allow_baseline
    category:   safety-floor
    why:        Names the AWS-managed-readonly baseline that gates EVERY action through policy_sentry's Read+List classification. Without this, only deny_actions + deny_actions_with_condition run — any Write-classified action the deny list doesn't enumerate (sts:AssumeRole, lambda:Invoke, iam:PassRole, etc.) passes by default.
    added in:   ibounce 0.5.0 (#220, 2026-05-17)
    default:    'aws_managed_readonly_access'

To accept the new defaults: ibounce profile doctor --apply
To suppress this warning:   ibounce profile doctor --acknowledge
```

## Field categories

Each missing default is classified into one of four categories. The
category determines whether the missing field triggers the **startup
banner warning** on `*bounce run`:

| Category | Triggers startup banner? | Examples |
| --- | --- | --- |
| `safety-floor` | YES | `deny_dcl_targets_public` (dbounce); `deny_subresource_writes` (kbouncer); `allow_baseline` (ibounce) |
| `detection` | no | burst-detector, prompt-injection sniffers |
| `audit` | no | preset versions, decision_source extensions |
| `convenience` | no | TTL defaults, profile naming, UX flags |

The startup banner only fires for `safety-floor` misses because those
are the kind that silently make the safety claim false. Convenience
misses surface only when you explicitly run `profile doctor`.

## Commands

### Inspect (default)

```bash
ibounce profile doctor
kbounce profile doctor
dbounce profile doctor
gbounce profile doctor  # v1.0: always reports current — see §gbounce-special-case
```

Exit code: `0` if current; `2` if any field is missing.

### Apply additively

```bash
ibounce profile doctor --apply
```

- Adds missing fields from shipped defaults (additive).
- Does **NOT** overwrite operator-customized field values.
- Backs up the prior profile to `<profiles.yaml>.bak-YYYYMMDD-HHMMSS`
  **before** writing.
- Per [[creates-never-mutates]]: additive only.

If you set a field to a non-default value deliberately
(e.g. `deny_dcl_targets_public: false`), the field is **present** in
your YAML → `--apply` skips it. The doctor cannot override an
explicit operator choice.

### Silence the warning

```bash
ibounce profile doctor --acknowledge
```

Writes a per-operator `.profiles-acknowledged-version` stamp next to
`profiles.yaml`. Future `*bounce run` startup banners skip the §A19
warning until a new shipped-defaults version bumps the stamp (which
re-arms the warning so you can review the new floor).

Note: `--acknowledge` silences the **startup banner only**. Explicit
`profile doctor` invocation still reports the gap — operators asking
should always get the truth.

### Show the diff `--apply` would write

```bash
ibounce profile doctor --diff
```

Prints the YAML fragment that `--apply` would add, so you can review
before you commit.

### Script-friendly modes

```bash
ibounce profile doctor --check     # silent; exit 0 if current, exit 2 if gaps
ibounce profile doctor --json      # machine-readable envelope
```

The JSON envelope has a stable contract — SIEM scripts can parse it
without a flag-version check:

```json
{
  "shipped_defaults_version": "2026-05-22-321",
  "installed_path": "/Users/operator/.iam-jit/bouncer/profiles.yaml",
  "missing": [
    {
      "profile": "safe-default",
      "field": "allow_baseline",
      "category": "safety-floor",
      "why": "Names the AWS-managed-readonly baseline...",
      "added_in": "ibounce 0.5.0 (#220, 2026-05-17)",
      "default": "aws_managed_readonly_access"
    }
  ]
}
```

## Startup-banner caveat

When a `safety-floor` field is missing AND no `.profiles-acknowledged-version`
matches the current shipped-defaults version, `*bounce run` emits a
one-line caveat to stderr on startup:

```
caveat: your safe-default profile is missing fields shipped in this version — run `ibounce profile doctor` for details (KNOWN-CAVEATS §A19)
```

Per [[security-team-positioning-safety-not-surveillance]]: this is
framed as "**your profile is behind**" — NOT "you are non-compliant."
The bouncer is on your side; the warning exists so an operator who
upgraded a year ago and never re-read the release notes doesn't
unknowingly run with a stale safety claim.

## The first-60-seconds workflow

When you upgrade a bouncer:

```bash
# 1. Upgrade the binary (Go: `go install`; Python: `pip install -U iam-jit`)
go install github.com/trsreagan3/dbounce/cmd/dbounce@latest

# 2. Check your installed profile against the new shipped defaults
dbounce profile doctor

# 3a. If there's only safety-floor misses: review + apply
dbounce profile doctor --diff   # see what would change
dbounce profile doctor --apply  # additively merge + back up

# 3b. If you'd prefer to acknowledge + decide later:
dbounce profile doctor --acknowledge

# 4. Start the proxy as usual — startup banner will be silent
dbounce run --profile safe-default
```

## gbounce special case (v1.0)

`gbounce` does not manage a shipped-default `profiles.yaml` in v1.0.
gbounce profile rules are loaded explicitly via
`--profile-rules-file` (JSON) or `--deny-host` / `--deny-hosts-file`
(newline / YAML list). There are no shipped defaults to be behind,
so `gbounce profile doctor` always reports "current" plus a Notes
line explaining the architectural difference:

```
$ gbounce profile doctor

gbounce: profile doctor — installed profile matches shipped defaults (version 2026-05-22-321).

gbounce v1.0 does not ship a default profiles.yaml; profile rules are loaded explicitly via --profile-rules-file (JSON) or --deny-host / --deny-hosts-file (newline / YAML list). There are no shipped defaults to be behind. G-Slice 2 will introduce a YAML profiles surface alongside the existing shapes; this surface will populate the doctor catalog at that time so older installs surface missing safety floors the same way dbounce / kbouncer / ibounce do today.
```

The doctor subcommand exists on gbounce for cross-product CLI parity
per [[cross-product-agent-parity]] — orchestrators that run
`<product> profile doctor` get a consistent shape across all four
Bounce products.

## Engineer note: extending the catalog

When you add a new field to a bouncer's embedded `defaults.yaml`,
you MUST also add a row to that bouncer's `shippedDefaultsCatalog`
(Go) / `SHIPPED_DEFAULTS_CATALOG` (Python). The
`TestDoctor_CatalogCoversEmbeddedDefaults` test (Go) /
`test_doctor_catalog_covers_defaults` (Python) enforces this — a CI
run will fail if you ship a new floor without wiring the upgrade
notification.

Bump `ShippedDefaultsVersion` in lockstep so operators who
acknowledged the prior version see the new warning. The version
stamp is consumed only by `--acknowledge`; bumping it doesn't
change any other product behavior.

## References

- KNOWN-CAVEATS.md §A19 — fix entry
- task #321 (this work)
- task #302 (dbounce DCL floor — the canonical example of a safety
  floor added after a version was shipped)
- [[cross-product-agent-parity]] — why all 4 products share the same
  flag shape
- [[creates-never-mutates]] — why `--apply` is additive only
- [[security-team-positioning-safety-not-surveillance]] — framing
  of the startup-banner caveat
