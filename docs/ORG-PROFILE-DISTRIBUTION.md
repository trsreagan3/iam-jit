# Distributing safety policy across your org

Status: documentation slice 2026-05-22 — companion to the
`bounce profile install --from URL` mechanics shipped in v1.0 and the
`bounce profile doctor` upgrade runbook shipped under task #321
(see [PROFILE-UPGRADE.md](PROFILE-UPGRADE.md)).

> **Status — v1.0 shipped surface vs v1.1 roadmap**
>
> **Shipped today (v1.0):** `ibounce profile install --from URL --sha256 <hex>`
> — one-shot install of a profile bundle from a URL with sha256 pinning. This
> is the load-bearing engineer-onboarding command. See
> [§4 — Engineer onboarding (day 1 flow)](#4-engineer-onboarding-day-1-flow)
> for the actual shipped flow.
>
> **v1.1 deliverable (PLANNED — not invokable in v1.0):** a unified
> `bounce init --org-url ...` for day-1 multi-profile bootstrap +
> `bounce profile sync` for ETag-based update polling. Both are
> documented in this runbook so security teams can plan their
> distribution shape now, but **the binaries do not yet ship these
> subcommands**. Where this doc references them, they are marked
> **PLANNED (v1.1)**. Today's equivalents (one-shot install + manual
> re-run for updates) are called out alongside.

Audience: security teams, DevSecOps, platform-engineering teams whose
engineers run AI coding agents (Claude Code, Cursor, OpenCode,
custom MCP clients) on production-adjacent credentials. If your
engineers are about to start handing AWS / Kubernetes / database
access to agents and you want **one curated artifact** that every
laptop, every CI runner, and every shared workstation inherits — this
is the runbook.

> **Note on canonical shape.** The Bounce suite is mid-pivot to a
> discovery-first default: bouncers pass traffic through by default
> and the operator's org policy is mostly a **denylist** + audit-
> export config + alert routing. The pre-pivot pattern of curating
> broad `allow_baseline` allow-sets is deprecated; the recommender +
> scoped role issuance now handle "what should this agent be allowed
> to do." Examples in this doc follow the canonical post-pivot
> deny-only shape. Where an example field is only meaningful under
> the canonical shape, it's marked **post-pivot preview** with a
> reference to task #323.

---

## 1. Who this is for

This is for the human (or team) inside an organization who answers
"**What is our agent safety policy?**" — typically:

- The security team that audits credential issuance
- The DevSecOps team that owns developer-laptop tooling
- The platform-engineering team that owns CI runners
- The IT team that ships onboarding scripts for new engineers

If you're the engineer being asked to install a bouncer on your
laptop on day 1, you don't need this doc — `ibounce profile install
--from <URL your IT team gave you> --sha256 <hex>` is the whole
story (v1.0; the unified `bounce init --org-url` form is PLANNED for
v1.1). The [`IBOUNCE.md`](IBOUNCE.md) reference covers the engineer
surface.

This doc is what your security team curates. It assumes you already
have:

- A team that is comfortable saying "agents in our org will not
  touch `arn:aws:iam::*:role/break-glass-*`" without an exhaustive
  allow-list
- A place to host static files behind HTTPS (S3 static website,
  GitHub Pages, an internal artifact registry, a static-site
  Cloudflare worker — anything)
- A change-management process for security policy

---

## 2. The shape

An **org profile bundle** is a YAML index + one or more profile
YAML files. The bundle declares:

| Section | What it does | Required? |
|---|---|---|
| **Denies** | What the proxy refuses on every agent's behalf — across all four Bounce products (ibounce / kbounce / dbounce / gbounce). Per [[dynamic-deny-rules]] denies are the load-bearing field. | Yes |
| **Audit-export config** | Webhook URL, preset (`splunk-hec`, `datadog`, etc.), alert routes (PagerDuty, Slack). Every decision the bouncer makes flows here. | Strongly recommended |
| **Alert routes** | Conditional routes — `severity: critical` goes to PagerDuty; `severity: info` goes to a low-priority channel. | Optional |
| **Minimum-TTL caps** | Floor on how long an agent's scoped credential can live. The bouncer issues TTLs shorter than the cap; never longer. | Optional |
| **Recommended task scopes** | Named "starter tasks" the recommender can offer engineers — `s3-readonly-staging`, `eks-describe-only`, etc. Not enforced floors; suggestion library. | Optional |

What an org profile bundle does **NOT** include (any more):

- **Broad allow-baselines.** Pre-pivot, profiles often shipped an
  `allow_baseline: aws_managed_readonly_access` field that
  enumerated which AWS-classified Read+List actions to permit. Post-
  pivot, the discovery-first default already permits everything
  except the denies, and per-task scoping (via the recommender)
  picks the right narrow allow-set for the specific job. Allow-
  baselines in org profiles are a deprecated pattern.
- **Per-team allow lists.** If your "data team" needs a different
  permission shape than your "platform team," ship two profiles in
  the bundle and let `applies_to_teams` route engineers to the
  right one. The profile's job is still to encode **what NOT to
  touch**, not to enumerate what's allowed.

The simpler shape (denies + observability + routing) is a much
easier sell to enterprise IT than the pre-pivot ask of "draft
exhaustive allow baselines for every job role in your org."

---

## 3. Distribution mechanics

The bundle lives at a URL your org controls. Engineers fetch it
once at onboarding.

### v1.0 shipped flow

```bash
ibounce profile install --from https://internal.example.com/bounce-profiles/my-profile.yaml \
    --sha256 <hex>
```

What that command does today:

1. **Fetches the profile YAML** over HTTPS. HTTP is refused.
2. **Verifies the SHA-256** against the operator-supplied `--sha256`
   value. Mismatch aborts the install before any state mutates. IT
   teams should ship the hash in onboarding docs.
3. **Validates the profile** against the profile schema.
4. **Installs the profile** to the per-product profile directory
   (`~/.iam-jit/bouncer/profiles.yaml` for ibounce) — marking the
   profile's `source` field as the fetch URL.
5. **Emits an `admin-action` audit event** for the install (who,
   when, from what URL, what SHA the profile resolved to).

Installed-from-URL profiles are **read-only at the CLI surface**.
Engineers cannot edit them via `ibounce profile edit`; doing so
would let an agent (or a curious engineer) bypass the org-level
floor. The only way to change an installed-from-URL profile is to
re-publish the bundle and re-run install. Per
[[creates-never-mutates]], attempted edits are logged but not
applied.

For multi-profile bundles in v1.0, IT teams ship one
`ibounce profile install --from URL --sha256 <hex>` invocation per
profile in their onboarding script.

### v1.1 PLANNED flow (NOT invokable in v1.0)

The v1.1 deliverable is a unified `bounce init --org-url ...` that
collapses the per-profile loop into a single command and adds
index-level mechanics:

```bash
# PLANNED — v1.1; NOT shipped in v1.0
bounce init --org-url https://internal.example.com/bounce-profiles/index.yaml
```

What that command will do (cross-product; ibounce / kbounce /
dbounce / gbounce all sharing the surface per
[[cross-product-agent-parity]]):

1. **Fetches the index** over HTTPS. HTTP refused.
2. **Validates the index** against the published schema (see
   `docs/examples/profiles/index.yaml.template`).
3. **Fetches each profile YAML** referenced by the index. All
   profiles in the bundle must validate before any are written.
4. **Verifies the bundle SHA-256** if `--sha256 <hex>` is supplied
   or the bundle declares `bundle_sha256` in its index.
5. **Installs the profiles** to the per-product profile directory.
6. **Pins the source URL** in per-product state so future
   `bounce profile sync` re-fetches without re-typing the URL.
7. **Emits an `admin-action` audit event** for the install.

ETag-based sync (PLANNED, v1.1): the bouncer will remember the
bundle's HTTP ETag (or the SHA if no ETag is sent) and
`bounce profile sync` will short-circuit when nothing has changed.
This is what will make `sync` cheap enough to run on every
`bounce run` startup — see §6. In v1.0, updates are operator-driven
by re-running `ibounce profile install --from URL --sha256 <new-hex>`.

---

## 4. Engineer onboarding (day 1 flow)

### Engineer onboarding (today — v1.0)

The handoff from "engineer joins" to "engineer's agents respect
the safety floor" is two commands:

```bash
# 1. Install the binary (one of: brew, pip, go install, docker)
pip install iam-jit

# 2. Apply the org safety floor
ibounce profile install \
    --from https://internal.example.com/bounce-profiles/my-profile.yaml \
    --sha256 <hex-your-IT-team-published>
# → fetches profile YAML, verifies sha256
# → installs org-wide denies + audit-export config
# → marks profile.source = the fetch URL (read-only at CLI)
# → engineer's agent immediately respects the floor

# 3. Start the proxy (normal day-1 workflow from here on)
ibounce run
```

Properties of this handoff:

- **Audited.** Every install is an `admin-action` OCSF event in the
  per-product audit log + (if configured) sent to the org's webhook
  before the engineer's first agent call.
- **Two commands.** Per-profile install loop in v1.0 (one install
  call per profile in your bundle); the v1.1 `bounce init --org-url`
  collapses this to one command.
- **Survives upgrades.** The profile stays installed across binary
  upgrades. `bounce profile doctor` (§6) surfaces drift when
  shipped defaults move forward of the installed bundle.
- **Read-only at the CLI.** Engineers cannot edit installed-from-URL
  profiles; the only way to change them is to re-publish + re-run
  install.

### Engineer onboarding (PLANNED — v1.1)

When `bounce init --org-url` ships, the day-1 flow collapses to:

```bash
# PLANNED — v1.1; NOT invokable in v1.0
pip install iam-jit
bounce init --org-url https://internal.example.com/bounce-profiles/index.yaml
ibounce run
```

The v1.1 form is idempotent (re-runs become sync-checks) and pulls
the entire bundle (multiple profiles + index-level metadata) in one
HTTP fetch. Until it lands, use the v1.0 per-profile install form
above.

---

## 5. Override semantics

Engineers can layer **on top of** the org safety floor; they
cannot peel it back.

| Action | Allowed? |
|---|---|
| Add a task-specific deny via `iam-jit deny add ...` per [[dynamic-deny-rules]] | Yes — additive, local-only, audit-logged |
| Add a local profile (e.g. `auto-2026-05-22-s3-readonly`) | Yes — local profiles compose with org floor |
| Remove a deny from the installed org profile | **No** — installed-from-URL profiles are read-only at the CLI surface |
| Edit a deny in the installed org profile to be narrower | **No** — same reason; the bundle is the source of truth |
| `bounce pause --for 30m` to demote enforcement to advisory | Yes, but every call inside the window is audit-linked to the pause id and surfaces on `/healthz` so monitors can flag it |

Attempts to remove or weaken an installed-from-URL deny produce
**admin-action OCSF events** (`category: profile`, `activity_name:
edit_attempt_blocked`) on the audit stream. Your security team
sees them in the SIEM; they're not silent failures.

This is the load-bearing property for enterprise distribution: the
org sets a floor; engineers move *above* the floor freely; nobody
moves *below* it without re-publishing the bundle.

---

## 6. Update flow

### Updates today (v1.0)

In v1.0 the update lifecycle has two commands:

```bash
# Re-fetch + re-install the profile with the new SHA
ibounce profile install \
    --from https://internal.example.com/bounce-profiles/my-profile.yaml \
    --sha256 <new-hex>

# Audit installed profile against shipped per-product defaults
bounce profile doctor             # see PROFILE-UPGRADE.md
bounce profile doctor --diff      # show what --apply would add
bounce profile doctor --apply     # additively merge new safety floors
```

What each does:

- **`ibounce profile install --from URL --sha256 <hex>`** — re-fetches
  the profile from the URL, verifies the new SHA, and atomically
  installs over the existing profile. The org workflow today: when
  your security team publishes a new profile version, IT pushes an
  updated onboarding hash; engineers re-run the install command (or
  a setup script does it on their behalf).
- **`bounce profile doctor`** — diffs your installed profile
  (whether locally curated or installed-from-URL) against the
  bouncer's *shipped* defaults. Surfaces fields the binary now
  knows about that your profile doesn't yet. Categorizes each
  miss into `safety-floor` / `detection` / `audit` / `convenience`;
  the first triggers a startup banner. Full runbook:
  [PROFILE-UPGRADE.md](PROFILE-UPGRADE.md). Per-bouncer auto-banner
  on `*bounce run` fires only for missing `safety-floor` fields.

### Updates PLANNED (v1.1)

```bash
# PLANNED — v1.1; NOT invokable in v1.0
bounce profile sync
```

**`bounce profile sync`** (PLANNED) — will re-fetch the bundle from
its pinned `--org-url`. If the ETag matches, no-op. If new content,
validates + (optionally) re-verifies SHA + atomically swaps the
installed profile. Old version is backed up to
`<profiles>.yaml.bak-<ts>`. Cheap enough to wire into `bounce run`
startup once it ships.

The v1.1 org workflow: when your security team publishes a new
bundle version, push it to the same URL. Every engineer's next
`bounce profile sync` (or `bounce run` if you wire sync to run on
startup) picks it up. No fleet-wide push needed; pull-only updates.
Until v1.1 lands, achieve the same outcome by re-running
`ibounce profile install --from URL --sha256 <new-hex>` (the
operator's setup script can wrap this).

---

## 7. CI/CD integration

The same `--org-url` works in CI/CD jobs. Every CI run inherits the
same floor as engineers' laptops, which is the [[ci-standard-play]]
shape — *"we run the bouncer in CI"* becomes a standard line in
your team's setup scripts.

A typical CI job pattern (GitHub Actions / GitLab CI / Buildkite),
v1.0 shape:

```yaml
# .github/workflows/agent-run.yml
- name: install bouncer + apply org safety floor
  run: |
    pip install iam-jit
    # v1.0: per-profile install loop
    ibounce profile install \
        --from ${{ secrets.ORG_BOUNCE_PROFILE_URL }} \
        --sha256 ${{ secrets.ORG_BOUNCE_PROFILE_SHA }}
- name: run the agent under the bouncer
  run: |
    ibounce run --background --profile ci-runner
    # ... agent runs here, all AWS calls gated by the org floor
```

When `bounce init --org-url` ships in v1.1, the install step
collapses to a single line — see §4 PLANNED block.

Why this matters: a misconfigured CI runner is the single highest-
leverage attack surface in most orgs (long-lived creds, no human
in the loop). Bouncer in CI means even a hijacked runner cannot
delete the `prod-*` cluster — the bouncer denies that call before
it leaves the runner.

The example `example-ci-runner.yaml` (in
`docs/examples/profiles/`) is a starting point — minimum TTL 5
minutes, no production writes, audit-export to the org SIEM.

---

## 8. Audit chain

Org profile changes are themselves first-class audit events:

| Event | When emitted | Fields |
|---|---|---|
| `profile.install` | `ibounce profile install --from URL --sha256 <hex>` (v1.0) / `bounce init --org-url ...` (v1.1 PLANNED) | source_url, bundle_sha256, profiles_added |
| `profile.sync` | `bounce profile sync` (v1.1 PLANNED — and content changed) | source_url, old_sha, new_sha, diff_summary |
| `profile.doctor.applied` | `bounce profile doctor --apply` | fields_added, shipped_defaults_version |
| `profile.edit_attempt_blocked` | Engineer tried to edit an installed-from-URL profile via CLI | profile_name, attempted_change, principal |
| `profile.pause_started` / `profile.pause_ended` | `bounce pause --for ...` window opened/closed | duration, reason |

These emit through the same audit-export pipeline as agent calls
themselves. If your bundle declares a Splunk-HEC or Datadog
webhook, profile-lifecycle events flow there alongside agent
decisions. Your security team gets a full lifecycle view: when
the bundle was installed, by whom (CI bot vs. an engineer's
keystrokes), what it denied during its lifetime, when it was
last synced, what was added.

The `category` field on every event distinguishes admin actions
from agent actions — `category: profile` vs.
`category: agent_call`. Splunk / Datadog dashboards can show them
as separate panels.

---

## 9. Hosting

Where you host the bundle is up to you. Common shapes:

- **S3 static website.** Bucket policy + CloudFront with a custom
  domain. ~5 minutes to set up; effectively free at this scale.
  Rotation is `aws s3 cp index.yaml s3://your-bucket/bounce/`.
- **GitHub Pages.** Push the bundle to a `bounce-profiles` repo;
  enable Pages; index.yaml lives at
  `https://your-org.github.io/bounce-profiles/index.yaml`. Free,
  public-by-default — use only if your profile bundle doesn't
  reference internal infrastructure by name. Private orgs can
  use GitHub Enterprise for the same shape behind SSO.
- **Internal artifact registry.** Artifactory / Nexus / a private
  npm-style registry — whatever your org already runs for binary
  distribution.
- **Static-site Cloudflare Worker** (or Vercel / Netlify / Fly.io).
  Behind your VPN if you want IP-allowlisting.
- **Internal Ingress** in a Kubernetes cluster you already run.
  Works fine if engineers' laptops can reach it over VPN.

**iam-jit-the-company does not host org profiles.** Per
[[no-hosted-saas]], we never operate multi-tenant infrastructure
that holds policy for many customers. Hosting is the operator's
problem — which is also its strength: the bundle URL is your
DNS, your TLS cert, your access controls. We never see it.

---

## 10. Composes with iam-jit role issuance

The denies in your org profile do double duty. The bouncer denies
matched calls at request time (the agent's call never reaches AWS).
The denies are *also* embedded as `Effect: Deny` statements in any
iam-jit-issued JIT role for the same account / boundary — so even
if the agent went around the bouncer (e.g. a Lambda runner with
its own AWS credentials), the AWS-side IAM policy denies the call
at credential-use time. Defense-in-depth per
[[dynamic-deny-rules]].

The same shape applies cross-product:

- **ibounce** → AWS-side IAM `Effect: Deny` statements
- **kbounce** → Kubernetes-side `NetworkPolicy` egress denies +
  RBAC `deny`-equivalent (named cluster roles excluded from binding)
- **dbounce** → database-side `REVOKE` on the matching object set
  (PostgreSQL grants, MySQL privileges)
- **gbounce** → host firewall rule (Linux netns + macOS PF) for
  the bypass-resistance hardened mode

You don't have to wire any of this manually — the bouncer's
"emit downstream deny" pass picks denies tagged
`reinforce_at_credential_use: true` and emits them at the
appropriate layer. **Post-pivot preview**: this field becomes
canonical when task #323 lands.

---

## Common patterns

Four short sketches of realistic deployments. Use these as
starting points — they're not exhaustive, and they're not
prescriptions for any specific org.

### Mid-size SaaS company with prod/staging split

Your engineers work in `staging-*` accounts during dev work and
need to ship to `prod-*` accounts at release time. The org profile
denies everything matching `prod-*` keyword targets across ARN +
account-alias dimensions, plus the universal denies (KMS deletion,
IAM credential creation, etc.). At release time, a separate
narrow profile (out-of-band approval) allows the specific prod
write the release requires. See `example-org-base.yaml` +
`example-prod-deny.yaml`.

### Regulated industry (healthcare / fintech) with PHI/PCI denies

Your data exists across S3 buckets tagged `data_classification:
PHI` (or `PCI`) and across RDS clusters with names matching
`*-card-data-*`. The org profile denies reads + writes on those
tag/name patterns across ibounce + dbounce. Engineers can request
narrower scopes via the recommender; nothing matching the
sensitive tags can ever be in a JIT role. See
`example-pci-compliance.yaml`. Note that bouncers are NOT
themselves PCI/HIPAA *certified* per [[ibounce-honest-positioning]] —
they're a tool you wire into your compliance program, not a
substitute for one.

### Open-source / community project enabling contributor agents

You're an OSS maintainer who wants outside contributors to be
able to point Claude Code / Cursor at your repo. The org profile
denies anything outside your test-fixtures bucket + your CI test
account. Contributors run
`ibounce profile install --from https://your-project.example.com/bounce-profiles/contributor.yaml --sha256 <hex>`
(v1.0; the unified `bounce init --org-url` form ships in v1.1) and
their agent gets a known-safe sandbox. The bundle lives in your
project repo's GitHub Pages.

### Enterprise with multi-team divisions (data / on-call / dev-platform)

You have a "data engineering" team that needs read access to the
warehouse but never customer-PII columns; a "platform" team that
provisions infrastructure but should never touch `break-glass-*`
roles; a "support" team that operates exclusively in read-only.
Your bundle ships three profiles + a per-team mapping in
`index.yaml`:

```yaml
profiles:
  - name: data-team
    file: example-data-team.yaml
    applies_to_teams: ["data-engineering", "analytics"]
  - name: platform-team
    file: example-platform-team.yaml
    applies_to_teams: ["platform-engineering"]
  - name: support-team
    file: example-support-readonly.yaml
    applies_to_teams: ["support", "tier-2-ops"]
```

PLANNED (v1.1): engineers will run
`bounce init --org-url ... --team data-engineering` to apply just
the matching profile + the universal `org-base` floor in one
command. In v1.0, IT's onboarding script runs the per-profile
`ibounce profile install --from URL --sha256 <hex>` calls for the
profiles assigned to the engineer's team.

---

## References

- [`docs/PROFILE-UPGRADE.md`](PROFILE-UPGRADE.md) — `bounce profile
  doctor` runbook (task #321 / KNOWN-CAVEATS §A19)
- [`docs/IBOUNCE.md`](IBOUNCE.md) — full ibounce CLI reference
  including `profile install --from URL`
- [`docs/WEBHOOK-PRESETS.md`](WEBHOOK-PRESETS.md) — audit-export
  webhook presets (`splunk-hec`, `datadog`, `elastic`)
- [`docs/PER-ORG-NOTIFICATION-ROUTING.md`](PER-ORG-NOTIFICATION-ROUTING.md)
  — alert-route configuration
- [`docs/examples/profiles/`](examples/profiles/) — five starter
  example profiles + index template
- [[discovery-first-default]] — pivot memo; profiles are
  denylists not allow-baselines
- [[dynamic-deny-rules]] — opt-in deny ergonomics
- [[enterprise-profile-distribution]] — shipped behavior
  (task #4 / #233 bounce-profiles repo)
- [[ci-standard-play]] — "we run the bouncer in CI" positioning
- [[creates-never-mutates]] — why installed-from-URL profiles are
  read-only at the CLI surface

---

*This document is the org-distribution runbook. It is NOT a
compliance certification; bouncers are tools, not auditors. Use
this to build a safety policy your security team can curate and
your engineers can install in one command.*
