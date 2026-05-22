# Distributing safety policy across your org

Status: documentation slice 2026-05-22 — companion to the
`bounce profile install --from URL` mechanics shipped in v1.0 and the
`bounce profile doctor` upgrade runbook shipped under task #321
(see [PROFILE-UPGRADE.md](PROFILE-UPGRADE.md)).

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
laptop on day 1, you don't need this doc — `bounce init --org-url
<URL your IT team gave you>` is the whole story. The
[`IBOUNCE.md`](IBOUNCE.md) reference covers the engineer surface.

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
| **Denies** | What the proxy refuses on every agent's behalf — across all four Bounce products (ibounce / kbouncer / dbounce / gbounce). Per [[dynamic-deny-rules]] denies are the load-bearing field. | Yes |
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
once at onboarding:

```bash
bounce init --org-url https://internal.example.com/bounce-profiles/index.yaml
```

What that command does (cross-product; ibounce / kbounce /
dbounce / gbounce all share the surface per
[[cross-product-agent-parity]]):

1. **Fetches the index** over HTTPS. HTTP is refused.
2. **Validates the index** against the published schema (see
   `docs/examples/profiles/index.yaml.template`).
3. **Fetches each profile YAML** referenced by the index. All
   profiles in the bundle must validate before any are written.
4. **Verifies the bundle SHA-256** if `--sha256 <hex>` is supplied
   or the bundle declares `bundle_sha256` in its index. IT teams
   should ship the hash in onboarding docs.
5. **Installs the profiles** to the per-product profile directory
   (e.g. `~/.iam-jit/bouncer/profiles.yaml` for ibounce,
   `~/.kbouncer/profiles.yaml` for kbouncer, etc.) — marking each
   profile's `source` field as the fetch URL.
6. **Pins the source URL** in per-product state. Future
   `bounce profile sync` re-fetches without the operator having to
   re-type the URL.
7. **Emits an `admin-action` audit event** for the install (who,
   when, from what URL, what SHA the bundle resolved to).

Installed-from-URL profiles are **read-only at the CLI surface**.
Engineers cannot edit them via `ibounce profile edit`; doing so
would let an agent (or a curious engineer) bypass the org-level
floor. The only way to change an installed-from-URL profile is to
re-publish the bundle and re-sync. Per [[creates-never-mutates]],
attempted edits are logged but not applied.

ETag-based sync: the bouncer remembers the bundle's HTTP ETag (or
the SHA if no ETag is sent) and `bounce profile sync` short-circuits
when nothing has changed. This makes `sync` cheap enough to run on
every `bounce run` startup if you want — see §6.

---

## 4. Engineer onboarding (day 1 flow)

The handoff from "engineer joins" to "engineer's agents respect
the safety floor" is one command:

```bash
# 1. Install the binary (one of: brew, pip, go install, docker)
pip install iam-jit

# 2. Apply the org safety floor
bounce init --org-url https://internal.example.com/bounce-profiles/index.yaml
# → fetches bundle, verifies sha256 (if pinned)
# → installs org-wide denies + audit-export config
# → pins source URL for future `bounce profile sync`
# → engineer's agent immediately respects the floor

# 3. Start the proxy (normal day-1 workflow from here on)
ibounce run
```

Properties of this handoff:

- **Idempotent.** Re-running `bounce init --org-url ...` with the
  same URL is a no-op (it sync-checks, doesn't reinstall).
- **Audited.** Every install + every sync is an `admin-action`
  OCSF event in the per-product audit log + (if configured) sent
  to the org's webhook before the engineer's first agent call.
- **Single command.** No follow-up wizard, no manual file edits.
  If your IT team can ship a `setup.sh` that calls `pip install
  iam-jit && bounce init --org-url $ORG_BOUNCE_URL`, you're done.
- **Survives upgrades.** The profile stays installed across binary
  upgrades. `bounce profile doctor` (§6) surfaces drift when
  shipped defaults move forward of the installed bundle.

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

Three commands cover the update lifecycle:

```bash
# Re-fetch the bundle from the pinned URL
bounce profile sync

# Audit installed profile against shipped per-product defaults
bounce profile doctor             # see PROFILE-UPGRADE.md
bounce profile doctor --diff      # show what --apply would add
bounce profile doctor --apply     # additively merge new safety floors
```

What each does:

- **`bounce profile sync`** — re-fetches the bundle from its pinned
  `--org-url`. If the ETag matches, no-op. If new content, validates
  + (optionally) re-verifies SHA + atomically swaps the installed
  profile. Old version is backed up to `<profiles>.yaml.bak-<ts>`.
- **`bounce profile doctor`** — diffs your installed profile
  (whether locally curated or installed-from-URL) against the
  bouncer's *shipped* defaults. Surfaces fields the binary now
  knows about that your profile doesn't yet. Categorizes each
  miss into `safety-floor` / `detection` / `audit` / `convenience`;
  the first triggers a startup banner. Full runbook:
  [PROFILE-UPGRADE.md](PROFILE-UPGRADE.md). Per-bouncer auto-banner
  on `*bounce run` fires only for missing `safety-floor` fields.

The org workflow: when your security team publishes a new bundle
version, push it to the same URL. Every engineer's next
`bounce profile sync` (or `bounce run` if you wire sync to run on
startup) picks it up. No fleet-wide push needed; pull-only updates.

---

## 7. CI/CD integration

The same `--org-url` works in CI/CD jobs. Every CI run inherits the
same floor as engineers' laptops, which is the [[ci-standard-play]]
shape — *"we run the bouncer in CI"* becomes a standard line in
your team's setup scripts.

A typical CI job pattern (GitHub Actions / GitLab CI / Buildkite):

```yaml
# .github/workflows/agent-run.yml
- name: install bouncer + apply org safety floor
  run: |
    pip install iam-jit
    bounce init --org-url ${{ secrets.ORG_BOUNCE_URL }}
- name: run the agent under the bouncer
  run: |
    ibounce run --background --profile ci-runner
    # ... agent runs here, all AWS calls gated by the org floor
```

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
| `profile.install` | `bounce init --org-url ...` | source_url, bundle_sha256, profiles_added |
| `profile.sync` | `bounce profile sync` (and content changed) | source_url, old_sha, new_sha, diff_summary |
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
- **kbouncer** → Kubernetes-side `NetworkPolicy` egress denies +
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
account. Contributors run `bounce init --org-url
https://your-project.example.com/bounce-profiles/index.yaml` and
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

Engineers' `bounce init --org-url ... --team data-engineering`
applies just the matching profile + the universal `org-base`
floor.

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
