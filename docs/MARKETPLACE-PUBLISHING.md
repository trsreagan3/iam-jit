# Marketplace publishing runbook

This doc covers publishing the iam-jit Bounce **Splunk app** and
**Datadog content pack** (assets in `marketplace-assets/`) to their
respective marketplaces.

Per [[tech-before-marketing]] **the actual publish stays deferred
until launch.** This runbook is the playbook we'll execute when we
hit the marketing phase — it lives here so the assets and the
publish steps stay in one place.

Having both apps published closes a material competitive gap (per
[[competitive-positioning]]): incumbents in the IAM-adjacent space
typically ship Splunk + Datadog content as a way to show "we're
ready for security teams to actually use us." Shipping with these
assets ready means we don't trail the bar on day one.

Cross-link: every event the Bounce suite emits conforms to OCSF
v1.1.0 class 6003. The full schema reference is at
`docs/QUERYING-AUDIT-LOGS.md`. The webhook presets (`datadog`,
`splunk-hec`, `generic`, `sentinel`) shipped in #257 are what these
marketplace assets consume on the ingest side.

---

## Splunkbase

### Account creation

1. Create a Splunk.com account: https://splunkbase.splunk.com
2. Enroll the account as a publisher via Splunkbase > Developers > Apply.
   Requires identity verification + the legal entity (iam-jit US LLC)
   on file.

### App vetting

Splunk runs every submitted app through **Splunk App Inspect**
(https://dev.splunk.com/enterprise/docs/developapps/testvalidate/appinspect/).
Run it locally first:

```
pip install splunk-appinspect
splunk-appinspect inspect marketplace-assets/iam_jit_bounce/
```

(libmagic is a runtime dep; on macOS install via `brew install libmagic`
and run with `DYLD_LIBRARY_PATH=/opt/homebrew/lib` if the loader can't
find it. Linux distros include libmagic out of the box.)

Failure modes we've designed against in the shipped app:

- **No `bin/` Python scripts.** The app is pure declarative config
  (`.conf` files + Simple XML). Splunk's strictest checks
  (privileged-script scans, signed-binary checks) don't apply because
  there are no executables in the package.
- **No phone-home.** No HTTP outbound; no scheduled scripts. Per
  [[self-host-zero-billing-dependency]] the app contributes zero
  telemetry endpoints.
- **No proprietary fields baked in.** Per [[don't-tailor-to-lighthouse]]
  dashboards + saved searches reference only fields documented in
  OCSF v1.1.0 + the public iam-jit extension block.

### Submission

1. Package the app: from `marketplace-assets/`, run
   `tar -czf iam_jit_bounce.spl iam_jit_bounce/`. The Splunkbase
   submission requires the tarball root to be the app directory
   (matches the `[package] id` stanza in `default/app.conf`).
2. Splunkbase > Apps > New > upload the `.spl`.
3. Fill in: short description, long description (re-use the README's
   intro), screenshots (capture the dashboard with sample data),
   support email.
4. Submit for review.

### Time-to-list expectations

Typical Splunkbase review takes **1-3 weeks**. The faster path is a
clean App Inspect run on first submission; iterative fixes after a
failed review extend the loop by 1-2 weeks each round.

### Renewal

Splunkbase requires **annual recertification** against the current
Splunk Enterprise release. The certification re-runs App Inspect +
checks Simple XML compatibility. Calendar reminder: 60 days before
the cert-expiry date Splunk emails to the publisher account.

### Cost

- **Community-licensed apps:** free.
- **Commercial apps:** Splunk's Marketplace agreement applies (revenue
  share if the app is paid). The iam-jit Bounce app is shipped under
  MIT and is community-licensed; no commercial agreement needed.

---

## Datadog Marketplace

### Datadog account requirements

- **Pro+ Datadog plan** required for publishing.
- Sign the Datadog Technology Partner Agreement (via Datadog's partner
  portal at https://partners.datadoghq.com).
- Identity verification on the legal entity (iam-jit US LLC).

### Content pack submission

1. Validate `manifest.json` matches the v2.0.0 spec (this content pack
   was built against the 2025-Q4 published spec; verify the version
   string at https://docs.datadoghq.com/developers/integrations/oauth_for_integrations/
   before submission).
2. Push the content pack directory to the partner portal:
   - Manifest gets validated server-side
   - Dashboard JSON gets imported into a sandbox tenant
   - Monitors validated for query syntax
   - Pipeline JSON validated for processor schema
3. Submit a screenshot of the live dashboard rendering with sample
   data (Datadog requires this; they re-run the screenshot in their
   marketplace listing UI).

### Time-to-list expectations

Datadog content pack review typically takes **2-4 weeks**, somewhat
longer than Splunkbase because Datadog does a manual UX review on
top of the schema validation.

### Cost

- **Free for community packs.**
- **Revenue share if monetized** (Datadog's standard is 75/25
  split favoring the partner; check the current agreement at
  submission time).

This pack is shipped under MIT and is community-licensed; no
monetization layer.

### Pipeline ordering caveat

After a customer installs the content pack, the iam-jit pipeline
needs to be ordered **above any catch-all JSON pipelines** in their
Datadog tenant. The README + the pack's `configuration` tile note
this. Datadog doesn't auto-order on install (this is a known gap in
their content-pack system that hasn't been addressed yet).

---

## Cross-marketplace shared steps

### Artifact signing

Per [[update-release-strategy]]: once #235 (Ed25519 release signing)
lands, sign both marketplace artifacts before submission:

```
# Splunk .spl
ed25519-sign iam_jit_bounce.spl > iam_jit_bounce.spl.sig

# Datadog content pack (tar the directory first)
tar -czf datadog-content-pack.tar.gz datadog-content-pack/
ed25519-sign datadog-content-pack.tar.gz > datadog-content-pack.tar.gz.sig
```

The signature files go in the GitHub release alongside the artifact.
Splunkbase doesn't have a built-in signature-verification UI; the
signature is for downstream customers who want to verify the
artifact matches our release. Datadog handles signature verification
on their end during the install flow.

### Version-bump cadence

Per [[update-release-strategy]]:

- **Bump `version` in `app.conf` + `manifest.json`** when content
  changes ship. Use semver.
- **Resubmit to the marketplace** on every minor/major version bump.
  Patch versions (bug fixes, doc updates) can ship via a re-upload
  to the existing listing.
- The scorer version is independent — these marketplace assets
  don't reference the scorer; only the OCSF wire format version
  matters (currently 1.1.0; bump when OCSF spec moves).

### Customer-issue triage

Where to file bugs (in priority order):

1. **GitHub Issues on the iam-jit repo** — primary channel, covers
   both apps + the emitter side.
2. **Splunkbase listing comments** — Splunk requires us to monitor
   these; route confirmed bugs to GitHub.
3. **Datadog partner portal** — Datadog opens a ticket per content-pack
   issue; respond within the 5-day SLA in the partner agreement.

---

## Pre-launch checklist

When the marketing phase opens and we're ready to publish:

- [ ] App version bump (currently 1.0.0) if anything's changed
      since asset creation
- [ ] Re-run `splunk-appinspect` locally → clean pass
- [ ] Re-validate Datadog `manifest.json` against current spec
- [ ] Capture screenshots of both dashboards with realistic
      sample data (use a 14-day staging window of dogfood events)
- [ ] Both READMEs proofread for accuracy on current emitter
      surface (event_type vocabulary, alert pattern names)
- [ ] Diff-scan the packaged artifacts for the operator-name +
      employer-name + home-dir-path patterns per
      [[push-policy-public-repo]]
- [ ] Sign artifacts (once #235 lands)
- [ ] Splunkbase submission
- [ ] Datadog Marketplace submission
- [ ] Cross-link from `docs/QUERYING-AUDIT-LOGS.md` to the live
      listings once approved
- [ ] Add listings to the landing site's "integrations" section
