# Example org-profile starters

This directory holds five example profiles + a bundle-index
template that an organization can use as a starting point for
distributing safety policy across their engineers' agents.

**These are starting points, not drop-in policies.** Every
example uses generic names (`example-org`, `your-company`,
`prod-*`) and reasonable defaults that catch the 80% case for the
named pattern. Before publishing any of these on your org's
profile-distribution endpoint, your security team should:

1. **Walk every deny.** Make sure the target shape matches your
   actual AWS / Kubernetes / database / hostname naming
   conventions. The `prod-deny` example assumes you use `prod-*`
   account aliases — if your shop uses account-id-as-name, the
   keyword match will silently no-op.
2. **Replace the `*_env` placeholders.** Webhook URLs, tokens,
   PagerDuty routing keys live in your secret manager + are
   referenced by env var name. The example values reference vars
   like `ORG_SIEM_WEBHOOK_URL` that you need to actually set.
3. **Audit the exceptions list.** Every example with an
   `exceptions:` block is documenting a known false-positive your
   org may or may not have. Remove what doesn't apply.
4. **Run `bounce profile validate`.** Every YAML in this directory
   should pass `bounce profile validate <file>`. If validation
   fails after your edits, fix the structure before publishing —
   silent skips in the bouncer would mean fields you intended to
   deny pass through.

## What's in the directory

| File | Audience | Purpose |
|---|---|---|
| [`example-org-base.yaml`](example-org-base.yaml) | Every engineer + CI runner | Universal denies (break-glass, IAM mutation, KMS deletion, audit-infra destruction, IMDS exfiltration, `GRANT TO PUBLIC`) |
| [`example-prod-deny.yaml`](example-prod-deny.yaml) | Every engineer + CI runner | Production isolation across ARN / account-alias / namespace / database / hostname dimensions |
| [`example-pci-compliance.yaml`](example-pci-compliance.yaml) | Teams handling cardholder data | Cross-bouncer denies for card-data buckets / tables / KMS keys / payment-processor APIs |
| [`example-data-team.yaml`](example-data-team.yaml) | Data engineering / analytics | Read-mostly with PII-tag denies; per-team profile |
| [`example-ci-runner.yaml`](example-ci-runner.yaml) | CI/CD jobs | Hard 5-min TTL, mandatory audit-export, no IAM mutations, narrow egress allowlist |
| [`index.yaml.template`](index.yaml.template) | Security team | Bundle-index template tying the above together |

## How to use as starting points

```bash
# 1. Copy this directory into a new repo your security team owns
cp -r docs/examples/profiles/ /path/to/your-org-bounce-profiles/
cd /path/to/your-org-bounce-profiles/

# 2. Rename + edit
mv example-org-base.yaml org-base.yaml
mv example-prod-deny.yaml prod-deny.yaml
# ... and so on; update index.yaml.template's file: references

# 3. Edit each file to match your shop's naming + tag conventions

# 4. Validate before publishing
for f in *.yaml; do bounce profile validate "$f"; done

# 5. Compute the bundle hash
sha256sum *.yaml | sha256sum   # → put this in index.yaml's bundle_sha256

# 6. Publish behind an HTTPS endpoint your engineers can reach
#    (S3 + CloudFront, GitHub Pages, internal artifact registry, etc.)

# 7. Ship the URL + bundle SHA in your onboarding docs:
#
#    bounce init --org-url https://your-internal-host/bounce-profiles/index.yaml \
#                --sha256 <your-bundle-sha256>
```

The full runbook for this distribution model lives in
[`../../ORG-PROFILE-DISTRIBUTION.md`](../../ORG-PROFILE-DISTRIBUTION.md).
That doc covers:

- Distribution mechanics (HTTPS fetch, SHA pinning, ETag sync)
- Engineer onboarding day-1 flow (one command)
- Override semantics (engineers add, never peel back)
- Update flow (`bounce profile sync` + `bounce profile doctor`)
- CI/CD integration
- Audit chain
- Hosting choices

## Cautions

**Do not copy-paste blindly.** A profile is a security policy; if
the names in your shop don't match the patterns in the examples,
the bouncer will silently fail to deny the things you thought
you'd denied. Read every section. Test with `bounce profile
validate`. Run a dry-run install (`bounce init --org-url <url>
--dry-run`) before pushing the bundle to production.

**These files are NOT compliance certifications.** Per
[[ibounce-honest-positioning]], the Bounce suite is a tool that
helps you encode + enforce your security team's policy. It is not
a substitute for the policy work itself, and it is not a
"PCI-certified" or "HIPAA-certified" artifact. Use these
examples alongside your real compliance program.

**These files use generic names on purpose.** Per
[[don't-tailor-to-lighthouse]], we ship examples that look like
any reasonable shop, not examples tailored to any specific
customer. If you find yourself thinking "the example has
`example-org` everywhere; let me replace with my real name and
ship" — yes, that's the workflow. The generic names are starting
points; your bundle is yours.

## See also

- [`../../ORG-PROFILE-DISTRIBUTION.md`](../../ORG-PROFILE-DISTRIBUTION.md)
  — the full runbook
- [`../../PROFILE-UPGRADE.md`](../../PROFILE-UPGRADE.md) —
  `bounce profile doctor` reference
- [`../../IBOUNCE.md`](../../IBOUNCE.md) — full ibounce CLI +
  profile YAML shape reference
- [`../../WEBHOOK-PRESETS.md`](../../WEBHOOK-PRESETS.md) — webhook
  preset reference (`splunk-hec`, `datadog`, `elastic`)
- [`../../PER-ORG-NOTIFICATION-ROUTING.md`](../../PER-ORG-NOTIFICATION-ROUTING.md)
  — alert-route configuration
