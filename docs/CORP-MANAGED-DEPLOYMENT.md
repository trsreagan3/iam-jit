# Corp-managed deployment — IT recipe

> **Tracking**: #491 LAUNCH-BLOCKER §A91.
> **Engineer-side counterpart**: `iam-jit init --managed --org-policy URL` (#490 §A90).
> **Memory reference**: `[[enterprise-profile-distribution]]`.

This runbook is for the **IT operator** who curates the org-policy and
distributes it to engineers. If you are an engineer who received a URL
and a public key from your IT team, see [DEPLOYMENT.md](DEPLOYMENT.md)
and the `init --managed` flag described there.

---

## What this covers

| Step | Who | Tool |
|------|-----|------|
| 1. Generate Ed25519 keypair | IT | `openssl genpkey` |
| 2. Distribute public key to engineers | IT | env var / file |
| 3. Author `org-policy.yaml` | IT | text editor / schema |
| 4. Sign the policy | IT | `iam-jit org-policy sign` |
| 5. Verify before publish | IT | `iam-jit org-policy verify` |
| 6. Publish to HTTPS endpoint | IT | S3 / static site / Nginx |
| 7. Engineers onboard | Engineers | `iam-jit init --managed` |

Per `[[no-hosted-saas]]` iam-jit ships no hosted publish service.
IT publishes to their own HTTPS endpoint (S3 bucket, GitHub Pages,
internal Nginx, or any CDN).

---

## Step 1 — Generate Ed25519 keypair

Run once on the IT machine that owns the signing secret. The private
key NEVER leaves this machine.

```bash
# Generate private key (PKCS8 PEM, unencrypted):
openssl genpkey -algorithm ED25519 -out org.priv
chmod 0600 org.priv

# Derive the public key:
openssl pkey -in org.priv -pubout -out org.pub
```

Alternatively, use the threat-feed publisher tool (if your team already
uses it for threat-feed signing from #409):

```bash
iam-jit-feed-publish init \
    --publisher corp-iam-team \
    --out-dir ~/.iam-jit/threat_feed
# Private key: ~/.iam-jit/threat_feed/publisher.ed25519.pem
# Public PEM:  ~/.iam-jit/threat_feed/publisher.ed25519.pub
```

Keep `org.priv` (`0600`) in a secrets manager or encrypted at-rest
volume. Rotate it if it is ever exposed or when team members who
accessed it leave.

---

## Step 2 — Distribute the public key to engineers

Engineers must have the public key **before** they run
`iam-jit init --managed`. There are three distribution paths (first
match wins at engineer-side):

| Priority | Mechanism | How |
|----------|-----------|-----|
| 1 | `--org-public-key /path/to/org.pub` flag | Pass on first `init --managed` invocation |
| 2 | `$IAM_JIT_ORG_PUBLIC_KEY=/path/to/org.pub` env var | Set in the engineer's shell profile / CI env |
| 3 | `~/.iam-jit/org.pub` (or `$XDG_CONFIG_HOME/iam-jit/org.pub`) | Drop the file into the engineer's config dir |

Typical distribution methods:

- **Onboarding script**: `curl -fsSL https://corp.example.com/iam-jit/org.pub > ~/.iam-jit/org.pub`
- **Company dotfiles repo**: commit `org.pub` into the internal dotfiles repo and let the bootstrap script drop it into place.
- **Secrets manager on CI**: set `IAM_JIT_ORG_PUBLIC_KEY` to the PEM string (not a path) in CI secrets.

The public key is safe to commit / distribute openly — it is only used
for **verification**, never for signing.

---

## Step 3 — Author `org-policy.yaml`

The org-policy is a standard iam-jit declarative config
(`ambient_config` schema). Example that enables ibounce in cooperative
mode for all engineers:

```yaml
# org-policy.yaml — authored + signed by IT; consumed via init --managed.
# See docs/AMBIENT-CONFIG.md for the full schema reference.
iam-jit:
  schema_version: "1.0"
  enabled: true
  posture: managed       # lock engineers to IT-curated settings
  bouncers:
    ibounce:
      enabled: true
      mode: cooperative  # agents see deny rationale + may retry scoped
```

Stricter example that enables all four bouncers and forces strict mode:

```yaml
iam-jit:
  schema_version: "1.0"
  enabled: true
  posture: managed
  bouncers:
    ibounce:
      enabled: true
      mode: strict
    kbouncer:
      enabled: true
      mode: strict
    dbounce:
      enabled: true
      mode: strict
    gbounce:
      enabled: true
      mode: strict
```

Validate locally against the schema before signing:

```bash
iam-jit doctor apply-config --config org-policy.yaml --dry-run
```

---

## Step 4 — Sign the policy

```bash
iam-jit org-policy sign \
    --in  org-policy.yaml \
    --key org.priv \
    --out org-policy.yaml.sig
```

This produces `org-policy.yaml.sig` — a base64-encoded raw Ed25519
signature. The private key is read, used to sign, and NEVER echoed to
stdout.

Expected output:

```
OK  signature written to org-policy.yaml.sig
    policy:    org-policy.yaml  (312 bytes)
    sig file:  org-policy.yaml.sig
    next:      run `iam-jit org-policy verify` to confirm, then publish both files to your HTTPS endpoint.
```

---

## Step 5 — Verify before publish

Run this **before** uploading to confirm the `.sig` will pass
`init --managed` verification. Uses the exact same
`_verify_ed25519_signature` implementation as the engineer-side
pipeline — a local pass guarantees a rollout pass.

```bash
iam-jit org-policy verify \
    --policy org-policy.yaml \
    --sig    org-policy.yaml.sig \
    --pubkey org.pub
```

Expected output on success:

```
OK  signature valid
    policy:  org-policy.yaml  (312 bytes)
    sig:     org-policy.yaml.sig
    pubkey:  org.pub
    Safe to publish both files to your HTTPS endpoint.
```

On failure (e.g., you forgot to re-sign after editing the policy):

```
INVALID  org-policy Ed25519 signature verification FAILED. ...
```

Exit codes: **0** = valid, **1** = invalid.

---

## Step 6 — Publish to your HTTPS endpoint

Publish both files at the SAME base URL:

```
https://corp.example.com/iam-jit/org-policy.yaml
https://corp.example.com/iam-jit/org-policy.yaml.sig  ← must be at <URL>.sig
```

The `.sig` URL is derived automatically by appending `.sig` to the
policy URL — you do not pass it separately.

### S3 example

```bash
aws s3 cp org-policy.yaml     s3://corp-internal/iam-jit/org-policy.yaml
aws s3 cp org-policy.yaml.sig s3://corp-internal/iam-jit/org-policy.yaml.sig

# Verify the HTTPS URL works from outside (no SSRF-gate issues):
curl -fsSL https://corp.example.com/iam-jit/org-policy.yaml | head -5
curl -fsSL https://corp.example.com/iam-jit/org-policy.yaml.sig
```

### Static site / GitHub Pages example

Commit both files into your internal-docs repo or a GitHub Pages branch:

```bash
cp org-policy.yaml     docs/iam-jit/org-policy.yaml
cp org-policy.yaml.sig docs/iam-jit/org-policy.yaml.sig
git add docs/iam-jit/
git commit -m "update iam-jit org-policy + signature"
git push
```

The published URL might look like:
`https://internal-docs.corp.example.com/iam-jit/org-policy.yaml`

### Nginx example

Drop both files into the Nginx root for the relevant server block:

```bash
cp org-policy.yaml     /srv/corp-internal/iam-jit/org-policy.yaml
cp org-policy.yaml.sig /srv/corp-internal/iam-jit/org-policy.yaml.sig
```

---

## Step 7 — Engineers onboard

Send engineers the following two pieces of information:

1. **Policy URL**: `https://corp.example.com/iam-jit/org-policy.yaml`
2. **Public key**: the contents of `org.pub` (or the URL to download it)

Engineer runs:

```bash
# Drop the public key into place (or set the env var):
mkdir -p ~/.iam-jit
curl -fsSL https://corp.example.com/iam-jit/org.pub > ~/.iam-jit/org.pub

# Bootstrap from the managed policy:
iam-jit init --managed \
    --org-policy https://corp.example.com/iam-jit/org-policy.yaml
```

Alternatively, the engineer can pass the public key directly:

```bash
iam-jit init --managed \
    --org-policy   https://corp.example.com/iam-jit/org-policy.yaml \
    --org-public-key /path/to/org.pub
```

In CI, set `IAM_JIT_ORG_PUBLIC_KEY` to the PEM string (no file
distribution required):

```yaml
# GitHub Actions example:
env:
  IAM_JIT_ORG_PUBLIC_KEY: ${{ secrets.IAM_JIT_ORG_PUBLIC_KEY }}
steps:
  - run: |
      iam-jit init --managed \
          --org-policy https://corp.example.com/iam-jit/org-policy.yaml
```

---

## Worked end-to-end example

```bash
# IT machine — one-time setup:
openssl genpkey -algorithm ED25519 -out org.priv && chmod 0600 org.priv
openssl pkey -in org.priv -pubout -out org.pub

# Author the policy:
cat > org-policy.yaml <<'EOF'
iam-jit:
  schema_version: "1.0"
  enabled: true
  posture: managed
  bouncers:
    ibounce:
      enabled: true
      mode: cooperative
EOF

# Sign:
iam-jit org-policy sign \
    --in  org-policy.yaml \
    --key org.priv \
    --out org-policy.yaml.sig

# Verify:
iam-jit org-policy verify \
    --policy org-policy.yaml \
    --sig    org-policy.yaml.sig \
    --pubkey org.pub
# → OK  signature valid

# Publish (S3):
aws s3 cp org-policy.yaml     s3://corp-internal/iam-jit/org-policy.yaml
aws s3 cp org-policy.yaml.sig s3://corp-internal/iam-jit/org-policy.yaml.sig
aws s3 cp org.pub             s3://corp-internal/iam-jit/org.pub

# Engineer machine:
curl -fsSL https://corp.example.com/iam-jit/org.pub > ~/.iam-jit/org.pub
iam-jit init --managed \
    --org-policy https://corp.example.com/iam-jit/org-policy.yaml
# → [managed] org-policy verified + written to ~/.iam-jit/iam-jit.yaml
```

---

## Policy update workflow

When you need to update the policy (e.g. add a bouncer, change mode):

1. Edit `org-policy.yaml`.
2. Re-sign: `iam-jit org-policy sign --in org-policy.yaml --key org.priv --out org-policy.yaml.sig --overwrite`
3. Verify: `iam-jit org-policy verify ...`
4. Publish updated files to the SAME URL.

Engineers who re-run `iam-jit init --managed --overwrite` pick up the new
policy automatically. No key rotation required unless the private key was
compromised.

---

## Troubleshooting

### Signature mismatch

**Error**: `org-policy Ed25519 signature verification FAILED`

Causes:
- Policy file was edited after signing without re-signing.
- Wrong `.sig` file for this policy version.
- Signature encoded differently (must be raw base64, not armored PEM).

Fix: re-run `iam-jit org-policy sign` and re-publish.

### SSRF rejection

**Error**: `org-policy URL must use https://` or `org-policy hostname resolves to internal IP`

Causes:
- You used `http://` instead of `https://`.
- The URL resolves to a private / RFC 1918 / loopback IP.

Fix: use an external HTTPS URL. Per #522 SSRF gate, internal URLs are
refused regardless of the hostname label.

### Missing public key

**Error**: `no operator public key found`

Causes:
- Neither `--org-public-key`, `$IAM_JIT_ORG_PUBLIC_KEY`, nor
  `~/.iam-jit/org.pub` resolves.

Fix: distribute `org.pub` to engineers and tell them where to place it,
or set `IAM_JIT_ORG_PUBLIC_KEY` in CI.

### Policy body too large

**Error**: `org-policy body exceeds 1 MB byte cap`

The YAML is capped at 1 MB to prevent OOM attacks. Reduce the policy
size (consider splitting large preset libraries into separate files and
referencing them rather than inlining).

---

## Related docs + issues

- `docs/DEPLOYMENT.md` — engineer-side deployment overview
- `docs/ENTERPRISE-SELF-BOOTSTRAP.md` — enterprise self-host bootstrap
- #489 — `iam-jit init` interactive bootstrap (engineer side)
- #490 §A90 — `iam-jit init --managed` non-interactive corp mode
- #491 §A91 — this doc + `iam-jit org-policy sign/verify` CLI (IT side)
- `[[enterprise-profile-distribution]]` — IT curates org profiles; engineers `init --managed` day 1
- `[[no-hosted-saas]]` — iam-jit ships no hosted service; IT publishes to their own endpoint
- `[[creates-never-mutates]]` — sign/verify write NEW files; never silently overwrite
