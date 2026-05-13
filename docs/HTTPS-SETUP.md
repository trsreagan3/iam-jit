# HTTPS for the iam-jit ALB

The SAM template deploys an ALB on HTTP (port 80) by default. HTTPS
is opt-in: provide an ACM certificate ARN via the `AlbCertificateArn`
parameter and the template adds a TLS 1.2/1.3 HTTPS listener on
port 443 and turns the HTTP listener into a 301 redirect.

This guide covers when HTTPS is required, how to provision a
certificate four different ways, and the operational concerns
(rotation, wildcards, cross-account, custom domains).

## When you can stay on HTTP

The HTTP-only default is suitable for:

  - Dev / scratch deployments inside a sandbox account
  - Staging deployments fronted by a corporate VPN (BeyondCorp,
    Zscaler, Tailscale ACL, etc.) so the ALB is only reachable from
    authenticated client hosts
  - Smoke testing the deploy mechanics before wiring real users

HTTP is **not** suitable for any deployment where:

  - Users will paste the `BootstrapSetupKey` over the public
    internet (the form POST sends the key cleartext)
  - Magic-link URLs travel through arbitrary networks (tokens in
    the URL are sniffable by anything in-path)
  - Session cookies need browser `Secure` flag enforcement (the
    iam-jit app sets `Secure=True` whenever
    `IAM_JIT_DEV_INSECURE_SECRET` is unset; without HTTPS those
    cookies are silently dropped by modern browsers when the page
    is loaded over plain HTTP — sign-in appears to succeed and the
    next page bounces to `/login`)

If you're unsure, default to HTTPS. The cost is minutes of setup;
the cost of guessing wrong is leaking the bootstrap key or session
tokens.

## Certificate provisioning: pick one

### Option 1 — Use an existing ACM cert (lowest friction)

If you already have an ACM cert in the same region as the ALB
(default us-east-1) covering the hostname users will type, just pass
its ARN at deploy:

```bash
sam deploy \
  --parameter-overrides \
    ... \
    EnablePublicALB=true \
    AlbVpcId=vpc-xxxx \
    AlbSubnetIds=subnet-aaaa,subnet-bbbb \
    AlbCertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/abc-... \
  --capabilities CAPABILITY_NAMED_IAM
```

Then point a DNS record (CNAME or Route 53 alias) for that hostname
at the ALB DNS name returned in the `AlbDnsName` output. Browsers
will see the cert when they hit the hostname.

```bash
# Get the ALB DNS:
aws cloudformation describe-stacks \
  --stack-name iam-jit \
  --query 'Stacks[0].Outputs[?OutputKey==`AlbDnsName`].OutputValue' \
  --output text

# Then in your DNS:
# CNAME iam-jit.your-corp.com -> iam-jit-alb-12345.us-east-1.elb.amazonaws.com
```

### Option 2 — Provision a new public ACM cert via DNS validation

If you don't have a cert yet, the simplest path is `aws acm
request-certificate` with DNS validation, complete the validation
record (auto if you use Route 53, manual otherwise), then deploy
with the new ARN.

**Single hostname:**

```bash
CERT_ARN=$(aws acm request-certificate \
  --domain-name iam-jit.your-corp.com \
  --validation-method DNS \
  --region us-east-1 \
  --query 'CertificateArn' --output text)
echo "$CERT_ARN"

# Get the validation record AWS wants you to publish:
aws acm describe-certificate --certificate-arn "$CERT_ARN" \
  --region us-east-1 \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord' \
  --output table
```

The output shows three fields — `Name`, `Type` (always `CNAME`), and
`Value`. Add that record to your DNS provider:

  - **Route 53 in the same account**: `aws route53 change-resource-record-sets`
    or use the Console. ACM picks it up in 1-3 minutes and marks
    the cert `ISSUED`.
  - **Route 53 in a different account**: log in to the cert-owning
    account, the steps are identical. The cert lives in the iam-jit
    account; the validation record lives in the zone-owning account.
  - **Non-Route 53 provider** (Cloudflare, GoDaddy, in-house BIND):
    add the CNAME through their UI / API. ACM polls every few
    minutes; validation usually completes within 30 minutes.

Once `aws acm describe-certificate` shows `Status: ISSUED`, deploy
iam-jit with `AlbCertificateArn=$CERT_ARN`. Total wall-clock time
is typically 5-15 minutes from request → issued.

**Wildcard hostname** (e.g. `*.iam-jit.your-corp.com`):

```bash
aws acm request-certificate \
  --domain-name "*.iam-jit.your-corp.com" \
  --subject-alternative-names "iam-jit.your-corp.com" \
  --validation-method DNS \
  --region us-east-1
```

Useful if you want `iam-jit-staging.your-corp.com` and
`iam-jit-prod.your-corp.com` to share a single cert across multiple
stacks. ACM requires the bare apex be in SANs to make the wildcard
cover the apex too.

### Option 3 — Email validation (only if you can't do DNS)

```bash
aws acm request-certificate \
  --domain-name iam-jit.your-corp.com \
  --validation-method EMAIL \
  --region us-east-1
```

ACM sends an approval email to five canonical addresses
(`admin@`, `administrator@`, `hostmaster@`, `postmaster@`,
`webmaster@your-corp.com`). Click the link in any of them. Validation
completes in ~1 minute.

Caveats:

  - Email-validated certs do **NOT** auto-renew. You'll get a fresh
    email 45-60 days before expiry; miss it and the cert lapses.
    DNS validation (Option 2) is strictly better for long-lived
    deployments.
  - The five canonical addresses need to actually receive mail. If
    your corporate domain doesn't have `hostmaster@` as a real
    inbox, this option won't work.

### Option 4 — Bring your own (private CA, internal corp PKI)

If your org runs its own private CA (AWS Private CA, HashiCorp Vault,
in-house OpenSSL), you can import the resulting cert into ACM via
`aws acm import-certificate`. The ARN looks the same as an AWS-issued
cert and the ALB doesn't care about provenance.

**Limitation:** imported certs do NOT auto-renew. You must re-import
before expiry. Use a CloudWatch alarm on `AWS/CertificateManager`
`DaysToExpiry` metric to catch this.

The cert chain must be a complete chain (leaf + intermediates) up
to a CA browsers trust. Self-signed certs won't be trusted by
browsers without manually adding the CA to every client device,
which is operationally painful. Use a real CA for any deployment
real users will hit.

## Cross-account certs

Common pattern in orgs with central DNS:

  - iam-jit deployed in `team-xyz` AWS account
  - DNS zone `corp.example.com` lives in `central-dns` account
  - Cert needs to be in `team-xyz` (same region as the ALB) but
    validated against `corp.example.com`

The cert MUST live in the same account + region as the ALB; ACM is
region-scoped and ALBs can only reference certs from their own region.

Two workflows:

  1. **DNS validation across accounts.** Request the cert in
     `team-xyz`. Take the validation CNAME from the cert. Switch to
     `central-dns`. Add the CNAME to the hosted zone. ACM polls and
     validates. The cert stays in `team-xyz`. (This is the standard
     pattern; it works fine.)

  2. **Imported cert.** Issue the cert in `central-dns` (via any CA),
     export it, import into `team-xyz`. Manual rotation pain. Avoid
     unless DNS validation isn't possible.

## DNS record pointing at the ALB

After deploy, point your hostname at the ALB:

```bash
# ALB DNS + canonical zone ID (both surfaced as stack outputs):
aws cloudformation describe-stacks --stack-name iam-jit \
  --query 'Stacks[0].Outputs[?OutputKey==`AlbDnsName` || OutputKey==`AlbCanonicalHostedZoneId`].[OutputKey,OutputValue]' \
  --output table
```

**Route 53 in same or different account** — use an `ALIAS` (`A`-type
alias) record. Better than CNAME because it works at the zone apex
and incurs no extra DNS lookups:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id ZXXXXXXXXXXX \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "iam-jit.your-corp.com",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "<AlbCanonicalHostedZoneId from stack output>",
          "DNSName": "<AlbDnsName from stack output>",
          "EvaluateTargetHealth": true
        }
      }
    }]
  }'
```

**Non-Route 53 DNS** — use a `CNAME`:

```
iam-jit.your-corp.com.  CNAME  iam-jit-alb-12345.us-east-1.elb.amazonaws.com.
```

Wait 1-5 minutes for DNS to propagate, then visit the hostname.
Browsers will see the ACM cert and pin a green padlock.

## Rotation

ACM certs issued via DNS validation **auto-renew** in place. ACM:

  1. Issues a new cert 60 days before expiry.
  2. Reuses the existing validation CNAME (no DNS change needed).
  3. Updates the ALB transparently — no template change, no
     redeploy, no downtime.

You don't need to do anything. CloudWatch metric
`AWS/CertificateManager DaysToExpiry` is still a good thing to
alarm on as a backstop.

For **email-validated** or **imported** certs, rotation is manual:

  - **Email**: AWS emails the canonical addresses 60 days before
    expiry. Click the renewal link. New cert ARN. Update
    `AlbCertificateArn` and redeploy.
  - **Imported**: re-import the cert before expiry. ALBs pick up
    the new cert version automatically if the ARN is unchanged
    (i.e., update the same cert in ACM, don't import a new one).

## ALB SSL policy

The template pins `ELBSecurityPolicy-TLS13-1-2-2021-06`:

  - TLS 1.3 supported
  - TLS 1.2 supported (minimum)
  - TLS 1.0/1.1 disabled
  - Cipher suites are AWS's curated 2021 list (no RC4, 3DES, etc.)

If you need a different policy (e.g. PCI requires more conservative
suites, or FedRAMP requires FIPS-mode), edit the `SslPolicy:` line
on the `IAMJitAlbListenerHttps` resource in the SAM template. AWS
publishes the policy catalog at:

  https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html

## Verification after deploy

```bash
DOMAIN=iam-jit.your-corp.com

# 1. DNS resolves to the ALB?
dig +short "$DOMAIN"

# 2. Cert chain is intact, hostname matches?
openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates

# 3. HTTPS endpoint responds?
curl -sS -i "https://${DOMAIN}/healthz"

# 4. HTTP redirects to HTTPS?
curl -sS -i "http://${DOMAIN}/healthz"
# Expect: HTTP/1.1 301 Moved Permanently  Location: https://...
```

If any of these fail, the most common causes:

  - **DNS not propagated** — wait 5 more minutes, retry
  - **Cert covers wrong hostname** — `describe-certificate` and
    verify `DomainName` / SANs match what you're hitting
  - **AlbCertificateArn cross-region** — cert must be in the same
    region as the ALB (us-east-1 by default)
  - **AllowedSourceCidrs blocks your IP** — check the runtime
    allowlist via `/api/v1/admin/network/cidrs` (admin endpoint)

## Quick reference: parameter combinations

| Goal | EnablePublicALB | AlbCertificateArn | Notes |
|---|---|---|---|
| Dev sandbox, no public users | `false` | (any) | Default. Function URL is the surface; reachable only if your AWS Org allows it. |
| VPN-fronted staging | `true` | `""` | HTTP-only ALB. Restrict via the security group / VPN ACL. |
| Production, public HTTPS | `true` | `arn:aws:acm:...` | Mode B. The ALB serves 443 with cert; 80 redirects. |
| HTTPS + auto-cert | not supported via the template today; do it externally via `aws acm request-certificate` and pass the ARN |
