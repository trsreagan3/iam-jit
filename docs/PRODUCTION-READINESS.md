# Production readiness — what's enforced, what's still on you

iam-jit ships with a set of safety baselines built into the SAM
template and the CFN Rules block. Anything in this doc that isn't
already enforced is an operator responsibility. The shape is
deliberate: rules that the template can express without ambiguity
get enforced at deploy; rules that depend on the operator's
environment (a real domain, a real Slack channel, a real on-call
rotation) get documented here.

The deploy is **demo-ready** when every "enforced" box is green
(it should be — the template guarantees them) AND every "operator-
owned" box is green for your specific environment.

## Enforced at deploy (no operator action needed)

  - [x] **DDB Point-in-Time Recovery** on all three iam-jit tables
        (RequestsTable, UsersTable, ApiTokensTable). Continuous
        backup for 35 days; recoverable from accidental writes /
        deletes.
        — Tested via `test_sam_dynamodb_tables_have_pitr_enabled`.

  - [x] **CloudWatch log retention** on `/aws/lambda/iam-jit`.
        Default 30 days, configurable via `LogRetentionDays`
        parameter. Without this, Lambda's auto-created log group
        retains logs forever and the bill grows linearly.
        — Tested via `test_sam_lambda_log_group_has_explicit_retention`.

  - [x] **State bucket** has BlockPublicAccess + AES256
        encryption + Versioning enabled.
        — Tested via `test_sam_state_bucket_blocks_public`.

  - [x] **CFN Rules** refuse known foot-gun parameter combos at
        changeset stage:
        - `UserConfigSource=dynamodb` without `AdminBootstrapEmail`
        - `AllowPublicNetworkExposure=true` without
          `AllowedSourceCidrs` OR with wildcard `CorsAllowedOrigins`
        - `EnablePublicALB=true` without `AlbIngressCidr`

  - [x] **DDB billing** is `PAY_PER_REQUEST` (no idle-cost growth).

  - [x] **Function URL** has explicit `lambda:InvokeFunctionUrl`
        permission. Missing this returns AWS-edge 403 for every
        request — non-obvious without the explicit resource.

  - [x] **ALB** invokes the Lambda via `lambda:InvokeFunction`
        (different IAM action than `InvokeFunctionUrl`), with a
        DependsOn ordering so the target group registration
        doesn't race with the permission.

  - [x] **Single-use bootstrap** — the `[claimed at …]` marker on
        the bootstrap user record prevents replay, enforced at the
        application layer.

  - [x] **NoEcho on secrets** — `MagicLinkSecret`,
        `BootstrapSetupKey`, `WebhookSigningSecret` never appear in
        CFN outputs, stack events, or the `sam deploy` echo.

## Operator-owned (template can't enforce; verify per deploy)

### Network surface

  - [ ] **`AlbIngressCidr` narrowed to your actual ingress.**
        `0.0.0.0/0` is the loud-warning fallback; production should
        be `<workstation-IP>/32`, `<VPN-egress-CIDR>`, or
        `<office-WAN>/24`. See `AGENT-DEPLOYMENT-PROMPT.md` step 8b.

  - [ ] **`AllowedSourceCidrs`** (application-layer allowlist) is
        a non-empty defense-in-depth complement to the SG. Add at
        least your egress CIDR.

  - [ ] **Function URL** is either (a) AWS_IAM mode, (b) blocked
        by SCP and effectively private, or (c) explicitly opted
        public via `AllowPublicNetworkExposure=true` with a
        non-empty CORS allowlist.

  - [ ] **`IAM_JIT_TRUSTED_PROXY_CIDRS` set when running behind a
        reverse proxy** (CloudFront, ALB with X-Forwarded-For
        rewriting, etc.). Required for `X-Forwarded-For`-based
        rate-limiting and `X-Forwarded-Host`-based magic-link
        URL construction to take effect; without it, those
        signals are ignored (correct default — direct Function URL
        exposure cannot trust forwarded headers).

  - [ ] **`IAM_JIT_ALLOWED_PUBLIC_HOSTS` set if magic-links
        should use a public hostname different from the Function
        URL.** Required for the X-Forwarded-Host path in
        `public_url.base_for` to honor the proxied host —
        without an allowlist, XFH is ignored even when trusted.

### Transport security

  - [ ] **HTTPS for any non-sandbox deploy.** Pass
        `AlbCertificateArn=<ACM ARN>`. The stack output
        `AlbTlsPosture` reads `HTTPS` when correct, `HTTP_ONLY`
        when not. See `docs/HTTPS-SETUP.md` for the four
        cert-provisioning paths.

  - [ ] **Custom domain** pointed at the ALB via Route 53 ALIAS
        (or external CNAME). Browsers won't trust the
        auto-generated ALB hostname against any cert.

### Identity + auth

  - [ ] **Magic-link delivery channel configured.** Either
        `SesSenderAddress` set to a verified SES address (prod
        default) or `IAM_JIT_ALLOW_LOG_CHANNEL=1` (small-team
        CloudWatch out-of-band delivery — the log line emits only
        the link's sha256 fingerprint, not the URL). Without
        either, the magic-link route returns a uniform 503 so the
        misconfiguration is loud at launch instead of silently
        leaking tokens via logs.

  - [ ] **Multi-instance replay protection (`MagicLinkNoncesTable`)
        in place.** Provisioned automatically by the SAM template.
        If you deploy without it, set
        `IAM_JIT_ALLOW_INSECURE_NONCES=1` AND cap the Lambda's
        reserved concurrency to 1 — otherwise a captured
        magic-link can be replayed against a cold-started second
        instance during its 15-minute TTL.

  - [ ] **Cross-instance bans store (`BansTable`) in place.**
        Provisioned by the SAM template. Without it the bans
        store is per-instance, so a banned user routed to a
        different Lambda is silently unbanned.

  - [ ] **MagicLinkSecret** is a real 32-byte hex value (the
        template accepts an empty default but session cookies
        validate against an empty secret — every cookie passes).
        Generate with `openssl rand -hex 32`. Rotate periodically.

  - [ ] **BootstrapSetupKey rotated** after first claim. The
        single-use marker prevents replay of the claim itself, but
        the env var still holds the value; rotation via redeploy
        with a fresh key removes any chance of someone reading the
        env var and replaying against a future fresh deploy.

  - [ ] **AdminBootstrapEmail rotated** to a real human admin once
        an org member can claim. The auto-seeded bootstrap row is
        not magic — it's a regular admin record that can be
        updated, renamed, or deleted.

### Observability

  - [ ] **CloudWatch alarms** wired up via your monitoring stack:
        - `AWS/Lambda Errors > 0` over 5min (function broken)
        - `AWS/Lambda Throttles > 0` over 5min (account-level
          concurrency exhausted)
        - `AWS/Lambda Duration p99 > 24s` (close to the 30s
          timeout)
        - `AWS/ApplicationELB HTTPCode_Target_5XX_Count > 0` over
          5min (Lambda error path reaching ALB)
        - `AWS/DynamoDB ThrottledRequests > 0` on each iam-jit
          table (account hit a hot key)
        - `AWS/Events FailedInvocations > 0` on the
          ScheduledExpiry rule (sweep is broken; expired grants
          aren't being cleaned)

        Not in the template (deliberately — SNS / paging
        integration is org-specific). Wire to your iam-jit-alerts
        SNS topic and onward to Slack / PagerDuty.

  - [ ] **ALB access logs** enabled (S3 destination of your
        choice). Required for incident forensics and most
        compliance regimes. Configure post-deploy via
        `aws elbv2 modify-load-balancer-attributes` or via Console.
        Not in the template because the destination bucket and
        retention policy are org-specific.

  - [ ] **Audit-log integrity checkpoint** running. iam-jit emits
        a tamper-proof audit chain; a scheduled job should verify
        the hash chain integrity periodically. Roadmap item.

### Operational

  - [ ] **Backup-restore runbook tested.** PITR is enabled; the
        DR procedure (point-in-time restore to a fresh table,
        UPDATE_REPLACE_POLICY=Retain on the IaC, etc.) should be
        practiced before you need it.

  - [ ] **`AlbIngressCidr` rotation procedure documented** for
        your network. If your VPN egress changes (provider rotation,
        new office WAN block), the template parameter must be
        updated and a redeploy run.

  - [ ] **Stack delete protection** considered for prod. The
        template does NOT set `EnableTerminationProtection` on the
        stack — opinion is that delete-protection invites
        false-confidence; instead, gate deploys via PR review.
        Either pattern is valid; pick one explicitly.

  - [ ] **Audit retention.** Audit log entries live in the state
        bucket. Bucket versioning is on, so deletes are recoverable
        for the bucket's lifecycle window. Set a lifecycle rule on
        non-current versions if storage cost becomes a concern.

## How to validate a deploy

```bash
# 1. Pre-deploy lint + structural tests (no AWS calls)
make deploy-dry-run

# 2. After sam deploy, verify the stack outputs
aws cloudformation describe-stacks --stack-name iam-jit \
    --query 'Stacks[0].Outputs' --output table \
    --profile <hub-account>

# 3. Read the AlbTlsPosture output
#    HTTPS      → ALB cert + HTTPS listener ready
#    HTTP_ONLY  → operator-owned cert work pending

# 4. Read the AlbIngressCidr value baked into the SG
aws ec2 describe-security-groups \
    --filters Name=tag:managed-by,Values=iam-jit \
    --query 'SecurityGroups[].IpPermissions' --output table \
    --profile <hub-account>

# 5. Smoke /healthz over the public surface
curl -sS "$(aws cloudformation describe-stacks --stack-name iam-jit \
    --query 'Stacks[0].Outputs[?OutputKey==`PublicBaseUrl`].OutputValue' \
    --output text --profile <hub-account>)/healthz"

# 6. Run the unit suite against the deployed code
.venv/bin/pytest tests -q --ignore=tests/integration --ignore=tests/e2e
```

If all six pass (and the operator-owned boxes in this doc are
checked for your environment), the deploy is demo-ready.

## What "demo-ready" means specifically

  - You can run `make deploy-dry-run` and it returns ✓ in <2s.
  - You can run `sam deploy --parameter-overrides …` and the stack
    reaches CREATE_COMPLETE in <5min.
  - `curl <PublicBaseUrl>/setup` returns HTTP 200 with the
    bootstrap form HTML.
  - You can claim the bootstrap admin from a browser without
    seeing any AWS-level errors (403, 5xx).
  - The 936+ unit tests pass on the same commit that's deployed.
  - The fresh-Claude validation agent reports the deploy completed
    cleanly with no doc bugs > polish-level findings.

When all of those hold, the next call you take can be a demo.
