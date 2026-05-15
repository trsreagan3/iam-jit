# MFA propagation through AssumeRole

*Recipe for the customer-side AWS configuration that makes
PCI 8.x / SOC 2 CC6.x / HIPAA 164.312(b) MFA evidence chain
unbroken from the IdP login all the way to the AWS API call.*

This is **Layer B** of iam-jit's [MFA compliance strategy](../../docs/COMPLIANCE-MAPPING.md).
Layer A (OIDC login) and Layer C (step-up freshness check) are
in iam-jit's code. Layer B is a one-time configuration you apply
in your AWS account.

## The shape

```
Layer A: IdP login (Google / Okta, MFA enforced)
            │
            ▼ AMR claim with `mfa` value
       iam-jit                                  ← code
            │
            ▼ AssumeRole call to provisioner role
       AWS STS                                  ← AWS-side config
            │
            ▼ Condition: aws:MultiFactorAuthPresent
       provisioner role's trust policy          ← THIS RECIPE
            │
            ▼ session credentials with mfa_present=true
       downstream resources                     ← see audit evidence
```

## Apply this to your provisioner role's trust policy

In the IAM role iam-jit assumes (the
`iam-jit-provisioner` role, ARN configured per account in
`accounts.yaml`), add a `Condition` block that requires
`aws:MultiFactorAuthPresent` to be `true`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TrustIamJitWithMfaEvidence",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<iam-jit-account-id>:role/iam-jit-lambda-role"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        },
        "StringEquals": {
          "sts:ExternalId": "<your-account-external-id-from-iam-jit>"
        }
      }
    }
  ]
}
```

**For local mode** (`iam-jit serve --local`), the provisioner role
is the role you're already assuming with `aws-cli` / `aws-vault`,
so the Condition is on the SECOND assume (the per-grant role), not
the first.

## Verify the chain end-to-end

After the condition is in place, exercise it with a real grant:

```bash
# 1. log in to iam-jit via Google OIDC (MFA-enforced at the IdP)
$ open http://localhost:8765/api/v1/auth/oidc/login

# 2. request a high-risk grant
$ curl -X POST -H "Authorization: Bearer $(cat ~/.iam-jit/cli-token)" \
      -H "Content-Type: application/json" \
      -d '{"apiVersion":"iam-jit.dev/v1alpha1", "kind":"AccessRequest", ...}' \
      http://localhost:8765/api/v1/requests

# 3. confirm the audit log shows mfa_present=true
$ curl -H "Authorization: Bearer $(cat ~/.iam-jit/cli-token)" \
      http://localhost:8765/api/v1/requests/<id>/audit | jq '.events[] | .details.mfa_present'
true
```

## What the auditor sees

When SOC 2 / PCI assessors ask "how do you prove MFA was present
at the time of this elevated action?", you can produce, for any
grant in the audit log:

| Field | Source | Means |
|---|---|---|
| `mfa_present: true` | iam-jit audit | OIDC AMR claim contained `mfa` |
| `mfa_age_seconds: 42` | iam-jit audit | seconds between MFA assertion and grant |
| `aws:MultiFactorAuthPresent` | CloudTrail event | downstream call ran under an MFA-tagged session |

Three independent observers (IdP log, iam-jit log, CloudTrail)
all show the same MFA assertion on the same chain. The auditor
stops asking questions.

## High-risk auto-step-up

By default, grants with `risk_score >= 7` require the user's MFA
cookie to be no older than **5 minutes** at grant time. If the
cookie is older, iam-jit returns 403 with a structured body
telling the client to re-authenticate:

```json
{
  "detail": "MFA step-up required for high-risk grant",
  "reason": "mfa_too_stale",
  "redirect_to": "/api/v1/auth/oidc/login?next=/api/v1/requests/<id>"
}
```

Tune via:

- `IAM_JIT_MFA_STEP_UP_AT_SCORE` (default `7`)
- `IAM_JIT_MFA_STEP_UP_MAX_AGE_SECONDS` (default `300`)

Low-risk grants never trigger step-up — they're auto-approved
under the safety-mode threshold and audited with whatever MFA
state the session has.

## What this doesn't cover

- **MFA bypass at the IdP.** If the IdP itself doesn't enforce
  MFA, no amount of downstream condition wiring helps. Confirm
  your IdP's MFA policy is "required, not optional."
- **Service accounts.** Agents are system accounts under PCI 8.6
  — the human authorizer's MFA satisfies the requirement. See
  [`COMPLIANCE-MAPPING.md`](../COMPLIANCE-MAPPING.md) for the
  delegation chain audit detail.
- **AWS root account access.** Use AWS Organizations SCPs to
  block root-account access; iam-jit doesn't operate against
  root.
