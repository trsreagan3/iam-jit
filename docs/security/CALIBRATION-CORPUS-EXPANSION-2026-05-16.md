# Calibration corpus expansion — 2026-05-16

## What

Added 20 new calibration examples under
`tests/calibration_corpus/vendor_real_world/` covering real-world IAM
policy shapes from public vendor docs and AWS reference policies. Goal:
surface scorer accuracy gaps against policies the user-base will
actually deploy. No scorer code changed this round (per the "calibration
is corpus-only" constraint after the recent rule-revert).

## Corpus delta

|                              | Before | After  | Delta  |
| ---------------------------- | -----: | -----: | -----: |
| Total corpus examples        |  2248  |  2268  |   +20  |
| Total failing                |    89  |   101  |   +12  |
| `vendor_real_world` examples |     0  |    20  |   +20  |
| `vendor_real_world` PASS     |     0  |     8  |    +8  |
| `vendor_real_world` FAIL     |     0  |    12  |   +12  |

Each failing YAML carries a `CALIBRATION GAP: scored X, expected Y;
reason: ...` block in its `description:` so the gap is visible in test
output AND the YAML stays in CI as a regression-protection target for
when the scorer is fixed.

## All new examples

| # | Name | Source | Expected | Actual | Pass? |
| - | ---- | ------ | -------: | -----: | :---: |
| 01 | datadog-aws-integration-readonly | docs.datadoghq.com | 2-5 | 8 | FAIL |
| 02 | github-actions-oidc-trust-scoped | docs.github.com | 1-5 | 7 | FAIL |
| 03 | github-actions-oidc-trust-wildcard-misconfig | docs.github.com | 6-10 | 7 | PASS |
| 04 | eks-irsa-trust-policy | docs.aws.amazon.com/eks | 1-5 | 7 | FAIL |
| 05 | circleci-oidc-trust-scoped | circleci.com/docs | 1-5 | 7 | FAIL |
| 06 | aws-self-manage-credentials | docs.aws.amazon.com/IAM | 1-5 | 9 | FAIL |
| 07 | s3-home-directory-user | docs.aws.amazon.com/IAM | 1-5 | 9 | FAIL |
| 08 | cross-account-assume-role-with-externalid | aws.amazon.com/blogs/security | 1-6 | 7 | FAIL |
| 09 | cross-account-assume-role-no-externalid | aws.amazon.com/blogs/security | 4-8 | 7 | PASS |
| 10 | terraform-state-s3-backend | developer.hashicorp.com | 1-4 | 3 | PASS |
| 11 | wiz-style-securityaudit-readonly | docs.wiz.io / SecurityAudit | 1-5 | 7 | FAIL |
| 12 | s3-cross-region-replication-role | docs.aws.amazon.com/AmazonS3 | 1-5 | 6 | FAIL |
| 13 | organizations-master-admin | docs.aws.amazon.com/organizations | 7-10 | 9 | PASS |
| 14 | aws-managed-poweruseraccess-equivalent | docs.aws.amazon.com/aws-managed-policy | 7-10 | 9 | PASS |
| 15 | secretsmanager-broad-write | docs.aws.amazon.com/secretsmanager | 6-10 | 8 | PASS |
| 16 | organizations-audit-role-readonly | docs.aws.amazon.com/organizations | 1-4 | 6 | FAIL |
| 17 | multi-region-condition-scoped | docs.aws.amazon.com/IAM | 1-5 | 8 | FAIL |
| 18 | saml-federated-trust-corporate | docs.aws.amazon.com/IAM | 1-5 | 7 | FAIL |
| 19 | iam-passrole-scoped-to-named-role | docs.aws.amazon.com/IAM | 1-5 | 4 | PASS |
| 20 | kms-decrypt-wildcard | docs.aws.amazon.com/kms | 5-9 | 8 | PASS |

## Cluster categorization of the calibration gaps

The 12 failures clump into **four families**, every one is a known
shape — calibrating these would make the scorer materially more
accurate without inventing new logic.

### Cluster A: Federated principal scored as cross-account regardless of context

Examples affected: 02, 04, 05, 18 (GitHub OIDC scoped, EKS IRSA,
CircleCI OIDC scoped, SAML SSO).

Symptom: every Federated-principal trust policy hits `+7` for
"cross-account-could-not-verify" — scoped GitHub OIDC, properly-bound
EKS IRSA, in-account SAML — all three score identically to the
**broken** GitHub OIDC variant (#03) that has no sub claim at all.

Recommendation: (a) recognise `oidc.eks.<region>.amazonaws.com` host
as in-account by construction; (b) accept an account-context hint on
the request so the scorer can verify same-account; (c) when the trust
condition includes a non-wildcard `:sub` AND `:aud=sts.amazonaws.com`,
reduce the federated penalty by ~3 points so well-scoped patterns
score below the auto-approve threshold.

### Cluster B: Wildcard-action accumulation on read-only statements

Examples affected: 01 (Datadog), 11 (Wiz/SecurityAudit), 16
(organizations-audit), and partially 07 (s3:* on per-user prefix).

Symptom: `Service:Describe*` / `Service:List*` / `Service:Get*`
wildcards each contribute to score even when access_type=read-only AND
every resolved action is in IAM access level Read or List. Datadog
accumulates ~25 such matches and scores 8 — making the official Datadog
integration role un-auto-approvable. Same shape as the
[dogfooding-findings memo](#) Condition-scoped wildcard finding.

Recommendation: when `access_type=read-only` AND every action in the
statement is in IAM access-levels Read/List, the wildcard-action rule
should not fire (or should fire at materially reduced weight).
Bonus: the sensitive-service rule (16) should also respect IAM
access-level — `organizations:ListAccounts` is not the same risk as
`organizations:LeaveOrganization`.

### Cluster C: Resource scoping invisible to the scorer

Examples affected: 06 (`${aws:username}` self-management), 07
(`s3:*` on per-user prefix), 12 (s3 replication role with explicit
dest-bucket), 17 (`aws:RequestedRegion` condition).

Symptom: scorer's "broad resource" / "Resource:*" detection ignores
(a) `${aws:username}` and other principal-self variables in resource
ARNs, (b) sub-bucket prefix scoping when combined with a service-action
wildcard, (c) `aws:RequestedRegion` and `aws:SourceArn` conditions, and
(d) the actual Resource list in the explanation strings for write-class
actions (12 reports "on Resource: *" when the YAML has a specific
bucket ARN).

Recommendation: extend the resource-arn parser to recognise principal
variables and condition-keys as scoping signals. The IAM-Write-class
factor in particular should use the actual Resource set in its message
text.

### Cluster D: External-ID condition not differentiating cross-account trust

Examples affected: 08 (with ExternalId) vs 09 (without ExternalId).

Symptom: same score (7) for both — the entire reason
`sts:ExternalId` exists is to mitigate confused-deputy attacks, and
the scorer doesn't differentiate.

Recommendation: when `Principal.AWS` is an external account ARN AND
`Condition` contains a `StringEquals` on `sts:ExternalId` to a
non-empty value, reduce the cross-account contribution by ~3 points.

## 3-5 concrete recommendations for the next calibration round

1. **Make IAM-access-level (Read/List/Write/Permissions-management) a
   first-class signal in the wildcard-action and sensitive-service
   rules.** Today both rules treat all actions equally. This single
   change would resolve clusters A (read-only) and B (sensitive-service
   read-only) and ~half of cluster C.

2. **Recognise scoping-via-condition as equivalent to scoping-via-resource
   in the wildcard penalty.** `aws:RequestedRegion` /
   `aws:SourceArn` / `aws:SourceAccount` / `aws:PrincipalOrgID`
   conditions on a non-wildcard value SHOULD reduce the
   wildcard-resource contribution. Resolves 17 and partially 12.

3. **Differentiate properly-scoped federated trust from
   broken/wildcard variants.** Today GitHub OIDC `repo:OWNER/REPO:*`
   scores the SAME as omitting the `:sub` condition entirely. Cluster
   A is the highest-volume vendor pattern in the corpus and the most
   urgent to fix; if iam-jit flags every single GitHub Actions OIDC
   role as needing human review, adoption stops at that step.

4. **Differentiate cross-account trust WITH `sts:ExternalId` from
   WITHOUT.** Resolves cluster D. One-line change in the cross-account
   trust scorer.

5. **Teach the resource-arn parser about `${aws:username}` and other
   principal-self variables.** Resolves 06 fully and 07 partially.
   Without this, the AWS-recommended self-credential-management
   pattern scores 9 — i.e., iam-jit recommends NOT using the
   AWS-recommended pattern.

## Why this matters (per the user's earlier prompt)

The user explicitly framed this round as "if the risk scores are not
accurate, people will stop using them." Three of the failures
(#01 Datadog, #04 EKS IRSA, #02 GitHub Actions OIDC) are policies
literally every AWS user installs. If the scorer flags them at 7-9,
the iam-jit user installs iam-jit, requests one of these standard
roles, sees "score 8 — human review required," and uninstalls.

These 12 failures aren't edge cases — they're the most common policy
shapes in production AWS. Closing this gap is the single highest-
leverage scorer improvement possible right now.

## Files

- `tests/calibration_corpus/vendor_real_world/01-datadog-aws-integration-readonly.yaml`
- `tests/calibration_corpus/vendor_real_world/02-github-actions-oidc-trust-scoped.yaml`
- `tests/calibration_corpus/vendor_real_world/03-github-actions-oidc-trust-wildcard-misconfig.yaml`
- `tests/calibration_corpus/vendor_real_world/04-eks-irsa-trust-policy.yaml`
- `tests/calibration_corpus/vendor_real_world/05-circleci-oidc-trust-scoped.yaml`
- `tests/calibration_corpus/vendor_real_world/06-aws-self-manage-credentials.yaml`
- `tests/calibration_corpus/vendor_real_world/07-s3-home-directory-user.yaml`
- `tests/calibration_corpus/vendor_real_world/08-cross-account-assume-role-with-externalid.yaml`
- `tests/calibration_corpus/vendor_real_world/09-cross-account-assume-role-no-externalid.yaml`
- `tests/calibration_corpus/vendor_real_world/10-terraform-state-s3-backend.yaml`
- `tests/calibration_corpus/vendor_real_world/11-wiz-style-securityaudit-readonly.yaml`
- `tests/calibration_corpus/vendor_real_world/12-s3-cross-region-replication-role.yaml`
- `tests/calibration_corpus/vendor_real_world/13-organizations-master-admin.yaml`
- `tests/calibration_corpus/vendor_real_world/14-aws-managed-poweruseraccess-equivalent.yaml`
- `tests/calibration_corpus/vendor_real_world/15-secretsmanager-broad-write.yaml`
- `tests/calibration_corpus/vendor_real_world/16-organizations-audit-role-readonly.yaml`
- `tests/calibration_corpus/vendor_real_world/17-multi-region-condition-scoped.yaml`
- `tests/calibration_corpus/vendor_real_world/18-saml-federated-trust-corporate.yaml`
- `tests/calibration_corpus/vendor_real_world/19-iam-passrole-scoped-to-named-role.yaml`
- `tests/calibration_corpus/vendor_real_world/20-kms-decrypt-wildcard.yaml`
