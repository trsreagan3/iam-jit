# Calibration model

The deterministic scorer applies 50+ rules across 9 categories.
This page documents the actual rule set + how it's regression-tested.

## The deterministic safety contract

The numeric `score` field (1–10) is computed **before** any LLM is
consulted. Once computed, the LLM:

- **Can**: add a narrative explanation, suggest additional risk-reduction tips.
- **Cannot**: change the `score`, the `factors`, or the `tier`.

This contract is enforced by the test
`tests/test_routes_score.py::test_score_matches_calibration_corpus`:
the API output and a direct call to `analyze_policy()` must produce
the same `risk_score`, `risk_factors`, `suggestions`, and `tier`.

**Practical implication**: even a compromised or adversarial LLM
cannot hallucinate a request into auto-approval.

## Rule categories

### 1. Service sensitivity

Services flagged as inherently sensitive — IAM mutations, secret
material, audit governance, etc. Wildcard actions in these services
floor at 8–9.

Default list (extendable via admin context):

- `iam`, `organizations`, `sts` — IAM / org governance
- `secretsmanager`, `kms`, `ssm` — credential / secret material
- `sso-admin`, `identitystore` — IAM Identity Center (cross-account admin minting)
- `bedrock` — LLM invocations (cost burn + RAG injection vector)

### 2. Action breadth

Resource: * — broad action types floor at varying levels:

| Pattern | Floor | Example |
|---|---|---|
| `*` alone (full admin) | 10 | `"Action": "*"` |
| `<sensitive-service>:*` on `Resource: *` | 8–9 | `iam:*` on `*` |
| `<service>:*` on `Resource: *` | 8 | `ec2:*` on `*` |
| `<service>:*` on narrow ARN | 7 | `s3:*` on one bucket |
| Action-name wildcard with destructive prefix | 7 | `s3:Delete*` |
| Action-name wildcard with broad resource | 5 | `ec2:*Network*` on `*` |

### 3. Destructive verb on broad resource

Any action starting with `Delete`, `Destroy`, `Reset`, `Terminate`,
`Disable`, `Stop`, `Revoke`, `Cancel`, or `Drop` on a broad resource
floors at **8**. Catches `ec2:TerminateInstances *`,
`s3:DeleteBucket *`, `rds:DeleteDBInstance *`, etc.

**Broad resource** includes: literal `*`, service-wide
(`arn:aws:s3:::*`), single-collection wildcards
(`arn:aws:lambda:.::function:*`), bucket-level wildcards
(`arn:aws:s3:::bucket/*`). Does NOT include path-narrowed wildcards
(`arn:aws:logs:.::log-group:/app:*` — fine-grained scoping within
ONE log group, not all log groups).

### 4. Catastrophic actions (floor 9)

API calls where the blast radius is "the entire account / its
governance / its evidence trail" — auto-approve never appropriate
even on a narrow ARN:

- `account:CloseAccount`, `organizations:LeaveOrganization`
- `organizations:CreateAccount`, `organizations:MoveAccount`
- `cloudtrail:DeleteTrail`, `StopLogging`, `UpdateTrail`
- `iam:AttachRolePolicy`, `PutRolePolicy`, `UpdateAssumeRolePolicy`, `CreateAccessKey`
- `iam:CreatePolicyVersion`, `SetDefaultPolicyVersion`
- `kms:ScheduleKeyDeletion`, `kms:PutKeyPolicy`
- `sso-admin:CreatePermissionSet`, `AttachManagedPolicyToPermissionSet`, `PutInlinePolicyToPermissionSet`, `CreateAccountAssignment`

### 5. High-impact mutations (floor 5)

Actions where even narrow-scope changes have wide blast — single
DNS record change moves prod traffic, single key-policy change can
grant decrypt anywhere, etc. Floors at 5 regardless of resource scope:

- DNS: `route53:ChangeResourceRecordSets`, `CreateHostedZone`, `DeleteHostedZone`
- Network: `ec2:AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`, `ModifySecurityGroupRules`, `ModifyVpcEndpoint`, `CreateRoute`, `DeleteRoute`, `ReplaceRoute`, `ModifyInstanceAttribute`
- Load balancers: `elasticloadbalancing:ModifyListener`, `DeleteListener`, `ModifyTargetGroupAttributes`
- S3: `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketAcl`, `PutObjectAcl`, `PutPublicAccessBlock`, `DeletePublicAccessBlock`, `PutBucketReplication`
- KMS: `PutKeyPolicy`, `ScheduleKeyDeletion`, `DisableKey`
- Lambda: `UpdateFunctionCode`, `DeleteFunction`, `AddPermission`, `RemovePermission`
- Secrets: `secretsmanager:UpdateSecret`, `PutSecretValue`, `RotateSecret`
- SSM: `SendCommand`, `StartSession`, `PutParameter`
- ECS: `UpdateService`, `RegisterTaskDefinition`
- CloudFormation: `CreateChangeSet`, `ExecuteChangeSet`, `UpdateStack`, `CreateStack`
- CodePipeline / CodeBuild: `StartPipelineExecution`, `StartBuild`
- ECR: `PutImage`, `BatchDeleteImage` (image poisoning RCE)

### 6. Access-type mismatch

If the requester marks `access_type=read-only` but the policy
contains write actions, the scorer floors at **6–8** depending on
the action class (the request is lying about its nature):

- Definite write (e.g. `s3:DeleteObject`) → 8
- Deceptive write (`rds-data:ExecuteStatement` — classified Read but can DELETE) → 6
- Wildcard action under read-only flag → 8

### 7. IAM PassRole

- `iam:PassRole` on `Resource: *` → 9 (full escalation path)
- `iam:PassRole` on a specific role ARN → 4 (still requires human review — the target role's policy may exceed caller permissions)

### 8. NotAction / NotResource

- `NotAction` with wildcard resource → 9 (grants everything EXCEPT — admin-minus-set)
- `NotResource` with wildcard action → 8 (operates on everything EXCEPT — almost always broader than intended)

### 9. Grant-duration amplification

For non-trivial baseline scores, longer grants raise the score:

- score ≥ 4 with duration > 1 week: +1
- score ≥ 6 with duration > 1 month: +2
- score ≥ 8 with duration > 1 day: +1

Capped at 10.

## Defensive conditions

The scorer does **not** lower the score based on policy conditions
(`aws:SourceIp`, `aws:MultiFactorAuthPresent`, etc). Reason: conditions
can be bypassed via legitimate-looking pathways (a compromised
principal already inside a trusted CIDR; a role-chain that satisfies
MFA via session token; tags the attacker can self-set). Conditions
are defense-in-depth, not score-reducers.

## Tier mapping

| Score | Tier | Auto-approve at threshold 5? |
|---|---|---|
| 1–3 | low | Yes |
| 4–5 | medium | At 5: depends on threshold |
| 6–10 | high | No |

## Regression test corpus

**2,691 unit tests** in CI, including 1,574 calibration-corpus YAMLs:

- **1,489 AWS managed policies** — every `arn:aws:iam::aws:policy/*`
  AWS publishes, scored and pinned with ±1 tolerance. Refactors that
  significantly shift verdicts on `AdministratorAccess` or
  `ReadOnlyAccess` fail CI immediately.
- **83 adversarial attack patterns** — privilege escalation kits,
  mislabel attacks, NotAction footguns, evidence-destruction, RCE
  primitives, audit evasion, persistence, cross-account exfil,
  image poisoning, AI-platform abuse.
- **10 real-world custom policies** — CI/CD Lambda updaters,
  Terraform state-bucket access, EKS pod readers, ECS task exec,
  data-warehouse queries.

**Calibration agreement**: 100% within ±1 of an Opus-4.7-as-judge
evaluation on the 100-policy reference set (`scripts/calibrate-loop.py`).

## Admin context — extending the rules

Two parameters let admins extend the built-in rule set with
organization-specific context:

- `additional_sensitive_services` — add a service to the sensitive
  list. Use case: your org treats `athena` or `redshift-data` as
  more dangerous than the default.
- `additional_high_impact_actions` — add an action to the high-impact
  list. Use case: a service-specific action your org has decided
  always needs human review.

These extend but never narrow the built-in rules. Pass via the API
request body or the CLI / GitHub Action input. For long-term
configuration, store in your iam-jit deployment's settings.
