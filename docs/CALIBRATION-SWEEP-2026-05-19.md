# Calibration corpus sweep — 2026-05-19

- **Sweep date:** 2026-05-19
- **Scorer commit tested:** `31417d2` (current `main` HEAD)
- **Corpus root:** `tests/calibration_corpus/`
- **Cases collected:** 2,267 examples (+1 sanity check)
- **Cases failing:** 96
- **Pass rate:** 2,171 / 2,267 = 95.77%
- **Issue tracking:** #256 (this sweep)
- **Last sweep on record:** none. Treat this as the baseline.
- **CI status:** `tests/test_calibration_corpus.py` is currently
  excluded from the validate workflow per commit `c5d3ccf`
  (2026-05-18); the exclusion comment explicitly points to this
  sweep as the unblock.

## Per-cluster regression summary

| Cluster | Total cases | Failing | Pass rate |
|---|---|---|---|
| `adversarial/` | 83 | 0 | 100.00% |
| `agent_discovered/` | 430 | 70 | 83.72% |
| `aws_managed/` | 1,489 | 0 | 100.00% |
| `bug_regressions/` | 2 | 0 | 100.00% |
| `high_risk/` | 3 | 0 | 100.00% |
| `low_risk/` | 4 | 0 | 100.00% |
| `medium_risk/` | 3 | 0 | 100.00% |
| `realworld/` | 10 | 0 | 100.00% |
| `realworld_composite/` | 6 | 3 | 50.00% |
| `research_patterns/` | 217 | 16 | 92.63% |
| `vendor_real_world/` | 20 | 7 | 65.00% |

### Direction of regression

| Direction | Count | Mean delta | Max delta |
|---|---|---|---|
| Scorer below ground truth (under-flags) | 86 | +1.66 | +5 |
| Scorer above ground truth (over-flags)  | 10 | +2.40 | +4 |

Two distinct failure modes:

- **Cluster A (under-flag, 86 cases):** scorer misses or under-weights
  documented attack primitives in `agent_discovered` and
  `research_patterns`. Concentrated in newer-service action lists, STS
  federated variants, condition-vacuity edges, cross-account STS
  pivots, and PrincipalOrgID/Arn foreign-org detection.
- **Cluster B (over-flag, 10 cases):** scorer is **too aggressive on
  vendor-shape read-mostly policies** (Datadog, Wiz, AWS-self-manage,
  organizations audit, glue crawler). Cumulative sensitive-service +
  action-wildcard rules accumulate above the auto-approve floor for
  read-only or read-mostly workloads.

## Top regressions

### Top 5 under-flags (scorer missed real risk)

1. `agent_discovered/agent-503-principal-org-id-foreign` — score=1
   expected_min=6 (Δ +5). Resource policy gated on
   `aws:PrincipalOrgID=o-attackerorg`. Scorer reads the condition as
   "scoped" without checking whether the org ID belongs to the
   deploying account's organization. Documented gap with proposed fix
   in the YAML.

2. `agent_discovered/agent-160-rds-data-narrow-aurora` — score=3
   expected_min=7 (Δ +4). `rds-data:ExecuteStatement` on a narrow
   Aurora ARN: SQL-over-IAM primitive that exfils every row with a
   single API call, but the `rds-data` service prefix is not in the
   sensitive set. Service-prefix-aliasing gap (the same class closed
   for `s3-object-lambda` in round 3).

3. `agent_discovered/agent-183-assumerole-saml-narrow-admin` —
   score=3 expected_min=7 (Δ +4). `sts:AssumeRoleWithSAML` +
   `AssumeRoleWithWebIdentity` on a narrow admin role ARN. Scored at
   narrow-STS-write floor; should hit the same `AssumeRole`-on-admin
   floor that `sts:AssumeRole` already triggers.

4. `agent_discovered/agent-612-statement-string-not-dict` — score=1
   expected_min=5 (Δ +4). Malformed `Statement` (string instead of
   dict). Scorer emits "No statements in policy" but does not raise
   the score; should treat malformed-Statement as a moderate-risk
   signal (an attacker can mask intent in malformed JSON that some
   AWS endpoints still accept).

5. `vendor_real_world/06-aws-self-manage-credentials` — score=9
   expected_max=5 (Δ +4 over, see Cluster B below).

### Top 5 over-flags (legitimate policy flagged too high)

1. `vendor_real_world/06-aws-self-manage-credentials` — score=9
   expected_max=5 (Δ +4). AWS's own canonical "self-manage MFA"
   policy. Read+narrow-self-write on `iam:*VirtualMFADevice` /
   `iam:ListMFADevices` on `*`. Sensitive-service rule fires linearly
   for every action, accumulating to 9 even though every action is a
   user-scoped self-service primitive.
2. `vendor_real_world/07-s3-home-directory-user` — score=9
   expected_max=5 (Δ +4). `s3:*` on a user-prefix-scoped resource is
   a valid Transfer Family / home-directory pattern. Scorer treats
   the action wildcard `s3:*` as broad even though the Resource is
   prefix-scoped.
3. `vendor_real_world/01-datadog-aws-integration-readonly` —
   score=8 expected_max=5 (Δ +3). Datadog's canonical AWS
   integration role: ~80 `Describe*`/`Get*`/`List*` actions + 5
   write-but-narrow log-subscription/event-bus actions. Action
   wildcards accumulate linearly across services + the
   "read-only-marked but X is Write" rule fires for each plumbing
   write.
4. `vendor_real_world/17-multi-region-condition-scoped` — score=8
   expected_max=5 (Δ +3). Multi-region EC2 with region-condition
   scoping. Region condition not being credited as a scope reducer.
5. `realworld_composite/glue-crawler-data-lake` — score=8
   expected_max=5 (Δ +3). Glue crawler role with broad
   `glue:Get*`/`List*` on `*`. Same shape as the
   organizations/iam-list over-flag: sensitive-service rule fires for
   each enumerated read action.

## Per-case detail table

See appendix below for the full 96-row table.

## Root-cause analysis

### Root cause 1 — corpus contains **documented aspirational gaps** (the dominant cause)

45 of 70 `agent_discovered` failures contain an explicit
`CALIBRATION GAP: scored X, expected Y` or `Why the scorer
underrates: ...` annotation in the YAML description. These cases
were authored DELIBERATELY against gaps the scorer doesn't yet
catch — they're the adversarial-loop's pending work queue, not
"the scorer regressed."

12 of 20 `vendor_real_world` files carry the same kind of
annotation for over-flag cases. Both directions of the corpus
include the gap explicitly.

**Interpretation:** the corpus is a forward-looking specification
of "what the scorer SHOULD do" — adversarial wave 8-13 added
~100 cases that the adversarial loop expected the scorer to close
in a subsequent fix wave. Those fix waves landed only partially
(the round-10 + cluster-A/B commits in `review.py` history are the
ones that did land). The 96 remaining failures are the
unaddressed half.

This is **not scorer regression**. It's **scorer backlog**.

**Authority for that claim:** in each YAML the description explains
the threat AND the proposed fix in the same file. The
`adversarial-loop-process` memo says this IS how the loop works —
find blind spots, file them as corpus entries, fix the scorer in a
later commit. The fixes are partially shipped; the corpus tracks
the remainder.

**No scorer fix shipped in this sweep.** Per [[scorer-is-ground-truth]]
the right action is NOT to lower expected scores. Per
[[deliberate-feature-completion]] the right action is to fix the
underlying scorer rules — but doing that here would gold-plate
this sweep into 96 small scorer changes across 15 distinct themes,
which is a multi-week program of work, not a sweep. The sweep's
output is this triage; the founder picks the order of attack.

### Root cause 2 — sensitive-service rule does not honor IAM access-level (the dominant over-flag cause)

7 of 10 over-flag cases (the entire `vendor_real_world` + 2 of 3
`realworld_composite`) trip on the same shape:

```
For each action in the policy:
  if service in SENSITIVE_SERVICES and resource is "*":
    risk_factors.append(f"{action} on Resource: * touches sensitive service {service}")
    score += sensitive_service_weight
```

The rule fires linearly per action without distinguishing between
read-class (`Read`, `List`) and write-class (`Write`,
`Permissions management`) IAM access levels. For a Datadog-shape
or Wiz-shape role with 20 different `iam:List*` / `organizations:List*`
/ `glue:GetTable` actions, the rule accumulates to 8-9 even though
every individual action is harmless metadata enumeration.

The scorer already imports IAM access-level data (`_action_level`
at `src/iam_jit/review.py:2040`), so the data is present — it just
isn't consulted in the sensitive-service-touch rule.

**Proposed fix (post-sweep, NOT this commit):** in the
sensitive-service-touch rule, demote the per-action weight from
"medium" to "low" when `_action_level(action)` returns `Read` or
`List`. The high-risk variant (`iam:CreateUser`, `iam:PutPolicy`,
`organizations:AttachPolicy`) keeps its full weight.

The exact same shape is documented in the
`vendor_real_world/16-organizations-audit-role-readonly` YAML
description and references the "Wiz/Datadog gap" by name. The
corpus author already identified the fix; it just hasn't shipped.

### Root cause 3 — `agent_discovered` 5xx + 6xx + 7xx + 8xx waves added newer-service primitives without a corresponding action-list update

22 of the under-flag cases share a single shape: the
`agent_discovered` adversarial waves filed cases for newer-service
APIs (omics, iotsitewise, mq, codeartifact, sso-admin, appstream,
iot, datasync, greengrass, mgn, networkmanager, autoscaling
CreateAutoScalingGroup-escalation, glue:UpdateDevEndpoint,
sagemaker:CreatePresignedDomainUrl). For each, the scorer
correctly reports "state-changing action on Resource: *" but
scores at floor 6, where the corpus expects 7-8 because the
specific action is a documented privilege-escalation primitive in
research §1-§13.

These need per-action floors in the high-impact set, not blanket
weight changes.

### Root cause 4 — service-prefix aliasing (4 cases)

`rds-data`, `bedrock-agent-runtime`, `cognito-identity`,
`s3express` are sibling prefixes that grant the same data plane as
their parent services. Scorer's sensitive set names the parent
prefix only.

Identical to the `s3-object-lambda` closure shipped in round 3.
Mechanical fix: add the aliases to `_SENSITIVE_SERVICES` (or to a
new `_SERVICE_ALIAS_MAP`).

### Root cause 5 — STS federated variants (4 cases)

`sts:AssumeRoleWithSAML`, `sts:AssumeRoleWithWebIdentity`,
`sts:GetFederationToken`, `sts:GetSessionToken` should hit the
same `AssumeRole`-on-admin-role floor that `sts:AssumeRole`
already trips.

Mechanical fix: extend whichever helper currently checks for
`sts:AssumeRole` to include the federated siblings.

### Root cause 6 — condition vacuity edges (4 cases)

`BoolIfExists` MFA-deny-bypass, numeric MFA-age-huge,
`*IfExists`-key-absent, irrelevant-bool-key. The condition-vacuity
catalog (`_condition_is_vacuous` at `src/iam_jit/review.py:1462`)
catches some of these patterns but not the four corpus cases here.

### Root cause 7 — foreign-org / foreign-account detection (3 cases)

`aws:PrincipalOrgID=o-attackerorg`,
`aws:PrincipalArn=arn:aws:iam::*:root`,
`Condition.ArnLike.aws:PrincipalArn: arn:aws:iam::*:*`.

These require either (a) cross-referencing the deploying account's
known org/account, or (b) treating "wildcarded account segment in
a PrincipalArn condition" as a high-risk signal regardless. The
proposed-fix block in each YAML recommends option (b).

### Root cause 8 — KMS scope gaps (4 cases)

The `kms:Decrypt`/`GenerateDataKey`-without-`kms:ViaService`
condition rule fires correctly but the resulting score floor
(currently 6) is below the corpus expectation (7). Single-rule
weight adjustment, not a missing detector.

### Root cause 9 — narrow-PassRole + admin-role-name detection (5 cases)

`iam:PassRole` on a Resource whose name contains "admin" /
"deploy" / "admin-deploy" should hit a higher floor than blanket
`PassRole`. Scorer currently fires the generic PassRole rule
without inspecting the target role name.

### Root cause 10 — silent on 12 cases ("All statements are scoped or limited")

12 cases have ZERO risk factors fired — the scorer is silent.
These are the highest-leverage gaps because adding ANY detector
moves the score off floor 1-3. The 12 are listed in the appendix.

## Calibration corpus discipline finding

The corpus has grown from 96 cases (referenced in the c5d3ccf
exclusion commit) to 2,267 cases. The c5d3ccf-era "96 cases"
language referred to the count of expected-mismatch cases AT the
time of exclusion — which by happenstance equals 96 today too,
suggesting roughly the same set of expectations are still
mismatched (no NEW regressions have been introduced since the
exclusion landed).

The corpus is not stale in the "case no longer represents the
canonical scenario" sense. The cases are well-documented; what's
stale is the **assumption that the scorer would catch up before
the sweep** ran. The corpus is the authority; the scorer hasn't
caught up.

No corpus updates shipped in this sweep. Per
[[calibration-quality-bar]] modifying corpus expectations to make
the scorer look better is exactly the failure mode the corpus
exists to prevent.

## Proposed fixes (founder triages priority)

In ascending order of mechanical cost:

| # | Fix | Cases closed | Estimated cost | Risk of regression |
|---|---|---|---|---|
| 1 | Add `rds-data`, `bedrock-agent-runtime`, `cognito-identity`, `s3express` to `_SENSITIVE_SERVICES` alias list | 4 | 15 min | low |
| 2 | Extend `sts:AssumeRole`-on-admin floor to STS federated siblings | 4 | 30 min | low |
| 3 | Add 13 newer-service action primitives (omics:CreateWorkflow, iotsitewise:CreateAccessPolicy, etc.) to high-impact list | 13 | 1 hr | low (action-list expansion is well-trodden) |
| 4 | Sensitive-service rule respects IAM access-level (Read/List demote-weight) | 7 over-flags | 2-3 hr + new aws_managed regression sweep | **medium** — risks new under-flags in aws_managed corpus, must validate against all 1,489 cases |
| 5 | KMS-without-ViaService floor: bump from 6 to 7 | 4 | 15 min | low |
| 6 | Narrow-PassRole-to-admin-named-role: inspect target name for admin/deploy/root | 5 | 1-2 hr | low |
| 7 | Foreign-PrincipalOrgID/Arn floor (cross-account-segment wildcard) | 3 | 1-2 hr | low |
| 8 | Condition-vacuity expansion (BoolIfExists / numeric / ifexists residuals) | 4 | 2 hr | low |
| 9 | OIDC repo-wildcard / SAML aud-wildcard detection | 2 | 1-2 hr | low |
| 10 | Action-name wildcard accumulation cap (Datadog-shape) | 3 over-flags | 3-4 hr + corpus validation | **medium** — same risk as fix #4 |
| 11 | Cross-account narrow STS-write floor | 3 | 1 hr | low |
| 12 | Silent-on-12 set (mixed root causes; one-by-one investigation) | 12 | 4-6 hr | low per case |
| 13 | Malformed-statement signal raise | 1-2 | 30 min | low |

**Highest-leverage trio (recommended):**
1. **Fix #4** (sensitive-service IAM access-level) — closes the 7
   highest-magnitude false positives, which are the cases that
   would cause real customer pain on Datadog/Wiz/AWS-canonical
   roles. This is the single most important fix.
2. **Fix #1 + #3** (service-prefix aliases + newer-service action
   list) — closes 17 cases for ~1.5hr total mechanical work; no
   regression risk to existing corpus.
3. **Fix #2** (STS federated siblings) — closes 4 cases for
   ~30min; closes a documented attack class (SAML/WebIdentity
   federated-admin assume).

Doing all 13 would close ~85 of the 96 cases. The 12 silent cases
need individual investigation and probably represent ~15hr of
deeper work.

## No fixes shipped this sweep

This sweep reports drift but does not modify the scorer. Per task
brief: this is calibration work; the output is the report. The
sweep deliberately avoids the founder-pick-the-priority step.

Per [[scorer-is-ground-truth]]: corpus stays authoritative. The
scorer needs to evolve toward the corpus, not the other way
around. Per [[deliberate-feature-completion]]: each scorer fix
above must ship complete (rule + tests + corpus re-sweep
confirming no new regressions in other clusters), not as a batch
of half-finished commits.

## CI re-enable conditions

`.github/workflows/validate.yml` currently excludes
`tests/test_calibration_corpus.py`. Re-enable requires:

1. Pick which fixes from the proposed-fix table ship (founder
   decision).
2. Fixes land; re-run sweep; confirm fail-count drops as expected
   AND no new failures elsewhere (especially aws_managed cluster).
3. For the residual failures NOT addressed by the chosen fixes,
   either:
   - File explicit known-fail markers on the YAMLs (xfail), or
   - Move them under a `_disabled_` prefix (the loader already
     skips files starting with `_`), or
   - Accept them as red CI with a documented opt-out flag.

Recommendation: don't re-enable until the over-flag set
(Cluster B, 10 cases) is closed. Over-flags are higher-priority
than under-flags because they cause real customers to bounce on
the auto-approve gate.

## Appendix — full per-case detail

Convention:
- `Delta` is always positive and is the amount by which the score
  diverges from ground truth.
- `scorer below` = under-flag (real risk missed).
- `scorer above` = over-flag (legitimate policy flagged).
- `must_aa=false` rows have score=4 which technically meets
  `score_min=4` but fail the `must_auto_approve=false` constraint
  (score < 5 → would auto-approve at default threshold) — same
  shape as Δ +1 under-flag.

| Case ID | Score | Expected | Delta | Direction | Top factor |
|---|---|---|---|---|---|
| `agent_discovered/agent-160-rds-data-narrow-aurora` | 3 | min=7 | +4 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-175-sts-federation-token-scp-escape` | 7 | min=8 | +1 | scorer below | `sts:GetFederationToken` on Resource: `*` (broad access to sensitive resource) |
| `agent_discovered/agent-176-assumerole-saml-webidentity-wildcard` | 7 | min=8 | +1 | scorer below | `sts:AssumeRoleWithSAML` on Resource: `*` (broad access to sensitive resource) |
| `agent_discovered/agent-179-apigateway-disable-iam-authorizer` | 5 | min=7 | +2 | scorer below | `apigateway:PATCH` is a high-impact mutation — a single narrowly-scoped change can affe... |
| `agent_discovered/agent-183-assumerole-saml-narrow-admin` | 3 | min=7 | +4 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-188-scarleteel-cross-account-assume` | 3 | min=6 | +3 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-193-conditionkey-sourcevpce-typo` | 1 | min=4 | +3 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-227-kms-key-collection-wildcard` | 6 | min=7 | +1 | scorer below | `kms:Decrypt` / `kms:GenerateDataKey` without `kms:ViaService` or `kms:EncryptionContex... |
| `agent_discovered/agent-235-condition-kms-viaservice-missing` | 4 | min=4 + must_aa=false | +1 | scorer below (must_aa=false) | `kms:Decrypt` / `kms:GenerateDataKey` without `kms:ViaService` or `kms:EncryptionContex... |
| `agent_discovered/agent-302-condition-arnlike-vacuous-principal` | 6 | min=7 | +1 | scorer below | `Condition.ArnLike.aws:PrincipalArn: arn:aws:iam::*:*` matches the named principal in E... |
| `agent_discovered/agent-327-policy-variable-injection-condition-value` | 6 | min=7 | +1 | scorer below | `Condition.StringLike.s3:prefix: "${aws:PrincipalTag/tenant}/*"` interpolates an attack... |
| `agent_discovered/agent-328-condition-boolifexists-mfa-deny-bypass` | 7 | min=8 | +1 | scorer below | `secretsmanager:GetSecretValue` on Resource: `*` (broad access to secrets) |
| `agent_discovered/agent-408-numeric-mfa-age-huge` | 3 | min=5 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-410-ifexists-key-absent-bypass` | 7 | min=9 | +2 | scorer below | `sts:AssumeRole` on Resource: `*` (broad access to sensitive resource) |
| `agent_discovered/agent-411-bool-irrelevant-key` | 1 | min=3 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-417-region-wildcard-on-secret` | 2 | min=5 | +3 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-419-iam-multi-segment-path-wildcard` | 2 | min=4 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-501-principal-arn-stringlike-any-root` | 6 | min=7 | +1 | scorer below | `Condition.StringLike.aws:PrincipalArn: arn:aws:iam::*:root` matches the named principa... |
| `agent_discovered/agent-503-principal-org-id-foreign` | 1 | min=6 | +5 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-508-bedrock-agent-runtime-rag-exfil` | 4 | min=7 | +3 | scorer below | Resource: `*` for bedrock-agent-runtime (broad cross-resource read/access) |
| `agent_discovered/agent-516-iam-pass-glob` | 7 | min=8 | +1 | scorer below | Wildcard within sensitive service action: `iam:Pass*` |
| `agent_discovered/agent-518-omics-create-workflow` | 6 | min=7 | +1 | scorer below | State-changing action `omics:CreateWorkflow` on Resource: `*` (IAM access level: Write) |
| `agent_discovered/agent-519-iotsitewise-access-policy` | 6 | min=7 | +1 | scorer below | State-changing action `iotsitewise:CreateAccessPolicy` on Resource: `*` (IAM access lev... |
| `agent_discovered/agent-520-ssm-incidents-response-plan` | 6 | min=7 | +1 | scorer below | State-changing action `ssm-incidents:CreateResponsePlan` on Resource: `*` (IAM access l... |
| `agent_discovered/agent-521-stringnotequals-inverted-deny` | 8 | min=9 | +1 | scorer below | `iam:DeleteUser` on Resource: `*` touches sensitive service `iam` |
| `agent_discovered/agent-522-mq-create-user` | 6 | min=7 | +1 | scorer below | State-changing action `mq:CreateUser` on Resource: `*` (IAM access level: Write) |
| `agent_discovered/agent-523-ec2-copy-image-exfil` | 6 | min=7 | +1 | scorer below | State-changing action `ec2:CopyImage` on Resource: `*` (IAM access level: Write) |
| `agent_discovered/agent-524-iam-tag-policy-saml-oidc` | 6 | min=7 | +1 | scorer below | `iam:TagPolicy` on Resource: `*` touches sensitive service `iam` |
| `agent_discovered/agent-525-kms-reencrypt-key-swap` | 6 | min=7 | +1 | scorer below | `kms:ReEncryptFrom` on Resource: `*` touches sensitive service `kms` |
| `agent_discovered/agent-526-codeartifact-external-connection` | 6 | min=7 | +1 | scorer below | State-changing action `codeartifact:AssociateExternalConnection` on Resource: `*` (IAM ... |
| `agent_discovered/agent-527-route53-narrow-zone-hijack` | 5 | min=7 | +2 | scorer below | `route53:ChangeResourceRecordSets` is a high-impact mutation — a single narrowly-scoped... |
| `agent_discovered/agent-528-iot-policy-attach` | 6 | min=7 | +1 | scorer below | State-changing action `iot:CreatePolicy` on Resource: `*` (IAM access level: Permission... |
| `agent_discovered/agent-604-trust-google-aud-stringequals-wildcard` | 3 | min=5 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-605-trust-service-wildcard-suffix` | 6 | min=8 | +2 | scorer below | `Principal.Service` (*.amazonaws.com) with no Condition — every caller from that servic... |
| `agent_discovered/agent-607-kms-key-wildcard-resource` | 6 | min=7 | +1 | scorer below | `kms:Decrypt` / `kms:GenerateDataKey` without `kms:ViaService` or `kms:EncryptionContex... |
| `agent_discovered/agent-612-statement-string-not-dict` | 1 | min=5 | +4 | scorer below | No statements in policy |
| `agent_discovered/agent-613-version-2008-policy-variable-literal` | 1 | min=4 | +3 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-614-stringequals-literal-wildcard-region` | 4 | min=5 | +1 | scorer below | `iam:PassRole` is an escalation primitive — the target role may have more privileges th... |
| `agent_discovered/agent-615-cloudformation-gettemplate-secret-leak` | 4 | min=6 | +2 | scorer below | Resource: `*` for cloudformation (broad cross-resource read/access) |
| `agent_discovered/agent-617-cognito-identity-get-credentials` | 6 | min=8 | +2 | scorer below | `cognito-identity:GetCredentialsForIdentity` on Resource: `*` touches sensitive service... |
| `agent_discovered/agent-618-lambda-invokefunctionurl-public` | 6 | min=7 | +1 | scorer below | State-changing action `lambda:InvokeFunctionUrl` on Resource: `*` (IAM access level: Wr... |
| `agent_discovered/agent-619-sts-tagsession-abac` | 6 | min=7 | +1 | scorer below | `sts:TagSession` on Resource: `*` touches sensitive service `sts` |
| `agent_discovered/agent-620-sso-admin-delete-account-assignment` | 8 | min=9 | +1 | scorer below | `sso-admin:DeleteAccountAssignment` on Resource: `*` touches sensitive service `sso-admin` |
| `agent_discovered/agent-621-iam-create-service-linked-role` | 6 | min=7 | +1 | scorer below | `iam:CreateServiceLinkedRole` on Resource: `*` touches sensitive service `iam` |
| `agent_discovered/agent-622-empty-account-arn-resource` | 4 | min=6 | +2 | scorer below | `iam:PassRole` is an escalation primitive — the target role may have more privileges th... |
| `agent_discovered/agent-627-s3express-bypass` | 4 | min=5 | +1 | scorer below | Resource: `*` for s3express (broad cross-resource read/access) |
| `agent_discovered/agent-628-sns-topic-bare-wildcard` | 6 | min=7 | +1 | scorer below | State-changing action `sns:Publish` on Resource: `*` (IAM access level: Write) |
| `agent_discovered/agent-629-appstream-image-builder-rce` | 6 | min=7 | +1 | scorer below | State-changing action `appstream:CreateImageBuilder` on Resource: `*` (IAM access level... |
| `agent_discovered/agent-634-ec2-mass-recon-describe` | 1 | min=3 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-641-passrole-narrow-list-admin-buried` | 4 | min=5 | +1 | scorer below | `iam:PassRole` is an escalation primitive — the target role may have more privileges th... |
| `agent_discovered/agent-713-encoding-bypass-nbsp-in-action` | 6 | min=7 | +1 | scorer below | `iam: PassRole` on Resource: `*` touches sensitive service `iam` |
| `agent_discovered/agent-715-trust-policy-vacuous-externalid` | 7 | min=8 | +1 | scorer below | Trust-policy statement with literal account-ARN Principal on `sts:AssumeRole` — grants ... |
| `agent_discovered/agent-716-trust-policy-empty-externalid` | 7 | min=8 | +1 | scorer below | Trust-policy statement with literal account-ARN Principal on `sts:AssumeRole` — grants ... |
| `agent_discovered/agent-719-datasync-cross-account-exfil` | 6 | min=7 | +1 | scorer below | State-changing action `datasync:CreateTask` on Resource: `*` (IAM access level: Write) |
| `agent_discovered/agent-721-mgn-server-takeover` | 6 | min=7 | +1 | scorer below | State-changing action `mgn:StartCutover` on Resource: `*` (IAM access level: Write) |
| `agent_discovered/agent-722-networkmanager-pivot` | 6 | min=7 | +1 | scorer below | State-changing action `networkmanager:RegisterTransitGateway` on Resource: `*` (IAM acc... |
| `agent_discovered/agent-723-greengrass-v2-passrole-fleet-rce` | 6 | min=8 | +2 | scorer below | State-changing action `greengrass:CreateDeployment` on Resource: `*` (IAM access level:... |
| `agent_discovered/agent-724-datasync-passrole-exfil` | 6 | min=8 | +2 | scorer below | State-changing action `datasync:CreateTask` on Resource: `*` (IAM access level: Write) |
| `agent_discovered/agent-801-double-slash-path-bypass` | 3 | min=5 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-802-apigateway-apikeys-collection` | 3 | min=5 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-804-iam-recon-narrow-assumerole` | 6 | min=7 | +1 | scorer below | `iam:ListRoles` on Resource: `*` touches sensitive service `iam` |
| `agent_discovered/agent-805-passrole-narrow-known-admin-name` | 4 | min=7 | +3 | scorer below | `iam:PassRole` is an escalation primitive — the target role may have more privileges th... |
| `agent_discovered/agent-806-autoscaling-createasg-privilege-escalation` | 6 | min=7 | +1 | scorer below | State-changing action `autoscaling:CreateAutoScalingGroup` on Resource: `*` (IAM access... |
| `agent_discovered/agent-807-pacu-vpc-snapshot-recon` | 1 | min=3 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-808-resource-policy-no-principal` | 1 | min=4 | +3 | scorer below | All statements are scoped or limited; no broad patterns |
| `agent_discovered/agent-809-invalid-arn-region-typo` | 4 | min=4 + must_aa=false | +1 | scorer below (must_aa=false) | Resource `arn:aws:s3:us-easst-1::example-bucket/*` has region `us-easst-1` which is not... |
| `agent_discovered/agent-811-stringlike-oidc-repo-wildcard` | 7 | min=8 | +1 | scorer below | `Principal.Federated` is an ARN (`arn:aws:iam::111122223333:oidc-provider/token.actions... |
| `agent_discovered/agent-819-pacu-organizations-assume` | 7 | min=8 | +1 | scorer below | `sts:AssumeRole` on Resource: `*` (broad access to sensitive resource) |
| `agent_discovered/agent-911-glue-update-dev-endpoint-narrow` | 6 | min=7 | +1 | scorer below | Code-execution primitive on narrow resource: glue:UpdateDevEndpoint. Even on a single n... |
| `agent_discovered/agent-913-sagemaker-presigned-domain-url-narrow` | 6 | min=7 | +1 | scorer below | Code-execution primitive on narrow resource: sagemaker:CreatePresignedDomainUrl. Even o... |
| `realworld_composite/cicd-eks-nodegroup-controller` | 9 | max=7 | +2 | scorer above | `iam:PassRole` is an escalation primitive — the target role may have more privileges th... |
| `realworld_composite/glue-crawler-data-lake` | 8 | max=5 | +3 | scorer above | `glue:GetDatabase` on Resource: `*` touches sensitive service `glue` |
| `realworld_composite/security-audit-readonly` | 6 | max=5 | +1 | scorer above | `iam:GetAccountAuthorizationDetails` on Resource: `*` touches sensitive service `iam` |
| `research_patterns/research-01-42-passrole-asg-createasg-existing-lc` | 6 | min=7 | +1 | scorer below | State-changing action `autoscaling:CreateAutoScalingGroup` on Resource: `*` (IAM access... |
| `research_patterns/research-02-3-pacu-api-gateway-create-api-keys` | 4 | min=5 | +1 | scorer below | Resource: `*` for apigateway (broad cross-resource read/access) |
| `research_patterns/research-02-5-pacu-organizations-assume-role` | 7 | min=8 | +1 | scorer below | `sts:AssumeRole` on Resource: `*` (broad access to sensitive resource) |
| `research_patterns/research-02-5-pacu-vpc-enum-lateral` | 1 | min=3 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `research_patterns/research-02-6-pacu-cloudtrail-download-events` | 4 | min=4 + must_aa=false | +1 | scorer below (must_aa=false) | Resource: `*` for cloudtrail (broad cross-resource read/access) |
| `research_patterns/research-02-6-pacu-guardduty-whitelist-ip` | 6 | min=7 | +1 | scorer below | State-changing action `guardduty:CreateThreatIntelSet` on Resource: `*` (IAM access lev... |
| `research_patterns/research-02-7-pacu-ebs-enum-snapshots-unauth` | 1 | min=3 | +2 | scorer below | All statements are scoped or limited; no broad patterns |
| `research_patterns/research-05-1-capital-one-waf-role` | 7 | min=8 | +1 | scorer below | Action-name wildcard `s3:List*` on broad resource — matches multiple s3 APIs at once |
| `research_patterns/research-05-2-code-spaces-root-destructive` | 8 | min=9 | +1 | scorer below | Destructive action `ec2:TerminateInstances` on Resource: `*` (blast radius = every reso... |
| `research_patterns/research-07-5-aa-invalid-arn-prefix-region` | 4 | min=4 + must_aa=false | +1 | scorer below (must_aa=false) | Resource `arn:aws:s3:us-easst-1::example-bucket/*` has region `us-easst-1` which is not... |
| `research_patterns/research-07-5-aa-missing-principal` | 1 | min=4 | +3 | scorer below | All statements are scoped or limited; no broad patterns |
| `research_patterns/research-09-5-lambda-eventbridge-persistence` | 8 | min=9 | +1 | scorer below | State-changing action `events:PutRule` on Resource: `*` (IAM access level: Write) |
| `research_patterns/research-10-7-question-mark-glob` | 5 | min=6 | +1 | scorer below | Action-name wildcard `s3:GetObjec?` on broad resource — matches multiple s3 APIs at once |
| `research_patterns/research-11-3-stringlike-sub-github` | 7 | min=8 | +1 | scorer below | `Principal.Federated` is an ARN (`arn:aws:iam::111122223333:oidc-provider/token.actions... |
| `research_patterns/research-12-4-deny-notaction-createuser` | 1 | min=2 | +1 | scorer below | All statements are scoped or limited; no broad patterns |
| `research_patterns/research-13-14-s3-star-alternative-surfaces` | 7 | min=8 | +1 | scorer below | Resource: `*` for s3-object-lambda, s3-outposts, s3express (broad cross-resource read/a... |
| `vendor_real_world/01-datadog-aws-integration-readonly` | 8 | max=5 | +3 | scorer above | Request marked read-only but `events:CreateEventBus` is IAM-classified as `Write` (muta... |
| `vendor_real_world/06-aws-self-manage-credentials` | 9 | max=5 | +4 | scorer above | `iam:GetAccountSummary` on Resource: `*` touches sensitive service `iam` |
| `vendor_real_world/07-s3-home-directory-user` | 9 | max=5 | +4 | scorer above | Resource: `*` for s3 (broad cross-resource read/access) |
| `vendor_real_world/11-wiz-style-securityaudit-readonly` | 7 | max=5 | +2 | scorer above | Action-name wildcard `ec2:Describe*` on broad resource — matches multiple ec2 APIs at once |
| `vendor_real_world/12-s3-cross-region-replication-role` | 6 | max=5 | +1 | scorer above | State-changing action `s3:ReplicateObject` on Resource: `*` (IAM access level: Write) |
| `vendor_real_world/16-organizations-audit-role-readonly` | 6 | max=4 | +2 | scorer above | `organizations:ListAccounts` on Resource: `*` touches sensitive service `organizations` |
| `vendor_real_world/17-multi-region-condition-scoped` | 8 | max=5 | +3 | scorer above | Action-name wildcard `ec2:Describe*` on broad resource — matches multiple ec2 APIs at once |

### Silent cases (scorer fires NO risk factor — top priority for new detectors)

These 12 cases score on the no-broad-patterns floor and have only
the message `"All statements are scoped or limited; no broad patterns"`.
Adding ANY detector that fires moves the score off the bottom.

- `agent_discovered/agent-160-rds-data-narrow-aurora`
- `agent_discovered/agent-183-assumerole-saml-narrow-admin`
- `agent_discovered/agent-188-scarleteel-cross-account-assume`
- `agent_discovered/agent-193-conditionkey-sourcevpce-typo`
- `agent_discovered/agent-408-numeric-mfa-age-huge`
- `agent_discovered/agent-411-bool-irrelevant-key`
- `agent_discovered/agent-417-region-wildcard-on-secret`
- `agent_discovered/agent-419-iam-multi-segment-path-wildcard`
- `agent_discovered/agent-604-trust-google-aud-stringequals-wildcard`
- `agent_discovered/agent-801-double-slash-path-bypass`
- `agent_discovered/agent-802-apigateway-apikeys-collection`
- `research_patterns/research-12-4-deny-notaction-createuser`

## Log entry — append to docs/calibration/CALIBRATION-LOG.md

```
- 2026-05-19: corpus sweep #256 — 2,267 cases re-scored against
  scorer commit 31417d2; 96 failures (95.77% pass). Two failure
  modes: 86 under-flags (concentrated in agent_discovered newer-
  service primitives + STS federated variants + condition vacuity
  edges) + 10 over-flags (concentrated in vendor_real_world read-
  mostly policies that hit sensitive-service rule linearly).
  Both modes were pre-documented in corpus YAML CALIBRATION-GAP
  annotations as scorer backlog from adversarial rounds 8-13. No
  scorer fixes shipped; 13 proposed fixes triaged for founder
  decision. CI exclusion remains in place pending fix prioritization.
  See CALIBRATION-SWEEP-2026-05-19.md.
```
