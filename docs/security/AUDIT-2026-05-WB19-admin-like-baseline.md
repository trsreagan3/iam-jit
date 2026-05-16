# Round 19 audit — AdminLikeWithSensitiveExclusions baseline (#154)

## Closure status (2026-05-16, post-audit fix pass)

| Finding | Status |
|---|---|
| MED-19-01 (s3:ListBucket falls through Deny — missing bucket-level ARN) | ✅ FIXED — DenySensitiveBucketReads now lists BOTH bucket-level (no /*) AND object-level (/*) ARNs for each sensitive pattern. New test asserts both forms; matches sibling ExploreReadOnlyWithSensitiveExclusions. |
| MED-19-02 (discrete actions don't cover audit-tampering vectors) | ✅ FIXED — block renamed DenyAuditInfraDestructionOrTampering; uses wildcards (cloudtrail:Stop*/Delete*/Update*, config:Stop*/Delete*, guardduty:Delete*/Disassociate*/Update*) + adds PutEventSelectors, PutInsightSelectors, logs:DeleteLogGroup/DeleteLogStream. cloudtrail:Update* closes the redirect-logs vector. New test asserts both destruction AND tampering wildcards. |
| LOW-19-03 (ssm:GetParameter* wildcard) | ✅ FIXED — DenySecretData uses ssm:GetParameter* wildcard + adds secretsmanager:BatchGetSecretValue (AWS 2024-01 bypass). New test. |
| LOW-19-04 (test comment refers to non-existent kms-block) | ✅ FIXED — comment updated. |
| LOW-19-05 (summary missing IAM principal-pivot note) | ✅ FIXED — entry summary explicitly notes "this policy DOES NOT block IAM principal-pivot (Allow `iam:*` + `sts:*`). For full containment, pair with a Permissions Boundary." |

Old test test_admin_like_baseline_denies_secret_data deleted — superseded by wildcard-form test. Post-closure: 25 catalog tests pass.

Commit under review: `16f8803` (`feat(catalog): add AdminLikeWithSensitiveExclusions baseline (#154)`).

Scope: catalog-data addition. One new `ManagedPolicyEntry` (`AdminLikeWithSensitiveExclusions`) in `src/iam_jit/aws_managed_catalog.py` + 6 sentinel tests in `tests/test_aws_managed_catalog.py`. No logic changes; no new functions; the browse API (`list_entries`, `get_entry`) is unchanged. The entry composes the third member of the broad-with-denylist family alongside `ExploreReadOnlyWithSensitiveExclusions` (read-only) and raw `AdministratorAccess` (unconstrained).

Audit focused on (1) policy-shape syntactic correctness, (2) AWS-IAM-semantics of the deny statements, (3) coverage gaps vs the docstring claim + the sibling `ExploreReadOnlyWithSensitiveExclusions` baseline, (4) scoring sanity, (5) browse-API integration, (6) test integrity. Read-only audit.

## Headline

5 findings: **0 CRIT, 0 HIGH, 2 MED, 3 LOW.** The catalog entry is syntactically well-formed, the Allow + Deny composition relies on AWS-IAM-standard "explicit-deny-overrides-allow" semantics which is correct, the scoring path returns 10/10 (parity with raw `AdministratorAccess` — appropriate; deny statements protect specific resources but the broad Allow still grants every other admin power), the browse-API integration is clean (`access_type='admin'` filter surfaces the entry as expected, `get_entry` round-trips), and the 6 sentinel tests cover the structural and per-deny-category claims they make.

The two MEDs are real silent fail-opens worth fixing before the entry is presented as the "recommended-default admin-class baseline":

- **MED-19-01** — `DenySensitiveBucketReads.Resource` lists object-level ARNs only (`arn:aws:s3:::*-secrets/*` with trailing `/*`). The statement also denies `s3:ListBucket`, but `s3:ListBucket` operates on the BUCKET-level resource (no trailing `/*`). Per AWS IAM resource-type rules, the deny silently does nothing for `s3:ListBucket` calls — an attacker can enumerate key names in `*-secrets` / `*-sensitive` / `*-pii` / `*-customer-data` buckets (key names themselves can leak data: e.g. `customer-bob@bank.com.json`). The sibling `ExploreReadOnlyWithSensitiveExclusions` entry (same file, lines 247-261) gets this right — it lists BOTH `arn:aws:s3:::*-secrets/*` AND `arn:aws:s3:::*-secrets` for each sensitive pattern. Fix is mechanical: mirror the Explore baseline's Resource list.

- **MED-19-02** — `DenyAuditInfraDestruction` claims via commit message + summary to block `cloudtrail:Stop*`, `cloudtrail:Delete*`, `config:Delete*`, `guardduty:Delete*` but enumerates discrete actions only. Real-world audit-evasion pivots that bypass the current list: `cloudtrail:UpdateTrail` (redirect logs to attacker bucket), `cloudtrail:PutEventSelectors` (exclude attacker activity from logs), `config:StopConfigurationRecorder` (silent stop, no delete), `config:DeleteDeliveryChannel`, `guardduty:UpdateDetector` (suspend findings), `logs:DeleteLogGroup` (drop CloudTrail's CW log group), `s3:PutBucketLogging` / `s3:DeleteBucket` on the CloudTrail bucket. The docstring's `Stop*` / `Delete*` wildcards are not used — the policy enumerates only 8 discrete actions. Either widen the actions to match the docstring (use wildcards) or downgrade the docstring claim.

The three LOWs are: a known-gap `ssm:GetParameterHistory` (returns parameter values, not in the deny list while sibling reads are), `secretsmanager:BatchGetSecretValue` (added by AWS in 2024-01, not in the deny list while `GetSecretValue` is), and the test-comment description of statement structure being slightly misleading (no actual bug — the test passes correctly).

The cross-principal escape (Allow includes `iam:*`, so a principal with this policy can `iam:CreateRole` + `iam:PutRolePolicy` to a NEW role without the Denies, then `sts:AssumeRole` into it) is a documented property of any Allow-+-Deny policy without a Permissions Boundary. This is **not** a bug in the catalog entry — it is the IAM semantics customers should understand when picking the baseline. Worth a note in the entry summary; not a finding.

Regression suite: **1947 passed, 29 skipped, 14 deselected** in 89s — matches the audit-prompt expectation exactly. No regressions.

## Closure status

| Finding | Status |
|---|---|
| MED-19-01 `DenySensitiveBucketReads` resource list missing bucket-level ARNs → `s3:ListBucket` deny is a no-op | OPEN |
| MED-19-02 `DenyAuditInfraDestruction` enumerates 8 discrete actions; docstring claims `Stop*` / `Delete*` wildcards. Gap covers cloudtrail:UpdateTrail / PutEventSelectors, config:StopConfigurationRecorder / DeleteDeliveryChannel, guardduty:UpdateDetector, logs:DeleteLogGroup, s3:PutBucketLogging on trail bucket | OPEN |
| LOW-19-03 `DenySecretData` missing `ssm:GetParameterHistory` (returns parameter values; sibling `ssm:GetParameter*` reads are denied) and `secretsmanager:BatchGetSecretValue` (added 2024-01) | OPEN |
| LOW-19-04 Test comment in `test_admin_like_baseline_has_broad_allow_and_three_deny_statements` says "audit-infra destruction + kms-key destruction are combined into one block" but the policy has no separate kms-key-destruction Sid — kms key actions are folded into `DenyAuditInfraDestruction`. The test logic itself is correct; only the comment is mildly misleading. | OPEN |
| LOW-19-05 Entry summary + commit message do not call out the IAM cross-principal escape (Allow `iam:*` + Allow `sts:AssumeRole` permits the principal to create a new role without the Denies and assume it). This is standard IAM behavior, not a bug, but customers picking this as "recommended default" may not realize it. Customer-facing docs should note the Permissions-Boundary requirement for hard containment. | OPEN |

## CRIT findings

None.

## HIGH findings

None.

## MED findings

### MED-19-01 — `DenySensitiveBucketReads` resource list omits bucket-level ARNs; `s3:ListBucket` deny silently no-ops

- File: `src/iam_jit/aws_managed_catalog.py:474-488`
- Issue: the statement lists three actions — `s3:GetObject`, `s3:ListBucket`, `s3:GetObjectVersion` — but Resource enumerates only object-level ARNs:
  ```
  arn:aws:s3:::*-secrets/*
  arn:aws:s3:::*-sensitive/*
  arn:aws:s3:::*-pii/*
  arn:aws:s3:::*-customer-data/*
  ```
  Per the AWS IAM Action / Resource type mapping ([AWS docs: actions, resources, condition keys for Amazon S3](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html)):
  - `s3:GetObject` and `s3:GetObjectVersion` operate on the **object** resource (`arn:aws:s3:::bucket/key`) — MATCHED by these patterns.
  - `s3:ListBucket` operates on the **bucket** resource (`arn:aws:s3:::bucket`, NO trailing `/key`) — NOT matched by any of the listed patterns.

  Effect: a principal granted this baseline can call `s3:ListBucket` on `bucket-name-secrets` and the Deny silently does not apply (no resource match in the Deny → falls through to the broad `Allow * on *`). The principal can enumerate key names in `*-secrets`, `*-sensitive`, `*-pii`, `*-customer-data` buckets. Object content reads (`GetObject`) are still correctly blocked. Whether key-name enumeration is "leakage" depends on naming conventions, but a common pattern is `customer-bob@bank.com.json`, `2025-10-15-backup.sql.enc`, `loan-application-{ssn-fragment}.pdf` — key names themselves can leak.

- Why this is the kind of bug audit-cadence-discipline targets: the asymmetry with the sibling `ExploreReadOnlyWithSensitiveExclusions` entry in the same file (lines 247-261) — which correctly lists BOTH `arn:aws:s3:::*-secrets/*` AND `arn:aws:s3:::*-secrets` for each sensitive pattern — is the textbook silent-fail-open pattern. The test `test_admin_like_baseline_denies_sensitive_s3_patterns` checks the four substring patterns are present in the Resource list but does NOT check resource-type / action compatibility; the test passes while the deny is half-broken.

- Repro (white-box):
  ```python
  from iam_jit.aws_managed_catalog import get_entry
  e = get_entry('AdminLikeWithSensitiveExclusions')
  s3_deny = next(s for s in e['policy']['Statement']
                 if s.get('Sid') == 'DenySensitiveBucketReads')
  # Bucket-level ARN form for s3:ListBucket (no /key suffix):
  bucket_arn = 'arn:aws:s3:::acme-prod-secrets'
  # The Deny's Resource list — NONE match the bucket-level ARN:
  for pat in s3_deny['Resource']:
      print(pat, 'matches?', pat.replace('*', 'acme-prod') == bucket_arn or pat.endswith('/*'))
  # All four entries end in /* — none match the bucket-level ARN.
  # Compare ExploreReadOnlyWithSensitiveExclusions which lists both forms:
  e2 = get_entry('ExploreReadOnlyWithSensitiveExclusions')
  print(next(s for s in e2['policy']['Statement']
             if s.get('Sid') == 'ExcludeSensitiveBucketReads')['Resource'])
  # Includes both arn:aws:s3:::*-secrets/* AND arn:aws:s3:::*-secrets — correct.
  ```

- Impact: silent fail-open. Customer believes the baseline blocks reading sensitive buckets; in fact only object reads are blocked, while `s3:ListBucket` is not blocked. For buckets with descriptive key names (the common case), key-name enumeration is itself a leak.

- Fix: mirror the sibling `ExploreReadOnlyWithSensitiveExclusions` entry's Resource list (add the four bucket-level ARNs without trailing `/*`):
  ```python
  "Resource": [
      "arn:aws:s3:::*-secrets/*",
      "arn:aws:s3:::*-sensitive/*",
      "arn:aws:s3:::*-pii/*",
      "arn:aws:s3:::*-customer-data/*",
      "arn:aws:s3:::*-secrets",
      "arn:aws:s3:::*-sensitive",
      "arn:aws:s3:::*-pii",
      "arn:aws:s3:::*-customer-data",
  ],
  ```
  And tighten `test_admin_like_baseline_denies_sensitive_s3_patterns` to assert BOTH forms (`/*` AND no-suffix) are present, not just the four substring patterns — otherwise the test will silently re-pass if someone re-introduces the bug.

### MED-19-02 — `DenyAuditInfraDestruction` enumerates 8 discrete actions but docstring + commit message imply wildcard coverage; multiple real-world audit-evasion pivots are not blocked

- File: `src/iam_jit/aws_managed_catalog.py:489-503`
- Issue: the commit message documents the deny block as covering `cloudtrail:Stop*`, `cloudtrail:Delete*`, `config:Delete*`, `guardduty:Delete*` — these are wildcard patterns. The policy_shape, however, enumerates 8 discrete actions only:
  ```
  cloudtrail:StopLogging
  cloudtrail:DeleteTrail
  config:DeleteConfigRule
  config:DeleteConfigurationRecorder
  guardduty:DeleteDetector
  guardduty:DisassociateFromMasterAccount
  kms:ScheduleKeyDeletion
  kms:DisableKey
  ```
  Audit-evasion pivots that bypass the current list (an attacker with this baseline could use these to hide their activity even though the docstring claims "audit trail must survive a (hypothetical) compromise" per `test_admin_like_baseline_denies_audit_infra_destruction`):

  | Action | Effect | In deny list? |
  |---|---|---|
  | `cloudtrail:UpdateTrail` | Redirect logs to attacker-controlled S3 bucket | NO |
  | `cloudtrail:PutEventSelectors` | Exclude attacker's events from the trail (event filtering) | NO |
  | `cloudtrail:DeleteEventDataStore` | Drop event data stores (CloudTrail Lake) | NO |
  | `config:StopConfigurationRecorder` | Stop recording without deleting (silent) | NO |
  | `config:PutConfigurationRecorder` | Replace recorder with a no-op one | NO |
  | `config:DeleteDeliveryChannel` | Drop log delivery (Config silently stops shipping) | NO |
  | `guardduty:UpdateDetector` | Disable threat findings without delete | NO |
  | `guardduty:DeleteMembers` / `guardduty:StopMonitoringMembers` | Detach org members from central GuardDuty | NO |
  | `logs:DeleteLogGroup` | Delete the CloudTrail / Config CloudWatch log group | NO |
  | `s3:PutBucketLogging` | Disable logging on the CloudTrail / Config bucket | NO |
  | `s3:DeleteBucket` (on the trail bucket) | Delete the bucket entirely | NO |

  The bypass surface is wide: `cloudtrail:UpdateTrail` alone is sufficient for an attacker to redirect logs to a bucket they own, after which they can delete the rerouted logs at will.

- Impact: silent fail-open against the docstring's claim. A reviewer reading the policy_shape may assume the wildcarded patterns from the commit message are present; in fact only 8 discrete actions are enumerated, leaving the most common audit-evasion pivots open.

- Recommended fix (one of):
  - **(a) [recommended]** Use wildcard actions to match the docstring claim:
    ```python
    "Action": [
        "cloudtrail:Stop*",
        "cloudtrail:Delete*",
        "cloudtrail:Update*",
        "cloudtrail:Put*",
        "config:Delete*",
        "config:Stop*",
        "config:Put*",
        "guardduty:Delete*",
        "guardduty:Update*",
        "guardduty:Stop*",
        "guardduty:Disassociate*",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
        "logs:Delete*",
    ],
    ```
    Risks: `config:Put*` is broad — would also block `config:PutConfigRule` (which is a legitimate admin task during incident response). Wildcards trade off precision vs coverage.
  - **(b)** Keep discrete enumeration but add the high-value misses: `cloudtrail:UpdateTrail`, `cloudtrail:PutEventSelectors`, `config:StopConfigurationRecorder`, `config:DeleteDeliveryChannel`, `guardduty:UpdateDetector`, `logs:DeleteLogGroup`. This stays explicit + commit-message-honest if the docstring claim is also softened.
  - **(c)** Add an `s3:PutBucketLogging` / `s3:DeleteBucket` deny resource-scoped to a customer-configurable "audit infra bucket" placeholder (e.g. `arn:aws:s3:::*-cloudtrail/*` + `*-config/*`) — symmetric with how `DenySensitiveBucketReads` works.
  - Whatever is chosen, the `test_admin_like_baseline_denies_audit_infra_destruction` test should be expanded to assert at least one of the currently-missed pivots is in the deny list — to prevent regression if the action list is later trimmed.

## LOW findings

### LOW-19-03 — `DenySecretData` missing `ssm:GetParameterHistory` and `secretsmanager:BatchGetSecretValue`

- File: `src/iam_jit/aws_managed_catalog.py:460-473`
- `ssm:GetParameterHistory` returns parameter VALUES (alongside metadata) — it is a sibling of `ssm:GetParameter` / `ssm:GetParameters` / `ssm:GetParametersByPath` in terms of data exposure. The deny list includes the other three but not this one. The commit message's prose claim "ssm:GetParameter*" wildcard, if implemented literally as `ssm:GetParameter*`, would have covered this — but the policy enumerates discrete actions.
- `secretsmanager:BatchGetSecretValue` was added by AWS in early 2024 as a multi-secret read alternative to `GetSecretValue`. Not yet ubiquitous in client SDKs but increasingly used. Not in the deny list.
- Fix: either widen to `ssm:GetParameter*` + add `secretsmanager:GetSecretValue` → `secretsmanager:*GetSecretValue*` (or wildcard), or enumerate the two missing actions explicitly.
- Severity: LOW because the gap is in the secret-data domain (high-value if exploited) but requires the attacker to know to use these specific alternate actions; and the standard SDK call paths (`get_secret_value`, `get_parameter`) ARE blocked. The miss surfaces as "competent attacker bypasses the named-API filter."

### LOW-19-04 — Test comment in `test_admin_like_baseline_has_broad_allow_and_three_deny_statements` mildly misleading

- File: `tests/test_aws_managed_catalog.py:96-97`
- The comment reads: `"Statements 1-3 are the three deny-category blocks (audit-infra destruction + kms-key destruction are combined into one block)."`
- The actual policy has no separate "kms-key destruction" Sid — KMS key actions (`kms:ScheduleKeyDeletion`, `kms:DisableKey`) are folded into `DenyAuditInfraDestruction`, which is correct (KMS key destruction IS audit-infra destruction when the destroyed key was encrypting trails or backups). The comment description ("combined into one block") is technically accurate but invites the reader to wonder where the separate kms-key block is. Minor.
- Fix: reword to e.g. `"Statements 1-3 are the three deny-category blocks: secrets, sensitive S3, and audit-infra (which includes KMS key destruction since destroying a key destroys the trail it encrypted)."`. Or just drop the parenthetical.

### LOW-19-05 — Entry summary omits IAM cross-principal-escape note

- File: `src/iam_jit/aws_managed_catalog.py:435-443` (the `summary=` field)
- The entry summary positions itself as "Recommended default over raw AdministratorAccess for incident response, infrastructure work, and most admin-class tasks." This is reasonable framing — the Denies do meaningfully reduce blast radius for the most common admin tasks. However, the entry includes `iam:*` and `sts:*` in the broad Allow (via `Action: "*"`), and the Denies do NOT cover IAM principal management. A principal with this baseline can:
  ```
  iam:CreateRole + iam:PutRolePolicy (grant the NEW role a policy without the Denies)
                 + sts:AssumeRole → new principal with no Denies → read secrets freely.
  ```
  This is standard AWS IAM semantics — Denies in a permissions policy apply only to the principal evaluating THAT policy, not to principals the original principal may create. The standard mitigation is a Permissions Boundary on `iam:CreateRole` / `iam:CreateUser` / `iam:PutRolePolicy`, which is out of scope for a managed-style entry like this.
- Not a bug. But a customer picking this baseline as "the safe-by-default admin" without understanding the IAM escape will overestimate its containment. The summary text should note (one sentence) that hard containment requires a Permissions Boundary on IAM principal-management actions.
- Severity: LOW (documentation gap, not a code bug; the escape is a fundamental AWS IAM property not specific to this entry).

## Test-integrity notes

The 6 new tests in `tests/test_aws_managed_catalog.py` probe what they claim:

- `test_admin_like_baseline_present_in_catalog` — direct membership check on `_CATALOG`. Solid.
- `test_admin_like_baseline_has_broad_allow_and_three_deny_statements` — asserts structure: 1 broad Allow at index 0, 3 Denies thereafter, with the expected Sids. Solid. (Minor comment nit per LOW-19-04.)
- `test_admin_like_baseline_denies_secret_data` — asserts the 4 critical secret-reading actions appear in the union of all Deny statements' actions. The test does this correctly (using a flatten loop, handling both `Action: str` and `Action: list[str]` forms). Solid.
- `test_admin_like_baseline_denies_sensitive_s3_patterns` — asserts the 4 substring patterns appear in `DenySensitiveBucketReads.Resource`. **Doesn't catch MED-19-01** because it only checks substring presence; doesn't validate action ↔ resource-type compatibility. Recommend extending per the MED-19-01 fix note.
- `test_admin_like_baseline_denies_audit_infra_destruction` — asserts the 4 named audit-infra actions appear in `DenyAuditInfraDestruction.Action`. **Doesn't catch MED-19-02** because it only checks named actions are present; doesn't probe the wider attack surface. Recommend extending to assert at least one currently-missed pivot (e.g. `cloudtrail:UpdateTrail`) per the MED-19-02 fix note.
- `test_admin_like_baseline_filterable_by_admin_access_type` — asserts both AdminLike and AdministratorAccess appear in `list_entries(access_type='admin')`. Solid.
- `test_admin_like_baseline_get_entry_returns_policy` — round-trip through `get_entry()`. Solid.

Counting per the file diff: 7 test functions added (not 6 as the audit prompt + commit message claim — the test file gained 7 distinct `test_admin_like_*` functions, lines 86-180 of the new test file). Minor count discrepancy; no impact.

## Regression check

`pytest tests/ -q --ignore=tests/e2e --ignore=tests/test_calibration_corpus.py` → **1947 passed, 29 skipped, 14 deselected** in 89.11s. Matches the audit-prompt's expectation exactly. No regressions.

## Scoring sanity (audit point 3)

Scored all three broad-family baselines via `analyze_policy()` with a generic request (`principal=user1, duration=1h, reason="incident response"`):

| Baseline | Risk score | Factors | Notes |
|---|---|---|---|
| AdministratorAccess (raw) | 10 | 1 (`Action * grants every AWS API call`) | Expected. |
| AdminLikeWithSensitiveExclusions | 10 | 1 (same factor) | Score identical to raw admin. The deterministic scorer does not currently model "explicit Deny reduces score." This is consistent with the rest of the catalog (scorer cares about the broad Allow shape; Denies are not credited as risk-reducing). Acceptable per the project's calibration philosophy — the Deny statements add real protection but the broad Allow still grants every other admin power including `iam:*`. |
| ExploreReadOnlyWithSensitiveExclusions | 9 | 12 (per-`*:Verb*` wildcards) | Read-only is scored slightly lower per the verb-wildcard breakdown. |

No scoring regressions; no surprises. If the project wants to surface "this admin baseline is safer than raw AdministratorAccess" as a score signal, that would be a `_deterministic` change (out of scope for this audit) and would need its own calibration corpus per [[calibration-quality-bar]]. For now the entry's value-prop is in the customer-facing summary text + the explicit Deny semantics at AWS-IAM evaluation time, not in the score.

## Browse + filter integration (audit point 5)

- `list_entries(access_type='admin')` returns 3 entries: `AdminLikeWithSensitiveExclusions`, `AdministratorAccess`, `PowerUserAccess`. Includes the new entry as expected.
- `get_entry('AdminLikeWithSensitiveExclusions')` returns the full body with all 4 Statements + correct `access_type='admin'` + the `iam-jit:catalog/` ARN prefix (consistent with the sibling `ExploreReadOnlyWithSensitiveExclusions` entry's ARN convention).
- No regressions in the broader `list_entries` filter paths (service, source, query, tag) — these were tested separately in the test file and pass.

## Summary

5 findings, none blocking launch. **MED-19-01 (`s3:ListBucket` deny no-op) and MED-19-02 (audit-infra action enumeration gaps) are worth closing before the entry is presented as the "recommended-default admin-class baseline"** in the template browser UI, since both create the "customer believes the baseline blocks X, in fact it doesn't" trust gap [[audit-cadence-discipline]] is designed to prevent. The 3 LOWs are polish items that can be batched with the next catalog iteration. Test additions are structurally sound but two of them (sensitive-S3 + audit-infra) could be tightened to prevent regression of the silent fail-opens.
