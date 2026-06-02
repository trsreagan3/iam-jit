# Regression scenarios: deploy-ci-dogfood-iam.sh OIDC ownership check

Tracks the three scenarios the OIDC ownership check in
`scripts/deploy-ci-dogfood-iam.sh` must handle correctly.  Added with fix
for #709 (OIDC chicken-and-egg on re-deploys).

## Background

AWS allows exactly one OIDC provider per issuer URL per account.
`ci-nightly-dogfood.yaml` has a `CreateOidcProvider` condition:

```yaml
Conditions:
  CreateOidcProvider: !Equals [!Ref ExistingOidcProviderArn, ""]
```

If the script passes a non-empty `ExistingOidcProviderArn`, CFN sees
`GitHubOidcProvider` as "no longer in template" → **DELETE**.
This means passing the ARN back to CFN when it was the one that created it
causes CFN to delete the provider it owns.

## Scenario A — Fresh deploy (no stack, no provider)

**State before run:**
- CloudFormation stack `iam-jit-ci-nightly` does not exist
- No `token.actions.githubusercontent.com` OIDC provider in account

**Script trace:**
1. `list-open-id-connect-providers` returns empty list
2. `EXISTING_OIDC_ARN=""` (probe finds nothing)
3. `describe-stack-resources` errors (stack not found); `STACK_OIDC=""`
4. Ownership check: both empty — ownership block not entered
5. `ExistingOidcProviderArn=""` passed to CFN
6. `CreateOidcProvider` condition is `true` — CFN creates provider + manages it

**Expected outcome:** stack created, OIDC provider created, role created. ✓

---

## Scenario B — Re-deploy where stack OWNS the existing OIDC (the #709 bug)

**State before run:**
- Stack `iam-jit-ci-nightly` EXISTS
- `GitHubOidcProvider` physical resource ID = `arn:aws:iam::590519617224:oidc-provider/token.actions.githubusercontent.com`
- Same ARN is present in `list-open-id-connect-providers`

**Script trace (BEFORE fix — broken):**
1. `list-open-id-connect-providers` returns the ARN
2. `EXISTING_OIDC_ARN="arn:aws:iam::590519617224:oidc-provider/..."` (non-empty)
3. No ownership check — ARN passed directly to CFN
4. `CreateOidcProvider` condition is `false` — CFN removes `GitHubOidcProvider` from stack
5. CFN **DELETES** the provider; next run fails with "No OpenIDConnect provider found"

**Script trace (AFTER fix — correct):**
1. `list-open-id-connect-providers` returns the ARN
2. `EXISTING_OIDC_ARN="arn:aws:iam::590519617224:oidc-provider/..."` (non-empty)
3. `describe-stack-resources --logical-resource-id GitHubOidcProvider` returns same ARN
4. `STACK_OIDC == EXISTING_OIDC_ARN` → ownership match detected
5. `EXISTING_OIDC_ARN=""` — cleared before CFN call
6. `CreateOidcProvider` condition is `true` — CFN keeps managing it; no delete, no recreate

**Expected outcome:** stack updates in-place, OIDC provider preserved. ✓

---

## Scenario C — Deploy where OIDC pre-exists from a DIFFERENT stack or external source

**State before run:**
- A separate process/stack created `arn:aws:iam::590519617224:oidc-provider/token.actions.githubusercontent.com`
- Stack `iam-jit-ci-nightly` either does not exist yet, or its `GitHubOidcProvider`
  resource does NOT match the found ARN (e.g. was never created because
  `ExistingOidcProviderArn` was set on first deploy)

**Script trace:**
1. `list-open-id-connect-providers` returns the external ARN
2. `EXISTING_OIDC_ARN="arn:aws:iam::..."` (non-empty)
3. `describe-stack-resources` either errors (stack not found) or returns a
   different physical ID (or `None` / empty text)
4. `STACK_OIDC != EXISTING_OIDC_ARN` → ownership match NOT triggered
5. `EXISTING_OIDC_ARN` kept as-is; passed to CFN
6. `CreateOidcProvider` condition is `false` — CFN references the external
   provider; skips creation; no conflict, no "already exists" error

**Expected outcome:** stack created/updated; external OIDC reused, not touched. ✓

---

## Manual verification (no real AWS required)

The script logic can be exercised with mock CLI stubs:

```bash
#!/usr/bin/env bash
# Paste into a temp file and run to trace scenario B manually.
set -euo pipefail

STACK_NAME="iam-jit-ci-nightly"
AWS_REGION="us-east-1"
MOCK_ARN="arn:aws:iam::590519617224:oidc-provider/token.actions.githubusercontent.com"

# Stub: simulate "list-open-id-connect-providers" returning our ARN
EXISTING_OIDC_ARN="${MOCK_ARN}"

# Stub: simulate "describe-stack-resources" returning the same ARN (stack owns it)
STACK_OIDC="${MOCK_ARN}"

if [[ -n "${STACK_OIDC}" && "${STACK_OIDC}" == "${EXISTING_OIDC_ARN}" ]]; then
  EXISTING_OIDC_ARN=""
  echo "PASS: ownership detected — EXISTING_OIDC_ARN cleared"
else
  echo "FAIL: ownership not detected — ARN would have been passed to CFN"
  exit 1
fi

[[ -z "${EXISTING_OIDC_ARN}" ]] && echo "PASS: EXISTING_OIDC_ARN is empty (CFN will keep managing)"
```

Run with `bash <script>` — both PASS lines should print; exit 0.

---

## Regression history

| Date | Issue | Symptom | Root cause |
|------|-------|---------|------------|
| 2026-05-31 | #709 | Re-running deploy deleted CFN-owned OIDC provider; next CI run failed "No OpenIDConnect provider found" | Script passed non-empty `ExistingOidcProviderArn` even when current stack owned the provider → CFN's `CreateOidcProvider` condition flipped false → CFN deleted the resource |
