#!/usr/bin/env bash
#
# Deploy the IAM role + GitHub OIDC provider that the #700 nightly CI
# dogfood (.github/workflows/dogfood-nightly.yml) assumes via OIDC.
#
# One-time setup. Run once per AWS account. Idempotent: re-running picks
# up template changes via `aws cloudformation deploy --no-fail-on-empty-
# changeset`. Reversible: `aws cloudformation delete-stack --stack-name
# iam-jit-ci-nightly` removes everything.
#
# Why this exists: the CI dogfood needs an IAM role that GitHub Actions
# can assume via OIDC, scoped to a specific (org/repo) and a minimal
# permission set. Clicking through the AWS console is error-prone +
# undocumented; this script + the CFN template make the setup a single
# command and version-control the exact permissions granted.
#
# Usage:
#   AWS_PROFILE=iam-jit AWS_REGION=us-east-1 scripts/deploy-ci-dogfood-iam.sh
#
# Optional overrides:
#   STACK_NAME=iam-jit-ci-nightly      # CFN stack name
#   GH_ORG=trsreagan3                  # GitHub org/user
#   GH_REPO=iam-jit                    # GitHub repo
#   ROLE_NAME=iam-jit-ci-nightly       # IAM role name (must match workflow)
#   BUDGET_EMAIL=ops@example.com       # cost-guard notification
#
# Exit codes:
#   0  — deploy successful (or no changes); role ARN printed to stdout
#   1  — deploy failed; CFN events tailed to stderr
#   2  — pre-flight check failed (wrong account, missing aws cli, etc.)
#
# Operator's `~/.aws/config` + `~/.aws/credentials` must NOT be modified.
# Sourced env vars only.

set -euo pipefail

# ----- defaults (override via env) -----
STACK_NAME="${STACK_NAME:-iam-jit-ci-nightly}"
GH_ORG="${GH_ORG:-trsreagan3}"
GH_REPO="${GH_REPO:-iam-jit}"
ROLE_NAME="${ROLE_NAME:-iam-jit-ci-nightly}"
BUDGET_EMAIL="${BUDGET_EMAIL:-trsreagan3@gmail.com}"
AWS_REGION="${AWS_REGION:-us-east-1}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="${REPO_ROOT}/infrastructure/cloudformation/ci-nightly-dogfood.yaml"

# ----- pre-flight -----
command -v aws >/dev/null 2>&1 || {
  echo "ERROR: 'aws' CLI not found in PATH. Install via 'brew install awscli'." >&2
  exit 2
}

[[ -f "${TEMPLATE}" ]] || {
  echo "ERROR: CFN template missing: ${TEMPLATE}" >&2
  exit 2
}

# Verify we can call AWS + capture the account ID. The role's ARN is
# computed by CFN, but printing the account here helps the operator
# confirm they're deploying to the right place BEFORE any change lands.
echo "==> Verifying AWS credentials..."
CALLER_JSON="$(aws sts get-caller-identity --output json 2>&1)" || {
  echo "ERROR: aws sts get-caller-identity failed:" >&2
  echo "${CALLER_JSON}" >&2
  echo "Hint: set AWS_PROFILE=iam-jit (or your equivalent) and re-run." >&2
  exit 2
}
ACCOUNT_ID="$(echo "${CALLER_JSON}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["Account"])')"
CALLER_ARN="$(echo "${CALLER_JSON}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["Arn"])')"
echo "    Account: ${ACCOUNT_ID}"
echo "    Caller:  ${CALLER_ARN}"
echo "    Region:  ${AWS_REGION}"
echo "    Stack:   ${STACK_NAME}"
echo

# ----- probe for existing GitHub OIDC provider -----
#
# AWS permits exactly ONE OIDC provider per issuer URL per account. If
# the account already has one wired in (common in shops that use OIDC
# for other workflows), the CFN stack would fail with "OIDC provider
# already exists." We probe and pass the existing ARN via
# ExistingOidcProviderArn so the CFN Condition skips creation.
#
# OWNERSHIP CHECK (fixes #709 chicken-and-egg):
#   If the existing OIDC provider is OWNED BY THIS STACK we must NOT pass
#   it as ExistingOidcProviderArn, because doing so flips the CFN condition
#   CreateOidcProvider to false — CFN interprets "no longer in template" as
#   DELETE, removing the provider it was managing.  We detect this by asking
#   CloudFormation whether GitHubOidcProvider in our stack resolves to the
#   same ARN we found.  Three scenarios:
#
#     (a) Fresh deploy (no stack yet):
#         probe returns nothing → EXISTING_OIDC_ARN="" → CFN creates ✓
#
#     (b) Re-deploy where stack OWNS the existing OIDC:
#         probe returns ARN; ownership check matches → EXISTING_OIDC_ARN=""
#         → CFN keeps managing it ✓
#
#     (c) Deploy where OIDC pre-exists from a DIFFERENT stack/external source:
#         probe returns ARN; ownership check finds no match → EXISTING_OIDC_ARN
#         passed through → CFN skips creation, reuses external ✓
echo "==> Checking for existing GitHub OIDC provider..."
OIDC_PROVIDERS="$(aws iam list-open-id-connect-providers --output json 2>&1)" || {
  echo "ERROR: list-open-id-connect-providers failed: ${OIDC_PROVIDERS}" >&2
  exit 1
}
EXISTING_OIDC_ARN="$(echo "${OIDC_PROVIDERS}" | python3 -c '
import sys, json
data = json.load(sys.stdin)
for p in data.get("OpenIDConnectProviderList", []):
    if "token.actions.githubusercontent.com" in p.get("Arn", ""):
        print(p["Arn"])
        break
')"

if [[ -n "${EXISTING_OIDC_ARN}" ]]; then
  echo "    Found: ${EXISTING_OIDC_ARN}"

  # Check whether this OIDC provider is managed by OUR stack (scenario b).
  # describe-stack-resources returns the PhysicalResourceId for the logical
  # resource GitHubOidcProvider if (and only if) the stack exists and the
  # resource is in it. Errors (stack not found, resource not found) are
  # suppressed — they all resolve to "not owned by us."
  STACK_OIDC="$(aws cloudformation describe-stack-resources \
    --stack-name "${STACK_NAME}" \
    --logical-resource-id GitHubOidcProvider \
    --region "${AWS_REGION}" \
    --query 'StackResources[0].PhysicalResourceId' \
    --output text 2>/dev/null || echo "")"

  if [[ -n "${STACK_OIDC}" && "${STACK_OIDC}" == "${EXISTING_OIDC_ARN}" ]]; then
    # Scenario (b): the existing OIDC is owned by this stack.
    # Passing the ARN would cause CFN to delete the resource on re-deploy.
    # Clear it so CFN's CreateOidcProvider condition stays true (stack keeps
    # managing the provider).
    EXISTING_OIDC_ARN=""
    echo "    Owned by stack '${STACK_NAME}' — keeping CFN ownership (ExistingOidcProviderArn cleared)."
    echo "    (CFN will continue managing the existing provider, not delete-and-recreate it.)"
  else
    # Scenario (c): external/different-stack OIDC. Pass ARN so CFN skips
    # creation and reuses it.
    echo "    Not owned by stack '${STACK_NAME}' — passing ARN to CFN (CFN will reuse, not create)."
  fi
else
  # Scenario (a): no existing provider.
  echo "    None found — CFN will create one."
fi
echo

# ----- deploy -----
echo "==> Deploying CloudFormation stack '${STACK_NAME}'..."
echo "    Template: ${TEMPLATE}"
echo

# `--no-fail-on-empty-changeset` makes re-runs idempotent (exit 0 if
# nothing changed). `--capabilities CAPABILITY_NAMED_IAM` is required
# because we name the IAM role explicitly (workflow's role-to-assume
# is a fixed string, not a ref). Tags are mirrored from the CFN's own
# tagging so `aws resourcegroupstaggingapi` queries find the stack +
# its resources together.
aws cloudformation deploy \
  --stack-name "${STACK_NAME}" \
  --template-file "${TEMPLATE}" \
  --region "${AWS_REGION}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --tags Project=iam-jit-ci-nightly ManagedBy=cli \
  --parameter-overrides \
    "GitHubOrg=${GH_ORG}" \
    "GitHubRepo=${GH_REPO}" \
    "RoleName=${ROLE_NAME}" \
    "BudgetEmail=${BUDGET_EMAIL}" \
    "ExistingOidcProviderArn=${EXISTING_OIDC_ARN}" \
  || {
    echo
    echo "ERROR: deploy failed. Last 20 stack events:" >&2
    aws cloudformation describe-stack-events \
      --stack-name "${STACK_NAME}" \
      --region "${AWS_REGION}" \
      --max-items 20 \
      --query 'StackEvents[*].[Timestamp,LogicalResourceId,ResourceStatus,ResourceStatusReason]' \
      --output table >&2 || true
    exit 1
  }

# ----- post-deploy verification -----
echo
echo "==> Verifying role exists..."
ROLE_ARN="$(aws iam get-role \
  --role-name "${ROLE_NAME}" \
  --query 'Role.Arn' \
  --output text 2>&1)" || {
  echo "ERROR: get-role failed: ${ROLE_ARN}" >&2
  exit 1
}
echo "    ${ROLE_ARN}"

# Read the workflow's current role-to-assume to flag mismatches early.
# A drift here = the deploy succeeded but the workflow won't use it.
WORKFLOW_YAML="${REPO_ROOT}/.github/workflows/dogfood-nightly.yml"
if [[ -f "${WORKFLOW_YAML}" ]]; then
  WORKFLOW_ROLE="$(grep -E '^\s*role-to-assume:' "${WORKFLOW_YAML}" | head -1 | awk '{print $2}' || true)"
  if [[ -n "${WORKFLOW_ROLE}" && "${WORKFLOW_ROLE}" != "${ROLE_ARN}" ]]; then
    echo
    echo "WARNING: workflow's role-to-assume does not match deployed role:" >&2
    echo "  workflow:  ${WORKFLOW_ROLE}" >&2
    echo "  deployed:  ${ROLE_ARN}" >&2
    echo "Edit ${WORKFLOW_YAML} and update role-to-assume to match." >&2
  fi
fi

echo
echo "==> Done. Next steps:"
echo "    1. gh secret list  # verify no leftover AWS_* secrets (OIDC obviates them)"
echo "    2. gh workflow run dogfood-nightly.yml  # trigger first manual run"
echo "    3. gh run watch  # tail the first run"
echo
echo "Cleanup (when you want to remove everything):"
echo "    aws cloudformation delete-stack --stack-name ${STACK_NAME} --region ${AWS_REGION}"
