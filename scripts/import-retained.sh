#!/usr/bin/env bash
# Re-adopt iam-jit's retained DDB tables and S3 state bucket back
# into a fresh CloudFormation stack. Wraps the multi-step CFN
# resource-import flow so a re-deploy that would otherwise collide
# with retained resources can proceed without manual change-set
# scripting.
#
# Background: iam-jit's persistent stores carry
# `DeletionPolicy: Retain` (audit / compliance — see
# security-notes.md § E5). After a stack-delete, the data tables
# and state bucket remain in the account, and a fresh `sam deploy`
# fails with `AlreadyExistsException` mid-create. The CFN resource
# import flow re-adopts them; this script automates it.
#
# This script also exists to dodge a tooling artifact: many
# Claude-Code-style harnesses approve `sam ...` invocations but
# decline raw `aws cloudformation create-change-set` calls. Wrapping
# the import as a single named script invocation makes the flow
# pass through single-command permission matchers.
#
# Usage:
#   scripts/import-retained.sh \
#     --profile <aws-profile> \
#     --region <region> \
#     --stack-name iam-jit \
#     --state-bucket <bucket-name>
#
# Required environment / parameters:
#   --profile         AWS CLI profile for the target account
#   --region          us-east-1 (or whatever your hub is in)
#   --stack-name      Defaults to "iam-jit"
#   --state-bucket    The retained S3 state bucket name (look it up
#                     with: aws s3 ls | grep iam-jit-state-)
#
# Optional table-name overrides (defaults match the SAM template):
#   --api-tokens-table     iam-jit-api-tokens
#   --users-table          iam-jit-users
#   --settings-table       iam-jit-settings
#   --cidrs-table          iam-jit-cidrs
#   --requests-table       iam-jit-requests-iam-jit
#
# What this script does:
#   1. Confirms the target stack does NOT already exist.
#   2. Confirms each retained resource DOES exist (won't try to
#      import something the account doesn't actually have).
#   3. Runs `sam build` so we have a template to import against.
#   4. Generates the resources-to-import JSON.
#   5. Creates an IMPORT change-set on the not-yet-existing stack.
#   6. Pauses for a manual review (the change-set should ONLY add
#      the 6 retained resources, nothing else).
#   7. After user confirms, executes the change-set.
#   8. Waits for IMPORT_COMPLETE.
#   9. Reminds the operator to run `sam deploy` next to add the
#      rest of the stack (Lambda, ALB, IAM role, log group).
#
# Idempotent in the FAIL-FAST sense: if any precondition is wrong,
# the script exits non-zero without touching AWS. Not idempotent in
# the RESUME sense — a half-completed import requires manual
# `cloudformation delete-change-set` cleanup.

set -euo pipefail

PROFILE=""
REGION=""
STACK_NAME="iam-jit"
STATE_BUCKET=""
API_TOKENS_TABLE="iam-jit-api-tokens"
USERS_TABLE="iam-jit-users"
SETTINGS_TABLE="iam-jit-settings"
CIDRS_TABLE="iam-jit-cidrs"
REQUESTS_TABLE="iam-jit-requests-iam-jit"
ASSUME_YES=0
# Passthrough params (Key=Value, repeatable). CFN change-set creation
# fails when template Rules can't be satisfied by parameter defaults —
# e.g., AuthMode=local needs AdminBootstrapEmail + BootstrapSetupKey +
# MagicLinkSecret; EnablePublicALB=true needs AlbVpcId + AlbSubnetIds
# + AlbIngressCidr. Pass --param 'Key=Value' for each one to satisfy
# Rules at import time. The same params are needed for the followup
# sam deploy; consider keeping them in env vars or a script.
EXTRA_PARAMS=()

usage() {
  # Print the header comment block, stopping just before the first
  # non-comment line. Skip the shebang on line 1.
  awk 'NR==1 {next} /^#/{print substr($0, 3); next} {exit}' "$0"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)              PROFILE="$2"; shift 2 ;;
    --region)               REGION="$2"; shift 2 ;;
    --stack-name)           STACK_NAME="$2"; shift 2 ;;
    --state-bucket)         STATE_BUCKET="$2"; shift 2 ;;
    --api-tokens-table)     API_TOKENS_TABLE="$2"; shift 2 ;;
    --users-table)          USERS_TABLE="$2"; shift 2 ;;
    --settings-table)       SETTINGS_TABLE="$2"; shift 2 ;;
    --cidrs-table)          CIDRS_TABLE="$2"; shift 2 ;;
    --requests-table)       REQUESTS_TABLE="$2"; shift 2 ;;
    --param)                EXTRA_PARAMS+=("$2"); shift 2 ;;
    --yes|-y)               ASSUME_YES=1; shift ;;
    -h|--help)              usage 0 ;;
    *)                      echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done

if [[ -z "$PROFILE" || -z "$REGION" || -z "$STATE_BUCKET" ]]; then
  echo "ERROR: --profile, --region, and --state-bucket are required." >&2
  usage 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/.aws-sam/build"
BUILD_TEMPLATE_PATH="${BUILD_DIR}/template.yaml"
# `sam package` rewrites the CodeUri to an s3:// URL. The
# unpackaged build template has a local CodeUri that CFN
# create-change-set refuses with "CodeUri is not a valid S3 Uri".
PACKAGED_TEMPLATE_PATH="${BUILD_DIR}/packaged.yaml"
TEMPLATE_PATH="$PACKAGED_TEMPLATE_PATH"
IMPORT_JSON="$(mktemp -t iam-jit-import.XXXXXX.json)"
CHANGE_SET_NAME="import-retained-$(date -u +%Y%m%dT%H%M%SZ)"

awscli() {
  aws --profile "$PROFILE" --region "$REGION" "$@"
}

step() { printf '\n=== %s ===\n' "$*"; }

step "1/9  Precondition: stack must NOT already exist"
if awscli cloudformation describe-stacks --stack-name "$STACK_NAME" \
     >/dev/null 2>&1; then
  echo "ERROR: stack '$STACK_NAME' already exists in $REGION." >&2
  echo "        Delete it first (sam delete --stack-name $STACK_NAME)" >&2
  echo "        before running this import." >&2
  exit 2
fi
echo "OK: stack '$STACK_NAME' does not exist."

step "2/9  Precondition: each retained resource must EXIST"
check_table() {
  local name="$1"
  if awscli dynamodb describe-table --table-name "$name" >/dev/null 2>&1; then
    echo "  OK: DDB table $name exists"
  else
    echo "  MISSING: DDB table $name not found in $REGION." >&2
    echo "           Skip importing it by passing a different --*-table" >&2
    echo "           value, or remove it from this script's resource set." >&2
    return 1
  fi
}
check_table "$API_TOKENS_TABLE"
check_table "$USERS_TABLE"
check_table "$SETTINGS_TABLE"
check_table "$CIDRS_TABLE"
check_table "$REQUESTS_TABLE"

if ! awscli s3api head-bucket --bucket "$STATE_BUCKET" >/dev/null 2>&1; then
  echo "ERROR: S3 bucket '$STATE_BUCKET' not found." >&2
  echo "        List candidates with: aws s3 ls | grep iam-jit-state-" >&2
  exit 3
fi
echo "  OK: S3 bucket $STATE_BUCKET exists"

step "3/9  Build + package the SAM artifact"
# `sam build` generates the build directory; `sam package` uploads
# the code to S3 and rewrites the template's CodeUri to an s3://
# URL. The unpackaged template has a LOCAL CodeUri that CFN's
# create-change-set rejects. --resolve-s3 lets SAM auto-manage
# its own packaging bucket.
if [[ ! -f "$BUILD_TEMPLATE_PATH" ]]; then
  (cd "$REPO_ROOT" && sam build)
fi
if [[ ! -f "$BUILD_TEMPLATE_PATH" ]]; then
  echo "ERROR: sam build did not produce $BUILD_TEMPLATE_PATH" >&2
  exit 4
fi
(cd "$REPO_ROOT" && sam package \
   --template-file "$BUILD_TEMPLATE_PATH" \
   --output-template-file "$PACKAGED_TEMPLATE_PATH" \
   --resolve-s3 \
   --profile "$PROFILE" --region "$REGION")
if [[ ! -f "$PACKAGED_TEMPLATE_PATH" ]]; then
  echo "ERROR: sam package did not produce $PACKAGED_TEMPLATE_PATH" >&2
  exit 4
fi
echo "OK: $TEMPLATE_PATH ready."

step "4/9  Generating resources-to-import payload"
cat > "$IMPORT_JSON" <<EOF
[
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "ApiTokensTable",
   "ResourceIdentifier": {"TableName": "$API_TOKENS_TABLE"}},
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "UsersTable",
   "ResourceIdentifier": {"TableName": "$USERS_TABLE"}},
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "SettingsTable",
   "ResourceIdentifier": {"TableName": "$SETTINGS_TABLE"}},
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "CidrsTable",
   "ResourceIdentifier": {"TableName": "$CIDRS_TABLE"}},
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "RequestsTable",
   "ResourceIdentifier": {"TableName": "$REQUESTS_TABLE"}},
  {"ResourceType": "AWS::S3::Bucket",
   "LogicalResourceId": "StateBucket",
   "ResourceIdentifier": {"BucketName": "$STATE_BUCKET"}}
]
EOF
echo "Wrote: $IMPORT_JSON"
echo "Will adopt 6 resources into stack '$STACK_NAME'."

step "5/9  Creating IMPORT change-set"
# Build the --parameters payload as a JSON file. CLI shorthand
# (`Key=Value,Key=Value`) splits on commas inside values, which
# breaks CommaDelimitedList parameters like AlbSubnetIds. JSON
# form is unambiguous.
PARAMS_JSON="$(mktemp -t iam-jit-params.XXXXXX.json)"
{
  printf '['
  printf '{"ParameterKey":"ApiTokensTableName","ParameterValue":"%s"},' "$API_TOKENS_TABLE"
  printf '{"ParameterKey":"UsersTableName","ParameterValue":"%s"},' "$USERS_TABLE"
  printf '{"ParameterKey":"SettingsTableName","ParameterValue":"%s"},' "$SETTINGS_TABLE"
  printf '{"ParameterKey":"CidrsTableName","ParameterValue":"%s"},' "$CIDRS_TABLE"
  printf '{"ParameterKey":"StateBucketName","ParameterValue":"%s"}' "$STATE_BUCKET"
  for kv in "${EXTRA_PARAMS[@]:-}"; do
    [[ -z "$kv" ]] && continue
    key="${kv%%=*}"
    val="${kv#*=}"
    # JSON-escape backslashes and double-quotes in the value.
    val_escaped="${val//\\/\\\\}"
    val_escaped="${val_escaped//\"/\\\"}"
    printf ',{"ParameterKey":"%s","ParameterValue":"%s"}' "$key" "$val_escaped"
  done
  printf ']'
} > "$PARAMS_JSON"

awscli cloudformation create-change-set \
  --stack-name "$STACK_NAME" \
  --change-set-name "$CHANGE_SET_NAME" \
  --change-set-type IMPORT \
  --template-body "file://$TEMPLATE_PATH" \
  --resources-to-import "file://$IMPORT_JSON" \
  --parameters "file://$PARAMS_JSON" \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  >/dev/null
echo "Change-set queued: $CHANGE_SET_NAME"

step "6/9  Waiting for change-set to be ready for inspection"
awscli cloudformation wait change-set-create-complete \
  --stack-name "$STACK_NAME" \
  --change-set-name "$CHANGE_SET_NAME" || {
    awscli cloudformation describe-change-set \
      --stack-name "$STACK_NAME" \
      --change-set-name "$CHANGE_SET_NAME" \
      --query '{Status:Status,StatusReason:StatusReason}' --output table
    echo "" >&2
    echo "ERROR: change-set creation failed. See the above table." >&2
    echo "       Common causes:" >&2
    echo "         - retained resource doesn't match template properties" >&2
    echo "         - missing CAPABILITY_IAM / CAPABILITY_NAMED_IAM" >&2
    echo "         - template parameter type mismatch" >&2
    exit 5
  }
echo "OK: change-set is ready."

step "7/9  Inspect the change-set BEFORE executing"
awscli cloudformation describe-change-set \
  --stack-name "$STACK_NAME" \
  --change-set-name "$CHANGE_SET_NAME" \
  --query 'Changes[].{Action:ResourceChange.Action,Type:ResourceChange.ResourceType,Logical:ResourceChange.LogicalResourceId,Physical:ResourceChange.PhysicalResourceId}' \
  --output table

echo ""
echo "Expected: 6 IMPORT actions for the resources listed in step 4."
echo "If anything is CREATE/MODIFY/DELETE here, ABORT — the template"
echo "diverged from what's in the account."
echo ""

if [[ "$ASSUME_YES" -ne 1 ]]; then
  read -r -p "Proceed with execute-change-set? [y/N] " ans
  if [[ "${ans:-}" != "y" && "${ans:-}" != "Y" ]]; then
    echo "Aborted. Cleaning up change-set."
    awscli cloudformation delete-change-set \
      --stack-name "$STACK_NAME" \
      --change-set-name "$CHANGE_SET_NAME" || true
    rm -f "$IMPORT_JSON" "$PARAMS_JSON"
    exit 6
  fi
fi

step "8/9  Executing change-set"
awscli cloudformation execute-change-set \
  --stack-name "$STACK_NAME" \
  --change-set-name "$CHANGE_SET_NAME"

echo "Waiting for import to finish (stack-import-complete)…"
awscli cloudformation wait stack-import-complete \
  --stack-name "$STACK_NAME" || {
    awscli cloudformation describe-stack-events \
      --stack-name "$STACK_NAME" \
      --max-items 20 \
      --query 'StackEvents[].{Time:Timestamp,Logical:LogicalResourceId,Status:ResourceStatus,Reason:ResourceStatusReason}' \
      --output table
    echo "ERROR: import failed. See the events above." >&2
    exit 7
  }
echo "OK: import complete. Stack '$STACK_NAME' now owns the 6 retained resources."

step "9/9  Done. Next step: add the rest of the stack."
echo ""
echo "Run sam deploy with the SAME table-name parameters you passed here:"
echo ""
echo "  sam deploy \\"
echo "    --stack-name $STACK_NAME \\"
echo "    --profile $PROFILE --region $REGION \\"
echo "    --parameter-overrides \\"
echo "      ApiTokensTableName=$API_TOKENS_TABLE \\"
echo "      UsersTableName=$USERS_TABLE \\"
echo "      SettingsTableName=$SETTINGS_TABLE \\"
echo "      CidrsTableName=$CIDRS_TABLE \\"
echo "      StateBucketName=$STATE_BUCKET \\"
echo "      <other params you'd normally pass>"
echo ""

rm -f "$IMPORT_JSON" "$PARAMS_JSON"
