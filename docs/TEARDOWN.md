# Tear-down — removing iam-jit cleanly

iam-jit lives in two places: a **hub-account** SAM stack and one or
more **destination-account** stacks. Removing it cleanly means
draining state in the right order so AWS doesn't end up with
orphaned IAM roles, S3 objects, or DynamoDB rows your audit team
later has to chase down.

This doc covers the supported teardown paths. None of them need an
in-app feature — every step is plain AWS CLI / CFN.

## Pre-flight

Before tearing down, make sure you have:

1. A copy of any audit log you want to keep.
2. A list of any ACTIVE IAM grants iam-jit has provisioned that you
   intend to keep alive past the teardown — those must be migrated to
   another permission system or accepted as orphans.
3. Confirmation that no live agents / CI runners are mid-flight on
   active grants. The cleanest way to check:

   ```bash
   curl -H "Authorization: Bearer $ADMIN_TOKEN" \
        $IAM_JIT_URL/api/v1/admin/provisioned | jq
   ```

   Anything in the `provisioned` array is a live IAM role iam-jit
   created in a destination account.

## Step 1 — Drain active grants

For every entry in `/api/v1/admin/provisioned`, either revoke it
through iam-jit (so the destination IAM role is deleted) or
explicitly migrate it. Bulk-revoke via the API:

```bash
for rid in $(curl -H "Authorization: Bearer $ADMIN_TOKEN" \
                  $IAM_JIT_URL/api/v1/admin/provisioned \
             | jq -r '.provisioned[].request_id'); do
  curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
       -H 'Content-Type: application/json' \
       -d '{"reason":"iam-jit teardown"}' \
       $IAM_JIT_URL/api/v1/requests/$rid/revoke
done
```

After draining, `/api/v1/admin/rediscover` should report zero
`stale` and zero `orphans` — IAM is clean.

## Step 2 — Tear down each destination-account stack

For each destination AWS account where you ran the
`destination-account-roles.yaml` stack:

```bash
aws cloudformation delete-stack \
  --stack-name iam-jit-roles \
  --profile <destination-account-profile>
aws cloudformation wait stack-delete-complete \
  --stack-name iam-jit-roles \
  --profile <destination-account-profile>
```

This removes:

- `ProvisionerRole` (the role iam-jit assumes to provision grants)
- `DiscoveryRole` (if you deployed it)
- their inline policies

It does NOT remove:

- IAM roles `iam-jit-grant-*` that iam-jit previously created — those
  are owned by the ProvisionerRole and live independently. Step 1
  above is what removes them. If you skipped Step 1, run this from a
  shell with the destination account's credentials:

  ```bash
  aws iam list-roles --path-prefix /iam-jit/ \
      --query 'Roles[].RoleName' --output text |
  xargs -n1 -I {} bash -c '
    aws iam list-role-policies --role-name {} --query PolicyNames --output text |
      xargs -n1 -I P aws iam delete-role-policy --role-name {} --policy-name P
    aws iam delete-role --role-name {}
  '
  ```

  This is the manual recovery path. Prefer Step 1.

## Step 3 — Tear down the hub stack

```bash
# Empty the state bucket first — AWS refuses to delete a non-empty
# bucket. iam-jit's bucket is versioned, so empty BOTH versions and
# delete-markers.
BUCKET=<your iam-jit state bucket>
aws s3api list-object-versions --bucket "$BUCKET" \
  --output json --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' \
  | aws s3api delete-objects --bucket "$BUCKET" --delete file:///dev/stdin
aws s3api list-object-versions --bucket "$BUCKET" \
  --output json --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' \
  | aws s3api delete-objects --bucket "$BUCKET" --delete file:///dev/stdin

# Then delete the SAM stack.
aws cloudformation delete-stack --stack-name iam-jit
aws cloudformation wait stack-delete-complete --stack-name iam-jit
```

**The DynamoDB tables and the S3 state bucket are RETAINED by
default.** Every persistent store in the template carries
`DeletionPolicy: Retain` (see `security-notes.md` § E5 — evidence
destruction defense). `aws cloudformation delete-stack` removes the
Lambda, ALB, IAM role, log group, and security group — but it
**does NOT delete:**

- `iam-jit-api-tokens` (DDB)
- `iam-jit-users` (DDB)
- `iam-jit-settings` (DDB)
- `iam-jit-cidrs` (DDB)
- `iam-jit-requests-iam-jit` (DDB)
- `iam-jit-state-<account>-<suffix>` (S3)

This is intentional. The retained data is your audit history; the
template won't let a stack-delete silently destroy it. To handle the
retained resources, pick one of:

- **Keep them** for audit retention. Tag them
  `iam-jit-archived=true` and document your retention window.
- **Adopt them on next deploy** via CFN resource import (see
  `docs/REDEPLOY.md` Path A) — preserves history.
- **Delete them explicitly** if you're sure the data is no longer
  needed (sandbox / dev only):

```bash
# DDB tables (manual delete required — they're retained on stack-delete):
aws dynamodb delete-table --table-name iam-jit-api-tokens
aws dynamodb delete-table --table-name iam-jit-users
aws dynamodb delete-table --table-name iam-jit-settings
aws dynamodb delete-table --table-name iam-jit-cidrs
aws dynamodb delete-table --table-name iam-jit-requests-iam-jit

# S3 state bucket (must empty before delete; see commands above).
```

If you plan to re-deploy iam-jit later in the same account, read
`docs/REDEPLOY.md` BEFORE deleting these — adopting the retained
resources back into a fresh stack preserves the full audit history.

## Step 4 — Confirm clean removal

```bash
# Hub: stack deleted?
aws cloudformation describe-stacks --stack-name iam-jit 2>&1 \
  | grep -q "does not exist" && echo "iam-jit hub stack: gone"

# State bucket: gone?
aws s3 ls "s3://$BUCKET" 2>&1 | grep -q "NoSuchBucket" \
  && echo "state bucket: gone"

# Each destination: any iam-jit-grant-* roles left?
aws iam list-roles --path-prefix /iam-jit/ \
  --query 'Roles[].RoleName' --output text  # should be empty

# ProvisionerRole gone?
aws iam get-role --role-name iam-jit-provisioner 2>&1 \
  | grep -q "NoSuchEntity" && echo "destination provisioner: gone"
```

## Local-dev teardown

`iam-jit serve` writes state to `./requests/`, `./.iam-jit-local/`,
and `/tmp/iam-jit-bootstrap-link.txt`. To wipe a local install:

```bash
rm -rf requests .iam-jit-local /tmp/iam-jit-bootstrap-link.txt
# Plus whatever --users-file path you passed.
```

No remote state to clean up — local mode never wrote to AWS.

## Recovery from partial teardown

If `delete-stack` got stuck (lambda still running, eventual-
consistency issue, retained-resource flag), the safe recovery is:

1. Wait 5 minutes — DynamoDB / S3 deletions sometimes lag.
2. `aws cloudformation describe-stack-events --stack-name iam-jit` to
   find the failing resource.
3. Most commonly: a non-empty S3 bucket. Re-run the version-and-marker
   cleanup from Step 3 and retry the delete.

If you've torn down the destination ProvisionerRole BEFORE draining
grants, the orphaned `iam-jit-grant-*` roles are still in the
destination account but iam-jit can no longer manage them. The shell
loop in Step 2's "manual recovery path" cleans them up. There is no
data loss; you've just lost the audit trail of who was using them.

## Audit retention

If you need to keep iam-jit's audit log past teardown:

1. Before deleting the state bucket, copy `audit-log/*` to a
   long-term bucket (Glacier, Object Lock).
2. Before deleting the request store, run a final
   `/api/v1/admin/provisioned?include_revoked=true` and archive the
   JSON.
3. Audit log integrity verifies post-teardown — the hash chain is
   self-contained.
