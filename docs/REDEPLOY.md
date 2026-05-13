# Re-deploying iam-jit in an account with retained resources

iam-jit's persistent data stores (DynamoDB tables, S3 state bucket)
carry `DeletionPolicy: Retain`. A `cloudformation delete-stack` removes
the Lambda / ALB / IAM role but **leaves the data tables and state
bucket in place** — by design, for audit + compliance preservation
(see `security-notes.md` § E5).

This means a fresh `sam deploy` into the same account+region will
collide: CloudFormation tries to create `iam-jit-settings`,
`iam-jit-cidrs`, etc., AWS reports `AlreadyExistsException`, and the
new stack lands in `REVIEW_IN_PROGRESS` / `CREATE_FAILED`. This doc
covers the two ways out.

> **Heads-up:** the error you'll see is opaque. CloudFormation
> reports `AWS::EarlyValidation::ResourceExistenceCheck failed` with
> no mention of which resource. Compare against
> `aws dynamodb list-tables` and `aws s3 ls | grep iam-jit-state` to
> identify the offenders.

## TL;DR — which path do you want?

| You want | Pick |
|---|---|
| Keep all prior request history, audit events, settings | Path A — CFN resource import |
| Start fresh (lose prior history); fastest path back to running | Path B — fresh tables via parameter override |
| Just nuke everything and start over (sandbox / dev) | Path C — delete retained resources first |

## Path A — CFN resource import (preserves data)

Use this when the retained tables hold audit history you must keep
(production, regulated environments).

**Easiest path: use the bundled helper.**

```bash
scripts/import-retained.sh \
  --profile <aws-profile> \
  --region <region> \
  --stack-name iam-jit \
  --state-bucket <retained-state-bucket-name>
```

The helper enforces all the preconditions (no existing stack, every
retained resource actually exists, sam build has produced a template),
generates the resources-to-import payload, creates the change-set,
pauses for inspection, then executes after you confirm. Pass
`--yes` to skip the interactive confirmation in CI flows.

When the helper finishes, the stack owns the 6 retained resources
but does NOT yet have the Lambda / ALB / IAM role. Run a normal
`sam deploy` next with the SAME table-name parameters (the helper
prints the exact command at the end).

**Manual path (if you can't run the helper):**

CloudFormation's resource-import flow lets you adopt existing AWS
resources into a new stack. Each retained resource is added back to
the template, then a single import change-set picks them up.

```bash
# 1. Identify the retained resources you need to adopt:
aws dynamodb list-tables --profile <prof> --region <region> \
  --query "TableNames[?contains(@, 'iam-jit')]"
aws s3 ls --profile <prof> | grep iam-jit-state

# 2. Build the resources-to-import file. One entry per retained
# resource, mapping (logical-id-in-template → physical resource).
# The logical IDs MUST match the template:
#   - SettingsTable, CidrsTable, ApiTokensTable, UsersTable
#   - RequestsTable, StateBucket
cat > /tmp/import.json <<'EOF'
[
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "SettingsTable",
   "ResourceIdentifier": {"TableName": "iam-jit-settings"}},
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "CidrsTable",
   "ResourceIdentifier": {"TableName": "iam-jit-cidrs"}},
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "ApiTokensTable",
   "ResourceIdentifier": {"TableName": "iam-jit-api-tokens"}},
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "UsersTable",
   "ResourceIdentifier": {"TableName": "iam-jit-users"}},
  {"ResourceType": "AWS::DynamoDB::Table",
   "LogicalResourceId": "RequestsTable",
   "ResourceIdentifier": {"TableName": "iam-jit-requests-iam-jit"}},
  {"ResourceType": "AWS::S3::Bucket",
   "LogicalResourceId": "StateBucket",
   "ResourceIdentifier": {"BucketName": "iam-jit-state-<your-suffix>"}}
]
EOF

# 3. Create an IMPORT change-set on the (not-yet-existing) stack:
aws cloudformation create-change-set \
  --stack-name iam-jit \
  --change-set-name import-retained \
  --change-set-type IMPORT \
  --template-body file://.aws-sam/build/template.yaml \
  --resources-to-import file:///tmp/import.json \
  --parameters <your-normal-parameter-overrides> \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --profile <prof> --region <region>

# 4. Inspect the change-set, then execute it:
aws cloudformation describe-change-set \
  --stack-name iam-jit --change-set-name import-retained \
  --profile <prof> --region <region>

aws cloudformation execute-change-set \
  --stack-name iam-jit --change-set-name import-retained \
  --profile <prof> --region <region>

# 5. Wait for IMPORT_COMPLETE, then run a normal sam deploy to add
# the rest of the stack (Lambda, ALB, IAM role, log group):
sam deploy --no-confirm-changeset --parameter-overrides <same as before>
```

After import, the stack owns the retained resources. Subsequent
deploys + deletes behave normally (and the `Retain` policy still
applies on the next stack-delete).

**Caveats:**

- The retained resources MUST match the template properties exactly,
  or the import will fail. If you've manually altered a table (e.g.,
  enabled a GSI by hand), update the template first or import will
  reject with a property-mismatch error.
- `AWS::EC2::SecurityGroup` and other ephemeral stack resources
  cannot be imported. Only the persistent stores (DDB, S3) need this.
- Resource import is single-shot per change-set. If you need to
  import 6 retained resources, list all 6 in the single
  `resources-to-import` file.

## Path B — fresh tables via parameter override (loses data)

Use this when the prior history doesn't matter (dev, sandbox,
re-deploy after a clean cut).

Override every table-name and bucket-name parameter to a new value
the new stack will create fresh:

```bash
sam deploy \
  --parameter-overrides \
    ApiTokensTableName=iam-jit-api-tokens-v2 \
    UsersTableName=iam-jit-users-v2 \
    SettingsTableName=iam-jit-settings-v2 \
    CidrsTableName=iam-jit-cidrs-v2 \
    StateBucketName=iam-jit-state-<your-account>-v2 \
    StackNameSuffix=v2 \
    <other params...>
```

The previously-retained tables are now orphan (still in the account,
still costing nothing on PAY_PER_REQUEST DDB billing). Decide:

- **Keep them** for offline audit / forensics. Tag them
  `iam-jit-archived=true` and document the retention window.
- **Delete them** if their data is genuinely useless:
  ```bash
  aws dynamodb delete-table --table-name iam-jit-settings \
    --profile <prof> --region <region>
  # repeat for each retained-but-not-needed table
  ```

> **Note on `RequestsTable`:** the default name uses
> `iam-jit-requests-${AWS::StackName}` so two stacks in the same
> account would already conflict without an override. The other
> tables had hardcoded names that survived stack-delete and forced
> this docs section into existence.

## Path C — delete retained resources first (sandbox only)

Use ONLY in dev / sandbox accounts where the retained data is
test data. **Never do this in a compliance-relevant environment** —
you're permanently deleting audit history.

```bash
# Delete all retained iam-jit DDB tables in the region:
for t in $(aws dynamodb list-tables --profile <prof> --region <region> \
  --query "TableNames[?contains(@, 'iam-jit')]" --output text); do
  aws dynamodb delete-table --table-name "$t" \
    --profile <prof> --region <region>
done

# Delete the retained state bucket(s). Must empty first:
for b in $(aws s3api list-buckets --profile <prof> \
  --query "Buckets[?contains(Name, 'iam-jit-state')].Name" --output text); do
  aws s3 rm "s3://$b" --recursive --profile <prof>
  aws s3api delete-bucket --bucket "$b" --profile <prof> --region <region>
done

# Now sam deploy starts truly clean.
sam deploy --parameter-overrides <your params>
```

## Recovering from a stuck `REVIEW_IN_PROGRESS` stack

If a deploy attempt collided and left the stack at `REVIEW_IN_PROGRESS`,
that state only allows `delete-stack`. The stack itself never created
any resources (the collision blocked it pre-create), so deleting it
is safe — your retained resources are unaffected.

```bash
# Either of these works:
aws cloudformation delete-stack --stack-name iam-jit \
  --profile <prof> --region <region>
# or
sam delete --stack-name iam-jit --profile <prof> --region <region> --no-prompts

# Wait for the stack to fully disappear:
aws cloudformation wait stack-delete-complete --stack-name iam-jit \
  --profile <prof> --region <region>
```

Then pick Path A, B, or C above for the actual re-deploy.

## Why retain by default?

iam-jit is an access-grant audit tool — every request, approval, and
provisioned role is a record auditors and incident responders need.
A stack-delete that took the audit data with it would mean a
compromised admin could (a) escalate themselves, (b) do damage, then
(c) `sam delete` to bury the evidence in one motion. The retain
posture makes that attack a separate, more visible step. See
`security-notes.md` § E5.

The trade-off is the friction this doc covers: re-deploys take more
care. The retention posture and the runtime `MinLogRetentionDays`
floor together implement the compliance side of the threat model.
