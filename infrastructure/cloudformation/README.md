# CloudFormation templates

Per-destination-account roles for iam-jit. Deploy in **each** AWS account where iam-jit will provision time-bound IAM grants. The hub account (where the iam-jit Lambda runs) gets a SAM stack instead — see `../sam/`.

## destination-account-roles.yaml

Creates the cross-account roles iam-jit's Lambda assumes:

- **ProvisionerRole** (always): scoped via tags so it can only modify resources tagged `managed-by: iam-jit`.
- **DiscoveryRole** (optional, parameter `EnableDiscovery`): read-only access used during the narrowing flow to suggest concrete ARNs. Set `EnableDiscovery: No` to skip it; provisioning still works.

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `HubAccountId` | yes | — | 12-digit account ID where iam-jit's Lambda runs. |
| `HubLambdaRoleName` | no | `iam-jit-lambda-execution` | IAM role name (not ARN) of the iam-jit Lambda. The trust policy allows only this principal. |
| `ProvisionerRoleName` | no | `iam-jit-provisioner` | Name for the provisioner role created in this account. |
| `DiscoveryRoleName` | no | `iam-jit-discovery` | Name for the discovery role (only created if `EnableDiscovery: Yes`). |
| `EnableDiscovery` | no | `Yes` | `Yes` to deploy the read-only discovery role, `No` to skip. |
| `ProvisioningMode` | no | `classic_iam` | `classic_iam`, `identity_center`, or `both`. |
| `AllowedPermissionSetArns` | when `identity_center` | empty | Comma-separated permission-set ARNs iam-jit may assign. |

### Apply

Pick one approach. All of them deploy the same template.

#### AWS CLI

```bash
aws cloudformation deploy \
  --template-file destination-account-roles.yaml \
  --stack-name iam-jit-roles \
  --parameter-overrides \
      HubAccountId=111111111111 \
      EnableDiscovery=Yes \
      ProvisioningMode=classic_iam \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1 \
  --profile <destination-account-profile>
```

#### Outputs to feed back to the hub

After the stack succeeds, capture the outputs and set them on the hub-account iam-jit Lambda:

```bash
aws cloudformation describe-stacks \
  --stack-name iam-jit-roles \
  --query "Stacks[0].Outputs" \
  --profile <destination-account-profile>
```

The hub config needs (per destination account):
- `ProvisionerRoleArn` → environment variable `IAM_JIT_PROVISIONER_ROLE_ARN_<account_id>`
- `ProvisionerExternalId` → `IAM_JIT_PROVISIONER_EXTERNAL_ID_<account_id>`
- `DiscoveryRoleArn` (if enabled) → `IAM_JIT_DISCOVERY_ROLE_ARN_<account_id>`
- `DiscoveryExternalId` (if enabled) → `IAM_JIT_DISCOVERY_EXTERNAL_ID_<account_id>`

The SAM template (`../sam/`) accepts these as deploy-time parameters, or you can pass them at runtime via Parameter Store / Secrets Manager / Lambda environment.

### Multi-account roll-out via StackSets

For organizations with many destination accounts, deploy via StackSets so a single change can propagate to all destinations:

```bash
aws cloudformation create-stack-set \
  --stack-set-name iam-jit-destination-roles \
  --template-body file://destination-account-roles.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false

aws cloudformation create-stack-instances \
  --stack-set-name iam-jit-destination-roles \
  --deployment-targets OrganizationalUnitIds=<your-OU-id> \
  --regions us-east-1 \
  --parameter-overrides \
      ParameterKey=HubAccountId,ParameterValue=111111111111
```

### What the ProvisionerRole can and cannot do

**Can**:
- Create new IAM roles under path `/iam-jit/*` if they're tagged `managed-by: iam-jit` at creation time. The full tag set iam-jit emits is allowed: `managed-by`, `iam-jit-deployment`, `iam-jit-version`, `request-id`, `requester`, `expires-at`, `provisioned-at`, `access-type`, `approver`. Additional tag keys are refused at the IAM layer.
- Modify or delete IAM roles already tagged `managed-by: iam-jit` — `iam:GetRole`, `iam:GetRolePolicy`, `iam:PutRolePolicy`, `iam:DeleteRolePolicy`, `iam:UpdateAssumeRolePolicy`, `iam:DeleteRole`, `iam:ListRolePolicies`, `iam:ListAttachedRolePolicies`, `iam:ListRoleTags`. (`ListRoleTags` is required by the cross-account rediscovery + force-delete admin endpoints — without it iam-jit can't confirm a role's `managed-by` tag before cleaning up.)
- List roles via `iam:ListRoles` (resource `*`) — used by the cross-account rediscovery sweep, always called with `--path-prefix /iam-jit/`.
- Read its own caller identity via `iam:GetUser` / `iam:GetRole` — used by the audit trail.
- (Identity Center mode) Create / delete account assignments **only for the permission-set ARNs in `AllowedPermissionSetArns`**.

**Cannot**:
- Touch any IAM resource not tagged `managed-by: iam-jit`.
- Create roles outside the `/iam-jit/*` path.
- Self-grant additional permissions, attach managed policies it didn't create, or assume any role other than the trust path defined here.
- Read or modify any service outside what's explicitly allowed.

The hub Lambda's IAM role is the upper bound on what it can grant — even if a policy slipped through every other gate, the system can't grant beyond its own ceiling.

### Tag-spoofing limitation (read this)

`iam-jit` identifies "its own" IAM roles by the combination of (a) path `/iam-jit/`, (b) role name pattern `iam-jit-grant-<id>`, and (c) the `managed-by=iam-jit` tag. **Any IAM principal in this destination account that already has `iam:CreateRole` and `iam:TagRole` could fabricate a role that satisfies all three conditions.** If they did, iam-jit's rediscovery would report it as an "orphan" (or "stale" if the synthetic `expires-at` is in the past), and an admin could be tricked into force-deleting it.

This is documented behavior, not a bug. The threat model assumes that anyone with destination-account IAM-write access doesn't *need* to bait iam-jit — they can already do anything iam-jit can do directly. The name + tag scoping prevents accidents (operator misconfiguration), not a privileged adversary.

If you want stronger isolation in a destination account where multiple iam-jit deployments coexist, set `IAM_JIT_DEPLOYMENT_NAME` differently in each hub deployment and pass `?deployment_filter=<name>` on `/api/v1/admin/rediscover`.

### Validation

Lint locally before applying:

```bash
pip install cfn-lint
cfn-lint infrastructure/cloudformation/destination-account-roles.yaml
```

There is no `cloudformation validate-template` step that would touch AWS in this flow — `cfn-lint` is purely local.
