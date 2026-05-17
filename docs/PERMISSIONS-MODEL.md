# Permissions model

The cross-account permissions architecture, threat model, and scoping examples for iam-jit.

## Trust topology

```
Hub account                                Destination account(s)
───────────                                ──────────────────────

IAMJitFunction (single Lambda, dispatched   iam-jit-provisioner
by event source — HTTP API or scheduled       trust: hub iam-jit-lambda-execution
expiry both run here)                                + sts:ExternalId == iam-jit-<acctid>
  ↓ runs as                                  perms: create/destroy roles tagged
iam-jit-lambda-execution                            managed-by: iam-jit, under path
  trust: lambda.amazonaws.com                       /iam-jit/*. (+ identity-center
  perms: assume-role into                           assignments if enabled.)
         provisioner+discovery
         in each destination               iam-jit-discovery (optional)
                                             trust: same as provisioner with a
                                                    different ExternalId
                                             perms: ReadOnlyAccess (AWS-managed)
                                                    + describe/list on the
                                                    configured service allow-list.
```

The single-Lambda design dispatches on event source: `event["source"] == "aws.events"` (scheduled expiry) vs HTTP request via the Function URL. Same code package, same IAM role; this keeps logs / alarms / cold-start tuning in one place.

## What the hub Lambda's role can and cannot do

**Can do** (the ceiling):

- `sts:AssumeRole` only into roles whose ARN matches the configured destination provisioner / discovery role names.
- Read/write the iam-jit state bucket.
- Read/write the API tokens DynamoDB table.
- Read the Anthropic API key Secret (only when configured for Anthropic).
- Invoke Bedrock models (only when configured for Bedrock).
- Write CloudWatch logs.

**Cannot do**:

- Touch any IAM resource directly in the hub account.
- Read or modify any other AWS resource in the hub account beyond the few above.
- Assume roles outside the configured destination list.

The Lambda execution role IS the upper bound on what the entire iam-jit system can do. Anything beyond this requires assuming a destination-account role, and that role itself is tightly scoped (see below).

## What ProvisionerRole can do (in each destination)

**Classic IAM mode**:

- `iam:CreateRole` and `iam:TagRole` for roles whose path is `/iam-jit/*` AND that have `aws:RequestTag/managed-by = iam-jit` at creation time.
- `iam:PutRolePolicy`, `iam:DeleteRolePolicy`, `iam:DeleteRole`, `iam:UpdateAssumeRolePolicy`, plus various `Get*`/`List*` for roles already tagged `managed-by: iam-jit`.
- `iam:ListRoles`, `iam:GetUser`, `iam:GetRole` for status queries (read-only).

**Identity Center mode**:

- `sso:CreateAccountAssignment`, `sso:DeleteAccountAssignment` for permission set ARNs in the explicit `AllowedPermissionSetArns` list.
- Related `Describe*` / `List*` for status.

**Cannot**:

- Touch any IAM resource not tagged `managed-by: iam-jit`.
- Create roles outside the `/iam-jit/*` path.
- Assign permission sets not in the deployer-provided allow-list.
- Self-grant additional permissions, attach customer-managed policies, or `iam:PassRole` to anything.

## What DiscoveryRole can do (when enabled)

- Read-only: AWS managed `ReadOnlyAccess` policy across the service allow-list specified at deploy time (default: `secretsmanager,kms,s3,dynamodb,ssm,iam,ec2,lambda,rds,eks,logs`).
- Used during the narrowing flow: when a requester says "I need access to the staging payments secret", the iam-jit service can describe Secrets Manager in that account to suggest concrete ARN patterns.
- **No write access of any kind.**

When discovery is disabled (`EnableDiscovery: No`), the role isn't created. iam-jit's narrowing flow falls back to the LLM/static suggestions and the human reviewer is the only gate that catches over-broad requests. Provisioning works identically either way.

## ExternalId and confused-deputy resistance

Each destination role's trust policy requires `sts:ExternalId` to be `iam-jit-<destination-account-id>` (or `iam-jit-discovery-<destination-account-id>` for the discovery role). The hub Lambda hardcodes this from the destination account ID it's targeting, so even if the hub account itself is compromised, an attacker who finds the hub Lambda's credentials still needs the right ExternalId per destination — and the ExternalId is a function of the target account, so it can't be reused across destinations.

## Threat model

| Threat | Mitigation |
|---|---|
| Agent (under prompt injection) authors a malicious policy | iam-jit does NOT generate policies from natural language (path removed in 0.4.0 per `docs/AGENTS.md`). The agent submits a draft policy (its responsibility); iam-jit scores it (1-10), enforces the auto-approve threshold, routes everything above the threshold to a human reviewer, and writes the full submission + decision to the audit log. The scoring engine itself is deterministic + calibration-corpus-backed (1,489 / 1,489 AWS-managed pass rate). |
| Requester pastes a wildcard-laden policy | Server-side risk review (1-10) flags it; narrowing flow asks for ARN scoping; human reviewer is the gate. |
| Compromise of the hub Lambda role | Limited to assume-role into ProvisionerRole — which can only manage `managed-by: iam-jit` resources under `/iam-jit/*`. Cannot escalate to controlling other IAM resources. |
| Compromise of a ProvisionerRole credential | Same blast radius as the hub Lambda for that destination. ExternalId requirement means the credential is bound to the hub account's principal. |
| Compromise of the iam-jit code (e.g. malicious dep) | Final ceiling is the IAM permissions of the Lambda + ProvisionerRole. Even arbitrary code execution can't grant beyond the destination role's tag-scoped IAM permissions. |
| Approver agent compromised | Agent can only call `approve_request` on requests already in the queue. Cannot create requests on someone else's behalf without that user's API token. |
| API token leaked | Per-user tokens, rotateable. Tokens are stored hashed in DynamoDB. Rotate via the UI or `revoke_token` MCP tool. |
| Accidental double-approval | Requests transition `pending → approved → provisioned` once. Idempotent provision check on the API side. |
| Cross-account confused deputy | ExternalId requirement on every assume-role; per-destination ExternalIds derived from account ID. |

## Audit trail

Every request and state transition is captured:

- Request YAML files in the state bucket (versioned — full history preserved).
- CloudTrail in each destination account records every assume-role + every IAM/sso-admin call.
- The hub Lambda's CloudWatch logs include request IDs, approver identity, and outcomes.
- The web UI's "history" tab and the `get_request` MCP tool surface the same data.

## Recommended monitoring (Phase 3+ work)

- CloudWatch alarm on `iam:CreateRole` calls in destination accounts NOT made by the iam-jit-provisioner principal — that's a sign someone is creating IAM roles outside the system.
- CloudWatch alarm on assume-role failures from the iam-jit Lambda — could indicate a misconfiguration or an attempted attack.
- Alarm on the expiry Lambda's `errors` count — if expiry stops working, grants accumulate beyond their intended duration.

## Authentication and authorization

VPN reachability is **not** authorization. iam-jit enforces identity at the application layer (or at the Function URL layer for AWS_IAM auth) so anyone who can reach the URL still gets `401` unless they hold valid credentials.

### Two auth modes

Selected per deployment via the `AuthMode` SAM parameter.

**`local` mode** (default; small teams)

- DynamoDB `UsersTable` holds: `user_id = email:<email>`, `roles`, `created_at`, magic-link state.
- Login flow: user enters email → server emails a single-use magic link via SES → user clicks → server sets a signed session cookie.
- Function URL has `AuthType: NONE`; the FastAPI middleware enforces the session cookie on every request and returns 401 otherwise.
- Bootstrap: SAM custom resource (Phase 1b) seeds the first admin user. After that, admins manage users via the API/UI.

**`aws_iam` mode** (recommended for orgs already on AWS Identity Center)

- Function URL has `AuthType: AWS_IAM`. Every request must be SigV4-signed; Lambda receives the verified caller identity in `event.requestContext.authorizer.iam.userArn`.
- DynamoDB `UsersTable` holds: `user_id = iam:<arn>`, `roles`. Maintained by the deployer or via the admin API.
- Recognizes:
  - IAM users (`arn:aws:iam::123:user/alice`)
  - IAM roles (`arn:aws:iam::123:role/devops`)
  - Identity Center session-assumed roles (`arn:aws:sts::123:assumed-role/AWSReservedSSO_DevOps_xxx/alice@example.com`)
- DDoS bound: only callers with valid AWS credentials hit Lambda at all; further bound by per-principal rate limiting in the app.

Both modes share the same internal `User { id, roles, email? }` shape; routes never branch on auth mode after the middleware extracts the user.

### Roles

| Role | Capabilities |
|---|---|
| `requester` | Submit own requests; view, edit, cancel own pending requests; comment on any request they participate in. |
| `approver` | All `requester` rights, plus: view all requests; approve / reject / request_changes on any request; comment on any. Cannot cancel others' requests (different action). |
| `admin` | All `approver` rights, plus: create/disable users, rotate API tokens, force-cancel stuck requests, change system config. |

A user can have multiple roles. Roles are additive.

### Owner-based authorization

A request has an `owner` field set at creation time (the submitting user's `user_id`). The middleware enforces:

- `view`, `edit`, `cancel` on a request require either `request.owner == user.id` OR `approver`/`admin` role for view-only.
- `approve`, `reject`, `request_changes` require `approver` or `admin` and **disallow self-approval** even for admins (a user cannot approve their own request).
- `force_cancel` is admin-only and emits an audit event.

### State transitions and who triggers them

```
draft → submit → pending ──approve(approver)──► provisioning → active → expire → expired
                    │
                    ├──reject(approver)──► rejected
                    │
                    ├──cancel(owner)──► cancelled
                    │
                    ├──request_changes(approver)──► needs_changes
                    │                                    │
                    │                                    ├──resubmit(owner)──► pending
                    │                                    │
                    │                                    └──cancel(owner)──► cancelled
                    │
                    └──edit(owner)──► pending  (new revision; full history retained)
```

Edits create a new revision with a monotonic version number; the state bucket holds every revision (versioned S3). The latest revision is what the queue and approver see.

### DDoS posture

- Every endpoint requires auth. There are no anonymous paths beyond `/healthz`.
- Function URL throttling is enabled by default; the SAM template can be extended with reserved concurrency for traffic spikes.
- Per-principal rate limiting is enforced in the API layer (Phase 1b).
- `aws_iam` mode adds a strong outer bound: only valid AWS credentials reach Lambda at all.
- Magic-link emails are rate-limited per email address to prevent SES abuse.

### Configuring access

The user list itself can be sourced one of two ways, picked at deploy time via `UserConfigSource`. Mutually exclusive — one source of truth.

| `UserConfigSource` | Source of truth | Update mechanism | Best for |
|---|---|---|---|
| `dynamodb` (default) | DynamoDB UsersTable | UI / CLI / API write | Small teams who want admin-managed access via a UI |
| `file` | YAML file in S3 (`users.yaml`) | Upload new version to S3 | GitOps / change-controlled access; PR-reviewed user changes |

In **either** mode, updates are effective without redeploying iam-jit:
- DynamoDB writes are immediately visible.
- S3 uploads are picked up within a 60s in-memory cache TTL (ETag-based, so re-parse only happens when the file actually changes).

The file format is JSON-Schema-validated (`schemas/users.schema.json`); the server rejects malformed files at load time and falls back to the previously-loaded version, so a bad upload can't lock everyone out.

| Mode | Adding a user | Removing a user | Promoting to approver |
|---|---|---|---|
| `local` + `dynamodb` | Admin invites by email; user clicks magic link | Admin disables in UsersTable | Admin updates roles in UsersTable |
| `aws_iam` + `dynamodb` | Admin adds `iam:<arn>` row to UsersTable | Admin deletes the row | Admin updates roles |
| `local` + `file` | Edit `users.yaml`, upload to S3 | Set `enabled: false` and re-upload | Edit roles in `users.yaml`, re-upload |
| `aws_iam` + `file` | Add an `iam:<arn>` entry to `users.yaml` | Remove or set `enabled: false` | Edit roles, re-upload |

### Switching `UserConfigSource`

The two modes are mutually exclusive at runtime, but switching between them is one SAM parameter change:

```bash
# Export the current DynamoDB user list to a YAML file
iam-jit users export > users.yaml

# Upload to the state bucket
aws s3 cp users.yaml s3://<state-bucket>/users.yaml

# Switch the parameter
sam deploy --parameter-overrides ... UserConfigSource=file
```

iam-jit now reads from S3. The DynamoDB table is left in place but unused (deletable later if you're sure).

For the reverse direction:

```bash
iam-jit users import s3://<state-bucket>/users.yaml
sam deploy --parameter-overrides ... UserConfigSource=dynamodb
```

`import` writes each YAML entry to the DynamoDB table; subsequent admin UI/CLI changes go to DynamoDB.

Both paths preserve audit history of access changes (S3 versioning for file mode + CloudWatch logs of every refresh; DynamoDB streams + CloudWatch logs for dynamodb mode).

## Hardening recommendations for production

- Put the API Function URL behind a VPC endpoint or IAM-IDP-protected proxy (Cognito, Cloudflare Access, Tailscale Funnel) — the SAM template uses `AuthType: NONE` for development simplicity; you must add auth in front before going to production.
- Set up CloudFormation drift detection on the destination stacks; manual edits to the ProvisionerRole undermine the trust model.
- Use Service Control Policies in your AWS organization to prevent the iam-jit destination stacks from being modified outside CloudFormation.
- For Identity Center mode, restrict `AllowedPermissionSetArns` to a small set of pre-vetted permission sets. Don't allow arbitrary permission set creation.
