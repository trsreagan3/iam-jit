# Using the AWS MCP server with iam-jit — recommendation + UAT

**Question:** should we recommend the AWS MCP server for agents, alongside iam-jit?
**Answer: Yes — as the AWS _access channel_, but only when paired with an
iam-jit-issued scoped, short-lived credential, never a standing
`AdministratorAccess`/`ReadOnlyAccess` role.** Verified by a live UAT against
account `590519617224`: AWS enforces the iam-jit scope server-side, *through*
the MCP server (direct and routed via ibounce).

## What it is

Two flavors, same model:
- **`awslabs.aws-api-mcp-server`** (open source, MIT) — local stdio MCP server.
- **AWS-managed remote MCP Server** (GA, re:Invent 2025) — adds IAM condition
  keys (`aws:CalledViaAWSMCP`) + managed hosting.

Tools: **`call_aws`** (runs *any* AWS CLI command), `suggest_aws_commands`
(NL→command), `get_execution_plan` (experimental). **Auth = the boto3 credential
chain** (`AWS_ACCESS_KEY_ID/…/AWS_SESSION_TOKEN`, or `AWS_API_MCP_PROFILE_NAME`).
So it consumes an iam-jit-issued credential with **zero glue** — iam-jit's
`assume_instructions.agent_usage_hints` already emit exactly the env-var /
`AWS_PROFILE` / `credentials_process` shapes it reads.

## Why pairing with iam-jit matters (the core finding)

`call_aws` executes **any** AWS CLI command the credential allows — the MCP
server has **no meaningful per-action authorization of its own** (just a tiny
built-in denylist + an optional `READ_OPERATIONS_ONLY` flag). AWS's own guidance
says "IAM permissions remain the primary and most reliable security control."
**That control is exactly what iam-jit provides** — a least-privilege,
time-bound credential instead of a standing role. So a prompt-injected agent
driving `call_aws` can only do what the *credential* permits: with a broad
standing role, that's everything; with an iam-jit grant, it's one task's scope
for ≤ its TTL.

## The live UAT

Minted a scoped 15-min STS session (only `s3:ListAllMyBuckets`) — the same shape
iam-jit issues — fed it to `awslabs.aws-api-mcp-server` over MCP/stdio, and drove
`call_aws`:

| Call | Expect | Result |
|---|---|---|
| `sts:GetCallerIdentity` (control: creds valid) | allow | **200 ✅** |
| `s3:ListAllMyBuckets` (granted) | allow | **200 ✅** |
| `s3:ListBucket` on a real bucket (ungranted *action*) | deny | **403 AccessDenied ✅** |
| `ec2:DescribeInstances` (other service) | deny | **403 UnauthorizedOperation ✅** |
| `iam:ListUsers` (other service) | deny | **403 ✅** |
| `s3:CreateBucket` (write) | deny | **403 AccessDenied ✅** |

**OVERALL: PASS — AWS enforced the scoped credential server-side, through the MCP
server.** Re-ran with `AWS_ENDPOINT_URL` pointed at **ibounce**: same result, so
the agent's AWS calls can be **audited by the bouncer** on the way out.

**Reproduce:** `scripts/aws_mcp_uat.py` (skips unless `IAMJIT_AWS_MCP_UAT=1` + a
profile that can `sts:GetFederationToken` + the server importable via
`IAMJIT_UAT_MCP_PYTHON`).

**Fidelity note:** the UAT used `GetFederationToken` as a quick stand-in for an
iam-jit grant. iam-jit's production mechanism is **AssumeRole** (a role session).
Server-side scope enforcement is identical; the only federation-token quirk is
that fed tokens are blanket-blocked from IAM/STS APIs (hence the `iam:ListUsers`
403 reads as `InvalidClientTokenId` rather than `AccessDenied`). With an
AssumeRole grant that denial is a clean `AccessDenied`.

## Advantages

**Usability**
- One tool (`call_aws`) covers the entire AWS API — no per-service tool sprawl.
- **Zero-glue with iam-jit**: point it at the issued creds (env or
  `credentials_process` so they auto-refresh + stay scoped/short-lived).
- `suggest_aws_commands` helps the agent form correct commands.
- Official, maintained, broad coverage; trivial install (`uvx`/`pip`/Docker).

**Security**
- Composes perfectly with least-privilege creds — and IAM (i.e. the iam-jit
  grant) is the authoritative control, verified above.
- Local file access is restricted to a working dir by default.
- Managed flavor's `aws:CalledViaAWSMCP` condition key lets you write IAM that
  only permits a role **via the audited MCP path** — strong defense-in-depth
  iam-jit can embed in the roles it issues.
- Works behind ibounce for an egress audit trail (verified).

## Disadvantages / risks

- **No per-action authz of its own** — `call_aws` runs anything the credential
  allows; a prompt-injected agent runs arbitrary AWS within scope. *This is the
  reason to pair with iam-jit, not a reason to avoid it.*
- **Telemetry is ON by default** (`AWS_API_MCP_TELEMETRY=true`) — set it `false`.
- **`READ_OPERATIONS_ONLY` is not a data-exfil guarantee** — AWS warns some
  read-only operations "can still return AWS credentials or sensitive
  information in command outputs."
- **No sandboxing** — runs with the user's full filesystem permissions
  (`unrestricted` file-access mode is dangerous; keep the default `workdir`).
- **Not multi-tenant; stdio only.** HTTP transport is explicitly not for
  multi-tenant use — don't expose it.
- **Prompt injection** — AWS says "do not connect this MCP server to data
  sources with untrusted data."
- The built-in security-policy denylist/elicitList is **exact-match only (no
  wildcards)** — a weak standalone control.

## Recommended configuration (the way to ship it)

1. **Credentials:** an iam-jit-issued grant, via env vars or a
   `credentials_process` profile — **never** a standing broad role.
2. `AWS_API_MCP_TELEMETRY=false`.
3. **stdio** transport only; never expose HTTP / multi-tenant.
4. `READ_OPERATIONS_ONLY=true` as defense-in-depth for read-only tasks (but the
   scoped credential is the real boundary).
5. Keep file access at the default `workdir`.
6. Optional: route through **ibounce** (`AWS_ENDPOINT_URL`) for an audit trail.
7. Optional: have iam-jit embed `aws:CalledViaAWSMCP` in issued roles so the
   grant only works via the audited MCP path.

## Bottom line

Recommend it. The AWS MCP server answers "how does the agent talk to AWS?";
iam-jit answers "what credential should it hold, scoped to what, for how long,
approved by whom?" They compose cleanly, and the UAT proves the security
property that makes the pairing worth recommending: **the agent — even a
compromised one — can only do what the iam-jit grant allows, and AWS enforces
that through the MCP server.**
