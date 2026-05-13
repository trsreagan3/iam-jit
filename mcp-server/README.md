# iam-jit MCP server

Model Context Protocol server bundle for [iam-jit](../README.md). Drops the iam-jit HTTP API into your agent's tool palette so Claude Code, Cursor, Continue, and any other MCP-compatible client can submit role requests, drive approvals, and pull audit reports natively.

## Install

```bash
pip install ./mcp-server
```

After install, the `iam-jit-mcp` command is on your `$PATH`.

## Configure your MCP client

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (or the equivalent on your OS):

```json
{
  "mcpServers": {
    "iam-jit": {
      "command": "iam-jit-mcp",
      "env": {
        "IAM_JIT_BASE_URL": "https://iam-jit.your-org.com",
        "IAM_JIT_API_TOKEN": "iamjit_..."
      }
    }
  }
}
```

Mint the `IAM_JIT_API_TOKEN` from the iam-jit web UI under Tokens. The raw token is shown only once — copy it directly into the config.

### Claude Code (CLI)

Add to `~/.config/claude-code/mcp.json` (or wherever your install reads MCP config):

```json
{
  "mcpServers": {
    "iam-jit": {
      "command": "iam-jit-mcp",
      "env": {
        "IAM_JIT_BASE_URL": "https://iam-jit.your-org.com",
        "IAM_JIT_API_TOKEN": "iamjit_..."
      }
    }
  }
}
```

### Cursor / Continue

Same shape — set `command: iam-jit-mcp` plus the two env vars in whatever MCP config format your client uses.

## Tools

| Tool | Audience | What it does |
|---|---|---|
| `submit_role_request` | requester | Create a new role request. Pass either a list of services or a pre-built policy. |
| `check_request_status` | requester | Get the current state of one of your requests. |
| `respond_to_changes` | requester | Edit a `needs_changes` request and resubmit. |
| `cancel_request` | requester | Cancel one of your own pending requests. |
| `list_pending_requests` | approver | Inbox of requests awaiting decision. |
| `get_request` | approver | Full request including policy, comments, history. |
| `comment_on_request` | any | Post a comment / suggestion on a request. |
| `approve_request` | approver | Approve and trigger provisioning. |
| `reject_request` | approver | Reject with a reason. |
| `request_changes` | approver | Send back with feedback for the requester to address. |
| `analyze_policy` | any | One-shot risk-score + narrowing on a policy without submitting. |
| `list_users` | admin | Show the configured user list. |
| `report_grants` | admin | Pull the audit report of grants, filterable. |

## Example sessions

```
# Developer asks Claude to create a role:
> "Claude, create a read-only IAM role to debug the staging EKS cluster
   in account 060392206767 for 24 hours, then submit to iam-jit."

# Claude decides what services are needed (eks, logs, ec2),
# calls submit_role_request, surfaces the request ID + risk score.

> "Show me my open requests."
# Claude calls list_pending_requests filtered by your user, renders.

# Approver asks Claude to triage:
> "Show me pending iam-jit requests."
# Claude calls list_pending_requests, sorts by risk score.

> "Approve devops-42 with comment 'looks fine for prod debugging'."
# Claude calls approve_request.

> "DEVOPS-43 is asking for s3:* on *. Send it back asking them
   to scope to a specific bucket prefix."
# Claude calls request_changes with suggestions.
```

## How it relates to local-AI tooling

Best workflow when you have full local context (codebase, kubeconfig, terraform state):

1. Ask Claude (Code / Cursor) to draft a tight, ARN-specific policy from your local files.
2. Claude calls `submit_role_request` with the drafted `policy` argument.
3. iam-jit runs server-side risk review on the agent's submission, narrowing flags fire if needed, the human reviewer is the gate.
4. Webhooks (Phase 1b-ε) notify the agent when the request changes state so it can respond.

The iam-jit hosted service intentionally doesn't see your codebase — only what you choose to send. The MCP layer makes that data flow explicit and audit-friendly.

## License

Apache 2.0 — see the parent [LICENSE](../LICENSE).
