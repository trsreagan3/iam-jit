"""MCP (Model Context Protocol) server exposing iam-jit policy generation.

Lets any MCP-aware agent (Claude Code, Cursor, custom Claude SDK
builds, etc.) natively request scoped AWS IAM policies for specific
tasks. The agent describes what it needs to do; the server returns a
generated policy + risk score; the agent (or its orchestrator) decides
whether to attach the policy to a JIT-issued STS credential.

Architecture:
  agent → MCP request: { task, context, bias }
        ↓
  this server: validates input, calls generate_policy(), runs the
               output through the deterministic scorer
        ↓
  agent ← MCP response: { policy, risk_score, refinement_hints }

The server uses the stdio transport (one MCP server per CLI invocation,
typically spawned by the agent's MCP-host configuration). Stdio is the
simplest transport — no auth, no network, perfect for local
developer-facing agents.

Spec reference: https://modelcontextprotocol.io/specification

Implementation note: this is a MINIMAL JSON-RPC 2.0 over stdio
implementation. We deliberately avoid pulling in heavy MCP SDK
dependencies — the protocol surface we need is tiny (one tool, no
prompts, no resources) and the spec is small. Going dependency-light
also keeps the iam-jit install footprint usable for environments
that don't want a full MCP SDK.

Run as:
  iam-jit mcp-server
  # OR
  python -m iam_jit.mcp_server

Usage in Claude Desktop / Code:
  Add to ~/.config/claude/mcp_settings.json:
  {
    "mcpServers": {
      "iam-jit": {
        "command": "iam-jit",
        "args": ["mcp-server"]
      }
    }
  }
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .policy_gen import (
    BIAS_ALLOW,
    BIAS_DENY,
    GenerationContext,
    GenerationRequest,
    Refinement,
    generate_policy,
)


SERVER_NAME = "iam-jit"
SERVER_VERSION = "0.2.0"
MCP_PROTOCOL_VERSION = "2024-11-05"


# Tool definition the agent will discover via the `tools/list` MCP call.
# The `inputSchema` follows JSON Schema; MCP hosts (Claude Code/Desktop)
# use it to validate before invoking the tool.
TOOLS = [
    {
        "name": "generate_iam_policy",
        "description": (
            "Generate a minimum-scope AWS IAM policy for a described task. "
            "The policy is scored by a deterministic risk engine (1-10) "
            "and includes refinement hints if the output may be too broad "
            "or too narrow. Use this when you need temporary scoped AWS "
            "access (read S3, query DynamoDB, deploy Lambda, etc.) and "
            "want to avoid using long-lived admin credentials.\n"
            "\n"
            "IMPORTANT — read-only default convention "
            "([[read-only-default]]): ALWAYS request "
            "`access_type: \"read-only\"` by default. ONLY request "
            "`read-write` when the user has explicitly asked you to make "
            "a state-changing operation in their current message "
            "(create / update / delete / modify resources). If you are "
            "uncertain whether a task needs writes, default to read-only "
            "and re-call this tool with read-write later if reads fail "
            "with permission errors. This is the convention that makes "
            "iam-jit's safety-mode work: the user has explicit visibility "
            "into when writes happen vs invisible read-only operation. "
            "Defaulting to read-write defeats the entire point."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["task"],
            "properties": {
                "task": {
                    "type": "string",
                    "description": (
                        "Plain-English description of the task. Be "
                        "specific about resources (bucket name, function "
                        "name, table name) and the operation (read, "
                        "write, deploy)."
                    ),
                },
                "access_type": {
                    "type": "string",
                    "enum": ["read-only", "read-write"],
                    "default": "read-only",
                    "description": (
                        "REQUIRED behavioral default: 'read-only'. "
                        "Only set to 'read-write' when the user has "
                        "explicitly authorized a state-changing "
                        "operation. When in doubt, use 'read-only' and "
                        "re-request later if needed."
                    ),
                },
                "account_id": {
                    "type": "string",
                    "description": "AWS account ID for ARN construction. Wildcards if omitted.",
                },
                "region": {
                    "type": "string",
                    "description": "AWS region. Wildcards if omitted.",
                },
                "partition": {
                    "type": "string",
                    "enum": ["aws", "aws-cn", "aws-us-gov"],
                    "description": "AWS partition. Default: aws.",
                },
                "resources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional list of explicit resource ARNs. Use when "
                        "the agent has already resolved a resource to its ARN."
                    ),
                },
                "bias": {
                    "type": "string",
                    "enum": ["allow", "deny"],
                    "description": (
                        "How to resolve ambiguity in the task description. "
                        "'allow' (default) includes more actions; 'deny' "
                        "includes only explicit ones."
                    ),
                },
                "exclude_actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Refinement: actions (or service:* globs) to "
                        "REMOVE from a prior result that was too broad."
                    ),
                },
                "include_actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Refinement: extra service:Action items to ADD "
                        "to a prior result that was too narrow."
                    ),
                },
                "rationale": {
                    "type": "string",
                    "description": (
                        "Free-text reason for the refinement. Surfaces "
                        "in audit logs for compliance review."
                    ),
                },
            },
        },
    },
    {
        "name": "score_iam_policy",
        "description": (
            "Score an existing AWS IAM policy on a 1-10 risk scale. "
            "Returns the score, risk factors, and a tier "
            "(low/medium/high). USE THIS PROACTIVELY whenever you "
            "generate or modify an IAM policy in any artifact the "
            "user will deploy — terraform `aws_iam_policy` resources, "
            "CloudFormation IAM templates, CDK `iam.PolicyDocument`, "
            "or raw JSON. The user should NOT have to manually pipe "
            "the policy through any other tool; calling this is the "
            "agent's responsibility before suggesting `terraform "
            "apply` / `cdk deploy` / `aws iam create-policy`.\n"
            "\n"
            "If score >= 5, surface the risk factors to the user and "
            "offer to refine the policy. If score >= 8, decline to "
            "suggest deploying without explicit user confirmation."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["policy"],
            "properties": {
                "policy": {
                    "type": "object",
                    "description": (
                        "The IAM policy document as a JSON object. "
                        "Must have `Version` and `Statement` keys. "
                        "Pass the FULL document, not a single statement."
                    ),
                },
                "access_type": {
                    "type": "string",
                    "enum": ["read-only", "read-write"],
                    "default": "read-write",
                    "description": (
                        "Hint about the policy's intended access type. "
                        "Affects suggested-fix prose; doesn't change "
                        "the raw score."
                    ),
                },
                "context": {
                    "type": "string",
                    "description": (
                        "Optional free-text context: what role this "
                        "policy is for, what workflow uses it. Helps "
                        "the audit log + future calibration."
                    ),
                },
            },
        },
    },
]


def _score_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Score an existing IAM policy via the deterministic engine.

    Wired so agents (Claude Code, Cursor) can score policies they
    just generated in a terraform/cdk/cfn artifact WITHOUT requiring
    the human to manually pipe the JSON anywhere. Per user direction
    2026-05-16: 'devs don't want to manually pipe the json through —
    it should just happen.'
    """
    policy = args.get("policy")
    if not isinstance(policy, dict):
        return {
            "error": "policy is required and must be a JSON object "
                     "with `Version` and `Statement` keys",
            "score": None,
        }
    access_type = args.get("access_type", "read-write")
    request_shell = {
        "spec": {
            "policy": policy,
            "access_type": access_type,
            "duration_hours": 1,
        },
    }
    try:
        from .review import analyze_policy
        analysis = analyze_policy(policy, request_shell)
    except Exception as e:
        return {
            "error": f"scoring engine failed: {e}",
            "score": None,
        }

    score = analysis.risk_score
    tier = "high" if score >= 7 else ("medium" if score >= 4 else "low")

    # Agent-facing decision hints in the structured response. The
    # tool description tells the agent the policy-on-policy rule
    # (>=5 surface to user, >=8 decline) but we ALSO compute the
    # recommended action here so a less-careful agent still does
    # the right thing.
    if score >= 8:
        recommended_action = "DECLINE_TO_DEPLOY_WITHOUT_EXPLICIT_CONFIRM"
    elif score >= 5:
        recommended_action = "SURFACE_FACTORS_TO_USER"
    else:
        recommended_action = "OK_TO_PROCEED"

    return {
        "score": score,
        "tier": tier,
        "factors": list(analysis.risk_factors),
        "suggestions": list(analysis.suggestions or []),
        "recommended_action": recommended_action,
        "context": args.get("context", ""),
    }


def _generate_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Call generate_policy with MCP-flavored args; return MCP-flavored result."""
    task = args.get("task", "")
    if not isinstance(task, str) or not task.strip():
        return {
            "error": "task is required and must be a non-empty string",
            "policy": None,
        }
    refinement = None
    if (
        args.get("exclude_actions")
        or args.get("include_actions")
        or args.get("rationale")
    ):
        refinement = Refinement(
            exclude_actions=list(args.get("exclude_actions") or []),
            include_actions=list(args.get("include_actions") or []),
            rationale=args.get("rationale", ""),
        )
    bias = args.get("bias", "allow")
    # access_type defaults to read-only per [[read-only-default]] —
    # the tool description tells the agent to default to read-only.
    # If the agent passes something else, honor it (the user's
    # explicit choice). If the agent passes something invalid,
    # coerce to read-only (the safe default).
    access_type = args.get("access_type", "read-only")
    if access_type not in {"read-only", "read", "read-write"}:
        access_type = "read-only"
    req = GenerationRequest(
        task_description=task,
        bias=BIAS_ALLOW if bias == "allow" else BIAS_DENY,
        access_type=access_type,
        context=GenerationContext(
            account_id=args.get("account_id"),
            region=args.get("region"),
            partition=args.get("partition", "aws"),
            resources=list(args.get("resources") or []),
        ),
        refinement=refinement,
    )
    result = generate_policy(req)
    return {
        "policy": result.policy,
        "matched_patterns": result.matched_patterns,
        "confidence": result.confidence,
        "scored_risk": result.scored_risk,
        "risk_factors": result.risk_factors,
        "risk_suggestions": result.risk_suggestions,
        "suppressed_actions": result.suppressed_actions,
        "refinement_hints": result.refinement_hints,
        "unmatched_reason": result.unmatched_reason,
        "reasons": result.reasons,
    }


def _handle_request(req: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC 2.0 request; return the response dict.

    Returns None for notifications (no `id` field) — JSON-RPC says
    notifications get no response.
    """
    method = req.get("method")
    rid = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return _ok(rid, {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })

    if method == "tools/list":
        return _ok(rid, {"tools": TOOLS})

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments") or {}
        if tool_name == "generate_iam_policy":
            result_payload = _generate_for_mcp(args)
        elif tool_name == "score_iam_policy":
            result_payload = _score_for_mcp(args)
        else:
            return _err(rid, -32601, f"unknown tool: {tool_name}")
        # MCP tool result format: { content: [{type: "text", text: "..."}] }
        return _ok(rid, {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result_payload, indent=2),
                }
            ],
            # Also include the structured payload for clients that
            # support the experimental "structuredContent" field.
            "structuredContent": result_payload,
        })

    if method in ("notifications/initialized", "notifications/cancelled"):
        # Notification — no response.
        return None

    return _err(rid, -32601, f"method not found: {method}")


def _ok(rid: object, result: object) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(rid: object, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": code, "message": message},
    }


def main() -> int:
    """Read JSON-RPC requests from stdin; write responses to stdout.

    One request per line. The MCP stdio transport spec uses
    line-delimited JSON (no Content-Length headers). Errors during
    request processing are returned as JSON-RPC error responses, not
    raised — the MCP host expects the server to stay alive.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            # Can't return a structured error because we don't have an id;
            # write a parse-error response with id=null per JSON-RPC.
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"parse error: {e}"},
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue
        try:
            resp = _handle_request(req)
        except Exception as e:  # defensive — never crash the server
            resp = _err(req.get("id"), -32603, f"internal error: {e}")
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
