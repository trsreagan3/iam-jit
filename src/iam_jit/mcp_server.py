"""MCP (Model Context Protocol) server exposing iam-jit's agent-facing tools.

Lets any MCP-aware agent (Claude Code, Cursor, custom Claude SDK
builds, etc.) browse iam-jit's template catalog, score arbitrary
IAM policies, and submit grant requests. Per [[no-nl-synthesis]]
(decision 2026-05-16), the server does NOT synthesize policies
from natural-language prompts — the agent (with its codebase
context + LLM) does the authoring, iam-jit scores and gates.
See docs/AGENTS.md for the reduction-loop pattern.

Architecture (4 live tools + 1 tombstone):

  list_templates  — browse the catalog (AWS-managed baselines +
                    iam-jit-curated entries like
                    ExploreReadOnlyWithSensitiveExclusions)
  get_template    — fetch a specific template's policy shape
  score_iam_policy — rate any policy 1-10 with per-factor breakdown
  submit_policy   — submit a finished policy for grant issuance
                    (HTTP POSTs to IAM_JIT_URL when configured)
  generate_iam_policy — REMOVED in 0.4.0; tombstone returns the
                        deprecation block + null policy + pointer
                        to replacement tools

The server uses the stdio transport (one MCP server per CLI
invocation, typically spawned by the agent's MCP-host configuration).
Stdio is the simplest transport — no auth, no network, perfect
for local developer-facing agents.

Spec reference: https://modelcontextprotocol.io/specification

Implementation note: this is a MINIMAL JSON-RPC 2.0 over stdio
implementation. We deliberately avoid pulling in heavy MCP SDK
dependencies — the protocol surface we need is tiny (4 tools, no
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

SERVER_NAME = "iam-jit"
# 0.4.0: stage 3 of NL deprecation deletes the policy_gen package
# entirely; generate_iam_policy is now a hard tombstone.
SERVER_VERSION = "0.4.0"
MCP_PROTOCOL_VERSION = "2024-11-05"


# Tool definition the agent will discover via the `tools/list` MCP call.
# The `inputSchema` follows JSON Schema; MCP hosts (Claude Code/Desktop)
# use it to validate before invoking the tool.
TOOLS = [
    {
        "name": "generate_iam_policy",
        "description": (
            "REMOVED in iam-jit 0.4.0 (tombstone). Calling this tool "
            "returns a deprecation block + null policy + a pointer to "
            "the replacement tools. Natural-language policy synthesis "
            "was measured at 1.8% joint sufficiency (see "
            "docs/calibration/100-prompt-sufficiency-loop.md) and is "
            "structurally limited because iam-jit lacks codebase "
            "context. Replacements: `list_templates` (browse the "
            "AWS-managed catalog), `get_template` (fetch a policy "
            "shape by name), `score_iam_policy` (rate any policy + "
            "get a per-factor breakdown the agent can iterate "
            "against), and `submit_policy` (submit a finished policy "
            "for grant issuance). Agent-driven workflow: pick a "
            "baseline → score → reduce using your codebase context → "
            "re-score → submit. See docs/AGENTS.md."
        ),
        # Tombstone — schema deliberately empty. Per LOW-16-03 closure:
        # the old per-property descriptions (task / access_type / bias /
        # exclude_actions / etc.) described synthesis behavior the
        # tombstone doesn't provide. Leaving them would undermine the
        # REMOVED signal. Agents discover the migration via the
        # description above + the structured deprecation block in any
        # response.
        "inputSchema": {"type": "object"},
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
    {
        "name": "list_templates",
        "description": (
            "Browse the iam-jit template catalog. Returns metadata only "
            "(no policy bodies — use `get_template` for the full shape). "
            "USE THIS as the first step when the user describes a task: "
            "find the closest baseline, fetch it, narrow it via the "
            "agent's codebase context, score it, submit. NO fuzzy "
            "matching against the user's prompt — pass `query` only if "
            "you already know part of a template's exact name. The "
            "catalog currently includes AWS-managed policies "
            "(ReadOnlyAccess, SecurityAudit, AmazonS3ReadOnlyAccess, "
            "AdministratorAccess, etc.) plus iam-jit baselines like "
            "ExploreReadOnlyWithSensitiveExclusions (broad read minus "
            "secrets/KMS/sensitive S3). See docs/AGENTS.md for the "
            "agent-driven reduction loop."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "access_type": {
                    "type": "string",
                    "enum": ["read-only", "read-write", "admin"],
                    "description": (
                        "Filter by access type. Per [[read-only-default]], "
                        "start with `read-only`; only request `read-write` "
                        "when the user explicitly authorized a state-"
                        "changing operation."
                    ),
                },
                "service": {
                    "type": "string",
                    "description": (
                        "AWS service prefix to filter by (e.g. `s3`, "
                        "`ec2`). Templates with services=['*'] match "
                        "every service query."
                    ),
                },
                "source": {
                    "type": "string",
                    "enum": ["aws-managed", "org-curated", "personal-recurring"],
                    "description": (
                        "Filter by template source. Pre-launch only "
                        "`aws-managed` returns entries; `org-curated` "
                        "and `personal-recurring` are reserved."
                    ),
                },
                "query": {
                    "type": "string",
                    "description": (
                        "Optional case-insensitive substring match on "
                        "template name. NOT a fuzzy / NL search — only "
                        "use if you already know part of an exact name."
                    ),
                },
                "tag": {
                    "type": "string",
                    "description": (
                        "Optional exact-match filter against an entry's "
                        "use-case tags. Examples: 'audit', 'incident-"
                        "response', 'explore', 'data-read', 'admin'. "
                        "Case-insensitive. NO fuzzy / NL search — exact "
                        "string match on the tag list."
                    ),
                },
            },
        },
    },
    {
        "name": "get_template",
        "description": (
            "Fetch one template's full policy shape by exact name "
            "(call `list_templates` first to find the name). Returns "
            "the policy ready to score / narrow / submit. Pre-launch "
            "covers AWS-managed catalog entries; post-launch will add "
            "org-curated + personal-recurring per the evolving preset "
            "library."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": (
                        "Exact template name (e.g. `AmazonS3ReadOnlyAccess`, "
                        "`ExploreReadOnlyWithSensitiveExclusions`). "
                        "Case-sensitive."
                    ),
                },
            },
        },
    },
    {
        "name": "save_template",
        "description": (
            "Save a policy as a NAMED TEMPLATE in your personal library. "
            "Per [[evolving-preset-library]] — once you've authored a "
            "policy that works (e.g. via score_iam_policy + iteration), "
            "save it so next time the same access is needed you can "
            "list_templates(source='personal-recurring') + get_template "
            "instead of re-authoring. The library COMPOUNDS in value "
            "as you use it. Per [[scorer-is-ground-truth]], the saved "
            "template is just a starting point — the scorer re-evaluates "
            "every submission. Past approval does NOT lower current risk."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["name", "policy"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": (
                        "Human-friendly name for the template (e.g. "
                        "'payment-incident-read', 'rotate-staging-secret'). "
                        "Must be unique within your personal library."
                    ),
                },
                "policy": {
                    "type": "object",
                    "description": "The IAM policy document to save.",
                },
                "description": {
                    "type": "string",
                    "description": (
                        "Optional free-text description of what this "
                        "template is for. Helps you remember context "
                        "when browsing your library later."
                    ),
                },
                "source_grant_id": {
                    "type": "string",
                    "description": (
                        "Optional: the grant id this template was "
                        "derived from. Surfaces in the audit log as "
                        "'based on saved template X originally from "
                        "grant Y'."
                    ),
                },
            },
        },
    },
    {
        "name": "list_my_templates",
        "description": (
            "List the templates in your personal library (saved via "
            "save_template). Returns metadata only (no policy bodies — "
            "use get_my_template for the full shape). To browse the "
            "broader AWS-managed + iam-jit catalog, use list_templates "
            "instead."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "get_my_template",
        "description": (
            "Fetch one of YOUR saved templates' full policy shape by "
            "name (or template_id). The personal-library read path — "
            "complements list_my_templates. Catalog templates (AWS-"
            "managed, etc.) are NOT served here; use get_template for "
            "those. Per [[evolving-preset-library]]: each fetch "
            "increments the template's reuse_count, which drives "
            "post-launch 'save-as-recurring' suggestions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": (
                        "Template name (as you saved it). Exact match. "
                        "Either name or template_id is required."
                    ),
                },
                "template_id": {
                    "type": "string",
                    "description": (
                        "Template id (e.g. 'tmpl_abc123'). Either name "
                        "or template_id is required. If both are given, "
                        "template_id wins."
                    ),
                },
            },
        },
    },
    {
        "name": "reduce_policy",
        "description": (
            "Apply deterministic reductions to a baseline policy. The "
            "core agent-driven reduction loop primitive — given a "
            "broad starting baseline (e.g. AdminLikeWithSensitive "
            "Exclusions or ReadOnlyAccess), reduce it along one or "
            "more axes before submission: drop services the task "
            "doesn't need, scope to specific accounts, scope to "
            "specific regions. Each reduction is recorded in the "
            "returned recipe — the audit-chain artifact (\"baseline "
            "X minus [rds, secretsmanager], scoped to account 123 + "
            "us-east-1\"). Use score_iam_policy after to verify the "
            "reduction lowered the risk; use submit_policy to "
            "submit. Per [[scorer-is-ground-truth]]: this tool only "
            "transforms; the scorer always evaluates the result."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["policy"],
            "properties": {
                "policy": {
                    "type": "object",
                    "description": (
                        "The policy to reduce — typically a baseline "
                        "fetched via get_template or get_my_template."
                    ),
                },
                "deny_services": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Service prefixes to deny (e.g. ['rds', "
                        "'secretsmanager']). Appends a Deny statement "
                        "blocking <service>:* for each."
                    ),
                },
                "narrow_to_accounts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "12-digit AWS account IDs. Adds aws:Requested"
                        "Account StringEquals condition to every "
                        "Allow statement. Non-conforming IDs rejected."
                    ),
                },
                "narrow_to_regions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "AWS region codes (e.g. ['us-east-1']). Adds "
                        "aws:RequestedRegion StringEquals condition "
                        "to every Allow statement. Note: GLOBAL "
                        "services (IAM, STS, billing) ignore this — "
                        "this narrowing is incremental defense, not "
                        "absolute."
                    ),
                },
            },
        },
    },
    {
        "name": "find_similar_templates",
        "description": (
            "Find templates in your personal library similar to a "
            "candidate policy. Useful when you're about to author a "
            "new policy — check whether you already have a saved one "
            "that fits. Similarity is action-overlap (Jaccard) based; "
            "returns top-K matches above min_similarity. NO fuzzy "
            "natural-language matching — purely shape-based comparison."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["policy"],
            "properties": {
                "policy": {
                    "type": "object",
                    "description": "The candidate policy to compare against your library.",
                },
                "top_k": {
                    "type": "integer",
                    "default": 5,
                    "description": "Max number of matches to return.",
                },
                "min_similarity": {
                    "type": "number",
                    "default": 0.3,
                    "description": (
                        "Minimum Jaccard similarity (0.0-1.0) to "
                        "include a match. Default 0.3 ~ 'meaningful overlap'."
                    ),
                },
            },
        },
    },
    {
        "name": "submit_policy",
        "description": (
            "Submit a finished IAM policy for grant issuance. Runs the "
            "policy through the same scorer as `score_iam_policy` and, "
            "if `IAM_JIT_URL` + `IAM_JIT_TOKEN` env vars are set, POSTs "
            "to the iam-jit request-creation endpoint. Otherwise returns "
            "the request body the agent would have submitted (so the user "
            "can pipe it through `iam-jit remote submit` themselves). "
            "USE THIS as the final step of the agent-driven workflow: "
            "list_templates → get_template → narrow → score_iam_policy → "
            "submit_policy. iam-jit's auto-approval gate fires here "
            "based on the score + safety mode; if the policy doesn't "
            "auto-approve, the response includes a `review_url` for "
            "human approval."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["policy", "description", "accounts"],
            "properties": {
                "policy": {
                    "type": "object",
                    "description": "The IAM policy document.",
                },
                "description": {
                    "type": "string",
                    "description": (
                        "Free-text justification — what this grant is "
                        "for. Used in the audit log; ~1KB max."
                    ),
                },
                "accounts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "AWS account IDs the grant targets. At least one."
                    ),
                },
                "duration_hours": {
                    "type": "integer",
                    "default": 1,
                    "description": "Grant TTL in hours. Default 1, max 720.",
                },
                "access_type": {
                    "type": "string",
                    "enum": ["read-only", "read-write"],
                    "default": "read-only",
                    "description": "Per [[read-only-default]].",
                },
                "assume_principal_arn": {
                    "type": "string",
                    "description": (
                        "Optional IAM principal that will assume the "
                        "issued role."
                    ),
                },
                "ticket": {
                    "type": "string",
                    "description": "Optional ticket / change reference.",
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


_DEPRECATION_BLOCK = {
    "deprecated": True,
    "removed_in": "0.4.0",
    "reason": (
        "Natural-language policy synthesis scored 1.8% joint sufficiency "
        "in the 2026-05-16 calibration loop. See "
        "docs/calibration/100-prompt-sufficiency-loop.md."
    ),
    "replacement_tools": [
        "list_templates",
        "get_template",
        "score_iam_policy",
        "submit_policy",
    ],
    "agent_guidance": (
        "Pick a baseline with list_templates → fetch it with get_template "
        "→ narrow it using your codebase context → re-score with "
        "score_iam_policy → submit with submit_policy. See docs/AGENTS.md."
    ),
}


def _list_templates_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Browse the iam-jit template catalog (metadata only).

    Input validation per MED-14-01: every filter arg must be a
    string if provided; otherwise return a structured rejection
    (not a raise) so the agent gets a useful error rather than
    a generic -32603 internal-error wrapper.
    """
    from .aws_managed_catalog import list_entries

    for field in ("access_type", "service", "source", "query", "tag"):
        val = args.get(field)
        if val is not None and not isinstance(val, str):
            return {
                "error": f"{field} must be a string (got {type(val).__name__})",
                "templates": [],
                "total": 0,
            }

    entries = list_entries(
        access_type=args.get("access_type"),
        service=args.get("service"),
        source=args.get("source"),
        query=args.get("query"),
        tag=args.get("tag"),
    )
    truncated = len(entries) > 50
    return {
        "templates": entries[:50],
        "total": len(entries),
        "truncated": truncated,
    }


def _get_template_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Fetch one template's full policy shape by exact name."""
    from .aws_managed_catalog import get_entry

    name = args.get("name")
    if not isinstance(name, str) or not name.strip():
        return {
            "error": "name is required and must be a non-empty string",
            "policy": None,
        }
    entry = get_entry(name.strip())
    if entry is None:
        return {
            "error": f"template not found: {name}",
            "policy": None,
        }
    return entry


# ---------------------------------------------------------------------------
# Personal preset library (per [[evolving-preset-library]] pre-launch slice)
# ---------------------------------------------------------------------------


def _current_user_id() -> str:
    """The user id for personal-library operations.

    MCP runs stdio-local; there's no authenticated session. We use a
    process-stable identifier from env or fall back to 'local'. In
    hosted/team mode (post-launch), this would derive from the bearer
    token. For local-mode + tests, 'local' is fine — the library lives
    on the user's laptop and they own all of it.
    """
    import os
    return (
        os.environ.get("IAM_JIT_USER_ID")
        or os.environ.get("USER")
        or "local"
    )


def _save_template_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Save a policy as a named template in the user's personal library."""
    import time
    import uuid
    from .user_templates_store import (
        UserTemplate,
        UserTemplateNameTaken,
        compute_shape_hash,
        get_default_store,
    )

    name = args.get("name")
    policy = args.get("policy")
    if not isinstance(name, str) or not name.strip():
        return {"error": "name is required and must be a non-empty string", "template_id": None}
    if not isinstance(policy, dict):
        return {"error": "policy is required and must be a JSON object", "template_id": None}

    desc = args.get("description")
    if desc is not None and not isinstance(desc, str):
        return {"error": "description must be a string if provided", "template_id": None}
    source_grant = args.get("source_grant_id")
    if source_grant is not None and not isinstance(source_grant, str):
        return {"error": "source_grant_id must be a string if provided", "template_id": None}

    store = get_default_store()
    user_id = _current_user_id()
    template = UserTemplate(
        template_id=f"tmpl_{uuid.uuid4().hex[:12]}",
        user_id=user_id,
        name=name.strip(),
        policy=policy,
        created_at=int(time.time()),
        source_grant_id=source_grant,
        source_description=(desc or None),
        shape_hash=compute_shape_hash(policy),
    )
    try:
        store.put(template)
    except UserTemplateNameTaken as e:
        return {"error": str(e), "template_id": None}
    return {
        "template_id": template.template_id,
        "name": template.name,
        "shape_hash": template.shape_hash,
        "saved_at": template.created_at,
    }


def _get_my_template_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Fetch one of the user's saved templates by name or template_id.

    MED-18-03 closure: the personal-library read path. Increments
    reuse_count on each successful fetch (the signal post-launch
    'save-as-recurring' suggestions key off of).
    """
    from .user_templates_store import UserTemplateNotFound, get_default_store

    name = args.get("name")
    template_id = args.get("template_id")

    if template_id is not None and not isinstance(template_id, str):
        return {"error": "template_id must be a string if provided", "policy": None}
    if name is not None and not isinstance(name, str):
        return {"error": "name must be a string if provided", "policy": None}
    if not template_id and not (name and name.strip()):
        return {
            "error": "either name or template_id is required",
            "policy": None,
        }

    store = get_default_store()
    user_id = _current_user_id()
    try:
        if template_id:
            t = store.get(template_id.strip(), user_id=user_id)
        else:
            assert name is not None  # narrowed by guard above
            t = store.get_by_name(user_id, name.strip())
    except UserTemplateNotFound:
        ident = template_id or name
        return {"error": f"template not found: {ident}", "policy": None}

    # Reuse counter — the signal post-launch will key off
    store.increment_reuse(t.template_id, user_id=user_id)

    return {
        "template_id": t.template_id,
        "name": t.name,
        "policy": t.policy,
        "shape_hash": t.shape_hash,
        "created_at": t.created_at,
        "reuse_count": t.reuse_count + 1,  # reflect the increment we just did
        "source_grant_id": t.source_grant_id,
        "source_description": t.source_description,
    }


def _list_my_templates_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """List the current user's personal templates (metadata only)."""
    from .user_templates_store import get_default_store

    store = get_default_store()
    user_id = _current_user_id()
    templates = store.list_for_user(user_id)
    return {
        "templates": [
            {
                "template_id": t.template_id,
                "name": t.name,
                "created_at": t.created_at,
                "shape_hash": t.shape_hash,
                "reuse_count": t.reuse_count,
                "source_grant_id": t.source_grant_id,
                "source_description": t.source_description,
            }
            for t in templates
        ],
        "total": len(templates),
    }


def _reduce_policy_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Apply deterministic reductions to a baseline policy and return
    the reduced policy + recipe metadata. Pure function: doesn't
    mutate the input.
    """
    from .reductions import apply_reductions

    policy = args.get("policy")
    if not isinstance(policy, dict):
        return {
            "error": "policy is required and must be a JSON object",
            "policy": None,
            "recipe": [],
        }

    for field in ("deny_services", "narrow_to_accounts", "narrow_to_regions"):
        val = args.get(field)
        if val is not None and not isinstance(val, list):
            return {
                "error": f"{field} must be a list of strings if provided",
                "policy": None,
                "recipe": [],
            }

    result = apply_reductions(
        policy,
        deny_services_list=args.get("deny_services") or [],
        narrow_to_accounts_list=args.get("narrow_to_accounts") or [],
        narrow_to_regions_list=args.get("narrow_to_regions") or [],
    )
    return result.to_dict()


def _find_similar_templates_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Find templates in the user's library similar to a candidate policy."""
    from .user_templates_store import find_similar, get_default_store

    policy = args.get("policy")
    if not isinstance(policy, dict):
        return {"error": "policy is required and must be a JSON object", "matches": []}

    top_k = args.get("top_k", 5)
    if not isinstance(top_k, int) or isinstance(top_k, bool) or top_k < 1 or top_k > 50:
        return {"error": "top_k must be an integer in [1, 50]", "matches": []}
    min_sim = args.get("min_similarity", 0.3)
    if not isinstance(min_sim, (int, float)) or isinstance(min_sim, bool) or min_sim < 0 or min_sim > 1:
        return {"error": "min_similarity must be a number in [0.0, 1.0]", "matches": []}

    store = get_default_store()
    user_id = _current_user_id()
    matches = find_similar(
        store, user_id, policy, top_k=top_k, min_similarity=float(min_sim)
    )
    return {
        "matches": [
            {
                "template_id": t.template_id,
                "name": t.name,
                "similarity": round(sim, 3),
                "created_at": t.created_at,
                "reuse_count": t.reuse_count,
            }
            for t, sim in matches
        ],
        "total": len(matches),
    }


def _submit_policy_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Submit a finished policy for grant issuance.

    Always scores via the same engine as score_iam_policy.
    If IAM_JIT_URL + IAM_JIT_TOKEN env vars are set, POSTs to
    /api/v1/requests; otherwise returns the request shape the user
    can submit themselves via `iam-jit remote submit`.
    """
    import os

    policy = args.get("policy")
    description = args.get("description")
    accounts = args.get("accounts")

    if not isinstance(policy, dict):
        return {
            "error": "policy is required and must be a JSON object",
            "request_id": None,
        }
    if not isinstance(description, str) or not description.strip():
        return {
            "error": "description is required and must be non-empty",
            "request_id": None,
        }
    if not isinstance(accounts, list) or not accounts:
        return {
            "error": "accounts is required and must be a non-empty list "
                     "of AWS account IDs",
            "request_id": None,
        }
    # MED-14-02: every account must be a non-empty string. Without
    # this, ints/dicts/None pass through to would_submit verbatim
    # and confuse downstream tools that trust account-IDs.
    if not all(isinstance(a, str) and a.strip() for a in accounts):
        return {
            "error": "accounts items must each be a non-empty string",
            "request_id": None,
        }
    duration_hours = args.get("duration_hours", 1)
    # LOW-14-08: bool subclasses int — reject explicitly so True/False
    # don't slip into a numeric field.
    if (
        isinstance(duration_hours, bool)
        or not isinstance(duration_hours, int)
        or duration_hours < 1
        or duration_hours > 720
    ):
        return {
            "error": "duration_hours must be an integer in [1, 720]",
            "request_id": None,
        }
    access_type = args.get("access_type", "read-only")
    if access_type not in {"read-only", "read-write"}:
        access_type = "read-only"

    # Score it locally first (cheap, gives the agent an immediate
    # signal even before any HTTP round-trip).
    score_result = _score_for_mcp({
        "policy": policy,
        "access_type": access_type,
    })

    request_body = {
        "spec": {
            "policy": policy,
            "description": description.strip()[:1024],
            "accounts": list(accounts),
            "duration_hours": duration_hours,
            "access_type": access_type,
        },
    }
    # MED-14-03: only accept string assume_principal_arn / ticket.
    # Drop silently if wrong-typed (the schema marks them optional;
    # an audit-search tool downstream might assume string).
    apa = args.get("assume_principal_arn")
    if isinstance(apa, str) and apa.strip():
        request_body["spec"]["assume_principal_arn"] = apa.strip()
    ticket = args.get("ticket")
    if isinstance(ticket, str) and ticket.strip():
        request_body["spec"]["ticket"] = ticket.strip()

    base_url = os.environ.get("IAM_JIT_URL", "").strip()
    token = os.environ.get("IAM_JIT_TOKEN", "").strip()

    # No backend configured — return the would-submit shape so the
    # agent / user can submit via `iam-jit remote submit` themselves.
    if not base_url or not token:
        return {
            "request_id": None,
            "submitted": False,
            "reason": (
                "IAM_JIT_URL and/or IAM_JIT_TOKEN env vars not set. "
                "Returning the request body the agent would have "
                "submitted. Pipe it through `iam-jit remote submit` "
                "or POST to <IAM_JIT_URL>/api/v1/requests manually."
            ),
            "would_submit": request_body,
            "score": score_result.get("score"),
            "tier": score_result.get("tier"),
            "factors": score_result.get("factors"),
            "recommended_action": score_result.get("recommended_action"),
        }

    # Backend configured — try to POST. Failures return a structured
    # error rather than crashing the MCP server.
    try:
        import httpx
        with httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        ) as client:
            resp = client.post("/api/v1/requests", json=request_body)
    except Exception as e:
        return {
            "request_id": None,
            "submitted": False,
            "error": f"HTTP submission failed: {e}",
            "would_submit": request_body,
            "score": score_result.get("score"),
            "tier": score_result.get("tier"),
            "factors": score_result.get("factors"),
        }

    if resp.status_code >= 400:
        return {
            "request_id": None,
            "submitted": False,
            "error": f"HTTP {resp.status_code}: {resp.text[:400]}",
            "would_submit": request_body,
            "score": score_result.get("score"),
            "tier": score_result.get("tier"),
        }

    try:
        body = resp.json()
    except Exception:
        body = {}

    return {
        "request_id": body.get("request_id") or body.get("id"),
        "submitted": True,
        "score": score_result.get("score"),
        "tier": score_result.get("tier"),
        "factors": score_result.get("factors"),
        "recommended_action": score_result.get("recommended_action"),
        "status": body.get("status"),
        "auto_approved": body.get("status") == "approved",
        "review_url": body.get("review_url"),
        "server_response": body,
    }


def _generate_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """TOMBSTONE — Stage 3 of [[no-nl-synthesis]] (iam-jit 0.4.0)
    deleted the entire policy_gen package. This entry point now
    returns a deprecation block + null policy + replacement_tools
    pointer. Tool stays discoverable in tools/list so agents that
    have it cached find out about the migration explicitly.
    See docs/AGENTS.md for the new agent-driven reduction loop.
    """
    return {
        "deprecation": _DEPRECATION_BLOCK,
        "error": (
            "generate_iam_policy is removed in iam-jit 0.4.0. "
            "Use list_templates + get_template + score_iam_policy + "
            "submit_policy instead (see docs/AGENTS.md)."
        ),
        "policy": None,
        "matched_patterns": [],
        "confidence": None,
        "scored_risk": None,
        "risk_factors": [],
        "risk_suggestions": [],
        "suppressed_actions": [],
        "refinement_hints": [],
        "unmatched_reason": "tool removed in 0.4.0",
        "reasons": [],
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
        elif tool_name == "list_templates":
            result_payload = _list_templates_for_mcp(args)
        elif tool_name == "get_template":
            result_payload = _get_template_for_mcp(args)
        elif tool_name == "submit_policy":
            result_payload = _submit_policy_for_mcp(args)
        elif tool_name == "save_template":
            result_payload = _save_template_for_mcp(args)
        elif tool_name == "list_my_templates":
            result_payload = _list_my_templates_for_mcp(args)
        elif tool_name == "get_my_template":
            result_payload = _get_my_template_for_mcp(args)
        elif tool_name == "find_similar_templates":
            result_payload = _find_similar_templates_for_mcp(args)
        elif tool_name == "reduce_policy":
            result_payload = _reduce_policy_for_mcp(args)
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
