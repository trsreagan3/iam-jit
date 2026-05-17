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
        "name": "get_reduction_checklist",
        "description": (
            "Return the curated checklist of reduction options for "
            "the guided-reduction walkthrough (per [[ui-guided-"
            "reduction-pro-tier]]). ~10 high-impact items: 'I don't "
            "need secrets', 'I don't need RDS', etc. UI users + "
            "agents who want a structured starting point use this. "
            "Each item has an id, label, description, and the "
            "reduction it applies. Pre-checked-by-default items are "
            "the sensitive-deny set most admins almost certainly "
            "don't need. NOT exhaustive — surfaces only items whose "
            "presence/absence shifts the scorer ≥1 point."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "apply_reduction_checklist",
        "description": (
            "Apply the user's checklist selections to a baseline "
            "policy + return the reduced result. The high-level "
            "wrapper over reduce_policy that takes ID-based "
            "selections from get_reduction_checklist's output. "
            "Returns {policy, recipe, summary, selected_item_ids, "
            "applied_item_ids}: selected_item_ids = what the user "
            "picked AND we recognize; applied_item_ids = subset "
            "whose axis actually fired (the audit chain distinguishes "
            "'user clicked' from 'policy actually changed'). Unknown "
            "IDs and unknown axes are silently ignored (forward-"
            "compatible with Enterprise-plugin checklist customizations)."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["policy", "selected_item_ids"],
            "properties": {
                "policy": {
                    "type": "object",
                    "description": "The baseline policy to reduce.",
                },
                "selected_item_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Item IDs from get_reduction_checklist that "
                        "the user checked (= 'I don't need this'). "
                        "Each adds a Deny to the policy."
                    ),
                },
                "narrow_to_accounts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional 12-digit account IDs to scope to.",
                },
                "narrow_to_regions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional AWS region codes to scope to.",
                },
            },
        },
    },
    {
        "name": "tail_grant",
        "description": (
            "Return recent AWS API events made under a JIT-issued "
            "grant's role session — the 'what is alice's agent "
            "doing right now with the grant I approved 10 min ago?' "
            "view. Reads from the configured LiveActionTailSource "
            "(default: null source returns empty; self-host admins "
            "wire CloudTrailLookupSource; Enterprise plugin wires "
            "EventBridge real-time streaming). Per "
            "[[creates-never-mutates]] this only READS — never "
            "modifies IAM. Per [[no-hosted-saas]] the query runs "
            "against the customer's own CloudTrail in the customer's "
            "own account. Returns the events plus the source's "
            "self-description so the caller knows what they're "
            "reading + the inherent freshness lag."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["grant_id"],
            "properties": {
                "grant_id": {
                    "type": "string",
                    "description": (
                        "The iam-jit request ID whose issued role "
                        "session you want to tail. The grant must be "
                        "in `status.provisioned` state (role created)."
                    ),
                },
                "since": {
                    "type": "string",
                    "description": (
                        "Optional ISO-8601 UTC lower bound. Defaults "
                        "to the grant's provisioned-at timestamp."
                    ),
                },
                "until": {
                    "type": "string",
                    "description": (
                        "Optional ISO-8601 UTC upper bound. Defaults "
                        "to the grant's expires_at timestamp."
                    ),
                },
                "aws_region": {
                    "type": "string",
                    "description": (
                        "Optional AWS region code to narrow to. If "
                        "omitted, the source's default region is used "
                        "(CloudTrail is regional)."
                    ),
                },
                "only_errors": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, return only failed API calls (non-empty errorCode).",
                },
                "max_events": {
                    "type": "integer",
                    "default": 100,
                    "description": "Max events to return (hard cap 1000 in OSS).",
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
                "deny_actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Specific action globs to deny (e.g. "
                        "['s3:Put*', 'ssm:GetParameter*', 'kms:Decrypt']). "
                        "Use when 'block whole service' is too coarse — "
                        "e.g. 'block S3 writes but keep reads'. Each "
                        "token must be in service:action format."
                    ),
                },
                "narrow_to_accounts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "12-digit AWS account IDs. Adds aws:Resource"
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
                "workload": {
                    "type": "string",
                    "enum": [
                        "k8s_pod", "eks_pod_identity", "ec2_instance",
                        "lambda_function", "ecs_task", "ci_runner",
                        "agent_local_dev", "human_cli", "other",
                    ],
                    "description": (
                        "What's making the AWS call. Per WB24 HIGH-24-01 "
                        "closure: when provided, iam-jit runs "
                        "check_iam_jit_compatibility internally BEFORE "
                        "issuance and refuses fixed-role workloads "
                        "(k8s_pod, ec2_instance, lambda_function, "
                        "ecs_task, eks_pod_identity) with a clear "
                        "redirect to use the existing role + bouncer. "
                        "Strongly recommended — saves an MCP round-trip "
                        "and enforces the 'call check_iam_jit_compatibility "
                        "FIRST' contract from AGENTS.md. If omitted, "
                        "submission proceeds but logs a "
                        "'submit_without_compatibility_check' audit event "
                        "so admins can spot agents bypassing the check."
                    ),
                },
            },
        },
    },
    # ---------------------------------------------------------------
    # Applicability framework (per [[iam-jit-inapplicable-cases]]):
    # agents call these BEFORE submitting a request so they don't
    # waste cycles trying iam-jit on cases where it fundamentally
    # can't help (k8s IRSA, EC2 instance profile, Lambda exec, etc.).
    # Per [[agent-friendly-not-bypassable]] Lens A: every non-PROCEED
    # response includes a next_action_hint so the agent has a path
    # forward, not just a vague "can't help."
    # ---------------------------------------------------------------
    {
        "name": "check_iam_jit_compatibility",
        "description": (
            "Ask iam-jit whether it can help with a specific use case "
            "BEFORE submitting a grant request. Returns one of four "
            "verdicts: 'proceed' (iam-jit-the-issuer can mint a JIT "
            "role), 'use_existing' (the workload requires a fixed "
            "pre-existing role — k8s IRSA, EC2 instance profile, "
            "Lambda exec role; iam-jit can't help with issuance but "
            "iam-jit-the-bouncer can gate), 'use_bouncer' (issuance "
            "doesn't apply but the local proxy does), 'cannot_help' "
            "(rare; escalate to human). Every non-PROCEED response "
            "includes reasoning + next_action_hint so the agent has "
            "a concrete path forward, not a vague error. Call this "
            "FIRST when you're about to use iam-jit in an unfamiliar "
            "environment — saves cycles trying iam-jit where it "
            "fundamentally can't help."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["workload"],
            "properties": {
                "workload": {
                    "type": "string",
                    "enum": [
                        "k8s_pod",
                        "eks_pod_identity",
                        "ec2_instance",
                        "lambda_function",
                        "ecs_task",
                        "codebuild_project",
                        "step_functions",
                        "glue_job",
                        "sagemaker",
                        "app_runner",
                        "batch_job",
                        "ci_runner",
                        "agent_local_dev",
                        "human_cli",
                        "other",
                    ],
                    "description": (
                        "What's making the AWS API call. Distinct "
                        "workloads have distinct compatibility profiles."
                    ),
                },
                "target_account_id": {
                    "type": "string",
                    "description": "Optional 12-digit AWS account ID.",
                },
                "target_services": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional list of AWS service prefixes the "
                        "workload needs to call (e.g. ['s3', 'dynamodb'])."
                    ),
                },
                "description": {
                    "type": "string",
                    "description": "Free-text use-case description (audit log only).",
                },
                "existing_role_hint": {
                    "type": "string",
                    "description": (
                        "Optional ARN of a pre-existing role the agent "
                        "already knows about. If the verdict is "
                        "'use_existing', this is echoed back so the "
                        "agent has a single response to act on."
                    ),
                },
            },
        },
    },
    {
        "name": "list_compatibility_catalog",
        "description": (
            "List the curated known-incompatible patterns iam-jit "
            "uses to answer compatibility questions. Useful for "
            "agents that want to see the full set of cases iam-jit "
            "recognizes (k8s IRSA, EC2 IP, Lambda exec, ECS task, "
            "OIDC CI, etc.) and the canonical next-action for each."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_compatibility_overrides",
        "description": (
            "List the admin-supplied compatibility allowlist (Slice 2 "
            "of #166). Each rule overrides the curated catalog for a "
            "specific account / workload combination — e.g. 'for "
            "account 111 + k8s_pod, always use this shared role.' "
            "Read-only for agents — only admins can mutate the "
            "allowlist (via the `iam-jit allowlist` CLI). Per "
            "[[agent-friendly-not-bypassable]]: agents can SEE what "
            "their org has configured but cannot grant themselves "
            "access by adding allowlist rules."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    # ---------------------------------------------------------------
    # iam-jit-bouncer (Lens A per [[agent-friendly-not-bypassable]]):
    # MCP-mirror of the iam-jit-bouncer CLI so agents can read +
    # configure the bouncer without shelling out. Every mutation here
    # writes to the bouncer's config-events audit log (Lens B); there
    # is no MCP tool that disables the bouncer or skips audit.
    # ---------------------------------------------------------------
    {
        "name": "bouncer_list_rules",
        "description": (
            "List the iam-jit-bouncer rules currently configured on "
            "this machine. Per [[agent-friendly-not-bypassable]]: "
            "agents should READ before WRITE so they understand the "
            "existing posture before proposing changes. Returns each "
            "rule with id + effect + pattern + scope + note + origin "
            "('user' / 'preset' / 'learn'). Read-only; doesn't change "
            "anything."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "bouncer_add_rule",
        "description": (
            "Add a new iam-jit-bouncer rule. The rule is validated + "
            "the addition is written to the bouncer's config-events "
            "audit log (no silent additions per "
            "[[agent-friendly-not-bypassable]] Lens B). Rejects "
            "malformed patterns immediately so a typo doesn't silently "
            "no-op. Use sparingly — prefer applying a preset baseline "
            "(`bouncer_list_presets` + `bouncer_apply_preset`) over "
            "authoring one-off rules."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["pattern"],
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": (
                        "service:action_glob (e.g. 's3:GetObject', "
                        "'s3:Put*', 'iam:Delete*'). Service must be "
                        "a bare prefix (no wildcards in service "
                        "position); action may include '*'."
                    ),
                },
                "effect": {
                    "type": "string",
                    "enum": ["allow", "deny"],
                    "default": "allow",
                },
                "arn_scope": {
                    "type": "string",
                    "description": "Optional ARN-glob to narrow the rule's scope.",
                },
                "region_scope": {
                    "type": "string",
                    "description": "Optional region-glob (e.g. 'us-east-1', 'us-*').",
                },
                "note": {
                    "type": "string",
                    "description": "Human-readable reason this rule exists (recommended).",
                },
            },
        },
    },
    {
        "name": "bouncer_remove_rule",
        "description": (
            "Remove a bouncer rule by id. The deletion is itself "
            "audit-logged with the full prior content of the rule so "
            "post-incident review can answer 'what rule existed at "
            "time T'. Per [[agent-friendly-not-bypassable]] Lens B: "
            "no agent can rules-add-then-remove to cover its tracks."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["rule_id"],
            "properties": {
                "rule_id": {"type": "integer", "minimum": 1},
            },
        },
    },
    {
        "name": "bouncer_decide",
        "description": (
            "Dry-run: ask the bouncer what it WOULD do for a "
            "hypothetical AWS API call, without forwarding it. The "
            "primary agent tool for 'before I make this call, will "
            "it pass?' — use this to figure out which rules need to "
            "exist before proposing them. Self-describing per "
            "[[agent-friendly-not-bypassable]]: response includes "
            "the matched rule id (if any) and the reason, so the "
            "agent can propose a config change in its next turn."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["service", "action"],
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Lowercase AWS service prefix (e.g. 's3', 'iam').",
                },
                "action": {
                    "type": "string",
                    "description": "AWS action name (e.g. 'GetObject', 'CreateRole').",
                },
                "arn": {"type": "string", "description": "Optional target ARN."},
                "region": {"type": "string", "description": "Optional AWS region."},
                "mode": {
                    "type": "string",
                    "enum": ["learn", "enforce", "prompt"],
                    "default": "enforce",
                },
                "default_policy": {
                    "type": "string",
                    "enum": ["allow", "deny"],
                    "default": "deny",
                    "description": "What enforce mode does when no rule matches.",
                },
            },
        },
    },
    {
        "name": "bouncer_list_presets",
        "description": (
            "List the curated preset baselines available "
            "(readonly / admin-minus-sensitive / prod-deny-destructive / "
            "deny-iam-admin). Per [[agent-friendly-not-bypassable]] "
            "Lens A: agents start from a vetted preset and narrow, "
            "instead of authoring rules from scratch. Returns each "
            "preset's name + description + rule count."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "bouncer_show_preset",
        "description": (
            "Show the rules a preset would add, WITHOUT applying "
            "them. Use to preview before `bouncer_apply_preset`."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["preset_name"],
            "properties": {
                "preset_name": {"type": "string"},
            },
        },
    },
    {
        "name": "bouncer_apply_preset",
        "description": (
            "Add all rules from a preset baseline to the current "
            "ruleset. Existing rules are PRESERVED — the preset "
            "rules are appended. The application is audit-logged "
            "with the preset name so post-review knows what starting "
            "point was chosen."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["preset_name"],
            "properties": {
                "preset_name": {"type": "string"},
            },
        },
    },
    {
        "name": "bouncer_tail_events",
        "description": (
            "Inspect the bouncer's config-change audit log (rule "
            "additions, removals, mode changes, preset applications). "
            "Per [[agent-friendly-not-bypassable]] Lens B: this is "
            "the chain that proves nothing was changed silently. "
            "Newest first. Filter by event kind."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 1000},
                "kind": {
                    "type": "string",
                    "enum": [
                        "rule_added", "rule_removed",
                        "mode_changed", "preset_applied",
                        # WB26 LOW-26-05: task lifecycle kinds
                        "task_started", "task_ended",
                        # WB25 LOW-25-01: allowlist lifecycle kinds
                        "allowlist_rule_added", "allowlist_rule_removed",
                    ],
                    "description": "Optional event-kind filter.",
                },
            },
        },
    },
    {
        "name": "bouncer_start_task",
        "description": (
            "Declare a TASK SCOPE that narrows the bouncer's behavior "
            "for the duration of a discrete task. The canonical use "
            "case (per [[proxy-smart-defaults-and-task-scope]]): the "
            "agent is doing X (e.g. 'upgrade EKS staging cluster to "
            "1.30'); declare the allow rules the task needs + deny "
            "rules for what the task must NOT touch (e.g. prod); the "
            "bouncer enforces; the audit chain captures the task "
            "lifecycle. Only ONE task may be active at a time in "
            "Slice B — end the previous task before starting a new "
            "one. Tasks auto-expire on the wall-clock duration so a "
            "forgotten end_task doesn't leave the scope active "
            "indefinitely. Per [[agent-friendly-not-bypassable]] "
            "Lens A: the agent is the one with the context to "
            "declare scope; the bouncer enforces what the agent "
            "promised."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "description": (
                        "Human-readable description of what the task "
                        "is doing (audit-logged + shown in CLI)."
                    ),
                },
                "allow_rules": {
                    "type": "array",
                    "description": (
                        "Rules declaring what the task NEEDS. Each: "
                        "{pattern, arn_scope?, region_scope?, note?}. "
                        "Pattern is service:action_glob. Effect is "
                        "forced to ALLOW; don't pass an effect field."
                    ),
                    "items": {
                        "type": "object",
                        "required": ["pattern"],
                        "properties": {
                            "pattern": {"type": "string"},
                            "arn_scope": {"type": "string"},
                            "region_scope": {"type": "string"},
                            "note": {"type": "string"},
                        },
                    },
                },
                "deny_rules": {
                    "type": "array",
                    "description": (
                        "Explicit denies for the task (e.g. 'no prod' "
                        "account). Same shape as allow_rules; effect "
                        "forced to DENY. Task-deny wins over both "
                        "global allows AND learn-mode."
                    ),
                    "items": {
                        "type": "object",
                        "required": ["pattern"],
                        "properties": {
                            "pattern": {"type": "string"},
                            "arn_scope": {"type": "string"},
                            "region_scope": {"type": "string"},
                            "note": {"type": "string"},
                        },
                    },
                },
                "duration_minutes": {
                    "type": "integer",
                    "default": 30,
                    "minimum": 1,
                    "maximum": 1440,
                    "description": (
                        "Task duration (auto-expiry); max 24h. "
                        "Forgotten end_task doesn't keep the scope "
                        "active forever."
                    ),
                },
            },
        },
    },
    {
        "name": "bouncer_end_task",
        "description": (
            "End an active task scope. The remaining duration is "
            "discarded; the task moves to status='completed'. The "
            "end event is audit-logged with the supplied reason. "
            "Idempotent: calling end_task on a task that's already "
            "ended is a no-op error (the audit chain isn't double-"
            "logged)."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["task_id"],
            "properties": {
                "task_id": {"type": "string"},
                "reason": {
                    "type": "string",
                    "description": "Why the task is ending (audit-logged).",
                },
            },
        },
    },
    {
        "name": "bouncer_active_task",
        "description": (
            "Return the currently-active task scope, or null if no "
            "task is active. Auto-expires if the wall-clock expiry "
            "has passed (the returned value will be null in that "
            "case, and an audit event records the expiry). Useful "
            "for agents that want to verify their task is still "
            "active before continuing work."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "bouncer_tail_decisions",
        "description": (
            "Inspect the bouncer's decision audit log (every call "
            "the bouncer has gated). Per "
            "[[agent-friendly-not-bypassable]]: even LEARN mode "
            "records here — there is no silent path. Newest first."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 1000},
                "decision": {
                    "type": "string",
                    "enum": ["allow", "deny", "prompt"],
                    "description": "Optional decision-class filter.",
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


# ---------------------------------------------------------------------------
# Compatibility-checker MCP tools (per [[iam-jit-inapplicable-cases]])
# ---------------------------------------------------------------------------


# WB24 LOW-24-05 closure: semantic validators that match what iam-jit
# expects elsewhere (mirrors store._validate_request_id pattern shape).
_ACCOUNT_ID_RE = __import__("re").compile(r"^\d{12}$")
_SERVICE_PREFIX_RE = __import__("re").compile(r"^[a-z][a-z0-9-]{1,62}$")


def _parse_compatibility_intent(args: dict[str, Any]) -> dict[str, Any]:
    """Parse + validate a compatibility intent from MCP args. Returns
    either {'error': '...'} or {'intent': CompatibilityIntent}. Shared
    by `_check_compatibility_for_mcp` and (post-Slice-2) submit_policy
    enforcement so both validate identically."""
    from .compatibility import CompatibilityIntent, WorkloadType

    workload = args.get("workload")
    if not isinstance(workload, str) or not workload.strip():
        return {"error": "workload is required and must be a string"}
    try:
        workload_enum = WorkloadType(workload.strip())
    except ValueError:
        valid = ", ".join(w.value for w in WorkloadType)
        return {"error": f"unknown workload {workload!r}; must be one of: {valid}"}

    target_account_id = args.get("target_account_id")
    if target_account_id is not None:
        if not isinstance(target_account_id, str):
            return {"error": "target_account_id must be a string if provided"}
        if not _ACCOUNT_ID_RE.match(target_account_id.strip()):
            return {"error": "target_account_id must be exactly 12 digits"}
        target_account_id = target_account_id.strip()

    target_services_raw = args.get("target_services")
    if target_services_raw is not None and not isinstance(target_services_raw, list):
        return {"error": "target_services must be a list if provided"}
    target_services_clean: list[str] = []
    for item in target_services_raw or []:
        if not isinstance(item, str):
            return {"error": "target_services items must all be strings"}
        normalized = item.strip().lower()
        if not _SERVICE_PREFIX_RE.match(normalized):
            return {
                "error": (
                    f"target_services contains invalid service prefix "
                    f"{item!r}; service prefixes are lowercase, start "
                    "with a letter, max 63 chars (e.g. 's3', 'ec2', 'iam')"
                )
            }
        target_services_clean.append(normalized)

    description = args.get("description")
    if description is not None and not isinstance(description, str):
        return {"error": "description must be a string if provided"}

    existing_role_hint = args.get("existing_role_hint")
    if existing_role_hint is not None and not isinstance(existing_role_hint, str):
        return {"error": "existing_role_hint must be a string if provided"}

    return {
        "intent": CompatibilityIntent(
            workload=workload_enum,
            target_account_id=target_account_id,
            target_services=tuple(target_services_clean),
            description=description,
            existing_role_hint=existing_role_hint,
        ),
    }


def _compatibility_audit_sink():
    """Return the bouncer's config_events table as the compatibility-
    check audit sink — both are config-shape decisions and live in
    the same local audit chain. WB24 MED-24-01 closure. Best-effort:
    on any error (e.g. bouncer state.db not initialized), return None
    and the checker skips audit-logging without crashing."""
    try:
        from .bouncer.store import BouncerStore

        store = BouncerStore()

        class _SinkAdapter:
            def record(self, *, kind, actor, summary, detail=None):
                store._record_config_event_locked(
                    actor=actor,
                    kind=kind,
                    summary=summary,
                    detail=detail,
                )

        return _SinkAdapter()
    except Exception:
        return None


def _compatibility_actor() -> str:
    """Identify the caller for the audit log (mirrors `_bouncer_actor`).
    Reads IAM_JIT_BOUNCER_ACTOR if set, else 'mcp-agent'."""
    import os
    return os.environ.get("IAM_JIT_BOUNCER_ACTOR") or "mcp-agent"


def _load_allowlist_for_check():
    """Build the admin allowlist store for the checker. Best-effort:
    if the store can't be loaded (e.g. permission error on the file),
    return None and the checker degrades to catalog-only."""
    try:
        from .compatibility_allowlist import build_default_store

        return build_default_store()
    except Exception:
        return None


def _check_compatibility_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Run the applicability checker against an agent-provided intent.
    Returns a self-describing verdict so the agent has a path forward
    regardless of whether iam-jit can directly help."""
    from .compatibility import check_compatibility

    parsed = _parse_compatibility_intent(args)
    if "error" in parsed:
        return parsed
    intent = parsed["intent"]
    sink = _compatibility_audit_sink()
    allowlist = _load_allowlist_for_check()
    result = check_compatibility(
        intent,
        allowlist=allowlist,
        audit_sink=sink,
        actor=_compatibility_actor(),
    )
    return result.to_dict()


def _list_compatibility_overrides_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Read-only view of the admin allowlist. Mutation is admin-only
    via the CLI per [[agent-friendly-not-bypassable]] — agents see
    what their org has configured but can't grant themselves access.

    WB25 LOW-25-05 closure: paginated. Mirrors `bouncer_tail_events`
    + `bouncer_tail_decisions` shape (limit default 50, hard cap 1000)
    so admins with very large allowlists don't blow MCP transport
    line limits."""
    from .compatibility_allowlist import build_default_store

    limit = args.get("limit", 50)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return {"error": "limit must be a positive integer if provided",
                "rules": [], "count": 0, "total": 0}
    limit = min(limit, 1000)

    try:
        store = build_default_store()
        rules = store.list()
    except Exception as e:
        return {"error": f"could not load allowlist: {e}", "rules": [], "count": 0, "total": 0}
    total = len(rules)
    paged = rules[:limit]
    return {
        "rules": [r.to_dict() for r in paged],
        "count": len(paged),
        "total": total,
    }


def _list_compatibility_catalog_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Return the curated known-incompatible catalog so agents can
    see the full set of cases iam-jit recognizes."""
    from .compatibility import list_catalog

    entries = list_catalog()
    return {"entries": entries, "count": len(entries)}


# ---------------------------------------------------------------------------
# Bouncer MCP tools (Lens A per [[agent-friendly-not-bypassable]])
# ---------------------------------------------------------------------------


def _bouncer_actor() -> str:
    """Identify the agent making bouncer mutations. Mirrors the
    bouncer_cli `_current_actor` helper: IAM_JIT_BOUNCER_ACTOR env
    if set (lets agents identify themselves explicitly), else
    'mcp-agent' so audit-log readers can distinguish MCP traffic
    from CLI traffic at a glance."""
    import os
    return os.environ.get("IAM_JIT_BOUNCER_ACTOR") or "mcp-agent"


def _bouncer_list_rules_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.store import BouncerStore

    store = BouncerStore()
    try:
        rules = store.list_rules()
    finally:
        store.close()
    return {
        "rules": [{"id": rid, **r.to_dict()} for rid, r in rules],
        "count": len(rules),
    }


def _bouncer_add_rule_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.rules import Effect, ProxyRule
    from .bouncer.store import BouncerStore, InvalidRuleError

    pattern = args.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        return {"error": "pattern is required and must be a non-empty string"}

    effect_str = args.get("effect", "allow")
    if effect_str not in ("allow", "deny"):
        return {"error": "effect must be 'allow' or 'deny'"}

    for field in ("arn_scope", "region_scope", "note"):
        val = args.get(field)
        if val is not None and not isinstance(val, str):
            return {"error": f"{field} must be a string if provided"}

    rule = ProxyRule(
        pattern=pattern,
        effect=Effect(effect_str),
        arn_scope=args.get("arn_scope"),
        region_scope=args.get("region_scope"),
        note=args.get("note"),
        origin="mcp-agent",
    )
    store = BouncerStore()
    try:
        try:
            rid = store.add_rule(rule, actor=_bouncer_actor())
        except InvalidRuleError as e:
            return {
                "error": str(e),
                "hint": "Patterns must be in service:action_glob form (e.g. 's3:GetObject' or 's3:Put*').",
            }
    finally:
        store.close()
    return {
        "rule_id": rid,
        "effect": rule.effect.value,
        "pattern": rule.pattern,
        "audit_event_kind": "rule_added",
    }


def _bouncer_remove_rule_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.store import BouncerStore

    rule_id = args.get("rule_id")
    if not isinstance(rule_id, int) or isinstance(rule_id, bool) or rule_id < 1:
        return {"error": "rule_id must be a positive integer"}

    store = BouncerStore()
    try:
        removed = store.remove_rule(rule_id, actor=_bouncer_actor())
    finally:
        store.close()
    if not removed:
        return {"error": f"no rule with id #{rule_id}"}
    return {"removed": True, "rule_id": rule_id, "audit_event_kind": "rule_removed"}


def _bouncer_decide_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.decisions import DefaultPolicy, Mode, decide
    from .bouncer.rules import RuleSet
    from .bouncer.store import BouncerStore

    service = args.get("service")
    action = args.get("action")
    if not isinstance(service, str) or not service.strip():
        return {"error": "service is required"}
    if not isinstance(action, str) or not action.strip():
        return {"error": "action is required"}
    for field in ("arn", "region"):
        val = args.get(field)
        if val is not None and not isinstance(val, str):
            return {"error": f"{field} must be a string if provided"}

    mode_str = args.get("mode", "enforce")
    if mode_str not in ("learn", "enforce", "prompt"):
        return {"error": "mode must be 'learn', 'enforce', or 'prompt'"}
    default_policy_str = args.get("default_policy", "deny")
    if default_policy_str not in ("allow", "deny"):
        return {"error": "default_policy must be 'allow' or 'deny'"}

    store = BouncerStore()
    try:
        id_tagged = store.list_rules()
    finally:
        store.close()
    ruleset = RuleSet(rules=[r for _, r in id_tagged])
    record = decide(
        ruleset,
        mode=Mode(mode_str),
        default_policy=DefaultPolicy(default_policy_str),
        service=service,
        action=action,
        arn=args.get("arn"),
        region=args.get("region"),
    )
    matched_rule_id: int | None = None
    if record.matched_rule is not None:
        for rid, r in id_tagged:
            if r == record.matched_rule:
                matched_rule_id = rid
                break
    out: dict[str, Any] = record.to_dict()
    out["matched_rule_id"] = matched_rule_id
    # Self-describing: give the agent enough context to propose a fix
    # in its next turn if the decision was a deny.
    if record.decision.value == "deny" and record.matched_rule is None:
        out["how_to_allow"] = (
            f"No rule matched. To allow this call, call bouncer_add_rule "
            f"with pattern='{service}:{action}' (or a narrower glob)."
        )
    return out


def _bouncer_list_presets_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.presets import PRESETS, list_preset_names

    presets = [PRESETS[name].to_dict() for name in list_preset_names()]
    # Trim the rules array from the listing to keep response sizes
    # bounded; agents should call bouncer_show_preset to see full rules.
    for p in presets:
        p.pop("rules", None)
    return {"presets": presets, "count": len(presets)}


def _bouncer_show_preset_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.presets import get_preset

    preset_name = args.get("preset_name")
    if not isinstance(preset_name, str) or not preset_name.strip():
        return {"error": "preset_name is required"}
    preset = get_preset(preset_name.strip())
    if preset is None:
        return {"error": f"no preset named {preset_name!r}; try bouncer_list_presets"}
    return preset.to_dict()


def _bouncer_apply_preset_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.presets import get_preset
    from .bouncer.store import BouncerStore, InvalidRuleError

    preset_name = args.get("preset_name")
    if not isinstance(preset_name, str) or not preset_name.strip():
        return {"error": "preset_name is required"}
    preset = get_preset(preset_name.strip())
    if preset is None:
        return {"error": f"no preset named {preset_name!r}"}

    actor = _bouncer_actor()
    added = 0
    skipped: list[dict[str, Any]] = []
    store = BouncerStore()
    try:
        for rule in preset.rules:
            try:
                store.add_rule(rule, actor=actor)
                added += 1
            except InvalidRuleError as e:
                # Shouldn't happen with curated presets, but record
                # if it does so the audit chain isn't surprised.
                skipped.append({"pattern": rule.pattern, "error": str(e)})
        store.record_preset_applied(
            preset_name=preset.name, rules_added=added, actor=actor
        )
    finally:
        store.close()
    return {
        "preset_name": preset.name,
        "rules_added": added,
        "rules_skipped": skipped,
        "audit_event_kind": "preset_applied",
    }


def _bouncer_tail_events_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.store import BouncerStore

    limit = args.get("limit", 50)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return {"error": "limit must be a positive integer"}
    limit = min(limit, 1000)
    kind = args.get("kind")
    if kind is not None and not isinstance(kind, str):
        return {"error": "kind must be a string if provided"}

    store = BouncerStore()
    try:
        events = store.list_config_events(limit=limit, kind_filter=kind)
    finally:
        store.close()
    return {"events": events, "count": len(events)}


def _bouncer_tail_decisions_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.decisions import Decision
    from .bouncer.store import BouncerStore

    limit = args.get("limit", 50)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return {"error": "limit must be a positive integer"}
    limit = min(limit, 1000)
    decision = args.get("decision")
    decision_filter: Decision | None = None
    if decision is not None:
        if decision not in ("allow", "deny", "prompt"):
            return {"error": "decision must be 'allow', 'deny', or 'prompt'"}
        decision_filter = Decision(decision)

    store = BouncerStore()
    try:
        out = store.list_decisions(limit=limit, decision_filter=decision_filter)
    finally:
        store.close()
    return {"decisions": out, "count": len(out)}


# ---------------------------------------------------------------------------
# Bouncer task-scope MCP tools (Slice B of [[proxy-smart-defaults-and-task-scope]])
# ---------------------------------------------------------------------------


def _bouncer_start_task_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.store import ActiveTaskExistsError, BouncerStore
    from .bouncer.tasks import TaskValidationError, build_task_scope

    description = args.get("description")
    if not isinstance(description, str) or not description.strip():
        return {"error": "description is required and must be a non-empty string"}
    allow_rules = args.get("allow_rules") or []
    deny_rules = args.get("deny_rules") or []
    if not isinstance(allow_rules, list):
        return {"error": "allow_rules must be a list if provided"}
    if not isinstance(deny_rules, list):
        return {"error": "deny_rules must be a list if provided"}
    duration = args.get("duration_minutes", 30)
    if not isinstance(duration, int) or isinstance(duration, bool):
        return {"error": "duration_minutes must be an integer"}

    try:
        scope = build_task_scope(
            description=description,
            allow_rules=allow_rules,
            deny_rules=deny_rules,
            duration_minutes=duration,
            started_by=_bouncer_actor(),
        )
    except TaskValidationError as e:
        return {"error": str(e)}

    store = BouncerStore()
    try:
        # The store's add_task atomically enforces the single-active
        # invariant (WB26 HIGH-26-02 closure). Catch the dedicated
        # exception so the agent gets a structured error + the active
        # task_id to act on.
        try:
            store.add_task(scope, actor=_bouncer_actor())
        except ActiveTaskExistsError as e:
            existing = store.get_active_task()
            return {
                "error": str(e),
                "active_task_id": existing.task_id if existing else None,
            }
    finally:
        store.close()
    return {
        "task_id": scope.task_id,
        "expires_at": scope.expires_at,
        "allow_rule_count": len(scope.allow_rules),
        "deny_rule_count": len(scope.deny_rules),
        "audit_event_kind": "task_started",
    }


def _bouncer_end_task_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.store import BouncerStore

    task_id = args.get("task_id")
    if not isinstance(task_id, str) or not task_id.strip():
        return {"error": "task_id is required and must be a non-empty string"}
    reason = args.get("reason") or "ended via MCP"
    if not isinstance(reason, str):
        return {"error": "reason must be a string if provided"}

    store = BouncerStore()
    try:
        ok = store.end_task(task_id.strip(), actor=_bouncer_actor(), end_reason=reason)
    finally:
        store.close()
    if not ok:
        return {
            "error": (
                f"no active task with id {task_id!r} "
                "(already ended, or task doesn't exist)"
            ),
        }
    return {
        "task_id": task_id,
        "ended": True,
        "audit_event_kind": "task_ended",
    }


def _bouncer_active_task_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    from .bouncer.store import BouncerStore

    store = BouncerStore()
    try:
        scope = store.get_active_task()
    finally:
        store.close()
    if scope is None:
        return {"active": None}
    return {"active": scope.to_dict()}


def _tail_grant_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Return CloudTrail events for the JIT-issued role session of
    a given grant. See the `tail_grant` MCP tool definition for the
    full contract; this function does the validation + lookup +
    formatting."""
    from .live_action_tail import (
        TailQuery,
        extract_tail_inputs_from_grant,
        format_event_summary,
        get_default_source,
    )

    grant_id = args.get("grant_id")
    if not isinstance(grant_id, str) or not grant_id.strip():
        return {
            "error": "grant_id is required and must be a non-empty string",
            "events": [],
            "source": None,
        }

    since = args.get("since")
    until = args.get("until")
    aws_region = args.get("aws_region")
    for field in ("since", "until", "aws_region"):
        val = args.get(field)
        if val is not None and not isinstance(val, str):
            return {
                "error": f"{field} must be a string if provided",
                "events": [],
                "source": None,
            }

    only_errors = args.get("only_errors", False)
    if not isinstance(only_errors, bool):
        return {
            "error": "only_errors must be a boolean if provided",
            "events": [],
            "source": None,
        }

    max_events = args.get("max_events", 100)
    if not isinstance(max_events, int) or isinstance(max_events, bool):
        return {
            "error": "max_events must be an integer if provided",
            "events": [],
            "source": None,
        }
    if max_events < 1:
        return {
            "error": "max_events must be >= 1",
            "events": [],
            "source": None,
        }
    # Hard cap matches CloudTrailLookupSource.HARD_MAX_EVENTS
    max_events = min(max_events, 1000)

    # Load the grant from the request store. Lazy import so MCP
    # consumers without a configured store still get a clean error.
    try:
        from .app import _build_request_store_from_env

        store = _build_request_store_from_env()
        request = store.get(grant_id.strip())
    except Exception as e:
        return {
            "error": f"could not load grant '{grant_id}': {e}",
            "events": [],
            "source": None,
        }

    base_query = extract_tail_inputs_from_grant(request)
    if base_query is None:
        return {
            "error": (
                f"grant '{grant_id}' has no provisioned role to tail "
                "(status.provisioned missing or incomplete)"
            ),
            "events": [],
            "source": None,
        }

    query = TailQuery(
        role_name=base_query.role_name,
        session_name=base_query.session_name,
        account_id=base_query.account_id,
        since=since or base_query.since,
        until=until or base_query.until,
        aws_region=aws_region or base_query.aws_region,
        max_events=max_events,
        only_errors=only_errors,
    )

    source = get_default_source()
    result = source.fetch_events(query)

    # WB22 HIGH-22-01 closure: every other admin action on a grant
    # appends to status.history; tail reads must too so the audit
    # chain doesn't have a hole. Best-effort: never block the read
    # if the audit-log write fails.
    try:
        from .live_action_tail import record_tail_read_in_history

        record_tail_read_in_history(
            store,
            request,
            grant_id=grant_id.strip(),
            query=query,
            result_ok=result.ok,
            event_count=len(result.events),
            actor=_current_user_id(),
        )
    except Exception:
        pass

    return {
        "grant_id": grant_id,
        "role_session_provision_name": query.session_name,
        "role_name": query.role_name,
        "account_id": query.account_id,
        "source": source.describe(),
        "ok": result.ok,
        "error": result.error,
        "event_count": len(result.events),
        "events": [e.to_dict() for e in result.events],
        "summaries": [format_event_summary(e) for e in result.events],
    }


def _get_reduction_checklist_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Return the curated reduction checklist."""
    from .guided_reduction import get_checklist

    items = get_checklist()
    return {"items": items, "total": len(items)}


def _apply_reduction_checklist_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Apply checklist selections to a baseline policy."""
    from .guided_reduction import apply_selections

    policy = args.get("policy")
    selected = args.get("selected_item_ids")
    if not isinstance(policy, dict):
        return {
            "error": "policy is required and must be a JSON object",
            "policy": None,
            "recipe": [],
        }
    if not isinstance(selected, list):
        return {
            "error": "selected_item_ids must be a list of strings",
            "policy": None,
            "recipe": [],
        }
    for field in ("narrow_to_accounts", "narrow_to_regions"):
        val = args.get(field)
        if val is not None and not isinstance(val, list):
            return {
                "error": f"{field} must be a list of strings if provided",
                "policy": None,
                "recipe": [],
            }

    return apply_selections(
        policy,
        selected_item_ids=selected,
        narrow_to_accounts=args.get("narrow_to_accounts"),
        narrow_to_regions=args.get("narrow_to_regions"),
    )


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

    for field in (
        "deny_services",
        "deny_actions",
        "narrow_to_accounts",
        "narrow_to_regions",
    ):
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
        deny_actions_list=args.get("deny_actions") or [],
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

    WB24 HIGH-24-01 closure: when `workload` is provided, runs the
    applicability checker BEFORE issuance and refuses fixed-role
    workloads (k8s_pod, ec2_instance, lambda_function, ecs_task,
    eks_pod_identity) with a clear redirect to use the existing role
    + bouncer. When `workload` is omitted, submission proceeds but
    a `submit_without_compatibility_check` audit event is logged
    (Lens B: bypass-able but auditable).
    """
    import os

    # WB24 HIGH-24-01 closure: compatibility-check enforcement.
    workload = args.get("workload")
    if workload is not None:
        if not isinstance(workload, str):
            return {
                "error": "workload must be a string if provided",
                "request_id": None,
            }
        # Build a minimal intent for the check; reuse the same validator
        # the standalone tool uses so the contract is identical.
        accounts_for_intent = args.get("accounts") or []
        compat_intent_args = {
            "workload": workload,
            "target_account_id": (
                accounts_for_intent[0]
                if accounts_for_intent and isinstance(accounts_for_intent[0], str)
                and _ACCOUNT_ID_RE.match(accounts_for_intent[0])
                else None
            ),
            "description": args.get("description") if isinstance(args.get("description"), str) else None,
        }
        parsed = _parse_compatibility_intent(compat_intent_args)
        if "error" in parsed:
            return {
                "error": f"workload validation failed: {parsed['error']}",
                "request_id": None,
            }
        from .compatibility import Compatibility, check_compatibility

        check_result = check_compatibility(
            parsed["intent"],
            allowlist=_load_allowlist_for_check(),
            audit_sink=_compatibility_audit_sink(),
            actor=_compatibility_actor(),
        )
        # WB25 MED-25-01 closure: USE_BOUNCER is also a non-PROCEED
        # verdict; the admin allowlist can return it (and Slice 1's
        # OTHER catch-all uses bouncer_recommended=True). submit_policy
        # must refuse all three rather than silently mint a role the
        # workload won't use.
        if check_result.verdict in (
            Compatibility.USE_EXISTING,
            Compatibility.USE_BOUNCER,
            Compatibility.CANNOT_HELP,
        ):
            return {
                "error": (
                    f"iam-jit cannot issue a role for workload "
                    f"{workload!r}: {check_result.reasoning}"
                ),
                "next_action_hint": check_result.next_action_hint,
                "verdict": check_result.verdict.value,
                "matched_pattern": check_result.matched_pattern,
                "bouncer_recommended": check_result.bouncer_recommended,
                "request_id": None,
            }
    else:
        # Workload omitted — log the bypass so admins can audit.
        sink = _compatibility_audit_sink()
        if sink is not None:
            try:
                sink.record(
                    kind="submit_without_compatibility_check",
                    actor=_compatibility_actor(),
                    summary="submit_policy invoked without a workload arg",
                    detail={"description_preview": str(args.get("description") or "")[:140]},
                )
            except Exception:
                pass

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
        elif tool_name == "get_reduction_checklist":
            result_payload = _get_reduction_checklist_for_mcp(args)
        elif tool_name == "apply_reduction_checklist":
            result_payload = _apply_reduction_checklist_for_mcp(args)
        elif tool_name == "tail_grant":
            result_payload = _tail_grant_for_mcp(args)
        elif tool_name == "bouncer_list_rules":
            result_payload = _bouncer_list_rules_for_mcp(args)
        elif tool_name == "bouncer_add_rule":
            result_payload = _bouncer_add_rule_for_mcp(args)
        elif tool_name == "bouncer_remove_rule":
            result_payload = _bouncer_remove_rule_for_mcp(args)
        elif tool_name == "bouncer_decide":
            result_payload = _bouncer_decide_for_mcp(args)
        elif tool_name == "bouncer_list_presets":
            result_payload = _bouncer_list_presets_for_mcp(args)
        elif tool_name == "bouncer_show_preset":
            result_payload = _bouncer_show_preset_for_mcp(args)
        elif tool_name == "bouncer_apply_preset":
            result_payload = _bouncer_apply_preset_for_mcp(args)
        elif tool_name == "bouncer_tail_events":
            result_payload = _bouncer_tail_events_for_mcp(args)
        elif tool_name == "bouncer_tail_decisions":
            result_payload = _bouncer_tail_decisions_for_mcp(args)
        elif tool_name == "bouncer_start_task":
            result_payload = _bouncer_start_task_for_mcp(args)
        elif tool_name == "bouncer_end_task":
            result_payload = _bouncer_end_task_for_mcp(args)
        elif tool_name == "bouncer_active_task":
            result_payload = _bouncer_active_task_for_mcp(args)
        elif tool_name == "check_iam_jit_compatibility":
            result_payload = _check_compatibility_for_mcp(args)
        elif tool_name == "list_compatibility_catalog":
            result_payload = _list_compatibility_catalog_for_mcp(args)
        elif tool_name == "list_compatibility_overrides":
            result_payload = _list_compatibility_overrides_for_mcp(args)
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
