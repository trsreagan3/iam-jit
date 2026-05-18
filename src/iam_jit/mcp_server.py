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
            "was measured at joint sufficiency below the calibration bar (see "
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
        "name": "iam_jit_scope_self_for_task",
        "description": (
            "ONE-SHOT 'scope me for this task' composer. The canonical "
            "agent self-scoping tool per "
            "[[self-scoping-without-interaction]]. Wires three "
            "narrowing systems atomically: (1) compatibility check, "
            "(2) bouncer task scope creation, (3) optional JIT role "
            "submission. Returns one of five terminal states: "
            "'scoped' (both bouncer task + JIT role active), "
            "'scoped_bouncer_only' (bouncer task active; existing "
            "creds gated), 'needs_human' (scope too broad for "
            "auto-approval), 'cannot_help' (admin allowlist says "
            "out-of-scope), 'failed' (validation / concurrent task "
            "conflict). No user interaction required when the "
            "declared scope is narrow enough. After task duration "
            "expires, scope evaporates + baseline restored "
            "automatically."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["description", "allow_rules"],
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Human-readable task description (audit-logged).",
                },
                "allow_rules": {
                    "type": "array",
                    "description": (
                        "Positive declaration of what the task needs. "
                        "Each item: {pattern: 'service:action', "
                        "arn_scope?, region_scope?, note?}. The "
                        "implied JIT policy is derived from these rules."
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
                        "Explicit denies for the task scope (e.g. "
                        "'no prod account'). Task-deny wins over "
                        "global allows."
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
                },
                "workload": {
                    "type": "string",
                    "enum": [
                        "k8s_pod", "eks_pod_identity", "ec2_instance",
                        "lambda_function", "ecs_task", "codebuild_project",
                        "step_functions", "glue_job", "sagemaker",
                        "app_runner", "batch_job", "ci_runner",
                        "agent_local_dev", "human_cli", "other",
                    ],
                    "description": (
                        "Workload classification per the compatibility "
                        "framework. If a fixed-role workload (k8s_pod, "
                        "etc.) is declared, the composer skips JIT role "
                        "submission and returns 'scoped_bouncer_only'."
                    ),
                },
                "target_account_id": {
                    "type": "string",
                    "description": (
                        "12-digit AWS account ID. Required for JIT role "
                        "submission; bouncer-only scoping works without it."
                    ),
                },
                "target_services": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "AWS service prefixes (for compatibility check).",
                },
                "owner": {
                    "type": "string",
                    "description": (
                        "Per-owner identifier for concurrent task "
                        "scopes (Slice C). Omit for default-owner slot."
                    ),
                },
                "submit_jit_role": {
                    "type": "boolean",
                    "default": True,
                    "description": (
                        "When false, skip JIT role submission entirely "
                        "and return scoped_bouncer_only. Useful for "
                        "the explicit 'gate me but don't issue a role' "
                        "path."
                    ),
                },
            },
        },
    },
    {
        "name": "bouncer_effective_scope",
        "description": (
            "Read-only snapshot of what's gating the caller RIGHT "
            "NOW. Returns the active task (if any) + global rule "
            "count + composed visibility info. Per the 'return to "
            "baseline' clarification (2026-05-17): after a task "
            "ends, has_active_task becomes False and global rules "
            "ARE the effective scope. Use this to verify your scope "
            "before making a sensitive call."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {
                    "type": "string",
                    "description": "Owner identifier (omit for default-owner slot).",
                },
            },
        },
    },
    {
        "name": "bouncer_recommend_rules",
        "description": (
            "Synthesize a draft ruleset from observed decisions in "
            "the bouncer's audit log. Per "
            "[[bouncer-learn-then-recommend]] + [[apply-little-snitch-"
            "principles]] Research Assistant pattern: groups observed "
            "decisions by service:action, detects ARN/region patterns, "
            "recommends ALLOW rules with the discovered scope, and "
            "attaches curated 'what does this action do' explanations "
            "for common actions. Closes the loop from LEARN mode to "
            "ENFORCE: run learn mode for a few days, call this, "
            "review + adjust + apply via bouncer_apply_recommendation. "
            "Pure read; never modifies anything."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {
                    "type": "string",
                    "description": "ISO-8601 lower bound. Omit for 'everything in log'.",
                },
                "until": {
                    "type": "string",
                    "description": "ISO-8601 upper bound. Omit for 'until now'.",
                },
                "min_support": {
                    "type": "integer",
                    "default": 3,
                    "minimum": 1,
                    "description": "Skip groups with fewer than N observed calls.",
                },
                "limit": {
                    "type": "integer",
                    "default": 10000,
                    "minimum": 1,
                    "maximum": 10000,
                    "description": "Max decisions to read from the audit log.",
                },
                "include_task_scoped": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "By default, decisions made under a Slice C "
                        "task scope (one-off declared sessions) are "
                        "EXCLUDED from recommendations so they don't "
                        "become permanent global rules. Pass true to "
                        "include them."
                    ),
                },
            },
        },
    },
    {
        "name": "bouncer_apply_recommendation",
        "description": (
            "Apply a SUBSET of recommendations from "
            "bouncer_recommend_rules as new rules. Each is added "
            "individually via the same audit-logged path as manual "
            "adds; plus a `recommendation_applied` config event "
            "records the batch. Per "
            "[[agent-friendly-not-bypassable]] Lens A: agents review "
            "the recommendation list, cherry-pick + modify before "
            "applying."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["rules"],
            "properties": {
                "rules": {
                    "type": "array",
                    "description": (
                        "List of rule dicts to add. Typically the "
                        "agent passes a subset of proposed_rule "
                        "values from bouncer_recommend_rules's "
                        "response, possibly with adjustments."
                    ),
                    "items": {
                        "type": "object",
                        "required": ["pattern"],
                        "properties": {
                            "pattern": {"type": "string"},
                            "effect": {"type": "string", "enum": ["allow", "deny"]},
                            "arn_scope": {"type": "string"},
                            "region_scope": {"type": "string"},
                            "note": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
    {
        "name": "bouncer_task_review",
        "description": (
            "Post-task review summary for a given task_id. Returns "
            "the task's metadata + aggregated decision counts "
            "(total / allow / deny / prompt) + the list of denied "
            "calls (capped at 1000 entries; full counts still "
            "accurate). Slice C of [[proxy-smart-defaults-and-task-scope]]: "
            "lets admins see what the agent actually attempted "
            "during the task — useful for spotting tasks whose "
            "scope was too narrow (many denies) or too broad "
            "(broad allow rules but no use). WB27 HIGH-27-02 "
            "closure: cross-owner review is refused. Pass `owner` "
            "matching the task's owner."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["task_id"],
            "properties": {
                "task_id": {"type": "string"},
                "owner": {
                    "type": "string",
                    "description": (
                        "Caller's owner identifier; must match the "
                        "task's owner. Omit for default-owner-slot "
                        "tasks."
                    ),
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
                "owner": {
                    "type": "string",
                    "description": (
                        "Slice C: optional owner identifier. Multiple "
                        "agent sessions on the same machine can each "
                        "have their own active task scope as long as "
                        "each declares a distinct non-empty owner. "
                        "Omit for the default-owner slot (single-"
                        "active machine-wide task; Slice B compat)."
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
            "logged). WB27 HIGH-27-02 closure: cross-owner end is "
            "refused. Pass `owner` matching the task's owner (or "
            "omit for default-owner-slot tasks)."
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
                "owner": {
                    "type": "string",
                    "description": (
                        "Caller's owner identifier; must match the "
                        "task's owner. Omit for default-owner-slot "
                        "tasks (single-laptop case)."
                    ),
                },
            },
        },
    },
    {
        "name": "bouncer_active_task",
        "description": (
            "Return the currently-active task scope for the given "
            "owner, or null if no task is active. Auto-expires if "
            "the wall-clock expiry has passed (the returned value "
            "will be null in that case, and an audit event records "
            "the expiry). Slice C: pass `owner` to look up a "
            "specific owner's task; omit for the default-owner slot."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {
                    "type": "string",
                    "description": "Owner identifier (omit for default-owner slot).",
                },
            },
        },
    },
    {
        "name": "bouncer_active_profile",
        "description": (
            "Return which environment profile is currently active for "
            "the bouncer (the value of --profile / IAM_JIT_BOUNCER_PROFILE "
            "at proxy-start time, or 'full-user' if no profile was selected). "
            "Per [[agent-friendly-not-bypassable]]: agents can READ this "
            "but CANNOT change it — profile switching is a human/admin "
            "action requiring a proxy restart. Use this to introspect "
            "whether a hard-floor deny layer is active before recommending "
            "actions to the operator. Returns profile name + description "
            "+ counts of deny_keywords / deny_verbs / only_account_ids / "
            "allow_rules + the profile's source field (\"local\" or the "
            "URL it was installed from)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "bouncer_active_mode",
        "description": (
            "Return the bouncer's currently effective operating mode "
            "(cooperative | transparent | off) plus where the value "
            "came from (session_override | env | default). Resolution "
            "order: session-override slot set by `ibounce run --mode` "
            "(highest), then IAM_JIT_BOUNCER_MODE env var, then the "
            "lean-permissive default `cooperative`. Per [[agent-friendly-"
            "not-bypassable]] + [[bouncer-mode-selection-for-agents]]: "
            "agents READ this to decide how to phrase the next request "
            "(e.g. announce a write before issuing it in transparent "
            "mode); agents CANNOT flip it — mode changes require a "
            "proxy restart by the operator. Mirrors kbounce_active_mode "
            "per [[cross-product-agent-parity]]."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "bouncer_recommend_mode_for_task",
        "description": (
            "DETERMINISTIC (not LLM) recommendation: given a task "
            "description and/or a list of AWS actions + a targets_prod "
            "flag + an audit-only flag, return 'cooperative' or "
            "'transparent' per the [[bouncer-mode-selection-for-agents]] "
            "decision matrix. AWS-shape: actions whose service is iam / "
            "kms / secretsmanager / sts (write verbs) bias toward "
            "transparent; verbs like delete / destroy / terminate / "
            "stop / drop / modify / rm classified as writes; verbs like "
            "list / describe / get / read / show / audit classified as "
            "reads. Decision matrix (lean-permissive per [[safety-mode-"
            "lean-permissive]] — unknown/ambiguous tasks LEAN COOPERATIVE, "
            "matching kbounce): wants_audit_only=true → cooperative; "
            "targets_prod=true AND has_writes → transparent; high-risk "
            "service AND has_writes → transparent; reads-only → "
            "cooperative; ambiguous → cooperative + confidence='low'. "
            "Use BEFORE starting a task to pick the right --mode flag; "
            "the agent's own LLM should NOT second-guess this — the "
            "answer is deterministic by design so the decision is "
            "auditable. Mirrors kbounce_recommend_mode_for_task per "
            "[[cross-product-agent-parity]]."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_description": {
                    "type": "string",
                    "description": (
                        "Free-text task description (e.g. 'delete the "
                        "prod-data S3 bucket', 'list buckets in "
                        "us-east-1'). Keywords are scanned for "
                        "write/read intent + sensitive-service "
                        "mentions. Optional if `actions` is given."
                    ),
                },
                "actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "AWS actions the task will use, in "
                        "`service:Action` form (e.g. ['s3:GetObject', "
                        "'iam:DeleteRole']). Optional if "
                        "`task_description` is given."
                    ),
                },
                "targets_prod": {
                    "type": "boolean",
                    "description": (
                        "True if the task will touch prod-classified "
                        "AWS accounts / regions / resources."
                    ),
                },
                "wants_audit_only": {
                    "type": "boolean",
                    "description": (
                        "True if the task is observation-only (no "
                        "enforcement needed; forces cooperative)."
                    ),
                },
            },
        },
    },
    {
        "name": "bouncer_plan_session_summary",
        "description": (
            "Return a roll-up of one plan-capture session — counts of "
            "allows / denies / prompts / unsupported, reads vs writes, "
            "the services + would-have-called actions touched, "
            "first/last call timestamps, AND the session's #145 "
            "write-switch state (phase / write_switch_notify / "
            "first_write_at / write_decision + answered-by + "
            "pending_prompt_id if any). Plan-capture (#132) is the "
            "4th proxy mode: every intercepted SDK call is parsed + "
            "audited + returned with a synthetic SDK-shaped success — "
            "nothing forwards to AWS. Per [[ibounce-honest-positioning]] "
            "this is operator PREVIEW, not a security boundary. Pass "
            "`session_id` to look up a specific session (from `ibounce "
            "plan list`); omit to get the session the proxy is "
            "CURRENTLY writing into (or null if plan-capture isn't "
            "running in this process). Returns zero-count shape for a "
            "known session with no calls yet; returns "
            "`{\"error\": \"...\"}` for unknown session ids."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": (
                        "Plan-capture session id (e.g. "
                        "'plan-20260518T141221Z-a3b4c5'). Omit to "
                        "use the proxy's currently-active session."
                    ),
                },
            },
        },
    },
    {
        "name": "bouncer_plan_pending_write_prompt",
        "description": (
            "#145 — return the current pending plan-write prompt for "
            "a plan-capture session (if any), so an agent can "
            "introspect 'should I wait for operator approval before "
            "continuing?'. Plan-write prompts fire when the agent "
            "transitions from a sequence of READ calls to its FIRST "
            "WRITE call in a plan-capture session running under "
            "--write-switch-notify=manual (the default). The agent's "
            "write call already got a synthetic-success response back "
            "(plan-capture never forwards); the prompt is for the "
            "OPERATOR's decision about subsequent writes (approve "
            "lets them continue; reject swaps them for a typed "
            "PlanCaptureWritesRejected synthetic error). DETERMINISTIC "
            "— pure SQL query, no LLM. Returns null on `pending` field "
            "when the session has no pending plan-write prompt (i.e. "
            "the agent is still in read_only, OR the operator already "
            "answered, OR the session is using auto-approve/reject "
            "which never enqueue a prompt). Per "
            "[[ibounce-honest-positioning]] this is a deterrent UX "
            "helper for the operator; an adversarial agent could "
            "always ignore the pending prompt and call writes "
            "anyway — the synthetic-response is identical in either "
            "case."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": (
                        "Plan-capture session id. Omit to use the "
                        "proxy's currently-active session (the in-"
                        "process slot set by `ibounce serve --mode "
                        "plan-capture`)."
                    ),
                },
            },
        },
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
    {
        "name": "bouncer_audit_export_status",
        "description": (
            "#252 Slice 1 + #262 Slice 2 + #264 — return the live "
            "status of the audit-export transport (JSONL log + HTTPS "
            "webhook), the suspicious-activity alert engine, AND the "
            "heartbeat emitter. Per [[security-team-audit-export]] "
            "this is the operator-visibility surface that lets a "
            "security team confirm 'is iam-jit shipping decisions to "
            "my collector?' + 'has the alert engine fired anything?' "
            "+ 'is the bouncer still alive?' without grepping logs. "
            "Returns per-channel `configured` flag, `total_events`, "
            "`dropped_events`, `webhook_in_flight`, `last_error`, "
            "plus alert-engine fields: `alerts_enabled` (bool), "
            "`alerts_fired_count` (int; since process start), "
            "`last_alert_pattern` (str | null; the most recent rule "
            "name that fired), plus heartbeat fields: "
            "`heartbeat_enabled` (bool), `heartbeat_interval_seconds` "
            "(int), `heartbeat_last_emit_seconds_ago` (int | null), "
            "`heartbeat_gap_detected` (bool; the load-bearing field "
            "external monitoring polls to learn 'did the bouncer "
            "disappear?'). The webhook token is NEVER returned "
            "(masked as '***'). Read-only. Safe for agents to poll; "
            "no side effects."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "list_audit_webhook_presets",
        "description": (
            "#259 — return the cross-product list of audit-webhook "
            "preset shapes the bouncer speaks, each preset's auth "
            "header convention + body shape + which CLI flags it "
            "requires / accepts as optional. Per [[audit-webhook-"
            "presets]] + [[cross-product-agent-parity]]: identical "
            "JSON shape across ibounce / kbounce / dbounce so an "
            "agent that wants to ask 'which webhook shape should "
            "I configure for this operator's Datadog org?' gets a "
            "structured answer regardless of which Bounce product "
            "it's talking to. READ-ONLY; no side effects; safe for "
            "agents to poll. Returns the SAME descriptor list "
            "`ibounce audit-webhook presets list --json` emits."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "bouncer_pending_sync_prompts",
        "description": (
            "#203 — return the list of currently-WAITING sync deny-"
            "prompts (NOT all pending prompts; just the ones that "
            "have a live proxy request blocked behind them awaiting "
            "an operator answer via `ibounce prompts answer`). An "
            "agent integrated with ibounce can poll this to learn "
            "'the operator hasn't answered yet, my request is still "
            "blocked' — useful when the agent wants to surface the "
            "wait to its user, or back off + try a different path. "
            "DETERMINISTIC: SQL query of pending_prompts filtered to "
            "rows whose sync_wait_id is currently registered in the "
            "proxy's in-process wait registry, so a stale row left "
            "by a crashed proxy doesn't appear waiting forever. Per "
            "[[ibounce-honest-positioning]] this is a READ-ONLY "
            "introspection tool — agents cannot answer sync prompts "
            "via MCP (the operator answers via the CLI). Per "
            "[[agent-friendly-not-bypassable]]: there is no MCP "
            "surface that resolves a waiting prompt without operator "
            "involvement."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "bouncer_prompts_bulk_pending",
        "description": (
            "#253 — return a structured summary of the burst-of-denies "
            "state + the 5 bulk-answer options so an agent can render "
            "the prompt inline in its UI. READ-ONLY; no side effects. "
            "Returns: pending_count (int), window_seconds (int), "
            "oldest_pending_seconds_ago (int), burst_firing (bool), "
            "options (array of {key, label, kind}). DETERMINISTIC — "
            "the count is a sliding-window query of pending_prompts; "
            "no LLM, no fuzzy match. Per [[bulk-prompt-answer-ux]] + "
            "[[safety-mode-lean-permissive]]: this is the safety-valve "
            "UX for the 'wall of denies' failure mode. Per "
            "[[security-team-positioning-safety-not-surveillance]] the "
            "language is neutral (the option labels frame the burst as "
            "'your task probably needs a broader scope,' NOT as a "
            "'violation' or 'unauthorized access')."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "bouncer_prompts_bulk_answer",
        "description": (
            "#253 — apply a bulk decision over every currently-pending "
            "deny-prompt. GATED BY OPERATOR-SET TOKEN: default disabled. "
            "When `--bulk-answer-mcp-token` is unset on `ibounce run`, "
            "every call returns "
            "`{error: 'bulk-answer via MCP is disabled by default; "
            "operator must enable with --bulk-answer-mcp-token to allow "
            "agent-driven bulk-answer'}`. When enabled, the agent must "
            "echo the exact operator-set token on every call "
            "(constant-time compare; the operator shares the token "
            "out-of-band — do not store it in env vars an agent can "
            "read). This prevents an adversarial agent from bulk-"
            "allowing itself out of every pending prompt per the "
            "[[bulk-prompt-answer-ux]] 'Don't' list. "
            "\n\n"
            "Inputs: `decision` ∈ {profile, session, 3h, 10min, none} "
            "+ optional `profile` (required when decision=profile) + "
            "required `token`. `session`/`3h`/`10min` create a TIME-"
            "BOUNDED ALLOW rule (expires_at column; swept on 30s tick; "
            "row preserved in DB for audit per [[creates-never-mutates]]). "
            "`profile` hot-swaps the active profile. `none` is a no-op "
            "(but still resets the burst detector). Returns a structured "
            "summary the agent can echo to its user."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["decision", "token"],
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["profile", "session", "3h", "10min", "none"],
                    "description": (
                        "Which bulk decision to apply. `session` = 60 "
                        "min inactivity / until restart. `3h` / `10min` "
                        "= wall-clock TTL. `profile` = hot-swap active "
                        "profile (requires `profile` arg). `none` = no-op."
                    ),
                },
                "profile": {
                    "type": "string",
                    "description": (
                        "Profile name to switch to when decision=profile. "
                        "Use `bouncer_active_profile` / "
                        "`bouncer_list_presets` to discover names."
                    ),
                },
                "token": {
                    "type": "string",
                    "description": (
                        "Operator-set token from --bulk-answer-mcp-"
                        "token on `ibounce run`. Constant-time compared "
                        "against the configured value. Required; the "
                        "tool errors if missing OR mismatched OR not "
                        "enabled (default)."
                    ),
                },
            },
        },
    },
]


# Bounce-suite rename (2026-05-17): every `bouncer_*` MCP tool gets
# an `ibounce_*` alias in v1.0. Both names dispatch to the same
# handler; the `bouncer_*` originals carry a `(DEPRECATED ...)` note
# in their description so agents discover the new naming via
# `tools/list`. The aliases are appended HERE rather than typed twice
# above so additions stay in lockstep without manual upkeep. See
# `project_bounce_suite_rename` memo.
_BOUNCER_ALIAS_DEPRECATION = (
    "(DEPRECATED — use ibounce_* in v1.1) "
)
for _t in list(TOOLS):
    _name = _t.get("name", "")
    if not _name.startswith("bouncer_"):
        continue
    # Tag the legacy tool's description so agents see the deprecation
    # on every `tools/list` response.
    _t["description"] = _BOUNCER_ALIAS_DEPRECATION + _t["description"]
    # Append the ibounce_-prefixed alias with an identical input schema.
    _alias = dict(_t)
    _alias["name"] = "ibounce_" + _name[len("bouncer_"):]
    # The alias's description drops the deprecation prefix; this is
    # the canonical v1.1 name.
    _alias["description"] = _t["description"][len(_BOUNCER_ALIAS_DEPRECATION):]
    TOOLS.append(_alias)
del _t, _name, _alias


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
        "Natural-language policy synthesis scored joint sufficiency below the calibration bar "
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
    the same local audit chain. WB24 MED-24-01 closure.

    WB29 HIGH-29-02 closure: delegates to `compatibility.default_audit_sink`
    so the HTTP `submit_request` gate (#166 Slice 3) and `doctor
    compatibility` CLI (#166 Slice 4) emit identically-shaped audit
    events. Single source of truth for the sink construction."""
    from .compatibility import default_audit_sink
    return default_audit_sink()


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
    owner = args.get("owner")
    if owner is not None and not isinstance(owner, str):
        return {"error": "owner must be a string if provided"}

    try:
        scope = build_task_scope(
            description=description,
            allow_rules=allow_rules,
            deny_rules=deny_rules,
            duration_minutes=duration,
            started_by=_bouncer_actor(),
            owner=owner,
        )
    except TaskValidationError as e:
        return {"error": str(e)}

    store = BouncerStore()
    try:
        # The store's add_task atomically enforces the per-owner
        # single-active invariant (WB26 HIGH-26-02 closure +
        # Slice C per-owner extension). Catch the dedicated exception
        # so the agent gets a structured error + the active task_id
        # to act on.
        try:
            store.add_task(scope, actor=_bouncer_actor())
        except ActiveTaskExistsError as e:
            existing = store.get_active_task(owner=scope.owner)
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
        "owner": scope.owner,
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
    owner = args.get("owner")
    if owner is not None and not isinstance(owner, str):
        return {"error": "owner must be a string if provided"}

    store = BouncerStore()
    try:
        # WB27 HIGH-27-02 closure: MCP always enforces owner match.
        # Cross-owner end is refused. Single-laptop callers omit
        # owner; they can only end tasks in the default-owner slot
        # (owner IS NULL).
        try:
            ok = store.end_task(
                task_id.strip(),
                actor=_bouncer_actor(),
                end_reason=reason,
                requesting_owner=owner,
                require_owner_match=True,
            )
        except PermissionError as e:
            return {"error": f"permission denied: {e}"}
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

    owner = args.get("owner")
    if owner is not None and not isinstance(owner, str):
        return {"error": "owner must be a string if provided"}

    store = BouncerStore()
    try:
        scope = store.get_active_task(owner=owner)
    finally:
        store.close()
    if scope is None:
        return {"active": None}
    return {"active": scope.to_dict()}


def _bouncer_active_profile_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """HIGH-05 closure (claims-audit): docs claim agents can READ the
    active profile via this tool; the tool now actually exists.

    Resolves the active profile the same way `ibounce run` does:
    --profile CLI flag (not visible to MCP) → IAM_JIT_BOUNCER_PROFILE
    env var → 'full-user'. Returns the profile name + description +
    counts + source so the agent can introspect whether a hard-floor
    deny layer is active without inferring from prior failures.
    """
    from .bouncer.profiles import load_profiles, resolve_active_profile

    try:
        profiles_map = load_profiles()
        profile = resolve_active_profile(cli_flag=None, profiles=profiles_map)
    except ValueError as e:
        return {"error": f"profile resolution failed: {e}"}
    return {
        "name": profile.name,
        "description": profile.description,
        "deny_keyword_count": len(profile.deny_keywords),
        "deny_verb_count": len(profile.deny_verbs),
        "only_account_id_count": len(profile.only_account_ids),
        "allow_rule_count": len(profile.allow_rules),
        "source": profile.source,
        "keyword_targets": list(profile.keyword_targets),
        "keyword_match": profile.keyword_match,
    }


def _bouncer_plan_session_summary_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Return a roll-up of one plan-capture session.

    Resolution order for the target session_id:
      1. `args["session_id"]` (operator-supplied)
      2. `plan_capture.current_session_id()` (the in-process slot
         set by `ibounce serve --mode plan-capture`)

    Returns an `{"error": "..."}` shape (NOT a raise) on unknown
    session ids so the agent surfaces a clean error rather than a
    generic JSON-RPC -32603. Per [[agent-friendly-not-bypassable]]
    this is a READ-ONLY surface — agents inspect their own plan
    transcript but cannot modify it.
    """
    from .bouncer.plan_capture import current_session_id
    from .bouncer.store import BouncerStore

    session_id = args.get("session_id")
    if session_id is not None and not isinstance(session_id, str):
        return {"error": "session_id must be a string if provided"}
    if session_id is None:
        session_id = current_session_id()
    if not session_id:
        return {
            "error": (
                "no session_id supplied AND no plan-capture session "
                "is active in this process. Start one via "
                "`ibounce serve --mode plan-capture` or pass an "
                "explicit session_id (see `ibounce plan list`)."
            ),
        }
    store = BouncerStore()
    try:
        session = store.get_plan_session(session_id)
        if session is None:
            return {
                "error": (
                    f"no plan-capture session with id {session_id!r}; "
                    f"run `ibounce plan list` to see available ids"
                ),
            }
        # get_plan_session already merges in plan_session_summary().
        # Surface the merged shape directly — agents get one flat
        # JSON instead of nested {session: ..., summary: ...}.
        return session
    finally:
        store.close()


def _bouncer_plan_pending_write_prompt_for_mcp(
    args: dict[str, Any],
) -> dict[str, Any]:
    """#145 — return the pending plan-write prompt for a session.

    Resolution order for the target session_id matches
    `_bouncer_plan_session_summary_for_mcp`:
      1. `args["session_id"]` (operator-supplied)
      2. `plan_capture.current_session_id()` (the in-process slot set
         by `ibounce serve --mode plan-capture`)

    Return shape:
      - On success with a pending plan-write prompt:
            {"session_id": str, "phase": str, "pending": {prompt row}}
      - On success without a pending plan-write prompt:
            {"session_id": str, "phase": str, "pending": null}
      - On unresolvable session id:
            {"error": "..."}

    DETERMINISTIC: pure SQL via the store's `get_pending_plan_write_
    prompt` + `get_plan_session_phase` helpers. No LLM involvement.
    Per [[agent-friendly-not-bypassable]] this is READ-ONLY — agents
    introspect but cannot answer the prompt (the operator answers via
    `ibounce prompts answer ID --kind plan-write --decision X`).
    """
    from .bouncer.plan_capture import current_session_id
    from .bouncer.store import BouncerStore

    session_id = args.get("session_id")
    if session_id is not None and not isinstance(session_id, str):
        return {"error": "session_id must be a string if provided"}
    if session_id is None:
        session_id = current_session_id()
    if not session_id:
        return {
            "error": (
                "no session_id supplied AND no plan-capture session is "
                "active in this process. Start one via `ibounce serve "
                "--mode plan-capture` or pass an explicit session_id "
                "(see `ibounce plan list`)."
            ),
        }
    store = BouncerStore()
    try:
        phase_row = store.get_plan_session_phase(session_id)
        if phase_row is None:
            return {
                "error": (
                    f"no plan-capture session with id {session_id!r}; "
                    f"run `ibounce plan list` to see available ids"
                ),
            }
        prompt = store.get_pending_plan_write_prompt(session_id)
        return {
            "session_id": session_id,
            "phase": phase_row["phase"],
            "write_switch_notify": phase_row["write_switch_notify"],
            "first_write_at": phase_row.get("first_write_at"),
            "pending": prompt,  # null if no pending plan-write prompt
        }
    finally:
        store.close()


def _bouncer_pending_sync_prompts_for_mcp(
    args: dict[str, Any],
) -> dict[str, Any]:
    """#203 — return the currently-waiting sync deny-prompts.

    Returns a shape like:
        {"waiting": [<prompt row>, ...], "count": int}

    `waiting` is the list of pending_prompts rows whose sync_wait_id
    is currently registered in the proxy's in-process wait registry
    (i.e. the LIVE blocked requests). Rows are filtered server-side
    by `BouncerStore.list_waiting_sync_prompts(sync_wait_ids=...)` so
    a row left behind by a crashed proxy doesn't show up.

    `args` is accepted for schema parity but not consulted; the tool
    has no inputs.

    Per [[agent-friendly-not-bypassable]]: READ-ONLY. There is no
    MCP-callable way to resolve a waiting prompt — the operator
    answers via `ibounce prompts answer`.
    """
    from .bouncer.proxy import _registered_sync_wait_ids
    from .bouncer.store import BouncerStore

    _ = args  # explicitly unused
    registered = _registered_sync_wait_ids()
    store = BouncerStore()
    try:
        rows = store.list_waiting_sync_prompts(sync_wait_ids=registered)
    finally:
        store.close()
    return {"waiting": rows, "count": len(rows)}


# ---------------------------------------------------------------------------
# #253 — bulk-prompt-answer MCP tools.
#
# The READ tool (`bouncer_prompts_bulk_pending`) is unrestricted: agents
# can poll it to discover that a burst is firing + show the 5 options
# inline. Read-only; no side effects.
#
# The WRITE tool (`bouncer_prompts_bulk_answer`) is GATED BY DEFAULT.
# Without --bulk-answer-mcp-token on `ibounce run`, every call returns
# the documented disabled-error message. When the operator opts in,
# the agent must echo the token on every call (constant-time compare
# via `verify_bulk_answer_mcp_token` in burst.py).
#
# Both tools dispatch to the SAME helpers (`_apply_bulk_time_bounded`,
# `_apply_bulk_profile_switch`) that the CLI subcommand uses, so the
# behavior is identical regardless of surface.
# ---------------------------------------------------------------------------


# Mirrors the labels in bouncer_cli for cross-surface consistency.
_BULK_OPTION_LABELS = {
    "profile": "Switch profile to one with broader scope",
    "session": "Allow ALL of these (and similar) for this session",
    "3h": "Allow ALL for the next 3 hours",
    "10min": "Allow ALL for the next 10 minutes",
    "none": "Leave pending; answer individually",
}


def _bouncer_prompts_bulk_pending_for_mcp(
    args: dict[str, Any],
) -> dict[str, Any]:
    """#253 — burst summary + 5 bulk-answer options.

    Returns:
      {
        "pending_count": int,        # total currently-pending deny-prompts
        "window_seconds": int,       # burst detector window
        "oldest_pending_seconds_ago": int,
        "burst_firing": bool,        # True iff threshold has crossed
        "options": [
          {"key": "profile", "label": "...", "kind": "profile-switch"},
          {"key": "session", "label": "...", "kind": "bulk-allow-time-bounded"},
          {"key": "3h",      "label": "...", "kind": "bulk-allow-time-bounded"},
          {"key": "10min",   "label": "...", "kind": "bulk-allow-time-bounded"},
          {"key": "none",    "label": "...", "kind": "noop"},
        ],
        "language_note": "Neutral framing per security-team-positioning-...",
      }

    Per [[security-team-positioning-safety-not-surveillance]]: the
    `language_note` field is a contract reminder to agents that may be
    paraphrasing for their user — do not introduce "violation" /
    "unauthorized" / "infraction" language when echoing.
    """
    from .bouncer.burst import (
        DEFAULT_BURST_WINDOW_SECONDS,
        active_burst_detector,
    )
    from .bouncer.store import BouncerStore

    _ = args
    store = BouncerStore()
    try:
        rows = store.list_pending_prompts(
            status="pending", kind="deny-prompt", limit=500,
        )
    finally:
        store.close()
    pending_count = len(rows)
    window_seconds = DEFAULT_BURST_WINDOW_SECONDS
    burst_firing = False
    oldest_ago = 0
    detector = active_burst_detector()
    if detector is not None:
        hint = detector.pending_hint()
        if hint is not None:
            burst_firing = True
            window_seconds = int(hint["window_seconds"])
            oldest_ago = int(hint["oldest_pending_seconds_ago"])
    if not burst_firing and rows:
        # Compute oldest from DB (the detector may be in a different
        # process — e.g. the agent is calling this from a separate
        # MCP-server process than `ibounce serve`).
        import datetime as _dt
        oldest_row = rows[-1].get("created_at") or ""
        try:
            oldest_dt = _dt.datetime.strptime(
                oldest_row, "%Y-%m-%dT%H:%M:%SZ",
            ).replace(tzinfo=_dt.UTC)
            oldest_ago = max(0, int(
                (_dt.datetime.now(_dt.UTC) - oldest_dt).total_seconds()
            ))
        except Exception:
            oldest_ago = 0
    options = [
        {"key": k, "label": v, "kind": (
            "profile-switch" if k == "profile"
            else "noop" if k == "none"
            else "bulk-allow-time-bounded"
        )}
        for k, v in _BULK_OPTION_LABELS.items()
    ]
    return {
        "pending_count": pending_count,
        "window_seconds": window_seconds,
        "oldest_pending_seconds_ago": oldest_ago,
        "burst_firing": burst_firing,
        "options": options,
        "language_note": (
            "Per security-team-positioning-safety-not-surveillance: "
            "frame the burst as 'your task probably needs a broader "
            "scope,' NOT as a policy violation / unauthorized access."
        ),
    }


def _bouncer_prompts_bulk_answer_for_mcp(
    args: dict[str, Any],
) -> dict[str, Any]:
    """#253 — apply a bulk decision over all currently-pending deny-
    prompts. Gated by the operator-set MCP token.

    Returns one of:
      - {"error": "...disabled by default..."}  when no token configured
      - {"error": "invalid token"}              when configured + mismatch
      - {"error": "..."}                        on bad inputs
      - {"applied": "session"|"3h"|...,
         "rules_added": int,
         "prompts_answered": int,
         "expires_at": str (ISO),
         "profile": str (only on profile-switch)}

    Per [[bulk-prompt-answer-ux]] 'Don't' list: this is the path that
    MUST NOT let an adversarial agent bulk-allow itself. Default
    DISABLED is the load-bearing default.
    """
    from .bouncer.burst import (
        active_burst_detector,
        bulk_answer_mcp_token_configured,
        verify_bulk_answer_mcp_token,
    )
    from .bouncer.store import BouncerStore

    # Gate: operator must have set --bulk-answer-mcp-token on serve()
    if not bulk_answer_mcp_token_configured():
        return {
            "error": (
                "bulk-answer via MCP is disabled by default; operator "
                "must enable with --bulk-answer-mcp-token to allow "
                "agent-driven bulk-answer"
            ),
        }
    supplied_token = args.get("token")
    if not isinstance(supplied_token, str) or not supplied_token:
        return {"error": "missing or empty 'token' argument"}
    if not verify_bulk_answer_mcp_token(supplied_token):
        return {"error": "invalid token"}

    decision = args.get("decision")
    if not isinstance(decision, str):
        return {"error": "missing 'decision' argument"}
    decision = decision.lower().strip()
    if decision not in {"profile", "session", "3h", "10min", "none"}:
        return {
            "error": (
                f"unknown decision {decision!r}; expected one of: "
                "profile | session | 3h | 10min | none"
            ),
        }
    # Use the same actor convention as the CLI: env var override or
    # 'mcp-agent' fallback (agents don't have an OS user; mark
    # explicitly so the audit chain shows the surface).
    import os as _os
    actor = _os.environ.get("IAM_JIT_BOUNCER_ACTOR") or "mcp-agent"

    store = BouncerStore()
    try:
        pending = store.list_pending_prompts(
            status="pending", kind="deny-prompt", limit=500,
        )
        if decision == "none":
            detector = active_burst_detector()
            if detector is not None:
                detector.reset()
            return {
                "applied": "none",
                "rules_added": 0,
                "prompts_answered": 0,
                "expires_at": None,
                "pending_remaining": len(pending),
            }
        if decision == "profile":
            profile_name = args.get("profile")
            if not isinstance(profile_name, str) or not profile_name:
                return {
                    "error": (
                        "decision='profile' requires the 'profile' arg "
                        "(name of an installed profile)"
                    ),
                }
            # Defer to the same helper the CLI uses to keep behavior in
            # lockstep across surfaces.
            from .bouncer_cli import _apply_bulk_profile_switch
            try:
                profile_obj, answered = _apply_bulk_profile_switch(
                    store=store, pending_rows=pending,
                    profile_name=profile_name, actor=actor,
                )
            except ValueError as e:
                return {"error": str(e)}
            detector = active_burst_detector()
            if detector is not None:
                detector.reset()
            return {
                "applied": "profile",
                "profile": profile_obj.name,
                "rules_added": 0,
                "prompts_answered": answered,
                "expires_at": None,
            }
        # Time-bounded bulk allow.
        from .bouncer_cli import _apply_bulk_time_bounded
        rules_added, answered, expires_at = _apply_bulk_time_bounded(
            store=store, pending_rows=pending,
            duration_key=decision, actor=actor,
        )
        detector = active_burst_detector()
        if detector is not None:
            detector.reset()
        return {
            "applied": decision,
            "rules_added": rules_added,
            "prompts_answered": answered,
            "expires_at": expires_at,
        }
    finally:
        store.close()


def _bouncer_audit_export_status_for_mcp(
    args: dict[str, Any],
) -> dict[str, Any]:
    """#252 Slice 1 — return the live status of the audit-export
    channels. Reads the module-level registry on `proxy`; if no
    channel is configured, the corresponding `configured` flag is
    False + the counters are zero.

    Per [[security-team-audit-export]]: webhook token NEVER appears
    in the response — masked as '***' at the source. The masked
    URL is the only thing that surfaces.
    """
    from .bouncer.proxy import audit_export_status
    return audit_export_status()


def _list_audit_webhook_presets_for_mcp(
    args: dict[str, Any],
) -> dict[str, Any]:
    """#259 — agent-facing surface mirroring `ibounce audit-webhook
    presets list --json`. Returns the same descriptor list the CLI
    emits so an agent can discover the webhook preset shapes the
    bouncer speaks without invoking a subprocess.

    Per [[cross-product-agent-parity]]: identical JSON shape across
    ibounce / kbounce / dbounce so cross-product orchestration code
    can call the matching MCP tool on each bouncer + collate the
    results uniformly.

    Per [[scorer-is-ground-truth]]: the descriptor list is static
    (no LLM, no scoring, no runtime introspection). The MCP tool
    just shells out to the same helper the CLI uses.
    """
    from .bouncer_cli import audit_webhook_preset_descriptors
    return {"presets": audit_webhook_preset_descriptors()}


def _bouncer_active_mode_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Return the bouncer's currently effective mode + provenance.

    Thin wrapper over `bouncer.proxy.resolve_active_mode`. Mirrors
    kbounce_active_mode's shape per [[cross-product-agent-parity]];
    the AWS-side deviation from the K8s shape is that we surface
    `source` (session_override | env | default) so agents can tell a
    user-pinned mode from a fall-through default — the K8s proxy
    binds mode at process start so it doesn't need the provenance.
    Per [[agent-friendly-not-bypassable]] this is a READ surface; the
    args dict is accepted for schema parity but ignored.
    """
    from .bouncer.proxy import resolve_active_mode

    return resolve_active_mode()


# Keywords that classify a task as performing WRITES against AWS.
# Used by `_bouncer_recommend_mode_for_task_for_mcp`. Mirrors
# kbounce's containsWriteVerb shape but AWS-shaped (verbs that
# appear in iam-jit's blacklist + the AWS-managed-policy denylist
# patterns). All lower-case; matching is case-insensitive substring.
_WRITE_KEYWORDS: tuple[str, ...] = (
    "create", "delete", "destroy", "terminate", "stop", "drop",
    "modify", "update", "put", "remove", "detach", "attach",
    "rotate", "revoke", "disable", "disassociate", "deregister",
    "patch", "rm",
)

# Read-only / observation keywords. Used to detect EXPLICIT read
# intent in a task description (so we can flag "ambiguous" when
# neither write nor read keywords appear).
_READ_KEYWORDS: tuple[str, ...] = (
    "list", "describe", "get", "read", "show", "audit", "view",
    "inspect", "check", "find", "search", "head",
)

# Service prefixes that bias toward transparent mode when paired
# with WRITE keywords/actions. These are the AWS services where a
# bad write blast-radius is high: IAM (escalation), KMS (key
# destruction), Secrets Manager (credential exposure), STS (session
# escalation). Per [[scorer-is-ground-truth]] this list mirrors the
# scorer's high-risk-service set; do not add services here without
# adding them there.
_HIGH_RISK_SERVICES: tuple[str, ...] = (
    "iam", "kms", "secretsmanager", "sts",
)


def _bouncer_recommend_mode_for_task_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """DETERMINISTIC mode recommendation for a task.

    AWS-shape of kbounce_recommend_mode_for_task. Inputs:
      task_description  free-text description; keyword-scanned
      actions           list of `service:Action` strings
      targets_prod      bool — prod-classified AWS account/region
      wants_audit_only  bool — observation-only declared

    Decision matrix (mirrors kbounce; fail-safe direction =
    COOPERATIVE per [[safety-mode-lean-permissive]]):
      wants_audit_only=true                          -> cooperative
      targets_prod=true AND has_writes               -> transparent
      high_risk_service AND has_writes               -> transparent
      has_writes only (non-prod, low-risk service)   -> cooperative
      reads_only on any env                          -> cooperative
      ambiguous (no signal either way)               -> cooperative
                                                        (confidence=low)

    Returns: {mode, reason, deterministic, confidence}.
    `deterministic: true` is a load-bearing signal that no LLM was
    consulted; callers can rely on the decision being reproducible.
    """
    description = args.get("task_description") or ""
    if not isinstance(description, str):
        return {"error": "task_description must be a string if provided"}

    actions_raw = args.get("actions") or []
    if not isinstance(actions_raw, list):
        return {"error": "actions must be a list if provided"}
    actions = [a for a in actions_raw if isinstance(a, str) and a.strip()]

    targets_prod = bool(args.get("targets_prod"))
    wants_audit_only = bool(args.get("wants_audit_only"))

    desc_lower = description.lower()
    has_write_keyword = any(kw in desc_lower for kw in _WRITE_KEYWORDS)
    has_read_keyword = any(kw in desc_lower for kw in _READ_KEYWORDS)

    # Action-level classification: an explicit AWS action whose name
    # part doesn't start with Get/List/Describe is a write.
    action_writes = False
    action_high_risk = False
    for a in actions:
        svc, _, op = a.partition(":")
        svc_l = svc.strip().lower()
        op_l = op.strip().lower()
        # Empty op (e.g. "s3:") -> can't classify; skip.
        if not op_l:
            continue
        is_read_op = (
            op_l.startswith("get")
            or op_l.startswith("list")
            or op_l.startswith("describe")
            or op_l.startswith("head")
            or op_l.startswith("batchget")
        )
        if not is_read_op:
            action_writes = True
            if svc_l in _HIGH_RISK_SERVICES:
                action_high_risk = True

    # Description-level high-risk service mention (only counts when
    # paired with a write keyword; "list iam roles" stays a read).
    desc_high_risk = (
        has_write_keyword
        and any(svc in desc_lower for svc in _HIGH_RISK_SERVICES)
    )

    has_writes = has_write_keyword or action_writes
    high_risk = action_high_risk or desc_high_risk

    # Ambiguity: caller gave us nothing classifiable (no actions, no
    # description keywords either way). Honor lean-permissive default
    # but surface confidence=low so the caller knows to ask the user.
    nothing_classifiable = (
        not actions
        and not has_write_keyword
        and not has_read_keyword
        and not description.strip()
    )

    confidence = "high"
    if wants_audit_only:
        mode = "cooperative"
        reason = (
            "cooperative mode: audit-only declared "
            "(wants_audit_only=true)"
        )
    elif targets_prod and has_writes:
        mode = "transparent"
        reason = (
            "transparent mode: prod-targeting write task "
            "(targets_prod=true AND task includes write actions)"
        )
    elif high_risk and has_writes:
        mode = "transparent"
        reason = (
            "transparent mode: write task touches a high-risk AWS "
            "service (iam / kms / secretsmanager / sts); "
            "enforcement recommended"
        )
    elif has_writes:
        mode = "cooperative"
        reason = (
            "cooperative mode: non-prod writes on low-risk services; "
            "lean-permissive with audit + admin-pause available"
        )
    elif has_read_keyword or actions:
        mode = "cooperative"
        reason = "cooperative mode: reads-only; no enforcement needed"
    else:
        mode = "cooperative"
        confidence = "low"
        reason = (
            "cooperative mode: task shape unclassifiable "
            "(no actions + no recognized keywords); lean-permissive "
            "default per safety-mode-lean-permissive"
        )

    if nothing_classifiable:
        # Even if a keyword matched coincidentally above, an empty
        # input shape MUST surface as low confidence.
        confidence = "low"

    return {
        "mode": mode,
        "reason": reason,
        "deterministic": True,
        "confidence": confidence,
    }


def _scope_self_for_task_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Slice E composer. Validates input + delegates to
    bouncer.self_scoping.scope_self_for_task; returns the unified
    SelfScopeResult dict."""
    from .bouncer.self_scoping import scope_self_for_task

    description = args.get("description")
    if not isinstance(description, str) or not description.strip():
        return {"error": "description is required and must be a non-empty string"}

    allow_rules = args.get("allow_rules")
    if not isinstance(allow_rules, list) or not allow_rules:
        return {"error": "allow_rules is required and must be a non-empty list"}
    for r in allow_rules:
        if not isinstance(r, dict) or not r.get("pattern"):
            return {"error": "allow_rules items must be dicts with a 'pattern' field"}

    deny_rules = args.get("deny_rules")
    if deny_rules is not None and not isinstance(deny_rules, list):
        return {"error": "deny_rules must be a list if provided"}

    duration = args.get("duration_minutes", 30)
    if not isinstance(duration, int) or isinstance(duration, bool):
        return {"error": "duration_minutes must be an integer"}

    for field in ("workload", "target_account_id", "owner"):
        val = args.get(field)
        if val is not None and not isinstance(val, str):
            return {"error": f"{field} must be a string if provided"}

    target_services = args.get("target_services")
    if target_services is not None and not isinstance(target_services, list):
        return {"error": "target_services must be a list if provided"}

    submit_jit_role = args.get("submit_jit_role", True)
    if not isinstance(submit_jit_role, bool):
        return {"error": "submit_jit_role must be a boolean if provided"}

    result = scope_self_for_task(
        description=description,
        allow_rules=allow_rules,
        deny_rules=deny_rules,
        duration_minutes=duration,
        workload=args.get("workload"),
        target_account_id=args.get("target_account_id"),
        target_services=target_services,
        owner=args.get("owner"),
        submit_jit_role=submit_jit_role,
        actor=_bouncer_actor(),
    )
    return result.to_dict()


def _effective_scope_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Read-only snapshot of bouncer's current effective scope."""
    from .bouncer.self_scoping import get_effective_scope

    owner = args.get("owner")
    if owner is not None and not isinstance(owner, str):
        return {"error": "owner must be a string if provided"}
    return get_effective_scope(owner=owner).to_dict()


def _bouncer_recommend_rules_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Slice D rule recommender — synthesize a draft ruleset from
    observed decisions in the audit log."""
    from .bouncer.recommender import (
        filter_decisions_by_window,
        summarize_window,
        synthesize_rules,
    )
    from .bouncer.store import BouncerStore

    since = args.get("since")
    until = args.get("until")
    if since is not None and not isinstance(since, str):
        return {"error": "since must be a string (ISO-8601) if provided"}
    if until is not None and not isinstance(until, str):
        return {"error": "until must be a string (ISO-8601) if provided"}

    min_support = args.get("min_support", 3)
    if not isinstance(min_support, int) or isinstance(min_support, bool) or min_support < 1:
        return {"error": "min_support must be a positive integer"}

    limit = args.get("limit", 10000)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return {"error": "limit must be a positive integer"}
    limit = min(limit, 10000)

    # WB28 MED-28-05 closure: agents/admins can opt in to rolling
    # task-scoped (Slice C) decisions into recommendations, but the
    # default is to exclude them so one-off task traffic doesn't
    # become a permanent global rule.
    include_task_scoped = args.get("include_task_scoped", False)
    if not isinstance(include_task_scoped, bool):
        return {"error": "include_task_scoped must be a boolean if provided"}

    store = BouncerStore()
    try:
        all_decisions = store.list_decisions(limit=limit)
    finally:
        store.close()
    # WB28 LOW-28-04 closure: semantic datetime compare.
    decisions = filter_decisions_by_window(
        all_decisions, since=since, until=until
    )
    summary = summarize_window(decisions)
    recs = synthesize_rules(
        decisions,
        min_support=min_support,
        include_task_scoped=include_task_scoped,
    )
    return {
        "summary": summary,
        "recommendations": [r.to_dict() for r in recs],
        "count": len(recs),
    }


def _bouncer_apply_recommendation_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Apply a subset of recommended rules. Each addition goes through
    the normal audit-logged add_rule path; plus a `recommendation_applied`
    config event records the batch."""
    from .bouncer.rules import Effect, ProxyRule
    from .bouncer.store import BouncerStore, InvalidRuleError

    rules_arg = args.get("rules")
    if not isinstance(rules_arg, list) or not rules_arg:
        return {"error": "rules is required and must be a non-empty list"}

    actor = _bouncer_actor()
    added_rule_ids: list[int] = []
    rejected: list[dict[str, Any]] = []
    store = BouncerStore()
    try:
        for entry in rules_arg:
            if not isinstance(entry, dict):
                rejected.append({"entry": entry, "error": "not a dict"})
                continue
            pattern = entry.get("pattern")
            if not isinstance(pattern, str) or not pattern.strip():
                rejected.append({"entry": entry, "error": "pattern required"})
                continue
            effect_str = entry.get("effect", "allow")
            if effect_str not in ("allow", "deny"):
                rejected.append({"entry": entry, "error": "effect must be allow|deny"})
                continue
            # WB28 HIGH-28-02 closure: validate the pass-through fields
            # before constructing ProxyRule. Without this, an agent
            # passing arn_scope={"nested": "object"} crashes SQLite
            # at insert time mid-batch — and the partial batch loses
            # its audit-event tag because the loop never reaches the
            # batch-event line.
            bad_field = None
            for field in ("arn_scope", "region_scope", "note"):
                val = entry.get(field)
                if val is not None and not isinstance(val, str):
                    bad_field = field
                    break
            if bad_field is not None:
                rejected.append({
                    "entry": entry,
                    "error": f"{bad_field} must be a string if provided",
                })
                continue
            rule = ProxyRule(
                pattern=pattern,
                effect=Effect(effect_str),
                arn_scope=entry.get("arn_scope"),
                region_scope=entry.get("region_scope"),
                note=entry.get("note") or "applied from bouncer recommendation",
                origin="recommendation",
            )
            # WB28 MED-28-02 closure: skip exact duplicates so
            # repeated `bouncer_apply_recommendation` calls don't
            # accumulate identical rule rows over time.
            if store.rule_exists(rule):
                rejected.append({"entry": entry, "error": "rule already exists"})
                continue
            try:
                rid = store.add_rule(rule, actor=actor)
                added_rule_ids.append(rid)
            except InvalidRuleError as e:
                rejected.append({"entry": entry, "error": str(e)})
        # WB28 MED-28-03 closure: top-level batch event now records
        # the specific rule_ids in the batch + the rejected entries,
        # so post-hoc review can correlate the batch with its rows
        # without timestamp guessing.
        store._record_config_event_locked(
            actor=actor,
            kind="recommendation_applied",
            summary=f"applied {len(added_rule_ids)} recommended rule(s) via MCP",
            detail={
                "count": len(added_rule_ids),
                "rule_ids": added_rule_ids,
                "rejected_count": len(rejected),
                "rejected": rejected,
            },
        )
    finally:
        store.close()
    return {
        "applied": len(added_rule_ids),
        "applied_rule_ids": added_rule_ids,
        "rejected": rejected,
        "audit_event_kind": "recommendation_applied",
    }


def _bouncer_task_review_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """Slice C per-task review summary. WB27 HIGH-27-02 closure:
    enforces owner-match so an agent can't review another agent's
    task by passing its task_id."""
    from .bouncer.store import BouncerStore

    task_id = args.get("task_id")
    if not isinstance(task_id, str) or not task_id.strip():
        return {"error": "task_id is required and must be a non-empty string"}
    owner = args.get("owner")
    if owner is not None and not isinstance(owner, str):
        return {"error": "owner must be a string if provided"}

    store = BouncerStore()
    try:
        try:
            summary = store.task_review_summary(
                task_id.strip(),
                requesting_owner=owner,
                require_owner_match=True,
            )
        except PermissionError as e:
            return {"error": f"permission denied: {e}"}
    finally:
        store.close()
    if not summary:
        return {"error": f"no task with id {task_id!r}"}
    return summary


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
        # #266 — capture clientInfo + mint an agent session ID per
        # [[agent-identity-in-audit]]. The MCP spec carries
        # `clientInfo: {name, version}` in initialize params; we
        # bind it to a fresh UUID-v7 session so every subsequent
        # OCSF audit event from this stdio process carries the
        # same session_id. Fail-soft: a bug in agent_context never
        # breaks the MCP handshake.
        try:
            from .bouncer.audit_export.agent_context import begin_mcp_session
            begin_mcp_session(params.get("clientInfo"))
        except Exception:
            pass
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
        # Bounce-suite rename (2026-05-17): `ibounce_*` is the canonical
        # name; `bouncer_*` still works in v1.0 + dispatches to the same
        # handler (see TOOLS-alias-loop above). Normalize here so each
        # handler only knows its `bouncer_*` lookup string.
        if isinstance(tool_name, str) and tool_name.startswith("ibounce_"):
            tool_name = "bouncer_" + tool_name[len("ibounce_"):]
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
        elif tool_name == "bouncer_active_profile":
            result_payload = _bouncer_active_profile_for_mcp(args)
        elif tool_name == "bouncer_active_mode":
            result_payload = _bouncer_active_mode_for_mcp(args)
        elif tool_name == "bouncer_plan_session_summary":
            result_payload = _bouncer_plan_session_summary_for_mcp(args)
        elif tool_name == "bouncer_plan_pending_write_prompt":
            result_payload = _bouncer_plan_pending_write_prompt_for_mcp(args)
        elif tool_name == "bouncer_audit_export_status":
            result_payload = _bouncer_audit_export_status_for_mcp(args)
        elif tool_name == "list_audit_webhook_presets":
            result_payload = _list_audit_webhook_presets_for_mcp(args)
        elif tool_name == "bouncer_pending_sync_prompts":
            result_payload = _bouncer_pending_sync_prompts_for_mcp(args)
        elif tool_name == "bouncer_prompts_bulk_pending":
            result_payload = _bouncer_prompts_bulk_pending_for_mcp(args)
        elif tool_name == "bouncer_prompts_bulk_answer":
            result_payload = _bouncer_prompts_bulk_answer_for_mcp(args)
        elif tool_name == "bouncer_recommend_mode_for_task":
            result_payload = _bouncer_recommend_mode_for_task_for_mcp(args)
        elif tool_name == "bouncer_task_review":
            result_payload = _bouncer_task_review_for_mcp(args)
        elif tool_name == "bouncer_recommend_rules":
            result_payload = _bouncer_recommend_rules_for_mcp(args)
        elif tool_name == "bouncer_apply_recommendation":
            result_payload = _bouncer_apply_recommendation_for_mcp(args)
        elif tool_name == "iam_jit_scope_self_for_task":
            result_payload = _scope_self_for_task_for_mcp(args)
        elif tool_name == "bouncer_effective_scope":
            result_payload = _effective_scope_for_mcp(args)
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


def _emit_session_ended_on_close() -> None:
    """#266 — when the MCP stdio loop exits (EOF on stdin = agent
    disconnect), retire the active agent session and emit a
    SESSION_ENDED OCSF event to whatever audit-export channels are
    configured. Fail-soft: a missing audit channel / unconfigured
    log writer must not raise out of the server's exit path.

    The event is bookend-only — it carries the session_id that was
    active so a SIEM filter on
    `unmapped.iam_jit.agent.session_id == "..."`
    sees a clean open->close pair. Per [[security-team-positioning-
    safety-not-surveillance]] severity is Informational; this isn't
    an alert, it's a forensic marker.
    """
    try:
        from .bouncer.audit_export.agent_context import (
            end_mcp_session,
            session_ended_event,
        )
        from .bouncer.proxy import _emit_audit_event
    except Exception:
        return
    try:
        prior = end_mcp_session()
    except Exception:
        return
    if prior is None:
        return
    try:
        _emit_audit_event(session_ended_event(prior))
    except Exception:
        # Audit-export channel may not be configured (common — the
        # MCP server runs everywhere, audit-export is opt-in).
        return


def main() -> int:
    """Read JSON-RPC requests from stdin; write responses to stdout.

    One request per line. The MCP stdio transport spec uses
    line-delimited JSON (no Content-Length headers). Errors during
    request processing are returned as JSON-RPC error responses, not
    raised — the MCP host expects the server to stay alive.

    On EOF (client disconnect) or KeyboardInterrupt we emit a #266
    SESSION_ENDED event so audit consumers see a clean session bookend.
    """
    try:
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
    finally:
        _emit_session_ended_on_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
