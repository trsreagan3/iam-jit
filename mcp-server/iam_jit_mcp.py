"""iam-jit MCP server.

Exposes the iam-jit HTTP API as Model Context Protocol tools so agents
(Claude Code, Cursor, Continue, custom clients) can call iam-jit natively
in their tool palette.

Configuration via environment variables:
  IAM_JIT_BASE_URL    Base URL of the iam-jit deployment, e.g. https://iam-jit.your-org.com
  IAM_JIT_API_TOKEN   Bearer token minted in the iam-jit UI (Tokens page)

Run as the MCP server in Claude Desktop / Cursor / etc.:
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
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("iam-jit")


# ---- HTTP client (lazy, env-driven) ----


def _client() -> httpx.Client:
    base = os.environ.get("IAM_JIT_BASE_URL")
    token = os.environ.get("IAM_JIT_API_TOKEN")
    if not base:
        raise RuntimeError(
            "IAM_JIT_BASE_URL is not set. Configure it in your MCP server env "
            "(e.g., the `env` block in claude_desktop_config.json)."
        )
    if not token:
        raise RuntimeError(
            "IAM_JIT_API_TOKEN is not set. Mint one in the iam-jit web UI under "
            "Tokens, then put it in your MCP server env."
        )
    return httpx.Client(
        base_url=base.rstrip("/"),
        headers={"Authorization": f"Bearer {token}"},
        timeout=30.0,
    )


def _post(path: str, json_body: dict[str, Any]) -> dict[str, Any]:
    with _client() as c:
        r = c.post(path, json=json_body)
        _raise_for_status(r)
        return _json(r)


def _get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    with _client() as c:
        r = c.get(path, params=params or None)
        _raise_for_status(r)
        return _json(r)


def _patch(path: str, json_body: dict[str, Any]) -> dict[str, Any]:
    with _client() as c:
        r = c.patch(path, json=json_body)
        _raise_for_status(r)
        return _json(r)


def _delete(path: str) -> dict[str, Any]:
    with _client() as c:
        r = c.delete(path)
        _raise_for_status(r)
        return _json(r)


def _raise_for_status(r: httpx.Response) -> None:
    if r.is_success:
        return
    detail: Any
    try:
        detail = r.json()
    except Exception:
        detail = r.text
    raise RuntimeError(f"iam-jit API error {r.status_code}: {detail}")


def _json(r: httpx.Response) -> dict[str, Any]:
    if not r.content:
        return {}
    try:
        return r.json()
    except Exception:
        return {"raw": r.text}


# ============================================================
# Requester-side tools
# ============================================================


@mcp.tool()
def submit_role_request(
    description: str,
    accounts: list[str],
    duration_hours: int = 24,
    access_type: str = "read-only",
    services: list[str] | None = None,
    policy: dict[str, Any] | None = None,
    provisioning_mode: str = "identity_center",
    assume_principal_arn: str | None = None,
    assume_session_name: str | None = None,
    ticket: str | None = None,
) -> dict[str, Any]:
    """Submit a new iam-jit role request for approval.

    Use either `services` (we draft the policy from CRUD action levels) OR
    `policy` (you've already drafted one — recommended when you've used a
    local agent with full codebase/cluster context to derive a tight policy).

    The server runs validation, narrowing detection, and risk review (when
    AI is enabled in the deployment) before queueing for approval.

    Args:
      description: Plain-English explanation of what the role is for.
      accounts: 12-digit AWS account IDs to provision into.
      duration_hours: How long the grant should last (default 24).
      access_type: `read-only` (default; faster to approve) or `read-write`.
      services: Optional list of AWS service prefixes (e.g. ['s3', 'eks']).
      policy: Optional pre-built IAM policy as a dict (Version, Statement).
      provisioning_mode: `identity_center` (default) or `classic_iam`.
      assume_principal_arn: IAM user/role ARN that will assume the role
        once provisioned. Locks the trust policy to this principal. If
        omitted, falls back to the principal inferred from your iam-jit
        login (only available in aws_iam auth mode). Set this explicitly
        when the role will be assumed from a different identity than the
        one submitting (e.g. a CI runner role).
      assume_session_name: Optional session name to record in the assume
        snippet. Default: `iam-jit-{request-id}`.
      ticket: Change/incident/access ticket URL authorizing this request.
        Required if the deployment sets IAM_JIT_REQUIRE_TICKET=1; iam-jit
        validates URL format only (it does not call out to the tracker).

    Returns the full request including its `id`, the risk review (when
    AI is enabled), and any narrowing questions that fired. After approval
    + provisioning, call `get_assume_instructions(request_id)` for the
    copy-paste assume-role snippet.
    """
    payload: dict[str, Any] = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "agent", "email": "agent@local"}},
        "spec": {
            "description": description,
            "access_type": access_type,
            "accounts": [{"account_id": a} for a in accounts],
            "duration": {"duration_hours": duration_hours},
            "provisioning": {"mode": provisioning_mode},
        },
    }
    if services:
        payload["spec"]["task_intent"] = {
            "services": services,
            "actions": ["read", "list"] if access_type == "read-only" else ["read", "list", "write"],
        }
    if policy is not None:
        payload["spec"]["policy"] = policy
    if assume_principal_arn or assume_session_name:
        assume_by: dict[str, Any] = {}
        if assume_principal_arn:
            assume_by["principal_arn"] = assume_principal_arn
        if assume_session_name:
            assume_by["session_name"] = assume_session_name
        payload["spec"]["assume_by"] = assume_by
    if ticket:
        payload["spec"]["ticket"] = ticket
    return _post("/api/v1/requests", payload)


@mcp.tool()
def check_request_status(request_id: str) -> dict[str, Any]:
    """Get the current status of a submitted iam-jit request.

    Returns the full request including its current state (`pending`,
    `provisioning`, `active`, `expired`, `rejected`, `cancelled`,
    `needs_changes`), comment thread, history, and risk review.
    """
    return _get(f"/api/v1/requests/{request_id}")


@mcp.tool()
def respond_to_changes(
    request_id: str,
    new_policy: dict[str, Any] | None = None,
    new_description: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    """Respond to an approver's `request_changes` by editing your request.

    The new policy and/or description replace the existing fields; the
    server re-runs review and bumps the request back to `pending`.

    Use this when the approver has commented with suggestions like "scope
    to a specific bucket" or "remove iam:* — too broad."
    """
    spec_patch: dict[str, Any] = {}
    if new_policy is not None:
        spec_patch["policy"] = new_policy
    if new_description is not None:
        spec_patch["description"] = new_description
    out = _patch(f"/api/v1/requests/{request_id}", {"spec": spec_patch})
    if comment:
        _post(f"/api/v1/requests/{request_id}/comments", {"message": comment})
    return out


@mcp.tool()
def cancel_request(request_id: str) -> dict[str, Any]:
    """Cancel one of YOUR OWN pending requests.

    Owner-only — you can't cancel someone else's request. Allowed only
    while the request is in `pending` or `needs_changes` state.
    """
    return _post(f"/api/v1/requests/{request_id}/cancel", {})


# ============================================================
# Approver-side tools
# ============================================================


@mcp.tool()
def list_pending_requests(state: str = "pending", limit: int = 50) -> dict[str, Any]:
    """List iam-jit requests waiting on action.

    Default returns all pending requests visible to you. Approvers see
    every request; requesters see only their own. Use `state=all` to
    include non-pending states.

    Returns a list of summaries: request_id, owner, risk score (when AI
    is enabled), state, age, description preview.
    """
    params: dict[str, Any] = {}
    if state and state != "all":
        params["state"] = state
    out = _get("/api/v1/requests", params)
    items = out.get("requests") or []
    return {"requests": items[:limit], "count": len(items[:limit]), "total_visible": out.get("count", len(items))}


@mcp.tool()
def get_request(request_id: str) -> dict[str, Any]:
    """Read the full iam-jit request including policy, comments, history,
    and risk review.

    Use this before approving or commenting so the agent (and the human
    behind it) sees the full context, not just the summary.
    """
    return _get(f"/api/v1/requests/{request_id}")


@mcp.tool()
def comment_on_request(
    request_id: str,
    message: str,
    suggested_constraints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Post a comment on an iam-jit request.

    Anyone who can view the request can comment. Use to ask the requester
    for clarification or to suggest narrowing. Optionally attach
    `suggested_constraints` — a list of {service, arn_patterns} pairs —
    that the requester can apply.
    """
    body: dict[str, Any] = {"message": message}
    if suggested_constraints:
        body["suggested_constraints"] = suggested_constraints
    return _post(f"/api/v1/requests/{request_id}/comments", body)


@mcp.tool()
def approve_request(request_id: str, comment: str | None = None) -> dict[str, Any]:
    """Approve a pending iam-jit request, transitioning it to provisioning.

    Approver- or admin-only. Self-approval is forbidden — you can't
    approve a request you submitted, even as an admin.
    """
    body: dict[str, Any] = {}
    if comment:
        body["comment"] = comment
    return _post(f"/api/v1/requests/{request_id}/approve", body)


@mcp.tool()
def reject_request(request_id: str, reason: str) -> dict[str, Any]:
    """Reject a pending iam-jit request.

    Approver- or admin-only. The reason is recorded in the request's
    history and visible to the requester.
    """
    return _post(f"/api/v1/requests/{request_id}/reject", {"reason": reason})


@mcp.tool()
def request_changes(
    request_id: str,
    suggestions: list[str],
    comment: str | None = None,
) -> dict[str, Any]:
    """Send a pending iam-jit request back to the requester with feedback.

    Approver-only. The request transitions to `needs_changes`; the
    requester edits and resubmits. Use this when the policy is close but
    needs scoping, the description is unclear, or the duration is too long.
    """
    body: dict[str, Any] = {"suggestions": suggestions}
    if comment:
        body["comment"] = comment
    return _post(f"/api/v1/requests/{request_id}/request-changes", body)


# ============================================================
# Shared utility
# ============================================================


@mcp.tool()
def download_request(request_id: str, mode: str = "template") -> dict[str, Any]:
    """Get a request as a re-submittable template (or full record).

    `mode='template'` (default): the parts useful for re-submission —
    description, intent, accounts, duration, policy. Strips the server-set
    id, status, history, comments, and review.

    `mode='full'`: the entire stored record including status block.

    Use this when an agent wants to save the exact request it submitted
    so a later session can repeat it (or adapt it) without re-deriving the
    policy. Pair with `submit_role_request(policy=<saved template's policy>)`
    to repeat verbatim.
    """
    return _get(f"/api/v1/requests/{request_id}/download", params={"as": "json", "mode": mode})


@mcp.tool()
def preview_account_onboarding(
    account_id: str,
    region: str = "us-east-1",
    account_alias: str | None = None,
    enable_discovery: bool = True,
    provisioning_mode: str = "classic_iam",
    provisioner_role_name: str = "iam-jit-provisioner",
    discovery_role_name: str = "iam-jit-discovery",
    hub_account_id: str | None = None,
    allowed_permission_set_arns: list[str] | None = None,
) -> dict[str, Any]:
    """Get the artifact set needed to add a new AWS account to iam-jit.

    iam-jit cannot bootstrap roles into a destination account itself —
    that would require pre-existing privileged access there, which is the
    chicken-and-egg this tool exists to solve. This call returns
    everything an agent or human needs to do the bootstrap themselves:

      - `artifacts.cloudformation_template`: CFN to deploy in the
        destination account (run with `aws cloudformation deploy`)
      - `artifacts.terraform_module`: equivalent Terraform skeleton
      - `artifacts.cli_commands`: copy-paste shell commands
      - `expected.*`: role ARNs and ExternalIds the deploy will produce
      - `after_deploy.register_payload` and `after_deploy.register_curl`:
        what to send back to iam-jit so it starts treating this account
        as a valid destination

    The returned commands are intentionally agnostic about how you source
    AWS credentials — env vars, named profiles, SSO, OIDC, instance role,
    container creds, aws-vault, etc. all work. Just make sure the
    calling identity has CloudFormation + IAM CreateRole privileges in
    the destination account.

    Args:
      account_id: 12-digit destination AWS account ID.
      region: Region to deploy the stack in (the IAM roles are global).
      account_alias: Optional human-friendly alias for stack naming.
      enable_discovery: Create the read-only DiscoveryRole. Set False to
        opt out of letting iam-jit read account contents for narrowing.
      provisioning_mode: 'classic_iam' (default), 'identity_center', or 'both'.
      provisioner_role_name: Override the ProvisionerRole name.
      discovery_role_name: Override the DiscoveryRole name.
      hub_account_id: Account where the iam-jit Lambda runs. Defaults to
        IAM_JIT_HUB_ACCOUNT_ID on the server.
      allowed_permission_set_arns: For identity_center mode, the SSO
        permission sets iam-jit may assign.
    """
    payload: dict[str, Any] = {
        "account_id": account_id,
        "region": region,
        "enable_discovery": enable_discovery,
        "provisioning_mode": provisioning_mode,
        "provisioner_role_name": provisioner_role_name,
        "discovery_role_name": discovery_role_name,
    }
    if account_alias:
        payload["account_alias"] = account_alias
    if hub_account_id:
        payload["hub_account_id"] = hub_account_id
    if allowed_permission_set_arns:
        payload["allowed_permission_set_arns"] = allowed_permission_set_arns
    return _post("/api/v1/accounts/onboarding/preview", payload)


@mcp.tool()
def continue_intake_conversation(
    conversation: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Drive the conversational intake one turn at a time.

    Pass the running conversation history (each item is
    {"role": "user"|"assistant", "content": "..."}). Returns:

      - `ask`: the next question to put to the user, or null if complete
      - `fields`: every gathered field so far (account_id, region,
        services, access_type, duration_hours, description, resources, ...)
      - `complete`: when true, you have everything and can submit
      - `draft_policy`: least-privilege IAM policy suggested by the model
        (only when complete)
      - `prefill`: a dict matching `submit_role_request`'s args, ready to
        hand off

    Use this when the user describes what they need in natural language
    and you want iam-jit to gather the missing details (account, region,
    bucket names, etc.) before drafting a policy. For policies you've
    already written, call `submit_role_request` directly.
    """
    body: dict[str, Any] = {"conversation": conversation or []}
    return _post("/api/v1/intake/turn", body)


@mcp.tool()
def register_account(
    account_id: str,
    provisioner_role_arn: str,
    provisioner_external_id: str,
    provisioning_mode: str = "classic_iam",
    alias: str | None = None,
    regions: list[str] | None = None,
    discovery_role_arn: str | None = None,
    discovery_external_id: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Register a destination AWS account with iam-jit (admin-only).

    Call this AFTER deploying the CloudFormation stack from
    `preview_account_onboarding`. The role ARNs and ExternalIds must
    match the stack outputs — iam-jit does not call AWS to verify them.

    Args:
      account_id: 12-digit AWS account ID.
      provisioner_role_arn: ARN of the ProvisionerRole created by the stack.
      provisioner_external_id: ExternalId in the ProvisionerRole's trust policy.
      provisioning_mode: 'classic_iam', 'identity_center', or 'both'.
      alias: Optional human-friendly alias.
      regions: Regions iam-jit should consider in scope for this account.
      discovery_role_arn: ARN of the DiscoveryRole, if discovery is enabled.
      discovery_external_id: Matching ExternalId for the discovery role.
      notes: Optional free-text notes.
    """
    payload: dict[str, Any] = {
        "account_id": account_id,
        "provisioner_role_arn": provisioner_role_arn,
        "provisioner_external_id": provisioner_external_id,
        "provisioning_mode": provisioning_mode,
    }
    if alias:
        payload["alias"] = alias
    if regions:
        payload["regions"] = regions
    if discovery_role_arn:
        payload["discovery_role_arn"] = discovery_role_arn
    if discovery_external_id:
        payload["discovery_external_id"] = discovery_external_id
    if notes:
        payload["notes"] = notes
    return _post("/api/v1/accounts", payload)


@mcp.tool()
def list_accounts(include_disabled: bool = False) -> dict[str, Any]:
    """List the destination AWS accounts iam-jit is registered to provision into."""
    return _get("/api/v1/accounts", params={"include_disabled": str(include_disabled).lower()})


@mcp.tool()
def deregister_account(account_id: str) -> dict[str, Any]:
    """Stop iam-jit from treating an account as a valid provisioning target.

    Does NOT delete the IAM roles in the destination account — the same
    agent/human who deployed the CloudFormation stack must delete it
    separately. Deregistering here just removes the account from iam-jit's
    registry.
    """
    return _delete(f"/api/v1/accounts/{account_id}")


@mcp.tool()
def get_assume_instructions(request_id: str) -> dict[str, Any]:
    """Get the AWS CLI assume-role snippet for a provisioned request.

    Returns the role ARN, the assumer principal (the identity locked into
    the trust policy), an `aws sts assume-role` one-liner, and an
    `~/.aws/config` profile block — everything an agent or human needs to
    actually use the role once it's active.

    When `provisioned=false`, the response carries `needs_assumer_principal`:
    if true, prompt the user for the IAM principal (user/role ARN) that
    will assume this role and re-submit via `submit_role_request` with
    `assume_principal_arn` set, or PATCH the existing request's
    `spec.assume_by.principal_arn`. Otherwise the trust policy can't be
    locked down at provision time.
    """
    return _get(f"/api/v1/requests/{request_id}/assume")


@mcp.tool()
def iam_jit_inspect_response_for_injection(
    body: str,
    content_type: str | None = None,
    mode: str = "warn",
    allowlist_patterns: list[str] | None = None,
    min_confidence_for_deny: float = 0.7,
) -> dict[str, Any]:
    """Scan a tool response body for indirect prompt injection (#730).

    Defense-in-depth: even when the bouncer (gbounce/ibounce/dbounce/
    kbouncer) is offline or not in MITM mode, the agent harness can
    call this BEFORE feeding any tool-call response into LLM context.
    Catches indirect-prompt-injection payloads (hidden HTML comments,
    forged tool-result envelopes, role-confusion smuggling) — the top
    OWASP Agentic 2026 risk.

    Args:
      body: the response body text to scan.
      content_type: optional Content-Type for short-circuiting binary
        payloads (image/* etc.).
      mode: action mode — "warn" (pass + add warning), "strip" (redact
        matching regions), "deny" (block when confidence >= threshold).
      allowlist_patterns: regexes that suppress detection in known-
        clean contexts.
      min_confidence_for_deny: deny-mode confidence floor (default 0.7).

    Returns a dict with:
      detected (bool), indicators (list of {rule, snippet, layer,
      severity, source}), confidence (0.0-1.0), suggested_action,
      decided_action (after profile reconciliation), modified_body
      (set iff decided_action == 'strip'), and low_confidence_explanation
      (set iff confidence < 0.5).

    PURE-LOCAL: this tool does NOT call the iam-jit HTTP API. The
    scanner runs in-process inside the MCP server.
    """
    # Lazy import — keeps the MCP server able to start even if the
    # iam_jit package isn't importable for some reason (the rest of
    # the MCP tools talk HTTP and don't need the lib loaded).
    from iam_jit.injection_scanner import (
        ProfileConfig,
        apply_strip,
        decide_action,
        scan_response_body,
    )

    allowlist = tuple(allowlist_patterns or ())
    result = scan_response_body(
        body,
        content_type=content_type,
        allowlist_patterns=allowlist,
    )
    profile = ProfileConfig(
        enabled=True,
        action=mode if mode in ("warn", "strip", "deny", "allow") else "warn",  # type: ignore[arg-type]
        allowlist_patterns=allowlist,
        min_confidence_for_deny=min_confidence_for_deny,
    )
    decided = decide_action(result, profile)
    response: dict[str, Any] = {
        "detected": result.detected,
        "indicators": [
            {
                "rule": i.rule,
                "snippet": i.snippet,
                "layer": i.layer,
                "severity": i.severity,
                "source": i.source,
            }
            for i in result.indicators
        ],
        "confidence": result.confidence,
        "suggested_action": result.suggested_action,
        "decided_action": decided,
        "body_truncated": result.body_truncated,
        "skipped_reason": result.skipped_reason,
        "low_confidence_explanation": result.low_confidence_explanation,
    }
    if decided == "strip":
        response["modified_body"] = apply_strip(body, result)
    return response


@mcp.tool()
def iam_jit_validate_tool_call(
    body: str,
    mode: str = "warn",
    allowlist_patterns: list[str] | None = None,
    min_confidence_for_deny: float = 0.7,
    schema_corpus_path: str = "",
) -> dict[str, Any]:
    """Validate a tool-call request body against a known-tool corpus (#729).

    Agent-callable pre-flight: BEFORE the harness emits a tool call,
    pass the planned request body through this tool. If the validator
    flags a hallucinated tool name (one the upstream doesn't actually
    offer), a placeholder credential, or a schema-mismatched argument
    set, the agent should self-correct rather than emit the bad call.

    Recognized shapes (auto-detected from the body):
      - MCP `tools/call` and direct method invocations
      - OpenAI tool_calls / function_call (Chat Completions API)
      - Anthropic tool_use content blocks (Messages API)

    Args:
      body: the tool-call request body as a JSON string.
      mode: action mode — "warn" (pass + add warning), "strip" (replace
        hallucinated entries with a redaction marker), "deny" (block when
        confidence >= threshold).
      allowlist_patterns: regexes; matches suppress detection (e.g.,
        operator-known custom tools).
      min_confidence_for_deny: deny-mode confidence floor (default 0.7).
      schema_corpus_path: optional path to a YAML / JSON corpus override
        file. When empty, the baked-in MCP + OpenAI + Anthropic standard
        corpus is used.

    Returns a dict with:
      detected (bool), indicators (list of {rule, shape, tool_name,
      severity, source, reason}), confidence (0.0-1.0), suggested_action,
      decided_action (after profile reconciliation), modified_body
      (set iff decided_action == 'strip'), low_confidence_explanation
      (set iff confidence < 0.5), extracted_calls (list of [shape, name]
      pairs the validator looked at).

    PURE-LOCAL: this tool does NOT call the iam-jit HTTP API. The
    validator runs in-process inside the MCP server.

    Honesty bar (per iam-jit-honest-positioning): every indicator
    carries the rule + WHY it fired; the "~95% catch rate" PDF claim
    is INTENTIONALLY NOT in this docstring because we haven't yet
    calibrated against a real corpus — a follow-up task is filed.
    """
    from iam_jit.tool_call_validator import (
        ProfileConfig,
        apply_strip as _apply_strip_tcv,
        decide_action as _decide_action_tcv,
        validate as _validate_tcv,
    )
    from iam_jit.tool_call_validator.corpus import load_corpus

    allowlist = tuple(allowlist_patterns or ())
    corpus = load_corpus(schema_corpus_path) if schema_corpus_path else None
    result = _validate_tcv(
        body,
        schema_corpus=corpus,
        allowlist_patterns=allowlist,
    )
    profile = ProfileConfig(
        enabled=True,
        action=mode if mode in ("warn", "strip", "deny", "allow") else "warn",  # type: ignore[arg-type]
        allowlist_patterns=allowlist,
        min_confidence_for_deny=min_confidence_for_deny,
    )
    decided = _decide_action_tcv(result, profile)
    response: dict[str, Any] = {
        "detected": result.detected,
        "indicators": [
            {
                "rule": i.rule,
                "shape": i.shape,
                "tool_name": i.tool_name,
                "severity": i.severity,
                "source": i.source,
                "reason": i.reason,
            }
            for i in result.indicators
        ],
        "confidence": result.confidence,
        "suggested_action": result.suggested_action,
        "decided_action": decided,
        "body_truncated": result.body_truncated,
        "skipped_reason": result.skipped_reason,
        "low_confidence_explanation": result.low_confidence_explanation,
        "extracted_calls": [list(c) for c in result.extracted_calls],
    }
    if decided == "strip":
        response["modified_body"] = _apply_strip_tcv(body, result)
    return response


@mcp.tool()
def analyze_policy(
    policy: dict[str, Any],
    description: str = "",
    access_type: str = "read-only",
    duration_hours: int = 24,
) -> dict[str, Any]:
    """Score an IAM policy without submitting it.

    Useful for agents that want to pre-flight a policy locally before
    submitting via `submit_role_request`. Returns the risk review block
    (when AI is enabled in the deployment) and any narrowing questions
    that fire on the policy as-is.

    The deployment's NoAI flag controls whether the risk score is included;
    narrowing questions surface either way.
    """
    return _post(
        "/api/v1/policy/analyze",
        {
            "policy": policy,
            "description": description,
            "access_type": access_type,
            "duration": {"duration_hours": duration_hours},
        },
    )


# ============================================================
# Admin tools
# ============================================================


@mcp.tool()
def list_users(include_disabled: bool = False) -> dict[str, Any]:
    """List configured iam-jit users (admin-only).

    Useful when figuring out who can approve or who's on the requester
    list. Returns each user's id, display name, roles, enabled flag.
    """
    return _get("/api/v1/users", params={"include_disabled": str(include_disabled).lower()})


@mcp.tool()
def report_grants(
    state: str | None = None,
    since: str | None = None,
    until: str | None = None,
    account_id: str | None = None,
    requester_id: str | None = None,
) -> dict[str, Any]:
    """Pull the iam-jit grants audit report (admin-only).

    Returns rows describing every request iam-jit knows about, filterable
    by state, time range, account, or requester. Useful for compliance
    audits and ad-hoc questions like "show me all grants on
    111111111111 in the last quarter."
    """
    params: dict[str, Any] = {}
    for k, v in {
        "state": state,
        "since": since,
        "until": until,
        "account_id": account_id,
        "requester_id": requester_id,
    }.items():
        if v is not None:
            params[k] = v
    return _get("/api/v1/reports/grants", params=params)


# ============================================================
# Entrypoint
# ============================================================


def main() -> None:
    """Run the MCP server over stdio (default for desktop / IDE clients)."""
    mcp.run()


if __name__ == "__main__":
    main()
