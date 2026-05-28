"""`iam-jit remote …` — drive a deployed iam-jit instance over HTTP.

Same surface as the MCP tools and the web UI; the difference is the
transport. An agent in CI / GitHub Actions / a Lambda / a developer's
shell hits these subcommands to:

  - chat through an intake to draft a policy
  - submit the resulting request
  - check status / fetch the LLM's draft policy
  - respond to "needs changes" without re-typing everything
  - comment, cancel, fetch the assume-role snippet

Auth: every command needs `--token` (or `IAM_JIT_TOKEN` env). Tokens
are minted from the iam-jit UI by the user themselves; the agent
inherits whatever role the token's user holds. There's no separate
agent identity, by design — your agent IS you when it acts on your
behalf.

Output: JSON to stdout, status/diagnostics to stderr. Composable with
`jq`, with `xargs -I {}`, with shell loops. Every command exits 0 on
success, non-zero on transport / auth / state errors.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import click


# ---- HTTP helpers ----


_DEFAULT_TIMEOUT = 60.0


def _client(url: str | None, token: str | None):
    import httpx

    base = url or os.environ.get("IAM_JIT_URL")
    if not base:
        raise click.UsageError(
            "no --url given and IAM_JIT_URL is not set"
        )
    bearer = token or os.environ.get("IAM_JIT_TOKEN")
    if not bearer:
        raise click.UsageError(
            "no --token given and IAM_JIT_TOKEN is not set"
        )
    headers = {"Authorization": f"Bearer {bearer}"}
    return httpx.Client(
        base_url=base.rstrip("/"),
        headers=headers,
        timeout=_DEFAULT_TIMEOUT,
    )


def _emit(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, default=str))


def _bail(resp) -> None:
    """Raise click.ClickException with a useful message on non-2xx."""
    if resp.status_code < 400:
        return
    try:
        body = resp.json()
        detail = body.get("detail") or body
    except Exception:
        detail = resp.text[:400]
    raise click.ClickException(
        f"HTTP {resp.status_code}: {json.dumps(detail, default=str)}"
    )


# ---- top-level group ----


@click.group("remote")
def remote() -> None:
    """Drive a deployed iam-jit instance over HTTP.

    \b
    Common environment:
      IAM_JIT_URL=https://iam-jit.example.com
      IAM_JIT_TOKEN=iamjit_…   (mint via the UI under /tokens)
    """


_url_opt = click.option(
    "--url", help="Base URL of the iam-jit deployment. "
    "Defaults to $IAM_JIT_URL.",
)
_token_opt = click.option(
    "--token", help="API bearer token. Defaults to $IAM_JIT_TOKEN.",
)


# ---- chat (multi-turn intake) ----


@remote.command("chat")
def chat() -> None:
    """REMOVED in iam-jit 0.4.0 — the conversational intake endpoint
    (/api/v1/intake/turn) was deleted in Stage 4 of [[no-nl-synthesis]].

    Replacement workflow: the agent uses the MCP tools
    (list_templates / get_template / score_iam_policy / submit_policy)
    to author + submit a policy with codebase context, OR the human
    pastes raw JSON via `iam-jit remote submit` (still works) or the
    web UI's paste page. See docs/AGENTS.md.
    """
    import click
    click.secho(
        "iam-jit remote chat has been removed in 0.4.0.",
        fg="yellow", err=True,
    )
    click.echo(
        "The conversational intake API was deleted in Stage 4 of the "
        "NL-synthesis deprecation. Use the MCP tools (list_templates / "
        "get_template / score_iam_policy / submit_policy) or "
        "`iam-jit remote submit` with raw JSON instead. See docs/AGENTS.md.",
        err=True,
    )
    raise click.exceptions.Exit(2)


@remote.command("submit")
@_url_opt
@_token_opt
@click.option("--description", help="Plain-English description. Required for read-write.")
@click.option("--account", multiple=True, required=True,
              help="Destination account ID(s). Can be repeated.")
@click.option("--duration", type=int, required=True,
              help="Grant duration in hours (1..8760).")
@click.option("--access-type", type=click.Choice(["read-only", "read-write"]),
              default="read-only", show_default=True)
@click.option("--policy-file",
              type=click.Path(exists=True, dir_okay=False),
              help="Path to a JSON or YAML file with the IAM policy.")
@click.option("--ticket", default=None, help="Optional change/incident ticket URL.")
@click.option("--assume-principal", default=None,
              help="ARN of the principal that will assume the role. "
              "Defaults to your login.")
def submit(
    url: str | None,
    token: str | None,
    description: str | None,
    account: tuple[str, ...],
    duration: int,
    access_type: str,
    policy_file: str | None,
    ticket: str | None,
    assume_principal: str | None,
) -> None:
    """Submit a request from explicit fields. The most direct path
    when an agent already has the policy in hand."""
    policy: dict[str, Any] | None = None
    if policy_file:
        with open(policy_file) as f:
            text = f.read()
        try:
            policy = json.loads(text)
        except json.JSONDecodeError:
            from ruamel.yaml import YAML

            policy = YAML(typ="safe").load(text)
    spec: dict[str, Any] = {
        "access_type": access_type,
        "accounts": [{"account_id": a} for a in account],
        "duration": {"duration_hours": duration},
    }
    if description:
        spec["description"] = description
    if policy is not None:
        spec["policy"] = policy
    else:
        spec["task_intent"] = {"services": ["s3"], "actions": ["read"]}
    if ticket:
        spec["ticket"] = ticket
    if assume_principal:
        spec["assume_by"] = {"principal_arn": assume_principal}

    payload = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {},
        "spec": spec,
    }
    with _client(url, token) as c:
        resp = c.post("/api/v1/requests", json=payload)
        _bail(resp)
        body = resp.json()
        _emit(body)
        # #694 — surface a verify hint when the response carries a
        # provisioned role ARN. Operators dogfooding the flow kept
        # reaching for `aws iam simulate-principal-policy` and getting
        # implicitDeny for every action (the TTL gate needs an
        # aws:CurrentTime context entry). `iam-jit verify-role`
        # injects that entry automatically.
        try:
            role_arn = (
                ((body or {}).get("request") or {})
                .get("status", {})
                .get("provisioned", {})
                .get("role_arn")
            )
        except Exception:
            role_arn = None
        if role_arn:
            click.echo(
                f"verify: iam-jit verify-role {role_arn}",
                err=True,
            )


@remote.command("status")
@_url_opt
@_token_opt
@click.argument("request_id")
def status(url: str | None, token: str | None, request_id: str) -> None:
    """Fetch the full request, including state, policy, comments,
    and (if active) the provisioned role ARN + assume snippet."""
    with _client(url, token) as c:
        resp = c.get(f"/api/v1/requests/{request_id}")
        _bail(resp)
        _emit(resp.json())


@remote.command("list")
@_url_opt
@_token_opt
@click.option("--state", default=None, help="Filter to a single state.")
@click.option("--limit", type=int, default=50, show_default=True)
@click.option("--offset", type=int, default=0, show_default=True)
def list_cmd(
    url: str | None, token: str | None,
    state: str | None, limit: int, offset: int,
) -> None:
    """List requests visible to the calling token (owner-scoped for
    requesters, all for approvers/admins)."""
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if state:
        params["state"] = state
    with _client(url, token) as c:
        resp = c.get("/api/v1/requests", params=params)
        _bail(resp)
        _emit(resp.json())


@remote.command("assume")
@_url_opt
@_token_opt
@click.argument("request_id")
def assume(url: str | None, token: str | None, request_id: str) -> None:
    """Print the assume-role snippet for an active request."""
    with _client(url, token) as c:
        resp = c.get(f"/api/v1/requests/{request_id}/assume")
        _bail(resp)
        _emit(resp.json())


# ---- mutate ----


@remote.command("comment")
@_url_opt
@_token_opt
@click.argument("request_id")
@click.argument("message")
def comment(
    url: str | None, token: str | None, request_id: str, message: str
) -> None:
    """Post a comment on a request thread."""
    with _client(url, token) as c:
        resp = c.post(
            f"/api/v1/requests/{request_id}/comments",
            json={"message": message},
        )
        _bail(resp)
        _emit(resp.json())


@remote.command("cancel")
@_url_opt
@_token_opt
@click.argument("request_id")
@click.option("--reason", default=None)
def cancel(
    url: str | None, token: str | None,
    request_id: str, reason: str | None,
) -> None:
    """Cancel a request the caller owns."""
    body: dict[str, Any] = {}
    if reason:
        body["reason"] = reason
    with _client(url, token) as c:
        resp = c.post(f"/api/v1/requests/{request_id}/cancel", json=body)
        _bail(resp)
        _emit(resp.json())


@remote.command("respond")
@_url_opt
@_token_opt
@click.argument("request_id")
@click.option("--policy-file",
              type=click.Path(exists=True, dir_okay=False),
              help="Replacement IAM policy after `request_changes`.")
@click.option("--description", default=None,
              help="Updated description.")
@click.option("--access-type", type=click.Choice(["read-only", "read-write"]),
              default=None)
@click.option("--duration", type=int, default=None,
              help="Updated grant duration in hours.")
def respond(
    url: str | None, token: str | None, request_id: str,
    policy_file: str | None, description: str | None,
    access_type: str | None, duration: int | None,
) -> None:
    """Edit a request after the approver asked for changes.

    Only `pending` and `needs_changes` requests can be edited; the
    server returns 409 otherwise. Pass only the fields you want to
    update."""
    spec: dict[str, Any] = {}
    if policy_file:
        with open(policy_file) as f:
            text = f.read()
        try:
            spec["policy"] = json.loads(text)
        except json.JSONDecodeError:
            from ruamel.yaml import YAML

            spec["policy"] = YAML(typ="safe").load(text)
    if description is not None:
        spec["description"] = description
    if access_type:
        spec["access_type"] = access_type
    if duration is not None:
        spec["duration"] = {"duration_hours": duration}
    if not spec:
        raise click.UsageError("nothing to update — pass at least one field")
    with _client(url, token) as c:
        resp = c.patch(
            f"/api/v1/requests/{request_id}",
            json={"spec": spec},
        )
        _bail(resp)
        _emit(resp.json())


# ---- approver actions (admin/approver tokens only) ----


@remote.command("approve")
@_url_opt
@_token_opt
@click.argument("request_id")
@click.option("--comment", default=None)
def approve(
    url: str | None, token: str | None,
    request_id: str, comment: str | None,
) -> None:
    """Approve a pending request. Requires an approver/admin token."""
    body: dict[str, Any] = {}
    if comment:
        body["comment"] = comment
    with _client(url, token) as c:
        resp = c.post(f"/api/v1/requests/{request_id}/approve", json=body)
        _bail(resp)
        _emit(resp.json())


@remote.command("reject")
@_url_opt
@_token_opt
@click.argument("request_id")
@click.argument("reason")
def reject(
    url: str | None, token: str | None, request_id: str, reason: str
) -> None:
    """Reject a pending request with a required reason."""
    with _client(url, token) as c:
        resp = c.post(
            f"/api/v1/requests/{request_id}/reject",
            json={"reason": reason},
        )
        _bail(resp)
        _emit(resp.json())


@remote.command("request-changes")
@_url_opt
@_token_opt
@click.argument("request_id")
@click.argument("comment")
def request_changes(
    url: str | None, token: str | None, request_id: str, comment: str
) -> None:
    """Send a request back to the owner with feedback."""
    with _client(url, token) as c:
        resp = c.post(
            f"/api/v1/requests/{request_id}/request-changes",
            json={"comment": comment},
        )
        _bail(resp)
        _emit(resp.json())
