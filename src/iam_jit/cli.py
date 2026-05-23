import json
import os
import pathlib
import sys

import click

from . import __version__
from .schema import load_request, scaffold_request, validate_request


@click.group()
@click.version_option(__version__, "-V", "--version")
def main() -> None:
    """iam-jit — author, validate, and (later) provision time-bound IAM roles."""


@main.command()
@click.option("--description", "-d", required=True, help="Plain-English task description.")
@click.option("--account", "-a", required=True, multiple=True, help="Target account ID.")
@click.option(
    "--duration-hours",
    "-h",
    type=int,
    default=24,
    show_default=True,
    help="How long the grant should last from approval.",
)
@click.option(
    "--write",
    "write_access",
    is_flag=True,
    default=False,
    help="Request read-write access. Default is read-only (much faster to approve).",
)
@click.option(
    "--out",
    "-o",
    type=click.Path(dir_okay=False, writable=True, path_type=pathlib.Path),
    help="Where to write the request YAML. Default: stdout.",
)
def init(
    description: str,
    account: tuple[str, ...],
    duration_hours: int,
    write_access: bool,
    out: pathlib.Path | None,
) -> None:
    """Scaffold a new role-request YAML from a description."""
    yaml_text = scaffold_request(
        description=description,
        accounts=list(account),
        duration_hours=duration_hours,
        access_type="read-write" if write_access else "read-only",
    )
    if out:
        out.write_text(yaml_text)
        click.echo(f"Wrote {out}", err=True)
    else:
        click.echo(yaml_text)


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
def validate(path: pathlib.Path) -> None:
    """Validate a role-request YAML against the schema."""
    request = load_request(path)
    errors = validate_request(request)
    if errors:
        click.echo(f"{path}: invalid", err=True)
        for err in errors:
            click.echo(f"  {err}", err=True)
        sys.exit(1)
    click.echo(f"{path}: ok", err=True)


# NOTE: `iam-jit suggest` and `iam-jit refine` removed in Stage 4 of
# [[no-nl-synthesis]]. They drafted/narrowed policies from task_intent
# via policy_sentry + LLM — the same synthesis pattern that measured
# joint sufficiency below the calibration bar. Replacement: agents (Claude Code, Cursor)
# use the MCP tools (list_templates / get_template / score_iam_policy /
# submit_policy); humans paste raw JSON via `iam-jit review` or the
# web UI's paste page.


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
@click.option(
    "--no-llm",
    is_flag=True,
    help="Skip the LLM narrative; show only deterministic score + factors.",
)
def review(path: pathlib.Path, no_llm: bool) -> None:
    """Show approver-facing risk analysis (1-10) for a request's policy."""
    from .llm import NoOpBackend, get_backend
    from .review import analyze_policy

    request = load_request(path)
    policy = request["spec"].get("policy")
    if not policy:
        click.echo(
            f"{path}: no policy on the request — run `iam-jit suggest` first or paste one.",
            err=True,
        )
        sys.exit(2)
    backend = None if no_llm else get_backend()
    if isinstance(backend, NoOpBackend):
        backend = None
    analysis = analyze_policy(policy, request, backend=backend)
    click.echo(f"Risk: {analysis.risk_score}/10 ({analysis.analyzer})")
    click.echo("Factors:")
    for factor in analysis.risk_factors:
        click.echo(f"  - {factor}")
    if analysis.suggestions:
        click.echo("Suggestions:")
        for s in analysis.suggestions:
            click.echo(f"  - {s}")
    if analysis.llm_narrative:
        click.echo()
        click.echo(analysis.llm_narrative)


# `iam-jit refine` removed in Stage 4 of [[no-nl-synthesis]].
# Same reasoning as the deleted `suggest` command above.


@main.command("seed-admin")
@click.option(
    "--email",
    required=True,
    help="Email address of the first admin. Becomes user_id `email:<addr>`.",
)
@click.option(
    "--display-name",
    default=None,
    help="Optional friendly name. Defaults to 'Bootstrap Admin'.",
)
@click.option(
    "--users-file",
    type=click.Path(dir_okay=False, path_type=pathlib.Path),
    help="Path to a local users.yaml. Required for file-mode dev.",
)
@click.option(
    "--users-table",
    help="DynamoDB table name. Used if --users-file is omitted and "
    "the AWS env points at the iam-jit users table.",
)
def seed_admin(
    email: str,
    display_name: str | None,
    users_file: pathlib.Path | None,
    users_table: str | None,
) -> None:
    """Seed the first admin user.

    Idempotent: if the email already exists in the store, nothing
    changes. Use this once per fresh deployment to break the
    chicken-and-egg bootstrap problem (every write endpoint requires
    an admin, but the store starts empty).

    \b
    Examples:
      # Local dev with a YAML file:
      iam-jit seed-admin --email you@example.com --users-file users.yaml

      # Production / Lambda already-running with DynamoDB:
      AWS_REGION=us-east-1 iam-jit seed-admin \\
          --email you@example.com --users-table iam-jit-users
    """
    from iam_jit.user_bootstrap import seed_bootstrap_admin
    from iam_jit.users_store import FileUserStore

    if users_file is not None:
        if not users_file.exists():
            users_file.write_text(
                "schema_version: 1\nauth_mode: local\nusers: []\n"
            )
            click.echo(f"Created empty users.yaml at {users_file}", err=True)
        # FileUserStore is read-only at runtime; for the bootstrap CLI
        # we open it write-through by editing the YAML directly.
        from ruamel.yaml import YAML

        yaml = YAML(typ="safe")
        with users_file.open() as f:
            data = yaml.load(f) or {}
        users = list(data.get("users") or [])
        user_id = f"email:{email.lower().strip()}"
        if any(u.get("id") == user_id for u in users):
            click.echo(f"User {user_id} already in {users_file} — no change.", err=True)
            return
        users.append(
            {
                "id": user_id,
                "display_name": display_name or "Bootstrap Admin",
                "roles": ["admin"],
                "enabled": True,
                "notes": "seeded by `iam-jit seed-admin`",
            }
        )
        data["users"] = users
        data.setdefault("schema_version", 1)
        data.setdefault("auth_mode", "local")
        from ruamel.yaml import YAML as _YAML

        out_yaml = _YAML()
        out_yaml.indent(mapping=2, sequence=4, offset=2)
        with users_file.open("w") as f:
            out_yaml.dump(data, f)
        click.echo(
            f"✓ Seeded admin {user_id} into {users_file}.\n"
            f"  Sign in at the iam-jit URL with {email}.",
            err=True,
        )
        return

    if users_table:
        from iam_jit.users_store import DynamoDBUserStore

        store = DynamoDBUserStore(users_table)
        result = seed_bootstrap_admin(
            store, email=email, display_name=display_name
        )
        if result.seeded:
            click.echo(
                f"✓ Seeded admin {result.user_id} in DynamoDB table "
                f"{users_table}. Sign in with {email}.",
                err=True,
            )
        elif result.reason == "user_already_exists":
            click.echo(
                f"User {result.user_id} already exists — no change.",
                err=True,
            )
        else:
            raise click.ClickException(
                f"seed failed: {result.reason}"
            )
        return

    raise click.ClickException(
        "either --users-file or --users-table is required"
    )


from .cli_remote import remote as _remote_group  # noqa: E402

main.add_command(_remote_group)


# #102 — Enterprise self-bootstrapping. Registered late so any tier
# gating happens inside the subcommand handler, not at import time
# (load_license touches the filesystem; we don't want that on
# `iam-jit --help`).
from .enterprise.cli import enterprise_group as _enterprise_group  # noqa: E402

main.add_command(_enterprise_group)


@main.command("agent-grant")
def agent_grant() -> None:
    """REMOVED in iam-jit 0.4.0 — see docs/AGENTS.md.

    Natural-language policy synthesis was measured below the
    calibration joint-sufficiency bar
    (docs/calibration/100-prompt-sufficiency-loop.md) and removed
    in [[no-nl-synthesis]] Stage 3. The replacement
    workflow uses the MCP tools list_templates + get_template +
    score_iam_policy + submit_policy, driven by an IDE agent with
    codebase context.
    """
    click.secho(
        'iam-jit agent-grant has been removed in 0.4.0.',
        fg='yellow', err=True,
    )
    click.echo(
        'Use the MCP tools (list_templates / get_template / '
        'score_iam_policy / submit_policy) instead. '
        'See docs/AGENTS.md.',
        err=True,
    )
    raise click.exceptions.Exit(2)


@main.command("serve")
@click.option(
    "--local",
    is_flag=True,
    default=False,
    help="Local mode — run iam-jit on this machine using local AWS credentials. "
         "Best for solo-dev / agent-safety use cases. No external dependencies; "
         "audit log + state in ~/.iam-jit/.",
)
@click.option(
    "--host",
    default="127.0.0.1",
    help="Host to bind. Default 127.0.0.1 (localhost only).",
)
@click.option(
    "--port",
    type=int,
    default=8765,
    help="Port to bind. Default 8765.",
)
@click.option(
    "--data-dir",
    type=click.Path(file_okay=False, path_type=pathlib.Path),
    default=None,
    help="Local data directory. Default: ~/.iam-jit/",
)
def serve(local: bool, host: str, port: int, data_dir: pathlib.Path | None) -> None:
    """Run iam-jit as a local process.

    `iam-jit serve --local` is the recommended entry point for
    solo devs + individual admins running iam-jit on their own
    machine. Uses local AWS credentials (boto3 default chain);
    persists state to ~/.iam-jit/; auto-creates a single admin
    user matching the local OS user.

    For Lambda / SAM deployments, do NOT use this; deploy via
    `sam deploy` instead.

    Example:
      iam-jit serve --local
      # ✓ Listening on http://127.0.0.1:8765
      # ✓ Admin: email:youruser@yourhost.local
      # ✓ Audit log: ~/.iam-jit/audit.db
    """
    if not local:
        click.echo(
            "iam-jit serve requires --local for now. Hosted/self-host "
            "deployments use `sam deploy`. See docs/DEPLOYMENT.md.",
            err=True,
        )
        sys.exit(1)

    from .local_server import run

    sys.exit(run(host=host, port=port, data_dir=data_dir))


@main.command("init-solo")
@click.option(
    "--data-dir",
    type=click.Path(file_okay=False, path_type=pathlib.Path),
    default=None,
    help="Local data directory. Default: ~/.iam-jit/",
)
@click.option(
    "--port",
    type=int,
    default=8765,
    show_default=True,
    help="Port iam-jit will listen on (used in the printed config snippets).",
)
@click.option(
    "--print-mcp-config",
    is_flag=True,
    default=False,
    help="Print the Claude Code MCP server config snippet only (no setup).",
)
def init_solo(
    data_dir: pathlib.Path | None,
    port: int,
    print_mcp_config: bool,
) -> None:
    """One-command setup for solo-dev / agent-safety mode.

    Bootstraps `~/.iam-jit/` (data dir, users.yaml, accounts.yaml,
    API token) and prints the snippets you paste into Claude Code's
    MCP config to wire iam-jit as your AWS safety layer.

    Does NOT start the server. After init-solo finishes, run:

      iam-jit serve --local

    Designed to be the 90-second on-ramp behind "don't give Claude
    your AWS keys."
    """
    from . import local_server

    cfg = local_server.LocalServerConfig(
        port=port,
        data_dir=data_dir or local_server._DEFAULT_DATA_DIR,
    )

    if print_mcp_config:
        _print_mcp_snippets(cfg)
        return

    click.echo("iam-jit init-solo")
    click.echo("")
    click.echo(f"  Data dir:  {cfg.data_dir}")

    local_server._ensure_data_dir(cfg)
    admin_user_id = local_server._seed_local_user(cfg)
    local_server._seed_local_accounts(cfg)
    local_server._set_local_env_defaults(cfg, admin_user_id)
    raw_token = local_server._ensure_local_cli_token(
        cfg, admin_user_id=admin_user_id,
    )

    click.echo(f"  Admin:     {admin_user_id}")
    click.echo(f"  API token: {cfg.cli_token_file} (mode 0600)")
    click.echo("")
    click.echo("Next steps:")
    click.echo("")
    click.echo("  1. Start the server:")
    click.echo(f"       iam-jit serve --local --port {cfg.port}")
    click.echo("")
    click.echo("  2. Tell Claude Code about the iam-jit MCP server.")
    click.echo("     Add this to your Claude Code MCP config")
    click.echo("     (run `iam-jit init-solo --print-mcp-config` to")
    click.echo("     print it again any time):")
    click.echo("")
    _print_mcp_snippets(cfg)
    click.echo("")
    click.echo("  3. In Claude Code, just ask for what you need.")
    click.echo("     The agent will route AWS access requests through")
    click.echo("     iam-jit (scoped, time-bound, audited).")
    click.echo("")


def _print_mcp_snippets(cfg) -> None:  # type: ignore[no-untyped-def]
    """Print Claude Code MCP server config + bearer-token usage.

    Two ways to wire iam-jit into Claude Code:
      A. As an MCP server (stdio transport — preferred for tool use)
      B. As an HTTP API the user calls explicitly (`curl` examples)

    init-solo prints both so the user picks whichever fits.
    """
    token_file = str(cfg.cli_token_file)
    click.echo("    Claude Code MCP config (stdio transport):")
    click.echo("")
    click.echo("    {")
    click.echo('      "mcpServers": {')
    click.echo('        "iam-jit": {')
    click.echo('          "command": "iam-jit",')
    click.echo('          "args": ["mcp-server"]')
    click.echo("        }")
    click.echo("      }")
    click.echo("    }")
    click.echo("")
    click.echo("    Bearer token (for direct HTTP API calls):")
    click.echo(f"      cat {token_file}")
    click.echo("")
    click.echo(
        f"      curl -H \"Authorization: Bearer $(cat {token_file})\" \\"
    )
    click.echo(
        f"           http://127.0.0.1:{cfg.port}/api/v1/users/me"
    )


@main.group("auth")
def auth_group() -> None:
    """OIDC-based authentication flows for iam-jit (agent-friendly)."""


@auth_group.command("device")
@click.option(
    "--api-url",
    default=None,
    help="iam-jit API URL. Default: http://127.0.0.1:8765",
)
@click.option(
    "--print-token",
    is_flag=True,
    default=False,
    help="Print the minted bearer token on success (otherwise just save to "
         "~/.iam-jit/cli-token.device).",
)
def auth_device(api_url: str | None, print_token: bool) -> None:
    """Browser-less OIDC login via RFC 8628 Device Authorization Grant.

    Run this from an agent / SSH / container where you can't open a
    browser. Prints a code + URL; you complete the dance on your phone
    or another machine; the command polls until success then mints a
    bearer token with MFA-at-issuance evidence for the iam-jit API.

    Per [[mfa-compliance-strategy]] PCI §8.6 — agent inherits the
    human's MFA via the token's mfa_at_issuance timestamp.
    """
    import sys
    import time as _time

    from .oidc import (
        OIDCProviderConfig,
        discover,
        start_device_flow,
        poll_device_flow,
        DeviceFlowPending,
        DeviceFlowSlowDown,
        DeviceFlowExpired,
        DeviceFlowDenied,
        HttpxClient,
    )

    config = OIDCProviderConfig.from_env()
    if config is None:
        click.echo(
            "OIDC not configured. Set IAM_JIT_OIDC_PROVIDER + the "
            "provider-specific env vars (CLIENT_ID, CLIENT_SECRET, "
            "REDIRECT_URI, HOSTED_DOMAIN for Google).",
            err=True,
        )
        sys.exit(2)

    client = HttpxClient()
    endpoints = discover(config, client)

    try:
        start = start_device_flow(config, endpoints, client)
    except Exception as e:
        click.echo(f"Device-flow start failed: {e}", err=True)
        sys.exit(3)

    click.echo("")
    click.echo("Open this URL on any browser-equipped device:")
    if start.verification_uri_complete:
        click.echo(f"  {start.verification_uri_complete}")
    else:
        click.echo(f"  {start.verification_uri}")
        click.echo("And enter this code:")
        click.echo(f"  {start.user_code}")
    click.echo("")
    click.echo(f"Waiting for you to complete the flow "
               f"(timeout in {start.expires_in}s)...")

    interval = start.interval
    deadline = _time.time() + start.expires_in
    while _time.time() < deadline:
        _time.sleep(interval)
        try:
            token = poll_device_flow(
                config, endpoints, start.device_code, client,
            )
            break
        except DeviceFlowPending:
            continue
        except DeviceFlowSlowDown:
            interval = min(interval * 2, 60)
            continue
        except DeviceFlowExpired:
            click.echo("Device code expired before you completed the flow.",
                       err=True)
            sys.exit(4)
        except DeviceFlowDenied:
            click.echo("You denied the request at the IdP.", err=True)
            sys.exit(5)
    else:
        click.echo("Timed out waiting for device-flow completion.", err=True)
        sys.exit(6)

    click.echo("")
    click.echo("✓ OIDC device flow complete.")

    # TODO Phase 2 follow-up: validate the id_token AMR claim, mint an
    # iam-jit bearer token via the running iam-jit API (POST /api/v1/tokens)
    # passing the id_token as proof-of-MFA, and persist the bearer to
    # ~/.iam-jit/cli-token.device for the agent to use.
    #
    # For now (skeleton): print the id_token so the user can manually
    # validate or pass it as a bearer for OIDC-bearer endpoints.
    if print_token:
        click.echo("")
        click.echo("ID token (for manual validation only — not the "
                   "iam-jit bearer token):")
        click.echo(token.id_token)
    else:
        click.echo("Use --print-token to display the raw id_token. "
                   "iam-jit bearer-token minting via the device flow is "
                   "Phase 2 follow-up work (#142).")


@main.command("dev-slack-mock")
@click.option(
    "--host",
    default="127.0.0.1",
    help="Host to bind. Default 127.0.0.1.",
)
@click.option(
    "--port",
    type=int,
    default=8766,
    show_default=True,
    help="Port to bind. Default 8766 (one above the local server's 8765).",
)
def dev_slack_mock(host: str, port: int) -> None:
    """Run a mock Slack API server for local dev + CI E2E testing.

    Implements just enough of Slack's Web API to exercise the
    iam-jit Slack-bot integration end-to-end without hitting real
    Slack. Useful when developing the bot or running E2E tests in
    CI where ngrok + a real workspace isn't available.

    See `src/iam_jit/_test_support/slack_mock.py` for the supported
    endpoint surface.
    """
    from ._test_support.slack_mock import run_standalone

    sys.exit(run_standalone(host=host, port=port))


@main.command("tail")
@click.argument("grant_id", type=str)
@click.option(
    "--since",
    type=str,
    default=None,
    help="ISO-8601 UTC lower bound (default: grant's provisioned-at).",
)
@click.option(
    "--until",
    type=str,
    default=None,
    help="ISO-8601 UTC upper bound (default: grant's expires_at).",
)
@click.option(
    "--region",
    "aws_region",
    type=str,
    default=None,
    help="Narrow to one AWS region (CloudTrail is regional).",
)
@click.option(
    "--errors-only",
    is_flag=True,
    default=False,
    help="Only show failed API calls (non-empty errorCode).",
)
@click.option(
    "--max",
    "max_events",
    type=int,
    default=100,
    show_default=True,
    help="Max events to display (hard cap 1000).",
)
def tail_cmd(
    grant_id: str,
    since: str | None,
    until: str | None,
    aws_region: str | None,
    errors_only: bool,
    max_events: int,
) -> None:
    """Show recent AWS API events for a JIT-issued grant's role session.

    Per [[live-action-tail-pro-tier]]: the "what is alice's agent
    doing right now with the grant I approved 10 min ago?" view.
    Reads from the configured LiveActionTailSource (default: null
    source). Self-host admins wire CloudTrailLookupSource in
    bootstrap; the Enterprise plugin wires EventBridge streaming.

    The grant must already be provisioned (status.provisioned set).
    Output is one event per line in CloudTrail-descending order.

    Example:

    \b
        iam-jit tail req-2026-05-17-alice-readonly --errors-only

    """
    from .app import _build_request_store_from_env
    from .live_action_tail import (
        TailQuery,
        extract_tail_inputs_from_grant,
        format_event_summary,
        get_default_source,
    )

    try:
        store = _build_request_store_from_env()
        request = store.get(grant_id)
    except Exception as e:
        click.echo(f"could not load grant '{grant_id}': {e}", err=True)
        sys.exit(2)

    base_query = extract_tail_inputs_from_grant(request)
    if base_query is None:
        click.echo(
            f"grant '{grant_id}' has no provisioned role to tail "
            "(status.provisioned missing or incomplete)",
            err=True,
        )
        sys.exit(2)

    query = TailQuery(
        role_name=base_query.role_name,
        session_name=base_query.session_name,
        account_id=base_query.account_id,
        since=since or base_query.since,
        until=until or base_query.until,
        aws_region=aws_region or base_query.aws_region,
        max_events=max(1, min(max_events, 1000)),
        only_errors=errors_only,
    )

    source = get_default_source()
    result = source.fetch_events(query)

    click.echo(f"# grant: {grant_id}")
    click.echo(f"# role:  {query.role_name}")
    click.echo(f"# account: {query.account_id}")
    click.echo(f"# source: {source.describe()}")
    click.echo(f"# events: {len(result.events)}")
    if not result.ok:
        # WB22 LOW-22-03 closure: don't silently exit 0 when the
        # source itself failed — admin needs to know "no events
        # because source broken" vs "no events because no activity".
        click.echo(f"# source error: {result.error}", err=True)
        sys.exit(3)
    if not result.events:
        click.echo(
            "# (no events — check that the source is configured "
            "and that the session window contains activity)"
        )
        return
    for ev in result.events:
        click.echo(format_event_summary(ev))


@main.group("allowlist")
def allowlist_group() -> None:
    """Manage the compatibility allowlist (#166 Slice 2).

    Admin-supplied per-account/per-workload overrides that change
    what `check_iam_jit_compatibility` returns. Lets your org
    declare 'for account X + workload Y, always use existing role Z'
    or 'for account A, iam-jit cannot help.'

    Every mutation is audit-logged to the bouncer's
    `config_events` table. Agents can READ the allowlist via the
    `list_compatibility_overrides` MCP tool but can NOT mutate it
    — only admins, via this CLI.
    """


def _allowlist_actor() -> str:
    import getpass
    import os
    explicit = os.environ.get("IAM_JIT_BOUNCER_ACTOR")
    if explicit:
        return explicit
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _allowlist_audit_record(*, kind: str, summary: str, detail: dict | None = None) -> None:
    """Mirror the bouncer's config_events writer. Best-effort — if
    the bouncer store isn't initialized, the CLI continues."""
    try:
        from .bouncer.store import BouncerStore
        store = BouncerStore()
        try:
            store._record_config_event_locked(
                actor=_allowlist_actor(), kind=kind, summary=summary, detail=detail,
            )
        finally:
            store.close()
    except Exception:
        pass


@allowlist_group.command("list")
@click.option("--json", "as_json", is_flag=True, default=False)
def allowlist_list(as_json: bool) -> None:
    """List all allowlist rules."""
    from .compatibility_allowlist import build_default_store

    store = build_default_store()
    rules = store.list()
    if as_json:
        click.echo(json.dumps([r.to_dict() for r in rules], indent=2))
        return
    if not rules:
        click.echo("(no allowlist rules configured)")
        return
    for r in rules:
        acct = r.account_id or "*"
        wl = r.workload.value if r.workload else "*"
        arn_tail = f" -> {r.existing_role_arn}" if r.existing_role_arn else ""
        click.echo(f"{r.rule_id}  {r.verdict.value:>13}  acct={acct}  workload={wl}{arn_tail}")
        click.echo(f"    reason: {r.reason}")
        click.echo(f"    by {r.created_by} at {r.created_at}")


@allowlist_group.command("add")
@click.option("--account", "account_id", default=None,
              help="12-digit AWS account ID, or omit for any-account wildcard.")
@click.option("--workload", default=None,
              help="WorkloadType (e.g. k8s_pod), or omit for any-workload wildcard.")
@click.option("--verdict", required=True,
              type=click.Choice(["proceed", "use_existing", "use_bouncer", "cannot_help"]))
@click.option("--role-arn", "existing_role_arn", default=None,
              help="IAM role ARN — REQUIRED when verdict=use_existing.")
@click.option("--reason", required=True,
              help="Admin justification (recorded in audit log).")
@click.option("--next-action-hint", default=None,
              help="Optional override for the next_action_hint returned to agents.")
def allowlist_add(
    account_id: str | None,
    workload: str | None,
    verdict: str,
    existing_role_arn: str | None,
    reason: str,
    next_action_hint: str | None,
) -> None:
    """Add an allowlist rule. Examples:

    \b
        # For account 111... + k8s pods, always use the shared role:
        iam-jit allowlist add \\
            --account 111111111111 --workload k8s_pod \\
            --verdict use_existing \\
            --role-arn arn:aws:iam::111111111111:role/shared-ml \\
            --reason "shared ML cluster"

    \b
        # Mark account 222... as out-of-scope:
        iam-jit allowlist add \\
            --account 222222222222 \\
            --verdict cannot_help \\
            --reason "compliance environment; named-role-only"
    """
    from .compatibility_allowlist import (
        InvalidRule, build_default_store, build_rule,
    )

    actor = _allowlist_actor()
    try:
        rule = build_rule(
            account_id=account_id,
            workload=workload,
            verdict=verdict,
            existing_role_arn=existing_role_arn,
            reason=reason,
            next_action_hint=next_action_hint,
            created_by=actor,
        )
    except InvalidRule as e:
        click.echo(f"rejected: {e}", err=True)
        sys.exit(2)
    store = build_default_store()
    store.add(rule)
    _allowlist_audit_record(
        kind="allowlist_rule_added",
        summary=f"allowlist rule {rule.rule_id} added: verdict={rule.verdict.value}",
        detail=rule.to_dict(),
    )
    click.echo(f"added rule {rule.rule_id}: {rule.verdict.value}")


@allowlist_group.command("remove")
@click.argument("rule_id")
def allowlist_remove(rule_id: str) -> None:
    """Remove an allowlist rule. The deletion is audit-logged with
    the rule's full prior content (per [[agent-friendly-not-
    bypassable]] Lens B — no covering tracks)."""
    from .compatibility_allowlist import RuleNotFound, build_default_store

    store = build_default_store()
    try:
        removed = store.remove(rule_id)
    except RuleNotFound:
        click.echo(f"no rule with id {rule_id!r}", err=True)
        sys.exit(1)
    _allowlist_audit_record(
        kind="allowlist_rule_removed",
        summary=f"allowlist rule {rule_id} removed: verdict={removed.verdict.value}",
        detail=removed.to_dict(),
    )
    click.echo(f"removed rule {rule_id}")


@allowlist_group.command("show")
@click.argument("rule_id")
def allowlist_show(rule_id: str) -> None:
    """Show one allowlist rule in detail."""
    from .compatibility_allowlist import RuleNotFound, build_default_store

    store = build_default_store()
    try:
        rule = store.get(rule_id)
    except RuleNotFound:
        click.echo(f"no rule with id {rule_id!r}", err=True)
        sys.exit(1)
    click.echo(json.dumps(rule.to_dict(), indent=2))


@main.command("bouncer", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.pass_context
def bouncer_pointer(ctx: click.Context) -> None:
    """Pointer to the standalone `ibounce` binary (formerly
    `iam-jit-bouncer`; renamed in the v1.0 Bounce-suite rename).

    The bouncer is a separate product with its own entry point;
    this stub catches users who type `iam-jit bouncer ...` and
    redirects them to the right binary.
    """
    extra = " " + " ".join(ctx.args) if ctx.args else " --help"
    click.echo(
        "ibounce is a separate binary (was `iam-jit-bouncer` before "
        "v1.0). Use it directly:",
        err=True,
    )
    click.echo(f"Run:   ibounce{extra}", err=True)
    sys.exit(2)


@main.group("mcp")
def mcp_group() -> None:
    """Wire iam-jit's MCP server into an agent runtime.

    iam-jit's MCP server speaks the open Model Context Protocol — any
    MCP-compatible agent (Claude Code, Cursor, Codex MCP, Devin,
    custom runtimes) can use it. The subcommands here help with the
    most-common integrations.
    """


def _mcp_server_config_dict() -> dict[str, object]:
    """The canonical JSON config snippet any MCP client ingests to
    use iam-jit as an MCP server (stdio transport). Centralized so
    `show-config`, `install-claude-code`, and `init-solo --print-mcp-config`
    all emit the SAME shape."""
    return {
        "mcpServers": {
            "iam-jit": {
                "command": "iam-jit",
                "args": ["mcp-server"],
            },
        },
    }


@mcp_group.command("show-config")
@click.option(
    "--pretty/--compact",
    default=True,
    show_default=True,
    help="Pretty-print the JSON (default) or emit compact.",
)
def mcp_show_config(pretty: bool) -> None:
    """Print the MCP server JSON config snippet to stdout.

    Vendor-neutral — paste into any MCP-compatible agent's config:
    Claude Code, Cursor, Codex MCP, Devin, custom. For Claude Code
    specifically, see `iam-jit mcp install-claude-code`.
    """
    cfg = _mcp_server_config_dict()
    click.echo(
        json.dumps(cfg, indent=2 if pretty else None,
                   separators=(", ", ": ") if pretty else (",", ":")),
    )


def _claude_desktop_config_path() -> pathlib.Path:
    """Best-effort detection of the Claude Desktop / Claude Code MCP
    config path on this platform. Returns the path even if the file
    doesn't exist yet (caller creates it).
    """
    import platform as _platform
    home = pathlib.Path.home()
    sysname = _platform.system()
    if sysname == "Darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if sysname == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return pathlib.Path(appdata) / "Claude" / "claude_desktop_config.json"
        return home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    # Linux + other
    return home / ".config" / "Claude" / "claude_desktop_config.json"


@mcp_group.command("install-claude-code")
@click.option(
    "--path",
    "explicit_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Override the default Claude Desktop config path. "
         "Default: ~/Library/Application Support/Claude/claude_desktop_config.json "
         "(macOS) / ~/.config/Claude/... (Linux) / %APPDATA%/Claude/... (Windows).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be written without modifying any file.",
)
@click.option(
    "--print-only",
    is_flag=True,
    default=False,
    help="Just print the JSON snippet + the target path; don't write.",
)
def mcp_install_claude_code(
    explicit_path: str | None,
    dry_run: bool,
    print_only: bool,
) -> None:
    """Install iam-jit as an MCP server in Claude Desktop / Claude Code config.

    Best-effort: detects the platform-appropriate config path,
    creates the parent directory if missing, and adds (or updates)
    the `mcpServers.iam-jit` entry. If you already have other
    mcpServers entries they are preserved. Existing iam-jit entries
    are OVERWRITTEN.

    After running, restart Claude Desktop / Claude Code so it
    re-reads the config.

    For other MCP clients (Cursor, Codex MCP, Devin, custom), use
    `iam-jit mcp show-config` and paste the snippet into your
    client's MCP config.
    """
    target = pathlib.Path(explicit_path) if explicit_path else _claude_desktop_config_path()
    snippet = _mcp_server_config_dict()

    if print_only or dry_run:
        click.echo(f"target config path: {target}")
        click.echo("")
        click.echo("would write / merge:")
        click.echo(json.dumps(snippet, indent=2))
        if dry_run:
            click.echo("")
            click.echo("(dry run; no changes made)")
        return

    # Load existing config if present; merge mcpServers.
    existing: dict[str, object] = {}
    if target.exists():
        try:
            existing = json.loads(target.read_text())
            if not isinstance(existing, dict):
                click.secho(
                    f"warning: {target} is not a JSON object; refusing to overwrite. "
                    "Pass --print-only and merge by hand.",
                    fg="red", err=True,
                )
                sys.exit(1)
        except json.JSONDecodeError as e:
            click.secho(
                f"warning: {target} is not valid JSON ({e}); refusing to overwrite. "
                "Pass --print-only and merge by hand.",
                fg="red", err=True,
            )
            sys.exit(1)

    mcp_servers = existing.setdefault("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        click.secho(
            f"warning: {target} has a non-object mcpServers value; refusing to overwrite. "
            "Pass --print-only and merge by hand.",
            fg="red", err=True,
        )
        sys.exit(1)
    overwriting = "iam-jit" in mcp_servers
    mcp_servers["iam-jit"] = snippet["mcpServers"]["iam-jit"]

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(existing, indent=2) + "\n")

    if overwriting:
        click.secho(f"✓ updated existing iam-jit MCP entry at {target}", fg="green")
    else:
        click.secho(f"✓ added iam-jit MCP server to {target}", fg="green")
    click.echo(
        "  Restart Claude Desktop / Claude Code so it re-reads the config. "
        "If you don't see iam-jit's tools after restart, run "
        "`iam-jit mcp show-config` and merge the snippet by hand."
    )


@main.command("mcp-server")
def mcp_server_cmd() -> None:
    """Run the iam-jit MCP server on stdio.

    Exposes iam-jit's tool surface to any MCP-compatible agent
    runtime (Claude Code, Cursor, Codex MCP, Devin, custom). The
    server speaks the open Model Context Protocol — agent-agnostic
    by spec.

    Communicates via JSON-RPC over stdin/stdout — one request per
    line. Typically launched by the agent's MCP host configuration.
    Use `iam-jit mcp install-claude-code` for the most-common path,
    or `iam-jit mcp show-config` for a vendor-neutral JSON snippet
    you paste into your client's MCP config.

    The agent has access to this live tool surface (see
    docs/AGENTS.md for the canonical self-scoping flow):

    Self-scoping + applicability:
      iam_jit_scope_self_for_task — the canonical first call:
                                   atomic compatibility check +
                                   bouncer task scope + JIT role
                                   issuance, returns scoped STS creds
      check_iam_jit_compatibility — verdict for a workload before
                                   any role request
      list_compatibility_overrides — read the admin allowlist

    Policy templates + scoring + submission:
      list_templates             — browse the AWS-managed + iam-jit catalog
      get_template               — fetch a template's policy shape by name
      score_iam_policy           — rate any policy 1-10 with per-factor breakdown
      submit_policy              — submit a finished policy for grant issuance
      save_template              — save a custom policy to your personal library
      list_my_templates          — list your saved policies
      get_my_template            — fetch one of your saved policies
      find_similar_templates     — find templates similar to a candidate

    Bouncer (local AWS-call gating proxy):
      bouncer_list_rules          — current gate rules
      bouncer_add_rule            — add a rule (audit-logged)
      bouncer_remove_rule         — remove a rule (audit-logged)
      bouncer_decide              — dry-run a hypothetical request
      bouncer_list_presets        — built-in protective baselines
      bouncer_show_preset         — inspect a preset
      bouncer_apply_preset        — apply a preset as rules
      bouncer_tail_decisions      — recent allow/deny decisions
      bouncer_tail_events         — recent config events
      bouncer_start_task          — declare a one-off task scope
      bouncer_active_task         — what's gating right now
      bouncer_end_task            — return to baseline
      bouncer_task_review         — per-task decision summary
      bouncer_effective_scope     — composed snapshot (task + global rules)
      bouncer_recommend_rules     — synthesize rules from observed traffic
      bouncer_apply_recommendation — bulk-add recommended rules

    Other:
      tail_grant                 — read recent CloudTrail events for a JIT grant

    Natural-language policy synthesis was removed in 0.4.0; the
    agent (with its codebase context + LLM) is the policy author
    now. The `generate_iam_policy` tool is a tombstone that returns
    a deprecation pointer.
    """
    from .mcp_server import main as mcp_main
    sys.exit(mcp_main())


# ---------------------------------------------------------------------------
# doctor — operational health checks for various integrations.
# ---------------------------------------------------------------------------


@main.group("license")
def license_group() -> None:
    """Inspect the iam-jit license + user-count cap (#161).

    Free tier: up to 25 users, no license file required.
    Pro / Team / Enterprise: install a signed license at
    `~/.iam-jit/license.json` (or `$IAM_JIT_LICENSE_FILE`) to raise
    the cap. The cap is enforced ONLY on new user creation; existing
    users keep working.

    No phone home, no telemetry, no licensing call-back.
    """


@license_group.command("show")
def license_show() -> None:
    """Show the active license + current cap. Exit 0 always."""
    from . import license as _license_mod

    try:
        lic = _license_mod.load_license()
    except _license_mod.LicenseInvalidError as e:
        click.secho("license: REJECTED", fg="red", bold=True)
        click.echo(f"  reason:    {e}")
        click.echo(f"  fallback:  Free tier (cap {_license_mod.FREE_TIER_MAX_USERS})")
        sys.exit(0)
    if lic is None:
        click.secho(
            f"license: not installed (Free tier, cap {_license_mod.FREE_TIER_MAX_USERS} users)",
            fg="yellow",
        )
        click.echo(
            "  to raise the cap, install a signed license at "
            f"{os.environ.get(_license_mod.LICENSE_PATH_ENV) or '~/.iam-jit/license.json'}"
        )
        sys.exit(0)
    click.secho(f"license: ACTIVE ({lic.tier})", fg="green", bold=True)
    click.echo(f"  issued_to:  {lic.issued_to}")
    click.echo(f"  license_id: {lic.license_id}")
    click.echo(f"  max_users:  {lic.max_users}")
    click.echo(f"  issued_at:  {lic.issued_at.isoformat()}")
    click.echo(f"  expires_at: {lic.expires_at.isoformat()} ({lic.days_until_expiry} days)")


@license_group.command("verify")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
def license_verify(path: str) -> None:
    """Verify a license file at PATH and print a structured report.

    Use this BEFORE moving a license file into place so a bad signature
    or expired license is caught with a clear error rather than a
    silent Free-tier fallback at server-start time."""
    from . import license as _license_mod

    try:
        lic = _license_mod.load_license(path=path)
    except _license_mod.LicenseInvalidError as e:
        click.secho(f"INVALID: {e}", fg="red", bold=True, err=True)
        sys.exit(1)
    if lic is None:
        click.secho("license file is empty or unreadable", fg="red", bold=True, err=True)
        sys.exit(1)
    click.secho(f"VALID — tier={lic.tier} max_users={lic.max_users}", fg="green", bold=True)
    click.echo(f"issued_to:  {lic.issued_to}")
    click.echo(f"expires_at: {lic.expires_at.isoformat()}")


@main.group("doctor")
def doctor() -> None:
    """Health checks for iam-jit integrations.

    Validates configuration + connectivity for the various
    integrations iam-jit supports. Use during onboarding to
    catch misconfiguration before deploying to production.
    """


@doctor.command("slack")
@click.option(
    "--channel",
    default=None,
    help="Channel ID to test posting to. Defaults to IAM_JIT_SLACK_APPROVAL_CHANNEL.",
)
def doctor_slack(channel: str | None) -> None:
    """Validate Slack approval-bot configuration.

    Checks:
      ✓ Env vars present (bot token + signing secret + channel)
      ✓ Bot token authenticates (auth.test)
      ✓ Bot can read its own user info
      ✓ Bot has chat:write scope (test post + delete to channel)
      ✓ Bot has users:read.email scope (helps approver resolution)
      ✓ Signing secret is plausibly-shaped (32+ chars hex)

    Exits 0 on all-green; non-zero on first failure. Suitable
    for CI / pre-deploy gating.
    """
    import os as _os

    from . import slack_bot

    failures: list[str] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        marker = "✓" if ok else "✗"
        color = "green" if ok else "red"
        click.secho(f"  {marker} {label}", fg=color, nl=False)
        if detail:
            click.echo(f" — {detail}")
        else:
            click.echo()
        if not ok:
            failures.append(label)

    click.secho("Slack approval-bot health check", fg="cyan", bold=True)
    click.echo()

    # 1. Env vars present
    bot_token = _os.environ.get("IAM_JIT_SLACK_BOT_TOKEN", "").strip()
    signing_secret = _os.environ.get("IAM_JIT_SLACK_SIGNING_SECRET", "").strip()
    approval_channel = (
        channel
        or _os.environ.get("IAM_JIT_SLACK_APPROVAL_CHANNEL", "").strip()
        or None
    )

    check("IAM_JIT_SLACK_BOT_TOKEN present", bool(bot_token))
    check("IAM_JIT_SLACK_SIGNING_SECRET present", bool(signing_secret))
    check("IAM_JIT_SLACK_APPROVAL_CHANNEL present", bool(approval_channel))

    if not (bot_token and signing_secret):
        click.echo()
        click.secho(
            "Cannot continue — bot_token and signing_secret are required.",
            fg="red",
        )
        sys.exit(1)

    # Signing secret shape (a sanity-check, not a real validation —
    # Slack signing secrets are 32-char hex but the exact format
    # has changed slightly over time).
    sig_shape_ok = len(signing_secret) >= 32
    check(
        f"Signing secret length plausible ({len(signing_secret)} chars; expected ≥32)",
        sig_shape_ok,
    )

    # 2. auth.test — bot token validates + bot identity
    import httpx as _httpx

    try:
        resp = _httpx.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {bot_token}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        auth = resp.json()
    except Exception as e:
        check("auth.test reachable", False, f"http error: {e}")
        sys.exit(1)

    if not auth.get("ok"):
        check("auth.test ok", False, f"error: {auth.get('error')!r}")
        sys.exit(1)
    workspace = auth.get("team", "<unknown>")
    user = auth.get("user", "<unknown>")
    bot_user_id = auth.get("user_id", "<unknown>")
    check(
        f"auth.test ok",
        True,
        f"workspace={workspace} bot={user} ({bot_user_id})",
    )

    # 3. Test approval-channel post (if channel set)
    if approval_channel:
        try:
            cfg = slack_bot.SlackConfig(
                bot_token=bot_token,
                signing_secret=signing_secret,
                approval_channel=approval_channel,
            )
            test_payload = {
                "channel": approval_channel,
                "text": "iam-jit doctor: health-check ping (delete me if it lands)",
            }
            post = _httpx.post(
                "https://slack.com/api/chat.postMessage",
                headers={
                    "Authorization": f"Bearer {bot_token}",
                    "Content-Type": "application/json; charset=utf-8",
                },
                json=test_payload,
                timeout=10.0,
            )
            post.raise_for_status()
            post_resp = post.json()
        except Exception as e:
            check(
                f"chat.postMessage to {approval_channel}",
                False,
                f"http error: {e}",
            )
            sys.exit(1)
        if not post_resp.get("ok"):
            check(
                f"chat.postMessage to {approval_channel}",
                False,
                f"slack error: {post_resp.get('error')!r}",
            )
            sys.exit(1)
        ts = post_resp.get("ts")
        check(
            f"chat.postMessage to {approval_channel}",
            True,
            f"posted (ts={ts}); delete the test message manually",
        )

    # 4. Check users.info works (we use it for approver resolution)
    try:
        info = _httpx.get(
            "https://slack.com/api/users.info",
            headers={"Authorization": f"Bearer {bot_token}"},
            params={"user": bot_user_id},
            timeout=10.0,
        )
        info.raise_for_status()
        info_resp = info.json()
    except Exception as e:
        check("users.info reachable", False, f"http error: {e}")
        sys.exit(1)
    if not info_resp.get("ok"):
        check(
            "users.info ok",
            False,
            f"error: {info_resp.get('error')!r}. Add 'users:read' scope to the bot.",
        )
        sys.exit(1)
    has_email = bool(
        ((info_resp.get("user") or {}).get("profile") or {}).get("email")
    )
    check(
        "users.info ok",
        True,
        f"bot can read user records (own email in profile: {has_email})",
    )
    if not has_email:
        click.secho(
            "  ⚠  users:read.email scope may not be granted. Approver "
            "resolution by email won't work. Add the scope in the Slack App "
            "config + re-install.",
            fg="yellow",
        )

    click.echo()
    if failures:
        click.secho(
            f"FAILED: {len(failures)} check(s) failed: {', '.join(failures)}",
            fg="red",
            bold=True,
        )
        sys.exit(1)
    click.secho("All Slack checks passed.", fg="green", bold=True)
    if approval_channel:
        click.echo(
            f"\nA test message was posted to {approval_channel}. "
            f"Delete it manually if it bothers anyone."
        )


@doctor.command("oidc")
def doctor_oidc() -> None:
    """Validate OIDC SSO configuration.

    Checks:
      ✓ Provider env var set + valid
      ✓ Client ID / secret / redirect URI present
      ✓ Provider-specific required fields (e.g., HOSTED_DOMAIN for Google)
      ✓ Discovery doc reachable + endpoints valid
      ✓ JWKS reachable + contains usable signing keys

    Exits 0 on all-green.
    """
    import os as _os

    from . import oidc as _oidc

    failures: list[str] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        marker = "✓" if ok else "✗"
        color = "green" if ok else "red"
        click.secho(f"  {marker} {label}", fg=color, nl=False)
        if detail:
            click.echo(f" — {detail}")
        else:
            click.echo()
        if not ok:
            failures.append(label)

    click.secho("OIDC SSO health check", fg="cyan", bold=True)
    click.echo()

    # Env-var validation via the canonical config loader.
    try:
        cfg = _oidc.OIDCProviderConfig.from_env()
    except _oidc.ConfigError as e:
        check("OIDC env vars valid", False, str(e))
        sys.exit(1)
    if cfg is None:
        check(
            "OIDC env vars set",
            False,
            "IAM_JIT_OIDC_PROVIDER + CLIENT_ID + CLIENT_SECRET + REDIRECT_URI required",
        )
        sys.exit(1)
    check(
        "OIDC env vars valid",
        True,
        f"provider={cfg.provider} issuer={cfg.issuer}",
    )
    if cfg.provider == "google":
        check(
            "Google hosted_domain set",
            bool(cfg.hosted_domain),
            f"hd={cfg.hosted_domain}",
        )

    # Discovery doc.
    client = _oidc.HttpxClient()
    try:
        endpoints = _oidc.discover(cfg, client)
    except _oidc.ConfigError as e:
        check("Discovery doc reachable", False, str(e))
        sys.exit(1)
    check(
        "Discovery doc reachable",
        True,
        f"jwks={endpoints.jwks_uri}",
    )

    # JWKS fetch.
    cache = _oidc.JWKSCache(client)
    try:
        # We don't know a real kid; just fetch the JWKS doc to confirm reachability.
        jwks = client.get_json(endpoints.jwks_uri)
        keys = jwks.get("keys") or []
        check(
            "JWKS reachable + has keys",
            len(keys) > 0,
            f"{len(keys)} key(s)",
        )
    except Exception as e:
        check("JWKS reachable", False, str(e))
        sys.exit(1)

    click.echo()
    if failures:
        click.secho(
            f"FAILED: {len(failures)} check(s)",
            fg="red",
            bold=True,
        )
        sys.exit(1)
    click.secho("All OIDC checks passed.", fg="green", bold=True)


@doctor.command("compatibility")
@click.option(
    "--workload",
    required=True,
    help="Workload shape to check (e.g. lambda_function, k8s_pod, "
         "ec2_instance, ci_runner, codebuild_project).",
)
@click.option(
    "--target-account-id",
    default=None,
    help="Optional AWS account ID (12 digits) for the check.",
)
@click.option(
    "--target-service",
    "target_services",
    multiple=True,
    help="Optional service prefix the workload needs to call. Repeatable.",
)
@click.option(
    "--description",
    default=None,
    help="Optional free-form task description.",
)
@click.option(
    "--existing-role-hint",
    default=None,
    help="Optional ARN of an existing role you suspect might fit.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit the verdict as JSON instead of human-readable text.",
)
def doctor_compatibility(
    workload: str,
    target_account_id: str | None,
    target_services: tuple[str, ...],
    description: str | None,
    existing_role_hint: str | None,
    as_json: bool,
) -> None:
    """Check whether iam-jit can issue a role for a given workload
    BEFORE submitting a request.

    Runs the same applicability check the HTTP + MCP submit paths
    use (#166 Slices 1+2+3) and prints a self-describing verdict +
    next-action hint. Exits 0 only when the verdict is PROCEED.

    Examples:

      iam-jit doctor compatibility --workload ci_runner

      iam-jit doctor compatibility --workload k8s_pod \\
          --target-account-id 123456789012 \\
          --target-service s3 --target-service dynamodb

    This is workload classification only — iam-jit does NOT inspect
    source code or external systems. The agent / human declares the
    workload; the checker uses it.
    """
    # `json` is already imported at module top; alias is fine
    # for clarity but redundant. Use module-level json directly.
    import re as _re

    from .compatibility import (
        Compatibility,
        CompatibilityIntent,
        WorkloadType,
        check_compatibility,
        default_audit_sink,
    )

    try:
        workload_enum = WorkloadType(workload.strip())
    except ValueError:
        valid = ", ".join(w.value for w in WorkloadType)
        click.secho(
            f"unknown workload {workload!r}; must be one of: {valid}",
            fg="red",
            err=True,
        )
        sys.exit(2)

    if target_account_id is not None:
        if not _re.match(r"^[0-9]{12}$", target_account_id):
            click.secho(
                "--target-account-id must be exactly 12 digits",
                fg="red",
                err=True,
            )
            sys.exit(2)

    services_clean: list[str] = []
    for s in target_services:
        s_norm = s.strip().lower()
        if not s_norm:
            continue
        if not _re.match(r"^[a-z][a-z0-9-]{1,62}$", s_norm):
            click.secho(
                f"--target-service {s!r} is not a valid service prefix "
                "(lowercase, start with a letter, max 63 chars)",
                fg="red",
                err=True,
            )
            sys.exit(2)
        services_clean.append(s_norm)

    intent = CompatibilityIntent(
        workload=workload_enum,
        target_account_id=target_account_id,
        target_services=tuple(services_clean),
        description=description,
        existing_role_hint=existing_role_hint,
    )

    try:
        from .compatibility_allowlist import build_default_store
        allowlist = build_default_store()
    except Exception:
        allowlist = None

    # WB29 HIGH-29-02 closure: pass audit_sink so doctor invocations
    # land in the audit chain alongside HTTP + MCP submissions.
    result = check_compatibility(
        intent,
        allowlist=allowlist,
        audit_sink=default_audit_sink(),
        actor="cli:doctor",
    )

    if as_json:
        click.echo(json.dumps({
            "verdict": result.verdict.value,
            "reasoning": result.reasoning,
            "next_action_hint": result.next_action_hint,
            "matched_pattern": result.matched_pattern,
            "bouncer_recommended": result.bouncer_recommended,
            "existing_role_arn": result.existing_role_arn,
        }, indent=2))
    else:
        verdict_color = {
            Compatibility.PROCEED: "green",
            Compatibility.USE_EXISTING: "yellow",
            Compatibility.USE_BOUNCER: "yellow",
            Compatibility.CANNOT_HELP: "red",
        }.get(result.verdict, "white")
        click.secho(
            f"verdict:    {result.verdict.value}",
            fg=verdict_color,
            bold=True,
        )
        click.echo(f"reasoning:  {result.reasoning}")
        if result.next_action_hint:
            click.echo(f"next:       {result.next_action_hint}")
        if result.matched_pattern:
            click.echo(f"matched:    {result.matched_pattern}")
        if result.existing_role_arn:
            click.echo(f"role hint:  {result.existing_role_arn}")
        if result.bouncer_recommended:
            click.echo(
                "bouncer:    recommended — consider ibounce "
                "(local AWS-call gating proxy) for this workload"
            )

    # Exit 0 only for PROCEED so the command composes with `&&` in
    # scripts ("if iam-jit can serve me, run my submit").
    sys.exit(0 if result.verdict == Compatibility.PROCEED else 1)


# #271 — register the `iam-jit audit query` cross-bouncer subcommand.
# Lives in a separate module so the heavy aiohttp / thread-pool /
# OCSF-bundle code doesn't pull into every CLI surface. The register
# call wires the subgroup onto the existing `main` Click group.
from .cli_audit_query import register_audit_query_group  # noqa: E402
audit_group = register_audit_query_group(main)

# #272 — register `iam-jit audit stream` (live cross-bouncer TUI).
# Hung off the same `audit` group so the operator's mental model is
# "audit query is a one-shot; audit stream is the live tail".
from .cli_audit_stream import register_audit_stream_command  # noqa: E402
register_audit_stream_command(audit_group)

# #285 — register `iam-jit session replay <FILE>` (cross-product session
# replay). Lives in its own module so the (small) profile-evaluator
# imports don't pull into every CLI surface. Mounts under a fresh
# `session` group sibling to `audit` per the spec.
from .cli_session_replay import register_session_replay_group  # noqa: E402
register_session_replay_group(main)

# #324 — register `iam-jit deny` (SKELETON). Surfaces the planned
# dynamic-deny-rule CLI shape on `--help`; each subcommand exits 2
# with a structured "not implemented yet" payload pointing at the
# design doc + the slice tracking the implementation. The full impl
# replaces this skeleton in #324e. See docs/DYNAMIC-DENY-RULES.md.
from .cli_deny import register_deny_group  # noqa: E402
register_deny_group(main)

# #326 — register `iam-jit profile generate-from-audit` + siblings.
# LLM-generated bounce profiles. Lives in its own module so the LLM
# import surface (+ recommender) doesn't load on every CLI surface.
# Distinct from `[[no-nl-synthesis]]` which forbids NL->IAM-policy;
# bounce profiles are operator-reviewable config artifacts.
from .cli_profile_generate import register_profile_group  # noqa: E402
register_profile_group(main)

# #383 / §A42 — register `iam-jit posture` cross-product orchestrator.
# Reports "iam-jit role / bouncer / both / neither" + per-traffic-class
# protection. Backed by iam_jit.posture which is the SAME module the
# `iam_jit_posture` MCP tool calls — schema parity by construction.
from .cli_posture import register_posture_command  # noqa: E402
register_posture_command(main)


if __name__ == "__main__":
    main()
