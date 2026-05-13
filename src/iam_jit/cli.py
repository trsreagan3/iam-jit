import json
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


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
@click.option(
    "--no-llm",
    is_flag=True,
    help="Skip LLM verb refinement; use task_intent.services/actions as-is.",
)
def suggest(path: pathlib.Path, no_llm: bool) -> None:
    """Draft a least-privilege policy for a request using policy_sentry."""
    from .suggest import suggest_policy

    request = load_request(path)
    policy = suggest_policy(request, use_llm=not no_llm)
    click.echo(json.dumps(policy, indent=2))


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


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
@click.option(
    "--no-llm",
    is_flag=True,
    help="Don't re-run LLM service refinement when re-suggesting after answers.",
)
def refine(path: pathlib.Path, no_llm: bool) -> None:
    """Detect overly-broad permissions and prompt for narrowing details.

    Answers are stored as `spec.resource_constraints`, then the policy is
    re-generated with those constraints applied.
    """
    from .narrow import apply_constraints, detect_broadness
    from .schema import dump_request
    from .suggest import suggest_policy

    request = load_request(path)
    policy = request["spec"].get("policy")
    if not policy:
        click.echo(
            f"{path}: no policy on the request — run `iam-jit suggest` first or paste one.",
            err=True,
        )
        sys.exit(2)

    questions = detect_broadness(policy, request)
    if not questions:
        click.echo("No broadness flags. Policy looks reasonably scoped.", err=True)
        return

    click.echo(f"Found {len(questions)} narrowing question(s):", err=True)
    answers: dict[str, list[str]] = {}
    for q in questions:
        click.echo()
        click.echo(f"[{q.severity}] {q.question}")
        if q.suggested_arn_format:
            click.echo(f"  example: {q.suggested_arn_format}")
        response = click.prompt(
            "Answer (comma-separated ARNs, or 'skip' to leave broad)", default="skip"
        )
        if response.strip().lower() == "skip":
            continue
        arns = [s.strip() for s in response.split(",") if s.strip()]
        if arns:
            answers[q.id] = arns

    if not answers:
        click.echo("No constraints added. Request unchanged.", err=True)
        return

    refined = apply_constraints(request, answers)
    refined["spec"]["policy"] = suggest_policy(refined, use_llm=not no_llm)
    path.write_text(dump_request(refined))
    click.echo(f"Wrote refined request to {path} with {len(answers)} constraint(s).", err=True)


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option("--port", default=8000, show_default=True, type=int, help="TCP port.")
@click.option(
    "--reload/--no-reload",
    default=True,
    show_default=True,
    help="Auto-reload on source changes (dev mode).",
)
@click.option(
    "--users-file",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
    help="Local users.yaml for FileUserStore (dev convenience).",
)
def serve(
    host: str,
    port: int,
    reload: bool,
    users_file: pathlib.Path | None,
) -> None:
    """Run the iam-jit FastAPI app locally.

    Defaults wire up FilesystemStore for requests (`./requests/`) and an
    insecure dev secret for sessions, so it just works on a laptop. For
    production, deploy via SAM and let the Lambda handler bring up the
    same FastAPI app with S3- and DynamoDB-backed stores.
    """
    import os
    import uvicorn

    os.environ.setdefault("IAM_JIT_DEV_INSECURE_SECRET", "1")
    os.environ.setdefault("IAM_JIT_AUTH_MODE", "local")
    if users_file:
        os.environ["IAM_JIT_USER_CONFIG_SOURCE"] = "file"
        os.environ["IAM_JIT_USERS_FILE_LOCAL_PATH"] = str(users_file.resolve())

    click.echo(f"Starting iam-jit on http://{host}:{port}", err=True)
    if users_file:
        click.echo(f"Users file: {users_file}", err=True)
    uvicorn.run(
        "iam_jit.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        reload_dirs=["src/iam_jit"] if reload else None,
    )


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


@main.command("agent-grant")
@click.option(
    "--task", "-t", required=True,
    help="Plain-English description of the task the role is for.",
)
@click.option(
    "--account", "-a", default=None,
    help="AWS account ID for ARN construction. Defaults to '*' wildcard.",
)
@click.option(
    "--region", "-r", default=None,
    help="AWS region. Defaults to '*' wildcard.",
)
@click.option(
    "--partition", default="aws",
    type=click.Choice(["aws", "aws-cn", "aws-us-gov"]),
    show_default=True,
)
@click.option(
    "--resource", "resources", multiple=True,
    help="Explicit resource ARN. Repeat for multiple. Caller-supplied "
         "ARNs are preferred over names extracted from --task.",
)
@click.option(
    "--bias",
    type=click.Choice(["allow", "deny"]),
    default="allow",
    show_default=True,
    help="When the task description is ambiguous, prefer broader "
         "actions (allow) or narrower (deny). `allow` is more usable; "
         "`deny` is safer for fully-automated agent loops.",
)
@click.option(
    "--duration-hours", "-h", type=int, default=1, show_default=True,
    help="How long the grant should last.",
)
@click.option(
    "--exclude-action", "exclude_actions", multiple=True,
    help="Refinement: action (or `service:*` glob) to exclude from the "
         "generated policy. Repeat for multiple. Use after reviewing a "
         "previous output that was too broad.",
)
@click.option(
    "--include-action", "include_actions", multiple=True,
    help="Refinement: extra action to include (must be service:Action "
         "form). Use after a previous output was too strict.",
)
@click.option(
    "--rationale", default="",
    help="Human-readable explanation for any refinement (--exclude-action / "
         "--include-action). Surfaces in audit logs.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["json", "policy", "human"]),
    default="human", show_default=True,
    help="`json` = full GenerationResult; `policy` = just the IAM policy "
         "JSON (pipe-friendly); `human` = formatted report.",
)
def agent_grant(
    task: str,
    account: str | None,
    region: str | None,
    partition: str,
    resources: tuple[str, ...],
    bias: str,
    duration_hours: int,
    exclude_actions: tuple[str, ...],
    include_actions: tuple[str, ...],
    rationale: str,
    output_format: str,
) -> None:
    """Generate a scoped IAM policy from a task description.

    Produces a minimum-scope policy for the described task, scores it
    via the deterministic risk engine, and surfaces refinement hints
    the caller can use to iterate. The output is consumable by an
    agent (`--format json`), a downstream pipeline (`--format policy`),
    or a human reviewer (`--format human`, the default).

    Examples:

      iam-jit agent-grant -t "read S3 logs from the prod-logs bucket"

      iam-jit agent-grant -t "deploy lambda incident-handler with role app-runtime-role" \\
                          --account 123456789012 --region us-east-1

      # Refine after seeing too-broad output:
      iam-jit agent-grant -t "deploy lambda" \\
                          --exclude-action iam:PassRole \\
                          --rationale "code-only deploy, role unchanged"
    """
    from .policy_gen import (
        BIAS_ALLOW, BIAS_DENY,
        GenerationContext, GenerationRequest, Refinement,
        generate_policy,
    )

    refinement = None
    if exclude_actions or include_actions or rationale:
        refinement = Refinement(
            exclude_actions=list(exclude_actions),
            include_actions=list(include_actions),
            rationale=rationale,
        )

    req = GenerationRequest(
        task_description=task,
        bias=BIAS_ALLOW if bias == "allow" else BIAS_DENY,
        context=GenerationContext(
            account_id=account,
            region=region,
            partition=partition,
            resources=list(resources),
        ),
        duration_hours=duration_hours,
        refinement=refinement,
    )
    result = generate_policy(req)

    if output_format == "json":
        # Full structured output for agents / MCP servers.
        payload = {
            "policy": result.policy,
            "matched_patterns": result.matched_patterns,
            "reasons": result.reasons,
            "confidence": result.confidence,
            "scored_risk": result.scored_risk,
            "risk_factors": result.risk_factors,
            "risk_suggestions": result.risk_suggestions,
            "suppressed_actions": result.suppressed_actions,
            "refinement_hints": result.refinement_hints,
            "unmatched_reason": result.unmatched_reason,
        }
        click.echo(json.dumps(payload, indent=2))
        return

    if output_format == "policy":
        # Just the IAM policy JSON, suitable for piping into
        # `aws iam create-policy --policy-document file://-`.
        if result.policy is None:
            click.echo(f"# No policy: {result.unmatched_reason}", err=True)
            sys.exit(2)
        click.echo(json.dumps(result.policy, indent=2))
        return

    # Human-readable report
    if result.policy is None:
        click.secho("No policy generated.", fg="yellow", err=True)
        click.echo(f"Reason: {result.unmatched_reason}", err=True)
        sys.exit(2)

    click.secho(f"Matched patterns: {', '.join(result.matched_patterns)}", fg="cyan")
    click.echo(f"Confidence: {result.confidence}/10 (1=high, 10=low)")
    risk_color = "green" if result.scored_risk and result.scored_risk <= 3 else (
        "yellow" if result.scored_risk and result.scored_risk <= 6 else "red"
    )
    click.secho(f"Risk score: {result.scored_risk}/10", fg=risk_color)
    click.echo()
    click.secho("Policy:", fg="cyan")
    click.echo(json.dumps(result.policy, indent=2))
    if result.risk_factors:
        click.echo()
        click.secho("Risk factors:", fg="cyan")
        for f in result.risk_factors[:5]:
            click.echo(f"  • {f}")
    if result.suppressed_actions:
        click.echo()
        click.secho(
            f"Suppressed by deny bias ({len(result.suppressed_actions)} actions):",
            fg="cyan",
        )
        for a in result.suppressed_actions[:5]:
            click.echo(f"  • {a}")
    if result.refinement_hints:
        click.echo()
        click.secho("Refinement hints:", fg="cyan")
        for h in result.refinement_hints:
            click.echo(f"  • {h}")
    if result.reasons:
        click.echo()
        click.secho("Generation notes:", fg="cyan")
        for r in result.reasons[:5]:
            click.echo(f"  • {r}")


@main.command("mcp-server")
def mcp_server_cmd() -> None:
    """Run the iam-jit MCP server on stdio.

    Exposes the policy-generation feature to MCP-aware agents
    (Claude Code, Claude Desktop, Cursor, custom Claude SDK builds).
    Communicates via JSON-RPC over stdin/stdout — one request per
    line. Typically launched by the agent's MCP host configuration:

    \b
    ~/.config/claude/mcp_settings.json:
    {
      "mcpServers": {
        "iam-jit": {
          "command": "iam-jit",
          "args": ["mcp-server"]
        }
      }
    }

    The agent then has access to the `generate_iam_policy` tool, which
    returns a scoped IAM policy + risk score + refinement hints for
    any task description it submits.
    """
    from .mcp_server import main as mcp_main
    sys.exit(mcp_main())


if __name__ == "__main__":
    main()
