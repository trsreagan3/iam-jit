"""#400 — `iam-jit doctor apply-config` Click subcommand.

Thin CLI shim over ``iam_jit.ambient_config.apply_declaration``.

Usage:

  iam-jit doctor apply-config                       # auto-discover + apply
  iam-jit doctor apply-config --config .iam-jit.yaml
  iam-jit doctor apply-config --dry-run             # plan; don't execute
  iam-jit doctor apply-config --inspect             # validate only
  iam-jit doctor apply-config --json                # structured output

Per the spec, this is implemented as a SUBCOMMAND of the existing
`iam-jit doctor` group rather than a top-level command. The doctor
group is the operator's "health check + apply" surface for
integrations; adding `apply-config` there fits the operator's mental
model.

The default surface is human-readable; pass --json for the structured
result (mirrors the MCP tool's `structuredContent`).
"""

from __future__ import annotations

import json as _json
import pathlib
import sys
from typing import Any

import click

from .ambient_config import (
    ConfigLoadError,
    apply_declaration,
    load_declaration,
    plan_declaration,
)


def register_apply_config_command(doctor_group: click.Group) -> click.Command:
    """Attach ``apply-config`` to the existing `iam-jit doctor` group.

    Returns the command so tests can invoke it via
    ``CliRunner.invoke(doctor.commands["apply-config"], [...])``.
    """

    @doctor_group.command("apply-config")
    @click.option(
        "--config",
        "config_path",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
        help="Path to the declaration: either a standalone "
             "`.iam-jit.yaml` OR a context file (CLAUDE.md / "
             "AGENTS.md / .cursorrules) containing a fenced "
             "`iam-jit-config` YAML codeblock. Default: auto-discover "
             "in the current working directory.",
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        default=False,
        help="Plan what would happen + print the result, but DO NOT "
             "start any bouncers or emit audit events. Always safe.",
    )
    @click.option(
        "--inspect",
        is_flag=True,
        default=False,
        help="Validate the declaration against the schema + print the "
             "parsed shape. Does NOT execute the plan and does NOT "
             "touch posture. Use to debug schema errors in CI.",
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured result as JSON (mirrors the "
             "iam_jit_setup_from_config MCP tool's `structuredContent`).",
    )
    @click.option(
        "--cwd",
        type=click.Path(file_okay=False, dir_okay=True, path_type=pathlib.Path),
        default=None,
        help="Override the auto-discovery cwd; only meaningful when "
             "--config is not passed.",
    )
    def apply_config_cmd(
        config_path: pathlib.Path | None,
        dry_run: bool,
        inspect: bool,
        as_json: bool,
        cwd: pathlib.Path | None,
    ) -> None:
        """Apply (or plan / validate) an iam-jit ambient declaration.

        Reads a `.iam-jit.yaml` (or a CLAUDE.md / AGENTS.md / .cursorrules
        file containing a fenced `iam-jit-config` YAML block), validates
        it against the published JSON schema, then for each enabled
        bouncer starts it (or plans to in --dry-run) + emits an
        admin_action.setup.applied OCSF audit event.

        Per [[creates-never-mutates]] a bouncer that is ALREADY RUNNING
        with a different config is NOT restarted; a warning is emitted +
        the operator must stop it manually + re-run.

        Per [[ibounce-honest-positioning]] every `when_X_present`
        heuristic resolves with its inputs visible in the output.
        """
        # Load + validate.
        try:
            declaration, source_label = load_declaration(
                config_path if config_path else None,
                cwd=cwd,
            )
        except ConfigLoadError as e:
            payload = {
                "status": "error",
                "code": e.code,
                "message": str(e),
                "source": e.source,
                "details": e.details,
            }
            if as_json:
                click.echo(_json.dumps(payload, indent=2))
            else:
                click.secho(
                    f"apply-config: {e.message}",
                    fg="red",
                    err=True,
                )
                if e.details and e.details.get("errors"):
                    for err in e.details["errors"]:
                        click.secho(
                            f"  - {err['path']}: {err['message']}",
                            err=True,
                        )
            sys.exit(2)

        # --inspect: validation only. Surface any posture cross-field
        # warnings the loader stashed (e.g. ambient + fail_on_deny).
        if inspect:
            posture_warnings = list(
                declaration.get("__posture_warnings__", []) or []
            )
            # Don't leak the sentinel key in the rendered declaration.
            clean_declaration = {
                k: v for k, v in declaration.items()
                if k != "__posture_warnings__"
            }
            payload = {
                "status": "ok",
                "validated": True,
                "source": source_label,
                "declaration": clean_declaration,
                "warnings": posture_warnings,
            }
            if as_json:
                click.echo(_json.dumps(payload, indent=2))
            else:
                click.secho(
                    f"declaration at {source_label} is VALID",
                    fg="green",
                )
                if posture_warnings:
                    click.echo()
                    click.secho("Posture warnings:", fg="yellow", bold=True)
                    for w in posture_warnings:
                        click.secho(f"  - {w}", fg="yellow")
                    click.echo()
                click.echo(_json.dumps(clean_declaration, indent=2))
            return

        # Plan or apply.
        if dry_run:
            result = plan_declaration(declaration, source=source_label)
        else:
            result = apply_declaration(
                declaration, source=source_label, execute=True
            )

        if as_json:
            click.echo(_json.dumps(result.as_dict(), indent=2, default=str))
            # Exit 1 if any warnings + dry-run for CI gating?
            # No — default exit 0; operators wanting strictness can
            # parse the JSON.
            return

        # Human renderer.
        _render_human(result, dry_run=dry_run)

    return apply_config_cmd


def _render_human(result: Any, *, dry_run: bool) -> None:
    """Render a SetupResult for human consumption."""
    header = "DRY-RUN PLAN" if dry_run else "APPLY"
    click.secho(f"iam-jit setup-from-config: {header}", fg="cyan", bold=True)
    click.echo(f"  source: {result.declaration_source}")
    click.echo(f"  status: {result.status}")

    if result.status == "disabled":
        click.secho(
            "  declaration has iam-jit.enabled=false; setup is a no-op.",
            fg="yellow",
        )

    if result.resolved_conditionals:
        click.echo()
        click.secho("Conditional resolution:", bold=True)
        for r in result.resolved_conditionals:
            color = "green" if r["enabled_resolved"] else "yellow"
            click.secho(
                f"  - {r['bouncer']}: {r['evidence']}",
                fg=color,
            )

    if getattr(result, "bouncer_mode_resolutions", None):
        click.echo()
        click.secho(
            "Per-bouncer mode resolution (declared → runtime):", bold=True,
        )
        for r in result.bouncer_mode_resolutions:
            declared = r.get("mode_declared")
            runtime = r.get("mode_runtime")
            src = r.get("mode_source", "declaration")
            same = declared == runtime
            arrow = "" if same else f" (runtime alias: {runtime})"
            click.echo(
                f"  - {r['bouncer']}: mode={declared!r}{arrow} "
                f"mode_source={src!r}"
            )

    if result.bouncers_started:
        click.echo()
        click.secho("Bouncers started:", bold=True)
        for n in result.bouncers_started:
            click.secho(f"  - {n}", fg="green")

    if result.bouncers_already_running:
        click.echo()
        click.secho("Bouncers already running (left alone):", bold=True)
        for n in result.bouncers_already_running:
            click.echo(f"  - {n}")

    if result.bouncers_planned and dry_run:
        click.echo()
        click.secho("Bouncers planned (dry-run; not executed):", bold=True)
        for record in result.bouncers_planned:
            cmd_str = " ".join(record.get("command", []))
            click.echo(
                f"  - {record['name']} on port {record.get('port')}: {cmd_str}"
            )

    if result.bouncers_skipped:
        click.echo()
        click.secho("Bouncers skipped:", bold=True)
        for s in result.bouncers_skipped:
            click.secho(f"  - {s['name']}: {s['reason']}", fg="yellow")

    if result.env_vars_to_set:
        click.echo()
        click.secho("Env vars the agent should set:", bold=True)
        for k, v in result.env_vars_to_set.items():
            click.echo(f"  export {k}={v}")

    if result.profiles_installed:
        click.echo()
        click.secho("Profiles in use:", bold=True)
        for p in result.profiles_installed:
            click.echo(
                f"  - {p['bouncer']}: {p['profile_name']} "
                f"(source={p['source']})"
            )

    if result.warnings:
        click.echo()
        click.secho("Warnings:", fg="yellow", bold=True)
        for w in result.warnings:
            click.secho(f"  - {w}", fg="yellow")

    if result.audit_event_ids:
        click.echo()
        click.secho("Audit events emitted:", bold=True)
        for ev in result.audit_event_ids:
            click.echo(f"  - {ev}")

    click.echo()
    if dry_run:
        click.secho(
            "(dry-run — re-run without --dry-run to apply)", fg="cyan"
        )


def apply_config_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """MCP backend for ``iam_jit_setup_from_config``.

    ``args`` accepts:
      * declaration: dict | str — parsed YAML dict OR path string OR
                                  raw YAML text (newline-detected)
      * dry_run: bool (default False — MCP tool intended to ACT;
                  agents that want plan-only pass dry_run=True)
      * cwd: str — override auto-discovery cwd when declaration omitted
      * inspect: bool — validate only, no plan
    """
    declaration_arg = args.get("declaration")
    dry_run = bool(args.get("dry_run", False))
    inspect = bool(args.get("inspect", False))
    cwd = args.get("cwd")

    try:
        if isinstance(declaration_arg, dict):
            declaration, source_label = load_declaration(declaration_arg)
        elif declaration_arg is None:
            declaration, source_label = load_declaration(None, cwd=cwd)
        else:
            declaration, source_label = load_declaration(
                declaration_arg, cwd=cwd
            )
    except ConfigLoadError as e:
        return {
            "status": "error",
            "code": e.code,
            "message": str(e),
            "source": e.source,
            "details": e.details,
        }

    if inspect:
        posture_warnings = list(
            declaration.get("__posture_warnings__", []) or []
        )
        clean_declaration = {
            k: v for k, v in declaration.items()
            if k != "__posture_warnings__"
        }
        return {
            "status": "ok",
            "validated": True,
            "source": source_label,
            "declaration": clean_declaration,
            "warnings": posture_warnings,
        }

    if dry_run:
        result = plan_declaration(declaration, source=source_label)
    else:
        result = apply_declaration(
            declaration, source=source_label, execute=True
        )
    payload = result.as_dict()
    payload.setdefault("status", "ok")
    return payload


__all__ = [
    "apply_config_for_mcp",
    "register_apply_config_command",
]
