"""#437 / §A71 — `iam-jit deployment-targets` Click subcommand-group.

Phase G of [[bouncer-informs-agent-informs-iam-jit]]. The
deployment-target taxonomy is declared in ``.iam-jit.yaml`` and is
the input the AGENT uses to scope a long-range audit query (#436)
when synthesising a per-target bouncer config.

Surfaces:

  iam-jit deployment-targets list             # print all declared
  iam-jit deployment-targets show <NAME>      # print one in detail

Both subcommands accept ``--config <PATH>`` to override the
auto-discovered declaration and ``--format json|yaml|table`` for
machine vs human consumption. Defaults to table for ``list`` and
JSON for ``show`` because ``show`` is what an agent pipes into a
``--scope-filter`` argument.

Per [[scorer-is-ground-truth]] this CLI is pure look-up — no
inference, no scoring. iam-jit just hands back what the operator
declared.

Per [[cross-product-agent-parity]] the same dimensions surface in
the ``bounce_deployment_targets_for_filter`` MCP tool so agents
get the identical wire shape.
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

import click


def register_deployment_targets_group(
    main_group: click.Group,
) -> click.Group:
    """Attach ``deployment-targets`` to the iam-jit Click root."""

    @main_group.group("deployment-targets")
    def deployment_targets_group() -> None:
        """Read the operator-declared deployment-target taxonomy.

        Phase G of [[bouncer-informs-agent-informs-iam-jit]]: the
        agent reads this taxonomy to scope a long-range audit query
        (`iam-jit audit query --since 2y --scope-filter <classifier>`)
        when synthesising a per-target bouncer config.

        iam-jit provides the look-up; the AGENT does the synthesis.
        """

    @deployment_targets_group.command("list")
    @click.option(
        "--config",
        "config_path",
        type=click.Path(
            exists=True,
            dir_okay=False,
            readable=True,
            path_type=pathlib.Path,
        ),
        default=None,
        help=(
            "Path to an iam-jit declaration (.iam-jit.yaml or "
            "context file). Default: auto-discover under cwd."
        ),
    )
    @click.option(
        "--format",
        "fmt",
        type=click.Choice(["table", "json"], case_sensitive=False),
        default="table",
        show_default=True,
        help="Output format. `table` for humans; `json` for pipes.",
    )
    def list_cmd(
        config_path: pathlib.Path | None,
        fmt: str,
    ) -> None:
        """List every declared deployment-target with its classifier.

        \b
        Example:
          iam-jit deployment-targets list
          iam-jit deployment-targets list --format json

          # Agent pipes one target's classifier as a scope filter:
          iam-jit deployment-targets list --format json \\
            | jq '.targets[] | select(.name=="prod-k8s").classifier'
        """
        targets = _load_targets(config_path)
        if fmt.lower() == "json":
            payload = {
                "targets": [t.as_dict() for t in targets],
            }
            click.echo(json.dumps(payload, indent=2))
            return
        # Table format. Honest about the empty case so the operator
        # sees "you haven't declared any" instead of a blank line.
        if not targets:
            click.echo(
                "(no deployment_targets declared in iam-jit config)",
            )
            return
        click.echo(
            f"{len(targets)} deployment-target(s):",
        )
        for t in targets:
            click.echo(f"")
            click.echo(f"  {t.name}")
            click.echo(f"    bouncer:   {t.bouncer}")
            if t.description:
                click.echo(f"    description: {t.description}")
            if not t.classifier:
                click.echo("    classifier: (no scope dimensions set)")
                continue
            click.echo("    classifier:")
            for dim, values in sorted(t.classifier.items()):
                joined = ", ".join(values) if values else "(empty)"
                click.echo(f"      {dim}: [{joined}]")

    @deployment_targets_group.command("show")
    @click.argument("name", type=str)
    @click.option(
        "--config",
        "config_path",
        type=click.Path(
            exists=True,
            dir_okay=False,
            readable=True,
            path_type=pathlib.Path,
        ),
        default=None,
        help=(
            "Path to an iam-jit declaration. Default: auto-discover."
        ),
    )
    @click.option(
        "--classifier-only",
        is_flag=True,
        default=False,
        help=(
            "Print ONLY the classifier dict (so an agent can pipe "
            "it directly to `iam-jit audit query --scope-filter`)."
        ),
    )
    def show_cmd(
        name: str,
        config_path: pathlib.Path | None,
        classifier_only: bool,
    ) -> None:
        """Print one deployment-target as JSON. Exits 1 if missing.

        \b
        Example:
          iam-jit deployment-targets show prod-k8s
          iam-jit deployment-targets show prod-k8s --classifier-only \\
            > /tmp/prod-scope.json
        """
        from .deployment_targets import (
            DeploymentTargetError,
            load_deployment_target,
        )

        declaration = _load_declaration_dict(config_path)
        try:
            target = load_deployment_target(declaration, name)
        except DeploymentTargetError as e:
            click.echo(
                json.dumps({
                    "status": "error",
                    "code": e.code,
                    "message": str(e),
                }, indent=2),
                err=True,
            )
            sys.exit(1)
        if classifier_only:
            click.echo(json.dumps(target.classifier, indent=2))
            return
        click.echo(json.dumps(target.as_dict(), indent=2))

    return deployment_targets_group


def _load_declaration_dict(
    config_path: pathlib.Path | None,
) -> dict[str, Any]:
    """Common declaration loader. Surfaces an explicit ClickException
    when load fails so the operator sees the schema-validation error
    inline (rather than a stack trace)."""
    from .ambient_config.loader import load_declaration
    try:
        if config_path is not None:
            declaration, _src = load_declaration(config_path)
        else:
            declaration, _src = load_declaration(None)
    except Exception as e:
        raise click.ClickException(
            f"failed to load iam-jit declaration: {e}",
        ) from e
    return declaration


def _load_targets(
    config_path: pathlib.Path | None,
) -> list[Any]:
    from .deployment_targets import list_deployment_targets
    declaration = _load_declaration_dict(config_path)
    try:
        return list_deployment_targets(declaration)
    except Exception as e:
        raise click.ClickException(
            f"failed to read deployment_targets block: {e}",
        ) from e
