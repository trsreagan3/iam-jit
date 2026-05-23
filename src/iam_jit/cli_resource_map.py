"""#420 / §A59 — `iam-jit resource-map` Click command.

Operator-side CLI sibling of the ``iam_jit_resource_map`` MCP tool.
Phase E of [[bouncer-informs-agent-informs-iam-jit]].

Usage:

  iam-jit resource-map \\
      --from-permissions /tmp/staging_perms.json \\
      --using staging_to_prod

  iam-jit resource-map \\
      --from-permissions /tmp/staging_perms.json \\
      --using staging_to_prod \\
      --config ./project/.iam-jit.yaml

The input file must be the JSON shape produced by
``iam-jit audit query --extract-permissions``. Output goes to stdout
(JSON) so it composes with shell pipes —

  iam-jit audit query --since 1h --bouncer ibounce \\
      --extract-permissions \\
  | jq '.' \\
  > /tmp/staging.json
  iam-jit resource-map --from-permissions /tmp/staging.json \\
      --using staging_to_prod

The CLI does NOT submit the mapped permission set anywhere — the next
step is the agent calling ``iam_jit_request_role_from_synthesis``
with this output (which carries the same structural shape plus a
``resource_mapping_applied`` field).

Per [[scorer-is-ground-truth]] pure substitution; no inference,
no scoring at this surface (scoring happens at the role-request
seam, not here).
"""

from __future__ import annotations

import json
import pathlib
import sys

import click

from .resource_map import (
    apply_resource_mapping_to_permissions,
    list_mappings_in_config,
    load_mapping_from_config,
)


def register_resource_map_command(main_group: click.Group) -> click.Command:
    """Attach ``resource-map`` to the top-level iam-jit Click group."""

    @main_group.command("resource-map")
    @click.option(
        "--from-permissions",
        "from_permissions",
        required=True,
        type=click.Path(
            exists=True,
            dir_okay=False,
            readable=True,
            path_type=pathlib.Path,
        ),
        help=(
            "JSON file produced by "
            "`iam-jit audit query --extract-permissions` (or a "
            "compatible hand-authored file with the same shape)."
        ),
    )
    @click.option(
        "--using",
        "using",
        required=True,
        type=str,
        help=(
            "Name of a `resource_mappings` entry in the loaded config "
            "(e.g. `staging_to_prod`). Run with `--list` to see the "
            "available names."
        ),
    )
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
            "context file). Default: auto-discover under cwd per "
            "the ambient-config loader."
        ),
    )
    @click.option(
        "--list",
        "list_only",
        is_flag=True,
        default=False,
        help=(
            "List available mapping names from the loaded config + "
            "exit. --using is ignored in this mode (still required "
            "by Click; pass any value)."
        ),
    )
    def resource_map_cmd(
        from_permissions: pathlib.Path,
        using: str,
        config_path: pathlib.Path | None,
        list_only: bool,
    ) -> None:
        """Apply a declared resource mapping to a permission set."""
        # Load the operator config (the source of mappings).
        from .ambient_config.loader import load_declaration
        try:
            if config_path is not None:
                declaration, source_label = load_declaration(config_path)
            else:
                declaration, source_label = load_declaration(None)
        except Exception as e:
            raise click.ClickException(
                f"failed to load iam-jit declaration: {e}",
            ) from e

        if list_only:
            names = list_mappings_in_config(declaration)
            if not names:
                click.echo(
                    f"no resource_mappings defined in {source_label}",
                    err=True,
                )
                sys.exit(1)
            click.echo(
                json.dumps({
                    "source": source_label,
                    "mappings": names,
                }, indent=2),
            )
            return

        try:
            mapping = load_mapping_from_config(declaration, using)
        except KeyError as e:
            raise click.ClickException(str(e)) from e
        except ValueError as e:
            raise click.ClickException(str(e)) from e

        try:
            perms_doc = json.loads(from_permissions.read_text())
        except json.JSONDecodeError as e:
            raise click.ClickException(
                f"--from-permissions: invalid JSON: {e}",
            ) from e
        if not isinstance(perms_doc, dict):
            raise click.ClickException(
                "--from-permissions must contain a JSON object "
                "(the shape produced by "
                "`iam-jit audit query --extract-permissions`).",
            )

        mapped = apply_resource_mapping_to_permissions(perms_doc, mapping)
        click.echo(json.dumps(mapped, indent=2))

    return resource_map_cmd
