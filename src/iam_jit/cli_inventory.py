# ADOPT-3 / #717 — `iam-jit inventory` Click command.
"""`iam-jit inventory` — enumerate the agent's MCP/A2A attack surface.

Thin shim over :func:`iam_jit.inventory.capture_inventory` +
:func:`render_inventory_table` so the same logic feeds the
``iam_jit_inventory`` MCP tool without duplication (mirrors the
posture CLI / MCP parity per [[cross-product-agent-parity]]).

Usage::

    iam-jit inventory                 # human-readable table
    iam-jit inventory --format json   # structured for agents / pipelines
    iam-jit inventory --format table  # explicit table (default)

Read-only: enumerates configured MCP servers + tools, wired bouncers +
their ports, and discoverable A2A endpoints. Never mutates any config,
never starts a process. Per [[ibounce-honest-positioning]] unknowns are
named (not fabricated) + per the #717 brief no token VALUE is emitted.
"""

from __future__ import annotations

import json

import click

from .inventory import (
    INVENTORY_SCHEMA_VERSION,
    capture_inventory,
    render_inventory_table,
)


def register_inventory_command(main_group: click.Group) -> click.Command:
    """Attach `inventory` to the top-level iam-jit Click group. Returns
    the command for inspection / test."""

    @main_group.command("inventory")
    @click.option(
        "--format",
        "fmt",
        type=click.Choice(["table", "json"]),
        default="table",
        show_default=True,
        help="Output format. ``json`` emits the structured snapshot "
        f"(schema version {INVENTORY_SCHEMA_VERSION}) for agent "
        "consumption / pipelines; ``table`` is the human banner.",
    )
    @click.option(
        "--no-sanitize",
        is_flag=True,
        default=False,
        hidden=True,
        help="Internal: disable the credential-scrubbing pass. ONLY for "
        "debugging the sanitizer itself; never use in production.",
    )
    def inventory_cmd(fmt: str, no_sanitize: bool) -> None:
        """Enumerate everything your agent can reach / be reached through.

        Lists the configured MCP servers (and, where discoverable, their
        tools), the bouncers wired in + their loopback ports/endpoints,
        and any A2A / agent endpoints — each tagged with risk-relevant
        metadata (loopback-only? authed?).

        Per [[ibounce-honest-positioning]] the output reports ONLY what
        is actually discoverable; unknowns are marked ``unknown`` rather
        than fabricated. No token VALUE is ever printed — only whether a
        server carries auth + which field names hold it.
        """
        snapshot = capture_inventory(sanitize=not no_sanitize)
        if fmt == "json":
            click.echo(json.dumps(snapshot, indent=2, sort_keys=True))
        else:
            click.echo(render_inventory_table(snapshot))

    return inventory_cmd


__all__ = ["register_inventory_command"]
