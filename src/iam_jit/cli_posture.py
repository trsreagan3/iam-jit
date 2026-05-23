"""#383 / §A42 — `iam-jit posture` Click command.

Cross-product orchestrator that surfaces which of the 4 modes
(iam-jit role / bouncer / both / neither) the operator + their
agents are currently operating in. Designed to be both
human-friendly + agent-consumable.

Usage:

  iam-jit posture                          # human-readable summary
  iam-jit posture --json                   # structured for agents
  iam-jit posture --check-direct           # warn loudly on DIRECT traffic
  iam-jit posture --exit-1-on-unprotected  # CI-gate use

Implementation is a thin shim over ``iam_jit.posture.capture_posture``
+ ``render_posture_human`` so the same logic feeds the
``iam_jit_posture`` MCP tool without code duplication.
"""

from __future__ import annotations

import json
import sys

import click

from .posture import (
    POSTURE_SCHEMA_VERSION,
    capture_posture,
    render_posture_human,
)


def register_posture_command(main_group: click.Group) -> click.Command:
    """Attach `posture` to the top-level iam-jit Click group. Returns
    the command so callers can inspect / test it. Idempotent: calling
    twice with the same group is a no-op (Click's add_command
    overwrites)."""

    @main_group.command("posture")
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured posture snapshot as JSON. Schema "
        f"version {POSTURE_SCHEMA_VERSION}. Designed for agent "
        "consumption / pipelines.",
    )
    @click.option(
        "--check-direct",
        is_flag=True,
        default=False,
        help="Print an extra loud warning section when any traffic "
        "class is DIRECT (UNPROTECTED). Useful as a pre-flight "
        "check before a sensitive operation.",
    )
    @click.option(
        "--exit-1-on-unprotected",
        is_flag=True,
        default=False,
        help="Exit with code 1 (not 0) if any traffic class is DIRECT. "
        "Useful for CI gates that should fail when the environment "
        "isn't running under the expected bouncer set.",
    )
    @click.option(
        "--no-sanitize",
        is_flag=True,
        default=False,
        hidden=True,
        help="Internal: disable the credential-scrubbing pass. ONLY "
        "for debugging the sanitizer itself; never use in production.",
    )
    def posture_cmd(
        as_json: bool,
        check_direct: bool,
        exit_1_on_unprotected: bool,
        no_sanitize: bool,
    ) -> None:
        """Report which iam-jit / bouncer mode you're operating in.

        Answers: "Am I behind iam-jit's scoped IAM role? Behind a
        bouncer? Both? Neither?" — for the operator's eyes AND for
        any MCP-connected agent (via the parallel `iam_jit_posture`
        tool).

        Per [[ibounce-honest-positioning]] the output is HONEST about
        uncertainty (reports "unknown" when it can't tell) + about
        misconfig (reports "MISCONFIGURED — env points at down
        bouncer" rather than silently claiming intercept).
        """
        snapshot = capture_posture(sanitize=not no_sanitize)
        if as_json:
            click.echo(json.dumps(snapshot, indent=2, sort_keys=True))
        else:
            click.echo(render_posture_human(snapshot))
            if check_direct and snapshot.get("unprotected_traffic_present"):
                click.echo("")
                click.secho(
                    "DIRECT TRAFFIC DETECTED — at least one of "
                    "AWS / K8s / DB / HTTP is going UNPROTECTED. "
                    "See the Effective Protection section above for "
                    "the per-class breakdown + Recommendations.",
                    err=True,
                    fg="red",
                    bold=True,
                )
        if exit_1_on_unprotected and snapshot.get(
            "unprotected_traffic_present"
        ):
            sys.exit(1)

    return posture_cmd


def posture_for_mcp(args: dict | None = None) -> dict:
    """MCP backend for the ``iam_jit_posture`` tool. Returns the
    sanitized posture snapshot. ``args`` is accepted for schema
    parity with other MCP handlers but currently unused — the
    snapshot is captured FRESH on every call (no caching) so agents
    that hot-poll see the live truth."""
    return capture_posture(sanitize=True)


__all__ = ["register_posture_command", "posture_for_mcp"]
