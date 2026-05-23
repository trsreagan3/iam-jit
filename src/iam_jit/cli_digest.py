"""#412 / §A56 — ``iam-jit digest`` CLI.

Cross-bouncer "your bouncer week in review" summary. Mirrors the
``bounce_digest_recent`` MCP tool per ``[[cross-product-agent-parity]]``;
both surfaces share the same :func:`iam_jit.digest.build_digest`
backend so the wire shape is identical.

Per ``[[ambient-value-prop-and-friction-framing]]`` the terminal +
markdown + HTML renderers all LEAD with caught-framing
("Your bouncer week in review"), never deficit-framing
("BLOCKED: 3 requests").

Per ``[[creates-never-mutates]]`` the digest is read-only — no profile
mutations, no audit emits, no queue writes.

Per ``[[v1-scope-bar]]`` we ship terminal + JSON + Markdown + HTML
exports. No separate web UI.
"""

from __future__ import annotations

import json as _json
import pathlib
import sys
from typing import Any

import click

from .digest import (
    DigestError,
    build_digest,
    render_html,
    render_json,
    render_markdown,
    render_terminal,
)


def _do_digest(
    *,
    since: str,
    bouncer: str | None,
    as_json: bool,
    export_format: str | None,
    out: pathlib.Path | None,
) -> int:
    """Backend for the CLI command. Returns an exit code.

    Per ``[[ibounce-honest-positioning]]`` adversarial denies bubble
    into the exit code: when ``--json`` is NOT set AND any deny was
    classified ``appears_adversarial``, exit code is ``3`` so an
    operator's CI / shell wrapper can branch on "did something need my
    attention?". Quiet weeks + ambiguous-only weeks exit ``0``.
    """
    try:
        data = build_digest(since=since, bouncer=bouncer)
    except DigestError as e:
        payload = {"status": "error", "code": e.code, "message": str(e)}
        if as_json or export_format == "json":
            click.echo(_json.dumps(payload, indent=2))
        else:
            click.secho(f"digest: {e}", fg="red", err=True)
        return 2
    except Exception as e:  # pragma: no cover
        payload = {"status": "error", "code": "unexpected", "message": str(e)}
        if as_json or export_format == "json":
            click.echo(_json.dumps(payload, indent=2))
        else:
            click.secho(f"digest: {e}", fg="red", err=True)
        return 2

    # Render.
    fmt = (export_format or ("json" if as_json else "terminal")).lower()
    if fmt == "json":
        rendered = render_json(data)
    elif fmt == "md" or fmt == "markdown":
        rendered = render_markdown(data)
    elif fmt == "html":
        rendered = render_html(data)
    elif fmt == "terminal":
        rendered = render_terminal(data)
    else:
        click.secho(
            f"digest: unsupported --export-format {fmt!r}; "
            "use one of md / html / json",
            fg="red",
            err=True,
        )
        return 2

    # Emit.
    if out is not None:
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(rendered)
        except OSError as e:
            click.secho(f"digest: could not write {out}: {e}", fg="red", err=True)
            return 2
        if not (as_json or export_format == "json"):
            click.secho(f"digest written to {out}", fg="green")
    else:
        click.echo(rendered)

    # Adversarial-classified denies set a non-zero exit so CI / shell
    # wrappers ("did anything need my attention this week?") can branch.
    adv = int((data.totals or {}).get("total_appears_adversarial") or 0)
    if adv > 0:
        return 3
    return 0


def register_digest_command(parent_group: click.Group) -> click.Command:
    """Attach `digest` to the top-level iam-jit Click group."""

    @parent_group.command("digest")
    @click.option(
        "--since",
        default="1w",
        show_default=True,
        help="Window lookback: `5m` / `1h` / `2d` / `1w` or an ISO 8601 "
             "lower bound.",
    )
    @click.option(
        "--bouncer",
        type=click.Choice(["ibounce", "kbouncer", "dbounce", "gbounce"]),
        default=None,
        help="Restrict to a single bouncer. Default: every reachable "
             "bouncer the autopilot status file knows about.",
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit JSON (same shape as the `bounce_digest_recent` MCP tool).",
    )
    @click.option(
        "--export-format",
        type=click.Choice(["md", "markdown", "html", "json"]),
        default=None,
        help="Render in this format instead of the terminal default. "
             "Use with --out to write to a file.",
    )
    @click.option(
        "--out",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
        help="Write the rendered digest to this file instead of stdout.",
    )
    def digest_cmd(
        since: str,
        bouncer: str | None,
        as_json: bool,
        export_format: str | None,
        out: pathlib.Path | None,
    ) -> None:
        """Weekly "your bouncer caught X" digest (cross-bouncer summary).

        Positive-signal counterweight to the deny-notification channel:
        leads with "your bouncer week in review", surfaces audited /
        caught counts side-by-side, and recommends pattern-generalize
        actions when 5+ allows share a prefix.

        \b
        Examples:
          iam-jit digest                                # 1-week terminal summary
          iam-jit digest --since 1d                     # 24-hour terminal summary
          iam-jit digest --bouncer ibounce              # one bouncer only
          iam-jit digest --json | jq .totals            # structured for agent
          iam-jit digest --export-format md --out /tmp/digest.md
          iam-jit digest --export-format html --out /tmp/digest.html

        Exit codes:
          0 — clean week (or only legit / ambiguous denies)
          2 — digest could not be built (e.g. bad --since)
          3 — at least one adversarial-classified deny in window
        """
        sys.exit(_do_digest(
            since=since,
            bouncer=bouncer,
            as_json=as_json,
            export_format=export_format,
            out=out,
        ))

    return digest_cmd


def digest_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """MCP backend for ``bounce_digest_recent``. Mirrors ``iam-jit digest``.

    Returns the structured shape (:class:`iam_jit.digest.DigestData` as
    a dict). On error returns a ``{"status": "error", ...}`` payload
    rather than raising — the MCP dispatch loop turns raises into
    JSON-RPC errors which agents handle worse than structured results.
    """
    since = args.get("since") or "1w"
    bouncer_raw = args.get("bouncer")
    bouncer = str(bouncer_raw) if bouncer_raw else None
    try:
        data = build_digest(since=str(since), bouncer=bouncer)
    except DigestError as e:
        return {
            "status": "error",
            "code": e.code,
            "message": str(e),
        }
    except Exception as e:
        return {
            "status": "error",
            "code": "unexpected",
            "message": str(e),
        }
    payload = data.as_dict()
    # Add a status + a human summary for agents that surface the text
    # back to the operator without parsing the structured fields.
    payload["status"] = "ok"
    payload["summary"] = render_terminal(data, use_color=False)
    return payload


__all__ = [
    "digest_for_mcp",
    "register_digest_command",
]
