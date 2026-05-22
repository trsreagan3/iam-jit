"""#324 — `iam-jit deny` subcommand-group SKELETON.

Cross-product dynamic-deny rules CLI surface. THIS module is the
SKELETON only (per [[ibounce-honest-positioning]]) — each command
exits 2 with a structured "not implemented yet" payload that points
back to the canonical design doc + the sub-task tracking refs. The
full implementation is broken out across #324a-f.

Why ship a skeleton at all
--------------------------

So `iam-jit deny --help` displays the planned command shape today.
That gives:

  * Operators a discoverable surface ("yes, this is coming; here's
    where to follow it").
  * Future implementation slices a contract to converge against
    (the command names + arg names + JSON shapes here are the
    contract; #324e replaces the bodies with real impl + MUST keep
    the surfaces identical or update the design doc first).
  * Agents inspecting the CLI via `--help` see the shape now without
    being misled — every command says "DESIGN; not implemented".

What this module deliberately does NOT do
-----------------------------------------

  * Read or write `~/.iam-jit/dynamic-denies.yaml`. The YAML
    schema lives at `docs/schemas/dynamic-denies-v1.json`; reading
    + writing it ships in #324e.
  * Talk to any bouncer. Cross-product fan-out ships in #324e.
  * Emit any OCSF audit event. The event shapes are spec'd in the
    design doc; emission ships per-bouncer in #324a-d + at the
    iam-jit-CLI level in #324e.
  * Implement the cross-protocol target resolver. The heuristics
    are spec'd in the design doc's `Cross-protocol target resolver`
    table; the resolver code lives in
    `src/iam_jit/dynamic_denies/resolver.py` (created in #324e).

Per ``[[deliberate-feature-completion]]``: this slice ships the
contract + skeleton + tracking. It does NOT claim partial
implementation. Each skeleton command's stderr message NAMES the
slice (#324a-f) that will replace it.

Per ``[[scorer-is-ground-truth]]``: no scoring claims here; dynamic
deny rules are operator-set policy, not scorer output.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import click


DESIGN_DOC_PATH = "docs/DYNAMIC-DENY-RULES.md"
"""Repo-relative path to the canonical design doc."""

DESIGN_DOC_URL = (
    "https://github.com/trsreagan3/iam-jit/blob/main/docs/DYNAMIC-DENY-RULES.md"
)
"""Web URL for the design doc — surfaced in the structured 'not
implemented yet' payload so operators clicking through from an agent
log can find it without `git clone`."""

SCHEMA_PATH = "docs/schemas/dynamic-denies-v1.json"
"""Repo-relative path to the canonical JSON schema for the on-disk YAML."""

TRACKING_REFS: dict[str, str] = {
    "#324a": "ibounce dynamic-deny core (ARN matcher + YAML watcher + decision pipeline + OCSF)",
    "#324b": "kbouncer dynamic-deny core (namespace/cluster matcher + YAML watcher)",
    "#324c": "dbounce dynamic-deny core (hostname/RDS pattern matcher + YAML watcher)",
    "#324d": "gbounce dynamic-deny core (URL/hostname glob matcher + YAML watcher)",
    "#324e": "iam-jit unified CLI + MCP + cross-bouncer fan-out (REPLACES this skeleton)",
    "#324f": "iam-jit recommender Deny-injection + role-effectiveness re-grade",
}
"""Sub-task tracking refs. The skeleton's stderr payload names the
slice that will replace each subcommand."""

REPLACEMENT_SLICE: dict[str, str] = {
    # Each skeleton command points at the slice that will REPLACE it.
    "add":    "#324e",
    "list":   "#324e",
    "remove": "#324e",
    "show":   "#324e",
}


def _not_implemented_payload(subcommand: str, **extra: Any) -> dict[str, Any]:
    """Build the structured 'not implemented yet' payload returned by
    every skeleton command.

    The shape is stable + documented — future tests + agent integrations
    can rely on the keys (`status`, `subcommand`, `tracking`, `design_doc`,
    `schema`, `replaced_by`) being present.
    """

    payload: dict[str, Any] = {
        "status": "not_implemented_yet",
        "subcommand": f"iam-jit deny {subcommand}",
        "message": (
            f"`iam-jit deny {subcommand}` is in DESIGN. See the design doc "
            f"for the planned CLI + MCP + YAML wire shapes; the "
            f"implementation lands in {REPLACEMENT_SLICE[subcommand]}."
        ),
        "design_doc": DESIGN_DOC_PATH,
        "design_doc_url": DESIGN_DOC_URL,
        "schema": SCHEMA_PATH,
        "replaced_by": REPLACEMENT_SLICE[subcommand],
        "tracking": TRACKING_REFS,
    }
    payload.update(extra)
    return payload


def _emit_not_implemented(
    subcommand: str,
    as_json: bool,
    **extra: Any,
) -> None:
    """Emit the structured 'not implemented yet' payload on stderr +
    exit 2.

    JSON mode emits machine-parseable; human mode emits a short
    operator-readable banner. Both modes carry the same information.
    """

    payload = _not_implemented_payload(subcommand, **extra)
    if as_json:
        click.echo(json.dumps(payload, indent=2), err=True)
    else:
        click.echo(
            f"`{payload['subcommand']}`: DESIGN — not implemented yet.",
            err=True,
        )
        click.echo("", err=True)
        click.echo(f"  Design doc:  {payload['design_doc']}", err=True)
        click.echo(f"               {payload['design_doc_url']}", err=True)
        click.echo(f"  Schema:      {payload['schema']}", err=True)
        click.echo(f"  Replaced by: {payload['replaced_by']}", err=True)
        click.echo("", err=True)
        click.echo("  Tracking refs:", err=True)
        for ref, summary in TRACKING_REFS.items():
            marker = " <-- this command" if ref == payload["replaced_by"] else ""
            click.echo(f"    {ref}  {summary}{marker}", err=True)
        click.echo("", err=True)
        click.echo(
            "  Pass --json to emit the machine-parseable shape.",
            err=True,
        )
    sys.exit(2)


def register_deny_group(main_group: click.Group) -> click.Group:
    """Mount the `deny` subcommand group on the top-level `iam-jit` CLI.

    Called from :func:`iam_jit.cli.main` at import time so
    ``iam-jit deny --help`` surfaces the planned shape today.

    Returns the registered group so future slices can hang additional
    subcommands off it without re-declaring the parent group.
    """

    @main_group.group("deny")
    def deny_group() -> None:
        """Dynamic deny rules across the Bounce suite (#324 — DESIGN).

        Operator + agent surface for installing short-lived denies that
        fan out to every applicable Bounce product (ibounce / kbouncer /
        dbounce / gbounce) AND get embedded as `Deny` statements in any
        role iam-jit issues during the deny window.

        \b
        Status: SKELETON. Every subcommand exits 2 with a structured
        'not implemented yet' payload pointing at the design doc +
        the slice tracking the implementation. See
        docs/DYNAMIC-DENY-RULES.md.
        """

    # -- add ------------------------------------------------------------

    @deny_group.command("add")
    @click.option(
        "--target", "targets",
        multiple=True,
        required=False,  # skeleton: don't fail click-arg validation; let
                         # the body emit the structured 'not implemented'
                         # payload + exit 2 uniformly.
        metavar="PATTERN",
        help="Target pattern (repeatable). Resolver classifies each "
             "by shape; see DYNAMIC-DENY-RULES.md table. Examples: "
             "'arn:aws:s3:::prod-*' (ibounce), "
             "'payments-db-prod.us-east-1.rds.amazonaws.com' (dbounce+gbounce), "
             "'kube-system' (kbouncer), 'api.openai.com' (gbounce).",
    )
    @click.option(
        "--reason",
        required=False,
        help="Short string surfaced verbatim in the bouncer's 403 "
             "deny_reason + the admin-action OCSF audit event.",
    )
    @click.option(
        "--duration",
        required=False,
        help="Go-style duration ('30m', '3h', '7d') or 'permanent'.",
    )
    @click.option(
        "--applies-to-recommender/--no-applies-to-recommender",
        "applies_to_recommender",
        default=True,
        help="When true (default; #324f): the iam-jit recommender "
             "embeds an explicit Deny matching the targets into any "
             "role it issues during the deny window. Defense-in-depth: "
             "bouncer-time deny + role-time deny.",
    )
    @click.option(
        "--bouncer", "bouncer_overrides",
        multiple=True,
        type=click.Choice(["ibounce", "kbounce", "dbounce", "gbounce"]),
        help="Override the resolver — force this rule onto specific "
             "bouncer(s). Repeatable.",
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured shape as JSON (overrides the human "
             "banner). Stable shape per the design doc.",
    )
    def deny_add(
        targets: tuple[str, ...],
        reason: str | None,
        duration: str | None,
        applies_to_recommender: bool,
        bouncer_overrides: tuple[str, ...],
        as_json: bool,
    ) -> None:
        """Install a dynamic deny rule across the Bounce suite (DESIGN).

        See docs/DYNAMIC-DENY-RULES.md for the planned ergonomics +
        sample success output + OCSF audit event shape.
        """

        _emit_not_implemented(
            "add",
            as_json=as_json,
            received_args={
                "targets": list(targets),
                "reason": reason,
                "duration": duration,
                "applies_to_recommender": applies_to_recommender,
                "bouncer_overrides": list(bouncer_overrides),
            },
        )

    # -- list -----------------------------------------------------------

    @deny_group.command("list")
    @click.option(
        "--bouncer", "bouncer_filter",
        multiple=True,
        type=click.Choice(["ibounce", "kbounce", "dbounce", "gbounce"]),
        help="Filter to rules whose `applied_to` includes the named "
             "bouncer(s). Repeatable.",
    )
    @click.option(
        "--include-expired",
        is_flag=True,
        default=False,
        help="Include rules whose `expires_at` is in the past. Useful "
             "for retros + audit reconciliation.",
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured shape as JSON (overrides the human "
             "table).",
    )
    def deny_list(
        bouncer_filter: tuple[str, ...],
        include_expired: bool,
        as_json: bool,
    ) -> None:
        """List active dynamic deny rules (DESIGN).

        Tabular by default; `--json` returns the full rule objects per
        docs/schemas/dynamic-denies-v1.json.
        """

        _emit_not_implemented(
            "list",
            as_json=as_json,
            received_args={
                "bouncer_filter": list(bouncer_filter),
                "include_expired": include_expired,
            },
        )

    # -- remove ---------------------------------------------------------

    @deny_group.command("remove")
    @click.argument("ids", nargs=-1)
    @click.option(
        "--reason",
        default=None,
        help="Optional audit-trail metadata; surfaces in the "
             "`dynamic_deny.removed` admin-action event.",
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured shape as JSON.",
    )
    def deny_remove(
        ids: tuple[str, ...],
        reason: str | None,
        as_json: bool,
    ) -> None:
        """Remove one or more dynamic deny rules by id (DESIGN).

        Org-distributed rules cannot be loosened by a personal `remove`;
        the request is refused with a structured error pointing at the
        rule's `org_distributed_url` per the design doc's
        `Conflict resolution` section.
        """

        _emit_not_implemented(
            "remove",
            as_json=as_json,
            received_args={
                "ids": list(ids),
                "reason": reason,
            },
        )

    # -- show -----------------------------------------------------------

    @deny_group.command("show")
    @click.argument("id_", metavar="ID", required=False)
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the full rule object + audit trail as JSON.",
    )
    def deny_show(id_: str | None, as_json: bool) -> None:
        """Show one dynamic deny rule including provenance + audit trail (DESIGN).

        Surfaces `source`, `added_by`, `added_at`, `expires_at`, plus
        every admin-action event for the rule (add, modify, expiry).
        """

        _emit_not_implemented(
            "show",
            as_json=as_json,
            received_args={"id": id_},
        )

    return deny_group
