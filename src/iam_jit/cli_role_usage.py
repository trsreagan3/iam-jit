# #727 / BUILD-6 — `iam-jit role-usage` CLI surface.
"""``iam-jit role-usage --session SID --granted-policy FILE``

The data-driven close of iam-jit's recommend → grant → observe loop.
Compares the permissions the JIT-issued role GRANTED (the inline policy
file) against the permissions the agent ACTUALLY USED in the session
(read off the bouncer's OCSF audit log), then surfaces "Used N of M
permissions" + a proposed narrowed policy.

Composes on top of, never duplicates:

* :mod:`iam_jit.role_usage` — pure-function diff + narrowing core.
* :func:`iam_jit.agent_diff.fetch_session_events_via_fanout` — the
  SAME per-session ``/audit/events`` fetch ``iam-jit agent-diff`` uses
  (which itself reuses ``iam-jit audit query``'s per-bouncer fetcher).

Per [[creates-never-mutates]] read-only — recommends a narrowed role,
never mutates the issued one. Per [[ibounce-honest-positioning]] the
narrowed policy is presented as a FLOOR with explicit caveats.
"""

from __future__ import annotations

import json
import sys
import typing

import click

from .agent_diff import fetch_session_events_via_fanout
from .role_usage import compute_role_usage


_FORMATS = ("json", "table")


def _parse_bouncer_list(values: tuple[str, ...]) -> tuple[str, ...]:
    """Split repeatable ``--bouncer`` values + comma-separated tokens.
    Mirrors the agent-diff / audit-query parser so the operator's
    mental model is one consistent multi-bouncer flag."""
    out: list[str] = []
    for v in values:
        for part in v.split(","):
            part = part.strip()
            if part:
                out.append(part)
    return tuple(out)


def _load_granted_policy(path: str) -> dict[str, typing.Any]:
    """Load + minimally validate the issued role's inline policy."""
    with open(path, encoding="utf-8") as fh:
        try:
            doc = json.load(fh)
        except json.JSONDecodeError as e:
            raise click.ClickException(
                f"granted policy in {path!r} is not valid JSON: {e}"
            )
    if not isinstance(doc, dict):
        raise click.ClickException(
            f"granted policy in {path!r} must be a JSON object "
            "(an IAM policy document), got "
            f"{type(doc).__name__}"
        )
    return doc


def _format_table(payload: dict[str, typing.Any]) -> str:
    lines: list[str] = []
    granted = payload["granted_count"]
    used = payload["used_count"]
    sid = payload["session_id"]
    lines.append(f"Session: {sid}")
    lines.append(f"Events analyzed: {payload['events_analyzed']}")
    lines.append("")
    lines.append(f"Used {used} of {granted} granted permissions")
    if payload["granted_count_basis"] == "literal_glob_count":
        lines.append("  (granted count is GLOB-level — see caveats)")
    lines.append("")

    used_actions = payload.get("used_actions") or []
    if used_actions:
        lines.append("Used permissions:")
        for a in used_actions:
            res = ", ".join(a["resources"]) if a["resources"] else "*"
            lines.append(f"  + {a['action']}  (x{a['count']})  -> {res}")
    else:
        lines.append("Used permissions: (none observed)")
    lines.append("")

    unused = payload.get("unused_permissions") or []
    if unused:
        lines.append(f"Unused (granted but never exercised): {len(unused)}")
        for p in unused[:50]:
            lines.append(f"  - {p}")
        if len(unused) > 50:
            lines.append(f"  ... and {len(unused) - 50} more")
    else:
        lines.append("Unused (granted but never exercised): 0")
    lines.append("")

    outside = payload.get("used_outside_grant") or []
    if outside:
        lines.append("WARNING — used but NOT in the granted policy "
                     "(possible mismatch / advisory-mode):")
        for p in outside:
            lines.append(f"  ! {p}")
        lines.append("")

    narrowed = payload.get("narrowed") or {}
    reason = narrowed.get("cannot_narrow_reason")
    if reason:
        lines.append(f"Narrowed policy: NONE — {reason}")
    else:
        lines.append(
            f"Proposed narrowed policy "
            f"({narrowed.get('statement_count', 0)} statements):"
        )
        lines.append(
            json.dumps(narrowed.get("policy", {}), indent=2, sort_keys=True)
        )
    for n in narrowed.get("notes") or []:
        lines.append(f"  note: {n}")
    lines.append("")

    caveats = payload.get("caveats") or []
    if caveats:
        lines.append("Caveats (read before tightening a long-lived role):")
        for c in caveats:
            lines.append(f"  * {c}")

    for n in payload.get("notes") or []:
        lines.append(f"note: {n}")
    return "\n".join(lines) + "\n"


@click.command("role-usage")
@click.option(
    "--session", "session_id",
    required=True,
    help="Session id to analyze (matches "
         "`unmapped.iam_jit.agent.session_id` in the bouncer OCSF log).",
)
@click.option(
    "--granted-policy", "granted_policy_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="Path to the issued role's inline IAM policy JSON (the policy "
         "iam-jit CREATED for this session). The granted set is "
         "derived from this document's Allow statements.",
)
@click.option(
    "--bouncer", "bouncers_raw",
    multiple=True,
    help="Bouncer(s) to fan out to for the session's audit events. "
         "Repeatable; comma-separated also accepted. Default: probe "
         "all four default bouncers on their standard mgmt ports. "
         "Override one entry with `name=URL`.",
)
@click.option(
    "--since",
    default="1h",
    show_default=True,
    help="Lookback window for the session's events. Short-form "
         "(5m / 1h / 2d) or ISO 8601 lower bound.",
)
@click.option(
    "--until",
    default=None,
    help="Optional upper bound. ISO 8601 or short-form.",
)
@click.option(
    "--format", "fmt",
    type=click.Choice(_FORMATS, case_sensitive=False),
    default=None,
    help="Output format. Default: `table` on a TTY, `json` otherwise.",
)
@click.option(
    "--limit",
    type=int,
    default=1000,
    show_default=True,
    help="Per-bouncer event cap for the session.",
)
@click.option(
    "--audit-events-token",
    default=None,
    help="Bearer token for /audit/events when bound off-loopback.",
)
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write to PATH instead of stdout.",
)
def role_usage_command(
    session_id: str,
    granted_policy_path: str,
    bouncers_raw: tuple[str, ...],
    since: str,
    until: str | None,
    fmt: str | None,
    limit: int,
    audit_events_token: str | None,
    output: str | None,
) -> None:
    """Show "Used N of M permissions" + a proposed narrowed role.

    Read-only. The narrowed policy is a recommendation artifact — a
    FLOOR based on the usage observed in this session window, not a
    guarantee. iam-jit never mutates the issued role
    (per [[creates-never-mutates]]).
    """
    granted_policy = _load_granted_policy(granted_policy_path)
    bouncers = _parse_bouncer_list(bouncers_raw)

    events, notes_by_bouncer = fetch_session_events_via_fanout(
        session_id=session_id,
        bouncers=bouncers,
        since=since,
        until=until or None,
        limit=limit,
        audit_events_token=audit_events_token or None,
    )
    notes: list[str] = []
    for b, err in sorted(notes_by_bouncer.items()):
        if err:
            notes.append(f"{b}: {err}")

    usage = compute_role_usage(
        session_id=session_id,
        granted_policy=granted_policy,
        events=events,
        notes=tuple(notes),
    )
    payload = usage.as_dict()

    resolved_fmt = fmt
    if resolved_fmt is None:
        resolved_fmt = "table" if sys.stdout.isatty() else "json"
    resolved_fmt = resolved_fmt.lower()

    if resolved_fmt == "json":
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    else:
        rendered = _format_table(payload)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        click.echo(f"role-usage written to {output}", err=True)
    else:
        click.echo(rendered, nl=False)


def register_role_usage_command(parent_group: click.Group) -> None:
    """Wire ``iam-jit role-usage`` onto the top-level CLI group.

    Mirrors the registration pattern used by ``cli_agent_diff`` so the
    import-time "register at the bottom of iam_jit.cli" discipline is
    consistent across the audit-adjacent command family.
    """
    parent_group.add_command(role_usage_command)
