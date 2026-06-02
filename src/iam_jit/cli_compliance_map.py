# ADOPT-2 / #716 — `iam-jit compliance-map` CLI surface.
"""``iam-jit compliance-map --session SID [--framework owasp|mitre|nist|
soc2|eu-ai-act] [--format json|summary]``

Maps the agent activity observed in a session's audit log to the
compliance-framework controls it touches, producing (a) a per-event
overlay (``compliance_tags``) and (b) a per-framework coverage report.

The differentiator vs HTTP-only competitors: iam-jit's audit stream
spans AWS IAM + K8s + SQL + HTTP, so this works across all four.

Composes on top of, never duplicates:

* :mod:`iam_jit.compliance` — pure mapping + projection core.
* :func:`iam_jit.agent_diff.fetch_session_events_via_fanout` — the
  SAME per-session ``/audit/events`` fetch ``iam-jit agent-diff`` /
  ``role-usage`` / ``audit query --format cyclonedx`` use.

Per [[creates-never-mutates]] read-only. Per
[[ibounce-honest-positioning]] this is NOT a certification — the
coverage report names per-framework gaps + flags partial sessions.
"""

from __future__ import annotations

import json
import sys

import click

from .agent_diff import fetch_session_events_via_fanout
from .compliance import build_overlay, format_summary
from .compliance.mapping import FRAMEWORK_IDS


_FORMATS = ("json", "summary")


def _parse_bouncer_list(values: tuple[str, ...]) -> tuple[str, ...]:
    """Split repeatable ``--bouncer`` values + comma-separated tokens.
    Mirrors the agent-diff / role-usage / audit-query parser so the
    operator's mental model is one consistent multi-bouncer flag."""
    out: list[str] = []
    for v in values:
        for part in v.split(","):
            part = part.strip()
            if part:
                out.append(part)
    return tuple(out)


@click.command("compliance-map")
@click.option(
    "--session", "session_id",
    required=True,
    help="Session id to analyze (matches "
         "`unmapped.iam_jit.agent.session_id` in the bouncer OCSF log).",
)
@click.option(
    "--framework",
    type=click.Choice(FRAMEWORK_IDS, case_sensitive=False),
    default=None,
    help="Restrict the overlay + report to one framework. Omit for all "
         f"five: {', '.join(FRAMEWORK_IDS)}.",
)
@click.option(
    "--bouncer", "bouncers_raw",
    multiple=True,
    help="Bouncer(s) to fan out to for the session's audit events. "
         "Repeatable; comma-separated also accepted. Default: probe "
         "all four default bouncers on their standard mgmt ports "
         "(AWS+K8s+SQL+HTTP). Override one entry with `name=URL`.",
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
    help="Output format. Default: `summary` on a TTY, `json` otherwise. "
         "`json` is the full overlay+report; `summary` is human-readable.",
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
def compliance_map_command(
    session_id: str,
    framework: str | None,
    bouncers_raw: tuple[str, ...],
    since: str,
    until: str | None,
    fmt: str | None,
    limit: int,
    audit_events_token: str | None,
    output: str | None,
) -> None:
    """Map a session's observed activity to compliance-framework controls.

    Produces a per-event overlay (`compliance_tags`) + a per-framework
    coverage report across OWASP Agentic Top 10, MITRE ATT&CK, NIST
    800-53 Rev5, SOC 2 TSC, and the EU AI Act — for AWS IAM + K8s + SQL
    + HTTP, not just HTTP.

    Read-only. This is NOT a compliance certification — it is evidence
    of which controls the agent's observed activity touched, with
    explicit per-framework coverage gaps (per
    [[ibounce-honest-positioning]]).

    \b
    Examples:
      iam-jit compliance-map --session sess_claude_42
      iam-jit compliance-map --session s --framework owasp --format json
      iam-jit compliance-map --session s --since 30d -o /tmp/report.json
    """
    framework_norm = framework.lower() if framework else None
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

    result = build_overlay(
        session_id=session_id,
        events=events,
        framework=framework_norm,
        notes=tuple(notes),
    )
    payload = result.as_dict()

    resolved_fmt = fmt
    if resolved_fmt is None:
        resolved_fmt = "summary" if sys.stdout.isatty() else "json"
    resolved_fmt = resolved_fmt.lower()

    if resolved_fmt == "json":
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    else:
        rendered = format_summary(result)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        click.echo(f"compliance-map written to {output}", err=True)
    else:
        click.echo(rendered, nl=False)


def register_compliance_map_command(parent_group: click.Group) -> None:
    """Wire ``iam-jit compliance-map`` onto the top-level CLI group.

    Mirrors the registration pattern used by ``cli_agent_diff`` /
    ``cli_role_usage`` so the import-time "register at the bottom of
    iam_jit.cli" discipline is consistent across the audit-adjacent
    command family.
    """
    parent_group.add_command(compliance_map_command)
