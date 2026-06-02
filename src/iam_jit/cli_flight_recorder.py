# #723 / BUILD-2 — `iam-jit flight-recorder` CLI surface.
"""``iam-jit flight-recorder --session SID``

Emit the cross-bouncer correlation TIMELINE for one agent session — the
data behind the Wireshark-style scrubbable replay UI. Stitches the
agent's external actions across AWS / K8s / SQL / HTTP (+ iam-jit
serve) into one ordered timeline keyed on
``unmapped.iam_jit.agent.session_id``.

Composes on top of, never duplicates:

* :func:`iam_jit.agent_diff.fetch_session_events_via_fanout` — the
  SAME per-session ``/audit/events`` fan-out ``iam-jit agent-diff`` /
  ``role-usage`` / ``compliance-map`` use (which itself reuses
  ``iam-jit audit query``'s per-bouncer fetcher). This command adds NO
  new wire path; it reuses the suite's one cross-bouncer query.
* :func:`iam_jit.flight_recorder.assemble_timeline` — the pure-function
  timeline assembler (ordering + the honesty / coverage block).

Read-only (per [[creates-never-mutates]]): emits a recorded view of a
past session, never mutates anything. Honest (per
[[ibounce-honest-positioning]]): unreachable / zero-event bouncers are
surfaced in the timeline ``coverage`` block, not hidden.
"""

from __future__ import annotations

import json
import sys
import typing

import click

from .agent_diff import fetch_session_events_via_fanout
from .flight_recorder import assemble_timeline

# `timeline-json` is the canonical machine format the replay UI loads.
# `summary` is a quick human read of coverage + step count.
_FORMATS = ("timeline-json", "summary")


def _parse_bouncer_list(values: tuple[str, ...]) -> tuple[str, ...]:
    """Split repeatable ``--bouncer`` values + comma-separated tokens.
    Mirrors the role-usage / agent-diff / audit-query parser so the
    operator's mental model is one consistent multi-bouncer flag."""
    out: list[str] = []
    for v in values:
        for part in v.split(","):
            part = part.strip()
            if part:
                out.append(part)
    return tuple(out)


def _format_summary(payload: dict[str, typing.Any]) -> str:
    cov = payload["coverage"]
    meta = payload["meta"]
    lines: list[str] = []
    lines.append(f"Session: {payload['session_id']}")
    lines.append(f"Steps: {payload['step_count']}  "
                 f"(events analyzed: {meta['events_analyzed']})")
    lines.append("")
    lines.append("Coverage:")
    lines.append(f"  probed:        {', '.join(cov['bouncers_probed']) or '(none)'}")
    lines.append(f"  contributing:  {', '.join(cov['bouncers_contributing']) or '(none)'}")
    if cov["bouncers_unreachable"]:
        lines.append("  unreachable:")
        for u in cov["bouncers_unreachable"]:
            lines.append(f"    ! {u['bouncer']}: {u['reason']}")
    if cov["bouncers_reachable_no_events"]:
        lines.append(
            f"  reachable, 0 events: "
            f"{', '.join(cov['bouncers_reachable_no_events'])}"
        )
    if cov["partial"]:
        lines.append("  PARTIAL — at least one probed bouncer did not answer; "
                     "this timeline is NOT the complete session.")
    lines.append("")
    proto = meta["steps_per_protocol"]
    if proto:
        lines.append("Steps per protocol:")
        for p in sorted(proto):
            lines.append(f"  {p}: {proto[p]}")
    lines.append("")
    if cov["gaps"]:
        lines.append("Gaps (read before trusting completeness):")
        for g in cov["gaps"]:
            lines.append(f"  * {g}")
    else:
        lines.append("Gaps: none flagged (all probed bouncers answered)")
    return "\n".join(lines) + "\n"


@click.command("flight-recorder")
@click.option(
    "--session", "session_id",
    required=True,
    help="Agent session id to replay (matches "
         "`unmapped.iam_jit.agent.session_id` in every bouncer's OCSF "
         "log — the shared cross-protocol correlation key).",
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
    help="Output format. `timeline-json` = the machine timeline the "
         "replay UI loads. `summary` = a quick human read of coverage "
         "+ step count. Default: `summary` on a TTY, `timeline-json` "
         "otherwise.",
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
def flight_recorder_command(
    session_id: str,
    bouncers_raw: tuple[str, ...],
    since: str,
    until: str | None,
    fmt: str | None,
    limit: int,
    audit_events_token: str | None,
    output: str | None,
) -> None:
    """Stitch one agent session across all bouncers into an ordered
    timeline (the data behind the scrubbable replay UI).

    \b
    Examples:
      # Timeline JSON for a session (default off a pipe).
      iam-jit flight-recorder --session 019687ef-... > timeline.json

      # Quick human coverage read.
      iam-jit flight-recorder --session 019687ef-... --format summary

      # Wider window + one overridden bouncer URL.
      iam-jit flight-recorder --session 019687ef-... --since 24h \\
          --bouncer kbounce=http://10.0.0.5:8766

    Read-only. Per [[ibounce-honest-positioning]] the `coverage` block
    names unreachable / zero-event bouncers so the operator never
    mistakes a probe failure for a genuine gap in the session.
    """
    if limit < 1 or limit > 10_000:
        raise click.BadParameter("--limit must be in 1..10000")

    bouncers = _parse_bouncer_list(bouncers_raw)

    events, notes_by_bouncer = fetch_session_events_via_fanout(
        session_id=session_id,
        bouncers=bouncers,
        since=since,
        until=until or None,
        limit=limit,
        audit_events_token=audit_events_token or None,
    )

    payload = assemble_timeline(
        session_id=session_id,
        events=events,
        notes_by_bouncer=notes_by_bouncer,
        since=since,
        until=until or None,
    )

    resolved_fmt = fmt
    if resolved_fmt is None:
        resolved_fmt = "summary" if sys.stdout.isatty() else "timeline-json"
    resolved_fmt = resolved_fmt.lower()

    if resolved_fmt == "summary":
        rendered = _format_summary(payload)
    else:
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        click.echo(f"flight-recorder timeline written to {output}", err=True)
    else:
        click.echo(rendered, nl=False)


def register_flight_recorder_command(parent_group: click.Group) -> None:
    """Wire ``iam-jit flight-recorder`` onto the top-level CLI group.

    Mirrors the registration pattern used by ``cli_role_usage`` /
    ``cli_agent_diff`` so the import-time "register at the bottom of
    iam_jit.cli" discipline is consistent across the audit-adjacent
    command family.
    """
    parent_group.add_command(flight_recorder_command)
