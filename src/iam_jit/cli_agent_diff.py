"""#722 / BUILD-1 — ``iam-jit agent-diff`` CLI surface.

Compares two agent sessions captured in the cross-bouncer audit log,
producing a structured diff per ``docs/AGENT-DIFF-DESIGN.md``.

Composes on top of:

* :mod:`iam_jit.agent_diff` — pure-function diff lib.
* :mod:`iam_jit.cli_audit_query` — per-bouncer ``/audit/events``
  fetcher (re-used so the wire shape stays consistent across the CLI
  family).

Per [[cross-product-agent-parity]] the same backend is reachable via
the ``iam_jit_agent_diff`` MCP tool (see :mod:`iam_jit.mcp_server`).
"""

from __future__ import annotations

import json
import sys
import typing

import click

from .agent_diff import compute_agent_diff, fetch_session_events_via_fanout


_SCOPES = ("permissions", "decisions", "behavioral", "risk", "all")
_NARROW_STRATEGIES = ("intersection", "union", "left", "right")
_FORMATS = ("json", "table", "markdown")


def _parse_bouncer_list(values: tuple[str, ...]) -> tuple[str, ...]:
    """Split repeatable ``--bouncer`` values + comma-separated tokens.
    Mirrors the audit-query parser shape so the operator's mental
    model is one consistent multi-bouncer flag across the CLI."""
    out: list[str] = []
    for v in values:
        for part in v.split(","):
            part = part.strip()
            if part:
                out.append(part)
    return tuple(out)


def _filter_scope(payload: dict[str, typing.Any], scope: str) -> dict[str, typing.Any]:
    """Drop the sub-deltas the operator didn't ask for. The ``sessions``
    + ``narrowing`` blocks always stay because they're the orient-the-
    operator headers; the operator who wants only ``permissions``
    gets ``permission_delta`` and nothing else of the deltas."""
    if scope == "all":
        return payload
    key_map = {
        "permissions": "permission_delta",
        "decisions": "decision_delta",
        "behavioral": "behavioral_delta",
        "risk": "risk_delta",
    }
    keep = key_map.get(scope)
    if not keep:
        return payload
    filtered: dict[str, typing.Any] = {}
    for k, v in payload.items():
        if k in ("sessions", "narrowing", "notes"):
            filtered[k] = v
        elif k == keep:
            filtered[k] = v
    return filtered


def _signed(n: int | float) -> str:
    """Render a delta with explicit sign + side indicator."""
    if isinstance(n, float):
        rounded = round(n, 4)
        if rounded > 0:
            return f"+{rounded} (B)"
        if rounded < 0:
            return f"{rounded} (A)"
        return "0"
    if n > 0:
        return f"+{n} (B)"
    if n < 0:
        return f"{n} (A)"
    return "0"


def _format_table(payload: dict[str, typing.Any]) -> str:
    """Compact operator-readable summary. Uses fixed widths so output
    is grep-friendly + scans visually on a 80-col terminal."""
    lines: list[str] = []
    s_a = payload["sessions"]["a"]
    s_b = payload["sessions"]["b"]
    lines.append(f"agent-diff: {s_a['session_id']} vs {s_b['session_id']}")
    lines.append("")
    if "behavioral_delta" in payload:
        bd = payload["behavioral_delta"]
        lines.append("Behavioral fingerprint")
        lines.append(f"  {'metric':<22} {'A':>6} {'B':>6} {'Δ':>14}")
        for label, k in (
            ("total_calls", "total_calls"),
            ("distinct_actions", "distinct_actions"),
            ("distinct_principals", "distinct_principals"),
            ("distinct_resources", "distinct_resources"),
            ("distinct_hosts", "distinct_hosts"),
        ):
            lines.append(
                f"  {label:<22} {bd['a'][k]:>6} {bd['b'][k]:>6} "
                f"{_signed(bd['delta'][k + '_delta']):>14}"
            )
        lines.append("")
    if "decision_delta" in payload:
        dd = payload["decision_delta"]
        lines.append("Decisions")
        lines.append(
            f"  allow_count: A={dd['a']['allow_count']} "
            f"B={dd['b']['allow_count']} Δ={_signed(dd['delta']['allow_count_delta'])}"
        )
        lines.append(
            f"  deny_count:  A={dd['a']['deny_count']} "
            f"B={dd['b']['deny_count']} Δ={_signed(dd['delta']['deny_count_delta'])}"
        )
        if dd["delta"]["deny_reasons_only_in_a"]:
            lines.append(
                f"  deny reasons only A: {', '.join(dd['delta']['deny_reasons_only_in_a'])}"
            )
        if dd["delta"]["deny_reasons_only_in_b"]:
            lines.append(
                f"  deny reasons only B: {', '.join(dd['delta']['deny_reasons_only_in_b'])}"
            )
        lines.append("")
    if "risk_delta" in payload:
        rd = payload["risk_delta"]
        lines.append("Risk")
        if rd["reason"]:
            lines.append(f"  {rd['reason']}")
        else:
            lines.append(
                f"  max_anomaly_score: A={rd['a']['max_anomaly_score']} "
                f"B={rd['b']['max_anomaly_score']} "
                f"Δ={_signed(rd['delta']['max_score_delta'])}"
            )
            lines.append(
                f"  anomalous events:  A={rd['a']['anomalous_event_count']} "
                f"B={rd['b']['anomalous_event_count']} "
                f"Δ={_signed(rd['delta']['anomalous_count_delta'])}"
            )
        lines.append("")
    if "permission_delta" in payload:
        pd = payload["permission_delta"]
        lines.append("Permissions")
        only_a = [r["action"] for r in pd["only_in_a"]]
        only_b = [r["action"] for r in pd["only_in_b"]]
        inter = [r["action"] for r in pd["intersection"]]
        lines.append(f"  only in A ({len(only_a)}): " + (", ".join(only_a) or "(none)"))
        lines.append(f"  only in B ({len(only_b)}): " + (", ".join(only_b) or "(none)"))
        lines.append(f"  intersection ({len(inter)}): " + (", ".join(inter) or "(none)"))
        lines.append("")
    n = payload["narrowing"]
    lines.append(f"Narrowing ({n['strategy']}) — {n['action_count']} actions")
    if n["cannot_narrow_reason"]:
        lines.append(f"  cannot narrow: {n['cannot_narrow_reason']}")
    if n["notes"]:
        for note in n["notes"]:
            lines.append(f"  note: {note}")
    if payload.get("notes"):
        lines.append("")
        lines.append("Notes")
        for note in payload["notes"]:
            lines.append(f"  - {note}")
    return "\n".join(lines) + "\n"


def _format_markdown(payload: dict[str, typing.Any]) -> str:
    """Markdown rendering — for paste-into-PR / paste-into-incident-doc.

    The narrowed-policy block embeds the real IAM policy JSON inside a
    fenced ``json`` block so reviewers can copy it directly into a
    role document.
    """
    s_a = payload["sessions"]["a"]
    s_b = payload["sessions"]["b"]
    out: list[str] = []
    out.append(f"# Agent Diff: {s_a['session_id']} vs {s_b['session_id']}")
    out.append("")
    if "behavioral_delta" in payload:
        bd = payload["behavioral_delta"]
        out.append("## Behavioral fingerprint")
        out.append("")
        out.append("| Metric | A | B | Δ |")
        out.append("| --- | --- | --- | --- |")
        for label, k in (
            ("total_calls", "total_calls"),
            ("distinct_actions", "distinct_actions"),
            ("distinct_principals", "distinct_principals"),
            ("distinct_resources", "distinct_resources"),
            ("distinct_hosts", "distinct_hosts"),
        ):
            out.append(
                f"| {label} | {bd['a'][k]} | {bd['b'][k]} | "
                f"{_signed(bd['delta'][k + '_delta'])} |"
            )
        out.append("")
    if "decision_delta" in payload:
        dd = payload["decision_delta"]
        out.append("## Decisions")
        out.append("")
        out.append("| Metric | A | B | Δ |")
        out.append("| --- | --- | --- | --- |")
        out.append(
            f"| allow_count | {dd['a']['allow_count']} | "
            f"{dd['b']['allow_count']} | "
            f"{_signed(dd['delta']['allow_count_delta'])} |"
        )
        out.append(
            f"| deny_count | {dd['a']['deny_count']} | "
            f"{dd['b']['deny_count']} | "
            f"{_signed(dd['delta']['deny_count_delta'])} |"
        )
        if dd["delta"]["deny_reasons_only_in_a"]:
            out.append("")
            out.append(
                "Deny reasons only in A: "
                + ", ".join(f"`{r}`" for r in dd["delta"]["deny_reasons_only_in_a"])
            )
        if dd["delta"]["deny_reasons_only_in_b"]:
            out.append("")
            out.append(
                "Deny reasons only in B: "
                + ", ".join(f"`{r}`" for r in dd["delta"]["deny_reasons_only_in_b"])
            )
        out.append("")
    if "risk_delta" in payload:
        rd = payload["risk_delta"]
        out.append("## Risk")
        out.append("")
        if rd["reason"]:
            out.append(f"_{rd['reason']}_")
        else:
            out.append("| Metric | A | B | Δ |")
            out.append("| --- | --- | --- | --- |")
            out.append(
                f"| max_anomaly_score | {rd['a']['max_anomaly_score']} | "
                f"{rd['b']['max_anomaly_score']} | "
                f"{_signed(rd['delta']['max_score_delta'])} |"
            )
            out.append(
                f"| anomalous_event_count | "
                f"{rd['a']['anomalous_event_count']} | "
                f"{rd['b']['anomalous_event_count']} | "
                f"{_signed(rd['delta']['anomalous_count_delta'])} |"
            )
        out.append("")
    if "permission_delta" in payload:
        pd = payload["permission_delta"]
        out.append("## Permissions")
        out.append("")
        out.append(
            "Only in A: "
            + (", ".join(f"`{r['action']}`" for r in pd["only_in_a"]) or "_(none)_")
        )
        out.append("")
        out.append(
            "Only in B: "
            + (", ".join(f"`{r['action']}`" for r in pd["only_in_b"]) or "_(none)_")
        )
        out.append("")
        out.append(
            "Intersection: "
            + (
                ", ".join(f"`{r['action']}`" for r in pd["intersection"])
                or "_(none)_"
            )
        )
        out.append("")
    n = payload["narrowing"]
    out.append(f"## Narrowed policy ({n['strategy']}, {n['action_count']} actions)")
    out.append("")
    if n["cannot_narrow_reason"]:
        out.append(f"_{n['cannot_narrow_reason']}_")
        out.append("")
    out.append("```json")
    out.append(json.dumps(n["policy"], indent=2, sort_keys=True))
    out.append("```")
    if n["notes"]:
        out.append("")
        for note in n["notes"]:
            out.append(f"> note: {note}")
    if payload.get("notes"):
        out.append("")
        out.append("## Notes")
        out.append("")
        for note in payload["notes"]:
            out.append(f"- {note}")
    return "\n".join(out) + "\n"


@click.command("agent-diff")
@click.argument("session_a")
@click.argument("session_b")
@click.option(
    "--bouncer", "bouncers_raw",
    multiple=True,
    help="Bouncer(s) to fan out to. Repeatable; comma-separated also "
         "accepted. Default: probe all four default bouncers on their "
         "standard mgmt ports. Override one entry with `name=URL`.",
)
@click.option(
    "--since",
    default="1h",
    show_default=True,
    help="Lookback window. Short-form (5m / 1h / 2d) or ISO 8601 "
         "lower bound.",
)
@click.option(
    "--until",
    default=None,
    help="Optional upper bound. ISO 8601 or short-form.",
)
@click.option(
    "--scope",
    type=click.Choice(_SCOPES, case_sensitive=False),
    default="all",
    show_default=True,
    help="Which sub-deltas to surface. `all` is the operator default; "
         "the scoped variants are useful for piping a single block to "
         "another tool.",
)
@click.option(
    "--format", "fmt",
    type=click.Choice(_FORMATS, case_sensitive=False),
    default=None,
    help="Output format. Default: `table` on a TTY, `json` otherwise.",
)
@click.option(
    "--narrow",
    type=click.Choice(_NARROW_STRATEGIES, case_sensitive=False),
    default="intersection",
    show_default=True,
    help="Strategy for the narrowed-policy block. `intersection` "
         "produces the operator-default tight policy; `union` admits "
         "either side's behaviour; `left`/`right` keep one session's "
         "actions verbatim.",
)
@click.option(
    "--limit",
    type=int,
    default=1000,
    show_default=True,
    help="Per-bouncer event cap per session.",
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
def agent_diff_command(
    session_a: str,
    session_b: str,
    bouncers_raw: tuple[str, ...],
    since: str,
    until: str | None,
    scope: str,
    fmt: str | None,
    narrow: str,
    limit: int,
    audit_events_token: str | None,
    output: str | None,
) -> None:
    """Differential audit: compare two agent sessions in the audit log.

    Surfaces the permission / decision / behavioral / risk deltas
    between two sessions + a narrowed IAM policy ready for operator
    review. Read-only — no state change. See ``docs/AGENT-DIFF-DESIGN.md``
    for the full data-model spec.

    \b
    Examples:
      iam-jit agent-diff sess_claude_a sess_codex_b
      iam-jit agent-diff a b --scope permissions --format markdown
      iam-jit agent-diff a b --narrow union --output /tmp/diff.json
    """
    if not session_a or not session_b:
        raise click.UsageError("both <session_a> and <session_b> are required")
    if session_a == session_b:
        # We allow this — useful for self-diff smoke tests — but warn.
        click.echo(
            "warning: session_a == session_b; deltas will be empty",
            err=True,
        )

    bouncers = _parse_bouncer_list(bouncers_raw)

    events_a, notes_a = fetch_session_events_via_fanout(
        session_id=session_a,
        bouncers=bouncers,
        since=since,
        until=until,
        limit=limit,
        audit_events_token=audit_events_token,
    )
    events_b, notes_b = fetch_session_events_via_fanout(
        session_id=session_b,
        bouncers=bouncers,
        since=since,
        until=until,
        limit=limit,
        audit_events_token=audit_events_token,
    )

    # Surface every bouncer's reachability per session as honest notes.
    notes: list[str] = []
    for b, err in sorted(notes_a.items()):
        if err:
            notes.append(f"session_a/{b}: {err}")
    for b, err in sorted(notes_b.items()):
        if err:
            notes.append(f"session_b/{b}: {err}")

    # Honest empty-result handling: if EVERY bouncer was unreachable
    # for BOTH sessions, exit 3 so the operator's script can branch.
    reachable_a = any(not err for err in notes_a.values())
    reachable_b = any(not err for err in notes_b.values())
    if not reachable_a and not reachable_b:
        click.echo(
            json.dumps({
                "status": "error",
                "code": "all_bouncers_unreachable",
                "notes": notes,
            }),
            err=True,
        )
        sys.exit(3)

    diff = compute_agent_diff(
        session_a_id=session_a,
        events_a=events_a,
        session_b_id=session_b,
        events_b=events_b,
        narrow=narrow,
        time_window_a={"from": since or "", "to": until or ""},
        time_window_b={"from": since or "", "to": until or ""},
        notes=tuple(notes),
    )

    payload = diff.as_dict()
    payload = _filter_scope(payload, scope)

    # Format resolution: default by TTY status.
    resolved_fmt = fmt
    if resolved_fmt is None:
        resolved_fmt = "table" if sys.stdout.isatty() else "json"
    resolved_fmt = resolved_fmt.lower()

    if resolved_fmt == "json":
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    elif resolved_fmt == "markdown":
        rendered = _format_markdown(payload)
    else:  # table
        rendered = _format_table(payload)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        click.echo(f"agent-diff written to {output}", err=True)
    else:
        click.echo(rendered, nl=False)


def register_agent_diff_command(parent_group: click.Group) -> None:
    """Wire ``iam-jit agent-diff`` onto the top-level CLI group.

    Mirrors the registration pattern used by the other audit-adjacent
    commands (``cli_audit_query.register_audit_query_group`` etc.) so
    the import-time side-effects from ``iam_jit.cli`` keep the same
    "register at the bottom" discipline.
    """
    parent_group.add_command(agent_diff_command)
