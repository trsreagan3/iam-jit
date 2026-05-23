"""#412 / §A56 — Weekly digest renderers.

Output formats:

  * :func:`render_terminal` — colored, human-readable, lead with
    positive-signal framing per ``[[ambient-value-prop-and-friction-framing]]``.
  * :func:`render_json` — pretty-printed JSON (the canonical wire shape;
    same as MCP tool response).
  * :func:`render_markdown` — emailable / Slack-channel friendly. Same
    lead framing as the terminal renderer.
  * :func:`render_html` — minimal HTML (no inline JS) for an emailable
    artifact. Per ``[[v1-scope-bar]]`` HTML is a nice-to-have; we ship a
    one-shot wrapper but DON'T grow into a web UI.

All renderers READ-ONLY on :class:`DigestData` (per
``[[creates-never-mutates]]``). They never touch profiles, queues, or
audit logs.
"""

from __future__ import annotations

import datetime as _dt
import html
import json
from typing import Any

from .core import DigestData


# ---------------------------------------------------------------------------
# Lead-line phrasing — per [[ambient-value-prop-and-friction-framing]] the
# digest MUST lead with caught-framing, never "BLOCKED" / "DENIED" /
# "ERROR". Adversarial denies surface explicitly per
# [[ibounce-honest-positioning]] so they aren't buried by the friendly
# framing.
# ---------------------------------------------------------------------------


def _window_label(time_window: dict[str, str]) -> str:
    """Render the time window as a human label ("last 7 days")."""
    try:
        from_iso = time_window.get("from") or ""
        to_iso = time_window.get("to") or ""
        if not from_iso or not to_iso:
            return "the configured window"
        f = _parse(from_iso)
        t = _parse(to_iso)
        delta = t - f
        days = delta.total_seconds() / 86400.0
        if days >= 6.5:
            return f"last {int(round(days))} days"
        if days >= 0.9:
            return f"last {int(round(days))} day(s)"
        hours = delta.total_seconds() / 3600.0
        if hours >= 0.9:
            return f"last {int(round(hours))} hour(s)"
        return f"last {int(delta.total_seconds() / 60)} minute(s)"
    except Exception:
        return "the configured window"


def _parse(s: str) -> _dt.datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return _dt.datetime.fromisoformat(s)


def _lead_line(window_label: str) -> str:
    """Positive-signal lead. NEVER 'BLOCKED' / 'ERROR' / 'DENIED'."""
    return f"Your bouncer week in review ({window_label})"


# ---------------------------------------------------------------------------
# Terminal renderer
# ---------------------------------------------------------------------------


def render_terminal(data: DigestData, *, use_color: bool = True) -> str:
    """Render a colored terminal summary.

    The lead line is ALWAYS caught-framing; the per-classification
    breakdown uses ``[+]`` (legit), ``[?]`` (ambiguous), ``[!]``
    (adversarial) markers so a scanner's eye lands on the high-signal
    rows first.
    """
    lines: list[str] = []
    window = _window_label(data.time_window)
    lines.append(_lead_line(window))
    lines.append("")

    totals = data.totals or {}
    lines.append("Across all bouncers:")
    audited = int(totals.get("total_requests_audited") or 0)
    denies = int(totals.get("total_denies") or 0)
    lines.append(f"  {audited:,} agent requests audited silently")
    if denies == 0:
        lines.append(
            f"  0 caught for review — quiet week. Your bouncer is "
            f"observing without finding anything to flag."
        )
    else:
        lines.append(f"  {denies} caught for review:")
        legit = int(totals.get("total_appears_legitimate") or 0)
        ambig = int(totals.get("total_ambiguous") or 0)
        adv = int(totals.get("total_appears_adversarial") or 0)
        if legit:
            lines.append(
                f"    [+] {legit} appeared legitimate "
                f"(review when convenient)"
            )
        if ambig:
            lines.append(
                f"    [?] {ambig} ambiguous (needs your judgment)"
            )
        if adv:
            lines.append(
                f"    [!] {adv} appeared adversarial (still blocked "
                f"— review when you're back)"
            )

    improve_cycles = int(totals.get("improve_cycles_run") or 0)
    auto_installed = int(totals.get("improve_changes_auto_installed") or 0)
    pending = int(totals.get("improve_changes_pending") or 0)
    if improve_cycles or auto_installed or pending:
        lines.append(f"  {improve_cycles} improvement cycle(s) ran in background")
        if auto_installed:
            lines.append(
                f"    {auto_installed} change(s) auto-installed within "
                f"your threshold"
            )
        if pending:
            lines.append(
                f"    {pending} change(s) pending your approval "
                f"(run `iam-jit profile pending`)"
            )

    pending_queue = int(totals.get("pending_approval_count") or 0)
    if pending_queue:
        lines.append(
            f"  {pending_queue} item(s) waiting in your allow-rule "
            f"approval queue"
        )

    lines.append("")

    # Per-bouncer breakdown (only if more than one bouncer present)
    if len(data.bouncers) > 1:
        lines.append("Per bouncer:")
        for name, b in sorted(data.bouncers.items()):
            audited = int(b.get("total_requests_audited") or 0)
            denies = int(b.get("total_denies") or 0)
            status = b.get("status") or "no_data"
            lines.append(
                f"  - {name} [{status}]: {audited:,} audited, "
                f"{denies} caught"
            )
        lines.append("")

    # Noteworthy events
    noteworthy: list[str] = []
    for name, b in sorted(data.bouncers.items()):
        for ev in b.get("noteworthy_events") or []:
            desc = ev.get("description") or ""
            if not desc:
                continue
            noteworthy.append(f"  - {desc}")
    if noteworthy:
        lines.append("Notable:")
        # Cap so the digest doesn't run off the screen.
        for n in noteworthy[:10]:
            lines.append(n)
        if len(noteworthy) > 10:
            lines.append(f"  ... +{len(noteworthy) - 10} more")
        lines.append("")

    # Recommendations
    if data.recommendations:
        lines.append("Recommendations:")
        for r in data.recommendations:
            lines.append(f"  - {r}")
        lines.append("")

    # Notes
    if data.notes:
        lines.append("Notes:")
        for n in data.notes:
            lines.append(f"  ({n})")
        lines.append("")

    lines.append(
        "Run `iam-jit denies recent --since 1w` for the per-row deny detail."
    )
    out = "\n".join(lines)
    # use_color is a hook for future ANSI escapes — today the terminal
    # surface uses plain text + bracketed markers so it copy-pastes
    # cleanly into Slack / email. We intentionally don't sprinkle ANSI
    # here so the same string serves --json-less CLI + webhook fallback.
    return out


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------


def render_json(data: DigestData) -> str:
    """Pretty-printed JSON. Same shape as the MCP tool response."""
    return json.dumps(data.as_dict(), indent=2, default=str)


# ---------------------------------------------------------------------------
# Markdown renderer — for email / Slack / Discord embed
# ---------------------------------------------------------------------------


def render_markdown(data: DigestData) -> str:
    """Markdown summary, Slack/Discord embed-friendly.

    Same caught-framing lead as the terminal renderer. Uses headings +
    bullets so it renders nicely in any Markdown-aware surface.
    """
    window = _window_label(data.time_window)
    lines: list[str] = []
    lines.append(f"# {_lead_line(window)}")
    lines.append("")

    totals = data.totals or {}
    audited = int(totals.get("total_requests_audited") or 0)
    denies = int(totals.get("total_denies") or 0)
    lines.append("## Across all bouncers")
    lines.append("")
    lines.append(f"- **{audited:,}** agent requests audited silently")
    if denies == 0:
        lines.append(
            "- **0** caught for review — quiet week. "
            "Your bouncer is observing without finding anything to flag."
        )
    else:
        lines.append(f"- **{denies}** caught for review:")
        legit = int(totals.get("total_appears_legitimate") or 0)
        ambig = int(totals.get("total_ambiguous") or 0)
        adv = int(totals.get("total_appears_adversarial") or 0)
        if legit:
            lines.append(f"  - `[+]` {legit} appeared legitimate")
        if ambig:
            lines.append(f"  - `[?]` {ambig} ambiguous")
        if adv:
            lines.append(
                f"  - `[!]` **{adv} appeared adversarial** "
                f"(still blocked — review when you're back)"
            )

    improve_cycles = int(totals.get("improve_cycles_run") or 0)
    auto_installed = int(totals.get("improve_changes_auto_installed") or 0)
    pending = int(totals.get("improve_changes_pending") or 0)
    if improve_cycles or auto_installed or pending:
        lines.append(
            f"- **{improve_cycles}** improvement cycle(s) ran in background"
        )
        if auto_installed:
            lines.append(
                f"  - {auto_installed} change(s) auto-installed within "
                f"your threshold"
            )
        if pending:
            lines.append(
                f"  - {pending} change(s) pending your approval"
            )
    pending_queue = int(totals.get("pending_approval_count") or 0)
    if pending_queue:
        lines.append(
            f"- **{pending_queue}** item(s) waiting in your allow-rule "
            f"approval queue"
        )

    lines.append("")
    if len(data.bouncers) > 1:
        lines.append("## Per bouncer")
        lines.append("")
        lines.append("| Bouncer | Status | Audited | Caught |")
        lines.append("|---|---|---:|---:|")
        for name, b in sorted(data.bouncers.items()):
            a = int(b.get("total_requests_audited") or 0)
            d = int(b.get("total_denies") or 0)
            s = b.get("status") or "no_data"
            lines.append(f"| {name} | {s} | {a:,} | {d} |")
        lines.append("")

    noteworthy: list[str] = []
    for _, b in sorted(data.bouncers.items()):
        for ev in b.get("noteworthy_events") or []:
            desc = ev.get("description") or ""
            if desc:
                noteworthy.append(desc)
    if noteworthy:
        lines.append("## Notable")
        lines.append("")
        for n in noteworthy[:10]:
            lines.append(f"- {n}")
        if len(noteworthy) > 10:
            lines.append(f"- ... +{len(noteworthy) - 10} more")
        lines.append("")

    if data.recommendations:
        lines.append("## Recommendations")
        lines.append("")
        for r in data.recommendations:
            lines.append(f"- {r}")
        lines.append("")

    if data.notes:
        lines.append("## Notes")
        lines.append("")
        for n in data.notes:
            lines.append(f"- {n}")
        lines.append("")

    lines.append(
        "_Run `iam-jit denies recent --since 1w` for per-row deny detail._"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML renderer — minimal, no JS, emailable
# ---------------------------------------------------------------------------


def render_html(data: DigestData) -> str:
    """Minimal HTML — no JS, inline styles only, suitable for email."""
    window = _window_label(data.time_window)
    totals = data.totals or {}
    audited = int(totals.get("total_requests_audited") or 0)
    denies = int(totals.get("total_denies") or 0)
    legit = int(totals.get("total_appears_legitimate") or 0)
    ambig = int(totals.get("total_ambiguous") or 0)
    adv = int(totals.get("total_appears_adversarial") or 0)

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html><head><meta charset="utf-8"><title>')
    parts.append(html.escape(_lead_line(window)))
    parts.append("</title></head><body style='font-family:system-ui,sans-serif;max-width:720px;margin:2em auto;line-height:1.5;'>")
    parts.append(f"<h1>{html.escape(_lead_line(window))}</h1>")

    parts.append("<h2>Across all bouncers</h2><ul>")
    parts.append(
        f"<li><strong>{audited:,}</strong> agent requests audited silently</li>"
    )
    if denies == 0:
        parts.append(
            "<li><strong>0</strong> caught for review — quiet week. "
            "Your bouncer is observing without finding anything to flag.</li>"
        )
    else:
        parts.append(f"<li><strong>{denies}</strong> caught for review:<ul>")
        if legit:
            parts.append(
                f"<li>[+] {legit} appeared legitimate</li>"
            )
        if ambig:
            parts.append(f"<li>[?] {ambig} ambiguous</li>")
        if adv:
            parts.append(
                f"<li style='color:#a00'><strong>[!] {adv} appeared adversarial</strong> "
                "(still blocked — review when you're back)</li>"
            )
        parts.append("</ul></li>")

    improve_cycles = int(totals.get("improve_cycles_run") or 0)
    auto_installed = int(totals.get("improve_changes_auto_installed") or 0)
    pending = int(totals.get("improve_changes_pending") or 0)
    if improve_cycles or auto_installed or pending:
        parts.append(
            f"<li><strong>{improve_cycles}</strong> improvement cycle(s) ran "
            f"in background; {auto_installed} auto-installed, {pending} pending</li>"
        )
    pending_queue = int(totals.get("pending_approval_count") or 0)
    if pending_queue:
        parts.append(
            f"<li><strong>{pending_queue}</strong> item(s) waiting in "
            "your allow-rule approval queue</li>"
        )
    parts.append("</ul>")

    if len(data.bouncers) > 1:
        parts.append("<h2>Per bouncer</h2>")
        parts.append("<table style='border-collapse:collapse;width:100%;'>")
        parts.append(
            "<thead><tr style='background:#f4f4f4;'>"
            "<th align='left' style='padding:0.4em;border-bottom:1px solid #ccc;'>Bouncer</th>"
            "<th align='left' style='padding:0.4em;border-bottom:1px solid #ccc;'>Status</th>"
            "<th align='right' style='padding:0.4em;border-bottom:1px solid #ccc;'>Audited</th>"
            "<th align='right' style='padding:0.4em;border-bottom:1px solid #ccc;'>Caught</th>"
            "</tr></thead><tbody>"
        )
        for name, b in sorted(data.bouncers.items()):
            a = int(b.get("total_requests_audited") or 0)
            d = int(b.get("total_denies") or 0)
            s = b.get("status") or "no_data"
            parts.append(
                f"<tr><td style='padding:0.3em;'>{html.escape(name)}</td>"
                f"<td style='padding:0.3em;'>{html.escape(str(s))}</td>"
                f"<td align='right' style='padding:0.3em;'>{a:,}</td>"
                f"<td align='right' style='padding:0.3em;'>{d}</td></tr>"
            )
        parts.append("</tbody></table>")

    noteworthy: list[str] = []
    for _, b in sorted(data.bouncers.items()):
        for ev in b.get("noteworthy_events") or []:
            desc = ev.get("description") or ""
            if desc:
                noteworthy.append(desc)
    if noteworthy:
        parts.append("<h2>Notable</h2><ul>")
        for n in noteworthy[:10]:
            parts.append(f"<li>{html.escape(n)}</li>")
        if len(noteworthy) > 10:
            parts.append(f"<li>... +{len(noteworthy) - 10} more</li>")
        parts.append("</ul>")

    if data.recommendations:
        parts.append("<h2>Recommendations</h2><ul>")
        for r in data.recommendations:
            parts.append(f"<li>{html.escape(r)}</li>")
        parts.append("</ul>")

    if data.notes:
        parts.append("<h2>Notes</h2><ul>")
        for n in data.notes:
            parts.append(f"<li>{html.escape(n)}</li>")
        parts.append("</ul>")

    parts.append(
        "<p><em>Run <code>iam-jit denies recent --since 1w</code> for "
        "per-row deny detail.</em></p>"
    )
    parts.append("</body></html>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Webhook card (Slack/Discord) — same payload shape as the autopilot's
# deny-notification webhook for consistency (operator sees a unified
# "bouncer is talking to me" channel).
# ---------------------------------------------------------------------------


def build_webhook_payload(data: DigestData) -> dict[str, Any]:
    """Build a Slack/Discord-compatible incoming-webhook payload.

    The card LEADS with caught-framing per
    ``[[ambient-value-prop-and-friction-framing]]``. Adversarial counts
    surface a ``color: danger`` attachment so the Slack UI bars red.
    Zero-deny weeks surface a ``color: good`` "quiet week" card.
    """
    window = _window_label(data.time_window)
    totals = data.totals or {}
    audited = int(totals.get("total_requests_audited") or 0)
    denies = int(totals.get("total_denies") or 0)
    adv = int(totals.get("total_appears_adversarial") or 0)
    pending = int(totals.get("pending_approval_count") or 0)

    if adv > 0:
        color = "danger"
    elif denies > 0:
        color = "warning"
    else:
        color = "good"

    fields: list[dict[str, Any]] = [
        {
            "title": "Requests audited",
            "value": f"{audited:,}",
            "short": True,
        },
        {
            "title": "Caught for review",
            "value": str(denies),
            "short": True,
        },
    ]
    if denies:
        legit = int(totals.get("total_appears_legitimate") or 0)
        ambig = int(totals.get("total_ambiguous") or 0)
        breakdown = (
            f"[+] {legit} legit  [?] {ambig} ambiguous  "
            f"[!] {adv} adversarial"
        )
        fields.append({
            "title": "Classification",
            "value": breakdown,
            "short": False,
        })
    if pending:
        fields.append({
            "title": "Allow queue pending",
            "value": f"{pending} item(s)",
            "short": True,
        })
    improve_cycles = int(totals.get("improve_cycles_run") or 0)
    auto_installed = int(totals.get("improve_changes_auto_installed") or 0)
    if improve_cycles or auto_installed:
        fields.append({
            "title": "Improve cycles",
            "value": (
                f"{improve_cycles} cycle(s), {auto_installed} auto-installed"
            ),
            "short": True,
        })

    if data.recommendations:
        rec_text = "\n".join(f"• {r}" for r in data.recommendations[:5])
        fields.append({
            "title": "Recommendations",
            "value": rec_text,
            "short": False,
        })

    text = _lead_line(window)
    if adv > 0:
        text += f"  -  {adv} adversarial deny(s) need review"
    return {
        "text": text,
        "attachments": [
            {
                "color": color,
                "fallback": text,
                "title": "iam-jit weekly digest",
                "fields": fields,
            }
        ],
    }


__all__ = [
    "build_webhook_payload",
    "render_html",
    "render_json",
    "render_markdown",
    "render_terminal",
]
