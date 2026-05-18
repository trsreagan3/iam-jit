"""#273 — `ibounce investigate` workflow helper.

Ties the existing #268 audit-tail export + #277 diagnostics bundle
together into a single one-shot "give me a Claude-ready evidence
pack" subcommand. The point is the operator opens THEIR Claude
session and drops the artifacts in — ibounce never sees the data,
never calls Anthropic, and stays on the local file system per
[[self-host-zero-billing-dependency]].

Two artifacts land in the chosen output directory:

  * ``ibounce-investigation.ndjson`` — OCSF Detection Finding bundle
    wrapping the filtered audit-tail events. The same shape as
    ``audit tail --export ocsf-bundle`` so a SIEM-side import has
    one schema to learn.
  * ``ibounce-investigation-context.zip`` — diagnostics bundle with
    redacted config / active-profile / system info / healthz
    snapshot. We pass ``--no-audit`` so the audit content isn't
    duplicated; the OCSF bundle already carries it.

Per [[security-team-positioning-safety-not-surveillance]] the
``--print-prompts`` block uses neutral framing ("denial",
"scope mismatch", "policy mismatch") and never the
"violation"/"infraction"/"unauthorized" vocabulary.

Per [[don't-tailor-to-lighthouse]] the prompts are generic — they
don't name a specific Claude client (Claude Code / Cursor /
desktop Claude / a hosted Anthropic console). The operator picks
the surface; ibounce just lands evidence.

Per [[creates-never-mutates]] the subcommand is strictly read-only.
It produces output files in the chosen --out-dir; it never edits
the store, the profiles file, or the audit log.
"""

from __future__ import annotations

import datetime as _dt
import pathlib
import re
from collections.abc import Iterable
from dataclasses import dataclass


# Output filenames the subcommand writes. Stable across runs so a
# follow-up `ibounce investigate` from the same operator overwrites
# the previous artifacts in the same --out-dir (rather than leaving
# a forest of timestamped files).
INVESTIGATION_EVIDENCE_FILENAME = "ibounce-investigation.ndjson"
INVESTIGATION_CONTEXT_FILENAME = "ibounce-investigation-context.zip"

# 10 generic starter prompts per the #273 spec. Cross-product
# alignment: kbounce / dbounce / gbounce ship the same list with
# product-specific token swaps (kbounce adds a pod-deletion prompt;
# dbounce adds a write-query prompt). Per
# [[security-team-positioning-safety-not-surveillance]] the
# language stays in the "investigate / review / cross-reference"
# register; nothing reads as accusation.
STARTER_PROMPTS: tuple[str, ...] = (
    "Review the past 24h of ibounce audit data. Anything that looks "
    "off?",
    "Which agent generated the most denies? Was it consistent or a "
    "one-shot spike?",
    "Did the heartbeat gap ever exceed 60s? If yes, when + how often?",
    "Are there bursts of similar operations from one agent? Identify "
    "the actor, time window, and operation set.",
    "Did any admin-action audit event happen outside normal working "
    "hours? List them with timestamps.",
    "Cross-reference the rule-trigger times against the audit-export "
    "channel's failures (if any). Any correlation?",
    "Are there deny patterns that suggest the wrong profile was "
    "loaded? Which profile name shows up in the denies?",
    "Which operations span the largest number of distinct actors? "
    "Rank them.",
    "Did the same agent.session_id show up across multiple ibounce "
    "deployments or restarts? Was that expected?",
    "Summarize the most common denial reasons and what they imply "
    "about the currently-active profile.",
)


@dataclass(frozen=True)
class InvestigateArtifacts:
    """Result returned by :func:`prepare_investigation`.

    The CLI prints a "now what" block keyed off these paths so the
    operator can copy them into their Claude session without
    scanning for filenames. Sizes are populated by the writer so the
    one-line stderr summary can report bytes.
    """

    evidence_path: pathlib.Path
    context_path: pathlib.Path
    evidence_bytes: int
    context_bytes: int
    event_count: int
    audit_log_present: bool


def default_out_dir() -> pathlib.Path:
    """Default --out-dir target: a per-invocation subdir under the
    OS temp directory.

    Why per-invocation rather than a fixed name? Two back-to-back
    `ibounce investigate` runs against different time windows
    shouldn't overwrite each other's evidence by surprise; the
    timestamp suffix preserves both.
    """
    import tempfile

    ts = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return pathlib.Path(tempfile.gettempdir()) / f"ibounce-investigate-{ts}"


# ---------------------------------------------------------------------------
# Time-range parsing
# ---------------------------------------------------------------------------


# Supported time-range suffixes — covers "last day / week / month"
# without dragging in a calendar library. Hours / days only;
# operators wanting finer granularity pipe `audit tail --filter`
# directly.
_TIME_RANGE_PATTERN = re.compile(r"^(\d+)([hdw])$", re.IGNORECASE)


class TimeRangeParseError(ValueError):
    """Raised when ``--time-range`` can't be parsed.

    Surfaced verbatim to the operator so the message itself is the
    documentation — no scrolling up to find a man page.
    """


def parse_time_range(expr: str) -> _dt.timedelta:
    """Parse a ``<N><unit>`` time-range expression.

    Forms: ``24h`` / ``7d`` / ``4w``. Anything else raises
    :class:`TimeRangeParseError` with a message naming the legal
    grammar (per the same UX pattern as ``audit tail --filter``).
    """
    if not expr or not isinstance(expr, str):
        raise TimeRangeParseError(
            "time-range expression cannot be empty"
        )
    m = _TIME_RANGE_PATTERN.match(expr.strip())
    if not m:
        raise TimeRangeParseError(
            f"time-range {expr!r}: expected <N>h | <N>d | <N>w "
            f"(e.g. '24h', '7d', '4w')"
        )
    n = int(m.group(1))
    unit = m.group(2).lower()
    if n <= 0:
        raise TimeRangeParseError(
            f"time-range {expr!r}: N must be positive"
        )
    if unit == "h":
        return _dt.timedelta(hours=n)
    if unit == "d":
        return _dt.timedelta(days=n)
    # unit == "w"
    return _dt.timedelta(weeks=n)


def time_range_to_filter_expr(window: _dt.timedelta, *, now: _dt.datetime | None = None) -> str:
    """Translate a parsed window into a tail-compatible filter
    expression of the form ``time>=<unix-ms>``.

    The audit-tail layer already supports numeric ``>=`` on dotted
    paths (OCSF ``time`` is unix-ms), so investigate can stay a thin
    composer over the existing surface — no new query language.
    """
    cutoff = (now or _dt.datetime.now(_dt.UTC)) - window
    cutoff_ms = int(cutoff.timestamp() * 1000)
    return f"time>={cutoff_ms}"


# ---------------------------------------------------------------------------
# Investigation worker
# ---------------------------------------------------------------------------


def render_now_what_block(
    artifacts: InvestigateArtifacts, *, prompt_count: int = 3
) -> str:
    """Render the "now what" guidance the CLI prints after writing
    the artifacts.

    Three prompt suggestions only — the full set is behind
    ``--print-prompts`` so the default exit screen stays scannable.
    The wording stays generic re: which Claude surface to use per
    [[don't-tailor-to-lighthouse]]; "local Claude client" covers
    Claude Code, Cursor's Claude integration, desktop Claude, and
    the Anthropic console without naming any of them.
    """
    lines: list[str] = [
        "",
        "Artifacts written:",
        f"  evidence  {artifacts.evidence_path}  "
        f"({artifacts.evidence_bytes} bytes, "
        f"{artifacts.event_count} event(s))",
        f"  context   {artifacts.context_path}  "
        f"({artifacts.context_bytes} bytes)",
    ]
    if not artifacts.audit_log_present:
        lines.append(
            "  note: the audit log was missing or empty for the "
            "selected window; the evidence file records the gap so "
            "your Claude analyst doesn't treat it as a bug."
        )
    lines.extend([
        "",
        "Next steps:",
        "  1. Open your local Claude client (Claude Code, Cursor's "
        "Claude integration, the desktop app — whichever you use).",
        "  2. Drop BOTH files into the conversation so the analyst "
        "has the events + the deployment context.",
        "  3. Start with one of these prompts (run "
        "`ibounce investigate --print-prompts` for the full list):",
    ])
    for prompt in STARTER_PROMPTS[:prompt_count]:
        lines.append(f"     - {prompt}")
    lines.append("")
    lines.append(
        "Privacy: ibounce does NOT send any data to Anthropic. The "
        "files stay on this host; the Claude session is YOURS. See "
        "docs/INVESTIGATE-WITH-CLAUDE.md for the full privacy story."
    )
    return "\n".join(lines)


def render_print_prompts_block() -> str:
    """Render the full ``--print-prompts`` block.

    Numbered for easy "use prompt 4 first" reference in
    documentation; the block is meant to be copy-pasted as a single
    chunk into the operator's notes file or runbook.
    """
    lines: list[str] = [
        "ibounce investigate — starter prompts",
        "=" * 50,
        "",
        "Paste any of these into your local Claude client AFTER "
        "uploading the two artifact files.",
        "",
    ]
    for i, prompt in enumerate(STARTER_PROMPTS, start=1):
        lines.append(f"{i:>2}. {prompt}")
    lines.append("")
    lines.append(
        "Privacy reminder: these prompts run inside YOUR Claude "
        "session. ibounce never calls Anthropic; the audit data "
        "leaves your host only if you choose to paste it."
    )
    return "\n".join(lines)


def collect_events_for_window(
    audit_path: pathlib.Path,
    *,
    extra_filters: Iterable[str] = (),
    window: _dt.timedelta | None = None,
    now: _dt.datetime | None = None,
) -> tuple[list[dict], bool]:
    """Read + filter the audit log to the events under investigation.

    Returns ``(events, audit_log_present)``. The second element is
    False when the file is missing OR exists-but-empty — the CLI
    surfaces that distinction so the operator's Claude analyst
    doesn't mis-diagnose "no events" as "ibounce is broken".

    Per [[creates-never-mutates]] this function never writes; the
    caller is responsible for materialising the OCSF bundle.
    """
    # Import lazily so the test that asserts "no network module is
    # touched" can validate the import graph more cheaply.
    from .audit_export.tail import (
        FilterParseError,
        iter_audit_file,
        parse_filter_expr,
    )

    audit_log_present = audit_path.exists() and audit_path.stat().st_size > 0
    events: list[dict] = []
    filters = []
    for expr in extra_filters:
        try:
            filters.append(parse_filter_expr(expr))
        except FilterParseError:
            # The CLI parses + validates filters up front so this
            # path should be unreachable from the user-facing entry
            # point; defensive raise keeps the contract obvious for
            # programmatic callers.
            raise
    if window is not None:
        filters.append(
            parse_filter_expr(time_range_to_filter_expr(window, now=now))
        )

    for event in iter_audit_file(audit_path):
        if all(f.matches(event) for f in filters):
            events.append(event)
    return events, audit_log_present


def write_investigation_evidence(
    events: list[dict],
    out_path: pathlib.Path,
    *,
    audit_log_present: bool,
    window: _dt.timedelta | None,
) -> int:
    """Materialise the OCSF Detection Finding bundle to ``out_path``.

    When ``events`` is empty we STILL write a valid bundle (count
    zero, severity Informational) so the operator's Claude analyst
    sees an explicit "no events in scope" finding rather than a
    missing file. The bundle's ``unmapped.iam_jit.investigate`` block
    records the requested window + whether the audit log was present
    so the analyst can distinguish "quiet day" from "log was wiped".
    """
    from .audit_export.tail import build_ocsf_bundle

    bundle = build_ocsf_bundle(
        events,
        title="ibounce investigate evidence",
    )
    bundle.setdefault("unmapped", {}).setdefault("iam_jit", {})[
        "investigate"
    ] = {
        "window_seconds": (
            int(window.total_seconds()) if window is not None else None
        ),
        "audit_log_present": audit_log_present,
        "event_count": len(events),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    import json as _json

    # NDJSON shape: one JSON document per line. With a single
    # Detection Finding wrapping all events the file is ONE line, but
    # the .ndjson extension keeps the door open for future emitters
    # that prefer a per-event line layout without a filename break.
    text = _json.dumps(bundle, ensure_ascii=False) + "\n"
    out_path.write_text(text, encoding="utf-8")
    return out_path.stat().st_size


def write_investigation_context(
    out_path: pathlib.Path,
    *,
    db_path: str | None = None,
    profiles_path: str | None = None,
    audit_log_path: pathlib.Path | None = None,
    healthz_url: str | None = None,
) -> int:
    """Build the diagnostics ZIP (per #277) with ``--no-audit``.

    We skip the audit-tail section because the evidence NDJSON
    already carries it; duplicating would inflate the artifact and
    risk drift between the two copies. The context bundle's
    contents (redacted config / active profile / healthz / system
    info) are exactly the supplementary info a Claude analyst needs
    to interpret the evidence in the operator's deployment.
    """
    from .diagnostics import (
        DEFAULT_HEALTHZ_URL,
        BundleOptions,
        write_diagnostics_bundle,
    )

    opts = BundleOptions(
        out_path=out_path,
        no_audit=True,
        db_path=db_path,
        profiles_path=profiles_path,
        audit_log_path=str(audit_log_path) if audit_log_path else None,
        healthz_url=healthz_url or DEFAULT_HEALTHZ_URL,
    )
    summary = write_diagnostics_bundle(opts)
    return summary.total_bytes


def prepare_investigation(
    *,
    out_dir: pathlib.Path,
    audit_path: pathlib.Path,
    extra_filters: Iterable[str] = (),
    window: _dt.timedelta | None = None,
    db_path: str | None = None,
    profiles_path: str | None = None,
    healthz_url: str | None = None,
    now: _dt.datetime | None = None,
) -> InvestigateArtifacts:
    """End-to-end worker: read events, write evidence + context.

    Split from the CLI handler so tests can drive the workflow
    without a Click runner. The CLI handler is a thin wrapper that
    formats the messages + emits the admin-action audit row.
    """
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    events, audit_log_present = collect_events_for_window(
        audit_path,
        extra_filters=extra_filters,
        window=window,
        now=now,
    )
    evidence_path = out_dir / INVESTIGATION_EVIDENCE_FILENAME
    context_path = out_dir / INVESTIGATION_CONTEXT_FILENAME

    evidence_bytes = write_investigation_evidence(
        events,
        evidence_path,
        audit_log_present=audit_log_present,
        window=window,
    )
    context_bytes = write_investigation_context(
        context_path,
        db_path=db_path,
        profiles_path=profiles_path,
        audit_log_path=audit_path,
        healthz_url=healthz_url,
    )
    return InvestigateArtifacts(
        evidence_path=evidence_path,
        context_path=context_path,
        evidence_bytes=evidence_bytes,
        context_bytes=context_bytes,
        event_count=len(events),
        audit_log_present=audit_log_present,
    )


__all__ = [
    "INVESTIGATION_CONTEXT_FILENAME",
    "INVESTIGATION_EVIDENCE_FILENAME",
    "InvestigateArtifacts",
    "STARTER_PROMPTS",
    "TimeRangeParseError",
    "collect_events_for_window",
    "default_out_dir",
    "parse_time_range",
    "prepare_investigation",
    "render_now_what_block",
    "render_print_prompts_block",
    "time_range_to_filter_expr",
    "write_investigation_context",
    "write_investigation_evidence",
]
