"""#268 — local-operator audit UX: filter / summary / export engine.

The `ibounce audit tail` subcommand wires its flags through the
functions in this module:

  * :func:`parse_filter_expr` + :func:`event_matches`  — `--filter`
  * :func:`summarize_events`                           — `--summary`
  * :func:`export_jsonl`, :func:`export_csv`,
    :func:`build_ocsf_bundle`                          — `--export`

The audit source for ibounce is the JSONL log produced by
``AuditLogWriter`` (one OCSF v1.1.0 class 6003 event per line). The
``ibounce run`` command points the writer at ``--audit-log-path`` and
this module reads back from the same path — :func:`iter_audit_file`
handles the read side (and :func:`follow_audit_file` does live tail
for ``--follow``).

Per the [[cross-product-agent-parity]] memo this filter / summary /
export surface is shared verbatim with kbounce + dbounce; a customer's
muscle memory transfers across the suite. Product-specific filterable
fields (e.g. ibounce's ``unmapped.iam_jit.ext.aws_region``) are still
selectable via dotted-path field references but are documented as
product-specific in ``docs/QUERYING-AUDIT-LOGS.md``.

Per [[security-team-positioning-safety-not-surveillance]] every new
human-facing string in this module avoids the forbidden vocabulary
("violation" / "infraction" / "unauthorized"). The verdict labels
("ALLOW" / "DENY") flow through unchanged because they're factual
OCSF status mappings, not editorial language.

Per [[creates-never-mutates]] every function here is read-only against
the audit file.

Per [[self-host-zero-billing-dependency]] no network calls; everything
runs on the local filesystem.

PII guard: the CSV exporter's default column set excludes
``actor.user.email`` (and any field whose dotted path includes
``email``) — the operator has to opt in with ``--csv-columns`` to
surface PII-shaped fields.
"""

from __future__ import annotations

import csv as _csv
import datetime as _dt
import io
import json
import os
import pathlib
import re
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

# Synthetic display label for plain decision events. The OCSF event
# carries `unmapped.iam_jit.event_type` only on synthetic events
# (HEARTBEAT, ADMIN_ACTION, AUDIT_DROPPED, ...); a regular decision
# has no marker. For summary tables and filtering, treat the absence
# of a marker as the implicit "DECISION" event_type so operators can
# count decisions vs synthetics without a special-case.
DECISION_EVENT_TYPE = "DECISION"

# Default CSV columns. Per the spec's PII guard: NO PII-shaped fields
# (anything an `email` / `phone` / `address` field would land in). The
# operator opts in with `--csv-columns` to include PII-shaped fields.
DEFAULT_CSV_COLUMNS: tuple[str, ...] = (
    "time",
    "severity_id",
    "event_type",
    "actor.user.name",
    "api.operation",
    "verdict",
    "unmapped.iam_jit.agent.name",
    "unmapped.iam_jit.agent.session_id",
)

# Fields whose CSV inclusion requires explicit `--csv-columns` opt-in.
# Match by substring on the dotted path; conservative on purpose so a
# new PII-shaped field added upstream is excluded by default.
_PII_PATH_HINTS: tuple[str, ...] = (
    "email",
    "phone",
    "address",
    "credential",
    "secret",
    "token",
)


# ---------------------------------------------------------------------------
# Dotted-path lookup
# ---------------------------------------------------------------------------


def get_path(event: dict[str, Any], path: str) -> Any:
    """Read a dotted path out of an OCSF event dict.

    ``get_path(e, "actor.user.name")`` returns
    ``e["actor"]["user"]["name"]`` or ``None`` if any intermediate key
    is missing (or the chain hits a non-dict). Never raises — the
    filter / summary / export pipeline always wants "field absent"
    rather than KeyError.

    Special-case: ``event_type`` (no dotted prefix) is treated as a
    shortcut for ``unmapped.iam_jit.event_type`` AND falls back to
    :data:`DECISION_EVENT_TYPE` when absent so plain decision events
    can be summarised + filtered without a per-call special-case at
    the caller.

    Special-case: ``verdict`` (no dotted prefix) is a shortcut for
    ``unmapped.iam_jit.verdict`` for the same reason.
    """
    if path == "event_type":
        explicit = get_path(event, "unmapped.iam_jit.event_type")
        return explicit or DECISION_EVENT_TYPE
    if path == "verdict":
        return get_path(event, "unmapped.iam_jit.verdict")
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


# ---------------------------------------------------------------------------
# Filter expressions
# ---------------------------------------------------------------------------


class FilterParseError(ValueError):
    """Raised when --filter EXPR can't be parsed.

    Surfaced verbatim to the operator (Click catches + prints) so the
    error message itself is the documentation.
    """


@dataclass(frozen=True)
class Filter:
    """One parsed filter expression.

    AND-combined with other filters in :func:`event_matches`. Four
    operators, all anchored to a dotted field path:

      ``=``   string equality (case-sensitive; we don't second-guess
              the operator — they wrote what they meant)
      ``~``   regex; :func:`re.search` semantics so partial-string
              matches work without manual ``.*`` anchors
      ``>=``  numeric comparison (event field coerced via float;
              non-numeric values fail the match)
      ``<=``  ditto

    The grammar deliberately doesn't grow further (no OR, no grouping,
    no negation). Per [[deliberate-feature-completion]] we ship the
    primary use cases (severity >= 3, agent name = X) and add more
    only when an operator asks; downstream tools (jq, DuckDB) do
    arbitrary boolean logic better.
    """

    field: str
    op: str
    raw_value: str

    def matches(self, event: dict[str, Any]) -> bool:
        value = get_path(event, self.field)
        if self.op == "=":
            if value is None:
                return False
            return str(value) == self.raw_value
        if self.op == "~":
            if value is None:
                return False
            try:
                return re.search(self.raw_value, str(value)) is not None
            except re.error:
                return False
        if self.op in (">=", "<="):
            if value is None:
                return False
            try:
                lhs = float(value)
                rhs = float(self.raw_value)
            except (TypeError, ValueError):
                return False
            return lhs >= rhs if self.op == ">=" else lhs <= rhs
        return False


# Operators ordered longest-first so the parser tries ``>=`` / ``<=``
# before falling through to single-char ``=``. ``~`` is single-char.
_OPERATORS: tuple[str, ...] = (">=", "<=", "=", "~")


def parse_filter_expr(expr: str) -> Filter:
    """Parse one ``field<op>value`` expression into a :class:`Filter`.

    Operators (checked longest-first so ``severity_id>=3`` parses as
    ``(severity_id, >=, 3)`` not ``(severity_id, =, ...)``):

      ``>=``  numeric ge
      ``<=``  numeric le
      ``=``   string eq
      ``~``   regex (re.search)

    Raises :class:`FilterParseError` with a helpful message — the
    operator sees the original expression in the error so they don't
    have to scroll up to figure out which ``--filter`` was bad.
    """
    if not expr or not isinstance(expr, str):
        raise FilterParseError("filter expression cannot be empty")
    for op in _OPERATORS:
        idx = expr.find(op)
        if idx > 0:
            field = expr[:idx].strip()
            raw_value = expr[idx + len(op):].strip()
            if not field:
                raise FilterParseError(
                    f"filter {expr!r}: missing field name before {op!r}"
                )
            if not raw_value:
                raise FilterParseError(
                    f"filter {expr!r}: missing value after {op!r}"
                )
            return Filter(field=field, op=op, raw_value=raw_value)
    raise FilterParseError(
        f"filter {expr!r}: expected one of '=', '~', '>=', '<=' "
        f"(e.g. 'severity_id>=3' or 'actor.user.name=alice')"
    )


def event_matches(event: dict[str, Any], filters: Iterable[Filter]) -> bool:
    """Return True iff ``event`` matches every filter (AND semantics)."""
    for f in filters:
        if not f.matches(event):
            return False
    return True


# ---------------------------------------------------------------------------
# Summary aggregation
# ---------------------------------------------------------------------------

# Default groupings for the --summary view. Matches kbounce + dbounce
# per [[cross-product-agent-parity]] so a customer scanning the same
# audit shape across three products sees the same table headings.
SUMMARY_GROUPINGS: tuple[tuple[str, str], ...] = (
    ("event_type counts", "event_type"),
    ("severity_id counts", "severity_id"),
    ("actor counts", "actor.user.name"),
    ("operation counts", "api.operation"),
)

# Severity labels per OCSF v1.1.0 base spec. Surfaced beside the
# numeric id in summary output so an operator who doesn't have the
# OCSF severity table memorised still reads it correctly.
_SEVERITY_LABEL = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}


def _summary_label(grouping_field: str, value: Any) -> str:
    """Format one group key for the summary table.

    severity_id gets the OCSF label appended; other groupings are
    rendered verbatim. Absent values render as ``"(none)"`` so the
    operator can spot "events with no actor" without it collapsing
    into the empty-string row that some terminals hide."""
    if value is None or value == "":
        return "(none)"
    if grouping_field == "severity_id":
        try:
            label = _SEVERITY_LABEL.get(int(value), "Unknown")
            return f"{value} ({label})"
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def summarize_events(
    events: Iterable[dict[str, Any]],
    groupings: Iterable[tuple[str, str]] = SUMMARY_GROUPINGS,
) -> list[tuple[str, list[tuple[str, int]]]]:
    """Produce the ``--summary`` output structure.

    Returns a list of ``(heading, [(label, count), ...])`` tuples —
    one per grouping. The list contains every grouping even when an
    empty audit log produced zero events (the heading shows up with
    an empty body so the operator sees "yes, the audit log was read,
    there was just nothing in it"). Per the spec's empty-log test.
    """
    materialised = list(events)
    out: list[tuple[str, list[tuple[str, int]]]] = []
    for heading, field in groupings:
        counter: Counter[str] = Counter()
        for ev in materialised:
            label = _summary_label(field, get_path(ev, field))
            counter[label] += 1
        # Sort by count desc, then label asc for deterministic output —
        # makes the CLI usable in CI / golden-file tests.
        rows = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
        out.append((heading, rows))
    return out


def render_summary(
    summary: list[tuple[str, list[tuple[str, int]]]],
) -> str:
    """Render a summary list as the CLI's ``--summary`` text block.

    Format intentionally mirrors the kbounce + dbounce equivalents
    per [[cross-product-agent-parity]] so a sibling product's output
    parses cleanly with the same regex.
    """
    lines: list[str] = []
    for heading, rows in summary:
        lines.append(f"{heading}:")
        if not rows:
            lines.append("  (no events)")
            continue
        label_w = max(len(label) for label, _ in rows)
        # Right-justify counts in an 8-wide column; readable up to
        # 9-digit counts (~100M events) without growing.
        for label, count in rows:
            lines.append(f"  {label:<{label_w}}  {count:>8}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Exporters
# ---------------------------------------------------------------------------


def export_jsonl(events: Iterable[dict[str, Any]], out_path: pathlib.Path) -> int:
    """Write ``events`` as JSONL to ``out_path``. Returns the row count.

    One JSON object per line, UTF-8, ``ensure_ascii=False`` so non-
    ASCII identifiers (a non-Latin agent name, a customer-supplied
    profile description) round-trip without escaping. Matches the
    on-disk format of the audit log itself so jq + DuckDB tooling
    consumes the export with the same recipe.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False))
            f.write("\n")
            count += 1
    return count


def _csv_column_is_pii(column: str) -> bool:
    """Return True iff a column's dotted path looks PII-shaped.

    Substring check against :data:`_PII_PATH_HINTS`; permissive on
    the safety-side per the spec: if a future OCSF field is named
    ``actor.user.email_hash`` we'd rather require explicit opt-in
    than silently emit it.
    """
    low = column.lower()
    return any(hint in low for hint in _PII_PATH_HINTS)


def resolve_csv_columns(
    explicit: list[str] | None,
) -> tuple[list[str], list[str]]:
    """Resolve the effective CSV column set + warn about PII columns.

    Returns ``(columns, warnings)``. ``warnings`` is empty for the
    default set; when the operator passes ``--csv-columns`` with a
    PII-shaped field we surface a stderr warning at the call site —
    that's the operator's opt-in moment per the spec's PII guard.
    """
    if explicit is None:
        return list(DEFAULT_CSV_COLUMNS), []
    cols = [c.strip() for c in explicit if c.strip()]
    warnings = [c for c in cols if _csv_column_is_pii(c)]
    return cols, warnings


def export_csv(
    events: Iterable[dict[str, Any]],
    out_path: pathlib.Path,
    columns: list[str] | None = None,
) -> int:
    """Write ``events`` as a CSV table to ``out_path``. Returns row count.

    The header row is the dotted-path column names verbatim (so a
    downstream consumer's column mapping is unambiguous).

    None values render as empty cells; nested objects (e.g. selecting
    ``unmapped.iam_jit`` as a column) JSON-serialise so a SIEM ingest
    can still recover the structure. The standard ``csv`` module
    handles quoting + escaping.
    """
    cols = columns if columns is not None else list(DEFAULT_CSV_COLUMNS)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = _csv.writer(f)
        writer.writerow(cols)
        for event in events:
            row: list[str] = []
            for col in cols:
                val = get_path(event, col)
                if val is None:
                    row.append("")
                elif isinstance(val, (dict, list)):
                    row.append(json.dumps(val, ensure_ascii=False))
                else:
                    row.append(str(val))
            writer.writerow(row)
            count += 1
    return count


# OCSF v1.1.0 class 2004 = "Detection Finding". The bundle wraps the
# filtered event list as evidence under a single Finding so a SIEM
# batch import surfaces them as one investigation rather than N
# unrelated events.
_DETECTION_FINDING_CLASS_UID = 2004
_DETECTION_FINDING_CLASS_NAME = "Detection Finding"
_DETECTION_FINDING_CATEGORY_UID = 2
_DETECTION_FINDING_CATEGORY_NAME = "Findings"
_DETECTION_FINDING_ACTIVITY_CREATE = 1
_DETECTION_FINDING_TYPE_UID = (
    _DETECTION_FINDING_CLASS_UID * 100 + _DETECTION_FINDING_ACTIVITY_CREATE
)


def _now_unix_ms() -> int:
    return int(_dt.datetime.now(_dt.UTC).timestamp() * 1000)


def build_ocsf_bundle(
    events: list[dict[str, Any]],
    *,
    title: str = "ibounce audit-tail export",
) -> dict[str, Any]:
    """Build an OCSF v1.1.0 class 2004 (Detection Finding) wrapping
    a filtered set of API Activity events as evidence.

    Why Detection Finding? It's the OCSF shape for "a security tool
    surfaced this collection of events for review" — exactly what a
    filtered audit-tail export is. Splunk + Sentinel + AWS Security
    Lake all index class 2004 as Findings so the bundle drops into
    the SIEM's existing investigation surface.

    The bundle's ``finding.severity_id`` is the MAX severity across
    the wrapped events (so a Finding containing one High event is
    itself High); empty input produces Informational. The wrapped
    events stay verbatim under ``finding.evidence.events`` — no
    re-encoding, no PII stripping (the operator already chose the
    filter scope; the bundle is what they asked us to export).
    """
    max_sev = 1
    for ev in events:
        sid = ev.get("severity_id")
        if isinstance(sid, int) and sid > max_sev:
            max_sev = sid
    sev_label = _SEVERITY_LABEL.get(max_sev, "Informational")

    # Per [[security-team-positioning-safety-not-surveillance]] the
    # bundle's message uses neutral framing — "events selected for
    # review", not "violations detected".
    return {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "ibounce",
                "vendor_name": "iam-jit",
            },
        },
        "time": _now_unix_ms(),
        "class_uid": _DETECTION_FINDING_CLASS_UID,
        "class_name": _DETECTION_FINDING_CLASS_NAME,
        "category_uid": _DETECTION_FINDING_CATEGORY_UID,
        "category_name": _DETECTION_FINDING_CATEGORY_NAME,
        "activity_id": _DETECTION_FINDING_ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": _DETECTION_FINDING_TYPE_UID,
        "type_name": (
            f"{_DETECTION_FINDING_CLASS_NAME}: Create"
        ),
        "severity_id": max_sev,
        "severity": sev_label,
        "status_id": 1,
        "status": "Success",
        "message": (
            f"{title}: {len(events)} event(s) selected for review"
        ),
        "finding": {
            "uid": f"audit-tail-{_now_unix_ms()}",
            "title": title,
            "types": ["audit-tail-export"],
            "evidence": {
                "events": events,
            },
        },
        "unmapped": {
            "iam_jit": {
                "event_type": "AUDIT_TAIL_EXPORT",
                "bundle_count": len(events),
            },
        },
    }


def export_ocsf_bundle(
    events: Iterable[dict[str, Any]],
    out_path: pathlib.Path,
    *,
    title: str = "ibounce audit-tail export",
) -> int:
    """Materialise + write an OCSF Detection Finding bundle. Returns
    the count of wrapped events."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    evs = list(events)
    bundle = build_ocsf_bundle(evs, title=title)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
    return len(evs)


# ---------------------------------------------------------------------------
# Reading the audit JSONL file
# ---------------------------------------------------------------------------


def iter_audit_file(path: pathlib.Path) -> Iterator[dict[str, Any]]:
    """Yield events from a JSONL audit log, oldest first.

    Skips lines that don't JSON-parse (a partial write interrupted
    mid-line, a logrotate gap). The writer's on-disk format is line-
    atomic for sub-PIPE_BUF sizes so partial lines are rare, but a
    SIGKILL'd process can leave one — we treat it as a single dropped
    row rather than failing the whole tail.

    Returns an empty iterator if the file doesn't exist (matches the
    "no events yet" path the CLI's `--summary` test exercises).
    """
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def follow_audit_file(
    path: pathlib.Path,
    *,
    poll_interval_s: float = 0.5,
    stop_flag: dict[str, bool] | None = None,
    yield_existing: bool = False,
) -> Iterator[dict[str, Any]]:
    """``tail -f`` over a JSONL audit log.

    Polls every ``poll_interval_s`` (default 500ms per the spec). When
    ``yield_existing`` is False (the default) the iterator seeks to
    EOF before its first read so live-tail shows ONLY new events; the
    operator's existing terminal scrollback already has the history.

    Stop control via the ``stop_flag`` dict — the CLI's SIGINT handler
    flips ``stop_flag["stop"] = True`` and the loop exits cleanly. We
    don't catch SIGINT inside this module because a library function
    grabbing signals would surprise embedders.

    Handles log rotation: if the file shrinks (truncate) or
    disappears (rename) we re-open from start; if the inode changes
    we reopen too (matches `tail -F` semantics).
    """
    if stop_flag is None:
        stop_flag = {}

    def _open() -> tuple[Any, int, int] | tuple[None, int, int]:
        """Open the file + return (handle, inode, size). Returns
        (None, 0, 0) if the file doesn't exist yet — caller polls.
        """
        try:
            st = path.stat()
        except FileNotFoundError:
            return None, 0, 0
        f = path.open("r", encoding="utf-8")
        return f, st.st_ino, st.st_size

    # Wait for the file to appear if it doesn't exist yet; the
    # operator can `ibounce audit tail --follow` before starting
    # `ibounce run` and we'll attach when the file shows up.
    handle: Any = None
    inode = 0
    while handle is None:
        if stop_flag.get("stop"):
            return
        handle, inode, _ = _open()
        if handle is None:
            time.sleep(poll_interval_s)

    try:
        if not yield_existing:
            handle.seek(0, io.SEEK_END)
        buffer = ""
        while not stop_flag.get("stop"):
            chunk = handle.read()
            if chunk:
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
                continue
            # No data — check for rotation before sleeping.
            try:
                st = path.stat()
            except FileNotFoundError:
                # File rotated away; re-poll for it to come back.
                handle.close()
                handle = None
                while handle is None:
                    if stop_flag.get("stop"):
                        return
                    time.sleep(poll_interval_s)
                    handle, inode, _ = _open()
                continue
            current_pos = handle.tell()
            if st.st_ino != inode or st.st_size < current_pos:
                # Inode changed (rename + create) or file truncated
                # under us — reopen from start.
                handle.close()
                handle, inode, _ = _open()
                if handle is None:
                    time.sleep(poll_interval_s)
                continue
            time.sleep(poll_interval_s)
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Row-rendering helpers used by the CLI's plain (non-summary) view
# ---------------------------------------------------------------------------


def render_event_row(event: dict[str, Any]) -> str:
    """One-line summary for ``ibounce audit tail`` (non-summary mode).

    Format:
      ``<ISO time>  sev=<n>  <event_type>  <actor>  <api.op>  <verdict>``

    Chosen so the column order matches the CSV default; an operator
    scanning the terminal sees the same columns the CSV export would
    write. The verdict cell is omitted (empty) for synthetic events
    that don't carry one.
    """
    time_ms = event.get("time")
    if isinstance(time_ms, int):
        ts = _dt.datetime.fromtimestamp(time_ms / 1000, tz=_dt.UTC).isoformat(
            timespec="seconds"
        )
    else:
        ts = str(time_ms or "")
    sev = event.get("severity_id", "")
    ev_type = get_path(event, "event_type") or ""
    actor = get_path(event, "actor.user.name") or ""
    op = get_path(event, "api.operation") or ""
    verdict = get_path(event, "unmapped.iam_jit.verdict") or ""
    return (
        f"{ts}  sev={sev}  {ev_type}  "
        f"{actor or '-'}  {op or '-'}  {verdict}"
    ).rstrip()


def default_audit_log_path() -> pathlib.Path:
    """Return the conventional ibounce audit log path.

    Mirrors ``bouncer.store.default_db_path``: respects an env-var
    override (``IAM_JIT_BOUNCER_AUDIT_LOG``) for self-host operators
    who want the log somewhere other than ``~/.iam-jit/audit.jsonl``,
    otherwise the conventional home-directory location.

    The path is advisory — :func:`iter_audit_file` returns an empty
    iterator if the file doesn't exist, so a fresh install with no
    audit data behaves correctly without special-casing.
    """
    override = os.environ.get("IAM_JIT_BOUNCER_AUDIT_LOG")
    if override:
        return pathlib.Path(override)
    return pathlib.Path.home() / ".iam-jit" / "audit.jsonl"
