"""#271 — `iam-jit audit query` cross-bouncer audit-query CLI.

Composes on top of #268 (per-product `audit tail` with filters) +
#271 A (per-bouncer GET /audit/events HTTP endpoint) by giving the
operator ONE command that queries multiple bouncers at once:

    iam-jit audit query [--bouncer ibounce,kbounce,dbounce,gbounce]
                        [--since ISO8601] [--until ISO8601]
                        [--filter EXPR ...]
                        [--limit N]
                        [--format jsonl|ocsf-bundle|csv|summary]
                        [--audit-events-token TOKEN]

Default behavior:

  * Probe localhost for all 4 bouncers' management ports (skip
    unreachable ones with a stderr note)
  * Query each reachable bouncer's `/audit/events` in parallel
  * Merge results, sort by timestamp
  * Apply the requested format

Per ``[[cross-product-agent-parity]]`` every Bounce-suite product
ships the same `/audit/events` endpoint shape, so this CLI is product-
agnostic — adding a new bouncer to the suite is one entry in the
DEFAULT_BOUNCERS dict.

Per ``[[creates-never-mutates]]`` read-only.
Per ``[[self-host-zero-billing-dependency]]`` no phone-home; the CLI
only ever talks to operator-controlled localhost mgmt ports.
Per ``[[security-team-positioning-safety-not-surveillance]]`` the
user-facing strings stay in neutral framing (no surveillance-vocab
language; the audit-query surface is for "events selected for
review", not blame-assigning incident framing).
"""

from __future__ import annotations

import csv as _csv
import io
import json
import sys
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, NamedTuple
from urllib import parse as _urlparse
from urllib import request as _urlrequest
from urllib.error import HTTPError, URLError

import click


class BouncerEndpoint(NamedTuple):
    """One configured bouncer probe target."""

    name: str
    """The bouncer's short name (e.g. ``ibounce``)."""

    mgmt_url: str
    """The base URL of the bouncer's management port (no trailing
    slash). ``/audit/events`` is appended at query time."""


DEFAULT_BOUNCERS: dict[str, BouncerEndpoint] = {
    "ibounce": BouncerEndpoint(name="ibounce", mgmt_url="http://127.0.0.1:8767"),
    "kbounce": BouncerEndpoint(name="kbounce", mgmt_url="http://127.0.0.1:8766"),
    "dbounce": BouncerEndpoint(name="dbounce", mgmt_url="http://127.0.0.1:8768"),
    "gbounce": BouncerEndpoint(name="gbounce", mgmt_url="http://127.0.0.1:8769"),
}
"""Default-probe set per ``[[cross-product-agent-parity]]``: every
Bounce-suite product ships a known mgmt port.

  * ibounce — 8767 (legacy iam-jit-bouncer port)
  * kbounce — 8766
  * dbounce — 8768
  * gbounce — 8769 (mgmt; proxy on 8080)

Operators with non-default ports pass ``--bouncer
name=http://host:port`` to override one entry."""


# Module-level so tests can monkeypatch — gives a hook to swap out the
# real urlopen for a mock without threading kwargs everywhere.
_urlopen = _urlrequest.urlopen
_DEFAULT_TIMEOUT_SECONDS = 5.0
"""Per-bouncer HTTP request timeout. 5s is long enough for the slow-
network case (a remote bouncer over a VPN, say) and short enough that
one unreachable bouncer doesn't pin the cross-bouncer query."""


# #320 / §A18 — short-form filter alias map. UAT 2026-05-22 surfaced
# that the headline cross-bouncer query example uses the short form
# `agent.session_id=X` (copy-pasted from the IAM-JIT-AUDIT-QUERY.md
# spec) but the per-bouncer parsers only accept the canonical long
# form `unmapped.iam_jit.agent.session_id=X` — every copy-paste
# returned HTTP 400. The fix is to expand short forms to their
# canonical long forms CLIENT-SIDE before forwarding so each bouncer
# still sees a fully-qualified field path. Documented in CLI help +
# docs/INTEGRATION-OPENCLAW-NANOCLAW.md.
#
# Per [[cross-product-agent-parity]] the canonical fields are the
# same across all four bouncers — the short-form alias map is one
# shared catalog. Future short-forms (verdict, severity, etc.) land
# here.
_SHORT_FORM_ALIASES: dict[str, str] = {
    "agent.session_id": "unmapped.iam_jit.agent.session_id",
    "agent.name": "unmapped.iam_jit.agent.name",
    "agent.detected_from": "unmapped.iam_jit.agent.detected_from",
}


def _expand_short_form_filter(expr: str) -> str:
    """Expand a short-form filter expression to its canonical OCSF
    long form. Pass-through for anything that doesn't match a known
    short-form prefix — preserves the existing exact-match behavior
    for callers that already pass the canonical path.

    Supports the four filter operators the per-bouncer parsers
    accept: `=`, `~`, `>=`, `<=`. The split is on the FIRST operator
    occurrence so a value containing `=` (e.g. base64) round-trips
    correctly.

    Examples:
        agent.session_id=01968d6a-...     → unmapped.iam_jit.agent.session_id=01968d6a-...
        agent.name~claude                  → unmapped.iam_jit.agent.name~claude
        unmapped.iam_jit.agent.name=psql  → unmapped.iam_jit.agent.name=psql   (no change)
        api.service.name=mysql             → api.service.name=mysql             (no change)
    """
    # Order matters: `>=` and `<=` are 2-char operators; split on them
    # first so the single-char `=` / `~` don't false-match.
    for op in (">=", "<=", "=", "~"):
        idx = expr.find(op)
        if idx <= 0:
            continue
        field = expr[:idx]
        rest = expr[idx:]
        canonical = _SHORT_FORM_ALIASES.get(field)
        if canonical is None:
            return expr
        return canonical + rest
    return expr


def _expand_short_form_filters(filters: tuple[str, ...]) -> tuple[str, ...]:
    """Apply _expand_short_form_filter to every entry in a tuple of
    filter expressions. Tuple-in / tuple-out so the call site can
    swap the click multi-option output directly."""
    return tuple(_expand_short_form_filter(f) for f in filters)


class _BouncerQueryResult(NamedTuple):
    """One bouncer's result of the parallel fan-out. Either ``events``
    is populated (success) or ``error`` is non-empty (probe-failed /
    HTTP-failed / parse-failed)."""

    bouncer: str
    events: list[dict[str, Any]]
    error: str


def _query_one_bouncer(
    endpoint: BouncerEndpoint,
    *,
    since: str | None,
    until: str | None,
    filters: tuple[str, ...],
    limit: int,
    bearer_token: str | None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> _BouncerQueryResult:
    """Run one GET /audit/events against one bouncer + return its
    events. Translates each bouncer's NDJSON response into a
    ``[dict, ...]``. The OCSF wire shape is identical across bouncers
    per ``[[cross-product-agent-parity]]`` so the merge layer treats
    them uniformly."""
    query_params: list[tuple[str, str]] = [("limit", str(limit))]
    if since:
        query_params.append(("since", since))
    if until:
        query_params.append(("until", until))
    for f in filters:
        query_params.append(("filter", f))
    qs = _urlparse.urlencode(query_params)
    url = f"{endpoint.mgmt_url}/audit/events?{qs}"

    headers = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    req = _urlrequest.Request(url, headers=headers)
    try:
        with _urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")
            err_msg = json.loads(err_body).get("error") or err_body
        except Exception:
            err_msg = str(e)
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[],
            error=f"HTTP {e.code}: {err_msg}",
        )
    except URLError as e:
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[],
            error=f"unreachable: {e.reason}",
        )
    except Exception as e:  # pragma: no cover — defensive
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[],
            error=f"{type(e).__name__}: {e}",
        )

    events: list[dict[str, Any]] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError as e:
            return _BouncerQueryResult(
                bouncer=endpoint.name, events=[],
                error=f"NDJSON parse: {e}",
            )
        # Stamp the source bouncer so cross-product correlation later
        # can group by bouncer without re-walking metadata.product.name.
        ev.setdefault("_bouncer", endpoint.name)
        events.append(ev)
    return _BouncerQueryResult(
        bouncer=endpoint.name, events=events, error="",
    )


def _event_time_key(ev: dict[str, Any]) -> int:
    """Sort key: OCSF ``time`` (Unix ms). Missing or non-numeric
    sorts to 0 so a malformed event still appears in the merged
    stream rather than crashing the sort."""
    t = ev.get("time")
    if isinstance(t, int):
        return t
    if isinstance(t, float):
        return int(t)
    if isinstance(t, str):
        try:
            return int(float(t))
        except ValueError:
            return 0
    return 0


def _format_summary(results: list[_BouncerQueryResult]) -> str:
    """Per-bouncer + total counts. Stable order matches the
    DEFAULT_BOUNCERS dict + suite naming order."""
    lines = []
    total = 0
    for r in results:
        if r.error:
            lines.append(f"{r.bouncer}: (unreachable: {r.error})")
            continue
        lines.append(f"{r.bouncer}: {len(r.events)} events")
        total += len(r.events)
    lines.append(f"total: {total} events")
    return "\n".join(lines) + "\n"


# OCSF Detection Finding constants for the cross-bouncer bundle.
_DETECTION_FINDING_CLASS_UID = 2004
_DETECTION_FINDING_CLASS_NAME = "Detection Finding"
_DETECTION_FINDING_CATEGORY_UID = 2
_DETECTION_FINDING_CATEGORY_NAME = "Findings"


def _format_ocsf_bundle(events: list[dict[str, Any]]) -> str:
    """Wrap all events from all bouncers in ONE Detection Finding so
    a SIEM batch import sees the cross-product correlation as a single
    artifact. Useful for #273 investigate-with-claude — the bundle is
    the single file the operator drops into their Claude client."""
    now_ms = int(_time.time() * 1000)
    bouncers = sorted({ev.get("_bouncer", "unknown") for ev in events})
    bundle = {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "iam-jit audit query",
                "vendor_name": "iam-jit",
            },
        },
        "time": now_ms,
        "class_uid": _DETECTION_FINDING_CLASS_UID,
        "class_name": _DETECTION_FINDING_CLASS_NAME,
        "category_uid": _DETECTION_FINDING_CATEGORY_UID,
        "category_name": _DETECTION_FINDING_CATEGORY_NAME,
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": _DETECTION_FINDING_CLASS_UID * 100 + 1,
        "type_name": f"{_DETECTION_FINDING_CLASS_NAME}: Create",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "message": (
            f"Cross-bouncer audit query: {len(events)} event(s) "
            f"from {len(bouncers)} bouncer(s) "
            f"({', '.join(bouncers) or 'none'})"
        ),
        "finding": {
            "uid": f"iam-jit-audit-query-{now_ms}",
            "title": "iam-jit cross-bouncer audit query",
            "types": ["cross-bouncer-correlation"],
            "evidence": {
                "events": events,
                "bouncers": bouncers,
            },
        },
        "unmapped": {
            "iam_jit": {
                "event_type": "AUDIT_QUERY_BUNDLE",
                "bundle_count": len(events),
                "bouncers": bouncers,
            },
        },
    }
    return json.dumps(bundle, indent=2) + "\n"


# CSV column order. Matches the default cross-product set per the
# kbounce/dbounce/gbounce CSV-export conventions; adds `bouncer` as
# the first column so a cross-product CSV is immediately groupable.
_DEFAULT_CSV_COLUMNS = (
    "bouncer",
    "time",
    "severity_id",
    "activity_name",
    "actor.user.name",
    "api.operation",
    "verdict",
)


def _csv_cell(ev: dict[str, Any], col: str) -> str:
    """Project one OCSF event field for the CSV exporter. Special-cases
    the `bouncer` column (sourced from the synthetic ``_bouncer`` field
    stamped at query time) and the convenience aliases
    (``verdict`` -> ``unmapped.iam_jit.verdict``)."""
    if col == "bouncer":
        return str(ev.get("_bouncer") or "")
    if col == "verdict":
        ext = (
            ev.get("unmapped", {}).get("iam_jit", {}).get("verdict")
        )
        return str(ext or "")
    cur: Any = ev
    for part in col.split("."):
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(part)
        if cur is None:
            return ""
    return str(cur)


def _format_csv(events: list[dict[str, Any]]) -> str:
    """Emit RFC 4180 CSV with the default column order."""
    buf = io.StringIO()
    w = _csv.writer(buf)
    w.writerow(_DEFAULT_CSV_COLUMNS)
    for ev in events:
        w.writerow([_csv_cell(ev, c) for c in _DEFAULT_CSV_COLUMNS])
    return buf.getvalue()


def _format_jsonl(events: list[dict[str, Any]]) -> str:
    """Emit one JSON-encoded event per line. Default format."""
    return "".join(
        json.dumps(ev, default=str, separators=(",", ":")) + "\n"
        for ev in events
    )


def _parse_bouncer_override(raw: str) -> BouncerEndpoint:
    """Parse a `--bouncer name=URL` override into a BouncerEndpoint.

    Two forms accepted:

      * ``ibounce``                → use DEFAULT_BOUNCERS["ibounce"]
      * ``ibounce=http://host:N`` → use the given URL

    Unknown name forms (e.g. ``mybounce=...``) are accepted too — the
    CLI is product-agnostic; the name is just a label in the summary.
    """
    if "=" in raw:
        name, url = raw.split("=", 1)
        name = name.strip()
        url = url.strip().rstrip("/")
        if not name or not url:
            raise click.BadParameter(
                f"--bouncer {raw!r}: expected name=URL with non-empty parts",
            )
        return BouncerEndpoint(name=name, mgmt_url=url)
    name = raw.strip()
    if name in DEFAULT_BOUNCERS:
        return DEFAULT_BOUNCERS[name]
    raise click.BadParameter(
        f"--bouncer {raw!r}: unknown bouncer name; "
        f"use one of {sorted(DEFAULT_BOUNCERS)} or pass name=URL explicitly",
    )


def _resolve_bouncer_set(
    raw: tuple[str, ...] | None,
) -> list[BouncerEndpoint]:
    """Resolve the operator's ``--bouncer`` flags into the probe set.
    Empty input = probe all four DEFAULT_BOUNCERS."""
    if not raw:
        return list(DEFAULT_BOUNCERS.values())
    out: list[BouncerEndpoint] = []
    for one in raw:
        # Allow comma-separated within one flag value:
        # `--bouncer ibounce,kbounce`.
        for part in one.split(","):
            part = part.strip()
            if not part:
                continue
            out.append(_parse_bouncer_override(part))
    return out


def register_audit_query_group(parent_group: click.Group) -> click.Group:
    """Register the `audit` subcommand-group on the iam-jit CLI.

    Called from :func:`iam_jit.cli.main` at import time so the existing
    ``iam-jit`` CLI surfaces ``iam-jit audit query`` without disturbing
    the existing top-level commands.

    Returns the newly-registered ``audit`` Click group so callers
    (e.g. ``register_audit_stream_command`` from #272) can hang
    additional subcommands off it without re-declaring the parent
    group.
    """

    @parent_group.group("audit")
    def audit_group() -> None:
        """Cross-bouncer audit queries + live streaming (#271, #272).

        Composes per-bouncer GET /audit/events endpoints into one
        merged + sorted stream. See :doc:`docs/IAM-JIT-AUDIT-QUERY.md`
        and :doc:`docs/AUDIT-STREAM-TUI.md` for the full guides.
        """

    @audit_group.command("query")
    @click.option(
        "--bouncer", "bouncers_raw",
        multiple=True,
        help="Which bouncer(s) to query. Repeatable; comma-separated "
             "also accepted. Default: probe all four default bouncers "
             "on their standard mgmt ports (ibounce 8767, kbounce 8766, "
             "dbounce 8768, gbounce 8769). Override one entry with "
             "`name=URL` (e.g. `kbounce=http://10.0.0.5:8766`).",
    )
    @click.option(
        "--since",
        default=None,
        help="ISO 8601 / RFC 3339 lower time bound. Forwarded to each "
             "bouncer verbatim. Example: `--since 2026-05-18T00:00:00Z`.",
    )
    @click.option(
        "--until",
        default=None,
        help="ISO 8601 / RFC 3339 upper time bound. Forwarded to each "
             "bouncer verbatim. Example: `--until 2026-05-18T23:59:59Z`.",
    )
    @click.option(
        "--filter", "filter_exprs",
        multiple=True,
        metavar="EXPR",
        help="Filter expression (repeatable; AND semantics). Forms: "
             "field=value | field~regex | field>=N | field<=N. "
             "Short-form aliases for the agent block (#320 / §A18): "
             "`agent.session_id=X` / `agent.name=X` / "
             "`agent.detected_from=X` expand to their canonical "
             "`unmapped.iam_jit.agent.*` paths client-side before "
             "forwarding. Forwarded to each bouncer's "
             "/audit/events?filter= so the filter runs server-side. "
             "See each product's docs/QUERYING-AUDIT-LOGS.md for the "
             "full supported field catalog.",
    )
    @click.option(
        "--limit",
        type=int,
        default=100,
        show_default=True,
        help="Per-bouncer response cap. Each bouncer returns up to "
             "this many events; the merged stream is the union, "
             "sorted by timestamp.",
    )
    @click.option(
        "--format", "fmt",
        type=click.Choice(
            ["jsonl", "ocsf-bundle", "csv", "summary"],
            case_sensitive=False,
        ),
        default="jsonl",
        show_default=True,
        help="Output format. `jsonl` = one merged + sorted OCSF event "
             "per line. `ocsf-bundle` = ONE Detection Finding wrapping "
             "events from all bouncers (cross-product correlation in a "
             "single SIEM-ingestible artifact). `csv` = tabular with "
             "the per-bouncer column. `summary` = per-bouncer + total "
             "counts (no event bodies).",
    )
    @click.option(
        "--audit-events-token",
        "audit_events_token",
        default=None,
        help="Bearer token sent to every bouncer's /audit/events. "
             "Required when ANY of the queried bouncers is bound off-"
             "loopback (the per-bouncer mgmt port refuses external "
             "binds without an --audit-events-token at run time). "
             "Loopback queries don't need this.",
    )
    @click.option(
        "--timeout",
        type=float,
        default=_DEFAULT_TIMEOUT_SECONDS,
        show_default=True,
        help="Per-bouncer HTTP timeout in seconds. One slow bouncer "
             "won't pin the cross-bouncer query — each runs in a "
             "thread + the merge layer drops late responders.",
    )
    @click.option(
        "--extract-permissions",
        "extract_permissions",
        is_flag=True,
        default=False,
        help="#419 / §A58 — instead of returning OCSF events, project "
             "the window into a structured permission set "
             "({action, resources, count}+observed_scope) ready for "
             "`iam_jit_request_role_from_synthesis`. Phase E of "
             "[[bouncer-informs-agent-informs-iam-jit]]. Implies "
             "single-bouncer scope — pass exactly one --bouncer.",
    )
    def audit_query_cmd(
        bouncers_raw: tuple[str, ...],
        since: str | None,
        until: str | None,
        filter_exprs: tuple[str, ...],
        limit: int,
        fmt: str,
        audit_events_token: str | None,
        timeout: float,
        extract_permissions: bool,
    ) -> None:
        """Query audit events across every reachable bouncer in
        parallel. Default probes ibounce/kbounce/dbounce/gbounce on
        loopback and merges the per-bouncer response streams into one
        sorted OCSF NDJSON output.

        \b
        Examples:
          # Latest 50 events across all four default bouncers.
          iam-jit audit query --limit 50

          # Cross-product correlation for one agent session (short form;
          # the CLI expands `agent.session_id` to the canonical
          # `unmapped.iam_jit.agent.session_id` before forwarding).
          iam-jit audit query \\
              --filter agent.session_id=019687ef-... \\
              --format ocsf-bundle > session-bundle.json

          # Same query in canonical long form (always supported).
          iam-jit audit query \\
              --filter unmapped.iam_jit.agent.session_id=019687ef-...

          # Counts only.
          iam-jit audit query --format summary

          # Override one bouncer's URL (rest = defaults).
          iam-jit audit query --bouncer kbounce=http://10.0.0.5:8766
        """
        if limit < 1 or limit > 10_000:
            raise click.BadParameter("--limit must be in 1..10000")

        # #320 / §A18: expand short-form filter aliases (e.g.
        # `agent.session_id=X` → `unmapped.iam_jit.agent.session_id=X`)
        # CLIENT-SIDE before forwarding so each bouncer's per-product
        # filter parser still sees the canonical OCSF long-form path.
        # UAT verified the spec-example copy-pasted short-form crashed
        # per-bouncer parsers with HTTP 400; this expansion closes the
        # gap without requiring per-bouncer changes.
        filter_exprs = _expand_short_form_filters(filter_exprs)

        bouncers = _resolve_bouncer_set(bouncers_raw)
        if not bouncers:
            raise click.UsageError(
                "no bouncers to query; pass --bouncer name (or name=URL)",
            )

        # Parallel fan-out. ThreadPoolExecutor (NOT asyncio) keeps the
        # CLI dependency-light + lets us reuse urllib without an
        # async-HTTP package. One worker per bouncer is the natural
        # ceiling — bumping the pool wouldn't help since each future
        # blocks on one I/O call.
        results: list[_BouncerQueryResult] = []
        with ThreadPoolExecutor(max_workers=len(bouncers)) as pool:
            futures = {
                pool.submit(
                    _query_one_bouncer,
                    e,
                    since=since,
                    until=until,
                    filters=filter_exprs,
                    limit=limit,
                    bearer_token=audit_events_token,
                    timeout=timeout,
                ): e
                for e in bouncers
            }
            for fut in as_completed(futures):
                results.append(fut.result())

        # Stable stderr-noting for unreachable bouncers — per the spec:
        # "Skip unreachable ones with a stderr note." Reachable bouncers
        # that returned an HTTP error also surface here so the operator
        # sees auth failures + bad filter syntax without staring at an
        # empty stdout.
        for r in sorted(results, key=lambda x: x.bouncer):
            if r.error:
                click.echo(
                    f"note: {r.bouncer} skipped ({r.error})",
                    err=True,
                )

        if fmt == "summary":
            # Stable name order for predictable output across runs.
            ordered = sorted(results, key=lambda x: x.bouncer)
            click.echo(_format_summary(ordered), nl=False)
            return

        # Merge + sort. ``_event_time_key`` puts oldest-first so the
        # merged stream reads chronologically (matches `audit tail`
        # default which is newest-first reversed for the live tail).
        merged: list[dict[str, Any]] = []
        for r in results:
            merged.extend(r.events)
        merged.sort(key=_event_time_key)

        # #419 / §A58 — `--extract-permissions` reshapes the merged
        # event stream into the structured permission-set shape used
        # by `iam_jit_request_role_from_synthesis`. We delegate to the
        # audit_extract module so the same projection is shared with
        # the MCP tool. Single-bouncer semantics — the agent
        # synthesises ROLES from ONE bouncer's window, never a merged
        # cross-bouncer set (mixing kbouncer activity into an iam-jit
        # AWS role request would be a category error).
        if extract_permissions:
            if len(bouncers) != 1:
                raise click.UsageError(
                    "--extract-permissions requires exactly one "
                    "--bouncer (the source of the permission set); "
                    f"got {len(bouncers)} bouncer(s).",
                )
            from .audit_extract import extract_permissions_from_events
            window = {"from": since or "", "to": until or ""}
            extracted = extract_permissions_from_events(
                merged,
                bouncer=bouncers[0].name,
                time_window=window,
                notes=tuple(
                    f"{r.bouncer} skipped ({r.error})"
                    for r in results if r.error
                ),
            )
            click.echo(json.dumps(extracted.as_dict(), indent=2))
            return

        if fmt == "ocsf-bundle":
            click.echo(_format_ocsf_bundle(merged), nl=False)
            return
        if fmt == "csv":
            click.echo(_format_csv(merged), nl=False)
            return
        # jsonl (default).
        click.echo(_format_jsonl(merged), nl=False)

    return audit_group


# Silence "imported but unused" warnings when `sys` is only used at
# module-import diagnostic time (debug helper retained for symmetry
# with the cross-product CLI siblings that emit to stderr).
_ = sys
