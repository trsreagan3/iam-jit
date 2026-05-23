"""#271 — GET /audit/events HTTP endpoint.

The "headless" sibling of ``ibounce audit tail --filter ... --export
jsonl`` (#268): same filter language (parse_filter_expr / event_matches),
same supported field catalog, same OCSF v1.1.0 wire shape. The cross-
bouncer ``iam-jit audit query`` CLI calls this endpoint on each
reachable bouncer in parallel and merges the results.

Wire shape::

    GET /audit/events?since=ISO8601&until=ISO8601
                     &filter=field=value&filter=...
                     &limit=N&format=jsonl|ocsf-bundle

Defaults: ``limit=100`` (max 1000), ``format=jsonl`` (one OCSF event
per line; the same shape ``AuditLogWriter`` emits).

Auth model:

  * **Loopback bind (default)**: NO ``Authorization`` header required.
    The proxy refuses to bind off-loopback without
    ``--i-know-this-binds-externally``.
  * **External bind**: requires ``Authorization: Bearer <TOKEN>``
    where the token matches ``ProxyConfig.audit_events_token``.
    Missing header → 401; wrong token → 403. The CLI refuses to start
    in external-bind mode without ``--audit-events-token``.

Per ``[[cross-product-agent-parity]]`` the same endpoint shape ships
on every bouncer in the suite (kbounce / dbounce / gbounce). Per
``[[creates-never-mutates]]`` this is read-only — it only reads the
JSONL audit log AND/OR the SQLite decision store. Per
``[[self-host-zero-billing-dependency]]`` no phone-home; the endpoint
only ever talks to the operator-controlled management port.

§A31 / #360 source resolution
-----------------------------
The handler reads from TWO possible sources:

  * **JSONL audit log** (preferred): when ``audit_log_path`` resolves
    to an existing file the handler reads events from it directly.
    This carries the richest OCSF shape — agent identity, src/dst
    endpoints, every ``unmapped.iam_jit.ext`` field the proxy attached
    at write time.
  * **SQLite decision store** (fallback): when the JSONL file is
    absent or empty AND a ``store`` was registered, the handler
    reconstructs minimal OCSF v1.1.0 class 6003 events from the
    persisted ``decisions`` rows. This matches kbounce/dbounce/gbounce
    which serve from SQLite directly per the same
    ``[[cross-product-agent-parity]]`` pattern.

Honest gap: SQLite-reconstructed events carry fewer fields than the
JSONL ones (no agent identity, no src/dst endpoint, no host —
``decisions`` only persists service/action/arn/region/verdict/reason/
timestamp). Operators who need the richer shape configure
``--audit-log-path``; everyone else still gets working cross-bouncer
fan-out (the §A31 launch-blocker) instead of an empty result.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import pathlib
import time
from typing import Any

from .event import audit_event_from_decision
from .tail import (
    DEFAULT_CSV_COLUMNS,
    FilterParseError,
    build_ocsf_bundle,
    default_audit_log_path,
    event_matches,
    get_path,
    iter_audit_file,
    parse_filter_expr,
)

logger = logging.getLogger(__name__)


AUDIT_EVENTS_DEFAULT_LIMIT = 100
"""Response cap when ?limit= is unset."""

AUDIT_EVENTS_MAX_LIMIT = 1000
"""Hard ceiling on ?limit= so a runaway query can't return an
unbounded payload."""

AUDIT_EVENTS_FORMAT_JSONL = "jsonl"
"""Default response format: one JSON-encoded OCSF event per line."""

AUDIT_EVENTS_FORMAT_OCSF_BUNDLE = "ocsf-bundle"
"""Single OCSF v1.1.0 class 2004 Detection Finding wrapping the
matched events. Useful when the caller wants ONE SIEM-ingestible
artifact instead of a stream."""

AUDIT_EVENTS_FORMAT_CSV = "csv"
"""CSV export (#425 / §A64). Header row is the dotted column names
from :data:`tail.DEFAULT_CSV_COLUMNS`; one event per row. The PII guard
default applies (no email/phone/credential/token/secret fields without
explicit opt-in via the future ``?csv_columns=`` query parameter)."""


def make_audit_events_handler(
    *,
    audit_log_path: pathlib.Path | None,
    require_bearer: str | None,
    store: Any | None = None,
):
    """Build the aiohttp handler for GET /audit/events.

    ``audit_log_path`` is the JSONL file the handler reads. ``None``
    falls back to :func:`default_audit_log_path` so the standalone-
    handler path still works when the operator hasn't passed
    ``--audit-log-path`` (the file just hasn't been created yet; we
    return an empty result set).

    ``store`` is the :class:`BouncerStore` to fall back to when the
    JSONL file is absent or empty. ``None`` (the legacy default)
    preserves the pre-§A31 behaviour — empty list when no JSONL.
    Passing a store gives the handler a SECOND source so cross-bouncer
    fan-out works even when the operator never configured
    ``--audit-log-path`` (the §A31 / #360 launch-blocker fix).

    Precedence when both sources have data: JSONL wins. Operators who
    deliberately enable JSONL are signalling "this is my durable
    source"; the SQLite store is only consulted when the JSONL path
    has nothing to offer (file missing OR file exists but yielded no
    matching events). This keeps backward-compat for every existing
    operator who already runs with ``--audit-log-path``.

    ``require_bearer`` is the bearer token to require. ``None`` (the
    loopback default) skips the auth gate entirely; non-empty triggers
    the auth flow.
    """
    try:
        from aiohttp import web
    except ImportError as e:  # pragma: no cover — covered by serve()
        raise RuntimeError(
            "aiohttp is required for the /audit/events endpoint",
        ) from e

    async def handler(request):
        if request.method != "GET":
            return web.json_response(
                {"error": "only GET is supported"},
                status=405,
            )

        if require_bearer:
            ah = request.headers.get("Authorization", "")
            if not ah:
                return web.json_response(
                    {"error": "Authorization: Bearer <token> required"},
                    status=401,
                )
            tok = _parse_bearer(ah)
            if tok is None or tok != require_bearer:
                return web.json_response(
                    {"error": "bearer token rejected"},
                    status=403,
                )

        try:
            opts = _parse_query(request.query)
        except _BadRequest as e:
            return web.json_response({"error": str(e)}, status=400)

        # Resolve the audit-log file. None or non-existent means "no
        # JSONL events" — we then try the SQLite store (§A31 / #360)
        # if one was registered. If neither has data, we return an
        # empty result (not an error).
        path = audit_log_path or default_audit_log_path()
        events: list[dict[str, Any]] = []
        if path and pathlib.Path(path).exists():
            try:
                for ev in iter_audit_file(pathlib.Path(path)):
                    if not _within_time_bounds(ev, opts["since"], opts["until"]):
                        continue
                    if opts["filters"] and not event_matches(
                        ev, opts["filters"],
                    ):
                        continue
                    events.append(ev)
            except Exception as exc:
                logger.warning(
                    "/audit/events: read failed for %s: %s", path, exc,
                )
                return web.json_response(
                    {"error": f"audit-log read failed: {exc}"},
                    status=500,
                )

        # §A31 / #360 fallback: when JSONL yielded nothing and we have
        # a store, reconstruct OCSF events from the persisted decision
        # rows. The richer-shape JSONL stream takes precedence when
        # configured (back-compat); the store is a safety net for
        # operators who never set --audit-log-path so cross-bouncer
        # fan-out still finds ibounce decisions instead of silently
        # excluding the bouncer.
        if not events and store is not None:
            try:
                # Pull a wide window (the response-side limit + filters
                # trim later). Cap at AUDIT_EVENTS_MAX_LIMIT so an
                # attacker can't ask for unbounded reads via filter
                # funnels — matches the gbounce fetch_limit pattern.
                rows = store.list_decisions(limit=AUDIT_EVENTS_MAX_LIMIT)
            except Exception as exc:
                logger.warning(
                    "/audit/events: store read failed: %s", exc,
                )
                return web.json_response(
                    {"error": f"store read failed: {exc}"},
                    status=500,
                )
            # list_decisions returns newest-first; rebuild as oldest-
            # first so the tail-slice below preserves the existing
            # "most recent N" semantics the JSONL path uses.
            for row in reversed(rows):
                ev = _decision_row_to_ocsf_event(row)
                if not _within_time_bounds(
                    ev, opts["since"], opts["until"],
                ):
                    continue
                if opts["filters"] and not event_matches(
                    ev, opts["filters"],
                ):
                    continue
                events.append(ev)

        # Tail-slice to the response cap. iter_audit_file yields
        # oldest-first; the spec asks for the most recent matching
        # events, so we slice from the end.
        if len(events) > opts["limit"]:
            events = events[-opts["limit"]:]

        if opts["format"] == AUDIT_EVENTS_FORMAT_OCSF_BUNDLE:
            bundle = build_ocsf_bundle(events)
            return web.json_response(bundle, status=200)

        if opts["format"] == AUDIT_EVENTS_FORMAT_CSV:
            # #425 / §A64: CSV export for SIEM handoff. Uses the same
            # default column set as `ibounce audit tail --export csv`
            # (PII guard applies; no email/phone/credential/token in
            # the default schema). Caller filters via ?filter= first;
            # the CSV body is the post-filter slice.
            csv_body = _format_csv(events)
            headers = {
                "Content-Disposition": (
                    "attachment; filename=\"audit-events.csv\""
                ),
            }
            return web.Response(
                body=csv_body,
                status=200,
                content_type="text/csv",
                charset="utf-8",
                headers=headers,
            )

        # JSONL (default) — emit one JSON object per line. Use a raw
        # response body so the Content-Type matches the cross-product
        # convention used by kbounce / dbounce / gbounce.
        body = "".join(
            json.dumps(ev, separators=(",", ":"), default=str) + "\n"
            for ev in events
        )
        return web.Response(
            body=body,
            status=200,
            content_type="application/x-ndjson",
        )

    return handler


def _format_csv(events: list[dict[str, Any]]) -> str:
    """Render ``events`` as a CSV string with :data:`DEFAULT_CSV_COLUMNS`.

    Materialises in-memory because the response handler needs the full
    body length up-front (aiohttp can stream but the
    ``Content-Disposition`` shape works better when the client gets a
    fully-formed download). The cap from
    :data:`AUDIT_EVENTS_MAX_LIMIT` is applied at the upstream slice so
    the CSV never grows unbounded.

    Per :data:`tail.DEFAULT_CSV_COLUMNS` the PII-guarded column set
    excludes email/phone/credential/token/secret-shaped fields — the
    operator who needs them passes the explicit set to the CLI
    (``ibounce audit tail --csv-columns``); the HTTP endpoint sticks
    to the safe default.
    """
    import csv as _csv
    import io as _io
    cols = list(DEFAULT_CSV_COLUMNS)
    sio = _io.StringIO()
    writer = _csv.writer(sio)
    writer.writerow(cols)
    for ev in events:
        row: list[str] = []
        for col in cols:
            val = get_path(ev, col)
            if val is None:
                row.append("")
            elif isinstance(val, (dict, list)):
                row.append(json.dumps(val, ensure_ascii=False))
            else:
                row.append(str(val))
        writer.writerow(row)
    return sio.getvalue()


def register_audit_events_route(
    app,
    *,
    audit_log_path: pathlib.Path | None,
    require_bearer: str | None,
    store: Any | None = None,
) -> None:
    """Register the /audit/events route on an aiohttp app.

    Registers BEFORE the catch-all handler so the exact-path route
    wins aiohttp's registration-order dispatch (matches /healthz
    handling).

    ``store`` is the optional :class:`BouncerStore` to read from when
    the JSONL log is unset (§A31 / #360 — keeps cross-bouncer fan-out
    working for operators who never set ``--audit-log-path``).
    """
    handler = make_audit_events_handler(
        audit_log_path=audit_log_path,
        require_bearer=require_bearer,
        store=store,
    )
    app.router.add_route("GET", "/audit/events", handler)


def _decision_row_to_ocsf_event(row: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct an OCSF v1.1.0 class 6003 event from a persisted
    decision row.

    §A31 / #360. The :class:`BouncerStore` persists a SUBSET of OCSF
    fields (verdict, mode, service, action, arn, region, reason,
    matched_rule_id, task_id, timestamp). We rebuild the event via
    :func:`audit_event_from_decision` so the wire shape matches what
    :class:`AuditLogWriter` would have emitted — same OCSF metadata,
    same status mapping, same ``unmapped.iam_jit`` block. Fields that
    weren't persisted (agent identity, src/dst endpoint, host) are
    omitted; downstream consumers that depend on those should configure
    ``--audit-log-path`` so the JSONL writer carries the richer shape.

    Per ``[[ibounce-honest-positioning]]`` this is the honest
    reconstruction — we never invent agent metadata; what's missing is
    documented in the endpoint module docstring.
    """
    # Build the base event via the shared constructor so the OCSF
    # shape stays in lockstep with the JSONL writer. `host` is unknown
    # at reconstruction time (not persisted) — pass empty string; the
    # builder skips dst_endpoint.hostname when host is falsy.
    extra: dict[str, Any] = {}
    if row.get("matched_rule_id") is not None:
        extra["matched_rule_id"] = row["matched_rule_id"]
    if row.get("task_id"):
        extra["active_task_id"] = row["task_id"]
    ev = audit_event_from_decision(
        decision_id=int(row.get("id") or 0),
        mode=row.get("mode") or "",
        profile=None,  # not persisted on the decision row
        verdict=row.get("decision") or "",
        reason=row.get("reason") or "",
        service=row.get("service") or "",
        action=row.get("action") or "",
        arn=row.get("arn"),
        region=row.get("region"),
        host="",  # not persisted; dst_endpoint stays empty
        enforced=(row.get("mode") == "enforce"),
        extra=extra or None,
    )
    # Overwrite `time` with the persisted timestamp (the builder
    # stamps NOW; we want when the decision was actually recorded).
    ts = row.get("at")
    if isinstance(ts, str) and ts:
        try:
            t = _parse_iso(ts)
            ev["time"] = int(t.timestamp() * 1000)
        except ValueError:
            # Tolerate odd persisted formats — keep the builder's
            # NOW timestamp rather than dropping the event.
            pass
    return ev


class _BadRequest(Exception):
    """Surfaced to the handler as a 400 with the message body."""


def _parse_query(query) -> dict[str, Any]:
    """Validate + parse the URL query into a typed option dict."""
    opts: dict[str, Any] = {
        "limit": AUDIT_EVENTS_DEFAULT_LIMIT,
        "format": AUDIT_EVENTS_FORMAT_JSONL,
        "since": None,
        "until": None,
        "filters": [],
    }
    if (v := query.get("limit")) is not None:
        try:
            n = int(v)
        except ValueError as exc:
            raise _BadRequest(
                f"limit={v!r}: must be a positive integer",
            ) from exc
        if n < 1:
            raise _BadRequest(f"limit={v!r}: must be a positive integer")
        if n > AUDIT_EVENTS_MAX_LIMIT:
            raise _BadRequest(
                f"limit={n} exceeds max {AUDIT_EVENTS_MAX_LIMIT}",
            )
        opts["limit"] = n
    if (v := query.get("format")) is not None:
        if v not in (
            AUDIT_EVENTS_FORMAT_JSONL,
            AUDIT_EVENTS_FORMAT_OCSF_BUNDLE,
            AUDIT_EVENTS_FORMAT_CSV,
        ):
            raise _BadRequest(
                f"format={v!r}: want one of: "
                f"{AUDIT_EVENTS_FORMAT_JSONL}, "
                f"{AUDIT_EVENTS_FORMAT_OCSF_BUNDLE}, "
                f"{AUDIT_EVENTS_FORMAT_CSV}",
            )
        opts["format"] = v
    for key in ("since", "until"):
        if (v := query.get(key)) is not None:
            try:
                opts[key] = _parse_iso(v)
            except ValueError as exc:
                raise _BadRequest(
                    f"{key}={v!r}: want RFC3339 / ISO 8601",
                ) from exc
    if opts["since"] and opts["until"] and opts["since"] > opts["until"]:
        raise _BadRequest("since must be <= until")
    for raw in query.getall("filter", []):
        try:
            opts["filters"].append(parse_filter_expr(raw))
        except FilterParseError as exc:
            raise _BadRequest(str(exc)) from exc
    return opts


def _parse_iso(s: str) -> _dt.datetime:
    """Parse an ISO 8601 / RFC 3339 timestamp + return aware UTC.

    Python's :func:`fromisoformat` accepts the ``Z`` suffix from 3.11
    onward; we normalise it to ``+00:00`` first for cross-version
    safety.
    """
    norm = s.strip()
    if norm.endswith("Z"):
        norm = norm[:-1] + "+00:00"
    t = _dt.datetime.fromisoformat(norm)
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.UTC)
    return t.astimezone(_dt.UTC)


def _within_time_bounds(
    event: dict[str, Any],
    since: _dt.datetime | None,
    until: _dt.datetime | None,
) -> bool:
    if since is None and until is None:
        return True
    t = event.get("time")
    if t is None:
        return False
    # OCSF "time" is Unix milliseconds per the schema. Some legacy
    # callers (and the SECURITY_ALERT path) may serialize as ISO 8601
    # string; accept both for forward-compat.
    if isinstance(t, str):
        try:
            event_time = _parse_iso(t)
        except ValueError:
            return False
    else:
        try:
            event_time = _dt.datetime.fromtimestamp(
                float(t) / 1000.0, tz=_dt.UTC,
            )
        except (TypeError, ValueError, OSError):
            return False
    if since is not None and event_time < since:
        return False
    if until is not None and event_time > until:
        return False
    return True


def _parse_bearer(header: str) -> str | None:
    """Pull the bearer token out of an Authorization header."""
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2:
        return None
    scheme, value = parts
    if scheme.lower() != "bearer":
        return None
    return value.strip()


# Silence "imported but unused" warnings — `time` is used implicitly
# by callers re-exporting from this module.
_ = time
