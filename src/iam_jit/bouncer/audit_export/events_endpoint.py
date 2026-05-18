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
JSONL audit log. Per ``[[self-host-zero-billing-dependency]]`` no
phone-home; the endpoint only ever talks to the operator-controlled
management port.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import pathlib
import time
from typing import Any

from .tail import (
    FilterParseError,
    build_ocsf_bundle,
    default_audit_log_path,
    event_matches,
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


def make_audit_events_handler(
    *,
    audit_log_path: pathlib.Path | None,
    require_bearer: str | None,
):
    """Build the aiohttp handler for GET /audit/events.

    ``audit_log_path`` is the JSONL file the handler reads. ``None``
    falls back to :func:`default_audit_log_path` so the standalone-
    handler path still works when the operator hasn't passed
    ``--audit-log-path`` (the file just hasn't been created yet; we
    return an empty result set).

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
        # events yet" (return an empty result; not an error).
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

        # Tail-slice to the response cap. iter_audit_file yields
        # oldest-first; the spec asks for the most recent matching
        # events, so we slice from the end.
        if len(events) > opts["limit"]:
            events = events[-opts["limit"]:]

        if opts["format"] == AUDIT_EVENTS_FORMAT_OCSF_BUNDLE:
            bundle = build_ocsf_bundle(events)
            return web.json_response(bundle, status=200)

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


def register_audit_events_route(
    app,
    *,
    audit_log_path: pathlib.Path | None,
    require_bearer: str | None,
) -> None:
    """Register the /audit/events route on an aiohttp app.

    Registers BEFORE the catch-all handler so the exact-path route
    wins aiohttp's registration-order dispatch (matches /healthz
    handling).
    """
    handler = make_audit_events_handler(
        audit_log_path=audit_log_path,
        require_bearer=require_bearer,
    )
    app.router.add_route("GET", "/audit/events", handler)


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
            AUDIT_EVENTS_FORMAT_JSONL, AUDIT_EVENTS_FORMAT_OCSF_BUNDLE,
        ):
            raise _BadRequest(
                f"format={v!r}: want one of: "
                f"{AUDIT_EVENTS_FORMAT_JSONL}, {AUDIT_EVENTS_FORMAT_OCSF_BUNDLE}",
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
