"""#620 — iam-jit serve `GET /audit/events` endpoint.

The cross-bouncer ``iam-jit audit query`` CLI (#271) fans out to every
reachable bouncer's ``/audit/events`` endpoint and merges the results.
Before #620 iam-jit serve itself had no parity endpoint: its own audit
log (request lifecycle, admin actions, cap-fire events from #613,
context-change events) was unreachable from the cross-product query
CLI.

The shipped #613 recipe (``docs/recipes/OUTSTANDING-REQUEST-CAP.md``)
told operators to run ``iam-jit audit query --kind request_cap_exceeded
--since 1h`` after the cap fired — and got back 0 events.  That was a
doc-lie: the cap-fire helper DID persist to the iam-jit audit log via
``audit.emit()``, but ``audit query`` only knew how to fan-out to the
four bouncers.  Operators following the recipe lost trust in the audit
story.

This module closes that gap.  It exposes the same wire shape as the
bouncer endpoint (per ``[[cross-product-agent-parity]]``) so the
existing ``cli_audit_query`` fan-out can include iam-jit serve as one
more surface without per-surface special-casing.

Wire shape (matches bouncer ``/audit/events``)::

    GET /audit/events?since=ISO8601&until=ISO8601
                     &filter=field=value&filter=...
                     &limit=N

Response: ``application/x-ndjson`` — one OCSF v1.1.0 event per line.

Read source: ``IAM_JIT_AUDIT_LOG`` (the same file ``audit.emit()``
writes to). When the env var is unset OR the file is missing/empty,
we return an empty NDJSON body (200 OK) — not an error.  The cap
event hasn't fired yet (or the operator hasn't enabled audit
persistence); an empty result is the honest answer.

Auth model: iam-jit serve already requires an authenticated session
on every JSON API.  We re-use that gate via ``require_admin`` —
audit-log contents may include actor IDs / IPs / request IDs, so
non-admin access would leak data.  Bouncers gate the same endpoint
on a bearer token; the moral equivalent here is "must be signed-in
admin".

Per ``[[creates-never-mutates]]`` read-only.
Per ``[[ibounce-honest-positioning]]`` an absent log returns 200 with
zero events (NOT 404) so the cross-bouncer fan-out treats the surface
as reachable-but-empty rather than silently excluding it.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import re as _re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from ..middleware import require_admin
from ..users_store import User

logger = logging.getLogger(__name__)


router = APIRouter()


AUDIT_EVENTS_DEFAULT_LIMIT = 100
"""Response cap when ?limit= is unset.  Mirrors the bouncer endpoint."""

AUDIT_EVENTS_MAX_LIMIT = 1000
"""Hard ceiling on ?limit= — mirrors bouncer endpoint so a runaway
fan-out can't ask one surface for an unbounded payload."""


# OCSF class for an API Activity event.  Matches the bouncers'
# /audit/events emit so the cross-product merge treats iam-jit serve
# events the same as bouncer events for class-based grouping.
_OCSF_CLASS_UID = 6003
_OCSF_CLASS_NAME = "API Activity"
_OCSF_CATEGORY_UID = 6
_OCSF_CATEGORY_NAME = "Application Activity"


def _audit_event_to_ocsf(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert an iam-jit ``AuditEvent`` (hash-chained JSON line) into
    the OCSF v1.1.0 wire shape ``cli_audit_query`` already knows how to
    merge + filter.

    The iam-jit audit log carries: ``timestamp`` (Unix seconds, float),
    ``actor`` (user id / "system" / "boot"), ``kind`` (event-type
    string), ``summary`` (one-line human), ``seq`` (monotonic),
    ``details`` (free dict), ``prev_hash`` / ``hash`` (chain).

    The bouncer endpoint emits OCSF events with ``time`` in Unix ms +
    ``metadata.product.name`` + ``unmapped.iam_jit.*`` for non-OCSF
    fields.  We mirror that shape so the cross-product fan-out can
    sort + filter without per-surface special-casing.

    Per ``[[cross-product-agent-parity]]`` the shape MUST match what
    bouncers emit — the merge layer reads ``time`` (ms), groups by
    ``_bouncer`` (stamped at query time, not here), and the
    ``--kind`` short-form expands to
    ``unmapped.iam_jit.kind=<value>``.
    """
    timestamp = raw.get("timestamp")
    try:
        time_ms = int(float(timestamp) * 1000) if timestamp is not None else 0
    except (TypeError, ValueError):
        time_ms = 0
    actor = raw.get("actor") or ""
    kind = raw.get("kind") or ""
    summary = raw.get("summary") or ""
    details = raw.get("details") or {}
    return {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "iam-jit-serve",
                "vendor_name": "iam-jit",
            },
        },
        "time": time_ms,
        "class_uid": _OCSF_CLASS_UID,
        "class_name": _OCSF_CLASS_NAME,
        "category_uid": _OCSF_CATEGORY_UID,
        "category_name": _OCSF_CATEGORY_NAME,
        # activity_id=1 = "Create"; the iam-jit log is an append-only
        # record-creation log so every entry is a create.
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": _OCSF_CLASS_UID * 100 + 1,
        "type_name": f"{_OCSF_CLASS_NAME}: Create",
        # severity_id=1 ("Informational") for normal lifecycle events.
        # We don't currently surface severity gradations through the
        # audit chain; operators filter by `kind` for the security-
        # sensitive ones (request_cap_exceeded, llm.changed,
        # context.changed, etc.).
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "actor": {"user": {"name": str(actor)}},
        "message": str(summary),
        # `unmapped.iam_jit` is the canonical home for non-OCSF fields
        # per the bouncer pattern.  Putting `kind` here is what makes
        # the --kind shortcut (cli_audit_query) work uniformly across
        # iam-jit serve + bouncers.
        "unmapped": {
            "iam_jit": {
                "kind": str(kind),
                "summary": str(summary),
                "seq": raw.get("seq"),
                "details": details,
                "prev_hash": raw.get("prev_hash"),
                "hash": raw.get("hash"),
                # Marker so a SIEM-side consumer can tell iam-jit serve
                # events from bouncer events without looking at
                # metadata.product.  Useful for cross-bouncer
                # correlation that wants to JOIN serve.actor with
                # bouncer.actor on the same id.
                "source": "iam-jit-serve",
            },
        },
    }


def _parse_iso(s: str) -> _dt.datetime:
    """Parse an ISO 8601 / RFC 3339 timestamp + return aware UTC.

    Tolerates the ``Z`` suffix on every Python version (the stdlib's
    ``fromisoformat`` accepts it from 3.11; we normalise first for
    cross-version safety).
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
    """Mirrors ``bouncer/audit_export/events_endpoint._within_time_bounds``.

    The shape we feed in already has ``time`` in Unix ms because
    ``_audit_event_to_ocsf`` projected it that way.
    """
    if since is None and until is None:
        return True
    t = event.get("time")
    if t is None:
        return False
    try:
        event_time = _dt.datetime.fromtimestamp(float(t) / 1000.0, tz=_dt.UTC)
    except (TypeError, ValueError, OSError):
        return False
    if since is not None and event_time < since:
        return False
    if until is not None and event_time > until:
        return False
    return True


# Filter parser — bouncer-grammar parity.  We accept the same four
# operators (``=``, ``~``, ``>=``, ``<=``) so a single ``--filter`` from
# ``iam-jit audit query`` works against every surface.  We DON'T import
# the bouncer's parser here because the bouncer module pulls in aiohttp
# at import time; that's an extra dependency we don't want on the
# serve-side route.  The grammar is small enough to re-implement.
_FILTER_OPS = (">=", "<=", "=", "~")


def _parse_filter(expr: str) -> tuple[str, str, str]:
    """Parse ``field<op>value`` into ``(field, op, value)``.

    Raises HTTPException(400) on malformed input — the operator sees
    the bad expression in the error so they don't have to scroll up.
    """
    if not expr or not isinstance(expr, str):
        raise HTTPException(status_code=400, detail="filter cannot be empty")
    for op in _FILTER_OPS:
        idx = expr.find(op)
        if idx > 0:
            field = expr[:idx].strip()
            value = expr[idx + len(op):].strip()
            if not field or not value:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"filter {expr!r}: missing field or value "
                        f"around {op!r}"
                    ),
                )
            return field, op, value
    raise HTTPException(
        status_code=400,
        detail=(
            f"filter {expr!r}: expected one of '=', '~', '>=', '<=' "
            "(e.g. 'unmapped.iam_jit.kind=request_cap_exceeded')"
        ),
    )


def _walk_dotted_path(ev: dict[str, Any], path: str) -> Any:
    """Walk a dotted path through nested dicts; return None on miss."""
    cur: Any = ev
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _filter_matches(ev: dict[str, Any], parsed: tuple[str, str, str]) -> bool:
    """Apply one parsed ``(field, op, value)`` to one OCSF event."""
    field, op, value = parsed
    actual = _walk_dotted_path(ev, field)
    if actual is None:
        # Missing field — never matches.  Bouncers behave the same way;
        # operators who want "field is missing" check via a separate
        # path.
        return False
    if op == "=":
        return str(actual) == value
    if op == "~":
        try:
            return _re.search(value, str(actual)) is not None
        except _re.error:
            return False
    # Numeric comparisons.  Tolerate the field being str-encoded
    # numeric (some unmapped.iam_jit.details fields are JSON-stringy).
    try:
        actual_num = float(actual)
        target_num = float(value)
    except (TypeError, ValueError):
        return False
    if op == ">=":
        return actual_num >= target_num
    if op == "<=":
        return actual_num <= target_num
    return False  # unreachable; parser would have rejected the op


def _iter_audit_log_lines(path: str):
    """Yield one parsed JSON dict per non-empty line of the audit log.

    Malformed lines are logged at WARN and skipped (rather than
    crashing the endpoint).  Mirrors ``routes/reports.py:audit_log_report``
    forgiveness so the two surfaces agree on what's readable.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "audit/events: skipping malformed line in %s: %s",
                        path, exc,
                    )
                    continue
    except OSError as exc:
        # Treat as "file not present" — the empty-list path will return
        # 200 + zero events.  The cap-fire recipe shouldn't error out
        # just because the operator hasn't configured the log yet.
        logger.warning("audit/events: cannot read %s: %s", path, exc)
        return


@router.get("/audit/events")
def get_audit_events(
    _: Annotated[User, Depends(require_admin)],
    since: Annotated[str | None, Query()] = None,
    until: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = AUDIT_EVENTS_DEFAULT_LIMIT,
    filter: Annotated[list[str] | None, Query()] = None,  # noqa: A002
) -> Response:
    """Query iam-jit serve's audit log.

    Wire-compatible with the bouncer ``/audit/events`` endpoint so the
    cross-bouncer ``iam-jit audit query`` CLI can fan-out to serve as
    one more surface without per-surface logic.

    Returns ``application/x-ndjson`` — one OCSF v1.1.0 event per line,
    sorted oldest-first (matches the bouncer wire shape).
    """
    if limit < 1:
        raise HTTPException(
            status_code=400, detail="limit must be a positive integer",
        )
    if limit > AUDIT_EVENTS_MAX_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=(
                f"limit={limit} exceeds max {AUDIT_EVENTS_MAX_LIMIT}"
            ),
        )

    since_dt: _dt.datetime | None = None
    until_dt: _dt.datetime | None = None
    if since:
        try:
            since_dt = _parse_iso(since)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"since={since!r}: want RFC3339 / ISO 8601",
            ) from exc
    if until:
        try:
            until_dt = _parse_iso(until)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"until={until!r}: want RFC3339 / ISO 8601",
            ) from exc
    if since_dt and until_dt and since_dt > until_dt:
        raise HTTPException(
            status_code=400, detail="since must be <= until",
        )

    parsed_filters: list[tuple[str, str, str]] = []
    for raw in (filter or []):
        parsed_filters.append(_parse_filter(raw))

    path = os.environ.get("IAM_JIT_AUDIT_LOG")
    events: list[dict[str, Any]] = []
    if path and os.path.exists(path):
        for raw in _iter_audit_log_lines(path):
            ev = _audit_event_to_ocsf(raw)
            if not _within_time_bounds(ev, since_dt, until_dt):
                continue
            ok = True
            for f in parsed_filters:
                if not _filter_matches(ev, f):
                    ok = False
                    break
            if not ok:
                continue
            events.append(ev)

    # Tail-slice — match the bouncer behaviour (return the most recent
    # N matching events, oldest-first).
    if len(events) > limit:
        events = events[-limit:]

    body = "".join(
        json.dumps(ev, separators=(",", ":"), default=str) + "\n"
        for ev in events
    )
    return Response(
        content=body,
        media_type="application/x-ndjson",
    )
