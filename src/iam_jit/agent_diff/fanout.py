# #722 / BUILD-1 — fan-out helper for `iam-jit agent-diff`.
"""Small helper that runs a per-session ``/audit/events`` query against
one or more bouncers and returns the merged event list.

Compose path:

* :func:`fetch_session_events_via_fanout` calls
  :func:`iam_jit.cli_audit_query._query_one_bouncer` once per bouncer,
  filtering by ``unmapped.iam_jit.agent.session_id`` server-side so
  the bouncer never returns a non-matching event.
* Per-bouncer errors land in the ``notes`` list (the diff still
  proceeds with whatever did return).
* Output preserves the ``_bouncer`` stamp from the fan-out so the
  session summary can list which bouncers contributed.

Per [[ibounce-honest-positioning]] an unreachable bouncer surfaces as
a note, NOT as a fatal — the caller sees ``events_analyzed: 0`` +
the operator-readable reason.
"""

from __future__ import annotations

import datetime as _dt
import typing


def _parse_since(spec: str | None) -> str | None:
    """Same lightweight parser used by audit_extract — short-form
    duration tokens (5m / 1h / 2d) or pass-through ISO 8601."""
    if not spec:
        return None
    s = spec.strip()
    if not s:
        return None
    if "T" in s or "-" in s[:10]:
        return s
    if not s[:-1].isdigit() or s[-1] not in ("s", "m", "h", "d", "w"):
        return s
    qty = int(s[:-1])
    unit = s[-1]
    delta = _dt.timedelta(**{
        "s": {"seconds": qty},
        "m": {"minutes": qty},
        "h": {"hours": qty},
        "d": {"days": qty},
        "w": {"weeks": qty},
    }[unit])
    lower = _dt.datetime.now(_dt.timezone.utc) - delta
    return lower.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_session_events_via_fanout(
    *,
    session_id: str,
    bouncers: typing.Sequence[str] = (),
    since: str | None = "1h",
    until: str | None = None,
    limit: int = 1000,
    audit_events_token: str | None = None,
    timeout: float = 5.0,
) -> tuple[list[dict[str, typing.Any]], dict[str, str]]:
    """Fan out to each named bouncer's ``/audit/events`` endpoint,
    filter server-side by session_id, return the merged event list +
    a per-bouncer notes dict.

    ``bouncers``: tuple of names or ``name=URL`` overrides. Empty =>
    fan-out to all four default bouncers per
    [[cross-product-agent-parity]].

    Returns ``(events, notes_by_bouncer)`` where ``notes_by_bouncer``
    is ``{bouncer_name: error_message_or_empty}``.
    """
    # Late import to avoid pulling the click / aiohttp tail of the
    # audit-query CLI into every agent-diff caller.
    from ..cli_audit_query import (
        DEFAULT_BOUNCERS,
        _parse_bouncer_override,
        _query_one_bouncer,
    )

    if not bouncers:
        endpoints = list(DEFAULT_BOUNCERS.values())
    else:
        endpoints = []
        for b in bouncers:
            if "=" in b:
                endpoints.append(_parse_bouncer_override(b))
            elif b in DEFAULT_BOUNCERS:
                endpoints.append(DEFAULT_BOUNCERS[b])
            else:
                # Unknown bouncer — surface as a per-source note via a
                # synthetic endpoint name; the caller sees the note.
                # We don't raise because the diff is still useful with
                # the other bouncers' events.
                endpoints.append(None)  # type: ignore[arg-type]
                # Stash the unknown name on a sentinel so the loop
                # below can emit a note.
                # Using None means we have to remember the name; just
                # use a marker tuple.
                # (Replace last entry with a marker.)
                endpoints[-1] = ("__unknown__", b)  # type: ignore[assignment]

    resolved_since = _parse_since(since)
    resolved_until = _parse_since(until) if until else None
    filter_expr = f"unmapped.iam_jit.agent.session_id={session_id}"

    merged: list[dict[str, typing.Any]] = []
    notes: dict[str, str] = {}
    for endpoint in endpoints:
        # Handle the unknown-bouncer marker tuple.
        if (
            isinstance(endpoint, tuple)
            and len(endpoint) == 2
            and endpoint[0] == "__unknown__"
        ):
            notes[endpoint[1]] = (
                f"unknown bouncer {endpoint[1]!r}; pass one of "
                f"{sorted(DEFAULT_BOUNCERS)} or name=URL explicitly"
            )
            continue
        result = _query_one_bouncer(
            endpoint,
            since=resolved_since,
            until=resolved_until,
            filters=(filter_expr,),
            limit=limit,
            bearer_token=audit_events_token,
            timeout=timeout,
        )
        notes[result.bouncer] = result.error or ""
        merged.extend(result.events)
    return merged, notes
