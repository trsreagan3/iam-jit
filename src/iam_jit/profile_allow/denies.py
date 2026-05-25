# #345 / §A25 — Deny-visibility: query each bouncer's /audit/events for
# recent DENY verdicts and synthesise a ``suggested_allow_command``.
"""Backend for ``iam-jit denies recent`` CLI + ``bounce_denies_recent``
MCP tool.

Per ``[[cross-product-agent-parity]]`` reuses
:mod:`iam_jit.cli_audit_query` helpers so the fan-out shape stays
identical to ``iam-jit audit query``. This module ONLY adds:

  * a verdict=deny default filter
  * a ``suggested_allow_command`` synthesis on each row
  * a ``deny_source`` classification (static profile / dynamic deny /
    safe-default / profile_only_account_ids / profile_only_regions)

Per ``[[ibounce-honest-positioning]]`` the deny_source field reflects
what the bouncer actually told us in the OCSF event; we don't guess.
Unknown / structurally-novel deny shapes surface as ``"unknown"`` with
the raw reason in ``deny_reason`` rather than a wrong classification.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import re
import typing


@dataclasses.dataclass(frozen=True)
class DenyRow:
    """One deny row the CLI / MCP layer renders."""

    when: str  # ISO 8601 UTC
    bouncer: str
    agent_session_id: str
    action: str  # service:Action
    resource: str  # ARN or hostname
    deny_reason: str  # human-readable, from the bouncer
    deny_source: str  # one of the _DENY_SOURCE_* values
    rule_id_if_dynamic: str | None
    suggested_allow_command: str

    def as_dict(self) -> dict[str, typing.Any]:
        return dataclasses.asdict(self)


_DENY_SOURCE_STATIC_PROFILE = "static_profile"
_DENY_SOURCE_DYNAMIC_DENY = "dynamic_deny"
_DENY_SOURCE_SAFE_DEFAULT = "safe_default"
_DENY_SOURCE_PROFILE_ONLY_ACCOUNT_IDS = "profile_only_account_ids"
_DENY_SOURCE_PROFILE_ONLY_REGIONS = "profile_only_regions"
_DENY_SOURCE_PROFILE_ALLOW_BASELINE = "profile_allow_baseline"
_DENY_SOURCE_TASK_DENY = "task_deny"
_DENY_SOURCE_GLOBAL_DENY = "global_deny"
_DENY_SOURCE_UNKNOWN = "unknown"

_DYNAMIC_RULE_ID_RE = re.compile(r"dd_[0-9A-HJKMNP-TV-Z]{26}")


def classify_deny_source(reason: str) -> tuple[str, str | None]:
    """Best-effort classify a deny_reason string into a deny_source +
    optional rule_id. Returns ``(source, rule_id_or_none)``.

    Recognises the substrings ibounce's profile / dynamic-deny / rule
    layers emit:

      * ``"matched dynamic deny"`` / ``dd_<ULID>`` -> dynamic_deny
      * ``"allow_baseline"`` -> profile_allow_baseline
      * ``"profile_only_account_ids"`` -> profile_only_account_ids
      * ``"profile_only_regions"`` -> profile_only_regions
      * ``"profile 'safe-default'"`` -> safe_default
      * ``"profile '<other>'"`` -> static_profile
      * ``"task deny"`` -> task_deny
      * ``"global deny"`` / ``"rule "`` -> global_deny
      * everything else -> unknown
    """
    if not isinstance(reason, str):
        return _DENY_SOURCE_UNKNOWN, None
    r = reason.lower()
    # Dynamic-deny first — the rule id is the strongest signal.
    m = _DYNAMIC_RULE_ID_RE.search(reason)
    if m:
        return _DENY_SOURCE_DYNAMIC_DENY, m.group(0)
    if "dynamic deny" in r or "dynamic-deny" in r:
        return _DENY_SOURCE_DYNAMIC_DENY, None
    if "profile_only_account_ids" in r:
        return _DENY_SOURCE_PROFILE_ONLY_ACCOUNT_IDS, None
    if "profile_only_regions" in r:
        return _DENY_SOURCE_PROFILE_ONLY_REGIONS, None
    # safe-default check BEFORE the generic allow_baseline check —
    # the canonical safe-default profile is the most-actionable label
    # for operators even when the reason also mentions allow_baseline.
    if "'safe-default'" in r or "safe-default" in r:
        return _DENY_SOURCE_SAFE_DEFAULT, None
    if "allow_baseline" in r:
        return _DENY_SOURCE_PROFILE_ALLOW_BASELINE, None
    if r.startswith("profile ") or "profile '" in r:
        return _DENY_SOURCE_STATIC_PROFILE, None
    if "task deny" in r or "task-deny" in r:
        return _DENY_SOURCE_TASK_DENY, None
    if r.startswith("rule ") or "global deny" in r:
        return _DENY_SOURCE_GLOBAL_DENY, None
    return _DENY_SOURCE_UNKNOWN, None


def synth_suggested_allow_command(
    *,
    resource: str,
    action: str,
    deny_source: str,
    bouncer: str,
) -> str:
    """Build the one-line ``iam-jit profile allow ...`` command an
    operator can copy-paste to unblock a future request matching the
    deny.

    Per the design memo: refuse to synthesise a command for
    dynamic-deny / org-distributed denies (those need to be lifted
    through a different surface). The output explains the alternative
    path instead of suggesting an inappropriate allow."""
    if deny_source == _DENY_SOURCE_DYNAMIC_DENY:
        return (
            "# this deny is from a dynamic-deny rule; lift via "
            "`iam-jit deny remove <id>` (use `iam-jit deny list` to "
            "find the id)"
        )
    if deny_source in (
        _DENY_SOURCE_PROFILE_ONLY_ACCOUNT_IDS,
        _DENY_SOURCE_PROFILE_ONLY_REGIONS,
    ):
        return (
            "# this deny is from a profile account/region floor; edit "
            "the profile's only_account_ids / only_regions field "
            "directly to add coverage"
        )
    if bouncer != "ibounce":
        return (
            f"# {bouncer} denies are not yet routable through "
            f"`iam-jit profile allow` (Phase 2); edit the bouncer's "
            f"config directly"
        )
    res = resource or "*"
    act = action or "*"
    if not res or res == "*" or not act or ":" not in act:
        return (
            "# the deny lacks a specific resource/action; review "
            "the profile manually before allowing"
        )
    return (
        f"iam-jit profile allow --target '{res}' --action '{act}' "
        f"--reason \"<why this is safe>\""
    )


def event_to_deny_row(
    ev: dict[str, typing.Any],
    *,
    bouncer_hint: str | None = None,
) -> DenyRow | None:
    """Project one OCSF audit event into a :class:`DenyRow`. Returns
    ``None`` when the event is NOT a deny (so a caller can use this
    as a filter pass)."""
    iam_jit = _walk(ev, "unmapped.iam_jit") or {}
    verdict = (iam_jit.get("verdict") or "").lower()
    if verdict not in ("deny", "denied", "denying"):
        return None
    when = _format_event_time(ev)
    bouncer = (
        ev.get("_bouncer")
        or _walk(ev, "metadata.product.name")
        or bouncer_hint
        or "unknown"
    )
    agent_block = iam_jit.get("agent") or {}
    agent_session_id = str(
        agent_block.get("session_id")
        or agent_block.get("session")
        or ""
    )
    api = ev.get("api") or {}
    action = str(api.get("operation") or "")
    resources = ev.get("resources") or []
    resource = ""
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            resource = str(first.get("uid") or first.get("name") or "")
    if not resource:
        # Fall back to dst_endpoint hostname (gbounce / dbounce shape).
        dst = ev.get("dst_endpoint") or {}
        if isinstance(dst, dict):
            resource = str(dst.get("hostname") or dst.get("ip") or "")
    # deny reason: prefer status_detail (the OCSF builder prepends the
    # human reason there); fall back to the iam_jit.ext reason.
    deny_reason = str(
        ev.get("status_detail")
        or (iam_jit.get("ext") or {}).get("reason")
        or ""
    )
    deny_source, rule_id = classify_deny_source(deny_reason)
    suggested = synth_suggested_allow_command(
        resource=resource,
        action=action,
        deny_source=deny_source,
        bouncer=str(bouncer),
    )
    return DenyRow(
        when=when,
        bouncer=str(bouncer),
        agent_session_id=agent_session_id,
        action=action,
        resource=resource,
        deny_reason=deny_reason,
        deny_source=deny_source,
        rule_id_if_dynamic=rule_id,
        suggested_allow_command=suggested,
    )


def _walk(ev: dict[str, typing.Any], path: str) -> typing.Any:
    cur: typing.Any = ev
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _format_event_time(ev: dict[str, typing.Any]) -> str:
    t = ev.get("time")
    if isinstance(t, (int, float)):
        try:
            dt = _dt.datetime.fromtimestamp(t / 1000.0, tz=_dt.timezone.utc)
            return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except (ValueError, OSError):
            return ""
    if isinstance(t, str):
        return t
    return ""


def parse_since(spec: str | None) -> str | None:
    """Convert a ``--since`` short form (``5m`` / ``1h`` / ``2d``) into
    an ISO 8601 lower bound usable by the audit-query fan-out. Pass-
    through for an explicit ISO string.

    Lenient by design: unknown shapes pass through so the bouncer's own
    parser can surface the canonical error. See :func:`validate_since`
    for the strict CLI-time gate (#606 Gap A) which rejects invalid
    shapes BEFORE the fan-out — silent pass-through to a degraded HTTP
    400 was the silent-degradation bug per
    ``[[ibounce-honest-positioning]]``.
    """
    if not spec:
        return None
    s = spec.strip()
    if not s:
        return None
    # ISO-ish heuristic.
    if "T" in s or "-" in s[:10]:
        return s
    if not s[:-1].isdigit() or s[-1] not in ("s", "m", "h", "d", "w"):
        return s  # let the bouncer's parser report bad input
    qty = int(s[:-1])
    unit = s[-1]
    delta = _dt.timedelta(
        **{
            "s": {"seconds": qty},
            "m": {"minutes": qty},
            "h": {"hours": qty},
            "d": {"days": qty},
            "w": {"weeks": qty},
        }[unit]
    )
    lower = _dt.datetime.now(_dt.timezone.utc) - delta
    return lower.replace(microsecond=0).isoformat().replace("+00:00", "Z")


# Short-form duration tokens accepted by --since on the CLI gate.
# Same s/m/h/d/w set :func:`parse_since` honors — keep these in lockstep
# so the validator's accept-set matches the resolver's accept-set.
_SHORT_FORM_DURATION_UNITS = ("s", "m", "h", "d", "w")


def validate_since(spec: str | None) -> str | None:
    """Strict CLI-time validation gate for ``--since`` (#606 Gap A).

    Raises :class:`ValueError` with an operator-actionable message when
    ``spec`` is non-empty AND doesn't look like one of:

      * short-form duration token: ``5m`` / ``1h`` / ``2d`` (s/m/h/d/w)
      * ISO 8601 / RFC 3339 timestamp: ``2026-05-25T10:00:00Z``

    Per ``[[ibounce-honest-positioning]]`` this is the up-front gate
    that turns the pre-#606 silent-degradation shape (invalid value
    passed through to the bouncer -> HTTP 400 -> hidden in notes[]
    while the CLI cheerfully claimed "caught nothing") into an honest
    exit-with-error at the CLI layer.

    Returns ``spec`` unchanged on success (caller can use the return
    value to thread through to :func:`parse_since`). Returns ``None``
    when ``spec`` is None or empty (the default-behavior path).
    """
    if not spec:
        return None
    s = spec.strip()
    if not s:
        return None
    # ISO 8601 / RFC 3339 shape: contains a 'T' OR starts with a date
    # (YYYY-MM-DD prefix). Use the same heuristic parse_since uses then
    # actually verify it parses as a real timestamp — pass-through here
    # was the Gap A bug (parse_since lets junk like ``2026-bad`` pass
    # under the heuristic and the bouncer's HTTP 400 was swallowed).
    if "T" in s or "-" in s[:10]:
        norm = s
        if norm.endswith("Z"):
            norm = norm[:-1] + "+00:00"
        try:
            _dt.datetime.fromisoformat(norm)
        except ValueError as exc:
            raise ValueError(
                f"want RFC 3339 / ISO 8601 timestamp "
                f"(e.g. 2026-05-25T10:00:00Z); got {spec!r}: {exc}"
            ) from exc
        return s
    # Short-form duration: must be <digits><unit> with unit in s/m/h/d/w.
    if len(s) < 2 or not s[:-1].isdigit() or s[-1] not in _SHORT_FORM_DURATION_UNITS:
        raise ValueError(
            f"want a duration like '5m' / '1h' / '2d' (units: "
            f"{'/'.join(_SHORT_FORM_DURATION_UNITS)}) OR an ISO 8601 "
            f"timestamp (e.g. 2026-05-25T10:00:00Z); got {spec!r}"
        )
    return s


@dataclasses.dataclass(frozen=True)
class BouncerQueryError:
    """One bouncer's failure shape from the deny fan-out (#606 Gap A).

    Distinct from the existing ``notes`` list (free-form strings) so the
    CLI / MCP layer can:

      * count how many bouncers were attempted vs how many failed
      * exit non-zero when ALL failed (or partial-warn when SOME failed)
      * surface a machine-readable error array in the ``--json`` shape

    Per ``[[ibounce-honest-positioning]]`` this is the wire-shape that
    turns "denies recent claimed zero" into "denies recent claimed
    zero because N of M bouncers were unreachable, here's why" — the
    operator can tell the difference between "no denies happened" and
    "we couldn't tell".
    """

    bouncer: str
    """The bouncer's short name (ibounce / kbounce / dbounce / gbounce)."""

    error: str
    """The error string from :class:`_BouncerQueryResult` (HTTP 400,
    unreachable: <reason>, NDJSON parse: <reason>, etc.). The leading
    classifier (``HTTP 400``, ``unreachable``) tells the operator
    whether to fix the input or fix the bouncer."""


def _fan_out_query(
    *,
    since: str | None,
    agent_session_id: str | None,
    limit: int,
    bouncer_names: typing.Sequence[str] | None,
    audit_events_token: str | None,
    timeout: float,
) -> tuple[list[DenyRow], list[str], list[BouncerQueryError], int]:
    """Shared fan-out helper used by both :func:`fetch_recent_denies`
    and :func:`fetch_recent_denies_with_errors` (#606 Gap B).

    Returns ``(rows, notes, errors, attempted_count)``:

      * ``rows`` — list of :class:`DenyRow` projected from successful
        bouncer responses (newest-first; sliced to ``limit``).
      * ``notes`` — list of free-form ``"<bouncer> skipped (<reason>)"``
        strings, preserved for backward-compat with the existing
        text-render path.
      * ``errors`` — structured per-bouncer error list (#606 Gap A);
        empty when every bouncer responded.
      * ``attempted_count`` — number of bouncers we attempted to query.
        The CLI uses this to distinguish "all failed" (exit 1) from
        "partial failure" (exit 2) from "all ok" (exit 0).

    Single fan-out implementation per ``[[cross-product-agent-parity]]``
    so the CLI text-mode + CLI JSON-mode + MCP tool can't drift on
    which bouncers were queried, how filters were built, or how
    failures surface. Mirrors the leaf-helper pattern from #601.
    """
    from ..cli_audit_query import (
        _query_one_bouncer,
        _resolve_bouncer_set,
    )

    raw = tuple(bouncer_names) if bouncer_names else ()
    bouncers = _resolve_bouncer_set(raw if raw else None)
    filters: list[str] = ["unmapped.iam_jit.verdict=deny"]
    if agent_session_id:
        filters.append(
            f"unmapped.iam_jit.agent.session_id={agent_session_id}"
        )
    resolved_since = parse_since(since)
    notes: list[str] = []
    errors: list[BouncerQueryError] = []
    rows: list[DenyRow] = []
    for endpoint in bouncers:
        r = _query_one_bouncer(
            endpoint,
            since=resolved_since,
            until=None,
            filters=tuple(filters),
            limit=limit,
            bearer_token=audit_events_token,
            timeout=timeout,
        )
        if r.error:
            notes.append(f"{r.bouncer} skipped ({r.error})")
            errors.append(
                BouncerQueryError(bouncer=r.bouncer, error=r.error)
            )
            continue
        for ev in r.events:
            row = event_to_deny_row(ev, bouncer_hint=endpoint.name)
            if row is not None:
                rows.append(row)
    # Most recent first.
    rows.sort(key=lambda x: x.when, reverse=True)
    return rows[:limit], notes, errors, len(bouncers)


def fetch_recent_denies(
    *,
    since: str | None = "5m",
    agent_session_id: str | None = None,
    limit: int = 50,
    bouncer_names: typing.Sequence[str] | None = None,
    audit_events_token: str | None = None,
    timeout: float = 5.0,
) -> tuple[list[DenyRow], list[str]]:
    """Fan out to every default bouncer, query /audit/events with a
    verdict=deny filter, project hits to :class:`DenyRow`. Returns
    ``(rows, notes)``. Notes lists per-bouncer skips for stderr.

    Backward-compat wrapper around :func:`_fan_out_query` (#606). The
    structured per-bouncer error shape lives on
    :func:`fetch_recent_denies_with_errors`; this function keeps the
    pre-#606 signature for the digest / autopilot / structured_deny
    callers that don't need the structured shape.
    """
    rows, notes, _errors, _attempted = _fan_out_query(
        since=since,
        agent_session_id=agent_session_id,
        limit=limit,
        bouncer_names=bouncer_names,
        audit_events_token=audit_events_token,
        timeout=timeout,
    )
    return rows, notes


def fetch_recent_denies_with_errors(
    *,
    since: str | None = "5m",
    agent_session_id: str | None = None,
    limit: int = 50,
    bouncer_names: typing.Sequence[str] | None = None,
    audit_events_token: str | None = None,
    timeout: float = 5.0,
) -> tuple[list[DenyRow], list[str], list[BouncerQueryError], int]:
    """Per-bouncer structured-error variant of :func:`fetch_recent_denies`
    (#606 Gap A).

    Returns ``(rows, notes, errors, attempted)`` where ``errors`` is a
    list of :class:`BouncerQueryError` (one per failed bouncer) and
    ``attempted`` is the total number of bouncers we tried.

    Callers use these to:

      * distinguish "0 denies; all queries succeeded" (honest empty
        window) from "0 denies; all queries failed" (no data, full
        degradation -> exit 1) from "0 denies; some queried OK"
        (partial degradation -> exit 2)
      * surface a machine-readable ``query_errors`` array in the
        ``--json`` shape so downstream agents can react to failure
        modes instead of seeing an empty ``rows: []``

    The new shape never silently drops error context — the existing
    free-form ``notes`` are kept too for the human-text path and for
    backward compat with the existing render code.
    """
    return _fan_out_query(
        since=since,
        agent_session_id=agent_session_id,
        limit=limit,
        bouncer_names=bouncer_names,
        audit_events_token=audit_events_token,
        timeout=timeout,
    )


__all__ = [
    "BouncerQueryError",
    "DenyRow",
    "classify_deny_source",
    "event_to_deny_row",
    "fetch_recent_denies",
    "fetch_recent_denies_with_errors",
    "parse_since",
    "synth_suggested_allow_command",
    "validate_since",
]
