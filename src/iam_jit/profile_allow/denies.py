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
    through for an explicit ISO string."""
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
    ``(rows, notes)``. Notes lists per-bouncer skips for stderr."""
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
            continue
        for ev in r.events:
            row = event_to_deny_row(ev, bouncer_hint=endpoint.name)
            if row is not None:
                rows.append(row)
    # Most recent first.
    rows.sort(key=lambda x: x.when, reverse=True)
    return rows[:limit], notes


__all__ = [
    "DenyRow",
    "classify_deny_source",
    "event_to_deny_row",
    "fetch_recent_denies",
    "parse_since",
    "synth_suggested_allow_command",
]
