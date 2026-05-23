# #419 / §A58 — permission extraction from bouncer audit events.
"""Project a window of OCSF audit events into a structured permission
set the agent can hand to ``iam_jit_request_role_from_synthesis``.

The aggregation is intentionally simple: group ``api.operation``
(service:Action) by action, collect distinct resources, count
occurrences. The observed_scope (account_ids + regions) is derived
from event metadata.

Cross-bouncer fan-out reuses :mod:`iam_jit.cli_audit_query` helpers so
the wire shape is the same one ``iam-jit audit query`` already speaks
(per [[cross-product-agent-parity]]). A bouncer that's unreachable
contributes a per-bouncer note rather than failing the whole call.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import re
import typing


@dataclasses.dataclass(frozen=True)
class PermissionAggregate:
    """One row of the aggregated permission set.

    ``action`` is the canonical ``service:Action`` form. ``resources``
    is the distinct set of resource ARNs / identifiers observed for
    this action in the window. ``count`` is the number of underlying
    events.
    """

    action: str
    resources: tuple[str, ...]
    count: int

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "action": self.action,
            "resources": list(self.resources),
            "count": self.count,
        }


@dataclasses.dataclass(frozen=True)
class ExtractedPermissions:
    """The full extraction result. Agent feeds this (minus
    ``events_analyzed`` + ``notes``) into role-from-synthesis."""

    time_window: dict[str, str]
    bouncer: str
    events_analyzed: int
    permissions: tuple[PermissionAggregate, ...]
    observed_scope: dict[str, list[str]]
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "time_window": dict(self.time_window),
            "bouncer": self.bouncer,
            "events_analyzed": self.events_analyzed,
            "permissions": [p.as_dict() for p in self.permissions],
            "observed_scope": {
                k: list(v) for k, v in self.observed_scope.items()
            },
            "notes": list(self.notes),
        }


# Best-effort ARN parser. ARNs look like
# ``arn:aws:<service>:<region>:<account>:<resource>``. We DON'T validate
# strictly — some bouncer-emitted "resources" are pseudo-ARNs (e.g. an
# S3 object path) and we still want to extract account_id / region
# when present without rejecting the rest.
_ARN_RE = re.compile(
    r"^arn:(?:aws|aws-cn|aws-us-gov):[^:]*:([^:]*):([^:]*):"
)


def _account_region_from_arn(arn: str) -> tuple[str | None, str | None]:
    """Return (region, account_id) extracted from an ARN, or (None, None)
    if the string isn't ARN-shaped. Empty positional fields (e.g.
    ``arn:aws:s3:::bucket``) map to ``None`` (global resources)."""
    if not isinstance(arn, str):
        return None, None
    m = _ARN_RE.match(arn)
    if not m:
        return None, None
    region = m.group(1) or None
    account = m.group(2) or None
    return region, account


def _walk(ev: dict[str, typing.Any], path: str) -> typing.Any:
    cur: typing.Any = ev
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _event_action(ev: dict[str, typing.Any]) -> str | None:
    """Extract the ``service:Action`` form from an OCSF event.

    Bouncers populate ``api.operation`` with the canonical
    ``service:Action`` form (e.g. ``s3:GetObject``). Fallback: build
    from ``api.service.name`` + ``api.operation`` when operation is the
    bare action only.
    """
    op = _walk(ev, "api.operation")
    if isinstance(op, str) and ":" in op:
        return op
    service = _walk(ev, "api.service.name")
    if isinstance(op, str) and isinstance(service, str) and op:
        return f"{service}:{op}"
    return None


def _event_resources(ev: dict[str, typing.Any]) -> list[str]:
    """Extract resource identifiers from an OCSF event.

    Prefers the ``resources[*].uid`` ARN form, falls back to
    ``resources[*].name``, then to ``dst_endpoint.hostname`` (the
    non-AWS bouncers' resource representation).
    """
    out: list[str] = []
    resources = ev.get("resources")
    if isinstance(resources, list):
        for r in resources:
            if not isinstance(r, dict):
                continue
            cand = r.get("uid") or r.get("name")
            if isinstance(cand, str) and cand:
                out.append(cand)
    if out:
        return out
    dst = ev.get("dst_endpoint")
    if isinstance(dst, dict):
        host = dst.get("hostname") or dst.get("ip")
        if isinstance(host, str) and host:
            out.append(host)
    return out


def _event_account_region(
    ev: dict[str, typing.Any],
    resources: list[str],
) -> tuple[str | None, str | None]:
    """Extract (account_id, region) for ``observed_scope`` derivation.

    Prefers explicit OCSF cloud block (``cloud.account.uid`` /
    ``cloud.region``); falls back to parsing the first resource ARN.
    Reading the explicit block first is important — the cloud-region
    can differ from the resource-region for cross-region S3 reads
    etc., and the cloud block is the canonical source.
    """
    acct = _walk(ev, "cloud.account.uid")
    region = _walk(ev, "cloud.region")
    if isinstance(acct, str) and isinstance(region, str) and acct and region:
        return acct, region
    if isinstance(acct, str) and acct:
        return acct, (region if isinstance(region, str) and region else None)
    # Fallback to ARN parse.
    for r in resources:
        arn_region, arn_acct = _account_region_from_arn(r)
        if arn_acct or arn_region:
            return arn_acct, arn_region
    return (None if not isinstance(acct, str) else acct,
            None if not isinstance(region, str) else region)


def extract_permissions_from_events(
    events: typing.Sequence[dict[str, typing.Any]],
    *,
    bouncer: str,
    time_window: dict[str, str] | None = None,
    notes: typing.Sequence[str] = (),
) -> ExtractedPermissions:
    """Aggregate a list of OCSF events into the permission set shape.

    Pure function — no I/O. Deterministic output ordering (actions
    alphabetical; resources within each action alphabetical; scope
    values sorted) so the result is diff-friendly and snapshot-testable.
    """
    by_action: dict[str, dict[str, int]] = {}  # action -> resource -> count
    counts_by_action: dict[str, int] = {}
    account_ids: set[str] = set()
    regions: set[str] = set()
    events_analyzed = 0

    for ev in events:
        action = _event_action(ev)
        if not action:
            continue
        events_analyzed += 1
        counts_by_action[action] = counts_by_action.get(action, 0) + 1
        resources = _event_resources(ev)
        by_resource = by_action.setdefault(action, {})
        # Always seed at least one resource entry per event so the count
        # reconciles with len(events_for_action). When the event has no
        # named resource we synthesise "*" rather than dropping the
        # contribution.
        if not resources:
            by_resource["*"] = by_resource.get("*", 0) + 1
        for r in resources:
            by_resource[r] = by_resource.get(r, 0) + 1
        acct, region = _event_account_region(ev, resources)
        if acct:
            account_ids.add(acct)
        if region:
            regions.add(region)

    permissions = tuple(
        PermissionAggregate(
            action=action,
            resources=tuple(sorted(by_action[action].keys())),
            count=counts_by_action[action],
        )
        for action in sorted(by_action.keys())
    )
    observed_scope = {
        "account_ids": sorted(account_ids),
        "regions": sorted(regions),
    }
    if time_window is None:
        time_window = {"from": "", "to": ""}
    return ExtractedPermissions(
        time_window=dict(time_window),
        bouncer=bouncer,
        events_analyzed=events_analyzed,
        permissions=permissions,
        observed_scope=observed_scope,
        notes=tuple(notes),
    )


def _parse_since(spec: str | None) -> str | None:
    """Convert a short-form ``--since`` (``5m`` / ``1h`` / ``2d``) into
    an ISO 8601 UTC lower bound. Pass-through for ISO strings.

    Duplicates the same parser used in :mod:`iam_jit.profile_allow.denies`
    so this module has no cross-feature import; the parser is small and
    the duplication isolates the audit-extract module from churn in
    the denies module.
    """
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


def extract_permissions_via_fanout(
    *,
    since: str | None = "1h",
    until: str | None = None,
    bouncer: str = "ibounce",
    limit: int = 1000,
    audit_events_token: str | None = None,
    timeout: float = 5.0,
) -> ExtractedPermissions:
    """Fan out to ONE bouncer's ``/audit/events`` endpoint, fetch the
    window, and aggregate.

    The single-bouncer default reflects the Phase E use case: the
    agent wants the permission set from "my staging bouncer" — a
    specific bouncer scope. The cross-bouncer probe lives one layer
    up (``iam-jit audit query``) and is not what this surface is for.

    Per [[ibounce-honest-positioning]] an unreachable bouncer surfaces
    as a per-bouncer ``note`` rather than crashing — the agent then
    sees ``events_analyzed: 0`` + a note explaining why and can re-ask.
    """
    from ..cli_audit_query import (
        DEFAULT_BOUNCERS,
        _query_one_bouncer,
        _parse_bouncer_override,
    )

    # Allow either a known bouncer name or a name=URL override.
    if "=" in bouncer:
        endpoint = _parse_bouncer_override(bouncer)
    else:
        endpoint = DEFAULT_BOUNCERS.get(bouncer)
        if endpoint is None:
            return ExtractedPermissions(
                time_window={"from": since or "", "to": until or ""},
                bouncer=bouncer,
                events_analyzed=0,
                permissions=(),
                observed_scope={"account_ids": [], "regions": []},
                notes=(
                    f"unknown bouncer {bouncer!r}; pass one of "
                    f"{sorted(DEFAULT_BOUNCERS)} or name=URL explicitly",
                ),
            )

    resolved_since = _parse_since(since)
    resolved_until = _parse_since(until) if until else None
    result = _query_one_bouncer(
        endpoint,
        since=resolved_since,
        until=resolved_until,
        filters=(),
        limit=limit,
        bearer_token=audit_events_token,
        timeout=timeout,
    )
    notes: tuple[str, ...] = ()
    if result.error:
        notes = (f"{result.bouncer} skipped ({result.error})",)
    time_window = {
        "from": resolved_since or "",
        "to": resolved_until or "",
    }
    return extract_permissions_from_events(
        result.events,
        bouncer=endpoint.name,
        time_window=time_window,
        notes=notes,
    )


__all__ = [
    "ExtractedPermissions",
    "PermissionAggregate",
    "extract_permissions_from_events",
    "extract_permissions_via_fanout",
]
