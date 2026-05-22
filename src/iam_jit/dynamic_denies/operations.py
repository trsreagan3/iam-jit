# #324e — High-level add/list/remove/show operations.
"""Shared operations layer for ``iam-jit deny`` CLI + MCP tools.

The CLI (``cli_deny.py``) and the MCP server (``mcp_server.py``) both
need the SAME workflow: read the YAML, mutate, write, fan-out to
bouncers, return a structured outcome. Putting that workflow here
keeps the two surfaces in lockstep per
``[[cross-product-agent-parity]]``.

Each operation returns a structured result dict the caller can render
as JSON (CLI ``--json`` / MCP structured content) or as a
human-readable banner (CLI default / MCP ``content[].text``).
"""

from __future__ import annotations

import datetime as _dt
import re
import typing

from .fanout import ReloadResult, fanout_reload
from .resolver import ResolutionResult, resolve_targets
from .store import (
    DynamicDenyWriteError,
    StoreFile,
    build_rule_dict,
    read_store,
    write_store,
)


class DenyOperationError(RuntimeError):
    """A structured error from an operations call. Carries a
    ``code`` so the CLI can map it to an exit status + the MCP tool
    can pick the right structured payload."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        details: dict[str, typing.Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


# ---------------------------------------------------------------------------
# Add
# ---------------------------------------------------------------------------


def add_rule(
    *,
    targets: typing.Sequence[str],
    reason: str,
    duration: str,
    applies_to_recommender: bool = True,
    bouncer_overrides: typing.Sequence[str] | None = None,
    bouncer_url_overrides: typing.Mapping[str, str] | None = None,
    source: str = "cli",
    path: str | None = None,
    skip_fanout: bool = False,
) -> dict[str, typing.Any]:
    """Resolve targets, append a rule, persist, fan out reloads.

    Returns a structured result the caller renders.

    Raises :class:`DenyOperationError` for operator-fixable problems
    (unclassifiable target without override; permission-loose YAML);
    propagates :class:`DynamicDenyWriteError` for fatal write
    failures.
    """
    targets_clean = [t for t in (s.strip() for s in targets) if t]
    if not targets_clean:
        raise DenyOperationError(
            "at least one --target is required",
            code="missing_targets",
        )
    if not reason or not reason.strip():
        raise DenyOperationError(
            "--reason is required (surfaces in the bouncer's 403 + audit)",
            code="missing_reason",
        )
    if not duration or not duration.strip():
        raise DenyOperationError(
            "--duration is required (e.g. `30m`, `3h`, `7d`, or `permanent`)",
            code="missing_duration",
        )

    resolution: ResolutionResult = resolve_targets(
        targets_clean,
        bouncer_overrides=bouncer_overrides,
    )
    if not resolution.applied_to:
        raise DenyOperationError(
            "no target could be classified to a bouncer; pass --bouncer NAME "
            "to route explicitly",
            code="no_routing",
            details={
                "targets": targets_clean,
                "per_target_rationale": [
                    {
                        "target": c.target,
                        "applied_to": list(c.applied_to),
                        "rationale": c.rationale,
                    }
                    for c in resolution.classifications
                ],
            },
        )
    if resolution.unclassifiable_targets:
        raise DenyOperationError(
            "one or more targets could not be classified; pass --bouncer "
            "NAME to override or fix the target pattern",
            code="unclassifiable_targets",
            details={
                "unclassifiable_targets": list(
                    resolution.unclassifiable_targets,
                ),
                "per_target_rationale": [
                    {
                        "target": c.target,
                        "applied_to": list(c.applied_to),
                        "rationale": c.rationale,
                    }
                    for c in resolution.classifications
                ],
            },
        )

    try:
        rule = build_rule_dict(
            targets=targets_clean,
            reason=reason,
            duration=duration,
            applied_to=resolution.applied_to,
            applies_to_recommender=applies_to_recommender,
            source=source,
        )
    except (DynamicDenyWriteError, ValueError) as e:
        raise DenyOperationError(
            str(e), code="rule_construction",
        ) from e

    store = read_store(path)
    store.rules.append(rule)
    written_path = write_store(store, path=path)

    fanout_results: list[ReloadResult] = []
    if not skip_fanout:
        fanout_results = fanout_reload(
            resolution.applied_to,
            overrides=bouncer_url_overrides,
        )

    return {
        "id": rule["id"],
        "rule": rule,
        "applied_to": list(resolution.applied_to),
        "routing_explanation": _routing_explanation(resolution),
        "per_target_rationale": [
            {
                "target": c.target,
                "applied_to": list(c.applied_to),
                "rationale": c.rationale,
            }
            for c in resolution.classifications
        ],
        "fanout": [_serialise_reload(r) for r in fanout_results],
        "written_to": written_path,
    }


def _routing_explanation(resolution: ResolutionResult) -> str:
    """One-line summary of the resolver's routing decision."""
    if not resolution.classifications:
        return "no targets resolved"
    lines: list[str] = []
    for c in resolution.classifications:
        applied = ", ".join(c.applied_to) if c.applied_to else "(unclassified)"
        lines.append(f"{c.target} -> {applied} [{c.rationale}]")
    return "; ".join(lines)


def _serialise_reload(r: ReloadResult) -> dict[str, typing.Any]:
    return {
        "bouncer": r.bouncer,
        "url": r.url,
        "reloaded": r.reloaded,
        "status_code": r.status_code,
        "rules_count": r.rules_count,
        "rules_applied_to_self": r.rules_applied_to_self,
        "error": r.error,
    }


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


def list_rules(
    *,
    path: str | None = None,
    include_expired: bool = False,
    bouncer_filter: typing.Sequence[str] | None = None,
) -> dict[str, typing.Any]:
    """Read the YAML, return all active rules + a filterable summary.
    """
    store = read_store(path)
    now = _dt.datetime.now(_dt.timezone.utc)

    filter_set = {b.strip() for b in (bouncer_filter or []) if b and b.strip()}

    rules: list[dict[str, typing.Any]] = []
    for r in store.rules:
        expires_at = _parse_iso(r.get("expires_at"))
        is_expired = expires_at is not None and expires_at < now
        if is_expired and not include_expired:
            continue
        if filter_set:
            applied = {
                str(a) for a in (r.get("applied_to") or []) if isinstance(a, str)
            }
            if not applied & filter_set:
                continue
        annotated = dict(r)
        annotated["_expired"] = is_expired
        annotated["_age_seconds"] = _age_seconds(r.get("added_at"), now=now)
        annotated["_expires_in_seconds"] = (
            int((expires_at - now).total_seconds())
            if expires_at is not None
            else None
        )
        rules.append(annotated)

    return {
        "path": store.source_path,
        "count": len(rules),
        "rules": rules,
    }


def _parse_iso(value: typing.Any) -> _dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


def _age_seconds(
    added_at: typing.Any,
    *,
    now: _dt.datetime,
) -> int | None:
    dt = _parse_iso(added_at)
    if dt is None:
        return None
    return int((now - dt).total_seconds())


# ---------------------------------------------------------------------------
# Show
# ---------------------------------------------------------------------------


def show_rule(
    rule_id: str,
    *,
    path: str | None = None,
) -> dict[str, typing.Any]:
    """Return a single rule's full dict.

    Raises :class:`DenyOperationError` with code ``not_found`` when
    the id is absent.
    """
    store = read_store(path)
    idx = store.rule_index(rule_id)
    if idx is None:
        raise DenyOperationError(
            f"no rule with id {rule_id!r} (use `iam-jit deny list` to "
            f"enumerate active ids)",
            code="not_found",
        )
    rule = store.rules[idx]
    now = _dt.datetime.now(_dt.timezone.utc)
    expires_at = _parse_iso(rule.get("expires_at"))
    return {
        "rule": rule,
        "path": store.source_path,
        "is_expired": (
            expires_at is not None and expires_at < now
        ),
        "expires_in_seconds": (
            int((expires_at - now).total_seconds())
            if expires_at is not None
            else None
        ),
        "age_seconds": _age_seconds(rule.get("added_at"), now=now),
    }


# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------


def remove_rules(
    rule_ids: typing.Sequence[str] | None = None,
    *,
    path: str | None = None,
    reason_match: str | None = None,
    drop_expired: bool = False,
    actor_reason: str | None = None,
    bouncer_url_overrides: typing.Mapping[str, str] | None = None,
    skip_fanout: bool = False,
) -> dict[str, typing.Any]:
    """Remove one or more rules from the YAML + fan out reloads to
    every previously-affected bouncer.

    Supports three selection modes:

      * ``rule_ids`` — explicit list of ids.
      * ``reason_match`` — regex against ``reason`` (bulk by intent).
      * ``drop_expired`` — drop every rule whose ``expires_at`` is in
        the past (audit-cleanup).
    """
    store = read_store(path)

    if not (rule_ids or reason_match or drop_expired):
        raise DenyOperationError(
            "remove requires at least one of: rule ids, --reason-match, "
            "or --expired",
            code="no_selector",
        )

    to_remove_ids: set[str] = set()
    if rule_ids:
        to_remove_ids.update(r for r in rule_ids if r)
    if reason_match:
        try:
            pat = re.compile(reason_match)
        except re.error as e:
            raise DenyOperationError(
                f"--reason-match {reason_match!r} is not a valid regex: {e}",
                code="bad_regex",
            ) from e
        for r in store.rules:
            reason = r.get("reason")
            if isinstance(reason, str) and pat.search(reason):
                rid = r.get("id")
                if isinstance(rid, str):
                    to_remove_ids.add(rid)
    if drop_expired:
        now = _dt.datetime.now(_dt.timezone.utc)
        for r in store.rules:
            expires_at = _parse_iso(r.get("expires_at"))
            if expires_at is not None and expires_at < now:
                rid = r.get("id")
                if isinstance(rid, str):
                    to_remove_ids.add(rid)

    affected_bouncers: set[str] = set()
    removed_rules: list[dict[str, typing.Any]] = []
    not_found: list[str] = []
    refused_org_distributed: list[str] = []

    for rid in list(to_remove_ids):
        idx = store.rule_index(rid)
        if idx is None:
            not_found.append(rid)
            continue
        rule = store.rules[idx]
        # Org-distributed rules cannot be loosened by personal denies
        # (design doc `Conflict resolution` rule 2). The personal CLI
        # is the only caller hitting this path right now; future
        # break-glass paths can extend the gate.
        if rule.get("source") == "org-distributed":
            refused_org_distributed.append(rid)
            continue
        store.rules.pop(idx)
        removed_rules.append(rule)
        for b in (rule.get("applied_to") or []):
            if isinstance(b, str) and b.strip():
                affected_bouncers.add(b.strip())

    written_path: str | None = None
    if removed_rules:
        written_path = write_store(store, path=path)

    fanout_results: list[ReloadResult] = []
    if removed_rules and not skip_fanout:
        fanout_results = fanout_reload(
            sorted(affected_bouncers),
            overrides=bouncer_url_overrides,
        )

    return {
        "removed_count": len(removed_rules),
        "removed_ids": [r["id"] for r in removed_rules],
        "removed_rules": removed_rules,
        "not_found": not_found,
        "refused_org_distributed": refused_org_distributed,
        "fanout": [_serialise_reload(r) for r in fanout_results],
        "written_to": written_path,
        "actor_reason": actor_reason,
    }


__all__ = [
    "DenyOperationError",
    "add_rule",
    "list_rules",
    "remove_rules",
    "show_rule",
]
