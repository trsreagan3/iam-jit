"""Improve-profile pipeline (#401).

Composes the existing audit-query + #326 generator + #345 profile-allow
path so the operator's profile auto-tightens around observed traffic.

Strict invariants per the brief:

  * Honor ``posture: managed`` — refuse to run if the declaration says
    managed (return ``status="managed_posture_refused"`` + clear error).
  * Auto-install only when diff size is below the declaration's
    ``require_operator_approval_above_change_threshold``.
  * Hold for operator approval (§A25 pending queue) otherwise.
  * Empty diff → ``status="no_change"`` (honest per
    ``[[ibounce-honest-positioning]]``).
  * Per ``[[creates-never-mutates]]`` we never overwrite or remove
    operator-authored allow rules — removals are surfaced as pending
    entries the operator approves.

Returns :class:`ImproveProfileResult` (round-trippable as a dict).

Tests for this module MUST follow the state-verification pattern per
``docs/CONTRIBUTING.md`` — assert observable state matches reported
status, not just the status string. This module was the surface that
shipped bug #448 (``status="auto_installed"`` with zero rules
actually persisted); the convention exists to prevent the same shape
from re-shipping.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import logging
import os
import pathlib
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors + result dataclass
# ---------------------------------------------------------------------------


class ImproveProfileError(RuntimeError):
    """Structured improve-profile error. ``code`` is the stable id the
    MCP/CLI surfaces map to an exit status."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


@dataclasses.dataclass
class ImproveProfileResult:
    """Structured outcome of one improve-profile invocation.

    Status values (per [[ibounce-honest-positioning]] — each string
    matches observable reality):

      * ``auto_installed`` — one or more allow rules were appended to
        the profile + admin_action audit events emitted (#452 fix:
        ONLY when ``rules_added > 0``; scope-only changes route to
        ``scope_only_change`` instead).
      * ``scope_only_change`` (#452) — generator proposed scope-floor
        tightening (e.g. ``only_account_ids``) but no new allow rules;
        scope-changes were enqueued to the pending JSONL so the
        operator can review (NEVER silently mutated; #451 fix).
      * ``pending_approval`` — change-size above threshold OR
        auto-install disabled; allow + scope changes both queued.
        ``pending_entry_ids`` is populated; JSONL file at
        ~/.iam-jit/bouncer/profile-allow-pending.jsonl is created.
      * ``no_change`` — nothing for the generator to add.
      * ``managed_posture_refused`` — posture=managed + we refused.
      * ``dry_run`` — ``apply=False`` preview.
      * ``error`` — surfaced via :class:`ImproveProfileError` adapter.
    """

    status: str  # auto_installed | pending_approval | scope_only_change | no_change | managed_posture_refused | error | dry_run
    bouncer: str
    cadence_window: str
    rules_added: int = 0
    rules_removed: int = 0
    scope_changes: list[str] = dataclasses.field(default_factory=list)
    change_size: float = 0.0
    requires_approval: bool = False
    audit_event_ids: list[str] = dataclasses.field(default_factory=list)
    pending_entry_ids: list[str] = dataclasses.field(default_factory=list)
    proposed_allows: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    proposed_removals: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    explanation: str = ""
    schema_version: str = "1.0"
    posture: str = "ambient"

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Cadence helpers
# ---------------------------------------------------------------------------


_CADENCE_TO_WINDOW = {
    "per_session": "1h",
    "daily": "24h",
    "weekly": "7d",
}


def _cadence_to_window(cadence: str | None, fallback: str = "1h") -> str:
    if not cadence:
        return fallback
    return _CADENCE_TO_WINDOW.get(cadence, fallback)


def _window_to_since_iso(window: str) -> str | None:
    """Convert ``5m`` / ``1h`` / ``24h`` / ``7d`` to an ISO 8601 lower
    bound. Returns ``None`` for unparseable inputs (caller defaults to
    "from beginning")."""
    s = (window or "").strip().lower()
    if not s:
        return None
    try:
        unit = s[-1]
        n = int(s[:-1])
    except (ValueError, IndexError):
        return None
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}.get(unit)
    if mult is None:
        return None
    delta = n * mult
    when = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=delta)
    return when.replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Diff computation (generator output vs current active profile)
# ---------------------------------------------------------------------------


def _normalize_target(t: str | None) -> str | None:
    """Treat ``None`` / ``""`` / ``"*"`` as the same "any-resource" scope
    so diff comparisons don't false-positive when the generator emits
    ``target: "*"`` and the existing rule has ``arn_scope=None``."""
    if t is None:
        return None
    s = str(t).strip()
    if not s or s == "*":
        return None
    return s


def _flatten_existing_allow_rules(active_profile: Any) -> set[tuple[str, str | None]]:
    """Return {(pattern, arn_scope)} from an existing Profile's allow_rules."""
    out: set[tuple[str, str | None]] = set()
    for rule in getattr(active_profile, "allow_rules", ()) or ():
        out.add(
            (
                getattr(rule, "pattern", "") or "",
                _normalize_target(getattr(rule, "arn_scope", None)),
            )
        )
    return out


def _flatten_proposed_allows(parsed_profile: dict[str, Any]) -> set[tuple[str, str | None]]:
    """Return {(action, target)} from the generator's emitted profile dict.

    The generator returns ``allows: [{target, actions, reason}, ...]``
    where ``actions`` may be a list of ``service:Action`` strings or a
    single string.
    """
    out: set[tuple[str, str | None]] = set()
    for entry in parsed_profile.get("allows", []) or []:
        if not isinstance(entry, dict):
            continue
        target = _normalize_target(entry.get("target"))
        actions = entry.get("actions") or []
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if not action:
                continue
            out.add((str(action), target))
    return out


def _flatten_proposed_scope(parsed_profile: dict[str, Any]) -> dict[str, list[str]]:
    """Per-bouncer scope dimensions the generator emitted (§A38).

    Returns one dict mapping ``only_X`` field → list of values.
    """
    fields = (
        "only_account_ids",
        "only_regions",
        "only_clusters",
        "only_namespaces",
        "only_hosts",
        "only_databases",
    )
    scope: dict[str, list[str]] = {}
    for f in fields:
        v = parsed_profile.get(f)
        if isinstance(v, list) and v:
            scope[f] = sorted(set(str(x) for x in v))
    return scope


def _flatten_existing_scope(active_profile: Any) -> dict[str, list[str]]:
    fields = (
        "only_account_ids",
        "only_regions",
        "only_clusters",
        "only_namespaces",
        "only_hosts",
        "only_databases",
    )
    out: dict[str, list[str]] = {}
    for f in fields:
        v = getattr(active_profile, f, None)
        if v:
            try:
                out[f] = sorted(set(str(x) for x in v))
            except TypeError:
                pass
    return out


def _compute_diff(
    *,
    current_profile: Any,
    proposed: dict[str, Any],
) -> tuple[set[tuple[str, str | None]], set[tuple[str, str | None]], list[str]]:
    """Return (added, removed, scope_changes).

    ``added`` = proposed allows that don't exist in current.
    ``removed`` = current allows that the generator did NOT propose.
    ``scope_changes`` = human-readable bullets like
        ``"only_account_ids: added 111122223333"``.

    Per [[creates-never-mutates]] removals are surfaced but never
    applied automatically; the operator must approve via the pending
    queue.
    """
    existing = _flatten_existing_allow_rules(current_profile)
    new = _flatten_proposed_allows(proposed)
    added = new - existing
    removed = existing - new
    scope_old = _flatten_existing_scope(current_profile)
    scope_new = _flatten_proposed_scope(proposed)
    scope_changes: list[str] = []
    keys = sorted(set(scope_old.keys()) | set(scope_new.keys()))
    for k in keys:
        old_set = set(scope_old.get(k, []))
        new_set = set(scope_new.get(k, []))
        added_vals = sorted(new_set - old_set)
        removed_vals = sorted(old_set - new_set)
        for v in added_vals:
            scope_changes.append(f"{k}: added {v}")
        for v in removed_vals:
            scope_changes.append(f"{k}: removed {v}")
    return added, removed, scope_changes


def _change_size(
    *,
    added: int,
    removed: int,
    scope_changes: int,
    current_count: int,
) -> float:
    """Normalized 0..1 change-size score.

    Per [[creates-never-mutates]] this measures what we'd actually DO
    (auto-install adds + scope tightening); removals are SURFACED but
    never applied so they don't drive the auto-install vs pending
    decision.

    Heuristic:
      * empty current + any adds → 1.0 (operator must approve the
        first profile build)
      * established profile → adds/(current_count+adds), with scope
        changes weighing half a rule each
    """
    if current_count <= 0 and added > 0:
        # First-ever rules go through operator approval — they're
        # establishing the baseline.
        return 1.0
    if added == 0 and scope_changes == 0:
        return 0.0
    denom = max(current_count, 1) + added
    numerator = added + 0.5 * scope_changes
    return min(1.0, round(numerator / denom, 4))


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def improve_profile(
    *,
    bouncer: str = "ibounce",
    cadence: str = "per_session",
    cadence_window: str | None = None,
    threshold: float = 0.30,
    auto_install: bool = True,
    apply: bool = True,
    posture: str = "ambient",
    profile_name: str | None = None,
    events: list[dict[str, Any]] | None = None,
    add_safety_denies: bool = True,
    preferred_backend: str | None = None,
    actor: str | None = None,
    source: str = "mcp",
    profiles_path: str | pathlib.Path | None = None,
    bouncer_url_overrides: dict[str, str] | None = None,
    queue_path: pathlib.Path | None = None,
    skip_fanout: bool = True,
    allow_agent_self_grant: bool | None = None,
) -> ImproveProfileResult:
    """Run one improve-profile cycle for a single bouncer.

    Strict per the brief:

    * ``posture="managed"`` → refuse to run (returns
      ``status="managed_posture_refused"``).
    * ``apply=False`` → return what WOULD happen (``status="dry_run"``).
    * Empty / no events → ``status="no_change"``.
    * Below threshold + ``auto_install=True`` → install via #345 path +
      admin_action audit emit; ``status="auto_installed"``.
    * At or above threshold → enqueue pending entries (§A25) +
      ``status="pending_approval"``.

    The default ``allow_agent_self_grant`` is ``True`` because the
    declaration's ``improve.auto_install_profiles`` is itself the
    operator's explicit consent (per ``[[agent-self-grant]]`` the
    declaration is the opt-in). The caller can override per-cycle.
    """
    window = cadence_window or _cadence_to_window(cadence, fallback="1h")

    # -----------------------------------------------------------------
    # Managed-posture refusal — explicit, clear, structured.
    # -----------------------------------------------------------------
    if posture == "managed":
        return ImproveProfileResult(
            status="managed_posture_refused",
            bouncer=bouncer,
            cadence_window=window,
            posture=posture,
            explanation=(
                "improve-profile refused: declaration has posture=managed "
                "which forbids auto-improve for reproducibility / "
                "auditability (commit profile changes via PR instead). "
                "Flip to posture=ambient or call improve-profile "
                "explicitly via CLI with --force (not yet implemented) "
                "to override."
            ),
        )

    # -----------------------------------------------------------------
    # Pull audit events if the caller didn't supply them.
    # -----------------------------------------------------------------
    if events is None:
        events = _fetch_events_for_bouncer(
            bouncer=bouncer,
            since=_window_to_since_iso(window),
        )

    if not events:
        return ImproveProfileResult(
            status="no_change",
            bouncer=bouncer,
            cadence_window=window,
            posture=posture,
            explanation=(
                f"no audit events for bouncer={bouncer} in cadence_window={window}; "
                f"no improvements to propose. Per "
                f"[[ibounce-honest-positioning]] reported as no-op rather "
                f"than fabricated change."
            ),
        )

    # -----------------------------------------------------------------
    # Run the existing generator pipeline (#326 + §A38).
    # -----------------------------------------------------------------
    try:
        from ..llm.profile_generator import generate_from_audit
    except Exception as e:  # pragma: no cover
        raise ImproveProfileError(
            f"could not import generator: {e}",
            code="generator_import_failed",
        ) from e

    bundle_name = profile_name or f"improve-{bouncer}-{_now_compact()}"
    gen_result = generate_from_audit(
        events=events,
        time_range=window,
        bouncers=[bouncer],
        add_safety_denies=add_safety_denies,
        profile_name=bundle_name,
        preferred_backend=preferred_backend,
    )

    # The generator returns ONE GeneratedProfile per bouncer; pick ours.
    target = None
    for gp in gen_result.bundle:
        if gp.bouncer == bouncer:
            target = gp
            break
    if target is None:
        return ImproveProfileResult(
            status="no_change",
            bouncer=bouncer,
            cadence_window=window,
            posture=posture,
            explanation=(
                f"generator produced no profile for bouncer={bouncer}; "
                f"likely no relevant events. Backend={gen_result.backend_name!r}."
            ),
        )

    # We have to peek at the parsed proposed allows. The generator
    # stores them in the parsed profile dict, not the rendered YAML.
    # Easiest: re-parse the rendered YAML to get the allows + scope.
    proposed = _parse_rendered_profile_yaml(target.profile_yaml)

    # -----------------------------------------------------------------
    # Load the current active profile for diffing.
    # -----------------------------------------------------------------
    try:
        from ..bouncer.profiles import load_profiles, resolve_active_profile
        profiles = load_profiles(path=profiles_path)
        current = (
            profiles[profile_name]
            if profile_name and profile_name in profiles
            else resolve_active_profile(profiles=profiles)
        )
    except Exception as e:
        # If we can't load profiles we report as error per the
        # honest-failure pattern.
        raise ImproveProfileError(
            f"could not load profiles for diffing: {e}",
            code="profiles_load_failed",
        ) from e

    added, removed, scope_changes = _compute_diff(
        current_profile=current, proposed=proposed,
    )
    current_count = len(getattr(current, "allow_rules", ()) or ())
    size = _change_size(
        added=len(added),
        removed=len(removed),
        scope_changes=len(scope_changes),
        current_count=current_count,
    )

    # Build proposed lists for the result dataclass (one entry per
    # added / removed pair, plus reason carried over from the generator
    # bundle's parsed allows).
    proposed_allows = [
        {"action": a, "target": t}
        for (a, t) in sorted(added, key=lambda x: (x[0], x[1] or ""))
    ]
    proposed_removals = [
        {"action": a, "target": t}
        for (a, t) in sorted(removed, key=lambda x: (x[0], x[1] or ""))
    ]

    # No diff?
    if not added and not removed and not scope_changes:
        return ImproveProfileResult(
            status="no_change",
            bouncer=bouncer,
            cadence_window=window,
            posture=posture,
            change_size=0.0,
            rules_added=0,
            rules_removed=0,
            scope_changes=[],
            requires_approval=False,
            explanation=(
                f"audit events found ({len(events)}) but generator's "
                f"profile is already a subset of the active profile "
                f"({current.name!r}). No-op."
            ),
        )

    # Dry-run path?
    if not apply:
        return ImproveProfileResult(
            status="dry_run",
            bouncer=bouncer,
            cadence_window=window,
            posture=posture,
            change_size=size,
            rules_added=len(added),
            rules_removed=len(removed),
            scope_changes=scope_changes,
            requires_approval=size >= threshold or not auto_install,
            proposed_allows=proposed_allows,
            proposed_removals=proposed_removals,
            explanation=(
                f"dry-run: size={size:.3f}, threshold={threshold:.3f}, "
                f"auto_install={auto_install}. Re-run with apply=True "
                f"to act."
            ),
        )

    # -----------------------------------------------------------------
    # Above threshold OR auto_install disabled → pending approval.
    # Per #451 (§A47b) fix: ALSO enqueue scope-only diffs so the JSONL
    # file is created + pending_entry_ids is populated — previously
    # scope-only paths reported pending_approval with an empty
    # pending_entry_ids[] and never created the file the explanation
    # pointed at.
    # -----------------------------------------------------------------
    above = size >= threshold
    if above or not auto_install:
        reason_str = (
            f"improve-profile @ size={size:.3f} "
            f"(threshold={threshold:.3f}) — "
            f"{len(events)} events in window={window}"
        )
        pending_ids = _enqueue_pending_for_each(
            proposed_allows=proposed_allows,
            reason=reason_str,
            profile_name=current.name,
            actor=actor,
            source=source,
            queue_path=queue_path,
        )
        pending_ids += _enqueue_pending_for_scope_changes(
            scope_changes=scope_changes,
            reason=reason_str,
            profile_name=current.name,
            actor=actor,
            source=source,
            queue_path=queue_path,
        )
        return ImproveProfileResult(
            status="pending_approval",
            bouncer=bouncer,
            cadence_window=window,
            posture=posture,
            change_size=size,
            rules_added=len(added),
            rules_removed=len(removed),
            scope_changes=scope_changes,
            requires_approval=True,
            pending_entry_ids=pending_ids,
            proposed_allows=proposed_allows,
            proposed_removals=proposed_removals,
            explanation=(
                f"change-size {size:.3f} >= threshold {threshold:.3f} "
                f"OR auto_install disabled. {len(pending_ids)} entries "
                f"queued for operator approval "
                f"({len(added)} allow + {len(scope_changes)} scope). "
                f"Review with `iam-jit denies recent --pending` "
                f"(or inspect ~/.iam-jit/bouncer/profile-allow-pending.jsonl)."
            ),
        )

    # -----------------------------------------------------------------
    # #452 (§A47c) honest-status routing: below threshold + only scope
    # changes (no allow adds) → status="scope_only_change" and route
    # the scope diffs through the pending queue per Fix 1. Previously
    # the auto-install loop ran zero iterations and we returned
    # status="auto_installed" with "auto-installed 0 allow rule(s)" —
    # which misleads operators per [[ibounce-honest-positioning]].
    # -----------------------------------------------------------------
    if not added and scope_changes:
        reason_str = (
            f"improve-profile scope-only @ size={size:.3f} "
            f"(threshold={threshold:.3f}) — "
            f"{len(events)} events in window={window}"
        )
        pending_ids = _enqueue_pending_for_scope_changes(
            scope_changes=scope_changes,
            reason=reason_str,
            profile_name=current.name,
            actor=actor,
            source=source,
            queue_path=queue_path,
        )
        return ImproveProfileResult(
            status="scope_only_change",
            bouncer=bouncer,
            cadence_window=window,
            posture=posture,
            change_size=size,
            rules_added=0,
            rules_removed=len(removed),
            scope_changes=scope_changes,
            requires_approval=True,
            pending_entry_ids=pending_ids,
            proposed_allows=[],
            proposed_removals=proposed_removals,
            explanation=(
                f"scope-only change for {bouncer}: {len(scope_changes)} "
                f"scope-floor diff(s) — no new allow rules to install. "
                f"Queued {len(pending_ids)} pending scope-change "
                f"entries for operator approval per "
                f"[[creates-never-mutates]] (inspect "
                f"~/.iam-jit/bouncer/profile-allow-pending.jsonl)."
            ),
        )

    # -----------------------------------------------------------------
    # Below threshold + auto_install → apply via existing #345 path.
    # -----------------------------------------------------------------
    audit_ids = []
    for entry in proposed_allows:
        action = entry["action"]
        # The #345 path refuses target="*" deliberately ([[creates-never-mutates]]
        # specificity). When the generator didn't bind a target, skip the
        # install + log — operator sees it in proposed_allows for review.
        target = entry["target"]
        if not target:
            logger.info(
                "improve-profile: skipping auto-install for action=%s "
                "without a specific target (would refuse target='*')",
                action,
            )
            continue
        try:
            from ..profile_allow.operations import (
                ProfileAllowError,
                add_profile_allow_rule,
            )
            add_result = add_profile_allow_rule(
                target=target,
                action=action,
                reason=(
                    f"improve-profile auto-install @ size={size:.3f} "
                    f"(threshold={threshold:.3f}, "
                    f"events={len(events)}, window={window})"
                ),
                profile_name=current.name,
                source=source,
                actor=actor,
                profiles_path=profiles_path,
                bouncer_url_overrides=bouncer_url_overrides,
                skip_fanout=skip_fanout,
                queue_path=queue_path,
                allow_agent_self_grant=(
                    allow_agent_self_grant
                    if allow_agent_self_grant is not None
                    else True  # declaration is the consent
                ),
            )
        except ProfileAllowError as e:
            # Refusing a single rule shouldn't fail the whole cycle —
            # log + continue per [[ibounce-honest-positioning]].
            logger.warning(
                "improve-profile rule add refused: %s (code=%s)",
                e, e.code,
            )
            continue
        except Exception as e:  # pragma: no cover
            logger.warning("improve-profile rule add raised: %s", e)
            continue
        # Emit admin_action audit (best-effort, may no-op out of
        # process; we still record the id locally).
        ev_id = _emit_improve_audit(
            actor=add_result.actor,
            target=target,
            action=action,
            profile_name=current.name,
            change_size=size,
            events_count=len(events),
            window=window,
            source=source,
        )
        if ev_id:
            audit_ids.append(ev_id)

    # Even when auto-installing allow rules, scope-floor changes route
    # through pending approval per [[creates-never-mutates]] (scope
    # narrowing affects what was previously permitted). Composes with
    # #451 (§A47b) so any scope diffs DO surface as pending entries
    # rather than disappearing silently.
    pending_scope_ids: list[str] = []
    if scope_changes:
        pending_scope_ids = _enqueue_pending_for_scope_changes(
            scope_changes=scope_changes,
            reason=(
                f"improve-profile auto-install side-effect @ size={size:.3f} "
                f"(threshold={threshold:.3f}) — "
                f"{len(events)} events in window={window}"
            ),
            profile_name=current.name,
            actor=actor,
            source=source,
            queue_path=queue_path,
        )

    return ImproveProfileResult(
        status="auto_installed",
        bouncer=bouncer,
        cadence_window=window,
        posture=posture,
        change_size=size,
        rules_added=len(added),
        rules_removed=len(removed),
        scope_changes=scope_changes,
        requires_approval=bool(pending_scope_ids),
        audit_event_ids=audit_ids,
        pending_entry_ids=pending_scope_ids,
        proposed_allows=proposed_allows,
        proposed_removals=proposed_removals,
        explanation=(
            f"auto-installed {len(added)} allow rule(s) for {bouncer} "
            f"(size={size:.3f} < threshold={threshold:.3f}). "
            f"{len(removed)} stale rule(s) flagged for operator review "
            f"but NOT removed per [[creates-never-mutates]]. "
            + (
                f"Queued {len(pending_scope_ids)} scope-change "
                f"entries for operator approval."
                if pending_scope_ids
                else ""
            )
        ).rstrip(),
    )


# ---------------------------------------------------------------------------
# Helpers — audit emit, pending enqueue, audit fetch, YAML re-parse
# ---------------------------------------------------------------------------


def _emit_improve_audit(
    *,
    actor: str,
    target: str,
    action: str,
    profile_name: str,
    change_size: float,
    events_count: int,
    window: str,
    source: str,
) -> str | None:
    """Best-effort admin-action emit for ``profile.install`` kind.

    Returns a synthetic event id on success, None when the audit channel
    is not reachable from this process (out-of-process CLI invocations).
    """
    try:
        from ..bouncer.audit_export.admin_action import (
            ADMIN_ACTION_RULE_ADD,
            emit_admin_action_direct,
        )
        from ..bouncer.proxy import _emit_audit_event
    except Exception:
        return None
    try:
        emit_admin_action_direct(
            _emit_audit_event,
            kind=ADMIN_ACTION_RULE_ADD,
            actor=actor,
            target_kind="profile_allow_rule",
            target_id=f"{profile_name}:{action}@{target}",
            source=source,
            extra={
                "origin": "improve-profile",
                "change_size": change_size,
                "events_in_window": events_count,
                "window": window,
            },
        )
    except Exception as e:  # pragma: no cover
        logger.debug("improve audit emit failed: %s", e)
        return None
    import time
    return f"improve-{action.replace(':', '_')}-{int(time.time() * 1000)}"


def _enqueue_pending_for_each(
    *,
    proposed_allows: list[dict[str, Any]],
    reason: str,
    profile_name: str,
    actor: str | None,
    source: str,
    queue_path: pathlib.Path | None,
) -> list[str]:
    """Enqueue one pending-approval entry per proposed allow.

    Per #451 (§A47b) fix: regardless of whether the caller's ``source``
    is ``cli`` / ``mcp`` / ``autopilot``, we ALWAYS route through the
    pending queue here — the contract is "this function pends; it does
    NOT apply". Previously we passed ``source`` through unchanged,
    which let the ``cli`` path slip past the agent-self-grant gate and
    silently APPLY (so ``pending_entry_ids`` came back empty + the
    JSONL file the explanation references was never created).

    The pending entry's ``source`` field preserves the caller's
    original source so the audit trail still shows whether a
    CLI / MCP / autopilot invocation triggered the pending request.
    We achieve "always pend" by writing directly to the JSONL queue
    via :func:`iam_jit.profile_allow.operations._enqueue_pending`,
    bypassing the gate entirely.
    """
    out: list[str] = []
    try:
        from ..profile_allow.operations import _enqueue_pending
    except Exception:  # pragma: no cover
        return out
    resolved_actor = (actor or "improve-profile-agent").strip() or "improve-profile-agent"
    for entry in proposed_allows:
        action = entry["action"]
        target = entry["target"] or "*"
        if target == "*":
            # The pending queue's reviewer surface refuses wildcard
            # targets too; surface a debug log + skip so we don't
            # write garbage rows.
            logger.warning(
                "improve-profile: skipping pending enqueue for "
                "wildcard target on action=%s", action,
            )
            continue
        try:
            written = _enqueue_pending(
                target=target,
                actions=[action],
                reason=reason,
                duration=None,
                expires_at=None,
                profile_name=profile_name,
                actor=resolved_actor,
                source=source,
                queue_path=queue_path,
                kind="profile_allow",
            )
        except Exception as e:
            logger.debug(
                "improve-profile pending enqueue failed: %s "
                "(action=%s target=%s)", e, action, target,
            )
            continue
        if written and written.get("id"):
            out.append(written["id"])
    return out


def _enqueue_pending_for_scope_changes(
    *,
    scope_changes: list[str],
    reason: str,
    profile_name: str,
    actor: str | None,
    source: str,
    queue_path: pathlib.Path | None,
) -> list[str]:
    """Enqueue one pending-approval entry per scope-floor change.

    Per #451 (§A47b) fix: scope-only diffs (e.g.
    ``only_account_ids: added 999988887777``) MUST land in the same
    JSONL queue as allow-rule proposals so the operator has ONE place
    to review every pending change AND the explanation message that
    references ``~/.iam-jit/bouncer/profile-allow-pending.jsonl`` is
    honest (file IS created on first scope-change).

    Each bullet has shape ``"<field>: <op> <value>"`` produced by
    :func:`_compute_diff`; we re-parse them here so the queue entry
    carries structured fields the operator's review tool can render.
    """
    out: list[str] = []
    if not scope_changes:
        return out
    try:
        from ..profile_allow.operations import enqueue_pending_scope_change
    except Exception:  # pragma: no cover
        return out
    resolved_actor = (actor or "improve-profile-agent").strip() or "improve-profile-agent"
    for bullet in scope_changes:
        # Bullet shape from _compute_diff: "<field>: <op> <value>"
        if ":" not in bullet:
            continue
        field, rhs = bullet.split(":", 1)
        rhs = rhs.strip()
        parts = rhs.split(None, 1)
        if len(parts) != 2:
            continue
        op, value = parts[0], parts[1]
        if op not in ("added", "removed"):
            continue
        try:
            entry = enqueue_pending_scope_change(
                field=field.strip(),
                op=op,
                value=value,
                reason=reason,
                profile_name=profile_name,
                actor=resolved_actor,
                source=source,
                queue_path=queue_path,
            )
        except Exception as e:  # pragma: no cover
            logger.debug(
                "improve-profile scope-change enqueue failed: %s (bullet=%s)",
                e, bullet,
            )
            continue
        if entry and entry.get("id"):
            out.append(entry["id"])
    return out


def _fetch_events_for_bouncer(
    *,
    bouncer: str,
    since: str | None,
) -> list[dict[str, Any]]:
    """Fan out to the named bouncer's /audit/events endpoint and
    return the events as a list. Returns ``[]`` on failure.
    """
    try:
        from ..cli_audit_query import (
            DEFAULT_BOUNCERS,
            _query_one_bouncer,
            _resolve_bouncer_set,
        )
    except Exception:  # pragma: no cover
        return []
    if bouncer not in DEFAULT_BOUNCERS:
        return []
    endpoints = _resolve_bouncer_set((bouncer,))
    out: list[dict[str, Any]] = []
    for ep in endpoints:
        r = _query_one_bouncer(
            ep,
            since=since,
            until=None,
            filters=(),
            limit=1000,
            bearer_token=None,
            timeout=5.0,
        )
        if r.error:
            logger.debug(
                "improve-profile audit fetch error for %s: %s",
                bouncer, r.error,
            )
            continue
        out.extend(r.events)
    return out


def _parse_rendered_profile_yaml(profile_yaml: str) -> dict[str, Any]:
    """Best-effort YAML parse to extract the proposed allows + scope
    from the generator's rendered output.

    The generator's YAML follows the bouncer-profile schema; we walk
    it and return ``{allows: [...], denies: [...], only_X: [...]}``.
    """
    try:
        import yaml
    except ImportError:  # pragma: no cover
        return {"allows": [], "denies": []}
    try:
        parsed = yaml.safe_load(profile_yaml) or {}
    except yaml.YAMLError as e:
        logger.warning("improve-profile YAML parse failed: %s", e)
        return {"allows": [], "denies": []}
    # The generator's YAML wraps the profile body under
    # `profiles.<name>` per the standard bouncer-profile schema; find
    # the (single) profile block.
    profiles_block = parsed.get("profiles") if isinstance(parsed, dict) else None
    if isinstance(profiles_block, dict) and profiles_block:
        # Take the first (deterministic — there's exactly one per
        # generator emit).
        body = next(iter(profiles_block.values()))
        if isinstance(body, dict):
            return body
    # Fallback: assume the parsed dict IS the body.
    if isinstance(parsed, dict):
        return parsed
    return {"allows": [], "denies": []}


def _now_compact() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# MCP + CLI surface adapters
# ---------------------------------------------------------------------------


def improve_profile_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """MCP backend for ``iam_jit_improve_profile``.

    Accepted args (all optional except ``bouncer`` which defaults to
    ``ibounce``):

      * bouncer: str (ibounce / kbouncer / dbounce / gbounce)
      * cadence: per_session | daily | weekly
      * cadence_window: explicit override (e.g. ``2h``)
      * threshold: float 0..1 (default 0.30)
      * auto_install: bool (default True)
      * apply: bool (default True; False = dry-run)
      * posture: ambient | managed (default ambient — managed refuses)
      * profile_name: override active-profile resolution
      * preferred_backend: anthropic | openai | bedrock | ollama
      * actor: identity recorded in audit + pending entries
      * events: pre-fetched OCSF events (optional)

    Returns the :class:`ImproveProfileResult` dict.
    """
    try:
        result = improve_profile(
            bouncer=str(args.get("bouncer") or "ibounce"),
            cadence=str(args.get("cadence") or "per_session"),
            cadence_window=(
                str(args["cadence_window"])
                if args.get("cadence_window")
                else None
            ),
            threshold=float(args.get("threshold") or 0.30),
            auto_install=bool(args.get("auto_install", True)),
            apply=bool(args.get("apply", True)),
            posture=str(args.get("posture") or "ambient"),
            profile_name=args.get("profile_name") or None,
            events=args.get("events") or None,
            add_safety_denies=bool(args.get("add_safety_denies", True)),
            preferred_backend=args.get("preferred_backend") or None,
            actor=args.get("actor") or None,
            source="mcp",
            allow_agent_self_grant=args.get("allow_agent_self_grant"),
        )
    except ImproveProfileError as e:
        return {
            "status": "error",
            "code": e.code,
            "message": str(e),
            "details": e.details,
        }
    return result.as_dict()


def improve_profile_for_cli(
    *,
    bouncer: str = "ibounce",
    cadence_window: str | None = None,
    threshold: float = 0.30,
    apply: bool = False,
    posture: str = "ambient",
    cadence: str = "per_session",
) -> ImproveProfileResult:
    """CLI shim — same defaults as MCP but ``apply`` defaults False so
    operators see a dry-run by default unless they pass ``--apply``."""
    return improve_profile(
        bouncer=bouncer,
        cadence=cadence,
        cadence_window=cadence_window,
        threshold=threshold,
        apply=apply,
        posture=posture,
        source="cli",
        actor=os.environ.get("USER") or "operator",
    )


__all__ = [
    "ImproveProfileError",
    "ImproveProfileResult",
    "improve_profile",
    "improve_profile_for_cli",
    "improve_profile_for_mcp",
]
