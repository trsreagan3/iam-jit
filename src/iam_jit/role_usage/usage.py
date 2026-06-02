# #727 / BUILD-6 — session-scoped role-usage analysis.
"""Pure-function core for "Used N of M permissions — here's the
narrowed role".

The data-driven close of iam-jit's recommend → grant → observe loop:

* The **granted** set = the Allow-action globs in the issued role's
  inline policy (the policy iam-jit CREATED for the session per
  [[create-not-assume-pattern]] / [[creates-never-mutates]]).
* The **used** set = the concrete ``service:Action`` operations the
  agent actually invoked, read off the bouncer's own OCSF audit log
  keyed by ``unmapped.iam_jit.agent.session_id`` (the same stream
  ``iam-jit audit query`` and ``iam-jit agent-diff`` consume).

This module does the diff and proposes a NARROWED policy containing
only the permissions that were used. It is read-only: per
[[creates-never-mutates]] it RECOMMENDS — it never mutates the issued
role, and the narrowed policy is an artifact for operator review.

Reuse, not reinvention:

* Event-walking (``_event_action`` / ``_event_resources`` /
  ``_aggregate_by_action``) is imported laterally from
  :mod:`iam_jit.agent_diff.diff` so the "used" view here is the SAME
  view the agent-diff and audit-extract surfaces produce. There is no
  second action/resource extractor.
* The narrowed-policy builder reuses the agent-diff narrowing shape
  (one Allow statement per action, resources scoped to what was
  observed, ``"*"`` flagged honestly when no named resource appeared).
* Action-glob expansion uses ``policy_sentry`` — the SAME corpus the
  scorer (``iam_jit.review``) uses — so the granted COUNT is the real
  number of concrete AWS actions the glob admits, not a glob count.

Honesty per [[ibounce-honest-positioning]]:

* The narrowed policy is described as a FLOOR derived from observed
  usage — never a guarantee the workload is complete. A read-only
  session, a short observation window, or audit gaps all mean "used"
  is a lower bound. Those caveats are surfaced as explicit
  ``caveats`` strings and a ``usage_is_complete: false`` style signal,
  never hidden.
* If policy_sentry is unavailable (it's an optional dep) we fall back
  to counting literal globs and SAY the count is glob-level, not
  action-level.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import typing

# Lateral reuse: the exact same event-walking helpers agent-diff and
# audit-extract use. Importing them here guarantees the "used" set in
# the role-usage view matches every other audit-derived view.
from ..agent_diff.diff import _aggregate_by_action


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class UsedAction:
    """One concrete action the agent actually invoked in the session."""

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
class NarrowedPolicy:
    """The proposed narrowed inline policy + provenance.

    ``policy`` is a real ``Version: 2012-10-17`` document containing
    only used actions, or an honestly-empty document with
    ``cannot_narrow_reason`` set. Per [[creates-never-mutates]] this is
    a RECOMMENDATION artifact — applying it is a separate, explicit,
    operator-driven request flow.
    """

    policy: dict[str, typing.Any]
    statement_count: int
    cannot_narrow_reason: str | None
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "policy": dict(self.policy),
            "statement_count": self.statement_count,
            "cannot_narrow_reason": self.cannot_narrow_reason,
            "notes": list(self.notes),
        }


@dataclasses.dataclass(frozen=True)
class RoleUsage:
    """Full "used N of M" report for one session."""

    session_id: str
    events_analyzed: int
    granted_count: int
    used_count: int
    granted_count_basis: str
    used_actions: tuple[UsedAction, ...]
    unused_permissions: tuple[str, ...]
    # Used actions NOT covered by any granted glob. In normal operation
    # this is empty (the bouncer only let through what the role allows);
    # a non-empty list is an honest signal of a granted/observed
    # mismatch (e.g. the operator passed the wrong policy, or the
    # bouncer ran cooperative-mode advisory) — surfaced, never hidden.
    used_outside_grant: tuple[str, ...]
    narrowed: NarrowedPolicy
    usage_is_complete: bool
    caveats: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "session_id": self.session_id,
            "events_analyzed": self.events_analyzed,
            "granted_count": self.granted_count,
            "used_count": self.used_count,
            "granted_count_basis": self.granted_count_basis,
            "used_actions": [a.as_dict() for a in self.used_actions],
            "unused_permissions": list(self.unused_permissions),
            "used_outside_grant": list(self.used_outside_grant),
            "narrowed": self.narrowed.as_dict(),
            "usage_is_complete": self.usage_is_complete,
            "caveats": list(self.caveats),
            "notes": list(self.notes),
        }

    def headline(self) -> str:
        """The one-line "Used N of M permissions" framing."""
        return (
            f"Used {self.used_count} of {self.granted_count} "
            f"granted permissions"
        )


# ---------------------------------------------------------------------------
# Granted-set extraction
# ---------------------------------------------------------------------------


def extract_granted_globs(policy: dict[str, typing.Any]) -> list[str]:
    """Return the Allow-effect Action globs from an IAM policy doc.

    Pure + defensive: tolerates ``Action`` as str or list, skips Deny
    statements (a narrowed FLOOR is about what was *allowed* + used;
    Deny boundaries are orthogonal and preserved by the operator if
    they re-request). Action strings are returned verbatim (original
    case) so the glob match against concrete actions is case-insensitive
    at compare time, not mutated here.
    """
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    globs: list[str] = []
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect")
        if not (isinstance(effect, str) and effect.strip().lower() == "allow"):
            continue
        actions = stmt.get("Action")
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            continue
        for a in actions:
            if isinstance(a, str) and a.strip():
                globs.append(a.strip())
    return globs


def _load_all_actions() -> list[str] | None:
    """Best-effort policy_sentry corpus of every concrete AWS action.

    Returns the action list (canonical ``service:Action`` case) or
    ``None`` when policy_sentry is not installed. policy_sentry is an
    optional dep — the module degrades to glob-level counting and SAYS
    so per [[ibounce-honest-positioning]].
    """
    try:
        from policy_sentry.querying.all import get_all_actions
    except Exception:
        return None  # noqa: SD-4 optional-dep absent; expand_granted falls back to literal_glob_count and compute_role_usage emits the "policy_sentry not installed" caveat (surfaced in RoleUsageResult.caveats)
    try:
        actions = get_all_actions()
    except Exception:
        return None  # noqa: SD-4 corpus query failed at runtime; same fail-soft as absent dep — surfaced via literal_glob_count caveat in RoleUsageResult.caveats
    if not actions:
        return None
    return sorted(actions)


def _glob_matches(glob: str, action_lc: str) -> bool:
    """Case-insensitive IAM action-glob match.

    IAM treats ``*`` / ``?`` as wildcards and matching is
    case-insensitive. A bare ``*`` matches everything.
    """
    return fnmatch.fnmatchcase(action_lc, glob.lower())


def expand_granted(
    globs: typing.Sequence[str],
    *,
    all_actions: typing.Sequence[str] | None = None,
) -> tuple[frozenset[str], str]:
    """Expand granted globs into the concrete granted action set.

    Returns ``(granted_set_lc, basis)`` where ``granted_set_lc`` is a
    frozenset of lowercased ``service:action`` strings and ``basis`` is
    a human string describing how the count was derived:

    * ``"policy_sentry_action_expansion"`` — every glob expanded
      against the real AWS action corpus; the count is the true number
      of concrete actions admitted.
    * ``"literal_glob_count"`` — policy_sentry unavailable; the granted
      set is the literal globs themselves (count is glob-level, an
      under-count of true breadth). Honest fallback.

    A bare ``"*"`` or ``"service:*"`` glob expands to every matching
    concrete action when the corpus is present.
    """
    if all_actions is None:
        all_actions = _load_all_actions()
    if not all_actions:
        # Fallback: count the literal globs. De-dup on lowercase.
        literal = frozenset(g.lower() for g in globs if g)
        return literal, "literal_glob_count"

    corpus_lc = [a.lower() for a in all_actions]
    granted: set[str] = set()
    for glob in globs:
        g = glob.strip()
        if not g:
            continue
        if not ("*" in g or "?" in g):
            # Literal action — keep as-is even if the corpus doesn't
            # know it (brand-new APIs). Lowercased for set hygiene.
            granted.add(g.lower())
            continue
        gl = g.lower()
        for a_lc in corpus_lc:
            if fnmatch.fnmatchcase(a_lc, gl):
                granted.add(a_lc)
    return frozenset(granted), "policy_sentry_action_expansion"


# ---------------------------------------------------------------------------
# Used-set extraction (reuses agent_diff aggregation)
# ---------------------------------------------------------------------------


def extract_used(
    events: typing.Sequence[dict[str, typing.Any]],
    *,
    allowed_only: bool = True,
) -> dict[str, dict[str, typing.Any]]:
    """Return ``{action: {resources: set, count: int}}`` for actions the
    agent actually invoked in the session.

    Reuses :func:`iam_jit.agent_diff.diff._aggregate_by_action` so this
    is the SAME used-view the agent-diff surface produces.

    ``allowed_only`` (default True): only ALLOW-verdict events count as
    "used" — a denied call did not exercise a granted permission, so a
    floor policy must not include it. Events with no verdict field
    (older/synthetic) are treated as used to avoid silently dropping
    real activity; that bias is conservative (keeps more, narrows less).
    """
    if not allowed_only:
        return _aggregate_by_action(events)

    kept: list[dict[str, typing.Any]] = []
    for ev in events:
        verdict = None
        unmapped = ev.get("unmapped")
        if isinstance(unmapped, dict):
            ij = unmapped.get("iam_jit")
            if isinstance(ij, dict):
                v = ij.get("verdict")
                if isinstance(v, str):
                    verdict = v.strip().lower()
        if verdict == "deny":
            continue
        kept.append(ev)
    return _aggregate_by_action(kept)


# ---------------------------------------------------------------------------
# Narrowed-policy builder
# ---------------------------------------------------------------------------


def build_narrowed_policy(
    used: dict[str, dict[str, typing.Any]],
) -> NarrowedPolicy:
    """Build a narrowed inline policy from the used-action aggregate.

    One Allow statement per used action, ``Resource`` scoped to the
    union of observed resources for that action. When no named resource
    was observed for an action, ``Resource`` is ``["*"]`` and the action
    is flagged in ``notes`` (honest: resource-scope was observed broadly
    / not captured, not that ``*`` is recommended).

    Mirrors the agent-diff narrowing shape so operators see one
    consistent narrowed-policy artifact across both surfaces. Empty used
    set → empty ``Statement`` + ``cannot_narrow_reason`` (never an
    invented Allow).
    """
    statements: list[dict[str, typing.Any]] = []
    notes: list[str] = []
    for action in sorted(used.keys()):
        res_set = set(used[action]["resources"])
        if not res_set:
            res_set = {"*"}
            notes.append(
                f"{action}: no specific resource observed in the "
                "session; resource scoped as '*'"
            )
        statements.append({
            "Effect": "Allow",
            "Action": [action],
            "Resource": sorted(res_set),
        })

    cannot_narrow_reason: str | None = None
    if not statements:
        cannot_narrow_reason = (
            "no allowed actions observed in this session; nothing to "
            "narrow to — the role went entirely unused (or the audit "
            "window/session id captured no events)"
        )

    return NarrowedPolicy(
        policy={"Version": "2012-10-17", "Statement": statements},
        statement_count=len(statements),
        cannot_narrow_reason=cannot_narrow_reason,
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------


def compute_role_usage(
    *,
    session_id: str,
    granted_policy: dict[str, typing.Any],
    events: typing.Sequence[dict[str, typing.Any]],
    all_actions: typing.Sequence[str] | None = None,
    notes: typing.Sequence[str] = (),
) -> RoleUsage:
    """Compose the granted-vs-used diff + narrowed policy.

    Pure function — no I/O. The CLI / MCP wrappers fetch ``events`` via
    the fan-out helper and load ``granted_policy`` from a file or the
    request store, then pass them in.

    Algorithm:

    1. Extract + expand the granted globs into the concrete granted
       action set (or literal globs if policy_sentry is absent).
    2. Aggregate the used actions off the audit events (ALLOW only).
    3. ``unused_permissions`` = granted actions NOT covered by any used
       action. For glob-level basis this is the granted globs none of
       whose family was touched.
    4. ``used_outside_grant`` = used actions not covered by any granted
       glob (honest mismatch signal).
    5. Build the narrowed policy from the used set.
    6. Decide ``usage_is_complete`` + caveats honestly.
    """
    granted_globs = extract_granted_globs(granted_policy)
    granted_set_lc, basis = expand_granted(
        granted_globs, all_actions=all_actions,
    )

    used_agg = extract_used(events, allowed_only=True)
    used_actions_lc = {a.lower() for a in used_agg}

    # used_outside_grant: a used action that no granted glob covers.
    def _granted_covers(action_lc: str) -> bool:
        # Fast path: literal/expanded set membership.
        if action_lc in granted_set_lc:
            return True
        # Glob path: any granted glob whose pattern matches the action.
        return any(_glob_matches(g, action_lc) for g in granted_globs)

    used_outside = sorted(
        a for a in used_actions_lc if not _granted_covers(a)
    )

    # unused_permissions: granted permissions never exercised.
    if basis == "policy_sentry_action_expansion":
        # granted_set_lc is concrete actions; unused = those not used.
        unused = sorted(granted_set_lc - used_actions_lc)
    else:
        # Literal-glob basis: a glob is "used" if any used action
        # matches it. Report the globs whose family went untouched.
        unused = sorted(
            g for g in {gg.lower() for gg in granted_globs}
            if not any(_glob_matches(g, a) for a in used_actions_lc)
        )

    used_actions = tuple(
        UsedAction(
            action=action,
            resources=tuple(sorted(used_agg[action]["resources"])),
            count=int(used_agg[action]["count"]),
        )
        for action in sorted(used_agg.keys())
    )

    narrowed = build_narrowed_policy(used_agg)

    # Honesty handling. The narrowed policy is a FLOOR based on observed
    # usage — never a completeness guarantee.
    caveats: list[str] = []
    usage_is_complete = False  # always a floor; never claim completeness
    caveats.append(
        "Narrowed policy is a FLOOR based on observed usage in this "
        "session window — not a guarantee the workload is complete. "
        "Re-run over a representative window before tightening a "
        "long-lived role."
    )
    if not used_agg:
        caveats.append(
            "Zero allowed actions observed: this may be a read-only "
            "session that hit no gated calls, an empty/short audit "
            "window, or a mismatched session id. Do NOT treat the "
            "empty narrowed policy as 'the role needs nothing'."
        )
    if basis == "literal_glob_count":
        caveats.append(
            "policy_sentry not installed: granted_count is a "
            "GLOB count, not the concrete-action count it admits — the "
            "true granted breadth is larger. Install policy_sentry for "
            "an action-level count."
        )
    if used_outside:
        caveats.append(
            "Some used actions are not covered by the granted policy "
            "passed in (see used_outside_grant). Confirm you passed the "
            "policy actually issued for this session; the narrowed "
            "policy still reflects what was observed."
        )

    return RoleUsage(
        session_id=session_id,
        events_analyzed=len(events),
        granted_count=len(granted_set_lc),
        used_count=len(used_agg),
        granted_count_basis=basis,
        used_actions=used_actions,
        unused_permissions=tuple(unused),
        used_outside_grant=tuple(used_outside),
        narrowed=narrowed,
        usage_is_complete=usage_is_complete,
        caveats=tuple(caveats),
        notes=tuple(notes),
    )
