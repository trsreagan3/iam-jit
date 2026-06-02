# #722 / BUILD-1 — `iam-jit agent-diff` differential audit.
"""Differential audit: compare two agent sessions captured in the
cross-bouncer audit log.

Per the competitive-firewall PDF this is iam-jit's **highest single
differentiation** — Apono / Pipelock / NanoClaw publish per-session
analysis but none surface session-to-session diff. Pairs with
role-effectiveness grading (#393) to answer "which agent should I
write the role for".

The public surface:

* :func:`compute_agent_diff` — pure function; takes two lists of OCSF
  events + a narrowing strategy and returns an :class:`AgentDiff`.
* :func:`fetch_session_events_via_fanout` — small fan-out helper that
  composes on top of :mod:`iam_jit.cli_audit_query`'s per-bouncer
  fetch. Lifted out so the CLI + MCP backends share one path.

Both surfaces honor [[ibounce-honest-positioning]]: empty deltas are
empty arrays + honest `cannot_narrow_reason` strings, not invented
insights. Per [[recommender-context-boundary]] the only inputs are
AWS state + audit events.

See ``docs/AGENT-DIFF-DESIGN.md`` for the data-model + algorithm spec.
"""

from .diff import (
    AgentDiff,
    BehavioralDelta,
    DecisionDelta,
    NarrowingResult,
    PermissionDelta,
    PermissionDeltaRow,
    PermissionIntersectionRow,
    RiskDelta,
    SessionSummary,
    build_narrowing_policy,
    compute_agent_diff,
    compute_behavioral_delta,
    compute_decision_delta,
    compute_permission_delta,
    compute_risk_delta,
)
from .fanout import fetch_session_events_via_fanout

__all__ = [
    "AgentDiff",
    "BehavioralDelta",
    "DecisionDelta",
    "NarrowingResult",
    "PermissionDelta",
    "PermissionDeltaRow",
    "PermissionIntersectionRow",
    "RiskDelta",
    "SessionSummary",
    "build_narrowing_policy",
    "compute_agent_diff",
    "compute_behavioral_delta",
    "compute_decision_delta",
    "compute_permission_delta",
    "compute_risk_delta",
    "fetch_session_events_via_fanout",
]
