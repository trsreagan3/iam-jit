"""Scorer calibration — measure scorer-vs-human disagreement.

The deterministic scorer's verdict on each request is recorded
alongside the human approver's actual decision in the request
lifecycle. This module walks the request store and computes
disagreement statistics so admins can see whether the scorer
is too cautious, too permissive, or drifting.

See `docs/EVOLVING-THE-SCORER.md` for the calibration loop this
data feeds.

Pure function over a sequence of request dicts: no network, no
clock other than for the `since` parameter. Easy to test by
constructing synthetic request payloads.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Iterable


# Terminal states for the lifecycle. A request in one of these
# is a finished decision the calibration can measure against.
_TERMINAL_STATES = frozenset(
    {"active", "rejected", "revoked", "expired", "cancelled",
     "provisioning_failed"}
)

# Human-approval states: a human decided yes/no on this request.
# (auto-approved requests are excluded from human-decision counts.)
_HUMAN_APPROVE_ACTIONS = frozenset({"approve"})
_HUMAN_REJECT_ACTIONS = frozenset({"reject", "request_changes"})
_AUTO_APPROVE_ACTOR = "system:auto-approver"


@dataclass(frozen=True)
class DecisionRow:
    """One observed decision, normalized for analysis."""

    request_id: str
    score: int | None
    """The deterministic score recorded at submit time, if any."""

    auto_approved: bool
    """True iff the auto-approver fired. Distinct from human approval."""

    human_verdict: str | None
    """One of: 'approved', 'rejected', None (no human decision yet)."""

    terminal_state: str | None
    """Final state if the request has reached one."""

    revoked_after_minutes: int | None
    """If the grant was revoked, how soon after going active.
    Short revoke windows are a signal the grant shouldn't have been
    auto-approved."""

    submitted_at: str | None


@dataclass(frozen=True)
class CalibrationReport:
    """Aggregate statistics over the analyzed decisions."""

    total: int
    auto_approved_count: int
    human_approved_count: int
    human_rejected_count: int
    no_decision_count: int

    # Disagreement: requests where the scorer would have auto-
    # approved (score < threshold) but a human rejected them.
    scorer_overshoot_count: int

    # Disagreement: requests where the scorer would NOT have auto-
    # approved (score >= threshold) but a human approved them
    # without issue.
    scorer_undershoot_count: int

    # Histogram of scores at human-approved decisions.
    score_distribution_approved: dict[int, int]
    # Histogram of scores at human-rejected decisions.
    score_distribution_rejected: dict[int, int]

    # Rows where the grant was revoked < `early_revoke_minutes` after
    # provisioning — potential "shouldn't have approved" signal.
    early_revoke_count: int

    # Score histogram for the early-revoke set; helps identify
    # which score ranges correlate with bad outcomes.
    score_distribution_early_revoke: dict[int, int]

    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "auto_approved_count": self.auto_approved_count,
            "human_approved_count": self.human_approved_count,
            "human_rejected_count": self.human_rejected_count,
            "no_decision_count": self.no_decision_count,
            "scorer_overshoot_count": self.scorer_overshoot_count,
            "scorer_undershoot_count": self.scorer_undershoot_count,
            "score_distribution_approved": dict(self.score_distribution_approved),
            "score_distribution_rejected": dict(self.score_distribution_rejected),
            "early_revoke_count": self.early_revoke_count,
            "score_distribution_early_revoke": dict(self.score_distribution_early_revoke),
            "notes": list(self.notes),
        }


def _parse_iso(s: str | None) -> _dt.datetime | None:
    if not s:
        return None
    # Tolerate trailing Z and microseconds.
    candidate = s.replace("Z", "+00:00")
    try:
        return _dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _extract_decision(req: dict[str, Any]) -> DecisionRow:
    """Normalize a request into a single DecisionRow for analysis."""
    metadata = req.get("metadata") or {}
    rid = metadata.get("id") or ""
    status = req.get("status") or {}
    review = status.get("review") or {}
    score = review.get("risk_score") if isinstance(review, dict) else None
    history = status.get("history") or []
    terminal_state = (
        status.get("state") if status.get("state") in _TERMINAL_STATES else None
    )

    auto_approved = False
    human_verdict: str | None = None
    provisioned_at: _dt.datetime | None = None
    revoked_at: _dt.datetime | None = None

    for ev in history:
        actor = ev.get("actor") or ev.get("by") or ""
        action = (ev.get("action") or "").lower()
        to_state = ev.get("to_state") or ev.get("to") or ""

        if actor == _AUTO_APPROVE_ACTOR and action == "auto_approve":
            auto_approved = True

        if action in _HUMAN_APPROVE_ACTIONS and not actor.startswith("system:"):
            human_verdict = "approved"
        elif action in _HUMAN_REJECT_ACTIONS and not actor.startswith("system:"):
            human_verdict = "rejected"

        if to_state == "active" and provisioned_at is None:
            provisioned_at = _parse_iso(ev.get("at"))
        if action in ("revoke", "revoked") or to_state == "revoked":
            revoked_at = _parse_iso(ev.get("at"))

    revoked_after_minutes: int | None = None
    if provisioned_at and revoked_at:
        delta = revoked_at - provisioned_at
        revoked_after_minutes = max(0, int(delta.total_seconds() / 60))

    return DecisionRow(
        request_id=rid,
        score=score if isinstance(score, int) else None,
        auto_approved=auto_approved,
        human_verdict=human_verdict,
        terminal_state=terminal_state,
        revoked_after_minutes=revoked_after_minutes,
        submitted_at=status.get("submitted_at"),
    )


def analyze(
    requests: Iterable[dict[str, Any]],
    *,
    threshold: int | None = None,
    early_revoke_minutes: int = 15,
    since: _dt.datetime | None = None,
) -> CalibrationReport:
    """Compute a calibration report over the given requests.

    Args:
      requests: every request to consider. Caller should filter to the
        relevant window before calling.
      threshold: the current `auto_approve_risk_below` value. Used to
        decide whether a request "would have" been auto-approved by
        the scorer for the under/overshoot calculation. None means the
        feature is disabled — only the human-decision histograms are
        computed in that case.
      early_revoke_minutes: a grant revoked within this many minutes
        of going active is flagged as "early revoke" — a potential
        signal the grant shouldn't have been auto-approved.
      since: ignore requests submitted before this datetime. None
        means no time filter.

    Returns:
      A CalibrationReport summarizing the decisions in scope.
    """
    total = 0
    auto_count = 0
    human_approved = 0
    human_rejected = 0
    no_decision = 0
    overshoot = 0  # scorer would auto-approve, human rejected
    undershoot = 0  # scorer would NOT auto-approve, human approved
    score_dist_approved: dict[int, int] = {}
    score_dist_rejected: dict[int, int] = {}
    score_dist_early_revoke: dict[int, int] = {}
    early_revoke = 0
    notes: list[str] = []

    for req in requests:
        row = _extract_decision(req)

        # Apply time filter
        if since is not None and row.submitted_at:
            ts = _parse_iso(row.submitted_at)
            if ts is None or ts < since:
                continue

        total += 1

        if row.auto_approved:
            auto_count += 1
        if row.human_verdict == "approved":
            human_approved += 1
            if row.score is not None:
                score_dist_approved[row.score] = (
                    score_dist_approved.get(row.score, 0) + 1
                )
                if threshold is not None and row.score >= threshold:
                    # Human approved a request the scorer would have
                    # routed to review. Scorer was over-cautious here.
                    undershoot += 1
        elif row.human_verdict == "rejected":
            human_rejected += 1
            if row.score is not None:
                score_dist_rejected[row.score] = (
                    score_dist_rejected.get(row.score, 0) + 1
                )
                if threshold is not None and row.score < threshold:
                    # Human rejected a request the scorer would have
                    # auto-approved. Scorer was under-cautious here.
                    overshoot += 1
        elif row.human_verdict is None and not row.auto_approved:
            no_decision += 1

        if (
            row.revoked_after_minutes is not None
            and row.revoked_after_minutes < early_revoke_minutes
        ):
            early_revoke += 1
            if row.score is not None:
                score_dist_early_revoke[row.score] = (
                    score_dist_early_revoke.get(row.score, 0) + 1
                )

    if threshold is None:
        notes.append(
            "auto-approve threshold is None (disabled); overshoot/"
            "undershoot counts are zero by definition. Set a "
            "threshold via PATCH /api/v1/admin/auto-approve/settings "
            "to start measuring scorer-vs-human agreement."
        )
    if total == 0:
        notes.append(
            "no decisions in the analyzed window. Submit some "
            "requests, or widen the `since` filter, then re-run."
        )
    elif human_approved + human_rejected == 0 and total > 0:
        notes.append(
            "all decisions in the window were auto-approved; no "
            "human-decision signal to calibrate against. Either "
            "lower the threshold to push more requests to review, "
            "OR confirm the auto-approve calibration is working as "
            "intended for your traffic."
        )

    return CalibrationReport(
        total=total,
        auto_approved_count=auto_count,
        human_approved_count=human_approved,
        human_rejected_count=human_rejected,
        no_decision_count=no_decision,
        scorer_overshoot_count=overshoot,
        scorer_undershoot_count=undershoot,
        score_distribution_approved=score_dist_approved,
        score_distribution_rejected=score_dist_rejected,
        early_revoke_count=early_revoke,
        score_distribution_early_revoke=score_dist_early_revoke,
        notes=notes,
    )
