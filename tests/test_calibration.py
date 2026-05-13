"""Calibration module — scorer-vs-human disagreement stats.

The numbers reported here drive the human-in-the-loop tuning process
in docs/EVOLVING-THE-SCORER.md. The tests pin the contract: a row of
fixture requests in, the disagreement counts out, with full
reproducibility.

We construct synthetic request payloads rather than using a real
store; the analyze() function is pure over an iterable so this
keeps the tests fast and focused.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

import pytest

from iam_jit import calibration


def _request(
    *,
    request_id: str,
    score: int | None,
    state: str,
    history: list[dict[str, Any]] | None = None,
    submitted_at: str = "2026-05-01T10:00:00Z",
) -> dict[str, Any]:
    """Build a minimal request dict with just the fields the analyzer
    reads. Keeping this constructor small avoids hidden coupling
    between tests and the schema."""
    review_block: dict[str, Any] = {}
    if score is not None:
        review_block["risk_score"] = score
    return {
        "metadata": {"id": request_id},
        "status": {
            "state": state,
            "submitted_at": submitted_at,
            "review": review_block,
            "history": history or [],
        },
    }


def _auto_approve_event(at: str = "2026-05-01T10:00:01Z") -> dict[str, Any]:
    return {
        "actor": "system:auto-approver",
        "action": "auto_approve",
        "to_state": "provisioning",
        "at": at,
    }


def _human_approve(actor: str = "email:approver@x") -> dict[str, Any]:
    return {
        "actor": actor,
        "action": "approve",
        "to_state": "provisioning",
        "at": "2026-05-01T10:05:00Z",
    }


def _human_reject(actor: str = "email:approver@x") -> dict[str, Any]:
    return {
        "actor": actor,
        "action": "reject",
        "to_state": "rejected",
        "at": "2026-05-01T10:05:00Z",
    }


def _active(at: str = "2026-05-01T10:01:00Z") -> dict[str, Any]:
    return {
        "action": "active",
        "to_state": "active",
        "by": "system",
        "at": at,
    }


def _revoke(at: str) -> dict[str, Any]:
    return {
        "action": "revoke",
        "to_state": "revoked",
        "by": "system",
        "at": at,
    }


# ---- Basic counts ---------------------------------------------------


def test_empty_returns_zeros_and_note() -> None:
    report = calibration.analyze([], threshold=5)
    assert report.total == 0
    assert "no decisions" in report.notes[0].lower()


def test_counts_auto_approved() -> None:
    reqs = [
        _request(
            request_id="r1", score=2, state="active",
            history=[_auto_approve_event(), _active()],
        ),
        _request(
            request_id="r2", score=3, state="active",
            history=[_auto_approve_event(), _active()],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5)
    assert report.total == 2
    assert report.auto_approved_count == 2
    assert report.human_approved_count == 0
    assert report.human_rejected_count == 0


def test_counts_human_approvals_with_score_distribution() -> None:
    reqs = [
        _request(
            request_id="r1", score=4, state="active",
            history=[_human_approve(), _active()],
        ),
        _request(
            request_id="r2", score=4, state="active",
            history=[_human_approve(), _active()],
        ),
        _request(
            request_id="r3", score=7, state="active",
            history=[_human_approve(), _active()],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5)
    assert report.human_approved_count == 3
    assert report.score_distribution_approved == {4: 2, 7: 1}


def test_counts_human_rejections_with_score_distribution() -> None:
    reqs = [
        _request(
            request_id="r1", score=8, state="rejected",
            history=[_human_reject()],
        ),
        _request(
            request_id="r2", score=2, state="rejected",
            history=[_human_reject()],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5)
    assert report.human_rejected_count == 2
    assert report.score_distribution_rejected == {8: 1, 2: 1}


# ---- The disagreement signals (the whole point) --------------------


def test_scorer_overshoot_when_human_rejects_low_score() -> None:
    """Scorer says auto-approve (score < threshold) but human
    rejects. Counted as scorer being too permissive."""
    reqs = [
        _request(
            request_id="r1", score=2, state="rejected",
            history=[_human_reject()],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5)
    assert report.scorer_overshoot_count == 1
    assert report.scorer_undershoot_count == 0


def test_scorer_undershoot_when_human_approves_high_score() -> None:
    """Scorer says route to review (score >= threshold) but human
    rubber-stamps. Counted as scorer being too cautious."""
    reqs = [
        _request(
            request_id="r1", score=8, state="active",
            history=[_human_approve(), _active()],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5)
    assert report.scorer_undershoot_count == 1
    assert report.scorer_overshoot_count == 0


def test_no_disagreement_when_human_agrees_with_scorer() -> None:
    reqs = [
        # Scorer would auto-approve, human approves
        _request(
            request_id="r1", score=2, state="active",
            history=[_human_approve(), _active()],
        ),
        # Scorer would route to review, human rejects
        _request(
            request_id="r2", score=8, state="rejected",
            history=[_human_reject()],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5)
    assert report.scorer_overshoot_count == 0
    assert report.scorer_undershoot_count == 0


def test_no_threshold_disables_disagreement_count() -> None:
    """When the deployment has auto-approve disabled (threshold=None),
    the over/undershoot fields are zero by definition. The notes list
    should explicitly call this out so admins know they need to set a
    threshold to start measuring."""
    reqs = [
        _request(
            request_id="r1", score=2, state="rejected",
            history=[_human_reject()],
        ),
    ]
    report = calibration.analyze(reqs, threshold=None)
    assert report.scorer_overshoot_count == 0
    assert any("threshold is none" in n.lower() for n in report.notes)


# ---- Early-revoke outcome signal -----------------------------------


def test_early_revoke_flagged() -> None:
    reqs = [
        _request(
            request_id="r1", score=2, state="revoked",
            history=[
                _auto_approve_event(),
                _active("2026-05-01T10:00:00Z"),
                _revoke("2026-05-01T10:02:00Z"),  # 2 min later
            ],
        ),
    ]
    report = calibration.analyze(
        reqs, threshold=5, early_revoke_minutes=15,
    )
    assert report.early_revoke_count == 1
    assert report.score_distribution_early_revoke == {2: 1}


def test_late_revoke_not_flagged() -> None:
    reqs = [
        _request(
            request_id="r1", score=2, state="revoked",
            history=[
                _auto_approve_event(),
                _active("2026-05-01T10:00:00Z"),
                _revoke("2026-05-01T11:30:00Z"),  # 90 min — fine
            ],
        ),
    ]
    report = calibration.analyze(
        reqs, threshold=5, early_revoke_minutes=15,
    )
    assert report.early_revoke_count == 0


def test_early_revoke_window_is_configurable() -> None:
    reqs = [
        _request(
            request_id="r1", score=2, state="revoked",
            history=[
                _auto_approve_event(),
                _active("2026-05-01T10:00:00Z"),
                _revoke("2026-05-01T10:20:00Z"),  # 20 min
            ],
        ),
    ]
    # Threshold 15 → not early
    r1 = calibration.analyze(reqs, threshold=5, early_revoke_minutes=15)
    assert r1.early_revoke_count == 0
    # Threshold 30 → early
    r2 = calibration.analyze(reqs, threshold=5, early_revoke_minutes=30)
    assert r2.early_revoke_count == 1


# ---- Time filtering -------------------------------------------------


def test_since_filter_excludes_old_requests() -> None:
    reqs = [
        _request(
            request_id="old", score=4, state="active",
            submitted_at="2025-01-01T00:00:00Z",
            history=[_human_approve(), _active()],
        ),
        _request(
            request_id="new", score=4, state="active",
            submitted_at="2026-05-01T00:00:00Z",
            history=[_human_approve(), _active()],
        ),
    ]
    since = _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC)
    report = calibration.analyze(reqs, threshold=5, since=since)
    assert report.total == 1


# ---- End-to-end: realistic multi-row report -----------------------


def test_realistic_mix_produces_actionable_report() -> None:
    """Multiple decision shapes in one window: the report should
    surface the disagreement signal that an admin can act on."""
    reqs = [
        # 3 auto-approves with healthy lifetimes
        _request(
            request_id="r1", score=2, state="active",
            history=[_auto_approve_event(), _active("2026-05-01T10:00:00Z")],
        ),
        _request(
            request_id="r2", score=2, state="expired",
            history=[
                _auto_approve_event(),
                _active("2026-05-01T10:00:00Z"),
                {"action": "expire", "to_state": "expired",
                 "at": "2026-05-01T11:00:00Z", "by": "system"},
            ],
        ),
        _request(
            request_id="r3", score=3, state="active",
            history=[_auto_approve_event(), _active("2026-05-01T10:00:00Z")],
        ),
        # 1 auto-approve that was revoked early — bad outcome signal
        _request(
            request_id="r4", score=4, state="revoked",
            history=[
                _auto_approve_event(),
                _active("2026-05-01T10:00:00Z"),
                _revoke("2026-05-01T10:03:00Z"),
            ],
        ),
        # 1 human-approved (over threshold; scorer would have flagged) — undershoot
        _request(
            request_id="r5", score=7, state="active",
            history=[_human_approve(), _active()],
        ),
        # 1 human-rejected (under threshold; scorer would have approved) — overshoot
        _request(
            request_id="r6", score=2, state="rejected",
            history=[_human_reject()],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5, early_revoke_minutes=15)
    assert report.total == 6
    assert report.auto_approved_count == 4
    assert report.human_approved_count == 1
    assert report.human_rejected_count == 1
    assert report.scorer_overshoot_count == 1
    assert report.scorer_undershoot_count == 1
    assert report.early_revoke_count == 1
    assert report.score_distribution_early_revoke == {4: 1}


# ---- Edge cases ---------------------------------------------------


def test_missing_score_does_not_crash() -> None:
    reqs = [
        _request(
            request_id="r1", score=None, state="active",
            history=[_human_approve(), _active()],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5)
    assert report.total == 1
    assert report.human_approved_count == 1
    # Score-less rows can't be in score distributions.
    assert report.score_distribution_approved == {}


def test_pending_request_counted_as_no_decision() -> None:
    reqs = [
        _request(
            request_id="r1", score=4, state="pending",
            history=[],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5)
    assert report.no_decision_count == 1


def test_audit_relevant_actor_distinguished_from_system() -> None:
    """An 'approve' action by 'system:auto-approver' must NOT be
    counted as a human approval — that's the whole point of the
    auto-approver actor being a distinct identity."""
    reqs = [
        _request(
            request_id="r1", score=2, state="active",
            history=[
                # Old code path used "approve" action by system — be
                # defensive: actor with system: prefix is never a
                # human decision regardless of action name.
                {"actor": "system:auto-approver", "action": "approve",
                 "to_state": "provisioning", "at": "2026-05-01T10:00:01Z"},
                _active(),
            ],
        ),
    ]
    report = calibration.analyze(reqs, threshold=5)
    assert report.human_approved_count == 0
