"""Scoring-feedback channel routes.

POST /api/v1/feedback/scoring     submit a scoring disagreement
GET  /api/v1/admin/feedback/scoring  list recent submissions (admin)
PATCH /api/v1/admin/feedback/scoring/{id}  mark reviewed (admin)

The submission endpoint is open to anonymous callers (with a
stricter rate-limit) AND authenticated customers (with a higher
cap). The admin endpoints require the admin role.

See `src/iam_jit/scoring_feedback.py` for the storage layer and
rate-limit semantics.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .. import scoring_feedback
from ..middleware import current_user, require_admin
from ..users_store import User


router = APIRouter(tags=["feedback"])


_VALID_CATEGORIES = {"false-positive", "false-negative", "missing-factor"}


class FeedbackSubmissionIn(BaseModel):
    """What a customer posts when they disagree with a score."""

    policy: dict[str, Any] = Field(
        ..., description="The IAM policy the caller had scored."
    )
    our_score: int = Field(
        ..., ge=1, le=10,
        description="What iam-jit returned as the score.",
    )
    expected_score: int | None = Field(
        default=None, ge=1, le=10,
        description=(
            "Optional — what the submitter thinks the correct score "
            "is. Omit if they just want to flag the case without a "
            "specific counter-claim."
        ),
    )
    category: str = Field(
        ...,
        description=(
            "false-positive | false-negative | missing-factor. "
            "false-positive = score is too high; false-negative = "
            "score is too low (missed risk); missing-factor = score "
            "is roughly right but the explanation is incomplete."
        ),
    )
    explanation: str = Field(
        default="",
        max_length=2000,
        description="Optional short explanation (≤ 2000 chars).",
    )


class FeedbackSubmissionOut(BaseModel):
    feedback_id: str
    submitted_at: str
    review_status: str = "new"


def _submitter_id(request: Request) -> str | None:
    """Identify the submitter from the request (None if anonymous).

    Mirrors the score-route bearer-token resolution path but
    doesn't require the token to map to a paid tier — every
    authenticated identity gets the higher cap."""
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    raw = auth.split(" ", 1)[1].strip()
    if not raw.startswith("iamjit_"):
        return None
    tokens_store = getattr(request.app.state, "api_tokens_store", None)
    if tokens_store is None:
        return None
    try:
        from ..auth import hash_token

        record = tokens_store.get_by_hash(hash_token(raw))
        return record.user_id
    except Exception:
        return None


def _submitter_ip(request: Request) -> str:
    """Delegate to the shared trusted_proxy.client_ip helper.

    Closes WB7F-07 sibling-miss — this route was reading
    `request.client.host` raw while `routes/score.py` had the
    defended XFF path. Behind an ALB/CloudFront the per-IP rate
    limit was collapsing to deployment-wide.
    """
    from .. import trusted_proxy

    return trusted_proxy.client_ip(request)


@router.post(
    "/api/v1/feedback/scoring",
    status_code=status.HTTP_201_CREATED,
    response_model=FeedbackSubmissionOut,
)
def submit_scoring_feedback(
    request: Request,
    payload: FeedbackSubmissionIn,
) -> FeedbackSubmissionOut:
    if payload.category not in _VALID_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"category must be one of {sorted(_VALID_CATEGORIES)}",
        )
    submitter_id = _submitter_id(request)
    submitter_ip = _submitter_ip(request)
    try:
        submission = scoring_feedback.get_default_store().submit(
            submitter_id=submitter_id,
            submitter_ip=submitter_ip,
            policy=payload.policy,
            our_score=payload.our_score,
            expected_score=payload.expected_score,
            category=payload.category,
            explanation=payload.explanation,
        )
    except scoring_feedback.RateLimitError as e:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Feedback rate-limit exceeded ({e.scope}). "
                "Thanks for the report — please try again later."
            ),
            headers={"Retry-After": str(max(1, e.retry_after_seconds))},
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return FeedbackSubmissionOut(
        feedback_id=submission.feedback_id,
        submitted_at=submission.submitted_at,
        review_status=submission.review_status,
    )


# ---- Admin endpoints --------------------------------------------------


class FeedbackRecordOut(BaseModel):
    feedback_id: str
    submitted_at: str
    submitter_id: str | None
    submitter_ip: str
    our_score: int
    expected_score: int | None
    category: str
    explanation: str
    review_status: str
    reviewer_notes: str


class FeedbackListOut(BaseModel):
    count: int
    items: list[FeedbackRecordOut]


@router.get(
    "/api/v1/admin/feedback/scoring",
    response_model=FeedbackListOut,
)
def list_scoring_feedback(
    _admin: Annotated[User, Depends(require_admin)],
    limit: int = 100,
) -> FeedbackListOut:
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be 1..1000")
    submissions = scoring_feedback.get_default_store().list_recent(limit=limit)
    items = [
        FeedbackRecordOut(
            feedback_id=s.feedback_id,
            submitted_at=s.submitted_at,
            submitter_id=s.submitter_id,
            submitter_ip=s.submitter_ip,
            our_score=s.our_score,
            expected_score=s.expected_score,
            category=s.category,
            explanation=s.explanation,
            review_status=s.review_status,
            reviewer_notes=s.reviewer_notes,
        )
        for s in submissions
    ]
    return FeedbackListOut(count=len(items), items=items)


class FeedbackReviewIn(BaseModel):
    status: str = Field(
        ...,
        description=(
            "new | reviewed | added_to_corpus | dismissed. "
            "added_to_corpus marks the submission for a fixture export "
            "the next time the adversarial-loop runs."
        ),
    )
    reviewer_notes: str = Field(default="", max_length=2000)


@router.patch(
    "/api/v1/admin/feedback/scoring/{feedback_id}",
    response_model=FeedbackRecordOut,
)
def mark_feedback_reviewed(
    feedback_id: str,
    payload: FeedbackReviewIn,
    _admin: Annotated[User, Depends(require_admin)],
) -> FeedbackRecordOut:
    try:
        updated = scoring_feedback.get_default_store().mark_reviewed(
            feedback_id,
            status=payload.status,
            reviewer_notes=payload.reviewer_notes,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if updated is None:
        raise HTTPException(status_code=404, detail=f"feedback {feedback_id} not found")
    return FeedbackRecordOut(
        feedback_id=updated.feedback_id,
        submitted_at=updated.submitted_at,
        submitter_id=updated.submitter_id,
        submitter_ip=updated.submitter_ip,
        our_score=updated.our_score,
        expected_score=updated.expected_score,
        category=updated.category,
        explanation=updated.explanation,
        review_status=updated.review_status,
        reviewer_notes=updated.reviewer_notes,
    )
