"""Policy utility endpoint.

POST /api/v1/policy/analyze   One-shot risk scoring + narrowing for a policy
                              the caller already has in hand. Doesn't create
                              a request; useful for agents that want to
                              pre-flight a policy before submission, and for
                              IDE plugins that want inline risk scoring.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from .. import narrow, review
from ..middleware import current_user
from ..users_store import User

router = APIRouter(prefix="/api/v1/policy", tags=["policy"])


@router.post("/analyze")
def analyze(
    payload: dict[str, Any],
    _: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    policy = payload.get("policy")
    if not isinstance(policy, dict):
        raise HTTPException(status_code=400, detail="policy is required and must be an object")
    fake_request = {
        "spec": {
            "description": payload.get("description") or "",
            "access_type": payload.get("access_type") or "read-only",
            "task_intent": payload.get("task_intent") or {"services": [], "actions": []},
            "accounts": payload.get("accounts") or [],
            "duration": payload.get("duration") or {"duration_hours": 1},
            "policy": policy,
            "resource_constraints": payload.get("resource_constraints") or [],
        }
    }
    # Risk scoring is gated on LLM availability — in NoAI mode the deployer
    # opted out of AI feedback, so no score is returned. Narrowing questions
    # are deterministic and surface either way.
    review_block: dict[str, Any] | None = None
    if review.is_review_enabled():
        review_block = review.analyze_policy(policy, fake_request).to_dict()
    questions = [q.__dict__ for q in narrow.detect_broadness(policy, fake_request)]
    return {
        "review": review_block,
        "narrowing_questions": questions,
        "ai_enabled": review.is_review_enabled(),
    }
