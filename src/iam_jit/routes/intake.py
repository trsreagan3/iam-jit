"""Conversational intake API.

Stateless endpoint for agents to drive the intake conversation. Each
call passes the full conversation history; the response carries the
next question (or a complete signal + draft policy + prefill).

POST /api/v1/intake/turn
  body: { "conversation": [{"role": "...", "content": "..."}, ...] }
  resp: { "ask": "...", "fields": {...}, "complete": false, ... }
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import audit, bans as bans_mod, intake as intake_mod, prompt_injection, rate_limit as rate_limit_mod
from ..middleware import current_user
from ..users_store import User

router = APIRouter(prefix="/api/v1/intake", tags=["intake"])


class _ChatMessage(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str


class IntakeTurnRequest(BaseModel):
    conversation: list[_ChatMessage] = Field(default_factory=list)


@router.post("/turn")
def intake_turn(
    body: IntakeTurnRequest,
    actor: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    """Advance an intake conversation by one turn.

    The caller (agent or UI) is responsible for persisting the
    conversation between calls. This endpoint is fully stateless.

    Inputs are scanned for prompt-injection patterns. A high-confidence
    detection bans the calling user; a medium-confidence detection
    refuses the turn but doesn't ban (gives space for accidental
    matches in legitimate phrasing).
    """
    from .. import llm

    bans = bans_mod.get_default_store()
    if bans.is_banned(actor.id):
        raise HTTPException(
            status_code=403,
            detail="account suspended due to a detected policy violation",
        )

    decision = rate_limit_mod.get_default_limiter().check(
        actor.id, kind="intake-turn"
    )
    if decision.over_hard:
        try:
            audit.emit(
                actor=actor.id,
                kind="security.rate_limit_hard",
                summary=(
                    f"intake-turn rate-limit hard cap exceeded: "
                    f"{decision.count} in {decision.window_seconds}s"
                ),
                details={
                    "count": decision.count,
                    "hard_cap": decision.hard_cap,
                    "window_seconds": decision.window_seconds,
                },
            )
        except Exception:
            pass
        bans_mod.ban_for_injection(
            store=bans,
            user_id=actor.id,
            reasons=["chat-rate-ddos"],
            snippets=[
                f"{decision.count} intake calls in "
                f"{decision.window_seconds}s, exceeds hard cap"
            ],
            confidence="high",
            is_admin=actor.is_admin,
        )
        raise HTTPException(
            status_code=403,
            detail="account suspended for sustained excessive request rate",
        )
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                f"too many intake-turn calls; retry in "
                f"{decision.retry_after_seconds}s"
            ),
            headers={"Retry-After": str(max(1, decision.retry_after_seconds))},
        )

    # Only inspect user-role messages — assistant messages come from the
    # model itself and re-feeding them isn't an injection vector here.
    for m in body.conversation:
        if m.role != "user":
            continue
        verdict = prompt_injection.detect(m.content)
        if not verdict.detected:
            continue
        try:
            audit.emit(
                actor=actor.id,
                kind="security.prompt_injection",
                summary=f"prompt-injection detected in /intake/turn ({verdict.confidence})",
                details={
                    "reasons": verdict.reasons,
                    "snippets": verdict.snippets,
                    "confidence": verdict.confidence,
                },
            )
        except Exception:
            pass
        if verdict.confidence == "high":
            bans_mod.ban_for_injection(
                store=bans,
                user_id=actor.id,
                reasons=verdict.reasons,
                snippets=verdict.snippets,
                confidence=verdict.confidence,
                is_admin=actor.is_admin,
            )
            raise HTTPException(
                status_code=403,
                detail=(
                    "account suspended for a detected prompt-injection attempt"
                ),
            )
        raise HTTPException(
            status_code=400,
            detail="conversation contains text classified as a prompt-injection attempt",
        )

    backend = llm.get_backend()
    convo = [{"role": m.role, "content": m.content} for m in body.conversation]
    turn = intake_mod.take_turn(convo, backend)
    return turn.to_dict()
