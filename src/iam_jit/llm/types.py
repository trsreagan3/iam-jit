"""Shared types for the pluggable LLM-backend abstraction.

The deterministic scorer remains canonical (per
[[scorer-is-ground-truth]]); a backend's `score_policy()` is purely
advisory — it contributes a short narrative summary and a small set of
risk-reduction suggestions for the approver-facing UI. A backend MUST
NOT mutate the deterministic risk score itself.

`ScoreContext` is the minimal envelope every backend receives. It is
intentionally a small, neutral dict-like dataclass — no AWS-specifics
leak in here, so future non-AWS reuses of the abstraction can adopt
the same shape.
"""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True)
class ScoreContext:
    """Minimal envelope handed to every backend's `score_policy`.

    `request_shape` mirrors the request payload the deterministic
    scorer already accepts; `deterministic_score` and
    `deterministic_factors` are forwarded so the LLM can reason
    about the same evidence the approver will see.

    Backends MUST NOT raise on unknown fields — they may receive
    additional keys in `extras` as the abstraction evolves.
    """

    request_shape: dict[str, Any]
    deterministic_score: int
    deterministic_factors: tuple[str, ...]
    description: str = ""
    extras: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class ScoreResponse:
    """A backend's contribution to a scoring call.

    `narrative` is a 1-3 sentence approver-facing summary. May be
    empty when the backend has nothing to add or failed silently.

    `suggestions` are short, actionable, single-sentence strings the
    requester could take to lower their risk; capped to 3 by the
    caller. Backends MUST NOT emit raw IAM action strings or policy
    JSON — those are caller-side concerns enforced downstream.

    `backend_name` is the registry name of the backend that produced
    the response (e.g. "anthropic"); helps the approver-facing UI
    surface which provider answered.

    `risk_signal` is an OPTIONAL advisory integer 1-10 indicating the
    backend's intuition. It is NEVER substituted for the deterministic
    score — the score the user sees is always the deterministic one.
    Surfaced only for calibration drift detection.
    """

    narrative: str = ""
    suggestions: tuple[str, ...] = ()
    backend_name: str = ""
    risk_signal: int | None = None

    def truncated_suggestions(self, limit: int = 3) -> list[str]:
        return [s for s in self.suggestions if isinstance(s, str) and s.strip()][:limit]
