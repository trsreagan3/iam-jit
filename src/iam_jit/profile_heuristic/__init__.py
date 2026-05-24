# Phase 1 of profile-generation design (docs/PROFILE-GENERATION-DESIGN.md
# §2.1 + §6). Lean-permissive heuristic action classifier.
"""Per-bouncer action-classification tables + pure-function classifier.

The classifier separates observed bouncer actions by their blast-radius
class so the Phase 3 lean-permissive heuristic can shape scope per-class
(read = broad, write/admin/destructive = tight). Pure data tables; no
LLM, no I/O, no policy_sentry dependency.

Per `[[bouncer-zero-llm-when-agent-in-loop]]` this is the deterministic
fallback's classification source. Per `[[ibounce-honest-positioning]]`
the tables are an initial intuition-derived pass; Phase 10's grading
corpus validates them — until then any marketing claim about accuracy
must qualify with "intuition-pass; calibration pending."

Per `[[calibration-quality-bar]]` the per-class prefix tables are
labelled "guess pending calibration" in `docs/PROFILE-GENERATION-DESIGN.md`
§9.

See `docs/PROFILE-GENERATION-DESIGN.md` for the full design rationale.
"""

from __future__ import annotations

from .classify import ActionClass, classify_action

__all__ = [
    "ActionClass",
    "classify_action",
]
