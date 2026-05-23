"""Main classifier: takes a deny event + recent context → returns
a structured classification + advisory action.

Composition rules (per `[[scorer-is-ground-truth]]`):
  * The classifier output is ADVISORY ONLY. It is consumed by Phase B
    (#402 structured deny response, #401 improve_profile, #403
    autopilot) to decide whether to "easy-allow" / "hold" / "escalate"
    AFTER the deterministic deny floor already fired.
  * If the deterministic scorer/profile says DENY but the classifier
    says "appears_legitimate", DENY STILL WINS — the classifier just
    helps the agent decide whether to suggest an `iam-jit profile
    allow` to the operator or to halt + escalate. The deny itself
    is not reversed.

Safety rails (encoded as invariants in `classify_deny()`):
  1. Known-adversarial actions with high confidence → ALWAYS escalate,
     regardless of operator's auto-allow config.
  2. Budget exceeded / LLM unavailable → safe fallback to
     `ambiguous` / `hold` (never crash the deny path).
  3. Free tier → classifier disabled with clear upgrade message.
  4. The classifier NEVER emits an `easy-allow` action for any
     known-adversarial pattern even at low confidence — the deny-list
     in `prompts.KNOWN_ADVERSARIAL_PATTERNS` is a hard backstop on
     the OUTPUT side, independent of the LLM's tag.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Literal

from .prompts import (
    FEW_SHOT_EXAMPLES,
    KNOWN_ADVERSARIAL_PATTERNS,
    SYSTEM_PROMPT,
    build_user_message,
)

logger = logging.getLogger("iam_jit.deny_classifier")


Classification = Literal["appears_legitimate", "ambiguous", "appears_adversarial"]
AdvisoryAction = Literal["easy-allow", "hold", "escalate"]


# ----- Public types ---------------------------------------------------------


@dataclass(frozen=True)
class DenyEvent:
    """One deny event the classifier examines.

    `action`         : e.g. "iam:CreateAccessKey", "s3:GetObject",
                       "DROP TABLE users", "kubectl delete namespace prod"
    `resource`       : ARN / bucket+key / SQL target / k8s resource string
    `agent_prompt_context`: short text excerpt of the agent's reasoning
                       that led to the request (provided by the
                       agent-facing 403 caller, optional)
    `operator_recent_pattern`: short text summary of the operator's
                       typical work shape (provided by Phase B
                       consumer from observed audit, optional)
    """

    action: str
    resource: str = "*"
    agent_prompt_context: str = ""
    operator_recent_pattern: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "DenyEvent":
        return cls(
            action=str(d.get("action") or ""),
            resource=str(d.get("resource") or "*"),
            agent_prompt_context=str(d.get("agent_prompt_context") or ""),
            operator_recent_pattern=str(d.get("operator_recent_pattern") or ""),
        )


@dataclass(frozen=True)
class ClassifierResult:
    """Output of `classify_deny()`. Always a complete, safe payload
    even when the underlying LLM call failed (in that case the result
    is the safe fallback: `ambiguous` / `hold` with `note` set)."""

    classification: Classification
    confidence: float
    reasoning: str
    advisory_action: AdvisoryAction
    cost_usd: float = 0.0
    backend: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "classification": self.classification,
            "confidence": round(float(self.confidence), 3),
            "reasoning": self.reasoning,
            "advisory_action": self.advisory_action,
            "cost_usd": round(float(self.cost_usd), 6),
            "backend": self.backend,
        }
        if self.note:
            out["note"] = self.note
        return out


# ----- Hard backstops -------------------------------------------------------


_ADV_PATTERNS_LOWER = tuple(p.lower() for p in KNOWN_ADVERSARIAL_PATTERNS)

# Patterns that match by substring containment in `action`. SQL / kubectl
# style patterns appear inside the action string (e.g. the action could
# be the full SQL statement when this is called from dbounce).
_ADV_SUBSTRING_PATTERNS = tuple(
    p.lower() for p in KNOWN_ADVERSARIAL_PATTERNS
    if " " in p or p.startswith("kubectl")
)


def _is_known_adversarial(action: str) -> bool:
    """Hard-coded match against `KNOWN_ADVERSARIAL_PATTERNS`. Used as a
    safety backstop on the OUTPUT side: even if the LLM somehow tags a
    known-adversarial action as legitimate, the classifier overrides
    to escalate. This is the deterministic floor on classifier output,
    parallel to the deterministic scorer floor on policy scoring."""
    if not action:
        return False
    norm = action.strip().lower()
    # Exact IAM action match (case-insensitive)
    if norm in _ADV_PATTERNS_LOWER:
        return True
    # Substring match for SQL / kubectl (e.g. action could be the full
    # statement when called from dbounce/kbouncer)
    for pat in _ADV_SUBSTRING_PATTERNS:
        if pat in norm:
            return True
    # Unbounded DELETE (any "DELETE FROM" without obvious WHERE)
    if re.search(r"\bdelete\s+from\b", norm) and not re.search(r"\bwhere\b", norm):
        return True
    return False


# ----- Confidence + action policy ------------------------------------------

HIGH_CONFIDENCE_THRESHOLD = 0.85
"""Above this, classifier opinion is treated as actionable. Below it
we lean conservative."""


def _decide_advisory_action(
    classification: Classification, confidence: float, *, is_adversarial_action: bool
) -> AdvisoryAction:
    """Map (classification, confidence, hard-pattern-match) to an
    advisory action. The function is pure + deterministic so callers
    can audit the decision matrix.

    Matrix:
      hard adversarial-action match  → escalate (ALWAYS)
      classification=adversarial AND conf>=0.85 → escalate
      classification=adversarial AND conf<0.85  → hold (ambiguous tier)
      classification=legitimate AND conf>=0.85  → easy-allow
      classification=legitimate AND conf<0.85   → hold
      classification=ambiguous (any confidence) → hold
    """
    if is_adversarial_action:
        return "escalate"
    if classification == "appears_adversarial":
        return "escalate" if confidence >= HIGH_CONFIDENCE_THRESHOLD else "hold"
    if classification == "appears_legitimate":
        return "easy-allow" if confidence >= HIGH_CONFIDENCE_THRESHOLD else "hold"
    return "hold"


# ----- Tier gating ----------------------------------------------------------


def _is_free_tier() -> bool:
    """Detect whether the current deployment is on the Free tier.

    Order of precedence:
      1. Explicit `IAM_JIT_TIER` env var (test / override hook)
      2. License-file derived tier via `iam_jit.license.current_tier()`
      3. Default: free
    """
    import os

    explicit = (os.environ.get("IAM_JIT_TIER") or "").strip().lower()
    if explicit:
        return explicit == "free"
    try:
        from iam_jit.license import current_tier
        return (current_tier() or "free").lower() == "free"
    except Exception:
        return True


# ----- LLM call -------------------------------------------------------------


def _safe_fallback(reason: str, *, backend: str = "") -> ClassifierResult:
    """Used when budget exceeded / LLM unavailable / parse failure.
    Per the brief: don't fail the deny path; just don't classify."""
    return ClassifierResult(
        classification="ambiguous",
        confidence=0.0,
        reasoning=(
            "Classifier unavailable; defaulting to ambiguous so the "
            "operator can decide. The deny itself stood."
        ),
        advisory_action="hold",
        cost_usd=0.0,
        backend=backend,
        note=reason,
    )


def _parse_llm_response(text: str) -> tuple[Classification, float, str] | None:
    """Parse the LLM's JSON output. Returns None on any deviation; the
    caller treats None as a safe-fallback trigger."""
    if not text:
        return None
    # Some models wrap JSON in code fences; strip them defensively
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try to extract the first JSON object found
        m = re.search(r"\{[^{}]*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict):
        return None

    cls_raw = (data.get("classification") or "").strip().lower()
    if cls_raw not in {"appears_legitimate", "ambiguous", "appears_adversarial"}:
        return None
    try:
        conf = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        return None
    conf = max(0.0, min(1.0, conf))
    reasoning = str(data.get("reasoning") or "").strip()[:500]
    if not reasoning:
        reasoning = "(no reasoning provided)"
    return cls_raw, conf, reasoning  # type: ignore[return-value]


def _estimate_cost(backend_module: Any, input_chars: int, output_chars: int) -> float:
    """Rough cost estimate. We charge by character / 4 to approximate
    tokens (the OpenAI/Anthropic rule of thumb). Used to honor
    `budget_usd` BEFORE the call returns; backends that can't estimate
    return 0.0 (treated as 'within budget')."""
    input_tokens = max(1, input_chars // 4)
    output_tokens = max(1, output_chars // 4)
    try:
        return float(backend_module.estimate_cost_per_1k(input_tokens, output_tokens))
    except Exception:
        return 0.0


def default_score_backend(*, preferred: str | None = None):
    """Shim around `iam_jit.llm.default_score_backend` so tests can
    monkey-patch THIS symbol (`iam_jit.deny_classifier.classifier.
    default_score_backend`) without reaching across module boundaries.
    Returns None when the llm package is unavailable."""
    try:
        from iam_jit.llm import default_score_backend as _impl
    except ImportError:
        return None
    try:
        return _impl(preferred=preferred)
    except Exception as e:
        logger.warning("deny_classifier: default_score_backend raised: %s", e)
        return None


def get_score_backend(name: str):
    """Shim around `iam_jit.llm.get_score_backend` with the same
    motivation as `default_score_backend` above."""
    try:
        from iam_jit.llm import get_score_backend as _impl
    except ImportError:
        return None
    return _impl(name)


def _llm_classify(
    deny_event: DenyEvent,
    recent_context: dict,
    *,
    backend_name: str | None,
    budget_usd: float,
) -> ClassifierResult:
    """Call the LLM with the classifier prompt; return a ClassifierResult.

    On any failure (no backend / backend unavailable / parse fail /
    budget exceeded), returns the safe fallback.
    """
    # Resolve backend
    backend = None
    if backend_name:
        try:
            backend = get_score_backend(backend_name)
        except ValueError as e:
            logger.warning("deny_classifier: backend %s unknown: %s", backend_name, e)
            backend = None
        if backend is not None and not backend.is_available():
            logger.info(
                "deny_classifier: backend %s not available; trying autoselect",
                backend_name,
            )
            backend = None
    if backend is None:
        backend = default_score_backend(preferred=backend_name)
    if backend is None:
        return _safe_fallback("no LLM backend available")

    # Build the prompt and budget-check BEFORE calling
    user_msg = build_user_message(
        {
            "action": deny_event.action,
            "resource": deny_event.resource,
            "agent_prompt_context": deny_event.agent_prompt_context,
            "operator_recent_pattern": deny_event.operator_recent_pattern,
        },
        recent_context,
    )
    est_input_chars = len(SYSTEM_PROMPT) + len(user_msg)
    est_output_chars = 256  # JSON response is small
    estimated = _estimate_cost(backend, est_input_chars, est_output_chars)
    if budget_usd > 0 and estimated > budget_usd:
        logger.info(
            "deny_classifier: estimated cost $%.6f exceeds budget $%.6f",
            estimated, budget_usd,
        )
        return _safe_fallback(
            f"estimated cost ${estimated:.6f} exceeds budget ${budget_usd:.6f}",
            backend=getattr(backend, "name", ""),
        )

    # Call the LLM. We use the chat() primitive on the underlying core
    # backend (Anthropic / Bedrock / Ollama / OpenAI). The registered
    # `_b_*` modules in iam_jit.llm.backends expose a `score_policy()`
    # surface oriented at the policy-scoring use case; for the
    # classifier we want a generic chat call, so we use the core
    # backend the module wraps when available, and otherwise fall back
    # to the module's `score_policy` envelope.
    text = _call_backend_chat(backend, SYSTEM_PROMPT, user_msg)
    if not text:
        return _safe_fallback(
            "LLM returned empty response", backend=getattr(backend, "name", "")
        )

    parsed = _parse_llm_response(text)
    if parsed is None:
        return _safe_fallback(
            "LLM response did not parse as expected JSON",
            backend=getattr(backend, "name", ""),
        )
    classification, confidence, reasoning = parsed

    # Hard backstop: if the action matches a known-adversarial pattern,
    # we override classification to adversarial regardless of what the
    # LLM said. This is the deterministic floor on classifier output.
    is_adv = _is_known_adversarial(deny_event.action)
    if is_adv and classification != "appears_adversarial":
        logger.info(
            "deny_classifier: hard-backstop override "
            "(LLM said %s, action %s matches known-adversarial)",
            classification, deny_event.action,
        )
        classification = "appears_adversarial"
        confidence = max(confidence, 0.9)
        reasoning = (
            f"[override: action matches known-adversarial pattern] {reasoning}"
        )

    advisory = _decide_advisory_action(
        classification, confidence, is_adversarial_action=is_adv
    )

    actual_cost = _estimate_cost(backend, est_input_chars, len(text))

    return ClassifierResult(
        classification=classification,
        confidence=confidence,
        reasoning=reasoning,
        advisory_action=advisory,
        cost_usd=actual_cost,
        backend=getattr(backend, "name", ""),
    )


def _call_backend_chat(backend_module: Any, system_prompt: str, user_msg: str) -> str:
    """Invoke chat on the underlying core backend.

    The `iam_jit.llm.backends.*` modules are oriented at policy
    scoring; they delegate to a core backend class (e.g.
    `_CoreAnthropicBackend`). We borrow the same core class via the
    module's `_build_backend()` helper when present; otherwise we fall
    back to using `chat()` on a fresh core backend selected by env.
    """
    builder = getattr(backend_module, "_build_backend", None)
    if builder is not None:
        try:
            core = builder()
        except Exception as e:
            logger.warning(
                "deny_classifier: could not build core backend for %s: %s",
                getattr(backend_module, "name", "?"), e,
            )
            return ""
    else:
        try:
            from iam_jit.llm import get_backend
            core = get_backend()
        except Exception as e:
            logger.warning("deny_classifier: get_backend() failed: %s", e)
            return ""

    chat = getattr(core, "chat", None)
    if chat is None:
        return ""
    try:
        return chat(
            system_prompt=system_prompt,
            messages=[{"role": "user", "content": user_msg}],
        ) or ""
    except Exception as e:
        logger.warning("deny_classifier: chat() raised: %s", e)
        return ""


# ----- Public entry point ---------------------------------------------------


def classify_deny(
    deny_event: dict | DenyEvent,
    *,
    recent_context: dict | None = None,
    backend: str | None = None,
    budget_usd: float = 0.001,
    _force_disable_tier_check: bool = False,
) -> dict[str, Any]:
    """Classify a deny event. Always returns a dict matching
    `ClassifierResult.to_dict()`.

    Per the brief:
      * `appears_legitimate` / `ambiguous` / `appears_adversarial`
        with confidence 0.0-1.0
      * advisory_action `easy-allow` / `hold` / `escalate`
      * `cost_usd` actual measured cost (0.0 for fallback / Free tier)

    Free tier: returns `ambiguous` / `hold` with a `note` field
    indicating the classifier is disabled.

    Pro+ tier: actually runs the LLM call.

    The deterministic floor on `KNOWN_ADVERSARIAL_PATTERNS` overrides
    the LLM's tag if the LLM mistakenly labels a known-bad action as
    legitimate.

    `budget_usd` of 0 means "no budget cap" (run the call regardless).
    Negative is treated as 0 (caller mistake).
    """
    if isinstance(deny_event, dict):
        ev = DenyEvent.from_dict(deny_event)
    else:
        ev = deny_event
    ctx = recent_context or {}
    budget = max(0.0, float(budget_usd))

    # Hard backstop: even on free tier we want adversarial-pattern
    # matches to escalate (the deterministic deny still wins; the
    # classifier just helps the agent decide). This protects the
    # auto-allow-if-easy path from being silently misled.
    is_adv = _is_known_adversarial(ev.action)

    if not _force_disable_tier_check and _is_free_tier():
        if is_adv:
            # Even on Free tier, surface the known-adversarial signal.
            # Operators MUST be told to escalate; the deterministic
            # backstop is independent of tier.
            return ClassifierResult(
                classification="appears_adversarial",
                confidence=0.9,
                reasoning=(
                    "Action matches a known-adversarial pattern "
                    "(deterministic backstop). Halt + escalate."
                ),
                advisory_action="escalate",
                cost_usd=0.0,
                backend="",
                note=(
                    "classifier disabled on free tier; deterministic "
                    "adversarial-pattern backstop fired"
                ),
            ).to_dict()
        return ClassifierResult(
            classification="ambiguous",
            confidence=0.0,
            reasoning=(
                "LLM classification disabled on Free tier. Upgrade to Pro "
                "to enable AI-assisted deny classification."
            ),
            advisory_action="hold",
            cost_usd=0.0,
            backend="",
            note="classifier disabled on free tier; upgrade to enable",
        ).to_dict()

    result = _llm_classify(
        ev, ctx, backend_name=backend, budget_usd=budget,
    )

    # One more pass of the safety rail just in case _llm_classify took
    # the safe-fallback path AND the action is adversarial — promote.
    if (
        result.advisory_action != "escalate"
        and _is_known_adversarial(ev.action)
    ):
        result = ClassifierResult(
            classification="appears_adversarial",
            confidence=max(result.confidence, 0.9),
            reasoning=(
                "[override: action matches known-adversarial pattern] "
                + result.reasoning
            ),
            advisory_action="escalate",
            cost_usd=result.cost_usd,
            backend=result.backend,
            note=result.note,
        )

    return result.to_dict()
