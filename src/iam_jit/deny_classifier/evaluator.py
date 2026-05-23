"""Corpus-based test harness for measuring classifier accuracy.

Two modes:

  * `evaluate_offline(corpus)` — runs the classifier WITHOUT calling
    any LLM. Uses only the deterministic backstop (known-adversarial
    patterns) and a heuristic-based stand-in for the LLM judgment.
    Used in CI (no API keys required).

  * `evaluate_with_llm(corpus, backend=...)` — runs the real LLM call
    for each entry. Used by `make calibrate` / by humans during prompt
    tuning. Skipped in default CI (requires credentials).

Both return an `EvaluationResult` with per-entry verdicts + the
aggregate accuracy.

"Accuracy" is binary per entry: predicted classification matches
expected classification. Confidence is NOT scored — we only require
the LABEL to match. Advisory-action correctness is also reported as a
secondary metric (helpful for catching prompt-rubric drift even when
the classification label is right).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .calibration import load_corpus
from .classifier import (
    HIGH_CONFIDENCE_THRESHOLD,
    DenyEvent,
    _decide_advisory_action,
    _is_known_adversarial,
    classify_deny,
)

logger = logging.getLogger("iam_jit.deny_classifier.evaluator")


@dataclass
class EntryVerdict:
    entry_id: str
    expected_classification: str
    actual_classification: str
    expected_advisory: str
    actual_advisory: str
    classification_match: bool
    advisory_match: bool
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entry_id,
            "expected": self.expected_classification,
            "actual": self.actual_classification,
            "expected_advisory": self.expected_advisory,
            "actual_advisory": self.actual_advisory,
            "classification_match": self.classification_match,
            "advisory_match": self.advisory_match,
            "reasoning": self.reasoning,
        }


@dataclass
class EvaluationResult:
    verdicts: list[EntryVerdict] = field(default_factory=list)
    backend: str = ""

    @property
    def total(self) -> int:
        return len(self.verdicts)

    @property
    def classification_correct(self) -> int:
        return sum(1 for v in self.verdicts if v.classification_match)

    @property
    def advisory_correct(self) -> int:
        return sum(1 for v in self.verdicts if v.advisory_match)

    @property
    def classification_accuracy(self) -> float:
        return self.classification_correct / self.total if self.total else 0.0

    @property
    def advisory_accuracy(self) -> float:
        return self.advisory_correct / self.total if self.total else 0.0

    def summary(self) -> str:
        return (
            f"classifier evaluation: backend={self.backend or '(none)'} "
            f"n={self.total} classification={self.classification_correct}/{self.total} "
            f"({self.classification_accuracy:.1%}) advisory={self.advisory_correct}/{self.total} "
            f"({self.advisory_accuracy:.1%})"
        )


# ----- Offline heuristic stand-in ------------------------------------------


def _heuristic_classify(deny: DenyEvent) -> tuple[str, float, str]:
    """A small deterministic heuristic that imitates what a well-tuned
    LLM would do on the corpus. This is used by `evaluate_offline()`
    so the corpus accuracy test runs in CI without an LLM.

    Rules (deliberately simple — we are NOT trying to outsmart the LLM,
    just produce a baseline the test can lock in):

      1. If `_is_known_adversarial(action)` → adversarial / 0.94.
      2. If `operator_recent_pattern` mentions a substring of the
         resource OR the action's service prefix → legitimate / 0.85.
      3. Mutation actions on novel-but-non-adversarial resources →
         ambiguous / 0.55.
      4. Read-only actions in novel resources → legitimate / 0.75 if
         the action is a Describe*/Get*/List* AND no red flags;
         otherwise ambiguous / 0.55.
      5. Default → ambiguous / 0.5.

    "Adversarial-shaped" extras the LLM should also flag (this
    heuristic catches a subset; the real LLM should catch more):
      - Resource path contains "admin", "master", "root", "secret"
        AND operator_recent_pattern doesn't mention it
      - Unicode control characters in resource (RTL-override etc.)
      - IAM mutations (any iam:* that's not GET/LIST/DESCRIBE)
    """
    import re
    import unicodedata

    if _is_known_adversarial(deny.action):
        return (
            "appears_adversarial",
            0.94,
            "Action matches a known-adversarial pattern.",
        )

    action = deny.action.strip()
    resource = deny.resource or ""
    pattern = (deny.operator_recent_pattern or "").lower()

    # Unicode obfuscation in resource
    has_unicode_ctrl = any(
        unicodedata.category(c) in {"Cf", "Cc", "Cn"}
        for c in resource
        if ord(c) > 127
    )
    if has_unicode_ctrl:
        return (
            "ambiguous",
            0.6,
            "Resource contains Unicode control/format characters; "
            "possible obfuscation. Hold for operator inspection.",
        )

    # Sensitive-noun resource AND not in observed pattern
    sensitive_tokens = ("admin", "master", "root")
    resource_lower = resource.lower()
    if any(tok in resource_lower for tok in sensitive_tokens):
        if not any(tok in pattern for tok in sensitive_tokens):
            return (
                "appears_adversarial",
                0.88,
                "Resource path contains a sensitive token "
                "(admin/master/root) and is not in operator's pattern.",
            )

    # IAM mutations that aren't in the hard list — still treat as
    # cautious-ambiguous (e.g. iam:DeleteAccessKey for legit rotation)
    if action.lower().startswith("iam:"):
        verb = action.split(":", 1)[1].lower() if ":" in action else ""
        read_verbs = ("get", "list", "describe", "simulate")
        if not any(verb.startswith(v) for v in read_verbs):
            return (
                "ambiguous",
                0.65,
                "IAM mutation outside the hard adversarial list; "
                "operator should review.",
            )

    # Pattern match — does the operator_recent_pattern hint that the
    # action+resource is in the observed family?
    service = action.split(":", 1)[0].lower() if ":" in action else ""
    in_pattern = False
    if service and service in pattern:
        in_pattern = True
    # Resource family check: split off everything before the first
    # digit/separator; if the prefix appears in pattern, treat as fit
    family_match = re.match(r"^([A-Za-z][A-Za-z0-9-]*)[-/_]?", resource_lower)
    if family_match:
        prefix = family_match.group(1)
        if prefix and len(prefix) >= 4 and prefix in pattern:
            in_pattern = True

    is_read = False
    if ":" in action:
        verb = action.split(":", 1)[1].lower()
        is_read = (
            verb.startswith("get")
            or verb.startswith("list")
            or verb.startswith("describe")
            or verb.startswith("query")
            or verb.startswith("scan")
            or verb.startswith("batchget")
            or verb.startswith("head")
        )

    if in_pattern and is_read:
        return (
            "appears_legitimate",
            0.85,
            "Action+resource fits the operator's observed pattern.",
        )
    if in_pattern and not is_read:
        # Mutation in observed pattern: still ambiguous unless we have
        # strong family signal (the heuristic is conservative).
        return (
            "ambiguous",
            0.6,
            "Mutation action; partial pattern match. Hold for operator.",
        )
    if is_read:
        return (
            "ambiguous",
            0.55,
            "Read-only action but resource is outside observed pattern.",
        )
    return (
        "ambiguous",
        0.5,
        "Action and resource have no clear pattern signal.",
    )


def _classify_offline(deny_event: dict) -> dict:
    """Mirrors `classify_deny()` but uses the heuristic instead of an
    LLM. Applies the same backstops + advisory-action mapping."""
    ev = DenyEvent.from_dict(deny_event)
    is_adv = _is_known_adversarial(ev.action)
    classification, confidence, reasoning = _heuristic_classify(ev)
    if is_adv and classification != "appears_adversarial":
        classification = "appears_adversarial"
        confidence = max(confidence, 0.9)
    advisory = _decide_advisory_action(
        classification, confidence, is_adversarial_action=is_adv
    )
    return {
        "classification": classification,
        "confidence": confidence,
        "reasoning": reasoning,
        "advisory_action": advisory,
    }


# ----- Public evaluators ----------------------------------------------------


def evaluate_offline(corpus: list[dict] | None = None) -> EvaluationResult:
    """Evaluate the classifier in offline mode (no LLM). Used in CI.

    Returns the EvaluationResult; aggregate accuracy is in
    `.classification_accuracy`."""
    if corpus is None:
        corpus = load_corpus()
    result = EvaluationResult(backend="offline-heuristic")
    for entry in corpus:
        predicted = _classify_offline(entry["deny_event"])
        verdict = EntryVerdict(
            entry_id=entry["id"],
            expected_classification=entry["expected_classification"],
            actual_classification=predicted["classification"],
            expected_advisory=entry["expected_advisory_action"],
            actual_advisory=predicted["advisory_action"],
            classification_match=(
                predicted["classification"] == entry["expected_classification"]
            ),
            advisory_match=(
                predicted["advisory_action"] == entry["expected_advisory_action"]
            ),
            reasoning=predicted["reasoning"],
        )
        result.verdicts.append(verdict)
    return result


def evaluate_with_llm(
    corpus: list[dict] | None = None,
    *,
    backend: str | None = None,
    budget_usd: float = 0.001,
) -> EvaluationResult:
    """Evaluate the classifier against the LLM. Used by humans during
    prompt tuning. Requires LLM credentials in the environment."""
    if corpus is None:
        corpus = load_corpus()
    result = EvaluationResult(backend=backend or "auto")
    for entry in corpus:
        predicted = classify_deny(
            entry["deny_event"],
            backend=backend,
            budget_usd=budget_usd,
            _force_disable_tier_check=True,
        )
        verdict = EntryVerdict(
            entry_id=entry["id"],
            expected_classification=entry["expected_classification"],
            actual_classification=predicted["classification"],
            expected_advisory=entry["expected_advisory_action"],
            actual_advisory=predicted["advisory_action"],
            classification_match=(
                predicted["classification"] == entry["expected_classification"]
            ),
            advisory_match=(
                predicted["advisory_action"] == entry["expected_advisory_action"]
            ),
            reasoning=predicted.get("reasoning", ""),
        )
        result.verdicts.append(verdict)
    return result


if __name__ == "__main__":  # pragma: no cover
    import sys

    res = evaluate_offline()
    print(res.summary())
    for v in res.verdicts:
        flag = "OK" if v.classification_match else "MISS"
        print(
            f"  [{flag}] {v.entry_id}: expected={v.expected_classification} "
            f"got={v.actual_classification}"
        )
    sys.exit(0 if res.classification_accuracy >= 0.80 else 1)
