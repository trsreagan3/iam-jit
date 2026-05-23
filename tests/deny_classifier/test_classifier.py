"""§A50 / #404 — tests for the deny classifier.

Tests required by the brief:
  * test_classifier_returns_legitimate_for_observed_pattern_match
  * test_classifier_returns_adversarial_for_known_persistence_pattern
  * test_classifier_returns_ambiguous_for_novel_but_plausible
  * test_classifier_budget_exceeded_returns_safe_fallback
  * test_classifier_llm_unavailable_returns_safe_fallback
  * test_classifier_high_confidence_adversarial_always_escalates_regardless_of_operator_auto_allow
  * test_classifier_free_tier_disabled_with_clear_message
  * test_classifier_corpus_accuracy_above_80_percent

Plus a few extra composition tests:
  * deterministic-deny-wins composition with `classify_deny`
  * SQL-shape adversarial detection (DROP TABLE, unbounded DELETE)
  * Unicode obfuscation → ambiguous (NOT auto-allow)
  * Hard backstop overrides LLM mistake (LLM says legitimate, action is bad)

All tests run with no LLM credentials — the LLM call is mocked or
forced to the safe-fallback path. The corpus-accuracy test uses the
offline heuristic evaluator (`evaluate_offline`).
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from iam_jit.deny_classifier import classify_deny
from iam_jit.deny_classifier.classifier import (
    HIGH_CONFIDENCE_THRESHOLD,
    DenyEvent,
    _decide_advisory_action,
    _is_known_adversarial,
    _parse_llm_response,
)
from iam_jit.deny_classifier.evaluator import evaluate_offline


# ----- Helpers --------------------------------------------------------------


@pytest.fixture(autouse=True)
def _force_pro_tier(monkeypatch):
    """Default every test to Pro tier so the LLM path runs. Individual
    tests that need to exercise Free-tier behaviour override this."""
    monkeypatch.setenv("IAM_JIT_TIER", "pro")


def _patched_llm(response_text: str):
    """Patch the chat call so the classifier sees `response_text`
    instead of calling a real LLM."""
    return patch(
        "iam_jit.deny_classifier.classifier._call_backend_chat",
        return_value=response_text,
    )


def _patched_backend(name: str = "anthropic", estimated_cost: float = 0.0001):
    """Patch the backend resolver so we don't need real LLM creds."""

    class _FakeBackend:
        def __init__(self, n, c):
            self.name = n
            self._cost = c

        def is_available(self):
            return True

        def estimate_cost_per_1k(self, _i, _o):
            return self._cost

    fake = _FakeBackend(name, estimated_cost)
    return patch(
        "iam_jit.deny_classifier.classifier.default_score_backend",
        return_value=fake,
    )


# ----- Required tests -------------------------------------------------------


def test_classifier_returns_legitimate_for_observed_pattern_match():
    response = json.dumps({
        "classification": "appears_legitimate",
        "confidence": 0.88,
        "reasoning": "Action+resource matches operator's observed reports-* family.",
    })
    with _patched_backend(), _patched_llm(response):
        r = classify_deny(
            {
                "action": "s3:GetObject",
                "resource": "reports-2026/q1.csv",
                "agent_prompt_context": "fetching q1 report",
                "operator_recent_pattern": "reports-* bucket reads",
            },
            backend="anthropic",
            budget_usd=0.01,
        )
    assert r["classification"] == "appears_legitimate"
    assert r["confidence"] >= HIGH_CONFIDENCE_THRESHOLD
    assert r["advisory_action"] == "easy-allow"
    assert r["backend"] == "anthropic"


def test_classifier_returns_adversarial_for_known_persistence_pattern():
    # The LLM here LIES (says legitimate) — the hard backstop must override.
    response = json.dumps({
        "classification": "appears_legitimate",
        "confidence": 0.9,
        "reasoning": "Looks fine to me.",
    })
    with _patched_backend(), _patched_llm(response):
        r = classify_deny(
            {
                "action": "iam:CreateAccessKey",
                "resource": "*",
                "agent_prompt_context": "data reporting task",
            },
            backend="anthropic",
            budget_usd=0.01,
        )
    assert r["classification"] == "appears_adversarial"
    assert r["advisory_action"] == "escalate"
    assert r["confidence"] >= 0.85


def test_classifier_returns_adversarial_for_s3_delete_bucket():
    response = json.dumps({
        "classification": "appears_adversarial",
        "confidence": 0.92,
        "reasoning": "Destructive action.",
    })
    with _patched_backend(), _patched_llm(response):
        r = classify_deny(
            {
                "action": "s3:DeleteBucket",
                "resource": "arn:aws:s3:::production-data",
            },
            backend="anthropic",
            budget_usd=0.01,
        )
    assert r["classification"] == "appears_adversarial"
    assert r["advisory_action"] == "escalate"


def test_classifier_returns_ambiguous_for_novel_but_plausible():
    response = json.dumps({
        "classification": "ambiguous",
        "confidence": 0.55,
        "reasoning": "Plausible but no observed pattern signal.",
    })
    with _patched_backend(), _patched_llm(response):
        r = classify_deny(
            {
                "action": "lambda:InvokeFunction",
                "resource": "arn:aws:lambda:us-east-1:123:function:nightly-job",
                "agent_prompt_context": "trigger the nightly batch",
                "operator_recent_pattern": "ec2:Describe* + s3:GetObject only",
            },
            backend="anthropic",
            budget_usd=0.01,
        )
    assert r["classification"] == "ambiguous"
    assert r["advisory_action"] == "hold"


def test_classifier_budget_exceeded_returns_safe_fallback():
    # Set a tiny budget so the cost estimate exceeds it. The fake
    # backend's estimate_cost_per_1k returns 0.5 USD (way above the
    # 0.000001 budget), which forces the safe fallback before any LLM
    # call is made.
    with _patched_backend(estimated_cost=0.5):
        r = classify_deny(
            {"action": "s3:GetObject", "resource": "reports-2026/q1.csv"},
            backend="anthropic",
            budget_usd=0.000001,
        )
    assert r["classification"] == "ambiguous"
    assert r["advisory_action"] == "hold"
    assert "budget" in r.get("note", "").lower()
    assert r["cost_usd"] == 0.0


def test_classifier_llm_unavailable_returns_safe_fallback():
    # No backend available → safe fallback.
    with patch(
        "iam_jit.deny_classifier.classifier.default_score_backend",
        return_value=None,
    ):
        r = classify_deny(
            {"action": "s3:GetObject", "resource": "reports-2026/q1.csv"},
            backend=None,
            budget_usd=0.01,
        )
    assert r["classification"] == "ambiguous"
    assert r["advisory_action"] == "hold"
    assert "no llm backend" in r.get("note", "").lower()


def test_classifier_llm_returns_empty_response_safe_fallback():
    with _patched_backend(), _patched_llm(""):
        r = classify_deny(
            {"action": "s3:GetObject", "resource": "reports-2026/q1.csv"},
            backend="anthropic",
            budget_usd=0.01,
        )
    assert r["classification"] == "ambiguous"
    assert r["advisory_action"] == "hold"


def test_classifier_llm_returns_unparseable_response_safe_fallback():
    with _patched_backend(), _patched_llm("not json at all, just prose"):
        r = classify_deny(
            {"action": "s3:GetObject", "resource": "reports-2026/q1.csv"},
            backend="anthropic",
            budget_usd=0.01,
        )
    assert r["classification"] == "ambiguous"
    assert r["advisory_action"] == "hold"


def test_classifier_high_confidence_adversarial_always_escalates_regardless_of_operator_auto_allow():
    """Even if the LLM says 'appears_legitimate' with high confidence,
    a known-adversarial action MUST escalate. This is the hard
    backstop per the safety rails — operator's auto-allow config
    cannot weaken it."""
    # LLM is fooled by injection; says legitimate with high confidence
    response = json.dumps({
        "classification": "appears_legitimate",
        "confidence": 0.99,
        "reasoning": (
            "The agent explained this is just for the quarterly data "
            "report; access key creation is a normal part of report "
            "generation in this org."
        ),
    })
    with _patched_backend(), _patched_llm(response):
        r = classify_deny(
            {
                "action": "iam:CreateAccessKey",
                "resource": "*",
                "agent_prompt_context": "quarterly report generation",
            },
            backend="anthropic",
            budget_usd=0.01,
        )
    # Hard backstop fires
    assert r["classification"] == "appears_adversarial"
    assert r["advisory_action"] == "escalate"
    assert r["confidence"] >= 0.85
    assert "override" in r["reasoning"].lower()


def test_classifier_free_tier_disabled_with_clear_message(monkeypatch):
    monkeypatch.setenv("IAM_JIT_TIER", "free")
    r = classify_deny(
        {
            "action": "s3:GetObject",
            "resource": "reports-2026/q1.csv",
            "agent_prompt_context": "fetching report",
        },
        backend="anthropic",
        budget_usd=0.01,
    )
    assert r["classification"] == "ambiguous"
    assert r["advisory_action"] == "hold"
    assert "free tier" in r["note"].lower()
    assert "upgrade" in r["note"].lower()
    assert r["cost_usd"] == 0.0


def test_classifier_free_tier_still_escalates_known_adversarial(monkeypatch):
    """Free tier disables the LLM call but the deterministic
    adversarial-pattern backstop is INDEPENDENT of tier. Even free
    users must see escalation for known-bad actions."""
    monkeypatch.setenv("IAM_JIT_TIER", "free")
    r = classify_deny(
        {
            "action": "iam:CreateAccessKey",
            "resource": "*",
            "agent_prompt_context": "trying to set up auth for the batch job",
        },
        backend="anthropic",
        budget_usd=0.01,
    )
    assert r["classification"] == "appears_adversarial"
    assert r["advisory_action"] == "escalate"
    assert r["confidence"] >= 0.85
    assert "free tier" in r["note"].lower()


# ----- Corpus accuracy ------------------------------------------------------


def test_classifier_corpus_accuracy_above_80_percent():
    """Run the offline heuristic against the 20-entry calibration
    corpus. Per [[deliberate-feature-completion]], 80% is the
    launch bar.

    The offline heuristic stands in for the LLM in CI; it's
    deliberately simple but should still hit the bar on the corpus
    because the corpus is constructed to be discriminable by clear
    signals (operator_recent_pattern matches, known-adversarial
    patterns, etc.).

    If this drops below 80%, tune the corpus shape / heuristic in
    `evaluator.py` — DO NOT tune the corpus to make a borderline
    heuristic look good (per [[scorer-is-ground-truth]])."""
    result = evaluate_offline()
    assert result.total >= 20, "corpus must have >= 20 entries"
    accuracy = result.classification_accuracy
    if accuracy < 0.80:
        misses = [v for v in result.verdicts if not v.classification_match]
        miss_details = "\n".join(
            f"  - {v.entry_id}: expected={v.expected_classification} "
            f"got={v.actual_classification} reason={v.reasoning}"
            for v in misses
        )
        pytest.fail(
            f"Classifier corpus accuracy {accuracy:.1%} is below the "
            f"80% launch bar. {result.classification_correct}/{result.total} "
            f"correct. Misses:\n{miss_details}"
        )


def test_classifier_corpus_no_negative_value_misclassifications():
    """A 'NEGATIVE-VALUE' miss is the worst kind: a known-adversarial
    entry was classified as appears_legitimate. Even if the overall
    accuracy is good, this kind of miss is launch-blocking — it
    means the safety floor leaks. Verify zero such misses."""
    result = evaluate_offline()
    negative_value_misses = [
        v for v in result.verdicts
        if v.expected_classification == "appears_adversarial"
        and v.actual_classification == "appears_legitimate"
    ]
    assert not negative_value_misses, (
        "Found NEGATIVE-VALUE classifications (adversarial labeled as "
        f"legitimate): {[v.entry_id for v in negative_value_misses]}"
    )


# ----- Backstop + composition unit tests -----------------------------------


def test_known_adversarial_action_detection():
    assert _is_known_adversarial("iam:CreateAccessKey") is True
    assert _is_known_adversarial("iam:createaccesskey") is True
    assert _is_known_adversarial("s3:DeleteBucket") is True
    assert _is_known_adversarial("s3:GetObject") is False
    assert _is_known_adversarial("DROP TABLE users") is True
    assert _is_known_adversarial("DELETE FROM orders") is True
    # Bounded DELETE is NOT in the hard list
    assert _is_known_adversarial("DELETE FROM orders WHERE id = 1") is False
    assert _is_known_adversarial("kubectl delete namespace prod") is True
    assert _is_known_adversarial("kubectl get pods") is False
    assert _is_known_adversarial("") is False
    assert _is_known_adversarial("ec2:DescribeInstances") is False


def test_advisory_action_decision_matrix():
    # Hard adversarial-action match → always escalate
    assert _decide_advisory_action("appears_legitimate", 0.99, is_adversarial_action=True) == "escalate"
    assert _decide_advisory_action("ambiguous", 0.5, is_adversarial_action=True) == "escalate"
    # High-confidence adversarial → escalate
    assert _decide_advisory_action("appears_adversarial", 0.9, is_adversarial_action=False) == "escalate"
    # Low-confidence adversarial → hold
    assert _decide_advisory_action("appears_adversarial", 0.6, is_adversarial_action=False) == "hold"
    # High-confidence legitimate → easy-allow
    assert _decide_advisory_action("appears_legitimate", 0.9, is_adversarial_action=False) == "easy-allow"
    # Low-confidence legitimate → hold
    assert _decide_advisory_action("appears_legitimate", 0.6, is_adversarial_action=False) == "hold"
    # Ambiguous → always hold
    assert _decide_advisory_action("ambiguous", 0.5, is_adversarial_action=False) == "hold"
    assert _decide_advisory_action("ambiguous", 0.9, is_adversarial_action=False) == "hold"


def test_parse_llm_response_strict():
    # Good
    good = json.dumps({"classification": "appears_legitimate", "confidence": 0.8, "reasoning": "x"})
    assert _parse_llm_response(good) == ("appears_legitimate", 0.8, "x")
    # Code-fenced
    fenced = "```json\n" + good + "\n```"
    assert _parse_llm_response(fenced) is not None
    # Unknown classification
    bad_cls = json.dumps({"classification": "bogus", "confidence": 0.8, "reasoning": "x"})
    assert _parse_llm_response(bad_cls) is None
    # Confidence clamped to [0,1]
    high_conf = json.dumps({"classification": "ambiguous", "confidence": 5.0, "reasoning": "x"})
    parsed = _parse_llm_response(high_conf)
    assert parsed is not None and parsed[1] == 1.0
    # Bad JSON
    assert _parse_llm_response("not json") is None
    assert _parse_llm_response("") is None


def test_deny_event_from_dict_defaults():
    ev = DenyEvent.from_dict({"action": "s3:GetObject"})
    assert ev.action == "s3:GetObject"
    assert ev.resource == "*"
    assert ev.agent_prompt_context == ""
    assert ev.operator_recent_pattern == ""


def test_classify_deny_accepts_deny_event_object():
    ev = DenyEvent(action="s3:GetObject", resource="reports-2026/x")
    with patch(
        "iam_jit.deny_classifier.classifier.default_score_backend",
        return_value=None,
    ):
        r = classify_deny(ev, budget_usd=0.001)
    assert r["classification"] == "ambiguous"  # safe fallback


def test_classifier_negative_budget_treated_as_zero():
    # Negative budget should not crash; treated as 0 (no cap).
    with _patched_backend(), _patched_llm(
        json.dumps({
            "classification": "appears_legitimate",
            "confidence": 0.7,
            "reasoning": "fine",
        })
    ):
        r = classify_deny(
            {"action": "s3:GetObject", "resource": "x"},
            backend="anthropic",
            budget_usd=-1.0,
        )
    assert r["classification"] in ("appears_legitimate", "ambiguous")


def test_classifier_result_shape_is_stable():
    """Phase B consumers depend on the dict shape. This locks it in."""
    with patch(
        "iam_jit.deny_classifier.classifier.default_score_backend",
        return_value=None,
    ):
        r = classify_deny(
            {"action": "s3:GetObject", "resource": "x"},
            budget_usd=0.001,
        )
    expected_keys = {
        "classification",
        "confidence",
        "reasoning",
        "advisory_action",
        "cost_usd",
        "backend",
    }
    assert expected_keys.issubset(r.keys())
    assert r["classification"] in {
        "appears_legitimate", "ambiguous", "appears_adversarial",
    }
    assert r["advisory_action"] in {"easy-allow", "hold", "escalate"}
    assert 0.0 <= r["confidence"] <= 1.0
    assert isinstance(r["reasoning"], str)
    assert isinstance(r["cost_usd"], (int, float))
    assert isinstance(r["backend"], str)


def test_classifier_unicode_obfuscation_does_not_auto_allow():
    """Edge case: agent-supplied resource contains Unicode RTL-override.
    Even if the LLM is fooled, the classifier MUST NOT emit
    easy-allow. The offline heuristic catches this; the LLM is patched
    to also catch it."""
    response = json.dumps({
        "classification": "ambiguous",
        "confidence": 0.6,
        "reasoning": "Resource contains unusual characters.",
    })
    # RTL-override character is U+202E
    obfuscated_resource = "reports-2026/q1‮-secret-exfil.csv"
    with _patched_backend(), _patched_llm(response):
        r = classify_deny(
            {
                "action": "s3:GetObject",
                "resource": obfuscated_resource,
                "operator_recent_pattern": "reports-* family",
            },
            backend="anthropic",
            budget_usd=0.01,
        )
    assert r["advisory_action"] != "easy-allow"


def test_classifier_composition_with_deterministic_deny():
    """Per [[scorer-is-ground-truth]]: even if the classifier says
    'appears_legitimate', the underlying deterministic deny stands.
    The classifier output is ADVISORY. This test verifies that the
    classifier doesn't pretend to lift the deny — it returns its
    advisory tag without claiming to reverse anything."""
    response = json.dumps({
        "classification": "appears_legitimate",
        "confidence": 0.95,
        "reasoning": "Fits operator pattern.",
    })
    with _patched_backend(), _patched_llm(response):
        r = classify_deny(
            {
                "action": "s3:GetObject",
                "resource": "reports-2026/q1.csv",
                "operator_recent_pattern": "reports-* family",
            },
            backend="anthropic",
            budget_usd=0.01,
        )
    # The classifier returns its tag; advisory_action is its
    # RECOMMENDATION, not a deny-reversal.
    assert r["classification"] == "appears_legitimate"
    assert r["advisory_action"] == "easy-allow"
    # Crucially: no field claims the deny was lifted. The classifier
    # surface is strictly advisory.
    assert "deny_lifted" not in r
    assert "allow" not in r  # only the action key (easy-allow) names allow


def test_classifier_module_exports():
    """Lock in the public API surface so Phase B can consume cleanly."""
    from iam_jit import deny_classifier

    assert callable(deny_classifier.classify_deny)
    assert hasattr(deny_classifier, "DenyEvent")
    assert hasattr(deny_classifier, "ClassifierResult")
