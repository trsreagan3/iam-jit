"""Calibration corpus for the deny classifier.

Per `[[calibration-quality-bar]]`: each labeled deny is hand-graded
against the rubric in `prompts.py`. The corpus is loaded by the
test suite (`test_classifier_corpus_accuracy_above_80_percent`) and
the evaluator (`evaluator.py`) for measuring drift.

The classifier MUST score >= 80% on this corpus to be considered
launch-ready per `[[deliberate-feature-completion]]`. If the bar
isn't met, surface honestly + don't ship — file v1.1 instead.

Adding new examples:
  1. Add to `corpus.json` with the same shape
  2. Re-run `pytest tests/deny_classifier -k corpus -v`
  3. If accuracy drops below 80%, tune the prompt (NOT the corpus)
     per `[[scorer-is-ground-truth]]`
"""

from __future__ import annotations

import json
import pathlib
from typing import Any


CORPUS_PATH = pathlib.Path(__file__).parent / "corpus.json"


def load_corpus() -> list[dict[str, Any]]:
    """Return the calibration entries as a list of dicts. Each entry:

      {
        "id": "<short-id>",
        "category": "legitimate|adversarial|ambiguous|edge",
        "deny_event": {
          "action": "...",
          "resource": "...",
          "agent_prompt_context": "...",
          "operator_recent_pattern": "...",
        },
        "expected_classification": "appears_legitimate" | "ambiguous" | "appears_adversarial",
        "expected_advisory_action": "easy-allow" | "hold" | "escalate",
        "rationale": "<why human graded this way>",
      }
    """
    with CORPUS_PATH.open() as fh:
        return json.load(fh)
