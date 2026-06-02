# ADOPT-7 / #721 — recognizer scan/redact tests that REQUIRE the
# presidio-analyzer optional extra. Skipped cleanly in CI (which does not
# install the extra) via the module-level importorskip; run locally where
# it IS installed.
from __future__ import annotations

import pytest

from iam_jit.pii import HONESTY_CAVEAT, parse_config

pytest.importorskip("presidio_analyzer")


def _scan(entities, text, **kw):
    from iam_jit.pii.recognizers import scan_text

    cfg = parse_config({"schema_version": 1, "entities": entities})
    return scan_text(text, cfg, **kw)


def test_pattern_entity_detected_and_redacted() -> None:
    res = _scan(
        [{"name": "EMP_BADGE", "patterns": [r"EMP-\d{5}"], "score": 0.8}],
        "my badge is EMP-12345 today",
    )
    assert len(res.matches) == 1
    m = res.matches[0]
    assert m.entity == "EMP_BADGE"
    assert m.text == "EMP-12345"
    assert "EMP-12345" not in res.redacted
    assert "[REDACTED:EMP_BADGE]" in res.redacted


def test_deny_list_entity_detected_and_redacted() -> None:
    res = _scan(
        [{"name": "PROJECT_CODE", "deny_list": ["Project Bluefin"]}],
        "we shipped Project Bluefin last week",
    )
    assert any(m.entity == "PROJECT_CODE" for m in res.matches)
    assert "Project Bluefin" not in res.redacted
    assert "[REDACTED:PROJECT_CODE]" in res.redacted


def test_context_word_boosts_score() -> None:
    entity = {
        "name": "CUSTOMER_ACCT",
        "patterns": [r"\b\d{8}\b"],
        "context": ["account"],
        "score": 0.3,
    }
    with_ctx = _scan([entity], "the account 12345678 is active")
    without_ctx = _scan([entity], "random number 12345678 here")
    assert with_ctx.matches[0].score > without_ctx.matches[0].score
    assert with_ctx.matches[0].score >= 0.6


def test_threshold_filters_low_confidence() -> None:
    entity = {"name": "WEAK", "patterns": [r"\b\d{8}\b"], "score": 0.3}
    res = _scan([entity], "number 12345678", threshold=0.5)
    assert res.matches == ()
    assert "12345678" in res.redacted


def test_multiple_entities_one_text() -> None:
    res = _scan(
        [
            {"name": "EMP_BADGE", "patterns": [r"EMP-\d{5}"], "score": 0.8},
            {"name": "PROJECT_CODE", "deny_list": ["Bluefin"]},
        ],
        "EMP-99999 works on Bluefin",
    )
    kinds = {m.entity for m in res.matches}
    assert kinds == {"EMP_BADGE", "PROJECT_CODE"}
    assert "EMP-99999" not in res.redacted
    assert "Bluefin" not in res.redacted


def test_scan_result_caveat_present() -> None:
    res = _scan([{"name": "X", "patterns": ["a"]}], "aaa")
    assert res.caveat == HONESTY_CAVEAT


def test_build_recognizers_maps_to_presidio_types() -> None:
    from iam_jit.pii.recognizers import build_recognizers

    cfg = parse_config(
        {
            "schema_version": 1,
            "entities": [
                {"name": "EMP_BADGE", "patterns": [r"EMP-\d{5}"]},
                {"name": "PROJECT_CODE", "deny_list": ["Bluefin"]},
            ],
        }
    )
    recs = build_recognizers(cfg)
    assert len(recs) == 2
    from presidio_analyzer import PatternRecognizer

    assert all(isinstance(r, PatternRecognizer) for r in recs)
    entities = {r.supported_entities[0] for r in recs}
    assert entities == {"EMP_BADGE", "PROJECT_CODE"}


def test_no_match_returns_text_unchanged() -> None:
    res = _scan([{"name": "EMP_BADGE", "patterns": [r"EMP-\d{5}"]}],
                "nothing sensitive here")
    assert res.matches == ()
    assert res.redacted == "nothing sensitive here"
