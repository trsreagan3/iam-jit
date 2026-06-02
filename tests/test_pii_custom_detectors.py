# ADOPT-7 / #721 — tests for the custom PII detector layer.
"""Tests split into two groups:

* config validation + optional-dep no-op tests run EVERYWHERE (incl. CI
  without the presidio extra);
* recognizer scan/redact tests are guarded with
  ``pytest.importorskip("presidio_analyzer")`` so they skip cleanly in
  CI (which doesn't install the optional extra) and run locally where it
  IS installed.
"""

from __future__ import annotations

import json

import pytest

from iam_jit.pii import (
    HONESTY_CAVEAT,
    PiiConfigError,
    PresidioUnavailableError,
    load_config,
    parse_config,
)


# ---------------------------------------------------------------------------
# Config validation — no presidio required
# ---------------------------------------------------------------------------


def test_parse_minimal_pattern_entity() -> None:
    cfg = parse_config(
        {
            "schema_version": 1,
            "entities": [{"name": "EMP_BADGE", "patterns": [r"EMP-\d{5}"]}],
        }
    )
    assert cfg.schema_version == 1
    assert cfg.entity_names == ("EMP_BADGE",)
    e = cfg.entities[0]
    assert e.patterns == (r"EMP-\d{5}",)
    assert e.score == pytest.approx(0.6)  # DEFAULT_SCORE


def test_parse_deny_list_entity() -> None:
    cfg = parse_config(
        {
            "schema_version": 1,
            "entities": [
                {"name": "PROJECT_CODE", "deny_list": ["Bluefin", "Redshift"]}
            ],
        }
    )
    assert cfg.entities[0].deny_list == ("Bluefin", "Redshift")


def test_entity_requires_pattern_or_deny_list() -> None:
    with pytest.raises(PiiConfigError, match="at least one of"):
        parse_config(
            {"schema_version": 1, "entities": [{"name": "EMPTY"}]}
        )


def test_entity_name_must_be_upper_snake() -> None:
    with pytest.raises(PiiConfigError, match="UPPER_SNAKE"):
        parse_config(
            {"schema_version": 1, "entities": [{"name": "emp badge",
                                                "patterns": ["x"]}]}
        )


def test_invalid_regex_fails_loud() -> None:
    with pytest.raises(PiiConfigError, match="invalid regex"):
        parse_config(
            {"schema_version": 1,
             "entities": [{"name": "BAD", "patterns": ["EMP-(\\d{5}"]}]}
        )


def test_score_out_of_range_rejected() -> None:
    with pytest.raises(PiiConfigError, match="between 0.0 and 1.0"):
        parse_config(
            {"schema_version": 1,
             "entities": [{"name": "X", "patterns": ["a"], "score": 1.5}]}
        )


def test_unsupported_schema_version_rejected() -> None:
    with pytest.raises(PiiConfigError, match="schema_version"):
        parse_config(
            {"schema_version": 2, "entities": [{"name": "X",
                                                "patterns": ["a"]}]}
        )


def test_empty_entities_rejected() -> None:
    with pytest.raises(PiiConfigError, match="non-empty 'entities'"):
        parse_config({"schema_version": 1, "entities": []})


def test_duplicate_entity_names_rejected() -> None:
    with pytest.raises(PiiConfigError, match="duplicate entity name"):
        parse_config(
            {
                "schema_version": 1,
                "entities": [
                    {"name": "DUP", "patterns": ["a"]},
                    {"name": "DUP", "patterns": ["b"]},
                ],
            }
        )


def test_load_config_yaml(tmp_path) -> None:
    p = tmp_path / "detectors.yaml"
    p.write_text(
        "schema_version: 1\n"
        "entities:\n"
        "  - name: EMP_BADGE\n"
        "    patterns: [\"EMP-\\\\d{5}\"]\n"
        "    context: [badge]\n"
        "    score: 0.8\n"
    )
    cfg = load_config(p)
    assert cfg.entities[0].name == "EMP_BADGE"
    assert cfg.entities[0].context == ("badge",)


def test_load_config_json(tmp_path) -> None:
    p = tmp_path / "detectors.json"
    p.write_text(json.dumps(
        {"schema_version": 1,
         "entities": [{"name": "EMP_BADGE", "patterns": [r"EMP-\d{5}"]}]}
    ))
    cfg = load_config(p)
    assert cfg.entity_names == ("EMP_BADGE",)


def test_load_config_missing_file(tmp_path) -> None:
    with pytest.raises(PiiConfigError, match="could not read"):
        load_config(tmp_path / "nope.yaml")


def test_honesty_caveat_mentions_false_positives() -> None:
    # Honesty per [[ibounce-honest-positioning]]: caveat surfaces BOTH
    # false positives and false negatives, and disclaims ML-grade.
    low = HONESTY_CAVEAT.lower()
    assert "false positive" in low
    assert "false negative" in low
    assert "not" in low and "ml-grade" in low


# ---------------------------------------------------------------------------
# Optional-dependency no-op behaviour — runs WITHOUT presidio too
# ---------------------------------------------------------------------------


def test_build_extra_redactor_none_when_no_config() -> None:
    from iam_jit.pii.bouncer_hook import build_extra_redactor

    # No config path => clean no-op (None), regardless of presidio.
    assert build_extra_redactor(None) is None
    assert build_extra_redactor("") is None


def test_scan_raises_clear_error_when_presidio_absent(monkeypatch) -> None:
    # Simulate the extra being absent and assert we get the friendly
    # PresidioUnavailableError (pip hint), not a bare ImportError/crash.
    import iam_jit.pii.recognizers as rec

    monkeypatch.setattr(rec, "presidio_available", lambda: False)
    cfg = parse_config(
        {"schema_version": 1, "entities": [{"name": "X", "patterns": ["a"]}]}
    )
    with pytest.raises(PresidioUnavailableError, match="pip install"):
        rec.scan_text("aaa", cfg)


def test_build_extra_redactor_noop_when_presidio_absent(monkeypatch, tmp_path) -> None:
    import iam_jit.pii.bouncer_hook as hook

    monkeypatch.setattr(hook, "presidio_available", lambda: False)
    p = tmp_path / "d.yaml"
    p.write_text(
        "schema_version: 1\nentities:\n  - name: X\n    patterns: [\"a\"]\n"
    )
    # Config is declared + valid, but presidio absent => clean no-op None
    # (with a warning logged), never a crash.
    assert hook.build_extra_redactor(p) is None


def test_build_extra_redactor_propagates_bad_config(monkeypatch, tmp_path) -> None:
    import iam_jit.pii.bouncer_hook as hook

    # Even if presidio were present, a declared-but-broken config must
    # fail LOUD (never silently disable protection the operator asked for).
    monkeypatch.setattr(hook, "presidio_available", lambda: True)
    p = tmp_path / "bad.yaml"
    p.write_text("schema_version: 1\nentities: []\n")
    with pytest.raises(PiiConfigError):
        hook.build_extra_redactor(p)
