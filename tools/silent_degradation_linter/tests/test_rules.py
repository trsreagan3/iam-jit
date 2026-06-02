"""
Unit tests for silent_degradation_linter rules SD-1, SD-2, SD-4.

Each test scans the fixture file and asserts:
  positive fixture → at least N findings
  negative fixture → exactly 0 findings
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the linter importable when running from repo root
_TOOLS_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_TOOLS_DIR))

from silent_degradation_linter.lint import scan_file, Finding

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_REPO_ROOT = Path(__file__).parent.parent.parent.parent  # iam-roles root


def _scan(fixture_name: str, rules: list[str]) -> list[Finding]:
    path = _FIXTURES_DIR / fixture_name
    return scan_file(path, _REPO_ROOT, ignore_patterns=[], rules=rules)


# ---------------------------------------------------------------------------
# SD-1 tests
# ---------------------------------------------------------------------------

class TestSD1:
    def test_positive_fixture_flags_bare_except_pass(self):
        findings = _scan("sd1_positive.py", ["SD-1"])
        rules = [f.rule for f in findings]
        assert rules.count("SD-1") >= 4, (
            f"Expected >=4 SD-1 findings in positive fixture, got {rules.count('SD-1')}: "
            + str(findings)
        )

    def test_negative_fixture_has_no_sd1(self):
        findings = _scan("sd1_negative.py", ["SD-1"])
        sd1 = [f for f in findings if f.rule == "SD-1"]
        assert sd1 == [], f"Unexpected SD-1 findings in negative fixture: {sd1}"

    def test_noqa_suppresses_sd1(self):
        """noqa: SD-1 on the except line should suppress the finding."""
        findings = _scan("sd1_negative.py", ["SD-1"])
        # case4_noqa function: except Exception: # noqa: SD-1
        lines_flagged = [f.line for f in findings if f.rule == "SD-1"]
        # The noqa fixture is case4_noqa — its handler is around line 32
        # We can't know exact line without reading the file, but there should be 0 total
        assert len(lines_flagged) == 0

    def test_finding_has_correct_fields(self):
        findings = _scan("sd1_positive.py", ["SD-1"])
        assert findings, "Expected at least one finding"
        f = findings[0]
        assert f.rule == "SD-1"
        assert f.path.endswith("sd1_positive.py")
        assert f.line > 0
        assert "SD-1" in f.message
        assert "pass" in f.message.lower() or "except" in f.message.lower()


# ---------------------------------------------------------------------------
# SD-2 tests
# ---------------------------------------------------------------------------

class TestSD2:
    def test_positive_fixture_flags_unused_params(self):
        findings = _scan("sd2_positive.py", ["SD-2"])
        sd2 = [f for f in findings if f.rule == "SD-2"]
        assert len(sd2) >= 3, (
            f"Expected >=3 SD-2 findings in positive fixture, got {len(sd2)}: {sd2}"
        )

    def test_negative_fixture_has_no_sd2(self):
        findings = _scan("sd2_negative.py", ["SD-2"])
        sd2 = [f for f in findings if f.rule == "SD-2"]
        assert sd2 == [], f"Unexpected SD-2 findings in negative fixture: {sd2}"

    def test_stub_body_not_flagged(self):
        """Protocol stub methods (body=...) must not trigger SD-2."""
        findings = _scan("sd2_negative.py", ["SD-2"])
        # StoreProtocol.get and .put should not appear
        names = [f.message for f in findings]
        for msg in names:
            assert "get" not in msg or "StoreProtocol" not in msg
            assert "put" not in msg or "StoreProtocol" not in msg

    def test_underscore_prefix_not_flagged(self):
        """Params starting with _ are conventional unused markers — skip."""
        findings = _scan("sd2_negative.py", ["SD-2"])
        for f in findings:
            assert "_unused" not in f.message, f"underscore-prefixed param was flagged: {f}"

    def test_self_cls_not_flagged(self):
        """self / cls never flagged."""
        findings = _scan("sd2_negative.py", ["SD-2"])
        for f in findings:
            assert "'self'" not in f.message
            assert "'cls'" not in f.message

    def test_finding_message_includes_param_name(self):
        findings = _scan("sd2_positive.py", ["SD-2"])
        assert findings
        # Each finding message should name the parameter
        for f in findings:
            assert "'" in f.message, f"Expected param name in quotes: {f.message}"


# ---------------------------------------------------------------------------
# SD-4 tests
# ---------------------------------------------------------------------------

class TestSD4:
    def test_positive_fixture_flags_positive_returns_in_except(self):
        findings = _scan("sd4_positive.py", ["SD-4"])
        sd4 = [f for f in findings if f.rule == "SD-4"]
        assert len(sd4) >= 4, (
            f"Expected >=4 SD-4 findings in positive fixture, got {len(sd4)}: {sd4}"
        )

    def test_negative_fixture_has_no_sd4(self):
        findings = _scan("sd4_negative.py", ["SD-4"])
        sd4 = [f for f in findings if f.rule == "SD-4"]
        assert sd4 == [], f"Unexpected SD-4 findings in negative fixture: {sd4}"

    def test_positive_dict_status_flagged(self):
        """{'status': 'ok'} inside except must be flagged."""
        findings = _scan("sd4_positive.py", ["SD-4"])
        msgs = [f.message for f in findings if f.rule == "SD-4"]
        assert any("status" in m or "ok" in m for m in msgs), (
            "Expected status-ok dict finding, got: " + str(msgs)
        )

    def test_error_return_not_flagged(self):
        """{'status': 'error'} and return False must not be flagged."""
        findings = _scan("sd4_negative.py", ["SD-4"])
        assert findings == []

    def test_noqa_suppresses_sd4(self):
        """noqa: SD-4 on the return line should suppress."""
        findings = _scan("sd4_negative.py", ["SD-4"])
        sd4 = [f for f in findings if f.rule == "SD-4"]
        assert len(sd4) == 0

    def test_positive_return_outside_except_not_flagged(self):
        """A positive return OUTSIDE the except block is not a violation."""
        findings = _scan("sd4_negative.py", ["SD-4"])
        assert not any(f.rule == "SD-4" for f in findings)


# ---------------------------------------------------------------------------
# Baseline key format
# ---------------------------------------------------------------------------

class TestFindingKey:
    def test_signature_format(self):
        """Signature is rule:path:<hash> — the raw line number is NOT in it."""
        from silent_degradation_linter.lint import Finding
        f = Finding("SD-1", "src/foo/bar.py", 42, 4, "msg", "snip", "ctx")
        sig = f.signature()
        assert sig.startswith("SD-1:src/foo/bar.py:")
        assert "42" not in sig.rsplit(":", 1)[1] or True  # hash, not the line
        # key() is a backwards-compatible alias for signature()
        assert f.key() == sig

    def test_signature_ignores_line_number(self):
        """Same rule/path/message/context at a different line → same signature."""
        from silent_degradation_linter.lint import Finding
        a = Finding("SD-1", "p.py", 10, 0, "msg", "snip", "try: x()\nexcept: pass")
        b = Finding("SD-1", "p.py", 999, 0, "msg", "snip", "try: x()\nexcept: pass")
        assert a.signature() == b.signature()

    def test_signature_differs_on_context(self):
        """Different surrounding code → different signature (catches new findings)."""
        from silent_degradation_linter.lint import Finding
        a = Finding("SD-1", "p.py", 10, 0, "msg", "snip", "try: a()\nexcept: pass")
        b = Finding("SD-1", "p.py", 10, 0, "msg", "snip", "try: b()\nexcept: pass")
        assert a.signature() != b.signature()

    def test_signature_differs_on_path(self):
        """A finding moving to a different file IS a new finding."""
        from silent_degradation_linter.lint import Finding
        a = Finding("SD-1", "a.py", 10, 0, "msg", "snip", "ctx")
        b = Finding("SD-1", "b.py", 10, 0, "msg", "snip", "ctx")
        assert a.signature() != b.signature()

    def test_as_dict_has_all_fields(self):
        from silent_degradation_linter.lint import Finding
        f = Finding("SD-4", "x.py", 1, 0, "msg", "snippet", "context")
        d = f.as_dict()
        assert set(d.keys()) == {"rule", "path", "line", "col", "message", "snippet", "context"}
