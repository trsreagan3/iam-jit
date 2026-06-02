# ADOPT-7 / #721 — ReDoS / DoS input-size cap (defense-in-depth).
"""Strings over MAX_SCAN_BYTES are skipped before any recognizer regex
runs, so an operator's pathological pattern can't stall the async
audit-redaction worker on huge input. Presidio's regex engine already
defeats classic catastrophic backtracking; this caps the worst case.

Requires presidio (scan_text builds recognizers); importorskip-guarded.
"""

from __future__ import annotations

import time

import pytest

pytest.importorskip("presidio_analyzer")

from iam_jit.pii.config import parse_config
from iam_jit.pii.recognizers import MAX_SCAN_BYTES, redact_text, scan_text


def _config():
    return parse_config(
        {
            "schema_version": 1,
            "entities": [{"name": "EMP_BADGE", "patterns": [r"EMP-\d{5}"]}],
        }
    )


def test_oversized_input_is_skipped_unchanged() -> None:
    cfg = _config()
    # Just over the cap, with a real match embedded that WOULD be redacted
    # if scanned. The cap means it is returned unchanged.
    big = "x" * (MAX_SCAN_BYTES + 1) + " EMP-12345"
    out = redact_text(big, cfg)
    assert out == big  # skipped: match NOT redacted because input too large
    assert "EMP-12345" in out

    result = scan_text(big, cfg)
    assert result.matches == ()
    assert result.redacted == big


def test_input_at_cap_still_scanned() -> None:
    cfg = _config()
    # Exactly at the cap (not over) is still scanned + redacted.
    pad = "x" * (MAX_SCAN_BYTES - len("EMP-12345"))
    text = pad + "EMP-12345"
    assert len(text.encode("utf-8")) == MAX_SCAN_BYTES
    out = redact_text(text, cfg)
    assert "EMP-12345" not in out
    assert "[REDACTED:EMP_BADGE]" in out


def test_oversized_input_returns_fast() -> None:
    # The skip happens before recognizer machinery, so even a large input
    # returns near-instantly (no hang). Generous bound to avoid CI flake.
    cfg = _config()
    big = "a" * (MAX_SCAN_BYTES * 4)
    start = time.monotonic()
    out = redact_text(big, cfg)
    elapsed = time.monotonic() - start
    assert out == big
    assert elapsed < 1.0
