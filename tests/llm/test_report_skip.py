"""§A93 / #509 Phase 2 — tests for :mod:`iam_jit.llm.report_skip`.

State-verification convention per ``docs/CONTRIBUTING.md`` —
each test verifies OBSERVABLE state (counter / log record / snapshot
shape), not just construction.
"""

from __future__ import annotations

import logging

import pytest

from iam_jit.llm import (
    REASON_BACKEND_UNAVAILABLE,
    REASON_NO_LLM_BACKEND,
    REASON_NO_SIDE_LLM_ENABLED,
    report_skip,
    reset_skip_counter,
    skip_counter_snapshot,
)
from iam_jit.llm.report_skip import DEFAULT_MODE_HINT


@pytest.fixture(autouse=True)
def _reset_counter() -> None:
    reset_skip_counter()
    yield
    reset_skip_counter()


# ---------------------------------------------------------------------------
# Counter behavior — observable state
# ---------------------------------------------------------------------------


def test_report_skip_increments_per_feature_counter() -> None:
    """One report_skip → counter for that feature is 1; second call →
    counter is 2. Verifies the live snapshot reflects the calls."""
    report_skip(feature="structured_deny.classify")
    snap1 = skip_counter_snapshot()
    assert snap1["counts"]["structured_deny.classify"] == 1
    assert snap1["total"] == 1

    report_skip(feature="structured_deny.classify")
    snap2 = skip_counter_snapshot()
    assert snap2["counts"]["structured_deny.classify"] == 2
    assert snap2["total"] == 2


def test_report_skip_tracks_per_reason_counter() -> None:
    """Distinct reasons increment their own bucket so an operator can
    distinguish 'no creds configured' from 'backend down'."""
    report_skip(feature="a", reason=REASON_NO_LLM_BACKEND)
    report_skip(feature="b", reason=REASON_NO_LLM_BACKEND)
    report_skip(feature="c", reason=REASON_BACKEND_UNAVAILABLE)
    snap = skip_counter_snapshot()
    assert snap["by_reason"][REASON_NO_LLM_BACKEND] == 2
    assert snap["by_reason"][REASON_BACKEND_UNAVAILABLE] == 1
    assert snap["total"] == 3


def test_report_skip_appends_to_ring_buffer() -> None:
    """last_skips is a ring buffer; newest entries on the back."""
    for i in range(3):
        report_skip(feature=f"feature.{i}")
    snap = skip_counter_snapshot()
    assert len(snap["last_skips"]) == 3
    assert snap["last_skips"][0]["feature"] == "feature.0"
    assert snap["last_skips"][2]["feature"] == "feature.2"
    # Each entry has the canonical shape.
    for entry in snap["last_skips"]:
        assert set(entry) == {"at", "feature", "reason"}
        assert entry["at"].endswith("Z")  # ISO-8601 UTC


def test_report_skip_ring_buffer_caps_at_20() -> None:
    """Ring buffer never balloons; newest 20 survive."""
    for i in range(25):
        report_skip(feature=f"f-{i:02d}")
    snap = skip_counter_snapshot()
    # All 25 calls counted in totals; only most-recent 20 in last_skips.
    assert snap["total"] == 25
    assert len(snap["last_skips"]) == 20
    # Newest survived — f-24 is at the back.
    assert snap["last_skips"][-1]["feature"] == "f-24"
    # Oldest fell off — f-00 .. f-04 are gone.
    feats = [e["feature"] for e in snap["last_skips"]]
    assert "f-00" not in feats
    assert "f-05" in feats


def test_skip_counter_snapshot_is_a_copy() -> None:
    """Callers can mutate the snapshot without affecting live state."""
    report_skip(feature="foo")
    snap = skip_counter_snapshot()
    snap["counts"]["foo"] = 999
    snap["last_skips"].clear()
    snap2 = skip_counter_snapshot()
    assert snap2["counts"]["foo"] == 1
    assert len(snap2["last_skips"]) == 1


def test_reset_skip_counter_clears_all_state() -> None:
    """Test-only reset clears counts + ring buffer."""
    report_skip(feature="x")
    report_skip(feature="y")
    assert skip_counter_snapshot()["total"] == 2
    reset_skip_counter()
    snap = skip_counter_snapshot()
    assert snap["total"] == 0
    assert snap["counts"] == {}
    assert snap["last_skips"] == []
    assert snap["by_reason"] == {}


# ---------------------------------------------------------------------------
# Logging behavior — observable via caplog
# ---------------------------------------------------------------------------


def test_report_skip_emits_warning_level_log(caplog: pytest.LogCaptureFixture) -> None:
    """Per the brief, report_skip emits WARNING (not debug) so
    operators see deferrals in default log configs."""
    caplog.set_level(logging.DEBUG, logger="iam_jit.llm.skip")
    report_skip(feature="structured_deny.classify")
    # Find our record.
    records = [r for r in caplog.records if r.name == "iam_jit.llm.skip"]
    assert len(records) >= 1
    record = records[0]
    assert record.levelname == "WARNING"


def test_report_skip_log_message_includes_feature_and_reason(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The default message template is greppable + actionable."""
    caplog.set_level(logging.WARNING, logger="iam_jit.llm.skip")
    report_skip(
        feature="autopilot.improve_cycle",
        reason=REASON_NO_SIDE_LLM_ENABLED,
    )
    msg = caplog.records[0].getMessage()
    assert "autopilot.improve_cycle" in msg
    assert REASON_NO_SIDE_LLM_ENABLED in msg
    assert "ran deterministic-only" in msg
    assert "local-dev/agent-in-loop mode" in msg


def test_report_skip_carries_structured_extra_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Stable structured fields for downstream log shippers."""
    caplog.set_level(logging.WARNING, logger="iam_jit.llm.skip")
    report_skip(
        feature="profile_generator.from_audit",
        reason=REASON_NO_LLM_BACKEND,
    )
    record = caplog.records[0]
    assert getattr(record, "llm_skip_feature", None) == "profile_generator.from_audit"
    assert getattr(record, "llm_skip_reason", None) == REASON_NO_LLM_BACKEND
    assert getattr(record, "llm_skip_mode_hint", None)  # non-empty


def test_report_skip_custom_mode_hint(caplog: pytest.LogCaptureFixture) -> None:
    """Caller-provided mode_hint replaces the default in the message."""
    caplog.set_level(logging.WARNING, logger="iam_jit.llm.skip")
    custom = "Use --enable-X to opt in (feature-specific)."
    report_skip(feature="custom.site", mode_hint=custom)
    msg = caplog.records[0].getMessage()
    assert custom in msg
    assert DEFAULT_MODE_HINT not in msg


def test_report_skip_filters_unsafe_extra_keys(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``extra`` must only carry keys with the ``llm_skip_`` prefix —
    arbitrary keys (which could shadow logging internals) are dropped.
    """
    caplog.set_level(logging.WARNING, logger="iam_jit.llm.skip")
    report_skip(
        feature="t",
        extra={
            "llm_skip_bouncer": "ibounce",
            "not_prefixed_should_drop": "secret",
        },
    )
    record = caplog.records[0]
    assert getattr(record, "llm_skip_bouncer", None) == "ibounce"
    assert not hasattr(record, "not_prefixed_should_drop")


def test_report_skip_handles_empty_feature_with_default() -> None:
    """Empty / None feature normalizes to 'unknown' instead of crashing."""
    report_skip(feature="")
    report_skip(feature=None)  # type: ignore[arg-type]
    snap = skip_counter_snapshot()
    assert snap["counts"]["unknown"] == 2
