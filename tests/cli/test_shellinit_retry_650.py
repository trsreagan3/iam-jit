"""#650 MED — shellinit retry-with-backoff tests.

Covers the start-up-race window fix: `iam-jit shellinit` invoked
immediately after `nohup ibounce run` (before listen() completes)
must retry rather than silently reporting NOT running.

Three required test scenarios:
  1. Probe fails 2x then succeeds — shellinit detects bouncer as running.
  2. Probe fails all 4 attempts — "not running" hint comment is emitted.
  3. Already-listening bouncer detects on first attempt — no unnecessary
     backoff (sleep not called).

Per [[tests-and-independent-uat-required]] these are post-landing
independent tests; per [[scorer-is-ground-truth]] we don't tune the
retry to pass — the retry must actually retry and the hint must
actually emit.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

import iam_jit.cli_shellinit as si


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snapshot_no_bouncers() -> dict[str, Any]:
    return {
        "bouncers": {
            "ibounce": {"running": False, "port": 8767},
            "kbounce": {"running": False, "port": 8766},
            "dbounce": {"running": False, "port": 5433},
            "gbounce": {"running": False, "port": 8080},
        }
    }


def _snapshot_ibounce_running() -> dict[str, Any]:
    return {
        "bouncers": {
            "ibounce": {"running": True, "port": 8767},
            "kbounce": {"running": False, "port": 8766},
            "dbounce": {"running": False, "port": 5433},
            "gbounce": {"running": False, "port": 8080},
        }
    }


# ---------------------------------------------------------------------------
# Test 1 — probe fails 2x then succeeds; shellinit detects bouncer as running
# ---------------------------------------------------------------------------


def test_retry_succeeds_after_two_failures() -> None:
    """Mock capture_posture to fail twice then return a running ibounce.
    Assert _capture_posture_with_retry returns (snapshot, all_missed=False)
    and that time.sleep was called with the first two retry delays.
    """
    call_count = 0

    def _fake_capture() -> dict[str, Any]:
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return _snapshot_no_bouncers()
        return _snapshot_ibounce_running()

    # Patch the posture.capture_posture that _capture_posture_with_retry
    # imports lazily inside the function.
    with (
        patch("iam_jit.posture.capture_posture", side_effect=_fake_capture),
        patch("iam_jit.cli_shellinit.time.sleep") as mock_sleep,
    ):
        snapshot, all_missed = si._capture_posture_with_retry()

    assert not all_missed, "should have detected ibounce running on attempt 3"
    assert snapshot["bouncers"]["ibounce"]["running"] is True
    # sleep called for first two retry delays (0.25 and 0.5)
    assert mock_sleep.call_count == 2
    assert mock_sleep.call_args_list[0] == call(si._RETRY_DELAYS[0])
    assert mock_sleep.call_args_list[1] == call(si._RETRY_DELAYS[1])


# ---------------------------------------------------------------------------
# Test 2 — all 4 attempts fail; hint comment is emitted in output
# ---------------------------------------------------------------------------


def test_all_probes_fail_emits_startup_race_hint() -> None:
    """When every retry attempt returns no running bouncer,
    render_shellinit must include the 'run shellinit again' hint line
    (per [[ibounce-honest-positioning]]) AND the 'not running' summary
    line must also be present (not suppressed).
    """
    with (
        patch(
            "iam_jit.posture.capture_posture",
            return_value=_snapshot_no_bouncers(),
        ),
        patch("iam_jit.cli_shellinit.time.sleep"),
    ):
        snapshot, all_missed = si._capture_posture_with_retry()

    assert all_missed, "should set all_missed=True when all probes fail"

    out = si.render_shellinit(snapshot, shell="bash", all_missed=all_missed)

    # The standard "not running" summary line must still be present.
    assert "Detected NOT running:" in out, (
        "not-running summary line must NOT be suppressed"
    )
    # The startup-race hint must be present.
    assert "run shellinit again" in out, (
        "startup-race hint must be present when all_missed=True"
    )
    assert "If you JUST started a bouncer" in out

    # Output must still be comment-only (no export lines).
    for line in out.splitlines():
        assert not line.startswith("export "), (
            f"all-failed output must not contain export lines: {line!r}"
        )


# ---------------------------------------------------------------------------
# Test 3 — already-listening bouncer detected on first attempt; no sleep
# ---------------------------------------------------------------------------


def test_no_sleep_when_bouncer_already_running() -> None:
    """When the first capture_posture call returns a running bouncer,
    time.sleep must NOT be called — no unnecessary backoff.
    """
    with (
        patch(
            "iam_jit.posture.capture_posture",
            return_value=_snapshot_ibounce_running(),
        ),
        patch("iam_jit.cli_shellinit.time.sleep") as mock_sleep,
    ):
        snapshot, all_missed = si._capture_posture_with_retry()

    assert not all_missed
    assert snapshot["bouncers"]["ibounce"]["running"] is True
    mock_sleep.assert_not_called()


# ---------------------------------------------------------------------------
# Test 4 — hint NOT emitted when bouncer IS running (all_missed=False)
# ---------------------------------------------------------------------------


def test_hint_not_emitted_when_bouncer_running() -> None:
    """The startup-race hint must only appear when all_missed=True.
    When a bouncer is running, all_missed=False and the hint must be absent.
    """
    snapshot = _snapshot_ibounce_running()
    out = si.render_shellinit(snapshot, shell="bash", all_missed=False)

    assert "run shellinit again" not in out
    assert "If you JUST started a bouncer" not in out
    # Export line must be present.
    assert "export AWS_ENDPOINT_URL='http://127.0.0.1:8767'" in out


# ---------------------------------------------------------------------------
# Test 5 — all_missed=False default preserves backward compat
# ---------------------------------------------------------------------------


def test_render_shellinit_all_missed_defaults_false() -> None:
    """render_shellinit(snapshot, shell=...) without all_missed must
    behave identically to all_missed=False — backward compat.
    """
    snapshot = _snapshot_no_bouncers()
    out_default = si.render_shellinit(snapshot, shell="bash")
    out_explicit = si.render_shellinit(snapshot, shell="bash", all_missed=False)
    assert out_default == out_explicit
    assert "run shellinit again" not in out_default
