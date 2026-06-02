"""pytest-compatible wrapper for soak-test invariants.

Runs ONE invariant check cycle against the live bouncers
(ibounce on :8767, gbounce on :8769).  Designed for CI gates
that want to catch invariant violations that don't require time
to surface (monotonicity regression, posture/healthz mismatch,
false-degraded, silent-audit-gap, etc.).

Marked ``@pytest.mark.live`` so they're easy to skip in pure-unit
CI pipelines:

  pytest -m "not live"      # skip live bouncer tests
  pytest -m live            # run only live bouncer tests

Each test is independent; they all share a single sample
collected once at module-import time (``session``-scoped fixture)
to avoid hammering the live bouncers.

Per [[tests-and-independent-uat-required]]: this is the thin CI
layer.  The full time-dependent violation class (VIOLATION-3
counter regression, VIOLATION-7 queue stall) still requires the
60-minute soak; these tests catch the structural invariants that
are visible in a single snapshot.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# Make the tools/soak_test package importable from tests/
_HERE = Path(__file__).parent
_TOOLS = _HERE.parent / "tools" / "soak_test"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from invariants import (  # noqa: E402
    SamplePair,
    Violation,
    check_invariants,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_json_live(url: str, timeout: float = 5.0) -> tuple[bool, dict[str, Any] | None]:
    """GET URL, return (ok, json_data)."""
    import urllib.request
    from urllib.error import URLError

    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return False, None
            return True, json.loads(resp.read().decode("utf-8"))
    except (URLError, OSError, json.JSONDecodeError):
        return False, None


def _run_posture() -> dict[str, Any] | None:
    try:
        result = subprocess.run(
            ["iam-jit", "posture", "--json"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def _run_denies() -> dict[str, Any] | None:
    try:
        result = subprocess.run(
            ["iam-jit", "denies", "recent", "--json", "--limit", "10"],
            capture_output=True, text=True, timeout=10,
        )
        stdout = (result.stdout or "").strip()
        if stdout:
            return json.loads(stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return None


# ---------------------------------------------------------------------------
# Session-scoped fixture: collect one live sample
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def live_sample() -> dict[str, Any]:
    """Collect a single live sample from the running bouncers.

    Skips the entire session if BOTH bouncers are unreachable
    (assume soak infra isn't running).
    """
    ibounce_ok, ibounce_healthz = _get_json_live("http://127.0.0.1:8767/healthz")
    gbounce_ok, gbounce_healthz = _get_json_live("http://127.0.0.1:8769/healthz")
    if not ibounce_ok and not gbounce_ok:
        pytest.skip("Neither ibounce nor gbounce is reachable — skip live tests")
    return {
        "ibounce_ok": ibounce_ok,
        "ibounce_healthz": ibounce_healthz,
        "gbounce_ok": gbounce_ok,
        "gbounce_healthz": gbounce_healthz,
        "posture": _run_posture(),
        "denies": _run_denies(),
    }


@pytest.fixture(scope="session")
def live_pair(live_sample: dict[str, Any]) -> SamplePair:
    return SamplePair(
        ibounce_healthz=live_sample["ibounce_healthz"],
        gbounce_healthz=live_sample["gbounce_healthz"],
        ibounce_healthz_ok=live_sample["ibounce_ok"],
        gbounce_healthz_ok=live_sample["gbounce_ok"],
        posture=live_sample["posture"],
        denies=live_sample["denies"],
        prev_ibounce_healthz=None,
        prev_gbounce_healthz=None,
        audit_queue_stall_count=0,
    )


# ---------------------------------------------------------------------------
# Unit tests: invariants against synthetic data
# ---------------------------------------------------------------------------


class TestV1SilentAuditGap:
    """Synthetic tests for VIOLATION-1: silent audit gap."""

    def test_no_violation_when_decisions_zero(self) -> None:
        pair = SamplePair(
            ibounce_healthz={
                "decisions_count": 0,
                "audit_export": {"configured": False, "log_total_events": 0},
                "audit_log": {},
            },
            gbounce_healthz=None,
            ibounce_healthz_ok=True,
            gbounce_healthz_ok=False,
            posture=None,
            denies=None,
        )
        violations = check_invariants(pair)
        v1 = [v for v in violations if v.code == "VIOLATION-1"]
        assert len(v1) == 0, "No V1 when decisions_count=0"

    def test_violation_when_decisions_nonzero_no_audit(self) -> None:
        pair = SamplePair(
            ibounce_healthz={
                "decisions_count": 93,
                "audit_export": {"configured": False, "log_total_events": 0},
                "audit_log": {},
            },
            gbounce_healthz=None,
            ibounce_healthz_ok=True,
            gbounce_healthz_ok=False,
            posture=None,
            denies=None,
        )
        violations = check_invariants(pair)
        v1 = [v for v in violations if v.code == "VIOLATION-1"]
        assert len(v1) == 1, "V1 when decisions=93 and audit not configured"
        assert "93" in v1[0].message

    def test_no_violation_when_audit_configured_and_writing(self) -> None:
        pair = SamplePair(
            ibounce_healthz={
                "decisions_count": 50,
                "audit_export": {"configured": True, "log_total_events": 45},
                "audit_log": {},
            },
            gbounce_healthz=None,
            ibounce_healthz_ok=True,
            gbounce_healthz_ok=False,
            posture=None,
            denies=None,
        )
        violations = check_invariants(pair)
        v1 = [v for v in violations if v.code == "VIOLATION-1"]
        assert len(v1) == 0, "No V1 when audit is configured and writing"


class TestV3CounterRegression:
    """Synthetic tests for VIOLATION-3: counter regression."""

    def test_no_violation_when_counter_increases(self) -> None:
        base_healthz = {
            "decisions_count": 10,
            "audit_export": {"configured": False, "log_total_events": 0},
            "audit_log": {},
        }
        new_healthz = {
            "decisions_count": 15,
            "audit_export": {"configured": False, "log_total_events": 0},
            "audit_log": {},
        }
        pair = SamplePair(
            ibounce_healthz=new_healthz,
            gbounce_healthz=None,
            ibounce_healthz_ok=True,
            gbounce_healthz_ok=False,
            posture=None,
            denies=None,
            prev_ibounce_healthz=base_healthz,
        )
        violations = check_invariants(pair)
        v3 = [v for v in violations if v.code == "VIOLATION-3"]
        assert len(v3) == 0

    def test_violation_when_counter_decreases(self) -> None:
        base_healthz = {
            "decisions_count": 100,
            "audit_export": {"configured": False, "log_total_events": 0},
            "audit_log": {},
        }
        new_healthz = {
            "decisions_count": 5,
            "audit_export": {"configured": False, "log_total_events": 0},
            "audit_log": {},
        }
        pair = SamplePair(
            ibounce_healthz=new_healthz,
            gbounce_healthz=None,
            ibounce_healthz_ok=True,
            gbounce_healthz_ok=False,
            posture=None,
            denies=None,
            prev_ibounce_healthz=base_healthz,
        )
        violations = check_invariants(pair)
        v3 = [v for v in violations if v.code == "VIOLATION-3"]
        assert len(v3) >= 1, "V3 when decisions_count decreased from 100 to 5"
        assert "100" in v3[0].message and "5" in v3[0].message


class TestV4PostureHealthzMismatch:
    """Synthetic tests for VIOLATION-4: posture/healthz running state mismatch."""

    def _make_posture(self, ibounce_running: bool, gbounce_running: bool) -> dict[str, Any]:
        return {
            "bouncers": {
                "ibounce": {"running": ibounce_running, "mode": "cooperative"},
                "gbounce": {"running": gbounce_running, "mode": "discovery"},
            }
        }

    def test_no_violation_when_both_agree_running(self) -> None:
        pair = SamplePair(
            ibounce_healthz={"decisions_count": 0, "audit_export": {}, "audit_log": {}},
            gbounce_healthz={"audit_log": {"status": "ok"}, "audit_log_total": 0},
            ibounce_healthz_ok=True,
            gbounce_healthz_ok=True,
            posture=self._make_posture(True, True),
            denies=None,
        )
        violations = check_invariants(pair)
        v4 = [v for v in violations if v.code == "VIOLATION-4"]
        assert len(v4) == 0

    def test_violation_when_posture_says_running_but_healthz_unreachable(self) -> None:
        pair = SamplePair(
            ibounce_healthz=None,
            gbounce_healthz=None,
            ibounce_healthz_ok=False,
            gbounce_healthz_ok=False,
            posture=self._make_posture(True, True),
            denies=None,
        )
        violations = check_invariants(pair)
        v4 = [v for v in violations if v.code == "VIOLATION-4"]
        assert len(v4) >= 1, "V4 when posture says running but healthz unreachable"


class TestV8FalseDegraded:
    """Synthetic tests for VIOLATION-8: false degraded claim."""

    def test_violation_when_disk_free_pct_high(self) -> None:
        pair = SamplePair(
            ibounce_healthz=None,
            gbounce_healthz={
                "audit_log": {
                    "status": "degraded",
                    "disk_free_pct": 60.0,
                },
                "audit_log_total": 10,
                "audit_log_path": "/tmp",
            },
            ibounce_healthz_ok=False,
            gbounce_healthz_ok=True,
            posture=None,
            denies=None,
        )
        violations = check_invariants(pair)
        v8 = [v for v in violations if v.code == "VIOLATION-8"]
        assert len(v8) == 1, "V8 when degraded but disk_free_pct=60%"

    def test_no_violation_when_genuinely_low_disk(self) -> None:
        pair = SamplePair(
            ibounce_healthz=None,
            gbounce_healthz={
                "audit_log": {
                    "status": "degraded",
                    "disk_free_pct": 2.0,
                },
                "audit_log_total": 10,
                "audit_log_path": "/tmp",
            },
            ibounce_healthz_ok=False,
            gbounce_healthz_ok=True,
            posture=None,
            denies=None,
        )
        violations = check_invariants(pair)
        v8 = [v for v in violations if v.code == "VIOLATION-8"]
        assert len(v8) == 0, "No V8 when disk_free_pct is genuinely low"


# ---------------------------------------------------------------------------
# Live tests (require running bouncers)
# ---------------------------------------------------------------------------


@pytest.mark.live
class TestLiveInvariants:
    """One-shot invariant check against the live running bouncers.

    These tests do NOT require time to surface — they catch structural
    violations visible in a single snapshot:
      - VIOLATION-1: silent audit gap (decisions > 0, audit not configured)
      - VIOLATION-4: posture/healthz running-state mismatch
      - VIOLATION-5: audit degraded mismatch
      - VIOLATION-8: false degraded (gbounce reporting degraded with plenty of disk)

    VIOLATION-3 and VIOLATION-7 require consecutive samples and are
    only caught by the full 60-minute soak in run.py.
    """

    def test_invariants_run_without_crashing(
        self, live_pair: SamplePair
    ) -> None:
        """Basic smoke test: check_invariants completes without exception."""
        violations = check_invariants(live_pair)
        # No assertion on violations — they're reported, not failed here
        assert isinstance(violations, list)

    def test_no_posture_healthz_mismatch(
        self, live_pair: SamplePair, live_sample: dict[str, Any]
    ) -> None:
        """VIOLATION-4: posture running-state must match /healthz reachability."""
        violations = check_invariants(live_pair)
        v4_errors = [
            v for v in violations
            if v.code == "VIOLATION-4" and v.severity == "ERROR"
        ]
        if v4_errors:
            msgs = "\n".join(v.message for v in v4_errors)
            pytest.fail(
                f"VIOLATION-4 (posture/healthz mismatch) detected:\n{msgs}"
            )

    def test_ibounce_healthz_reachable(
        self, live_sample: dict[str, Any]
    ) -> None:
        """ibounce /healthz should be reachable (PID 87794 per brief)."""
        if not live_sample["ibounce_ok"]:
            pytest.fail(
                "ibounce /healthz unreachable at http://127.0.0.1:8767/healthz. "
                "Expected PID 87794 to be running."
            )

    def test_gbounce_healthz_reachable(
        self, live_sample: dict[str, Any]
    ) -> None:
        """gbounce /healthz should be reachable (PID 86597 per brief)."""
        if not live_sample["gbounce_ok"]:
            pytest.fail(
                "gbounce /healthz unreachable at http://127.0.0.1:8769/healthz. "
                "Expected PID 86597 to be running."
            )

    def test_v1_silent_audit_gap_reported(
        self, live_pair: SamplePair, live_sample: dict[str, Any],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """VIOLATION-1: if decisions > 0 and audit not configured, report it.

        This test does NOT fail — V1 is an expected-but-reportable
        condition when the operator runs in observation-only mode.
        We assert only that the invariant engine detected it correctly.
        """
        violations = check_invariants(live_pair)
        v1 = [v for v in violations if v.code == "VIOLATION-1"]
        ih = live_sample.get("ibounce_healthz") or {}
        decisions = ih.get("decisions_count") or 0
        ae = ih.get("audit_export") or {}
        configured = ae.get("configured", False)
        if decisions > 0 and not configured:
            assert len(v1) >= 1, (
                f"Expected V1 to fire: decisions={decisions} audit_configured={configured}"
            )
        # If V1 did fire, print a note (not a failure)
        if v1:
            print(
                f"\nNOTE: VIOLATION-1 detected — {v1[0].message}", file=sys.stderr
            )

    def test_gbounce_degraded_state_is_honest(
        self, live_pair: SamplePair
    ) -> None:
        """VIOLATION-8: if gbounce says degraded, disk must actually be low."""
        violations = check_invariants(live_pair)
        v8 = [v for v in violations if v.code == "VIOLATION-8"]
        if v8:
            msgs = "\n".join(v.message for v in v8)
            pytest.fail(
                f"VIOLATION-8 (false degraded) detected:\n{msgs}\n"
                "gbounce is claiming disk pressure but the filesystem shows "
                "sufficient free space. This may be a stale state or a "
                "threshold miscalibration."
            )

    def test_all_violations_surfaced(
        self, live_pair: SamplePair
    ) -> None:
        """Enumerate ALL violations found in the live snapshot (diagnostic)."""
        violations = check_invariants(live_pair)
        if violations:
            summary = "\n".join(
                f"  [{v.severity}] {v.code} ({v.bouncer}): {v.message}"
                for v in violations
            )
            # Print for visibility; only ERROR-severity violations are failures
            print(f"\nLive violations found:\n{summary}", file=sys.stderr)
            error_violations = [v for v in violations if v.severity == "ERROR"]
            if error_violations:
                err_summary = "\n".join(
                    f"  [{v.severity}] {v.code} ({v.bouncer}): {v.message}"
                    for v in error_violations
                )
                pytest.fail(
                    f"ERROR-severity invariant violations detected:\n{err_summary}"
                )
