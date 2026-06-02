"""Soak-test harness for the iam-jit Bounce suite.

Phase 1 — observe-only against the operator's live bouncers.
No destructive operations.  No spin-up of new processes.

Usage
-----
  python tools/soak_test/run.py [--interval 60] [--duration 60]

  # Quick smoke run (5 samples, 10s apart):
  python tools/soak_test/run.py --interval 10 --duration 1

  # Default 1-hour soak:
  python tools/soak_test/run.py

Output (all under SOAK_DIR = /tmp/soak-test-2026-06-01/):
  samples/<timestamp>.json   — one file per sample cycle
  timeline.jsonl             — every sample appended, NDJSON
  violations.md              — violation report (updated live)
  summary.md                 — final summary (written on clean exit)

Standing constraints
--------------------
- Do NOT kill PIDs 86597 or 87794
- Do NOT write to ~/.gbounce/, ~/.iam-jit/, ~/.aws/, ~/.kbounce/, ~/.dbounce/
- Read-only filesystem operations on those directories are fine
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request
from typing import Any
from urllib.error import URLError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SOAK_DIR = pathlib.Path("/tmp/soak-test-2026-06-01")
SAMPLES_DIR = SOAK_DIR / "samples"
TIMELINE_PATH = SOAK_DIR / "timeline.jsonl"
VIOLATIONS_MD_PATH = SOAK_DIR / "violations.md"
SUMMARY_MD_PATH = SOAK_DIR / "summary.md"

# ibounce and gbounce mgmt endpoints (per mission brief)
IBOUNCE_HEALTHZ = "http://127.0.0.1:8767/healthz"
GBOUNCE_HEALTHZ = "http://127.0.0.1:8769/healthz"

HEALTHZ_TIMEOUT = 5.0  # seconds per request

# ---------------------------------------------------------------------------
# Import invariants engine
# ---------------------------------------------------------------------------

_HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(_HERE))

from invariants import (  # noqa: E402
    SamplePair,
    Violation,
    check_invariants,
)

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _get_json(url: str, timeout: float = HEALTHZ_TIMEOUT) -> tuple[bool, dict[str, Any] | None]:
    """GET a URL and parse the JSON body.

    Returns (ok, data) where ok=True means HTTP 200 + valid JSON.
    Never raises.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return False, None
            body = resp.read().decode("utf-8", errors="replace")
            return True, json.loads(body)
    except (URLError, OSError, json.JSONDecodeError, Exception):
        return False, None


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _run_iam_jit(*args: str, timeout: int = 10) -> tuple[bool, dict[str, Any] | str | None]:
    """Run `iam-jit <args>` and return (ok, result).

    ok=True means exit 0 + parseable JSON (first line of stdout).
    On failure returns (False, stderr_string).
    """
    cmd = ["iam-jit", *args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode not in (0, 1):
            # exit 1 is acceptable from some commands (e.g. all-bouncers-unreachable)
            pass
        stdout = (result.stdout or "").strip()
        if not stdout:
            return False, result.stderr.strip() or "(no output)"
        # Try to parse as JSON
        try:
            data = json.loads(stdout)
            return True, data
        except json.JSONDecodeError:
            return False, stdout
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except FileNotFoundError:
        return False, "iam-jit not found in PATH"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


# ---------------------------------------------------------------------------
# Sample collection
# ---------------------------------------------------------------------------


def collect_sample(cycle: int) -> dict[str, Any]:
    """Collect one sample cycle.  Returns a dict with all sub-fields."""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. ibounce /healthz
    ibounce_ok, ibounce_healthz = _get_json(IBOUNCE_HEALTHZ)

    # 2. gbounce /healthz
    gbounce_ok, gbounce_healthz = _get_json(GBOUNCE_HEALTHZ)

    # 3. iam-jit posture --json
    posture_ok, posture_data = _run_iam_jit("posture", "--json")

    # 4. iam-jit denies recent --json --limit 50
    denies_ok, denies_data = _run_iam_jit("denies", "recent", "--json", "--limit", "50")

    # 5. iam-jit audit query --since 5m --format summary
    audit_ok, audit_data = _run_iam_jit(
        "audit", "query", "--since", "5m", "--format", "summary"
    )

    sample = {
        "cycle": cycle,
        "timestamp": ts,
        "ibounce": {
            "healthz_ok": ibounce_ok,
            "healthz": ibounce_healthz,
        },
        "gbounce": {
            "healthz_ok": gbounce_ok,
            "healthz": gbounce_healthz,
        },
        "posture": {
            "ok": posture_ok,
            "data": posture_data if posture_ok else None,
            "error": posture_data if not posture_ok else None,
        },
        "denies": {
            "ok": denies_ok,
            "data": denies_data if denies_ok else None,
            "error": denies_data if not denies_ok else None,
        },
        "audit_summary": {
            "ok": audit_ok,
            "data": audit_data if audit_ok else None,
            "error": audit_data if not audit_ok else None,
        },
    }
    return sample


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def persist_sample(sample: dict[str, Any]) -> None:
    """Write sample to samples/<ts>.json and append to timeline.jsonl."""
    ts_safe = sample["timestamp"].replace(":", "-").replace("+", "p")
    sample_path = SAMPLES_DIR / f"{ts_safe}.json"
    sample_path.write_text(
        json.dumps(sample, indent=2, default=str),
        encoding="utf-8",
    )
    with TIMELINE_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(sample, default=str) + "\n")


def append_violation_to_md(v: Violation, ts: str, cycle: int) -> None:
    """Append one violation entry to violations.md."""
    header_written = VIOLATIONS_MD_PATH.exists()
    with VIOLATIONS_MD_PATH.open("a", encoding="utf-8") as fh:
        if not header_written:
            fh.write("# Soak-Test Violation Report\n\n")
            fh.write(
                "Generated by `tools/soak_test/run.py` — updated live.\n\n"
            )
            fh.write("---\n\n")
        fh.write(f"## [{v.severity}] {v.code} — {v.bouncer} (cycle {cycle})\n\n")
        fh.write(f"**Timestamp:** {ts}  \n")
        fh.write(f"**Message:** {v.message}\n\n")
        if v.evidence:
            fh.write("**Evidence:**\n\n```json\n")
            fh.write(json.dumps(v.evidence, indent=2, default=str))
            fh.write("\n```\n\n")
        if v.next_steps:
            fh.write(f"**Next steps:** {v.next_steps}\n\n")
        fh.write("---\n\n")


# ---------------------------------------------------------------------------
# State tracking for monotonicity / stall detection
# ---------------------------------------------------------------------------


class SoakState:
    """Mutable state carried across soak cycles."""

    def __init__(self) -> None:
        self.prev_ibounce_healthz: dict[str, Any] | None = None
        self.prev_gbounce_healthz: dict[str, Any] | None = None
        self.audit_queue_stall_count: int = 0

        # For final summary
        self.start_time = datetime.datetime.now(datetime.timezone.utc)
        self.start_ibounce_decisions: int | None = None
        self.start_gbounce_audit_total: int | None = None
        self.end_ibounce_decisions: int | None = None
        self.end_gbounce_audit_total: int | None = None

        self.total_samples: int = 0
        self.total_violations: int = 0
        self.violations_by_code: dict[str, int] = {}
        # Deduplicate: only log a violation if not seen in the last N cycles
        self._recent_violation_keys: dict[str, int] = {}
        self._dedup_window: int = 3  # suppress re-emit within 3 cycles

    def record_start_counters(self, sample: dict[str, Any]) -> None:
        ih = (sample.get("ibounce") or {}).get("healthz") or {}
        gh = (sample.get("gbounce") or {}).get("healthz") or {}
        if self.start_ibounce_decisions is None:
            v = ih.get("decisions_count")
            self.start_ibounce_decisions = int(v) if isinstance(v, int) else 0
        if self.start_gbounce_audit_total is None:
            v = gh.get("audit_log_total")
            self.start_gbounce_audit_total = int(v) if isinstance(v, int) else 0

    def record_end_counters(self, sample: dict[str, Any]) -> None:
        ih = (sample.get("ibounce") or {}).get("healthz") or {}
        gh = (sample.get("gbounce") or {}).get("healthz") or {}
        v = ih.get("decisions_count")
        self.end_ibounce_decisions = int(v) if isinstance(v, int) else None
        v = gh.get("audit_log_total")
        self.end_gbounce_audit_total = int(v) if isinstance(v, int) else None

    def update_stall_count(self, sample: dict[str, Any]) -> None:
        ih = (sample.get("ibounce") or {}).get("healthz") or {}
        ae = ih.get("audit_export") or {}
        depth = ae.get("queue_depth") or 0
        capacity = ae.get("queue_capacity") or 0
        if capacity > 0 and depth > 0:
            self.audit_queue_stall_count += 1
        else:
            self.audit_queue_stall_count = 0

    def is_duplicate(self, v: Violation, cycle: int) -> bool:
        """True if we surfaced the same violation code+bouncer within the dedup window."""
        key = f"{v.code}:{v.bouncer}"
        last = self._recent_violation_keys.get(key)
        if last is not None and (cycle - last) < self._dedup_window:
            return True
        return False

    def record_violation(self, v: Violation, cycle: int) -> None:
        key = f"{v.code}:{v.bouncer}"
        self._recent_violation_keys[key] = cycle
        self.total_violations += 1
        self.violations_by_code[v.code] = (
            self.violations_by_code.get(v.code, 0) + 1
        )


# ---------------------------------------------------------------------------
# Main soak loop
# ---------------------------------------------------------------------------


def _print_status(cycle: int, ts: str, violations: list[Violation]) -> None:
    line = f"[{ts}] cycle={cycle}"
    if violations:
        codes = ", ".join(v.code for v in violations)
        line += f" VIOLATIONS: {codes}"
    else:
        line += " OK"
    print(line, flush=True)


def run_soak(interval_s: int = 60, duration_min: int = 60) -> None:
    """Main soak loop."""
    # Ensure output directories exist
    SOAK_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    end_time = time.monotonic() + duration_min * 60
    state = SoakState()
    cycle = 0

    print(
        f"Soak started — interval={interval_s}s duration={duration_min}min "
        f"output={SOAK_DIR}",
        flush=True,
    )
    print(
        f"Monitoring: ibounce={IBOUNCE_HEALTHZ}  gbounce={GBOUNCE_HEALTHZ}",
        flush=True,
    )

    try:
        while time.monotonic() < end_time:
            cycle_start = time.monotonic()
            cycle += 1
            ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

            # Collect
            sample = collect_sample(cycle)
            state.total_samples += 1

            # Record start counters on first cycle
            if cycle == 1:
                state.record_start_counters(sample)

            # Always update end counters (last wins)
            state.record_end_counters(sample)

            # Update stall count
            state.update_stall_count(sample)

            # Persist
            persist_sample(sample)

            # Build SamplePair for invariant engine
            pair = SamplePair(
                ibounce_healthz=(sample.get("ibounce") or {}).get("healthz"),
                gbounce_healthz=(sample.get("gbounce") or {}).get("healthz"),
                ibounce_healthz_ok=(sample.get("ibounce") or {}).get(
                    "healthz_ok", False
                ),
                gbounce_healthz_ok=(sample.get("gbounce") or {}).get(
                    "healthz_ok", False
                ),
                posture=(sample.get("posture") or {}).get("data"),
                denies=(sample.get("denies") or {}).get("data"),
                prev_ibounce_healthz=state.prev_ibounce_healthz,
                prev_gbounce_healthz=state.prev_gbounce_healthz,
                audit_queue_stall_count=state.audit_queue_stall_count,
            )

            violations = check_invariants(pair)

            new_violations: list[Violation] = []
            for v in violations:
                if not state.is_duplicate(v, cycle):
                    new_violations.append(v)
                    state.record_violation(v, cycle)
                    append_violation_to_md(v, ts, cycle)

            _print_status(cycle, ts, new_violations)

            # Update prev for next cycle
            state.prev_ibounce_healthz = (
                (sample.get("ibounce") or {}).get("healthz") or None
            )
            state.prev_gbounce_healthz = (
                (sample.get("gbounce") or {}).get("healthz") or None
            )

            # Sleep until next cycle
            elapsed = time.monotonic() - cycle_start
            sleep_for = max(0, interval_s - elapsed)
            if time.monotonic() + sleep_for < end_time:
                time.sleep(sleep_for)
            else:
                break

    except KeyboardInterrupt:
        print("\nSoak interrupted by operator.", flush=True)

    # Write final summary
    _write_summary(state, cycle)
    print(f"\nSoak complete — {state.total_samples} samples, "
          f"{state.total_violations} violations. "
          f"Reports in {SOAK_DIR}", flush=True)


def _write_summary(state: SoakState, final_cycle: int) -> None:
    end_time = datetime.datetime.now(datetime.timezone.utc)
    duration_s = (end_time - state.start_time).total_seconds()
    duration_min = duration_s / 60

    lines = [
        "# Soak-Test Final Summary",
        "",
        f"**Run start:** {state.start_time.isoformat()}  ",
        f"**Run end:**   {end_time.isoformat()}  ",
        f"**Duration:**  {duration_min:.1f} minutes  ",
        f"**Cycles completed:** {final_cycle}  ",
        f"**Samples collected:** {state.total_samples}  ",
        "",
        "---",
        "",
        "## Violations",
        "",
        f"**Total violations surfaced:** {state.total_violations}  ",
    ]
    if state.violations_by_code:
        lines.append("")
        lines.append("| Code | Count |")
        lines.append("|------|-------|")
        for code, count in sorted(state.violations_by_code.items()):
            lines.append(f"| {code} | {count} |")
    else:
        lines.append("")
        lines.append("No invariant violations detected.")

    lines += [
        "",
        "---",
        "",
        "## Counter Monotonicity",
        "",
    ]

    start_d = state.start_ibounce_decisions
    end_d = state.end_ibounce_decisions
    if start_d is not None and end_d is not None:
        mono_ok = end_d >= start_d
        lines.append(
            f"- ibounce decisions_count: {start_d} → {end_d} "
            f"({'MONOTONIC OK' if mono_ok else 'REGRESSION DETECTED'})"
        )
    else:
        lines.append("- ibounce decisions_count: n/a (ibounce not reachable)")

    start_g = state.start_gbounce_audit_total
    end_g = state.end_gbounce_audit_total
    if start_g is not None and end_g is not None:
        mono_ok = end_g >= start_g
        lines.append(
            f"- gbounce audit_log_total: {start_g} → {end_g} "
            f"({'MONOTONIC OK' if mono_ok else 'REGRESSION DETECTED'})"
        )
    else:
        lines.append("- gbounce audit_log_total: n/a (gbounce not reachable)")

    lines += [
        "",
        "---",
        "",
        "## Recommendations",
        "",
    ]

    if state.violations_by_code.get("VIOLATION-1", 0) > 0:
        lines.append(
            "- **VIOLATION-1 (silent-audit-gap):** ibounce is running without "
            "an audit log configured. All decisions are invisible to audit "
            "queries. Reproduce #711. Enable audit logging: restart with "
            "`--audit-log-path`."
        )
    if state.violations_by_code.get("VIOLATION-5", 0) > 0:
        lines.append(
            "- **VIOLATION-5 (audit-degraded-mismatch):** gbounce is in "
            "disk-pressure pause mode. Free up disk space at ~/.gbounce or "
            "raise the warn_pct threshold. This also explains why denies "
            "fan-out may return 0 events — gbounce is pausing audit writes."
        )
    if state.violations_by_code.get("VIOLATION-8", 0) > 0:
        lines.append(
            "- **VIOLATION-8 (false-degraded):** gbounce reports degraded "
            "status that may be stale. Investigate the gbounce disk-threshold "
            "fix in flight — the threshold check may be reading a different "
            "mount point from the actual data path."
        )
    if not state.violations_by_code:
        lines.append(
            "- All invariants held for the entire soak window. "
            "No action required."
        )

    lines += [
        "",
        "---",
        "",
        f"*Generated by `tools/soak_test/run.py` — soak harness UAT improvement #1*",
    ]

    SUMMARY_MD_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Summary written to {SUMMARY_MD_PATH}", flush=True)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="soak_test",
        description=(
            "Phase-1 soak-test observer for the iam-jit Bounce suite. "
            "Periodically samples live bouncers, asserts cross-component "
            "invariants, and surfaces violations."
        ),
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Seconds between sample cycles (default: 60).",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        metavar="MINUTES",
        help="Total soak duration in minutes (default: 60).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run_soak(interval_s=args.interval, duration_min=args.duration)
