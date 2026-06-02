"""Soak-test invariant engine for the iam-jit Bounce suite.

This module contains ONLY the invariant-check logic — it takes two samples
(current + optional previous) and returns a list of Violation objects.

It has NO knowledge of time, loops, or file I/O.  The loop lives in run.py;
tests can import this module directly and call check_invariants() against
synthetic fixtures without spinning up live bouncers.

Invariant catalogue
-------------------
VIOLATION-1  silent-audit-gap       decisions_count > 0 but audit_export
             not configured and log_total_events = 0.  Reproduces #711.

VIOLATION-2  audit-configured-not-writing  audit_export configured but
             log_total_events = 0 while decisions_count > 0 (and was > 0
             in the previous sample too, so we know time has passed).

VIOLATION-3  counter-regression     decisions_count or log_total_events
             DECREASED between consecutive samples.  Possible silent
             restart / counter reset.

VIOLATION-4  posture-healthz-mismatch  posture says bouncer RUNNING but
             /healthz returned non-200 (or vice versa).

VIOLATION-5  audit-degraded-mismatch  posture says audit_log.status=degraded
             but /healthz disagrees (or vice versa).

VIOLATION-6  denies-fan-out-missing  iam-jit denies recent returned results
             but a running bouncer is absent from the bouncers_succeeded set.

VIOLATION-7  audit-queue-stalled    audit_export.queue_depth > 0 for more
             than QUEUE_STALL_SAMPLE_THRESHOLD consecutive samples.

VIOLATION-8  false-degraded         /healthz audit_log.status = "degraded"
             but disk_free_pct > DISK_FREE_HONEST_PCT and absolute free
             > DISK_FREE_HONEST_BYTES.  (bouncer reports degraded when it
             isn't actually under pressure.)
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any

# -----------------------------------------------------------------
# Tuneable thresholds
# -----------------------------------------------------------------

QUEUE_STALL_SAMPLE_THRESHOLD = 5
"""How many consecutive samples with queue_depth > 0 before VIOLATION-7."""

DISK_FREE_HONEST_PCT = 4.0
"""If disk_free_pct is above this AND absolute free > DISK_FREE_HONEST_BYTES,
a degraded status is suspicious (VIOLATION-8)."""

DISK_FREE_HONEST_BYTES = 5 * 1024 ** 3  # 5 GiB


# -----------------------------------------------------------------
# Data types
# -----------------------------------------------------------------

SEVERITY_ERROR = "ERROR"
SEVERITY_WARN = "WARN"
SEVERITY_INFO = "INFO"


@dataclass
class Violation:
    code: str
    """Machine-readable violation code, e.g. VIOLATION-1."""
    severity: str
    """One of ERROR / WARN / INFO."""
    bouncer: str
    """Which bouncer the violation is about, or 'cross-product'."""
    message: str
    """Human-readable summary."""
    evidence: dict[str, Any] = field(default_factory=dict)
    """Raw JSON fragments that support the finding."""
    next_steps: str = ""
    """Operator action recommendation."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "bouncer": self.bouncer,
            "message": self.message,
            "evidence": self.evidence,
            "next_steps": self.next_steps,
        }


# -----------------------------------------------------------------
# Per-bouncer sample accessors
# -----------------------------------------------------------------

def _ibounce_decisions(healthz: dict[str, Any]) -> int | None:
    """Extract decisions_count from ibounce /healthz JSON."""
    v = healthz.get("decisions_count")
    if isinstance(v, int):
        return v
    return None


def _ibounce_audit_export(healthz: dict[str, Any]) -> dict[str, Any]:
    ae = healthz.get("audit_export") or {}
    return ae


def _ibounce_audit_log(healthz: dict[str, Any]) -> dict[str, Any]:
    al = healthz.get("audit_log") or {}
    return al


def _gbounce_audit_log(healthz: dict[str, Any]) -> dict[str, Any]:
    """gbounce uses a flat shape: audit_log.status, etc."""
    al = healthz.get("audit_log") or {}
    return al


def _gbounce_audit_total(healthz: dict[str, Any]) -> int | None:
    v = healthz.get("audit_log_total")
    if isinstance(v, int):
        return v
    return None


# -----------------------------------------------------------------
# The invariant checks
# -----------------------------------------------------------------

def _check_v1_silent_audit_gap(
    ibounce_healthz: dict[str, Any] | None,
) -> Violation | None:
    """VIOLATION-1: decisions > 0 but audit_export not configured + 0 events."""
    if ibounce_healthz is None:
        return None
    decisions = _ibounce_decisions(ibounce_healthz)
    if not decisions:
        return None
    ae = _ibounce_audit_export(ibounce_healthz)
    configured = ae.get("configured", False)
    total_events = ae.get("log_total_events", 0) or 0
    if not configured and total_events == 0:
        return Violation(
            code="VIOLATION-1",
            severity=SEVERITY_WARN,
            bouncer="ibounce",
            message=(
                f"decisions_count={decisions} but audit_export.configured=False "
                f"and log_total_events=0. Silent audit gap — no decisions are "
                f"being written to an audit log (reproduces #711)."
            ),
            evidence={
                "decisions_count": decisions,
                "audit_export.configured": configured,
                "audit_export.log_total_events": total_events,
            },
            next_steps=(
                "This is expected when ibounce is running in observation-only mode "
                "without an audit log path configured. To enable audit logging, "
                "restart ibounce with --audit-log-path=/var/log/ibounce/audit.jsonl "
                "or set IAM_JIT_AUDIT_LOG_PATH. "
                "If audit logging IS expected, check the ibounce startup flags."
            ),
        )
    return None


def _check_v2_audit_configured_not_writing(
    current_ibounce: dict[str, Any] | None,
    prev_ibounce: dict[str, Any] | None,
) -> Violation | None:
    """VIOLATION-2: audit configured but not writing while decisions are made."""
    if current_ibounce is None or prev_ibounce is None:
        return None
    decisions_now = _ibounce_decisions(current_ibounce) or 0
    decisions_prev = _ibounce_decisions(prev_ibounce) or 0
    if decisions_now <= 0:
        return None
    # Must have seen activity in BOTH samples to know time has passed
    if decisions_prev <= 0:
        return None
    ae_now = _ibounce_audit_export(current_ibounce)
    configured = ae_now.get("configured", False)
    if not configured:
        return None  # VIOLATION-1 handles that case
    total_events_now = ae_now.get("log_total_events", 0) or 0
    ae_prev = _ibounce_audit_export(prev_ibounce)
    total_events_prev = ae_prev.get("log_total_events", 0) or 0
    # If configured + decisions are happening but 0 events written still
    if total_events_now == 0 and decisions_now > decisions_prev:
        return Violation(
            code="VIOLATION-2",
            severity=SEVERITY_ERROR,
            bouncer="ibounce",
            message=(
                f"audit_export.configured=True but log_total_events=0 while "
                f"decisions_count grew from {decisions_prev} to {decisions_now}. "
                f"Audit is configured but NOT writing events."
            ),
            evidence={
                "audit_export.configured": configured,
                "audit_export.log_total_events_now": total_events_now,
                "audit_export.log_total_events_prev": total_events_prev,
                "decisions_count_now": decisions_now,
                "decisions_count_prev": decisions_prev,
                "log_last_error": ae_now.get("log_last_error"),
                "log_path": ae_now.get("log_path"),
            },
            next_steps=(
                "Check ibounce logs for write errors. Verify the audit log path "
                "is writable and has sufficient disk space. "
                "Check audit_export.log_last_error for the specific error."
            ),
        )
    return None


def _check_v3_counter_regression(
    current: dict[str, Any] | None,
    prev: dict[str, Any] | None,
    bouncer: str,
    counter_path: str,
    extractor: Any,
) -> Violation | None:
    """VIOLATION-3: a monotonic counter decreased between samples."""
    if current is None or prev is None:
        return None
    val_now = extractor(current)
    val_prev = extractor(prev)
    if val_now is None or val_prev is None:
        return None
    if val_now < val_prev:
        return Violation(
            code="VIOLATION-3",
            severity=SEVERITY_ERROR,
            bouncer=bouncer,
            message=(
                f"{counter_path} decreased from {val_prev} to {val_now}. "
                f"Counter regression — possible silent restart or reset."
            ),
            evidence={
                "counter": counter_path,
                "previous_value": val_prev,
                "current_value": val_now,
            },
            next_steps=(
                f"Check if {bouncer} restarted unexpectedly between samples. "
                f"Review process logs. If restarted, this is expected; "
                f"if not, it indicates a counter reset bug."
            ),
        )
    return None


def _check_v4_posture_healthz_mismatch(
    posture: dict[str, Any] | None,
    ibounce_healthz_ok: bool,
    gbounce_healthz_ok: bool,
) -> list[Violation]:
    """VIOLATION-4: posture says RUNNING but /healthz returned non-200."""
    violations: list[Violation] = []
    if posture is None:
        return violations
    bouncers = posture.get("bouncers") or {}

    # ibounce
    ibounce_posture = bouncers.get("ibounce") or {}
    posture_says_running_ibounce = ibounce_posture.get("running", False)
    if posture_says_running_ibounce and not ibounce_healthz_ok:
        violations.append(Violation(
            code="VIOLATION-4",
            severity=SEVERITY_ERROR,
            bouncer="ibounce",
            message=(
                "posture says ibounce is RUNNING but /healthz returned non-200 "
                "(or was unreachable). Cross-component state mismatch."
            ),
            evidence={
                "posture.ibounce.running": posture_says_running_ibounce,
                "ibounce_healthz_reachable": ibounce_healthz_ok,
            },
            next_steps=(
                "Check ibounce process: `ps aux | grep ibounce`. "
                "The posture module may cache stale state."
            ),
        ))
    elif not posture_says_running_ibounce and ibounce_healthz_ok:
        violations.append(Violation(
            code="VIOLATION-4",
            severity=SEVERITY_WARN,
            bouncer="ibounce",
            message=(
                "posture says ibounce is NOT running but /healthz returned 200. "
                "Posture underreports — agent asking posture would not enable ibounce features."
            ),
            evidence={
                "posture.ibounce.running": posture_says_running_ibounce,
                "ibounce_healthz_reachable": ibounce_healthz_ok,
            },
            next_steps=(
                "The posture module checks a different signal than /healthz. "
                "Check posture.py probe logic for ibounce detection."
            ),
        ))

    # gbounce
    gbounce_posture = bouncers.get("gbounce") or {}
    posture_says_running_gbounce = gbounce_posture.get("running", False)
    if posture_says_running_gbounce and not gbounce_healthz_ok:
        violations.append(Violation(
            code="VIOLATION-4",
            severity=SEVERITY_ERROR,
            bouncer="gbounce",
            message=(
                "posture says gbounce is RUNNING but /healthz returned non-200 "
                "(or was unreachable). Cross-component state mismatch."
            ),
            evidence={
                "posture.gbounce.running": posture_says_running_gbounce,
                "gbounce_healthz_reachable": gbounce_healthz_ok,
            },
            next_steps=(
                "Check gbounce process: `ps aux | grep gbounce`. "
                "The posture module may cache stale state."
            ),
        ))
    elif not posture_says_running_gbounce and gbounce_healthz_ok:
        violations.append(Violation(
            code="VIOLATION-4",
            severity=SEVERITY_WARN,
            bouncer="gbounce",
            message=(
                "posture says gbounce is NOT running but /healthz returned 200. "
                "Posture underreports — agent asking posture would not enable gbounce features."
            ),
            evidence={
                "posture.gbounce.running": posture_says_running_gbounce,
                "gbounce_healthz_reachable": gbounce_healthz_ok,
            },
            next_steps=(
                "The posture module checks a different signal than /healthz. "
                "Check posture.py probe logic for gbounce detection."
            ),
        ))
    return violations


def _check_v5_audit_degraded_mismatch(
    posture: dict[str, Any] | None,
    ibounce_healthz: dict[str, Any] | None,
    gbounce_healthz: dict[str, Any] | None,
) -> list[Violation]:
    """VIOLATION-5: posture audit_log.status and /healthz disagree on degraded."""
    violations: list[Violation] = []
    if posture is None:
        return violations

    # ibounce
    if ibounce_healthz is not None:
        posture_ibounce = (posture.get("bouncers") or {}).get("ibounce") or {}
        posture_disk = posture_ibounce.get("disk_pressure") or {}
        posture_audit_status = posture_disk.get("status") or "unknown"
        healthz_audit_log = _ibounce_audit_log(ibounce_healthz)
        healthz_status = healthz_audit_log.get("status") or "unknown"
        posture_degraded = "degraded" in posture_audit_status.lower()
        healthz_degraded = "degraded" in healthz_status.lower()
        if posture_degraded != healthz_degraded:
            violations.append(Violation(
                code="VIOLATION-5",
                severity=SEVERITY_WARN,
                bouncer="ibounce",
                message=(
                    f"posture says ibounce audit_log.status={posture_audit_status!r} "
                    f"but /healthz says audit_log.status={healthz_status!r}. "
                    f"Degraded-state mismatch."
                ),
                evidence={
                    "posture.disk_pressure.status": posture_audit_status,
                    "healthz.audit_log.status": healthz_status,
                },
                next_steps=(
                    "The posture module and /healthz probe different fields. "
                    "One of them may be stale. "
                    "Check ibounce restart time and posture capture time."
                ),
            ))

    # gbounce: check misconfig flag in posture vs healthz status
    # Note: posture does not surface gbounce audit_log.status directly —
    # it only provides misconfig + mode.  V5 fires when posture explicitly
    # marks gbounce as misconfigured (misconfig != None) but /healthz says
    # ok, or vice versa.
    if gbounce_healthz is not None:
        posture_gbounce = (posture.get("bouncers") or {}).get("gbounce") or {}
        posture_misconfig = posture_gbounce.get("misconfig")
        healthz_al = _gbounce_audit_log(gbounce_healthz)
        healthz_status = healthz_al.get("status") or "unknown"
        healthz_bouncer_status = gbounce_healthz.get("status") or "unknown"
        # Only flag if posture says bouncer is misconfigured but /healthz says ok
        if posture_misconfig is not None and "ok" in healthz_bouncer_status.lower():
            violations.append(Violation(
                code="VIOLATION-5",
                severity=SEVERITY_WARN,
                bouncer="gbounce",
                message=(
                    f"posture.gbounce.misconfig={posture_misconfig!r} "
                    f"but /healthz.status={healthz_bouncer_status!r}. "
                    f"Posture and /healthz disagree on gbounce health."
                ),
                evidence={
                    "posture.gbounce.misconfig": posture_misconfig,
                    "healthz.status": healthz_bouncer_status,
                    "healthz.audit_log.status": healthz_status,
                },
                next_steps=(
                    "Investigate the misconfig posture reports for gbounce. "
                    "Run `iam-jit posture` for human-readable detail."
                ),
            ))
    return violations


def _check_v6_denies_fan_out_missing(
    denies_result: dict[str, Any] | None,
    ibounce_healthz_ok: bool,
    gbounce_healthz_ok: bool,
) -> Violation | None:
    """VIOLATION-6: running bouncer absent from denies fan-out results."""
    if denies_result is None:
        return None
    succeeded: list[str] = []
    # denies recent --json shape: bouncers_succeeded int, notes list
    # The notes contain "X skipped" for unreachable bouncers
    # bouncers_succeeded is a count not a list, so parse notes for names
    notes = denies_result.get("notes") or []
    attempted = denies_result.get("bouncers_attempted") or 0
    if attempted == 0:
        return None  # no fan-out happened at all
    # Collect skipped bouncer names from notes
    skipped: set[str] = set()
    for note in notes:
        note_lower = note.lower()
        for name in ("ibounce", "gbounce", "kbounce", "dbounce"):
            if name in note_lower and "skipped" in note_lower:
                skipped.add(name)
    missing: list[str] = []
    if ibounce_healthz_ok and "ibounce" in skipped:
        missing.append("ibounce")
    if gbounce_healthz_ok and "gbounce" in skipped:
        missing.append("gbounce")
    if missing:
        return Violation(
            code="VIOLATION-6",
            severity=SEVERITY_WARN,
            bouncer="cross-product",
            message=(
                f"Running bouncer(s) {missing} are absent from `iam-jit denies recent` "
                f"fan-out. Events from those bouncers are invisible in cross-product queries."
            ),
            evidence={
                "missing_from_fan_out": missing,
                "skipped": list(skipped),
                "notes": notes,
                "bouncers_attempted": attempted,
            },
            next_steps=(
                "Check if the bouncer's mgmt port is firewalled or if the CLI "
                "is pointed at the wrong port. "
                "Run `iam-jit audit query --format summary` to debug fan-out."
            ),
        )
    return None


def _check_v7_audit_queue_stalled(
    current_ibounce: dict[str, Any] | None,
    consecutive_stall_count: int,
) -> Violation | None:
    """VIOLATION-7: audit queue depth > 0 for too many consecutive samples."""
    if current_ibounce is None:
        return None
    ae = _ibounce_audit_export(current_ibounce)
    capacity = ae.get("queue_capacity") or 0
    depth = ae.get("queue_depth") or 0
    if capacity <= 0:
        return None  # queue not in use
    if depth <= 0:
        return None
    if consecutive_stall_count >= QUEUE_STALL_SAMPLE_THRESHOLD:
        return Violation(
            code="VIOLATION-7",
            severity=SEVERITY_WARN,
            bouncer="ibounce",
            message=(
                f"audit_export queue stalled: depth={depth} capacity={capacity} "
                f"for {consecutive_stall_count} consecutive samples "
                f"(threshold={QUEUE_STALL_SAMPLE_THRESHOLD}). "
                f"Events may be accumulating and not flushing."
            ),
            evidence={
                "queue_depth": depth,
                "queue_capacity": capacity,
                "consecutive_stall_samples": consecutive_stall_count,
            },
            next_steps=(
                "Check ibounce audit log writer. "
                "High queue depth with no drain suggests the writer thread is blocked. "
                "Check disk space, file permissions, and ibounce logs."
            ),
        )
    return None


def _check_v8_false_degraded(
    gbounce_healthz: dict[str, Any] | None,
) -> Violation | None:
    """VIOLATION-8: bouncer reports degraded but disk is not actually under pressure."""
    if gbounce_healthz is None:
        return None
    al = _gbounce_audit_log(gbounce_healthz)
    status = al.get("status") or ""
    if "degraded" not in status.lower():
        return None
    disk_free_pct = al.get("disk_free_pct")
    if disk_free_pct is None:
        return None  # can't judge without data
    try:
        pct = float(disk_free_pct)
    except (TypeError, ValueError):
        return None

    # Respect the bouncer's own warn_pct threshold: if disk_free_pct is
    # below (100 - warn_pct), the bouncer has legitimate grounds to report
    # degraded.  We only flag V8 when free is well above the warn threshold.
    warn_pct = al.get("warn_pct")
    if warn_pct is not None:
        try:
            warn_free_floor = 100.0 - float(warn_pct)
            # Degraded is justified if free <= warn_free_floor + 2% hysteresis
            if pct <= warn_free_floor + 2.0:
                return None  # legitimately within warn zone
        except (TypeError, ValueError):
            pass

    # Also check OS-level free space on the gbounce data path
    audit_path = gbounce_healthz.get("audit_log_path") or "/Users/reagan/.gbounce"
    try:
        usage = shutil.disk_usage(audit_path)
        actual_free_bytes = usage.free
    except (OSError, FileNotFoundError):
        actual_free_bytes = None

    # The threshold: if disk_free_pct > DISK_FREE_HONEST_PCT AND
    # actual free > DISK_FREE_HONEST_BYTES, the degraded claim is
    # suspicious. (We skip the absolute-free check if we can't read
    # the filesystem.)
    if pct <= DISK_FREE_HONEST_PCT:
        return None  # genuinely low disk
    if actual_free_bytes is not None and actual_free_bytes <= DISK_FREE_HONEST_BYTES:
        return None  # genuinely low disk (different mount-point view)

    return Violation(
        code="VIOLATION-8",
        severity=SEVERITY_WARN,
        bouncer="gbounce",
        message=(
            f"gbounce /healthz audit_log.status={status!r} (degraded) "
            f"but disk_free_pct={pct:.1f}% > {DISK_FREE_HONEST_PCT}% threshold"
            + (
                f" and actual_free={actual_free_bytes // (1024**3):.1f} GiB"
                if actual_free_bytes is not None
                else ""
            )
            + ". Degraded claim may be stale or use a mismatched threshold."
        ),
        evidence={
            "healthz.audit_log.status": status,
            "healthz.audit_log.disk_free_pct": disk_free_pct,
            "disk_free_honest_pct_threshold": DISK_FREE_HONEST_PCT,
            "actual_free_bytes": actual_free_bytes,
            "disk_free_honest_bytes_threshold": DISK_FREE_HONEST_BYTES,
        },
        next_steps=(
            "gbounce audit_log.status may reflect a previous high-pressure event "
            "that has since resolved (stale state). "
            "Restart gbounce to clear the degraded status, or increase the disk "
            "warn_pct threshold if disk usage is genuinely near the limit. "
            "See the gbounce disk-threshold fix in flight."
        ),
    )


# -----------------------------------------------------------------
# Public API
# -----------------------------------------------------------------

@dataclass
class SamplePair:
    """A pair of consecutive samples (current + optional previous)
    with all the parsed sub-fields the invariant checks need."""

    # Raw healthz JSON (None if the endpoint was unreachable)
    ibounce_healthz: dict[str, Any] | None
    gbounce_healthz: dict[str, Any] | None
    ibounce_healthz_ok: bool
    gbounce_healthz_ok: bool

    # Posture JSON (None if subprocess failed)
    posture: dict[str, Any] | None

    # denies recent JSON (None if not available)
    denies: dict[str, Any] | None

    # Previous sample's healthz for monotonicity checks
    prev_ibounce_healthz: dict[str, Any] | None = None
    prev_gbounce_healthz: dict[str, Any] | None = None

    # Number of consecutive samples with ibounce audit queue depth > 0
    audit_queue_stall_count: int = 0


def check_invariants(pair: SamplePair) -> list[Violation]:
    """Run all invariant checks against the given sample pair.

    Returns a list of Violation objects (may be empty).  Never raises —
    individual checks are wrapped in try/except so one broken extractor
    cannot silence subsequent checks.
    """
    violations: list[Violation] = []

    def _safe(fn: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            violations.append(Violation(
                code="INVARIANT-CHECK-ERROR",
                severity=SEVERITY_WARN,
                bouncer="harness",
                message=f"Invariant check {fn.__name__} raised: {exc}",
                evidence={"exception": str(exc)},
            ))
            return None

    # VIOLATION-1
    v = _safe(_check_v1_silent_audit_gap, pair.ibounce_healthz)
    if v:
        violations.append(v)

    # VIOLATION-2
    v = _safe(
        _check_v2_audit_configured_not_writing,
        pair.ibounce_healthz,
        pair.prev_ibounce_healthz,
    )
    if v:
        violations.append(v)

    # VIOLATION-3: ibounce decisions_count monotonicity
    v = _safe(
        _check_v3_counter_regression,
        pair.ibounce_healthz,
        pair.prev_ibounce_healthz,
        "ibounce",
        "decisions_count",
        _ibounce_decisions,
    )
    if v:
        violations.append(v)

    # VIOLATION-3: ibounce log_total_events monotonicity
    def _ibounce_log_total(h: dict[str, Any]) -> int | None:
        ae = _ibounce_audit_export(h)
        v2 = ae.get("log_total_events")
        return int(v2) if isinstance(v2, int) else None

    v = _safe(
        _check_v3_counter_regression,
        pair.ibounce_healthz,
        pair.prev_ibounce_healthz,
        "ibounce",
        "audit_export.log_total_events",
        _ibounce_log_total,
    )
    if v:
        violations.append(v)

    # VIOLATION-3: gbounce audit_log_total monotonicity
    v = _safe(
        _check_v3_counter_regression,
        pair.gbounce_healthz,
        pair.prev_gbounce_healthz,
        "gbounce",
        "audit_log_total",
        _gbounce_audit_total,
    )
    if v:
        violations.append(v)

    # VIOLATION-4: posture / healthz running-state mismatch
    v4_list = _safe(
        _check_v4_posture_healthz_mismatch,
        pair.posture,
        pair.ibounce_healthz_ok,
        pair.gbounce_healthz_ok,
    )
    if v4_list:
        violations.extend(v4_list)

    # VIOLATION-5: audit degraded mismatch
    v5_list = _safe(
        _check_v5_audit_degraded_mismatch,
        pair.posture,
        pair.ibounce_healthz,
        pair.gbounce_healthz,
    )
    if v5_list:
        violations.extend(v5_list)

    # VIOLATION-6: denies fan-out missing running bouncer
    v = _safe(
        _check_v6_denies_fan_out_missing,
        pair.denies,
        pair.ibounce_healthz_ok,
        pair.gbounce_healthz_ok,
    )
    if v:
        violations.append(v)

    # VIOLATION-7: audit queue stalled
    v = _safe(
        _check_v7_audit_queue_stalled,
        pair.ibounce_healthz,
        pair.audit_queue_stall_count,
    )
    if v:
        violations.append(v)

    # VIOLATION-8: false degraded (gbounce)
    v = _safe(_check_v8_false_degraded, pair.gbounce_healthz)
    if v:
        violations.append(v)

    return violations


__all__ = [
    "Violation",
    "SamplePair",
    "check_invariants",
    "QUEUE_STALL_SAMPLE_THRESHOLD",
    "DISK_FREE_HONEST_PCT",
    "DISK_FREE_HONEST_BYTES",
    "SEVERITY_ERROR",
    "SEVERITY_WARN",
    "SEVERITY_INFO",
]
