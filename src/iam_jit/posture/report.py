"""Top-level posture-snapshot assembly + human renderer.

Public API:
  * ``capture_posture()`` — assemble the structured dict (used by the
    `iam-jit posture --json` CLI + the `iam_jit_posture` MCP tool).
  * ``render_posture_human(snapshot)`` — render the structured dict
    as the human banner the `iam-jit posture` CLI prints by default.

Schema stability: ``POSTURE_SCHEMA_VERSION`` is bumped on any
breaking change. Per [[config-export-wire-divergence]] this is a
STRING (matches ibounce/audit-export wire conventions).
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from .bouncers import detect_all_bouncers
from .identity import detect_iam_jit_role
from .sanitize import sanitize_posture
from .traffic import (
    derive_overall_mode,
    derive_tips,
    has_unprotected_traffic,
    summarize_traffic,
)

POSTURE_SCHEMA_VERSION = "1.0"


def capture_posture(*, sanitize: bool = True) -> dict[str, Any]:
    """Assemble the full posture snapshot.

    Always safe to call (never raises; each sub-detector is
    fail-soft). When ``sanitize`` is True (default + recommended) the
    result is run through the credential-scrubbing pass before
    returning.
    """
    identity = detect_iam_jit_role()
    bouncers = detect_all_bouncers()
    effective = summarize_traffic(bouncers)
    tips = derive_tips(
        identity=identity, bouncers=bouncers, effective=effective
    )
    overall = derive_overall_mode(identity=identity, effective=effective)
    snapshot: dict[str, Any] = {
        "schema_version": POSTURE_SCHEMA_VERSION,
        "captured_at": _dt.datetime.now(_dt.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "overall_mode": overall,
        "iam_jit": identity,
        "bouncers": bouncers,
        "effective_protection": effective,
        "unprotected_traffic_present": has_unprotected_traffic(effective),
        "tips": tips,
    }
    if sanitize:
        snapshot = sanitize_posture(snapshot)
    return snapshot


# ---------------------------------------------------------------------------
# Human renderer
# ---------------------------------------------------------------------------


def _fmt_iam_jit_block(identity: dict[str, Any]) -> list[str]:
    arn = identity.get("role_arn") or "(no role ARN visible in env)"
    scoped = identity.get("scoped_role_active")
    src = identity.get("ambient_credential_source") or "unknown"
    evidence = identity.get("iam_jit_issued_evidence") or []
    notes = identity.get("notes") or []
    lines = ["Identity:"]
    if scoped is True:
        lines.append(f"  AWS: {arn}  [iam-jit-issued]")
    elif scoped is False:
        lines.append(f"  AWS: {arn}  [NOT iam-jit issued]")
    else:
        lines.append(f"  AWS: {arn}  [iam-jit origin: unknown]")
    lines.append(f"       Source: {src}")
    for e in evidence:
        lines.append(f"       Evidence: {e}")
    for n in notes:
        lines.append(f"       Note: {n}")
    return lines


def _fmt_bouncers_block(bouncers: dict[str, Any]) -> list[str]:
    lines = ["Bouncers:"]
    for name in ("ibounce", "kbounce", "dbounce", "gbounce"):
        b = bouncers.get(name, {})
        running = "RUNNING" if b.get("running") else "STOPPED"
        port = b.get("port", "?")
        line = f"  {name}: {running}"
        if b.get("running"):
            line += f" on 127.0.0.1:{port}"
        lines.append(line)
        if b.get("running"):
            mode = b.get("mode") or "unknown"
            profile = b.get("active_profile") or "unknown"
            extra = f"    Mode: {mode}   Profile: {profile}"
            lines.append(extra)
        if b.get("env_var_pointing_here"):
            lines.append(f"    Env: {b['env_var_pointing_here']}")
        if b.get("misconfig"):
            lines.append(f"    MISCONFIG: {b['misconfig']}")
        # #424 / §A63 — surface disk-pressure state per bouncer when
        # /healthz (or in-process state) provided it. Always present
        # in the snapshot when the bouncer is running; framed per
        # [[ambient-value-prop-and-friction-framing]] (informational
        # by default; recommendation surfaces only at degraded /
        # critical / emergency).
        _dp = b.get("disk_pressure")
        if _dp:
            _dp_status = _dp.get("status") or "unknown"
            _dp_mode = _dp.get("disk_pressure_mode") or "unknown"
            _dp_used = _dp.get("used_pct")
            _dp_archives = _dp.get("current_archive_count") or 0
            _used_str = (
                f"{_dp_used:.1f}% used"
                if isinstance(_dp_used, (int, float)) else "n/a"
            )
            lines.append(
                f"    Disk: {_dp_status} ({_used_str})  "
                f"Mode: {_dp_mode}  "
                f"Archives: {_dp_archives}"
            )
            _dp_rec = b.get("disk_pressure_recommendation")
            if _dp_rec:
                lines.append(f"    DISK PRESSURE: {_dp_rec}")
            # #499 / §A76b — anomaly-detection surface. Always present
            # (None when the hook is NOT installed) so an operator can
            # answer "is this bouncer scoring requests?" at a glance.
            _ad = b.get("anomaly_detection")
            if _ad is None:
                lines.append("    Anomaly detection: off")
            elif _ad.get("enabled"):
                _ad_mode = _ad.get("mode") or "unknown"
                _ad_sens = _ad.get("sensitivity") or "unknown"
                _ad_count = _ad.get("alerts_emitted_total", 0)
                lines.append(
                    f"    Anomaly detection: enabled "
                    f"(mode={_ad_mode}, sensitivity={_ad_sens}, "
                    f"alerts_emitted={_ad_count})"
                )
            else:
                lines.append("    Anomaly detection: off")
    return lines


_TRAFFIC_LABELS = {
    "aws_calls": "AWS",
    "k8s_calls": "K8s",
    "db_calls": "DB",
    "http_calls": "HTTP",
}


def _fmt_effective_block(effective: dict[str, Any]) -> list[str]:
    lines = ["Effective protection:"]
    for key, label in _TRAFFIC_LABELS.items():
        e = effective.get(key, {})
        intercepted = e.get("intercepted_by")
        if intercepted:
            mode = e.get("mode") or "unknown"
            verb = "ENFORCE" if e.get("enforces_denials") else "OBSERVE"
            lines.append(
                f"  {label:<4} -> {intercepted} ({mode.upper()} — {verb})"
            )
            if not e.get("enforces_denials"):
                lines.append(
                    f"        WARNING: {e.get('warning') or 'does not enforce denials'}"
                )
        else:
            lines.append(f"  {label:<4} -> DIRECT  (UNPROTECTED)")
            warn = e.get("warning")
            if warn:
                lines.append(f"        {warn}")
    return lines


def _fmt_tips_block(tips: list[str]) -> list[str]:
    if not tips:
        return []
    lines = ["", "Recommendations:"]
    for t in tips:
        lines.append(f"  - {t}")
    return lines


def render_posture_human(snapshot: dict[str, Any]) -> str:
    """Render a posture snapshot as the human-readable banner.

    Stable output shape (tests pin section headers): three blocks
    (Identity / Bouncers / Effective protection) + optional
    Recommendations. The first line is a banner naming the overall
    mode so a glance suffices.
    """
    lines: list[str] = []
    lines.append("== iam-jit posture ==")
    lines.append(f"Overall: {snapshot.get('overall_mode', 'unknown')}")
    lines.append(f"Captured: {snapshot.get('captured_at', '?')}")
    lines.append("")
    lines.extend(_fmt_iam_jit_block(snapshot.get("iam_jit", {})))
    lines.append("")
    lines.extend(_fmt_bouncers_block(snapshot.get("bouncers", {})))
    lines.append("")
    lines.extend(_fmt_effective_block(snapshot.get("effective_protection", {})))
    lines.extend(_fmt_tips_block(snapshot.get("tips") or []))
    return "\n".join(lines)
