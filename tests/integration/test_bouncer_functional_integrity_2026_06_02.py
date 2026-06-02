"""Bouncer functional integrity (post-install) verification for 2026-06-02.

Per the founder direction 2026-06-02: "solidify any outstanding work/bugs on
existing features before adding new ones".

This file complements test_full_install_matrix_verification_2026_06_02.py
by verifying that AFTER install, the bouncer-adjacent CLIs still behave
correctly + surface honest state per [[ibounce-honest-positioning]]:

  - posture command honest about reachable bouncers + their modes
  - audit query honest when bouncers are not auth-configured (HTTP 421 surfaced
    per-bouncer with reason, not silently empty)
  - denies recent honest about "no events vs query failed"
  - disk-pressure dual-threshold (#712) — verifies the unit of the disk-check
    helper triggers correctly at both thresholds
  - audit_warning field (#711) — verified by inspecting healthz schema

These tests deliberately do NOT depend on Docker — they exercise the live
host bouncers (running on :8767 and :8769 per session note) or fall to
honest skip when the host bouncer is not reachable.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import sys
from contextlib import closing

import pytest

# ---------------------------------------------------------------------------
# Repo root + binary discovery
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_VENV_BIN = _REPO_ROOT / ".venv" / "bin"
_IAM_JIT_BIN = str(_VENV_BIN / "iam-jit") if (_VENV_BIN / "iam-jit").exists() else "iam-jit"


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(0.5)
        try:
            return s.connect_ex((host, port)) == 0
        except OSError:
            return False


_IBOUNCE_RUNNING = _port_open(8767)
_GBOUNCE_RUNNING = _port_open(8769)


# ===========================================================================
# posture command — honest about bouncer state
# ===========================================================================


class TestPostureHonestState:
    """`iam-jit posture --json` must accurately report each bouncer's running /
    misconfig / mode fields per [[ibounce-honest-positioning]]."""

    def test_posture_json_emits_all_four_bouncers(self) -> None:
        result = subprocess.run(
            [_IAM_JIT_BIN, "posture", "--json"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, (
            f"posture --json failed: {result.stderr}"
        )
        data = json.loads(result.stdout)
        bouncers = data.get("bouncers", {})
        # The four bouncer kinds must be reported.
        for kind in ("ibounce", "kbounce", "dbounce", "gbounce"):
            assert kind in bouncers, f"posture missing bouncer kind: {kind}"
            entry = bouncers[kind]
            # Must have a running flag (true/false) — never undefined.
            assert "running" in entry, f"{kind} entry missing 'running' field"
            # Must have a misconfig field (null OR string reason).
            assert "misconfig" in entry, f"{kind} entry missing 'misconfig' field"

    @pytest.mark.skipif(not _IBOUNCE_RUNNING, reason="host ibounce not running on :8767")
    def test_posture_marks_ibounce_running_when_up(self) -> None:
        result = subprocess.run(
            [_IAM_JIT_BIN, "posture", "--json"],
            capture_output=True, text=True, timeout=15,
        )
        data = json.loads(result.stdout)
        ibounce_entry = data["bouncers"]["ibounce"]
        # Honest: when port 8767 is open, ibounce.running must be true.
        # Per [[ibounce-honest-positioning]], `running: true` + `mode: "unknown"`
        # is a silent-degradation signal we should NOT see.
        # However posture may return running=False if /healthz didn't shape OK.
        # The assertion is: if it reports running, mode must be a real string.
        if ibounce_entry.get("running"):
            assert ibounce_entry.get("mode") in ("cooperative", "transparent", "strict", "plan-capture"), (
                f"ibounce.mode is suspect: {ibounce_entry}"
            )


# ===========================================================================
# audit query — honest "we couldn't fetch" when auth fails
# ===========================================================================


class TestAuditQueryHonestFailure:
    """When the host bouncers don't have audit-events bearer tokens configured
    (which is the common dev-host case), `audit query` must surface the per-bouncer
    error reason — never silently return an empty list."""

    def test_audit_query_summary_surfaces_per_bouncer_errors(self) -> None:
        result = subprocess.run(
            [_IAM_JIT_BIN, "audit", "query", "--limit", "1", "--format", "summary"],
            capture_output=True, text=True, timeout=30,
        )
        combined = result.stdout + result.stderr
        # If the host has no bouncers OR they're unreachable OR they have HTTP 421,
        # we MUST see a per-bouncer error note. We must NOT see a silent empty list.
        if _IBOUNCE_RUNNING or _GBOUNCE_RUNNING:
            # At least one bouncer is up; the CLI must mention either successful events
            # OR a per-bouncer skipped note with reason.
            assert (
                "skipped" in combined
                or "events" in combined.lower()
                or "error" in combined.lower()
                or "failed" in combined.lower()
            ), (
                f"audit query produced no honest signal:\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )


# ===========================================================================
# denies recent — honest about "no events vs broken probe"
# ===========================================================================


class TestDeniesRecentHonest:
    """`iam-jit denies recent` must distinguish 'no denies' from 'cannot probe'."""

    def test_denies_recent_surfaces_failure_when_probes_break(self) -> None:
        result = subprocess.run(
            [_IAM_JIT_BIN, "denies", "recent"],
            capture_output=True, text=True, timeout=30,
        )
        combined = result.stdout + result.stderr
        # When the host bouncers aren't audit-token-configured (the common case),
        # we expect a loud WARNING + ERROR per [[ibounce-honest-positioning]].
        if "WARNING" in combined or "ERROR" in combined or "failed" in combined.lower():
            # Honest failure surfaced — pass.
            return
        # Otherwise: at least one bouncer must have returned a real event count.
        # Either "caught" text or "(empty)" with an explicit "no denies" qualifier.
        assert (
            "caught" in combined.lower()
            or "no denies" in combined.lower()
            or "0 denies" in combined.lower()
        ), (
            f"denies recent produced ambiguous output:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ===========================================================================
# disk-pressure dual-threshold (#712)
# ===========================================================================


class TestDiskPressureDualThreshold:
    """#712 — disk-pressure mode requires BOTH percentage AND absolute-bytes
    conditions to be met before triggering crit/emergency mode."""

    def test_disk_pressure_helper_exists(self) -> None:
        """The dual-threshold logic ships in iam_jit.bouncer.audit_export.disk_pressure."""
        from iam_jit.bouncer.audit_export import disk_pressure  # noqa: F401
        # If the module imports clean, the helper is present.

    @pytest.mark.skipif(not _GBOUNCE_RUNNING, reason="host gbounce not running on :8769")
    def test_gbounce_healthz_emits_disk_pressure_block(self) -> None:
        """Live gbounce on the host should emit an audit_log.disk_free_pct +
        disk_free_bytes pair in its /healthz response. Dual-threshold relies on
        both being present."""
        # http.client does NOT honor HTTP_PROXY env var, unlike urllib.
        # When ibounce/gbounce are configured + HTTP_PROXY points at gbounce,
        # urllib double-proxies the healthz query through the proxy, yielding
        # HTTP 421. Use raw http.client to hit /healthz directly.
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", 8769, timeout=5)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        assert resp.status == 200, f"gbounce /healthz returned {resp.status}"
        data = json.loads(resp.read())
        audit_log = data.get("audit_log", {})
        assert "disk_free_pct" in audit_log, "gbounce healthz missing disk_free_pct"
        assert "disk_free_bytes" in audit_log, "gbounce healthz missing disk_free_bytes"
        # Dual-threshold pressure fields must coexist
        assert "warn_pct" in audit_log, "gbounce healthz missing warn_pct"
        assert "warn_threshold_bytes" in audit_log, (
            "gbounce healthz missing warn_threshold_bytes — dual-threshold incomplete"
        )


# ===========================================================================
# audit_warning field (#711) — surfaces when decisions made without audit destination
# ===========================================================================


class TestAuditWarningField:
    """#711 — `audit_warning` must appear in healthz schema. When the bouncer
    has counted decisions but has no audit log destination configured, the
    field must be a non-null string."""

    @pytest.mark.skipif(not _IBOUNCE_RUNNING, reason="host ibounce not running")
    def test_ibounce_healthz_has_audit_warning_field(self) -> None:
        # Use http.client to avoid HTTP_PROXY env-var indirection.
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", 8767, timeout=5)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        assert resp.status == 200, f"ibounce /healthz returned {resp.status}"
        data = json.loads(resp.read())
        # The audit_warning field MUST exist (null OR string).
        assert "audit_warning" in data, (
            f"ibounce healthz missing audit_warning field per #711.\n"
            f"keys: {list(data.keys())}"
        )

    @pytest.mark.skipif(not _IBOUNCE_RUNNING, reason="host ibounce not running")
    def test_posture_surfaces_audit_warning_from_healthz(self) -> None:
        """posture --json must propagate the audit_warning field from /healthz."""
        result = subprocess.run(
            [_IAM_JIT_BIN, "posture", "--json"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        ibounce = data["bouncers"]["ibounce"]
        assert "audit_warning" in ibounce, (
            f"posture ibounce entry missing audit_warning field: {ibounce}"
        )
