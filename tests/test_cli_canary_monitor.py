"""Tests for `iam-jit canary monitor` (#542 / MRR-5 §M1).

Per ``docs/CONTRIBUTING.md`` state-verification convention: every test
that asserts a reported success status MUST also assert the observable
state matches. Each test pairs the snapshot/exit-code claim with an
observable assertion (per-signal status mapping, monitor.state.json
contents, mocked /healthz reads).

These tests verify the §M1 acceptance criterion: operator can self-
monitor the 11 documented MRR-5 signals via a single subcommand with
cron-friendly JSON + watch-mode + exit-code semantics.
"""

from __future__ import annotations

import json
import pathlib
from unittest import mock

import pytest
from click.testing import CliRunner

import iam_jit.cli_canary as cc
from iam_jit.cli import main


@pytest.fixture
def isolated_canary(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Point all canary-module paths at a tmp dir (per existing fixture
    pattern in tests/test_cli_canary.py)."""
    canary_dir = tmp_path / "canary"
    canary_dir.mkdir()
    monkeypatch.setattr(cc, "CANARY_DIR", canary_dir)
    monkeypatch.setattr(cc, "ISSUES_PATH", canary_dir / "issues.jsonl")
    monkeypatch.setattr(cc, "NOTES_PATH", canary_dir / "notes.md")
    monkeypatch.setattr(cc, "STATUS_PATH", canary_dir / "status.json")
    monkeypatch.setattr(cc, "URLS_PATH", canary_dir / "urls.md")
    monkeypatch.setattr(
        cc, "MONITOR_STATE_PATH", canary_dir / "monitor.state.json",
    )
    return canary_dir


def _write_status(canary_dir: pathlib.Path, status: dict) -> None:
    (canary_dir / "status.json").write_text(
        json.dumps(status, indent=2, sort_keys=True), encoding="utf-8",
    )


# Shared healthz responses ---------------------------------------------------

_HEALTHZ_OK_IBOUNCE = {
    "bouncer_kind": "ibounce",
    "status": "ok",
    "mode": "cooperative",
    "default_policy": "deny",
    "active_profile": "full-user",
    "decisions_count": 37,
    "audit_log": {
        "status": "ok",
        "disk_free_pct": 87.0,
        "warn_pct": 15,
        "crit_pct": 5,
    },
    "audit_export": {
        "configured": False,
        "webhook_configured": False,
        "queue_depth": 0,
        "queue_capacity": 0,
        "dropped_count_since_start": 0,
        "webhook_consecutive_failures": 0,
    },
    "dynamic_denies": {
        "enabled": True,
        "rules_count": 0,
        "rules_in_file": 0,
        "total_reloads": 0,
        "total_parse_errors": 0,
        "initial_load_error": None,
    },
    "anomaly_detection": None,
    "llm_skips": {"total": 0, "counts": {}, "by_reason": {}, "last_skips": []},
    "heartbeat": None,
}

_HEALTHZ_OK_GBOUNCE = {
    "product": "gbounce",
    "status": "ok",
    "mode": "discovery",
    "upstream": "",
    "audit_log": {
        "status": "ok",
        "disk_free_pct": None,
        "warn_pct": 85,
        "crit_pct": 95,
    },
    "dynamic_denies_enabled": True,
    "dynamic_denies_count": 0,
    "total_requests": 19,
}


def _status_two_bouncers() -> dict:
    return {
        "canary_day": 2,
        "bouncers": {"ibounce": "discovery", "gbounce": "discovery"},
        "pids": {"ibounce": 99225, "gbounce": 99403},
        "ports": {
            "ibounce": 7401,
            "gbounce": 7402,
            "gbounce_mgmt": 7412,
        },
    }


def _patch_pid_alive(monkeypatch, alive_pids: set[int]) -> None:
    monkeypatch.setattr(
        cc, "_pid_alive", lambda pid: int(pid) in alive_pids,
    )


def _patch_healthz(
    monkeypatch, body_by_url: dict[str, dict | None],
    status_by_url: dict[str, int] | None = None,
) -> None:
    """Replace cc._fetch_healthz_json with a mapper.

    ``body_by_url`` maps the full /healthz URL to the response body
    (dict for success; None for unreachable).
    """
    def fake_fetch(url, timeout=3.0):
        body = body_by_url.get(url)
        if body is None:
            return None, None, "unreachable: mocked"
        status = (status_by_url or {}).get(url, 200)
        return body, status, None
    monkeypatch.setattr(cc, "_fetch_healthz_json", fake_fetch)


def _patch_threat_feed_no_subs(monkeypatch) -> None:
    """Threat-feed signal degrades to UNKNOWN/GREEN depending on
    importability; mock the loader to return zero subscriptions which
    yields a GREEN signal with a 'no subscriptions declared' note."""
    fake_load = mock.MagicMock(return_value=([], None, "none"))
    try:
        import iam_jit.cli_updates as cu
        monkeypatch.setattr(cu, "_load_subscriptions", fake_load)
    except Exception:
        # If cli_updates can't import, the signal will UNKNOWN itself.
        pass


def _patch_chain_unknown(monkeypatch) -> None:
    """Force audit_chain_continuity to UNKNOWN (no log dir)."""
    monkeypatch.delenv("IAM_JIT_AUDIT_LOG_PATH", raising=False)


# -- Test 1: all-green snapshot --------------------------------------------


def test_all_green(isolated_canary, monkeypatch):
    """All 11 signals GREEN or UNKNOWN-with-notes → exit 0."""
    _write_status(isolated_canary, _status_two_bouncers())
    _patch_pid_alive(monkeypatch, {99225, 99403})
    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": _HEALTHZ_OK_IBOUNCE,
        "http://127.0.0.1:7412/healthz": _HEALTHZ_OK_GBOUNCE,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "monitor", "--json"])

    # 1. The claim: exit 0 + overall_status GREEN.
    assert result.exit_code == 0, result.output
    snapshot = json.loads(result.output)
    assert snapshot["overall_status"] == "GREEN"

    # 2. Observable: the snapshot lists 11 signals, none CRIT, none
    #    WARNING. UNKNOWN allowed (heartbeat opt-out, chain not
    #    configured) but doesn't degrade overall when other GREENs.
    assert len(snapshot["signals"]) == 11
    assert snapshot["crit_count"] == 0
    assert snapshot["warning_count"] == 0

    # 3. Observable: monitor.state.json was persisted (rate-baseline
    #    for next poll).
    state_path = isolated_canary / "monitor.state.json"
    assert state_path.exists()
    state = json.loads(state_path.read_text())
    assert "decisions" in state
    assert "ibounce" in state["decisions"]
    assert state["decisions"]["ibounce"]["total"] == 37


# -- Test 2: one warning -> exit 1 ------------------------------------------


def test_one_warning(isolated_canary, monkeypatch):
    """One WARNING-shape signal (disk free below warn threshold) →
    exit 1 + overall_status WARNING."""
    _write_status(isolated_canary, _status_two_bouncers())
    _patch_pid_alive(monkeypatch, {99225, 99403})

    warn_ibounce = json.loads(json.dumps(_HEALTHZ_OK_IBOUNCE))
    warn_ibounce["audit_log"]["disk_free_pct"] = 10.0  # < warn 15

    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": warn_ibounce,
        "http://127.0.0.1:7412/healthz": _HEALTHZ_OK_GBOUNCE,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "monitor", "--json"])

    # 1. Claim: exit 1 + overall WARNING.
    assert result.exit_code == 1, result.output
    snapshot = json.loads(result.output)
    assert snapshot["overall_status"] == "WARNING"

    # 2. Observable: the disk_pressure signal is the one in WARNING.
    disk_sig = next(
        s for s in snapshot["signals"] if s["name"] == "disk_pressure"
    )
    assert disk_sig["status"] == "WARNING"
    assert disk_sig["per_bouncer"]["ibounce"]["disk_free_pct"] == 10.0
    assert snapshot["warning_count"] >= 1
    assert snapshot["crit_count"] == 0


# -- Test 3: one crit -> exit 2 --------------------------------------------


def test_one_crit(isolated_canary, monkeypatch):
    """Disk_free_pct < 5 → CRIT → exit 2 + overall_status CRIT."""
    _write_status(isolated_canary, _status_two_bouncers())
    _patch_pid_alive(monkeypatch, {99225, 99403})

    crit_ibounce = json.loads(json.dumps(_HEALTHZ_OK_IBOUNCE))
    crit_ibounce["audit_log"]["disk_free_pct"] = 4.0  # < crit 5

    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": crit_ibounce,
        "http://127.0.0.1:7412/healthz": _HEALTHZ_OK_GBOUNCE,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "monitor", "--json"])

    assert result.exit_code == 2, result.output
    snapshot = json.loads(result.output)
    assert snapshot["overall_status"] == "CRIT"
    disk_sig = next(
        s for s in snapshot["signals"] if s["name"] == "disk_pressure"
    )
    assert disk_sig["status"] == "CRIT"
    # State verification: MRR-4 halt cross-reference C1 is surfaced for
    # operator routing.
    assert disk_sig["mrr4_halt_condition"] == "C1"
    assert "RB-C1" in (disk_sig["response_procedure"] or "")
    assert snapshot["crit_count"] >= 1


# -- Test 4: unreachable bouncer -> exit 3 (degraded) ----------------------


def test_unreachable_bouncer_unknown(isolated_canary, monkeypatch):
    """All bouncers unreachable + no recorded PIDs (operator hasn't
    fully bootstrapped) → signals marked UNKNOWN + exit 3 (degraded
    monitoring).

    Per MRR-5 Signal 2: a recorded PID that's alive + /healthz
    unreachable IS a CRIT (not UNKNOWN) because the process should be
    serving. To exercise the UNKNOWN path we drop the PIDs from
    status.json — no PID recorded = "no claim to verify against"."""
    status = _status_two_bouncers()
    # Drop pids so bouncer_process_health goes UNKNOWN per
    # `pid is None` branch, NOT CRIT.
    status["pids"] = {}
    _write_status(isolated_canary, status)
    _patch_pid_alive(monkeypatch, set())
    # All /healthz endpoints unreachable.
    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": None,
        "http://127.0.0.1:7412/healthz": None,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "monitor", "--json"])

    # exit 3 = degraded (unreachable bouncers; no real CRIT/WARNING).
    assert result.exit_code == 3, result.output
    snapshot = json.loads(result.output)

    # Observable: both bouncers listed as unreachable in the snapshot.
    assert sorted(snapshot["bouncers_unreachable"]) == [
        "gbounce", "ibounce",
    ]
    # Disk-pressure signal records UNKNOWN per bouncer.
    disk_sig = next(
        s for s in snapshot["signals"] if s["name"] == "disk_pressure"
    )
    assert disk_sig["per_bouncer"]["ibounce"]["status"] == "UNKNOWN"
    assert disk_sig["per_bouncer"]["gbounce"]["status"] == "UNKNOWN"
    # Process-health signal is UNKNOWN (no PID recorded), not CRIT.
    proc_sig = next(
        s for s in snapshot["signals"]
        if s["name"] == "bouncer_process_health"
    )
    assert proc_sig["status"] == "UNKNOWN"


# -- Test 5: JSON output shape ---------------------------------------------


def test_json_output_shape(isolated_canary, monkeypatch):
    """--json output conforms to the documented schema."""
    _write_status(isolated_canary, _status_two_bouncers())
    _patch_pid_alive(monkeypatch, {99225, 99403})
    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": _HEALTHZ_OK_IBOUNCE,
        "http://127.0.0.1:7412/healthz": _HEALTHZ_OK_GBOUNCE,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "monitor", "--json"])
    assert result.exit_code == 0
    snapshot = json.loads(result.output)

    # Documented top-level keys per the §M1 spec.
    for key in (
        "schema_version", "captured_at", "canary_day",
        "overall_status", "exit_code",
        "bouncers_monitored", "bouncers_unreachable",
        "signals", "summary",
        "green_count", "warning_count", "crit_count", "unknown_count",
    ):
        assert key in snapshot, f"missing top-level key: {key!r}"

    assert snapshot["schema_version"] == "1.0"
    assert isinstance(snapshot["signals"], list)
    assert len(snapshot["signals"]) == 11

    # Each signal carries the documented per-signal shape.
    expected_signal_names = {
        "disk_pressure", "bouncer_process_health",
        "audit_chain_continuity", "audit_export_queue",
        "webhook_health", "anomaly_alert_rate",
        "threat_feed", "llm_skips", "decision_rate",
        "dynamic_denies", "heartbeat",
    }
    actual = {s["name"] for s in snapshot["signals"]}
    assert actual == expected_signal_names
    for sig in snapshot["signals"]:
        for key in (
            "name", "mrr5_signal", "status",
            "threshold_warning", "threshold_crit",
            "mrr4_halt_condition", "response_procedure",
            "raw_source",
        ):
            assert key in sig, (
                f"signal {sig.get('name')} missing key {key!r}"
            )
        assert sig["status"] in ("GREEN", "WARNING", "CRIT", "UNKNOWN")
        assert 1 <= sig["mrr5_signal"] <= 11


# -- Test 6: watch mode re-polls + SIGINT-safe ----------------------------


def test_watch_mode_re_polls(isolated_canary, monkeypatch):
    """--watch loops; each iteration writes monitor.state.json. We
    interrupt after 2 iterations with a KeyboardInterrupt to verify
    SIGINT-safety."""
    _write_status(isolated_canary, _status_two_bouncers())
    _patch_pid_alive(monkeypatch, {99225, 99403})
    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": _HEALTHZ_OK_IBOUNCE,
        "http://127.0.0.1:7412/healthz": _HEALTHZ_OK_GBOUNCE,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    iteration_count = {"n": 0}
    real_sleep = cc.time.sleep

    def fake_sleep(seconds):
        iteration_count["n"] += 1
        if iteration_count["n"] >= 2:
            raise KeyboardInterrupt()
        # No actual sleep during tests.
        return None
    monkeypatch.setattr(cc.time, "sleep", fake_sleep)

    runner = CliRunner()
    result = runner.invoke(
        main, ["canary", "monitor", "--json", "--watch", "--interval", "1"],
    )
    # SIGINT-safe: KeyboardInterrupt unwinds cleanly to exit 0.
    assert result.exit_code == 0, result.output
    # Observable: at least 2 JSON snapshots written.
    snapshots_in_output = [
        line for line in result.output.splitlines()
        if line.strip().startswith("{")
    ]
    # Each indent=2 snapshot spans many lines; instead count the
    # number of `"schema_version"` occurrences (1 per snapshot).
    assert result.output.count('"schema_version"') >= 2, (
        f"expected >=2 snapshots in --watch output; "
        f"got {result.output.count('schema_version')}"
    )
    # State persistence happened.
    assert (isolated_canary / "monitor.state.json").exists()
    # Restore real sleep for any later teardown.
    monkeypatch.setattr(cc.time, "sleep", real_sleep)


# -- Test 7: MRR-4 cross-ref on warning output ------------------------------


def test_mrr4_cross_ref_in_warning_output(isolated_canary, monkeypatch):
    """A WARNING/CRIT signal carries a response_procedure pointing at
    the MRR-4 RB-xx runbook entry."""
    _write_status(isolated_canary, _status_two_bouncers())
    _patch_pid_alive(monkeypatch, {99225, 99403})

    crit_ibounce = json.loads(json.dumps(_HEALTHZ_OK_IBOUNCE))
    crit_ibounce["audit_log"]["disk_free_pct"] = 4.0  # CRIT

    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": crit_ibounce,
        "http://127.0.0.1:7412/healthz": _HEALTHZ_OK_GBOUNCE,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "monitor", "--json"])
    assert result.exit_code == 2
    snapshot = json.loads(result.output)
    disk_sig = next(
        s for s in snapshot["signals"] if s["name"] == "disk_pressure"
    )

    # Claim: signal is CRIT.
    assert disk_sig["status"] == "CRIT"

    # Observable: MRR-4 halt-condition + response_procedure populated.
    assert disk_sig["mrr4_halt_condition"] == "C1"
    assert "RB-C1" in (disk_sig["response_procedure"] or ""), (
        f"expected RB-C1 reference; got {disk_sig['response_procedure']!r}"
    )


# -- Test 8: disk warning at 15% threshold --------------------------------


def test_disk_pressure_warning_at_15pct(isolated_canary, monkeypatch):
    """disk_free_pct=10 (< warn=15, > crit=5) → WARNING."""
    _write_status(isolated_canary, _status_two_bouncers())
    _patch_pid_alive(monkeypatch, {99225, 99403})

    warn_ibounce = json.loads(json.dumps(_HEALTHZ_OK_IBOUNCE))
    warn_ibounce["audit_log"]["disk_free_pct"] = 14.0
    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": warn_ibounce,
        "http://127.0.0.1:7412/healthz": _HEALTHZ_OK_GBOUNCE,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "monitor", "--json"])
    assert result.exit_code == 1
    snapshot = json.loads(result.output)
    disk_sig = next(
        s for s in snapshot["signals"] if s["name"] == "disk_pressure"
    )
    assert disk_sig["status"] == "WARNING"
    assert disk_sig["per_bouncer"]["ibounce"]["status"] == "WARNING"


# -- Test 9: disk crit at 5% threshold ------------------------------------


def test_disk_pressure_crit_at_5pct(isolated_canary, monkeypatch):
    """disk_free_pct=4 (< crit=5) → CRIT."""
    _write_status(isolated_canary, _status_two_bouncers())
    _patch_pid_alive(monkeypatch, {99225, 99403})

    crit_ibounce = json.loads(json.dumps(_HEALTHZ_OK_IBOUNCE))
    crit_ibounce["audit_log"]["disk_free_pct"] = 4.0
    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": crit_ibounce,
        "http://127.0.0.1:7412/healthz": _HEALTHZ_OK_GBOUNCE,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "monitor", "--json"])
    assert result.exit_code == 2
    snapshot = json.loads(result.output)
    disk_sig = next(
        s for s in snapshot["signals"] if s["name"] == "disk_pressure"
    )
    assert disk_sig["status"] == "CRIT"
    assert disk_sig["per_bouncer"]["ibounce"]["status"] == "CRIT"


# -- Test 10: dead PID is CRIT --------------------------------------------


def test_bouncer_down_is_crit(isolated_canary, monkeypatch):
    """Recorded PID not alive → bouncer_process_health CRIT → exit 2."""
    _write_status(isolated_canary, _status_two_bouncers())
    # Only gbounce alive; ibounce PID is dead.
    _patch_pid_alive(monkeypatch, {99403})
    # ibounce /healthz also unreachable since process is dead.
    _patch_healthz(monkeypatch, {
        "http://127.0.0.1:7401/healthz": None,
        "http://127.0.0.1:7412/healthz": _HEALTHZ_OK_GBOUNCE,
    })
    _patch_threat_feed_no_subs(monkeypatch)
    _patch_chain_unknown(monkeypatch)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "monitor", "--json"])

    # CRIT wins over the UNKNOWN-due-to-unreachable: exit 2.
    assert result.exit_code == 2, result.output
    snapshot = json.loads(result.output)
    assert snapshot["overall_status"] == "CRIT"

    proc_sig = next(
        s for s in snapshot["signals"]
        if s["name"] == "bouncer_process_health"
    )
    assert proc_sig["status"] == "CRIT"
    # Observable: ibounce flagged as the offending bouncer.
    assert proc_sig["per_bouncer"]["ibounce"]["status"] == "CRIT"
    assert proc_sig["mrr4_halt_condition"] == "C3"
    assert "RB-C3" in (proc_sig["response_procedure"] or "")
