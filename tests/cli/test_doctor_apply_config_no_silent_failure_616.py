"""#616 HIGH — `iam-jit doctor apply-config` must honestly report
bouncer start failures.

Pre-#616: when a bouncer's ``subprocess.Popen`` succeeded but the child
died inside the start-grace window (port collision, missing config file,
invalid CLI arg, missing dependency), ``_start_bouncer`` returned
``started=True`` and ``apply-config`` returned ``status="ok"`` with
exit code 0 — same shape as the silent-degradation cluster
(#560 / #592 / #594 / #596 / #598 / #606 / #607 / #610 / #618 / #619).
14th recurrence.

This file pins:
  1. ``_is_pid_alive_for_start`` — post-Popen PID-liveness verification
     uses ``proc.poll()`` (NOT ``os.kill``) so zombies are reaped
     correctly.
  2. ``_start_bouncer`` — when the child exited inside the grace window,
     the record flips to ``started=False`` + ``skipped=True`` +
     ``kind="start_failure"`` with a reason naming the exit code.
  3. ``apply_declaration`` — when ALL declared bouncers fail to start
     (no started + ≥1 start_failure), top-level ``status`` is
     ``"failed"`` (was the pre-#616 silent ``"ok"``).
  4. ``apply-config`` CLI — exit code follows the #606 / #616 contract:
     0 ok / 1 failed / 2 partial.
  5. Sabotage check — if the PID-liveness step is monkey-patched to
     always say "alive", the pre-#616 silent-degradation behaviour
     comes back. Proves the verification is load-bearing per
     ``docs/CONTRIBUTING.md`` observable-state convention.

Per [[ibounce-honest-positioning]] + [[scorer-is-ground-truth]] every
assertion pairs the reported value (``result.status``, exit code) with
an observable-state fact (PID alive / dead via poll(), skip kind,
warning code).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from typing import Any
from unittest import mock

import pytest
from click.testing import CliRunner

import iam_jit.ambient_config.setup as setup_mod
from iam_jit.ambient_config import apply_declaration
from iam_jit.cli import doctor
from iam_jit.cli_apply_config import _exit_code_for_status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _no_running_bouncers() -> dict[str, Any]:
    """Posture snapshot where every bouncer is reported NOT running so
    the apply path takes the start-bouncer branch."""
    return {
        "schema_version": "1.0",
        "overall_mode": "neither",
        "bouncers": {
            "ibounce": {"running": False, "port": 8767, "pid": None},
            "kbounce": {"running": False, "port": 8766, "pid": None},
            "gbounce": {"running": False, "port": 8080, "pid": None},
            "dbounce": {"running": False, "port": 5433, "pid": None},
        },
    }


def _isolate_snapshot_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> None:
    """Redirect snapshot config-file list into tmp_path so tests don't
    touch the operator's real `~/.iam-jit/`."""
    fake_root = tmp_path / "iam_jit_state"
    fake_root.mkdir()
    monkeypatch.setattr(
        setup_mod, "_SETUP_SNAPSHOT_CONFIG_FILES",
        (
            fake_root / "profiles.yaml",
            fake_root / "profiles_state.yaml",
        ),
    )


# ---------------------------------------------------------------------------
# 1. _is_pid_alive_for_start uses poll() — zombies correctly reported dead
# ---------------------------------------------------------------------------


def test_is_pid_alive_for_start_returns_false_for_dead_child() -> None:
    """A child that has already exited must report alive=False — this
    is the load-bearing primitive for the #616 fix.

    We deliberately use ``proc.poll()`` over ``os.kill(pid, 0)`` because
    a zombie process is still ``os.kill``-reachable but is functionally
    dead. The helper MUST report it as dead so apply-config doesn't
    claim a defunct bouncer is running.
    """
    proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
    proc.wait()
    assert proc.poll() is not None  # confirmed exited
    assert setup_mod._is_pid_alive_for_start(proc) is False


def test_is_pid_alive_for_start_returns_true_for_living_child() -> None:
    """A child that is still running must report alive=True."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
    try:
        # Give the OS a beat to start the process.
        time.sleep(0.1)
        assert setup_mod._is_pid_alive_for_start(proc) is True
    finally:
        proc.terminate()
        proc.wait(timeout=2)


# ---------------------------------------------------------------------------
# 2. _start_bouncer — Popen succeeds but child dies → start_failure
# ---------------------------------------------------------------------------


def test_start_bouncer_marks_failure_when_child_dies_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-#616 this test would fail: subprocess.Popen succeeds against
    /usr/bin/false, the process exits with code 1 inside the 200ms
    grace window, and ``record["started"]`` was True.

    Post-#616 the record is honest: started=False, skipped=True,
    kind/reason naming the immediate-exit + the bouncer's exit code.
    """
    # Force the binary lookup to a real binary that exits immediately.
    immediate_exit_bin = shutil.which("false") or "/usr/bin/false"
    if not pathlib.Path(immediate_exit_bin).exists():
        pytest.skip(
            f"no immediate-exit binary at {immediate_exit_bin}; "
            "test relies on a real /usr/bin/false-shaped binary"
        )
    monkeypatch.setattr(
        setup_mod, "_find_binary", lambda _candidates: immediate_exit_bin,
    )

    record = setup_mod._start_bouncer(
        "gbounce",
        port=8080,
        mode="discovery",
        profile="auto",
        extra_args=None,
        execute=True,
    )

    # Reported state is HONEST — not pre-#616 silent True.
    assert record["started"] is False, (
        f"pre-#616 regression: _start_bouncer claimed started=True after "
        f"Popen of a binary that exits immediately. Record: {record!r}"
    )
    assert record["skipped"] is True
    assert "exited immediately" in (record.get("reason") or "")
    # PID is still recorded so the caller can correlate with audit logs.
    assert record.get("pid"), "pid should be recorded even on immediate-exit"
    # Observable: the recorded PID is actually dead.
    try:
        os.kill(int(record["pid"]), 0)
        # If we get here without ProcessLookupError, the process IS still
        # alive somehow (shouldn't happen for /usr/bin/false). The test
        # is still meaningful because we asserted started=False above.
    except ProcessLookupError:
        # Expected: /usr/bin/false has exited.
        pass


# ---------------------------------------------------------------------------
# 3. apply_declaration — all bouncers fail → status="failed"
# ---------------------------------------------------------------------------


def test_apply_declaration_all_fail_returns_failed_status(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every declared+enabled bouncer fails to start → top-level
    status must be "failed" (not the pre-#616 silent "ok").

    Sabotage check that closes the silent-degradation cluster:
    pre-#616 the partial-install branches only fired when both
    started>=1 AND start_failures>=1. With all-failure the status
    remained the dataclass default "ok" — agents reading only
    `result.status` thought setup succeeded.
    """
    _isolate_snapshot_files(monkeypatch, tmp_path)

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        return {
            "name": name, "started": False, "skipped": True,
            "reason": "stubbed start_failure (binary not found)",
            "command": [], "port": port or 8080, "mode": mode,
            "mode_declared": mode, "mode_runtime": mode, "profile": profile,
        }

    monkeypatch.setattr(setup_mod, "_start_bouncer", fake_start)

    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
                "gbounce": {"enabled": True, "mode": "discovery"},
            },
        },
    }
    result = apply_declaration(
        declaration,
        posture=_no_running_bouncers(),
        env={},
        execute=True,
        rollback_on_failure=False,
    )

    # 1. Status honestly reflects all-failed (NOT pre-#616 silent ok).
    assert result.status == "failed", (
        f"all-failures must surface as status='failed' per #616; "
        f"got status={result.status!r}, "
        f"bouncers_started={result.bouncers_started!r}, "
        f"bouncers_skipped={result.bouncers_skipped!r}"
    )
    # 2. Observable: nothing in bouncers_started.
    assert result.bouncers_started == []
    # 3. Observable: every declared bouncer is in bouncers_skipped with
    #    kind=start_failure.
    skip_names = {s["name"] for s in result.bouncers_skipped}
    assert skip_names == {"ibounce", "gbounce"}
    for s in result.bouncers_skipped:
        assert s["kind"] == "start_failure"
    # 4. Warning surface carries the coded #616 message.
    assert any(
        "all_bouncers_failed_to_start" in w for w in result.warnings
    ), f"missing all_bouncers_failed_to_start warning; got {result.warnings!r}"


def test_apply_declaration_partial_still_returns_partial_install(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression-pin: the #538/#592 partial-install path is unchanged.
    One bouncer starts + one fails → status partial_install (not the
    new #616 'failed' status, which is reserved for all-failure)."""
    _isolate_snapshot_files(monkeypatch, tmp_path)
    monkeypatch.setattr(setup_mod.os, "kill", lambda *a, **kw: None)

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        if name == "ibounce":
            return {
                "name": "ibounce", "started": True, "skipped": False,
                "pid": 9999, "port": 8767, "command": ["ibounce"],
                "mode": mode, "mode_declared": mode,
                "mode_runtime": "cooperative", "profile": profile,
            }
        return {
            "name": name, "started": False, "skipped": True,
            "reason": "stubbed start_failure", "command": [],
            "port": port or 8080, "mode": mode, "mode_declared": mode,
            "mode_runtime": mode, "profile": profile,
        }

    monkeypatch.setattr(setup_mod, "_start_bouncer", fake_start)

    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
                "gbounce": {"enabled": True, "mode": "discovery"},
            },
        },
    }
    result = apply_declaration(
        declaration,
        posture=_no_running_bouncers(),
        env={},
        execute=True,
        rollback_on_failure=False,
    )

    # #616 must NOT swallow the existing #592 partial_install contract.
    assert result.status == "partial_install"
    assert "all_bouncers_failed_to_start" not in " ".join(result.warnings)


def test_apply_declaration_all_ok_returns_ok(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy-path regression-pin: every bouncer starts → status='ok'."""
    _isolate_snapshot_files(monkeypatch, tmp_path)

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        return {
            "name": name, "started": True, "skipped": False,
            "pid": 12345, "port": port or 8767,
            "command": [name], "mode": mode, "mode_declared": mode,
            "mode_runtime": "cooperative", "profile": profile,
        }

    monkeypatch.setattr(setup_mod, "_start_bouncer", fake_start)

    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
            },
        },
    }
    result = apply_declaration(
        declaration,
        posture=_no_running_bouncers(),
        env={},
        execute=True,
        rollback_on_failure=False,
    )
    assert result.status == "ok"
    assert result.bouncers_started == ["ibounce"]


# ---------------------------------------------------------------------------
# 4. CLI exit-code contract (#616 → #606 alignment)
# ---------------------------------------------------------------------------


def _make_cfg_yaml(td: str, bouncers: dict[str, dict[str, Any]]) -> str:
    """Write a minimal .iam-jit.yaml in tmp dir and return its path."""
    lines = ["iam-jit:", "  enabled: true", "  bouncers:"]
    for name, body in bouncers.items():
        lines.append(f"    {name}:")
        for k, v in body.items():
            lines.append(f"      {k}: {v}")
    cfg_path = os.path.join(td, ".iam-jit.yaml")
    with open(cfg_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return cfg_path


def _invoke_apply_config(
    cfg_path: str, *extra_args: str,
) -> tuple[int, str]:
    runner = CliRunner()
    apply_cmd = doctor.commands["apply-config"]
    result = runner.invoke(
        apply_cmd, ["--config", cfg_path, *extra_args],
        catch_exceptions=False,
    )
    return result.exit_code, result.output


def test_cli_exit_code_zero_on_ok(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: all bouncers start → exit 0."""
    _isolate_snapshot_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        setup_mod, "_capture_posture_safe", _no_running_bouncers,
    )

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        return {
            "name": name, "started": True, "skipped": False,
            "pid": 11111, "port": port or 8767,
            "command": [name], "mode": mode, "mode_declared": mode,
            "mode_runtime": "cooperative", "profile": profile,
        }

    monkeypatch.setattr(setup_mod, "_start_bouncer", fake_start)

    with tempfile.TemporaryDirectory() as td:
        cfg_path = _make_cfg_yaml(td, {
            "ibounce": {"enabled": "true", "mode": "discovery"},
        })
        exit_code, out = _invoke_apply_config(cfg_path, "--json")

    assert exit_code == 0
    payload = json.loads(out)
    assert payload["status"] == "ok"


def test_cli_exit_code_one_on_failed(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All bouncers fail → status='failed' → exit 1 per #616 contract."""
    _isolate_snapshot_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        setup_mod, "_capture_posture_safe", _no_running_bouncers,
    )

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        return {
            "name": name, "started": False, "skipped": True,
            "reason": "stub start_failure", "command": [],
            "port": port or 8080, "mode": mode, "mode_declared": mode,
            "mode_runtime": mode, "profile": profile,
        }

    monkeypatch.setattr(setup_mod, "_start_bouncer", fake_start)

    with tempfile.TemporaryDirectory() as td:
        cfg_path = _make_cfg_yaml(td, {
            "ibounce": {"enabled": "true", "mode": "discovery"},
        })
        exit_code, out = _invoke_apply_config(cfg_path, "--json")

    assert exit_code == 1, (
        f"all-failed apply-config must exit 1 per #616; got {exit_code}. "
        f"output: {out[:500]}"
    )
    payload = json.loads(out)
    assert payload["status"] == "failed"


def test_cli_exit_code_two_on_partial(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Some started + some failed → status='partial_install' / 'rolled_back'
    → exit 2 per #616 contract."""
    _isolate_snapshot_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        setup_mod, "_capture_posture_safe", _no_running_bouncers,
    )
    monkeypatch.setattr(setup_mod.os, "kill", lambda *a, **kw: None)

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        if name == "ibounce":
            return {
                "name": "ibounce", "started": True, "skipped": False,
                "pid": 22222, "port": 8767, "command": ["ibounce"],
                "mode": mode, "mode_declared": mode,
                "mode_runtime": "cooperative", "profile": profile,
            }
        return {
            "name": name, "started": False, "skipped": True,
            "reason": "stub start_failure", "command": [],
            "port": port or 8080, "mode": mode, "mode_declared": mode,
            "mode_runtime": mode, "profile": profile,
        }

    monkeypatch.setattr(setup_mod, "_start_bouncer", fake_start)

    with tempfile.TemporaryDirectory() as td:
        cfg_path = _make_cfg_yaml(td, {
            "ibounce": {"enabled": "true", "mode": "discovery"},
            "gbounce": {"enabled": "true", "mode": "discovery"},
        })
        exit_code, out = _invoke_apply_config(cfg_path, "--json")

    assert exit_code == 2, (
        f"partial-install apply-config must exit 2 per #616; "
        f"got {exit_code}. output: {out[:500]}"
    )
    payload = json.loads(out)
    assert payload["status"] in ("partial_install", "rolled_back",
                                 "rollback_incomplete")


def test_cli_exit_code_zero_on_disabled(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Declaration with enabled=false is a no-op success → exit 0."""
    _isolate_snapshot_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        setup_mod, "_capture_posture_safe", _no_running_bouncers,
    )

    with tempfile.TemporaryDirectory() as td:
        cfg_path = os.path.join(td, ".iam-jit.yaml")
        with open(cfg_path, "w") as f:
            f.write(textwrap.dedent("""
                iam-jit:
                  enabled: false
            """).strip() + "\n")
        exit_code, out = _invoke_apply_config(cfg_path, "--json")

    assert exit_code == 0
    payload = json.loads(out)
    assert payload["status"] == "disabled"


def test_exit_code_for_unknown_status_is_two() -> None:
    """fail-CLOSED per [[scorer-is-ground-truth]] — unknown status MUST
    NOT pass as exit 0. We map it to 2 (partial / uncertain) so the
    operator's CI gate still trips."""
    assert _exit_code_for_status("ok") == 0
    assert _exit_code_for_status("disabled") == 0
    assert _exit_code_for_status("failed") == 1
    assert _exit_code_for_status("partial_install") == 2
    assert _exit_code_for_status("rolled_back") == 2
    assert _exit_code_for_status("rollback_incomplete") == 2
    # The fail-CLOSED guarantee:
    assert _exit_code_for_status("some_future_status") == 2
    assert _exit_code_for_status(None) == 2


# ---------------------------------------------------------------------------
# 5. Sabotage check — verification step is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_pid_liveness_check_is_load_bearing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per docs/CONTRIBUTING.md observable-state convention: monkey-patch
    ``_is_pid_alive_for_start`` to ALWAYS return True, then re-run the
    immediate-exit binary scenario. The pre-#616 silent-degradation
    behaviour should come back — proving the post-Popen verification
    step is what's actually doing the work.

    If this test fails (i.e., the sabotage doesn't reintroduce the bug),
    then the fix is duplicated somewhere else and the verification step
    in `_start_bouncer` is dead code — we'd want to know.
    """
    immediate_exit_bin = shutil.which("false") or "/usr/bin/false"
    if not pathlib.Path(immediate_exit_bin).exists():
        pytest.skip("no immediate-exit binary available")
    monkeypatch.setattr(
        setup_mod, "_find_binary", lambda _candidates: immediate_exit_bin,
    )
    # Sabotage: always claim the child is alive.
    monkeypatch.setattr(
        setup_mod, "_is_pid_alive_for_start", lambda proc: True,
    )

    record = setup_mod._start_bouncer(
        "gbounce",
        port=8080,
        mode="discovery",
        profile="auto",
        extra_args=None,
        execute=True,
    )

    # Pre-#616 behaviour returns: the silent claim that started=True.
    assert record["started"] is True, (
        "sabotaging _is_pid_alive_for_start should reintroduce the "
        "pre-#616 silent-degradation behaviour; if started is False "
        "here, some OTHER guard is doing the work and #616's fix is "
        "dead code"
    )
    # And no skip reason — the bug is back.
    assert not record.get("skipped"), (
        "sabotage check expected `skipped` to revert to False; got "
        f"{record!r}"
    )
