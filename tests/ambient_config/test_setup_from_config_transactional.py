"""#538 — `iam_jit_setup_from_config` transactional-rollback tests.

Per docs/MRR-4-ROLLBACK-RUNBOOK.md RB-B6 (the UC-20 load-bearing
partial-install gap): pre-#538 a mid-apply failure left the operator
with some bouncers started + others orphaned. #538 adds an opt-out-able
transactional path:

  * `_capture_setup_state()` snapshots config files + posture pids.
  * `_restore_setup_state(snap, new_pids)` SIGTERMs new pids + restores
    config files.
  * `apply_declaration(rollback_on_failure=True)` invokes rollback when
    `bouncers_started` is non-empty AND any `bouncers_skipped` entry has
    `kind: start_failure`.

Per docs/CONTRIBUTING.md every reported-success assertion is paired
with an observable-state assertion (PID killed, file restored, etc.).
"""

from __future__ import annotations

import os
import pathlib
import signal
from typing import Any
from unittest import mock

import pytest

from iam_jit.ambient_config import apply_declaration
from iam_jit.ambient_config.setup import (
    _capture_setup_state,
    _restore_setup_state,
)
import iam_jit.ambient_config.setup as setup_mod


def _isolate_snapshot_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> list[pathlib.Path]:
    """Redirect the module-level snapshot-file list to two synthetic
    paths in tmp_path so tests don't touch the operator's real
    ``~/.iam-jit/`` state."""
    fake_root = tmp_path / "iam_jit_state"
    fake_root.mkdir()
    file_a = fake_root / "profiles.yaml"
    file_b = fake_root / "profiles_state.yaml"
    monkeypatch.setattr(
        setup_mod, "_SETUP_SNAPSHOT_CONFIG_FILES",
        (file_a, file_b),
    )
    return [file_a, file_b]


def _stub_capture_posture(
    monkeypatch: pytest.MonkeyPatch, posture: dict[str, Any],
) -> None:
    monkeypatch.setattr(
        setup_mod, "_capture_posture_safe", lambda: dict(posture),
    )


def _posture_with_running_pids(
    pids: dict[str, int] | None = None,
) -> dict[str, Any]:
    base = {
        "schema_version": "1.0",
        "overall_mode": "neither",
        "bouncers": {
            "ibounce": {"running": False, "port": 8767, "pid": None},
            "kbounce": {"running": False, "port": 8766, "pid": None},
            "gbounce": {"running": False, "port": 8080, "pid": None},
            "dbounce": {"running": False, "port": 5433, "pid": None},
        },
    }
    if pids:
        for name, pid in pids.items():
            base["bouncers"][name]["pid"] = pid
            base["bouncers"][name]["running"] = pid is not None
    return base


# ---------------------------------------------------------------------------
# 1. _capture_setup_state snapshots existing + missing files distinctly
# ---------------------------------------------------------------------------


def test_capture_setup_state_records_existing_and_missing_files(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Snapshot must record existing files with content + missing files
    with exists=False, so restore can revert each correctly."""
    files = _isolate_snapshot_files(monkeypatch, tmp_path)
    # Make file_a exist with content; file_b absent.
    files[0].write_text("baseline-profile-yaml-content\n")
    assert not files[1].exists()

    _stub_capture_posture(monkeypatch, _posture_with_running_pids({"ibounce": 999}))

    snap = _capture_setup_state()

    # 1. Reported shape.
    assert "config_files" in snap
    assert "posture_pids" in snap
    # 2. Observable: file_a is in the snapshot with content + mode.
    entry_a = snap["config_files"][str(files[0])]
    assert entry_a["exists"] is True
    assert entry_a["content"] == b"baseline-profile-yaml-content\n"
    assert entry_a["mode"] is not None
    # 3. Observable: file_b is in the snapshot but marked absent.
    entry_b = snap["config_files"][str(files[1])]
    assert entry_b["exists"] is False
    assert entry_b["content"] is None
    # 4. Posture pids recorded from posture stub.
    assert snap["posture_pids"]["ibounce"] == 999


# ---------------------------------------------------------------------------
# 2. _restore_setup_state SIGTERMs only NEWLY-started PIDs
# ---------------------------------------------------------------------------


def test_restore_setup_state_kills_only_new_pids(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIGTERM only the PIDs absent from the snapshot's posture_pids —
    pre-existing bouncers MUST be left alone per [[creates-never-mutates]]."""
    _isolate_snapshot_files(monkeypatch, tmp_path)

    killed: list[tuple[int, int]] = []

    def fake_kill(pid: int, sig: int) -> None:
        killed.append((int(pid), int(sig)))

    monkeypatch.setattr(setup_mod.os, "kill", fake_kill)

    snapshot = {
        "captured_at": 0.0,
        # ibounce was running before apply at pid 1000; we should NOT kill it.
        "posture_pids": {"ibounce": 1000, "kbounce": None},
        "posture_ports": {},
        "config_files": {},
    }

    outcome = _restore_setup_state(
        snapshot,
        new_pids={"ibounce": 1000, "kbounce": 2001, "gbounce": 3001},
    )

    # 1. Reported: ok.
    assert outcome["status"] == "ok"
    # 2. Observable: only NEW pids killed (1000 was pre-existing).
    killed_pids = sorted(p for p, _ in killed)
    assert killed_pids == [2001, 3001]
    # 3. Observable: outcome's killed_pids matches the os.kill record.
    assert sorted(outcome["killed_pids"]) == [2001, 3001]


def test_restore_setup_state_treats_already_dead_pid_as_success(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ProcessLookupError from os.kill (PID already gone) is the
    rollback goal — count it as success, not failure."""
    _isolate_snapshot_files(monkeypatch, tmp_path)

    def fake_kill(pid: int, sig: int) -> None:
        raise ProcessLookupError("already dead")

    monkeypatch.setattr(setup_mod.os, "kill", fake_kill)

    outcome = _restore_setup_state(
        {"posture_pids": {}, "posture_ports": {}, "config_files": {}},
        new_pids={"ibounce": 4444},
    )
    assert outcome["status"] == "ok"
    assert outcome["kill_failures"] == []
    assert outcome["killed_pids"] == [4444]


def test_restore_setup_state_records_kill_failure_as_incomplete(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PermissionError from os.kill MUST mark rollback `incomplete` +
    list the failure for operator triage."""
    _isolate_snapshot_files(monkeypatch, tmp_path)

    def fake_kill(pid: int, sig: int) -> None:
        raise PermissionError("EPERM")

    monkeypatch.setattr(setup_mod.os, "kill", fake_kill)

    outcome = _restore_setup_state(
        {"posture_pids": {}, "posture_ports": {}, "config_files": {}},
        new_pids={"ibounce": 5555},
    )
    assert outcome["status"] == "incomplete"
    assert any("ibounce" in m for m in outcome["kill_failures"])


# ---------------------------------------------------------------------------
# 3. _restore_setup_state restores existing files + deletes new files
# ---------------------------------------------------------------------------


def test_restore_setup_state_round_trips_file_content(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file present-in-snapshot that was later mutated MUST be
    restored to the snapshot's content."""
    files = _isolate_snapshot_files(monkeypatch, tmp_path)
    files[0].write_text("snapshot-content\n")
    # Snapshot it.
    snap = _capture_setup_state()
    # Now mutate the file (simulate mid-apply config rewrite).
    files[0].write_text("mid-apply-mutated-content\n")
    assert files[0].read_text() == "mid-apply-mutated-content\n"

    monkeypatch.setattr(setup_mod.os, "kill", lambda *a, **kw: None)

    outcome = _restore_setup_state(snap, new_pids={})

    # 1. Reported.
    assert outcome["status"] == "ok"
    # 2. Observable: file content restored.
    assert files[0].read_text() == "snapshot-content\n"
    assert str(files[0]) in outcome["files_restored"]
    # 3. Observable: no verification drift.
    assert outcome["verification_drift"] == []


def test_restore_setup_state_deletes_files_created_after_snapshot(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file ABSENT-in-snapshot that was created mid-apply MUST be
    deleted by rollback."""
    files = _isolate_snapshot_files(monkeypatch, tmp_path)
    assert not files[1].exists()
    snap = _capture_setup_state()
    # Now create the file (simulate a bouncer dropping its config).
    files[1].write_text("new-mid-apply-file\n")

    monkeypatch.setattr(setup_mod.os, "kill", lambda *a, **kw: None)

    outcome = _restore_setup_state(snap, new_pids={})

    assert outcome["status"] == "ok"
    # Observable: file is gone.
    assert not files[1].exists()
    assert str(files[1]) in outcome["files_deleted"]


# ---------------------------------------------------------------------------
# 4. apply_declaration triggers rollback on partial-install
# ---------------------------------------------------------------------------


def test_apply_declaration_rolls_back_on_partial_install(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When one bouncer starts + another start-fails, the rollback
    SIGTERMs the started bouncer + clears `bouncers_started` so the
    result honestly reports no live bouncers."""
    _isolate_snapshot_files(monkeypatch, tmp_path)

    killed: list[int] = []
    monkeypatch.setattr(
        setup_mod.os, "kill",
        lambda pid, sig: killed.append(int(pid)),
    )

    # Stub _start_bouncer: ibounce starts OK with pid=7777; gbounce
    # binary-not-found (start failure).
    call_log: list[str] = []

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        call_log.append(name)
        if name == "ibounce":
            return {
                "name": "ibounce", "started": True, "skipped": False,
                "pid": 7777, "port": 8767, "command": ["ibounce"],
                "mode": mode, "mode_declared": mode, "mode_runtime": "cooperative",
                "profile": profile,
            }
        return {
            "name": name, "started": False, "skipped": True,
            "reason": "binary not found on PATH",
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
        }
    }
    result = apply_declaration(
        declaration,
        posture=_posture_with_running_pids(),
        env={},
        execute=True,
        rollback_on_failure=True,
    )

    # 1. Reported: rollback_outcome present + status "rolled_back".
    assert result.rollback_outcome is not None
    assert result.rollback_outcome["status"] == "ok"
    assert result.status == "rolled_back"
    # 2. Observable: SIGTERM was sent to pid 7777 (the started ibounce).
    assert killed == [7777]
    # 3. Observable: bouncers_started is empty post-rollback (we killed it).
    assert result.bouncers_started == []
    # 4. Observable: the warning surface tells the operator what happened.
    assert any("#538" in w for w in result.warnings)
    assert any("partial-install" in w for w in result.warnings)


def test_apply_declaration_opt_out_keeps_partial_state(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With rollback_on_failure=False (opt-out), the same partial-install
    leaves bouncers_started intact + rollback_outcome=None."""
    _isolate_snapshot_files(monkeypatch, tmp_path)

    killed: list[int] = []
    monkeypatch.setattr(
        setup_mod.os, "kill",
        lambda pid, sig: killed.append(int(pid)),
    )

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        if name == "ibounce":
            return {
                "name": "ibounce", "started": True, "skipped": False,
                "pid": 8888, "port": 8767, "command": ["ibounce"],
                "mode": mode, "mode_declared": mode, "mode_runtime": "cooperative",
                "profile": profile,
            }
        return {
            "name": name, "started": False, "skipped": True,
            "reason": "binary not found", "command": [], "port": 8080,
            "mode": mode, "mode_declared": mode, "mode_runtime": mode,
            "profile": profile,
        }

    monkeypatch.setattr(setup_mod, "_start_bouncer", fake_start)

    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
                "gbounce": {"enabled": True, "mode": "discovery"},
            },
        }
    }
    result = apply_declaration(
        declaration,
        posture=_posture_with_running_pids(),
        env={},
        execute=True,
        rollback_on_failure=False,
    )

    # 1. Reported: rollback_outcome stays None.
    assert result.rollback_outcome is None
    # 2. Observable: pid 8888 was NOT killed.
    assert killed == []
    # 3. Observable: ibounce stays in bouncers_started (partial-install left).
    assert result.bouncers_started == ["ibounce"]
    # 4. Observable: status is still "ok" (legacy semantics).
    assert result.status == "ok"


# ---------------------------------------------------------------------------
# 5. apply_declaration does NOT rollback when only conditional-false skips
# ---------------------------------------------------------------------------


def test_apply_declaration_skips_rollback_for_conditional_false(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A `when_X_present` conditional resolving to false is NOT a
    partial-install — rollback MUST NOT fire."""
    _isolate_snapshot_files(monkeypatch, tmp_path)

    killed: list[int] = []
    monkeypatch.setattr(
        setup_mod.os, "kill",
        lambda pid, sig: killed.append(int(pid)),
    )

    # Force kubeconfig probe to return False so kbouncer's conditional
    # resolves false on dev machines where ~/.kube/config exists.
    monkeypatch.setitem(
        setup_mod._CONDITIONAL_RESOLVERS,
        "when_kubeconfig_present",
        lambda env: (False, "stubbed: forced false for test"),
    )

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        # ibounce starts OK; we don't expect this to be invoked for
        # kbouncer because the conditional is forced false.
        return {
            "name": name, "started": True, "skipped": False,
            "pid": 9999, "port": 8767, "command": [name],
            "mode": mode, "mode_declared": mode, "mode_runtime": "cooperative",
            "profile": profile,
        }

    monkeypatch.setattr(setup_mod, "_start_bouncer", fake_start)

    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
                # kbouncer is when_kubeconfig_present; with env={}, false.
                "kbouncer": {
                    "enabled": "when_kubeconfig_present",
                    "mode": "discovery",
                },
            },
        }
    }
    result = apply_declaration(
        declaration,
        posture=_posture_with_running_pids(),
        env={},
        execute=True,
        rollback_on_failure=True,
    )

    # 1. Reported: rollback_outcome MUST be None (no partial-install).
    assert result.rollback_outcome is None, (
        f"rollback fired on conditional-false skip; this is the "
        f"#538 false-positive shape. Result: {result.rollback_outcome!r}"
    )
    # 2. Observable: ibounce was NOT killed.
    assert killed == []
    # 3. Observable: ibounce stays in bouncers_started.
    assert result.bouncers_started == ["ibounce"]
    # 4. Observable: kbouncer skip is recorded with kind=conditional_false.
    kb_skips = [s for s in result.bouncers_skipped if s["name"] == "kbouncer"]
    assert kb_skips
    assert kb_skips[0].get("kind") == "conditional_false"


# ---------------------------------------------------------------------------
# 6. End-to-end snapshot + restore round trip via apply_declaration
# ---------------------------------------------------------------------------


def test_apply_declaration_restores_mutated_config_on_rollback(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: pre-apply config file content is restored when
    rollback fires + post-rollback re-read matches the snapshot byte-
    for-byte."""
    files = _isolate_snapshot_files(monkeypatch, tmp_path)
    files[0].write_text("PRE-APPLY-PROFILES-YAML\n")

    monkeypatch.setattr(setup_mod.os, "kill", lambda *a, **kw: None)

    def fake_start(name, *, port, mode, profile, extra_args, execute):
        if name == "ibounce":
            # Simulate the bouncer mutating profiles.yaml as part of
            # startup.
            files[0].write_text("MUTATED-BY-IBOUNCE-STARTUP\n")
            return {
                "name": "ibounce", "started": True, "skipped": False,
                "pid": 6666, "port": 8767, "command": ["ibounce"],
                "mode": mode, "mode_declared": mode, "mode_runtime": "cooperative",
                "profile": profile,
            }
        return {
            "name": name, "started": False, "skipped": True,
            "reason": "binary not found", "command": [], "port": 8080,
            "mode": mode, "mode_declared": mode, "mode_runtime": mode,
            "profile": profile,
        }

    monkeypatch.setattr(setup_mod, "_start_bouncer", fake_start)

    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
                "gbounce": {"enabled": True, "mode": "discovery"},
            },
        }
    }
    result = apply_declaration(
        declaration,
        posture=_posture_with_running_pids(),
        env={},
        execute=True,
        rollback_on_failure=True,
    )

    # 1. Reported: rollback fired.
    assert result.rollback_outcome is not None
    assert result.status == "rolled_back"
    # 2. Observable: profiles.yaml is restored to pre-apply content.
    assert files[0].read_text() == "PRE-APPLY-PROFILES-YAML\n", (
        f"profiles.yaml was not restored; current content: "
        f"{files[0].read_text()!r}"
    )
    assert str(files[0]) in result.rollback_outcome["files_restored"]
    # 3. Observable: zero verification drift.
    assert result.rollback_outcome["verification_drift"] == []
