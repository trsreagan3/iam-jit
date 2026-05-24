"""§A102 (#525) — daemon_args + auto-relaunch + verify-setup tests.

Per ``docs/CONTRIBUTING.md`` state-verification convention: every
test that asserts a reported success status MUST also assert the
observable state matches. These tests cover the calibration-drift
bug #18 shape — smoke-test ``--upstream`` pin leaking into daily-dev
canary mode — and the §A102 fix that makes it structurally
impossible to recur:

  1. YAML loader warns when daemon_args contains --upstream under
     iam-jit.canary: true.
  2. _restart_bouncers auto-relaunches with recorded daemon_args
     (no longer relies on operator to manually re-launch).
  3. _restart_bouncers files a CRIT issue when relaunch fails.
  4. verify-setup is GREEN when bouncer matches operator intent
     (general-proxy daily-dev mode).
  5. verify-setup is RED when bouncer cmdline contains --upstream
     that is NOT in recorded daemon_args (the bug #18 shape).
  6. verify-setup is RED when the recorded PID is dead.
  7. status.json round-trips daemon_args from YAML through to the
     live process the operator sees.
"""

from __future__ import annotations

import json
import pathlib
import warnings
from typing import Any
from unittest import mock

import pytest
from click.testing import CliRunner

import iam_jit.cli_canary as cc
from iam_jit.cli import main


@pytest.fixture
def isolated_canary(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    canary_dir = tmp_path / "canary"
    canary_dir.mkdir()
    monkeypatch.setattr(cc, "CANARY_DIR", canary_dir)
    monkeypatch.setattr(cc, "ISSUES_PATH", canary_dir / "issues.jsonl")
    monkeypatch.setattr(cc, "NOTES_PATH", canary_dir / "notes.md")
    monkeypatch.setattr(cc, "STATUS_PATH", canary_dir / "status.json")
    monkeypatch.setattr(cc, "URLS_PATH", canary_dir / "urls.md")
    monkeypatch.setattr(cc, "CANARY_YAML_PATH", canary_dir / ".iam-jit.yaml")
    return canary_dir


# ---------------------------------------------------------------------------
# 1. YAML loader warns on smoke-pin under canary: true
# ---------------------------------------------------------------------------


def test_canary_yaml_warns_on_smoke_upstream(
    isolated_canary: pathlib.Path,
) -> None:
    """The §A102 calibration-drift bug #18 shape: YAML declares
    daemon_args containing --upstream under canary: true. The loader
    must emit a UserWarning so the operator + tests see the drift."""
    yaml_path = isolated_canary / ".iam-jit.yaml"
    yaml_path.write_text(
        "iam-jit:\n"
        "  canary: true\n"
        "  bouncers:\n"
        "    ibounce:\n"
        "      enabled: true\n"
        "      port: 7401\n"
        "      daemon_args: ['--upstream', 'http://127.0.0.1:4566']\n"
        "    gbounce:\n"
        "      enabled: true\n"
        "      port: 7402\n"
        "      mgmt_port: 7412\n"
        "      daemon_args: ['--allow-connect']\n",
        encoding="utf-8",
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        loaded = cc.load_canary_yaml()

    # 1. Reported result: YAML parsed.
    assert loaded["iam-jit"]["canary"] is True

    # 2. Observable: warning fired for the ibounce --upstream pin, not
    #    for gbounce (which only has --allow-connect).
    upstream_warnings = [
        w for w in caught
        if issubclass(w.category, UserWarning)
        and "calibration-drift" in str(w.message)
        and "ibounce" in str(w.message)
    ]
    assert len(upstream_warnings) == 1, (
        f"expected exactly 1 UserWarning about ibounce --upstream pin; "
        f"got {[str(w.message) for w in caught]}"
    )
    # 3. State verification: gbounce did NOT trigger a warning (its
    #    daemon_args has --allow-connect which is legitimate).
    gbounce_warnings = [
        w for w in caught
        if "gbounce" in str(w.message) and "calibration-drift" in str(w.message)
    ]
    assert gbounce_warnings == [], (
        f"--allow-connect must not trigger the §A102 warning; "
        f"got {[str(w.message) for w in gbounce_warnings]}"
    )


# ---------------------------------------------------------------------------
# 2. _restart_bouncers auto-relaunches with recorded daemon_args
# ---------------------------------------------------------------------------


def test_restart_bouncers_auto_relaunches(
    isolated_canary: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-§A102 _restart_bouncers only SIGTERMed; operator was
    expected to relaunch manually. §A102 auto-relaunches with the
    recorded daemon_args."""
    # Write canary YAML with explicit operator intent (general proxy).
    (isolated_canary / ".iam-jit.yaml").write_text(
        "iam-jit:\n"
        "  canary: true\n"
        "  bouncers:\n"
        "    ibounce:\n"
        "      enabled: true\n"
        "      port: 7401\n"
        "      daemon_args: []\n"
        "    gbounce:\n"
        "      enabled: true\n"
        "      port: 7402\n"
        "      mgmt_port: 7412\n"
        "      daemon_args: ['--allow-connect']\n",
        encoding="utf-8",
    )
    cc.write_status({
        "ports": {"ibounce": 7401, "gbounce": 7402, "gbounce_mgmt": 7412},
        "pids": {"ibounce": 11111, "gbounce": 22222},
    })

    # Stub out the OS-level interactions: no real lsof / kill / sleep.
    monkeypatch.setattr(
        cc.subprocess, "run",
        lambda *a, **kw: mock.Mock(
            stdout="", stderr="", returncode=0,
        ),
    )
    monkeypatch.setattr(cc.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(cc.time, "sleep", lambda *_a, **_kw: None)

    relaunch_calls: list[dict[str, Any]] = []

    def fake_relaunch(name, port, daemon_args, mgmt_port=None, **kw):
        relaunch_calls.append({
            "name": name,
            "port": port,
            "daemon_args": list(daemon_args),
            "mgmt_port": mgmt_port,
        })
        # Return a synthetic successful PID per bouncer.
        return True, 90000 + len(relaunch_calls), "fake-cmdline"

    monkeypatch.setattr(cc, "_relaunch_bouncer", fake_relaunch)

    pre = cc.read_status()
    ok, msg = cc._restart_bouncers(pre)

    # 1. Reported success.
    assert ok, msg
    # 2. Observable: _relaunch_bouncer was called per-bouncer with the
    #    YAML-recorded daemon_args.
    by_name = {c["name"]: c for c in relaunch_calls}
    assert "ibounce" in by_name
    assert by_name["ibounce"]["daemon_args"] == []
    assert by_name["ibounce"]["mgmt_port"] is None
    assert "gbounce" in by_name
    assert by_name["gbounce"]["daemon_args"] == ["--allow-connect"]
    assert by_name["gbounce"]["mgmt_port"] == 7412
    # 3. State verification: status.json mirrors the new PIDs +
    #    daemon_args so verify-setup sees the same shape.
    new_status = cc.read_status()
    assert new_status["pids"]["ibounce"] >= 90000
    assert new_status["pids"]["gbounce"] >= 90000
    assert new_status["daemon_args"]["ibounce"] == []
    assert new_status["daemon_args"]["gbounce"] == ["--allow-connect"]
    assert "last_relaunch_at" in new_status


# ---------------------------------------------------------------------------
# 3. _restart_bouncers files a CRIT issue on relaunch failure
# ---------------------------------------------------------------------------


def test_restart_bouncers_relaunch_failure_files_crit(
    isolated_canary: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When _relaunch_bouncer returns ok=False the restart must
    surface (ok=False, msg) AND append a CRIT issue."""
    (isolated_canary / ".iam-jit.yaml").write_text(
        "iam-jit:\n"
        "  canary: true\n"
        "  bouncers:\n"
        "    ibounce:\n"
        "      enabled: true\n"
        "      port: 7401\n"
        "      daemon_args: []\n",
        encoding="utf-8",
    )
    cc.write_status({
        "ports": {"ibounce": 7401},
        "pids": {"ibounce": 11111},
    })
    monkeypatch.setattr(
        cc.subprocess, "run",
        lambda *a, **kw: mock.Mock(stdout="", stderr="", returncode=0),
    )
    monkeypatch.setattr(cc.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(cc.time, "sleep", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        cc, "_relaunch_bouncer",
        lambda *a, **kw: (False, None, "fake: /healthz did not respond"),
    )

    pre = cc.read_status()
    ok, msg = cc._restart_bouncers(pre)

    # 1. Reported failure.
    assert not ok
    assert "relaunch ibounce failed" in msg

    # 2. Observable: a CRIT issue is in issues.jsonl.
    issues = cc.read_issues()
    crit = [i for i in issues if i.get("severity") == "CRIT"]
    assert len(crit) == 1, f"expected 1 CRIT; got {issues!r}"
    assert crit[0]["category"] == "bouncer_error"
    assert "§A102" in crit[0]["observable"]
    assert crit[0]["related_task"] == "#525"


# ---------------------------------------------------------------------------
# 4. verify-setup GREEN when bouncer matches operator intent
# ---------------------------------------------------------------------------


def test_verify_setup_green_when_general_proxy(
    isolated_canary: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: gbounce running with --allow-connect (no --upstream).
    Live cmdline matches recorded daemon_args; /healthz returns 200 +
    upstream='' — verify-setup exit 0."""
    (isolated_canary / ".iam-jit.yaml").write_text(
        "iam-jit:\n"
        "  canary: true\n"
        "  bouncers:\n"
        "    gbounce:\n"
        "      enabled: true\n"
        "      port: 7402\n"
        "      mgmt_port: 7412\n"
        "      daemon_args: ['--allow-connect']\n",
        encoding="utf-8",
    )
    cc.write_status({
        "ports": {"gbounce": 7402, "gbounce_mgmt": 7412},
        "pids": {"gbounce": 55555},
        "daemon_args": {"gbounce": ["--allow-connect"]},
    })

    # Stub live process: alive, cmdline contains --allow-connect, no --upstream.
    monkeypatch.setattr(cc, "_pid_alive", lambda pid: pid == 55555)
    monkeypatch.setattr(
        cc, "_process_cmdline",
        lambda pid: ["/path/to/gbounce", "run", "--port", "7402",
                     "--mgmt-port", "7412", "--allow-connect"],
    )
    # /healthz returns 200 with upstream="".
    monkeypatch.setattr(
        cc, "_curl_responsive", lambda url, timeout=3.0: (True, 200),
    )

    fake_body = json.dumps({"status": "ok", "upstream": ""}).encode("utf-8")

    class _FakeResp:
        def __init__(self) -> None:
            self._body = fake_body

        def read(self) -> bytes:
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(cc.urllib.request, "urlopen", lambda *a, **kw: _FakeResp())

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "verify-setup"])

    # 1. Reported success: exit 0.
    assert result.exit_code == 0, result.output
    # 2. Observable: human output shows the OK tag + bouncer name.
    assert "[OK" in result.output
    assert "gbounce" in result.output
    assert "All bouncers match operator intent" in result.output


# ---------------------------------------------------------------------------
# 5. verify-setup RED when smoke-test --upstream pin is live
# ---------------------------------------------------------------------------


def test_verify_setup_red_when_smoke_upstream(
    isolated_canary: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The §A102 calibration-drift bug #18 shape: live ibounce process
    has --upstream in cmdline but recorded daemon_args is []
    (general-proxy intent). verify-setup MUST flag this loudly +
    exit non-zero."""
    (isolated_canary / ".iam-jit.yaml").write_text(
        "iam-jit:\n"
        "  canary: true\n"
        "  bouncers:\n"
        "    ibounce:\n"
        "      enabled: true\n"
        "      port: 7401\n"
        "      daemon_args: []\n",
        encoding="utf-8",
    )
    cc.write_status({
        "ports": {"ibounce": 7401},
        "pids": {"ibounce": 12345},
        "daemon_args": {"ibounce": []},
    })

    # Live cmdline has --upstream — the bug #18 shape.
    monkeypatch.setattr(cc, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        cc, "_process_cmdline",
        lambda pid: [
            "/path/to/ibounce", "run", "--port", "7401",
            "--upstream", "http://127.0.0.1:4566",
        ],
    )
    monkeypatch.setattr(
        cc, "_curl_responsive", lambda url, timeout=3.0: (True, 200),
    )

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "verify-setup"])

    # 1. Reported failure: exit code 2 (CRIT).
    assert result.exit_code == 2, result.output
    # 2. Observable: human output flags the --upstream drift + the
    #    bug #18 framing.
    assert "[CRIT]" in result.output
    assert "--upstream" in result.output
    assert (
        "§A102" in result.output
        or "smoke-test pin leaking" in result.output
        or "daily-dev mode requires general proxy" in result.output
    )


# ---------------------------------------------------------------------------
# 6. verify-setup RED when recorded PID is dead
# ---------------------------------------------------------------------------


def test_verify_setup_red_when_pid_dead(
    isolated_canary: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Status.json records a PID that no longer exists — the bouncer
    crashed / was killed externally. verify-setup MUST flag this +
    exit non-zero."""
    cc.write_status({
        "ports": {"ibounce": 7401},
        "pids": {"ibounce": 99999999},
        "daemon_args": {"ibounce": []},
    })

    monkeypatch.setattr(cc, "_pid_alive", lambda pid: False)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "verify-setup"])

    # 1. Reported failure: non-zero.
    assert result.exit_code == 2, result.output
    # 2. Observable: human output identifies the dead PID.
    assert "[CRIT]" in result.output
    assert "99999999 not alive" in result.output or "not alive" in result.output


# ---------------------------------------------------------------------------
# 7. status.json records daemon_args (YAML→status→live round-trip)
# ---------------------------------------------------------------------------


def test_status_json_records_daemon_args(
    isolated_canary: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After _restart_bouncers runs the auto-relaunch path, status.json
    must mirror the daemon_args that came from the YAML — closing the
    YAML → status → live process round-trip so verify-setup + the
    next session both see the same intent."""
    (isolated_canary / ".iam-jit.yaml").write_text(
        "iam-jit:\n"
        "  canary: true\n"
        "  bouncers:\n"
        "    gbounce:\n"
        "      enabled: true\n"
        "      port: 7402\n"
        "      mgmt_port: 7412\n"
        "      daemon_args: ['--allow-connect']\n",
        encoding="utf-8",
    )
    cc.write_status({
        "ports": {"gbounce": 7402, "gbounce_mgmt": 7412},
        "pids": {"gbounce": 33333},
    })
    monkeypatch.setattr(
        cc.subprocess, "run",
        lambda *a, **kw: mock.Mock(stdout="", stderr="", returncode=0),
    )
    monkeypatch.setattr(cc.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(cc.time, "sleep", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        cc, "_relaunch_bouncer",
        lambda name, port, args, mgmt_port=None, **kw: (
            True, 88888, "fake"
        ),
    )

    pre = cc.read_status()
    ok, _msg = cc._restart_bouncers(pre)
    assert ok

    # State verification: status.json now contains daemon_args matching
    # the YAML — operator intent recorded once + visible cross-session.
    final = cc.read_status()
    assert final["daemon_args"]["gbounce"] == ["--allow-connect"]
    assert final["pids"]["gbounce"] == 88888

    # And the YAML loader returns the same args via the public helper
    # (so verify-setup picks them up).
    yaml_doc = cc.load_canary_yaml()
    assert cc.daemon_args_from_yaml(yaml_doc, "gbounce") == ["--allow-connect"]


# ---------------------------------------------------------------------------
# Registration: verify-setup must appear in `canary --help`.
# ---------------------------------------------------------------------------


def test_verify_setup_subcommand_registered() -> None:
    """The `iam-jit canary` group must list verify-setup so operators
    discover it. Catches accidental decorator drops."""
    runner = CliRunner()
    result = runner.invoke(main, ["canary", "--help"])
    assert result.exit_code == 0, result.output
    assert "verify-setup" in result.output


# ---------------------------------------------------------------------------
# Linux portability — per docs/LINUX-SUPPORT-AUDIT-2026-05-24.md
# ---------------------------------------------------------------------------


def test_port_bound_pure_python_no_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_port_bound` MUST be pure-stdlib (socket only) — no shelling
    out to `lsof`. Linux slim containers don't ship `lsof` and the
    canary update flow has to work there per LINUX-SUPPORT-AUDIT
    finding #1.

    State verification: monkeypatch subprocess.run to raise; if
    `_port_bound` ever shells out the test fails loudly.
    """
    def _no_subprocess(*a: Any, **kw: Any) -> Any:
        raise AssertionError(
            "_port_bound shelled out to subprocess; must be pure-stdlib"
        )

    monkeypatch.setattr(cc.subprocess, "run", _no_subprocess)
    # Probe a port that's definitely not bound. We don't care about
    # the result — only that it returns without raising.
    result = cc._port_bound(1)  # port 1 is reserved + not bound
    assert result is False  # Observable: no listener → False.


def test_lsof_pids_on_port_returns_empty_when_lsof_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_lsof_pids_on_port` MUST silently return [] when `lsof` is not
    on PATH — that's the Linux-slim-container shape. Callers (i.e.
    `_restart_bouncers`) then fall back to status.json recorded PIDs.
    """
    monkeypatch.setattr(cc.shutil, "which", lambda name: None)
    assert cc._lsof_pids_on_port(7401) == []


def test_restart_bouncers_uses_recorded_pids_no_lsof(
    isolated_canary: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When status.json records a live PID, `_restart_bouncers` MUST
    SIGTERM it directly without invoking `lsof` — works on Linux slim
    containers where `lsof` is absent.

    State verification: subprocess.run is monkeypatched to raise; the
    test will fail if any code path tries to shell out for PID
    discovery.
    """
    (isolated_canary / ".iam-jit.yaml").write_text(
        "iam-jit:\n"
        "  canary: true\n"
        "  bouncers:\n"
        "    ibounce:\n"
        "      enabled: true\n"
        "      port: 7401\n"
        "      daemon_args: []\n",
        encoding="utf-8",
    )
    cc.write_status({
        "ports": {"ibounce": 7401},
        "pids": {"ibounce": 12345},
    })

    # 1. PID-alive check returns True for the recorded PID.
    monkeypatch.setattr(cc, "_pid_alive", lambda pid: pid == 12345)
    # 2. SIGTERM is a no-op (we don't actually have PID 12345).
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        cc.os, "kill",
        lambda pid, sig: killed.append((pid, sig)),
    )
    # 3. Wait loop short-circuits: port is "released" immediately.
    monkeypatch.setattr(cc, "_port_bound", lambda port, host="127.0.0.1": False)
    monkeypatch.setattr(cc.time, "sleep", lambda *_a, **_kw: None)
    # 4. No subprocess.run anywhere on the hot path.
    monkeypatch.setattr(
        cc.subprocess, "run",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError(
                "_restart_bouncers shelled out (subprocess.run) "
                "for PID discovery; must use status.json recorded "
                "PIDs per LINUX-SUPPORT-AUDIT finding #1"
            )
        ),
    )
    # 5. _relaunch_bouncer is stubbed (we test it separately).
    monkeypatch.setattr(
        cc, "_relaunch_bouncer",
        lambda name, port, args, mgmt_port=None, **kw: (True, 99999, "stub"),
    )

    pre = cc.read_status()
    ok, msg = cc._restart_bouncers(pre)

    # 1. Reported success.
    assert ok, msg
    # 2. Observable: SIGTERM went to the RECORDED PID (12345), not a
    #    lsof-discovered one — proves the no-shell-out path is active.
    assert (12345, cc.signal.SIGTERM) in killed, (
        f"expected SIGTERM to recorded PID 12345; got {killed!r}"
    )
