"""#539 — `_fail()` complete-rollback-chain tests.

Per docs/MRR-4-ROLLBACK-RUNBOOK.md RB-D2/RB-D5 + docs/CONTRIBUTING.md
state-verification convention: pre-#539 the `_fail()` rollback was a
partial chain (git checkout only); operators had to run pip + restart
manually. Bug shape exactly mirrored #475 — the rollback path reported
"FAIL" + a single CRIT issue but the venv/Go binary/bouncer-process
side effects were still on the post-update tree.

#539 closes that gap. Each test below asserts:

  1. The reported status (what `_fail()` echoes / what canary report shows).
  2. The observable side effect (which subprocess.run calls happened,
     which issues.jsonl rows were appended, which CRIT step is named).

Helpers stub subprocess + os.kill + bouncer-process introspection so
the tests run hermetically — same posture as
``tests/test_cli_canary_daemon_args.py``.
"""

from __future__ import annotations

import pathlib
from typing import Any
from unittest import mock

import pytest
from click.testing import CliRunner  # noqa: F401  — kept for parity with sibling suites

import iam_jit.cli_canary as cc


# ---------------------------------------------------------------------------
# Shared fixtures (mirror tests/test_cli_canary_daemon_args.py)
# ---------------------------------------------------------------------------


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


def _baseline_status() -> dict[str, Any]:
    """Status.json shape that mirrors a real canary deploy."""
    return {
        "ports": {"ibounce": 7401, "gbounce": 7402, "gbounce_mgmt": 7412},
        "pids": {"ibounce": 11111, "gbounce": 22222},
        "daemon_args": {"ibounce": [], "gbounce": ["--allow-connect"]},
    }


def _stub_filesystem_repos(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> dict[str, pathlib.Path]:
    """Point `_CANARY_REPOS` at synthetic dirs the test owns so the
    rollback path's `_git` / `pip install` / `go install` invocations
    can be intercepted without touching the operator's real checkouts."""
    iam_roles = tmp_path / "iam-roles"
    gbounce = tmp_path / "gbounce"
    iam_roles.mkdir()
    gbounce.mkdir()
    (iam_roles / ".git").mkdir()  # so `_git` doesn't short-circuit
    (gbounce / ".git").mkdir()
    monkeypatch.setattr(
        cc, "_CANARY_REPOS",
        {"iam-roles": iam_roles, "gbounce": gbounce},
    )
    return {"iam-roles": iam_roles, "gbounce": gbounce}


def _stub_venv(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> pathlib.Path:
    """Create a synthetic ~/.iam-jit/venv/bin/pip path the rollback
    pip-install step will see + execute."""
    venv = tmp_path / "home" / ".iam-jit" / "venv" / "bin"
    venv.mkdir(parents=True)
    pip = venv / "pip"
    pip.write_text("#!/bin/sh\necho fake pip\n")
    pip.chmod(0o755)
    monkeypatch.setattr(
        cc.pathlib.Path, "home", classmethod(lambda cls: tmp_path / "home"),
    )
    return pip


class _SubprocessRecorder:
    """Captures every subprocess.run invocation + lets the test script
    the returncode / output per-call. The rollback chain's calls are:

      * `git checkout <sha>` per repo (one per `_CANARY_REPOS` entry)
      * `pip install -e .` (one)
      * `go install ./...` (one, only if `shutil.which('go')` succeeds)
      * `*bounce --version` per recorded bouncer
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        # Per-key scripted return; key is a stable shape derived from argv[0].
        self.responses: dict[str, mock.Mock] = {}
        self.default = mock.Mock(stdout="", stderr="", returncode=0)

    def for_argv(self, *, contains: str) -> mock.Mock | None:
        """Find a scripted response whose registered tag matches."""
        for key, resp in self.responses.items():
            if key in contains:
                return resp
        return None

    def __call__(self, argv, *args, **kwargs):
        cwd = kwargs.get("cwd")
        self.calls.append({"argv": list(argv), "cwd": cwd})
        # Try to match a scripted response by inspecting argv shape.
        joined = " ".join(str(a) for a in argv)
        match = self.for_argv(contains=joined)
        return match if match is not None else self.default


def _install_subprocess_stub(
    monkeypatch: pytest.MonkeyPatch,
) -> _SubprocessRecorder:
    rec = _SubprocessRecorder()
    monkeypatch.setattr(cc.subprocess, "run", rec)
    return rec


# ---------------------------------------------------------------------------
# 1. Happy path: every rollback step succeeds; no incomplete-rollback CRIT
# ---------------------------------------------------------------------------


def test_fail_complete_rollback_happy_path(
    isolated_canary: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All 6 post-rollback steps succeed; only the canonical
    update_failure CRIT is filed (no #539 incomplete-rollback CRIT)."""
    repos = _stub_filesystem_repos(monkeypatch, tmp_path)
    _stub_venv(monkeypatch, tmp_path)
    rec = _install_subprocess_stub(monkeypatch)

    # gbounce stub binary in synthetic ~/.go/bin so _bouncer_executable
    # returns a non-None path; force shutil.which to return it for "go".
    monkeypatch.setattr(cc.shutil, "which", lambda name: f"/fake/bin/{name}")
    # Make _bouncer_executable predictable for the version probe.
    monkeypatch.setattr(
        cc, "_bouncer_executable", lambda name: f"/fake/{name}",
    )

    # _restart_bouncers + _post_rollback_verify stubbed to True.
    monkeypatch.setattr(
        cc, "_restart_bouncers", lambda pre: (True, "stubbed restart OK"),
    )
    monkeypatch.setattr(
        cc, "_post_rollback_verify",
        lambda pre: (True, []),
    )

    cc.write_status(_baseline_status())

    cc._fail(
        msg="pip install -e . failed: deps explode",
        pre_status=_baseline_status(),
        pre_shas={"iam-roles": "abc123def456", "gbounce": "789012345678"},
        dry_run=False,
    )

    # 1. Reported status: canonical update_failure CRIT only.
    issues = cc.read_issues()
    crits = [i for i in issues if i.get("severity") == "CRIT"]
    assert len(crits) == 1, (
        f"happy-path rollback must file exactly 1 CRIT (the original "
        f"update_failure), not a #539 incomplete-rollback CRIT; got "
        f"{issues!r}"
    )
    assert crits[0]["category"] == "update_failure"
    assert "#539 rollback chain incomplete" not in crits[0]["observable"]

    # 2. Observable: subprocess saw git checkout per repo AND
    #    pip install -e . AND go install ./...
    argv_strs = [" ".join(c["argv"]) for c in rec.calls]
    git_checkouts = [
        s for s in argv_strs if "git" in s and "checkout" in s
    ]
    assert len(git_checkouts) == 2, (
        f"expected 2 git checkout calls (one per canary repo); "
        f"got {git_checkouts!r}"
    )
    pip_installs = [
        s for s in argv_strs if "pip" in s and "install -e ." in s
    ]
    assert pip_installs, (
        "rollback must run `pip install -e .` after git checkout; "
        f"argvs were {argv_strs!r}"
    )
    go_installs = [s for s in argv_strs if "go install ./..." in s]
    assert go_installs, (
        "rollback must run `go install ./...` after pip install; "
        f"argvs were {argv_strs!r}"
    )

    # 3. Observable: the pip install ran with cwd == iam-roles repo
    pip_call = next(c for c in rec.calls if "pip" in " ".join(c["argv"]))
    assert pip_call["cwd"] == str(repos["iam-roles"])


# ---------------------------------------------------------------------------
# 2. pip install failure files a #539 CRIT + halts the chain
# ---------------------------------------------------------------------------


def test_fail_complete_rollback_pip_install_failure_files_crit(
    isolated_canary: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When pip install fails during rollback, a SECOND CRIT must be
    appended naming the failing step + the chain must NOT proceed to
    go install / restart / verify."""
    _stub_filesystem_repos(monkeypatch, tmp_path)
    _stub_venv(monkeypatch, tmp_path)
    rec = _install_subprocess_stub(monkeypatch)
    # Scripted pip install failure.
    rec.responses["pip install -e ."] = mock.Mock(
        stdout="", stderr="ERROR: incompatible deps", returncode=1,
    )
    monkeypatch.setattr(cc.shutil, "which", lambda name: f"/fake/bin/{name}")

    restart_called = {"value": False}

    def fake_restart(pre):
        restart_called["value"] = True
        return True, "should not be called"

    monkeypatch.setattr(cc, "_restart_bouncers", fake_restart)

    cc.write_status(_baseline_status())
    cc._fail(
        msg="bouncer restart failed mid-update",
        pre_status=_baseline_status(),
        pre_shas={"iam-roles": "abc123", "gbounce": "def456"},
        dry_run=False,
    )

    # 1. Reported failure: 2 CRITs (canonical + #539 pip step).
    issues = cc.read_issues()
    crits = [i for i in issues if i.get("severity") == "CRIT"]
    assert len(crits) == 2, f"expected 2 CRITs; got {issues!r}"

    canonical = [c for c in crits if "#539" not in c["observable"]]
    incomplete = [c for c in crits if "#539" in c["observable"]]
    assert len(canonical) == 1
    assert len(incomplete) == 1
    assert incomplete[0]["related_task"] == "#539"
    assert "pip_install" in incomplete[0]["observable"]

    # 2. Observable: _restart_bouncers was NEVER called (chain halted).
    assert restart_called["value"] is False, (
        "pip install failure must halt the rollback chain BEFORE restart"
    )

    # 3. Observable: go install was NEVER attempted either.
    argv_strs = [" ".join(c["argv"]) for c in rec.calls]
    go_installs = [s for s in argv_strs if "go install ./..." in s]
    assert not go_installs, (
        f"go install must NOT run after pip install failed; "
        f"argvs were {argv_strs!r}"
    )


# ---------------------------------------------------------------------------
# 3. _restart_bouncers failure files a #539 CRIT + halts before verify
# ---------------------------------------------------------------------------


def test_fail_complete_rollback_restart_failure_files_crit(
    isolated_canary: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When _restart_bouncers returns (False, msg) during rollback,
    a #539 CRIT names the restart_bouncers step + verify-setup is NOT
    invoked."""
    _stub_filesystem_repos(monkeypatch, tmp_path)
    _stub_venv(monkeypatch, tmp_path)
    _install_subprocess_stub(monkeypatch)
    monkeypatch.setattr(cc.shutil, "which", lambda name: f"/fake/bin/{name}")
    monkeypatch.setattr(
        cc, "_bouncer_executable", lambda name: f"/fake/{name}",
    )

    monkeypatch.setattr(
        cc, "_restart_bouncers",
        lambda pre: (False, "fake: relaunch failed"),
    )

    verify_called = {"value": False}

    def fake_verify(pre):
        verify_called["value"] = True
        return True, []

    monkeypatch.setattr(cc, "_post_rollback_verify", fake_verify)

    cc.write_status(_baseline_status())
    cc._fail(
        msg="go install failed",
        pre_status=_baseline_status(),
        pre_shas={"iam-roles": "abc123", "gbounce": "def456"},
        dry_run=False,
    )

    # 1. Reported failure: canonical + #539 restart_bouncers CRIT.
    issues = cc.read_issues()
    incomplete = [
        i for i in issues
        if i.get("severity") == "CRIT" and "#539" in i.get("observable", "")
    ]
    assert len(incomplete) == 1
    assert "restart_bouncers" in incomplete[0]["observable"]
    assert "fake: relaunch failed" in incomplete[0]["observable"]

    # 2. Observable: verify-setup was NEVER invoked (chain halted).
    assert verify_called["value"] is False


# ---------------------------------------------------------------------------
# 4. verify-setup failure files a #539 CRIT (final-step failure)
# ---------------------------------------------------------------------------


def test_fail_complete_rollback_verify_failure_files_crit(
    isolated_canary: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When _post_rollback_verify reports problems, a #539 CRIT names
    the verify_setup step + the problems list is surfaced."""
    _stub_filesystem_repos(monkeypatch, tmp_path)
    _stub_venv(monkeypatch, tmp_path)
    _install_subprocess_stub(monkeypatch)
    monkeypatch.setattr(cc.shutil, "which", lambda name: f"/fake/bin/{name}")
    monkeypatch.setattr(
        cc, "_bouncer_executable", lambda name: f"/fake/{name}",
    )
    monkeypatch.setattr(
        cc, "_restart_bouncers", lambda pre: (True, "ok"),
    )
    monkeypatch.setattr(
        cc, "_post_rollback_verify",
        lambda pre: (False, ["ibounce: PID 11111 not alive"]),
    )

    cc.write_status(_baseline_status())
    cc._fail(
        msg="initial update_failure",
        pre_status=_baseline_status(),
        pre_shas={"iam-roles": "abc123", "gbounce": "def456"},
        dry_run=False,
    )

    issues = cc.read_issues()
    incomplete = [
        i for i in issues
        if i.get("severity") == "CRIT" and "#539" in i.get("observable", "")
    ]
    assert len(incomplete) == 1
    assert "verify_setup" in incomplete[0]["observable"]
    assert "PID 11111 not alive" in incomplete[0]["observable"]


# ---------------------------------------------------------------------------
# 5. git_checkout failure files #539 CRIT + halts chain immediately
# ---------------------------------------------------------------------------


def test_fail_complete_rollback_git_checkout_failure_halts(
    isolated_canary: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When git checkout fails for one repo, the chain MUST NOT proceed
    to pip/go/restart — bailing out early avoids operating on a
    half-reverted tree."""
    _stub_filesystem_repos(monkeypatch, tmp_path)
    _stub_venv(monkeypatch, tmp_path)
    rec = _install_subprocess_stub(monkeypatch)
    # Make the first git checkout fail.
    rec.responses["git checkout"] = mock.Mock(
        stdout="", stderr="error: index lock", returncode=1,
    )

    restart_called = {"value": False}
    monkeypatch.setattr(
        cc, "_restart_bouncers",
        lambda pre: (restart_called.update({"value": True}), True, "")[1:],
    )

    cc.write_status(_baseline_status())
    cc._fail(
        msg="bouncer restart failed",
        pre_status=_baseline_status(),
        pre_shas={"iam-roles": "abc123", "gbounce": "def456"},
        dry_run=False,
    )

    # 1. Reported: canonical CRIT + #539 git_checkout CRIT.
    issues = cc.read_issues()
    incomplete = [
        i for i in issues
        if i.get("severity") == "CRIT" and "#539" in i.get("observable", "")
    ]
    assert len(incomplete) == 1
    assert "git_checkout" in incomplete[0]["observable"]

    # 2. Observable: pip install + restart never ran (chain halted).
    argv_strs = [" ".join(c["argv"]) for c in rec.calls]
    pip_installs = [s for s in argv_strs if "pip" in s and "install -e ." in s]
    assert not pip_installs, (
        f"git checkout failure must halt BEFORE pip install; argvs={argv_strs!r}"
    )
    assert restart_called["value"] is False
