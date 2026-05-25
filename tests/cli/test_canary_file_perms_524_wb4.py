"""#524 WB-4 — restrictive perms on canary state files.

Per ``[[ibounce-honest-positioning]]`` perms ARE part of operator
trust posture. The #484 audit flagged WB-4: ``cli_canary.py`` wrote
operator state (``issues.jsonl``, ``status.json``, ``monitor.state.json``,
bouncer logs under ``~/.iam-jit/canary/``) with the process default
0o755 dir + 0o644 file perms. Audit metadata + deploy URLs + bouncer
logs warrant restrictive perms by default.

The fix introduces three helpers on ``cli_canary``:

* ``_ensure_dir(path=None)`` — ``mkdir(mode=0o700)`` + ``chmod`` to
  tighten an existing dir created with broader perms
* ``_atomic_write_canary_file(path, contents)`` — ``os.open`` +
  ``fdopen`` with ``O_CREAT mode=0o600`` + atomic rename; mirrors the
  ``local_server.py`` cli-token writer
* ``_append_canary_jsonl(path, line)`` — ``os.open`` with
  ``O_APPEND | O_CREAT, 0o600`` + post-write ``chmod`` to tighten any
  pre-existing broad-perm file

Per ``docs/CONTRIBUTING.md`` state-verification convention every test
below asserts the ACTUAL ``stat.st_mode`` on disk, not "the chmod
was called". A sabotage check confirms the perm-setting code is
load-bearing (removing it makes a positive test fail).

Skipped on Windows where POSIX mode bits are simulated and don't
reflect real ACL state.
"""

from __future__ import annotations

import json
import os
import pathlib
import platform
import stat

import pytest
from click.testing import CliRunner

import iam_jit.cli_canary as cc
from iam_jit.cli import main


pytestmark = pytest.mark.skipif(
    platform.system() == "Windows",
    reason=(
        "POSIX mode bits on Windows are simulated by the runtime and "
        "do not reflect ACL-backed access control; the WB-4 fix is a "
        "POSIX-only posture by design."
    ),
)


def _mode(path: pathlib.Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_canary(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Point every canary-module path at a tmp dir.

    NOTE: unlike the broader test_cli_canary.py fixture this one does
    NOT pre-create the canary dir — the perms tests need to observe
    the helper's mode-on-creation behaviour from a clean slate.
    """
    canary_dir = tmp_path / "canary"
    monkeypatch.setattr(cc, "CANARY_DIR", canary_dir)
    monkeypatch.setattr(cc, "ISSUES_PATH", canary_dir / "issues.jsonl")
    monkeypatch.setattr(cc, "NOTES_PATH", canary_dir / "notes.md")
    monkeypatch.setattr(cc, "STATUS_PATH", canary_dir / "status.json")
    monkeypatch.setattr(cc, "URLS_PATH", canary_dir / "urls.md")
    monkeypatch.setattr(cc, "CANARY_YAML_PATH", canary_dir / ".iam-jit.yaml")
    monkeypatch.setattr(
        cc, "MONITOR_STATE_PATH", canary_dir / "monitor.state.json",
    )
    return canary_dir


# ---------------------------------------------------------------------------
# Directory helper — _ensure_dir
# ---------------------------------------------------------------------------


def test_ensure_dir_creates_directory_with_0o700(
    isolated_canary: pathlib.Path,
) -> None:
    """A fresh canary dir is created 0o700."""
    assert not isolated_canary.exists()
    cc._ensure_dir()
    assert isolated_canary.is_dir()
    assert _mode(isolated_canary) == 0o700, (
        f"expected canary dir 0o700, got 0o{_mode(isolated_canary):o}"
    )


def test_ensure_dir_tightens_preexisting_directory_with_broad_perms(
    isolated_canary: pathlib.Path,
) -> None:
    """A pre-existing 0o755 dir is tightened to 0o700 on next call.

    The bug shape this prevents: operator (or a pre-#524 deploy
    script) created ``~/.iam-jit/canary/`` with 0o755; nothing in the
    CLI tightened it. Now any CLI write path that goes through
    ``_ensure_dir`` repairs the posture.
    """
    isolated_canary.mkdir(parents=True, mode=0o755)
    os.chmod(isolated_canary, 0o755)
    assert _mode(isolated_canary) == 0o755
    cc._ensure_dir()
    assert _mode(isolated_canary) == 0o700


def test_ensure_dir_accepts_alternate_path_argument(
    isolated_canary: pathlib.Path,
) -> None:
    """The helper can also harden non-CANARY_DIR paths (e.g. log dir)."""
    log_dir = isolated_canary / "logs"
    cc._ensure_dir(log_dir)
    assert log_dir.is_dir()
    assert _mode(log_dir) == 0o700


# ---------------------------------------------------------------------------
# Full-file writer — _atomic_write_canary_file
# ---------------------------------------------------------------------------


def test_atomic_write_canary_file_creates_file_with_0o600(
    isolated_canary: pathlib.Path,
) -> None:
    """``write_status`` and friends call this; resulting file is 0o600."""
    target = isolated_canary / "status.json"
    cc._atomic_write_canary_file(target, json.dumps({"k": 1}) + "\n")
    assert target.exists()
    assert _mode(target) == 0o600, (
        f"expected status file 0o600, got 0o{_mode(target):o}"
    )
    # Side-effect: content was actually written (state-verification —
    # the perms claim must be backed by an actually-written file).
    assert json.loads(target.read_text(encoding="utf-8")) == {"k": 1}


def test_atomic_write_canary_file_tightens_preexisting_broad_perms(
    isolated_canary: pathlib.Path,
) -> None:
    """A pre-existing 0o644 file is rewritten + ends up 0o600.

    The atomic rename copies the tmp's mode (0o600) over the prior
    file, so even a file the operator chmod'd 0o644 manually ends up
    locked down after the next write.
    """
    isolated_canary.mkdir(parents=True, mode=0o700)
    target = isolated_canary / "status.json"
    target.write_text("old", encoding="utf-8")
    os.chmod(target, 0o644)
    assert _mode(target) == 0o644
    cc._atomic_write_canary_file(target, "new")
    assert _mode(target) == 0o600
    assert target.read_text(encoding="utf-8") == "new"


def test_write_status_persists_file_at_0o600_end_to_end(
    isolated_canary: pathlib.Path,
) -> None:
    """Public ``write_status`` call results in 0o600 on disk."""
    cc.write_status({"canary_day": 1, "started_at": "2026-05-25T00:00:00Z"})
    assert _mode(isolated_canary / "status.json") == 0o600
    # State verification: dir is also locked down.
    assert _mode(isolated_canary) == 0o700


# ---------------------------------------------------------------------------
# Append-only JSONL writer — _append_canary_jsonl
# ---------------------------------------------------------------------------


def test_append_canary_jsonl_creates_file_with_0o600_on_first_write(
    isolated_canary: pathlib.Path,
) -> None:
    target = isolated_canary / "issues.jsonl"
    cc._append_canary_jsonl(target, json.dumps({"i": 1}))
    assert _mode(target) == 0o600
    assert target.read_text(encoding="utf-8") == '{"i": 1}\n'


def test_append_canary_jsonl_tightens_preexisting_broad_perms(
    isolated_canary: pathlib.Path,
) -> None:
    """A pre-existing 0o644 JSONL is tightened to 0o600 on next append.

    ``O_CREAT`` mode only fires on creation; the post-write ``chmod``
    is what repairs the posture for a file the operator (or pre-#524
    code) left broad.
    """
    isolated_canary.mkdir(parents=True, mode=0o700)
    target = isolated_canary / "issues.jsonl"
    target.write_text('{"prior": true}\n', encoding="utf-8")
    os.chmod(target, 0o644)
    assert _mode(target) == 0o644
    cc._append_canary_jsonl(target, json.dumps({"i": 2}))
    assert _mode(target) == 0o600
    # State verification: both prior and new lines are present.
    lines = target.read_text(encoding="utf-8").splitlines()
    assert lines == ['{"prior": true}', '{"i": 2}']


def test_append_issue_helper_writes_0o600_jsonl(
    isolated_canary: pathlib.Path,
) -> None:
    """The public ``append_issue`` (used by ``canary file-issue``)
    routes through the hardened helper."""
    cc.append_issue(
        bouncer="ibounce",
        severity="HIGH",
        category="deny_surprise",
        observable="test",
        expected="",
    )
    target = isolated_canary / "issues.jsonl"
    assert target.exists()
    assert _mode(target) == 0o600


# ---------------------------------------------------------------------------
# End-to-end CLI test
# ---------------------------------------------------------------------------


def test_canary_file_issue_cli_produces_0o600_file_end_to_end(
    isolated_canary: pathlib.Path,
) -> None:
    """``iam-jit canary file-issue`` end-to-end leaves issues.jsonl 0o600."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "canary", "file-issue",
            "--severity", "HIGH",
            "--category", "deny_surprise",
            "--bouncer", "ibounce",
            "--note", "wb4-perms end-to-end",
        ],
    )
    assert result.exit_code == 0, result.output
    issues_path = isolated_canary / "issues.jsonl"
    assert issues_path.exists()
    assert _mode(issues_path) == 0o600, (
        f"CLI-written issues.jsonl perms: expected 0o600, "
        f"got 0o{_mode(issues_path):o}"
    )
    # State verification: the perm claim is backed by an actually-
    # written + parseable entry.
    lines = issues_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["observable"] == "wb4-perms end-to-end"
    # And the parent dir is also 0o700.
    assert _mode(isolated_canary) == 0o700


# ---------------------------------------------------------------------------
# Sabotage check — proves perm-setting code is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_check_perm_setting_is_load_bearing(
    isolated_canary: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If we monkey-patch ``os.chmod`` to a no-op AND force the
    underlying ``os.open`` to pass mode=0o644 instead of 0o600, the
    end-to-end test's perm assertion fails.

    The point: this test would PASS the file-perm assertion only if
    perm-setting is purely cosmetic (chmod is decorative + open
    flags are wrong). Forcing both to broad perms proves the
    production code's perm-tightening is what makes the other tests
    pass — not the operating system's default umask.
    """
    real_open = os.open

    def broad_open(path, flags, mode=0o777, *args, **kwargs):
        # Strip O_NOFOLLOW so the underlying call still works on
        # platforms where it's not supported.
        return real_open(path, flags, 0o644, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", lambda *a, **k: None)
    monkeypatch.setattr(cc.os, "open", broad_open)
    # Also defeat the explicit chmod in _ensure_dir by monkey-patching
    # the module-attr (cc.os is the same module so the above already
    # covers it, but pin for clarity).
    monkeypatch.setattr(cc.os, "chmod", lambda *a, **k: None)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "canary", "file-issue",
            "--severity", "HIGH",
            "--category", "deny_surprise",
            "--bouncer", "ibounce",
            "--note", "sabotage check",
        ],
    )
    # The CLI still SUCCEEDS — sabotage only nukes perms, not function.
    assert result.exit_code == 0, result.output

    issues_path = isolated_canary / "issues.jsonl"
    assert issues_path.exists()
    # With sabotage applied, the perms should NOT be 0o600 — proving
    # the hardening code in production is load-bearing.
    sabotaged_mode = _mode(issues_path)
    assert sabotaged_mode != 0o600, (
        f"sabotage check failed: even with chmod no-op'd and open mode "
        f"forced to 0o644, the file ended up 0o{sabotaged_mode:o} — "
        f"this means the production perm-setting code is NOT what "
        f"makes the positive tests pass, which invalidates the fix"
    )
