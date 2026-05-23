"""§A101 — `iam-jit canary update --watch` safety + doc-truth tests.

Pre-§A101 ``--watch`` polled (somewhere — the help text claimed
'LOCAL only / no phone-home' but in fact called ``git fetch`` which
contacts the remote) and on a new origin/main commit auto-redeployed.
That's a footgun under the standing ``[[push-policy-public-repo]]``
discipline: every commit landing on any of the 3 tracked repos
becomes a live install with no operator-in-the-loop.

Post-§A101:

  * ``--watch`` alone is NOTIFY-ONLY. New commits are reported to
    stdout + appended as a HIGH-severity issue to issues.jsonl.
    ``_do_one_update`` is NOT called.
  * ``--watch --auto-deploy`` restores the pre-§A101 behaviour. A
    WARN line is logged at watch-loop start so the operator sees
    the autopilot posture.
  * Help text honestly describes the polling behaviour (it contacts
    remote git) and the autopilot opt-in.

State-verified per ``docs/CONTRIBUTING.md``:

  * notify-only test asserts BOTH that ``_do_one_update`` was not
    called AND that an entry appears in issues.jsonl.
  * auto-deploy test asserts BOTH that ``_do_one_update`` WAS called
    AND that the WARN line appears in stdout.
  * help-text test asserts the string contents of the rendered
    --help output, which is the observable surface an operator
    actually sees.
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
    canary_dir = tmp_path / "canary"
    canary_dir.mkdir()
    monkeypatch.setattr(cc, "CANARY_DIR", canary_dir)
    monkeypatch.setattr(cc, "ISSUES_PATH", canary_dir / "issues.jsonl")
    monkeypatch.setattr(cc, "NOTES_PATH", canary_dir / "notes.md")
    monkeypatch.setattr(cc, "STATUS_PATH", canary_dir / "status.json")
    monkeypatch.setattr(cc, "URLS_PATH", canary_dir / "urls.md")
    return canary_dir


def _git_responses_for_new_commits(repo_names: list[str]):
    """Build a side-effect function for ``cc._git`` that simulates
    'remote has new commits on every tracked repo'.

    The watch loop calls _git(repo, 'fetch', ...) then 'rev-parse
    HEAD' then 'rev-parse @{u}'. We make HEAD != upstream so the
    loop sees new commits."""
    call_log: list[tuple] = []

    def fake_git(repo, *args):
        call_log.append((str(repo), args))
        if args[0] == "fetch":
            return (0, "")
        if args == ("rev-parse", "HEAD"):
            return (0, "a" * 40)  # current HEAD
        if args == ("rev-parse", "@{u}"):
            return (0, "b" * 40)  # upstream is ahead
        return (0, "")

    return fake_git, call_log


# ---------------------------------------------------------------------------
# 1. --watch alone is NOTIFY-ONLY (default behaviour change vs pre-§A101)
# ---------------------------------------------------------------------------


def test_watch_default_is_notify_only_does_not_auto_deploy(
    isolated_canary, monkeypatch,
) -> None:
    """The §A101 default: ``--watch`` alone MUST NOT call
    ``_do_one_update`` even when the upstream has new commits.

    State verification: issues.jsonl ends up with at least one
    entry (the notification) AND the _do_one_update mock was
    never invoked."""
    fake_git, _ = _git_responses_for_new_commits(
        list(cc._CANARY_REPOS.keys())
    )
    monkeypatch.setattr(cc, "_git", fake_git)

    do_update_calls: list[dict] = []

    def fake_update(*, dry_run):
        do_update_calls.append({"dry_run": dry_run})

    monkeypatch.setattr(cc, "_do_one_update", fake_update)

    # Break out of the infinite loop after the first sleep.
    def fake_sleep(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(cc.time, "sleep", fake_sleep)

    runner = CliRunner()
    result = runner.invoke(
        main, ["canary", "update", "--watch", "--interval", "1s"],
        catch_exceptions=True,
    )
    # Click catches KeyboardInterrupt and converts it to SystemExit
    # via click.Abort. Either is acceptable — the test just needs
    # the watch loop to terminate so we can inspect side effects.
    assert isinstance(result.exception, (KeyboardInterrupt, SystemExit)), (
        f"expected KeyboardInterrupt / SystemExit from fake_sleep, "
        f"got {result.exception!r}; output:\n{result.output}"
    )

    # 1. Claim verification: stdout reports new commits were seen.
    assert "new commits" in result.output, result.output

    # 2. State verification A: _do_one_update was NOT called.
    assert do_update_calls == [], (
        f"§A101 regression: --watch (no --auto-deploy) called "
        f"_do_one_update {len(do_update_calls)} time(s). The default "
        f"MUST be notify-only."
    )

    # 3. State verification B: notification landed in issues.jsonl.
    issues_path = isolated_canary / "issues.jsonl"
    assert issues_path.exists(), "issues.jsonl was not written"
    lines = issues_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1, (
        f"§A101 regression: notify-only mode did not append to "
        f"issues.jsonl. Found {len(lines)} entries."
    )
    parsed = [json.loads(line) for line in lines]
    # The existing _CATEGORIES taxonomy doesn't have a dedicated
    # 'update_available' bucket so the §A101 entry is filed under
    # 'other' with the §A101 marker in the observable string.
    assert any(
        e.get("severity") == "HIGH"
        and e.get("related_task") == "§A101"
        and "update_available" in (e.get("observable") or "")
        for e in parsed
    ), (
        f"§A101 regression: no HIGH-severity §A101 'update_available' "
        f"entry in issues.jsonl. Got: {parsed}"
    )

    # 4. State verification C: stdout banner reflects the notify-only
    # posture, not the pre-§A101 'no phone-home' lie.
    assert "notify-only" in result.output.lower() or "NOT auto-deploying" in result.output


# ---------------------------------------------------------------------------
# 2. --watch --auto-deploy DOES call _do_one_update + logs a WARN
# ---------------------------------------------------------------------------


def test_watch_with_auto_deploy_calls_do_one_update_and_warns(
    isolated_canary, monkeypatch,
) -> None:
    """``--watch --auto-deploy`` is the explicit opt-in to autopilot
    redeploy. The §A101 contract: ``_do_one_update`` IS called AND a
    WARN line surfaces at watch-loop start so the operator sees
    the autopilot posture in the terminal."""
    fake_git, _ = _git_responses_for_new_commits(
        list(cc._CANARY_REPOS.keys())
    )
    monkeypatch.setattr(cc, "_git", fake_git)

    do_update_calls: list[dict] = []

    def fake_update(*, dry_run):
        do_update_calls.append({"dry_run": dry_run})

    monkeypatch.setattr(cc, "_do_one_update", fake_update)

    def fake_sleep(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(cc.time, "sleep", fake_sleep)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "canary", "update", "--watch", "--auto-deploy",
            "--interval", "1s",
        ],
        catch_exceptions=True,
    )
    assert isinstance(result.exception, (KeyboardInterrupt, SystemExit)), (
        f"output:\n{result.output}"
    )

    # 1. WARN banner fires at start.
    assert "WARNING" in result.output, (
        f"§A101 regression: --watch --auto-deploy did NOT fire the "
        f"autopilot WARN at startup. Output:\n{result.output}"
    )
    assert "auto-deploy" in result.output.lower()

    # 2. _do_one_update WAS called.
    assert len(do_update_calls) >= 1, (
        f"§A101 regression: --watch --auto-deploy did NOT call "
        f"_do_one_update. Calls: {do_update_calls}"
    )


# ---------------------------------------------------------------------------
# 3. Help text is honest (no 'LOCAL only / no phone-home' lie)
# ---------------------------------------------------------------------------


def test_help_text_is_truthful_about_remote_polling() -> None:
    """The pre-§A101 help string ``LOCAL git fetch only; no phone-
    home`` is a lie — ``git fetch`` contacts the remote. Per
    ``[[ibounce-honest-positioning]]`` user-facing claims MUST be
    honest. The post-§A101 help text MUST mention 'remote' AND
    require explicit ``--auto-deploy`` opt-in for autopilot."""
    runner = CliRunner()
    result = runner.invoke(main, ["canary", "update", "--help"])
    assert result.exit_code == 0, result.output

    out = result.output.lower()

    # State verification: the help text MUST contain honesty
    # signals about what the watch loop actually does.
    assert "remote" in out, (
        f"§A101 regression: help text omits the word 'remote'. The "
        f"watch loop contacts origin via git fetch — the operator "
        f"needs to know that. Output:\n{result.output}"
    )
    assert "auto-deploy" in out, (
        f"§A101 regression: help text omits 'auto-deploy'. The opt-in "
        f"flag MUST be visible in --help. Output:\n{result.output}"
    )

    # And the --watch flag's own help text MUST NOT contain the
    # pre-§A101 lie. We scope this assertion to the --watch flag's
    # description block (not the surrounding docstring, where
    # "phone-home" still legitimately disclaims phone-home-to-iam-
    # jit-the-company in a clarifying paragraph).
    #
    # The --watch flag rendered help block ends at the next --flag
    # boundary in Click's output.
    watch_block_start = out.find("--watch")
    assert watch_block_start >= 0, "no --watch in help"
    watch_block_end = out.find("--auto-deploy", watch_block_start)
    if watch_block_end < 0:
        watch_block_end = out.find("--interval", watch_block_start)
    watch_block = out[watch_block_start:watch_block_end]
    assert "local git fetch only" not in watch_block, (
        f"§A101 regression: --watch help reintroduced the "
        f"misleading 'LOCAL git fetch only' claim. git fetch "
        f"contacts the remote. Block:\n{watch_block}"
    )


def test_auto_deploy_help_exists() -> None:
    """The --auto-deploy flag MUST appear in --help."""
    runner = CliRunner()
    result = runner.invoke(main, ["canary", "update", "--help"])
    assert result.exit_code == 0
    assert "--auto-deploy" in result.output


# ---------------------------------------------------------------------------
# 4. The notify-only banner ALSO honestly explains what's happening
# ---------------------------------------------------------------------------


def test_notify_only_banner_explains_polling_and_no_redeploy(
    isolated_canary, monkeypatch,
) -> None:
    """When ``--watch`` (notify-only) starts, the operator MUST see
    a banner that says 'polling remote' + 'no auto-redeploy' so
    they're not confused into thinking the loop is doing nothing."""
    fake_git, _ = _git_responses_for_new_commits(
        list(cc._CANARY_REPOS.keys())
    )
    monkeypatch.setattr(cc, "_git", fake_git)
    monkeypatch.setattr(cc, "_do_one_update", lambda *, dry_run: None)

    def fake_sleep(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(cc.time, "sleep", fake_sleep)

    runner = CliRunner()
    result = runner.invoke(
        main, ["canary", "update", "--watch", "--interval", "1s"],
        catch_exceptions=True,
    )
    assert isinstance(result.exception, (KeyboardInterrupt, SystemExit))
    # Banner mentions polling-the-remote AND no-auto-redeploy.
    assert "polling remote" in result.output.lower()
    assert "no auto-redeploy" in result.output.lower() or "notify-only" in result.output.lower()
