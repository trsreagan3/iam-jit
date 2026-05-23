"""Tests for the `iam-jit canary` subcommand cluster (#507 / §A92).

Per ``docs/CONTRIBUTING.md`` state-verification convention: every test
that asserts a reported success status MUST also assert the observable
state matches. Each test below pairs an exit-0 assertion with a
file-on-disk / output-content assertion.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from click.testing import CliRunner

import iam_jit.cli_canary as cc
from iam_jit.cli import main


@pytest.fixture
def isolated_canary(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    """Point ALL canary-module paths at a tmp dir.

    The module reads CANARY_DIR / ISSUES_PATH / NOTES_PATH / STATUS_PATH /
    URLS_PATH at import time; monkey-patch them per test for isolation.
    """
    canary_dir = tmp_path / "canary"
    canary_dir.mkdir()
    monkeypatch.setattr(cc, "CANARY_DIR", canary_dir)
    monkeypatch.setattr(cc, "ISSUES_PATH", canary_dir / "issues.jsonl")
    monkeypatch.setattr(cc, "NOTES_PATH", canary_dir / "notes.md")
    monkeypatch.setattr(cc, "STATUS_PATH", canary_dir / "status.json")
    monkeypatch.setattr(cc, "URLS_PATH", canary_dir / "urls.md")
    return canary_dir


# -- append_issue / read_issues ------------------------------------------


def test_append_issue_writes_jsonl_entry(isolated_canary: pathlib.Path) -> None:
    entry = cc.append_issue(
        bouncer="ibounce",
        severity="HIGH",
        category="deny_surprise",
        observable="aws s3 ls denied unexpectedly",
        expected="aws s3 ls allowed",
        repro_hint="HTTPS_PROXY=http://localhost:7401 aws s3 ls",
        auto_generated=False,
        related_task="#507",
    )

    # 1. Returned dict carries the entry shape.
    assert entry["severity"] == "HIGH"
    assert entry["category"] == "deny_surprise"

    # 2. Observable: the file ACTUALLY contains the JSON line.
    path = isolated_canary / "issues.jsonl"
    assert path.exists()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["severity"] == "HIGH"
    assert parsed["observable"] == "aws s3 ls denied unexpectedly"
    assert parsed["related_task"] == "#507"


def test_append_issue_rejects_bad_severity(isolated_canary: pathlib.Path) -> None:
    with pytest.raises(ValueError, match="severity must be one of"):
        cc.append_issue(
            bouncer="ibounce",
            severity="EXTREME",  # not in _SEVERITIES
            category="other",
            observable="x",
            expected="y",
        )
    # State: file does NOT exist (no partial write).
    assert not (isolated_canary / "issues.jsonl").exists()


def test_append_issue_rejects_bad_category(isolated_canary: pathlib.Path) -> None:
    with pytest.raises(ValueError, match="category must be one of"):
        cc.append_issue(
            bouncer="ibounce",
            severity="LOW",
            category="surprise_party",
            observable="x",
            expected="y",
        )
    assert not (isolated_canary / "issues.jsonl").exists()


def test_read_issues_filters_by_since(isolated_canary: pathlib.Path) -> None:
    cc.append_issue(
        bouncer="ibounce",
        severity="LOW",
        category="other",
        observable="old",
        expected="y",
        ts="2025-01-01T00:00:00Z",
    )
    cc.append_issue(
        bouncer="ibounce",
        severity="LOW",
        category="other",
        observable="new",
        expected="y",
        ts="2099-01-01T00:00:00Z",
    )

    all_issues = cc.read_issues()
    assert len(all_issues) == 2

    recent = cc.read_issues(since_iso="2050-01-01T00:00:00Z")
    assert len(recent) == 1
    assert recent[0]["observable"] == "new"


# -- status command ------------------------------------------------------


def test_status_cmd_no_file_exits_nonzero(isolated_canary: pathlib.Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["canary", "status"])
    assert result.exit_code == 1
    assert "No canary status yet" in (result.output + (result.stderr or ""))


def test_status_cmd_renders_status_file(isolated_canary: pathlib.Path) -> None:
    cc.write_status(
        {
            "canary_day": 1,
            "started_at": "2026-05-23T22:00:00Z",
            "llm_mode": "agent-delegated",
            "bouncers": {"ibounce": "discovery", "gbounce": "discovery"},
            "ports": {"ibounce": 7401, "gbounce": 7402},
            "commits": {"iam-roles": "abc1234567890", "gbounce": "def4567890123"},
        }
    )
    # State precondition: file exists with the data we wrote.
    assert (isolated_canary / "status.json").exists()

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "status"])
    assert result.exit_code == 0, result.output
    # Observable: each key/value pair is visible in human output.
    assert "canary_day" in result.output
    assert "ibounce" in result.output
    assert "7401" in result.output
    assert "agent-delegated" in result.output


def test_status_cmd_json_emits_verbatim(isolated_canary: pathlib.Path) -> None:
    data = {"canary_day": 2, "llm_mode": "agent-delegated"}
    cc.write_status(data)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "status", "--json"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    # Observable: round-trips faithfully.
    assert parsed == data


# -- urls command --------------------------------------------------------


def test_urls_cmd_prints_urls_md(isolated_canary: pathlib.Path) -> None:
    (isolated_canary / "urls.md").write_text(
        "# canary urls\n- ibounce: http://localhost:7401/healthz\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(main, ["canary", "urls"])
    assert result.exit_code == 0
    assert "http://localhost:7401/healthz" in result.output


def test_urls_cmd_no_file_exits_nonzero(isolated_canary: pathlib.Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["canary", "urls"])
    assert result.exit_code == 1


# -- file-issue command --------------------------------------------------


def test_file_issue_cmd_appends_to_jsonl(isolated_canary: pathlib.Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "canary",
            "file-issue",
            "--severity",
            "MED",
            "--category",
            "operator_friction",
            "--bouncer",
            "gbounce",
            "--note",
            "gh CLI was slow through proxy",
            "--repro-hint",
            "gh pr list",
        ],
    )
    # 1. Reported success.
    assert result.exit_code == 0, result.output

    # 2. Observable: the file contains the entry with all fields.
    path = isolated_canary / "issues.jsonl"
    assert path.exists()
    entries = [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]
    assert len(entries) == 1
    e = entries[0]
    assert e["severity"] == "MED"
    assert e["category"] == "operator_friction"
    assert e["bouncer"] == "gbounce"
    assert e["observable"] == "gh CLI was slow through proxy"
    assert e["repro_hint"] == "gh pr list"
    assert e["auto_generated"] is False


def test_file_issue_cmd_rejects_bad_severity_via_click(
    isolated_canary: pathlib.Path,
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "canary",
            "file-issue",
            "--severity",
            "BANANA",
            "--note",
            "x",
        ],
    )
    # Click rejects with exit 2 (usage error). State: no file written.
    assert result.exit_code != 0
    assert not (isolated_canary / "issues.jsonl").exists()


# -- report command ------------------------------------------------------


def test_report_cmd_human_summary(isolated_canary: pathlib.Path) -> None:
    cc.write_status({"canary_day": 3, "denies_24h": 5})
    cc.append_issue(
        bouncer="ibounce",
        severity="HIGH",
        category="deny_surprise",
        observable="s3 list denied",
        expected="allowed",
    )
    (isolated_canary / "notes.md").write_text(
        "## 2099-01-01 12:00\nbouncer felt slow on sam build\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "report", "--since", "all"])
    assert result.exit_code == 0, result.output
    # Observable: report includes the status snippet, issues count, and
    # the notes excerpt.
    assert "Day 3" in result.output
    assert "Issues in window: 1" in result.output
    assert "HIGH" in result.output
    assert "s3 list denied" in result.output
    assert "sam build" in result.output


def test_report_cmd_json_carries_full_structure(
    isolated_canary: pathlib.Path,
) -> None:
    cc.write_status({"canary_day": 1})
    cc.append_issue(
        bouncer="ibounce",
        severity="LOW",
        category="other",
        observable="x",
        expected="y",
    )

    runner = CliRunner()
    result = runner.invoke(
        main, ["canary", "report", "--since", "all", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["issues_count"] == 1
    assert payload["issues_by_severity"]["LOW"] == 1
    assert payload["status"]["canary_day"] == 1


def test_report_cmd_since_parser_rejects_bad_format(
    isolated_canary: pathlib.Path,
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["canary", "report", "--since", "yesterday"])
    assert result.exit_code != 0


# -- update command (dry-run only; no actual git/install in tests) -------


def test_update_dry_run_reports_planned_actions(
    isolated_canary: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dry-run should NOT touch git or run pip / go; should announce plan."""

    # Make _git return clean tree + recognisable SHAs.
    def fake_git(repo: pathlib.Path, *args: str) -> tuple[int, str]:
        if args[:1] == ("rev-parse",):
            return 0, "deadbeefcafe0000"
        if args[:1] == ("status",):
            return 0, ""  # clean tree
        return 0, ""

    monkeypatch.setattr(cc, "_git", fake_git)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "update", "--dry-run"])
    assert result.exit_code == 0, result.output
    # Observable: dry-run announces planned actions; does NOT log an
    # update_success issue (no actual update happened).
    assert "[dry-run]" in result.output
    issues = cc.read_issues()
    assert not any(
        i.get("category") in ("update_success", "update_failure") for i in issues
    ), "dry-run must not append update_* issues"


def test_update_refuses_uncommitted_changes(
    isolated_canary: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If any canary repo has uncommitted changes, update must FAIL +
    log a CRIT update_failure issue."""

    def fake_git(repo: pathlib.Path, *args: str) -> tuple[int, str]:
        if args[:1] == ("rev-parse",):
            return 0, "abc12345678900000"
        if args[:1] == ("status",):
            return 0, " M src/some_file.py"  # dirty tree
        return 0, ""

    monkeypatch.setattr(cc, "_git", fake_git)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "update"])
    # Reported: command surfaces the failure.
    assert "uncommitted changes" in (result.output + (result.stderr or ""))

    # Observable: a CRIT update_failure entry landed in issues.jsonl.
    issues = cc.read_issues()
    failure_issues = [i for i in issues if i.get("category") == "update_failure"]
    assert len(failure_issues) == 1
    assert failure_issues[0]["severity"] == "CRIT"
    assert "uncommitted" in failure_issues[0]["observable"]


# -- registration --------------------------------------------------------


def test_canary_group_registered_on_main() -> None:
    """`iam-jit canary --help` must list the four subcommands."""
    runner = CliRunner()
    result = runner.invoke(main, ["canary", "--help"])
    assert result.exit_code == 0, result.output
    for sub in ("status", "urls", "report", "file-issue", "update"):
        assert sub in result.output, f"missing subcommand: {sub}"
