"""CLI end-to-end tests for `ibounce plan list/show/export` (#132).

Each test seeds a fresh SQLite db with synthetic plan-capture rows
(no real proxy invocation needed) and drives the CLI via
click.testing.CliRunner.
"""

from __future__ import annotations

import json
import pathlib

from click.testing import CliRunner

from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main as ibounce_main


def _seed_session(
    db_path: pathlib.Path,
    *,
    session_id: str = "plan-20260518T000000Z-aaa111",
    n_calls: int = 3,
) -> None:
    store = BouncerStore(db_path=str(db_path))
    try:
        store.ensure_plan_session(
            session_id=session_id,
            started_by="test",
            note="seeded by test",
        )
        for i in range(n_calls):
            store.record_plan_call(
                session_id=session_id,
                method="GET",
                host="s3.amazonaws.com",
                path=f"/bucket/key-{i}",
                service="s3",
                action="GetObject",
                region="us-east-1",
                arn=None,
                verdict="allow",
                would_have_called="s3:GetObject",
                would_have_returned={"Body": "<empty in plan-capture>"},
                supported=True,
            )
    finally:
        store.close()


# ---------------------------------------------------------------------------
# `plan list`
# ---------------------------------------------------------------------------


def test_plan_list_empty(tmp_path) -> None:
    db = tmp_path / "b.db"
    # ensure schema migrates by instantiating once
    BouncerStore(db_path=str(db)).close()
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main, ["plan", "list", "--db", str(db)],
    )
    assert result.exit_code == 0
    assert "no plan-capture sessions" in result.stderr or "no plan-capture sessions" in result.output


def test_plan_list_human(tmp_path) -> None:
    db = tmp_path / "b.db"
    _seed_session(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main, ["plan", "list", "--db", str(db)],
    )
    assert result.exit_code == 0
    assert "plan-20260518T000000Z-aaa111" in result.output
    assert "calls=3" in result.output
    assert "allow=3" in result.output


def test_plan_list_json(tmp_path) -> None:
    db = tmp_path / "b.db"
    _seed_session(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main, ["plan", "list", "--db", str(db), "--json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 1
    assert data[0]["session_id"] == "plan-20260518T000000Z-aaa111"
    assert data[0]["call_count"] == 3


# ---------------------------------------------------------------------------
# `plan show`
# ---------------------------------------------------------------------------


def test_plan_show_unknown_session_exits_nonzero(tmp_path) -> None:
    db = tmp_path / "b.db"
    BouncerStore(db_path=str(db)).close()
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main, ["plan", "show", "no-such-session", "--db", str(db)],
    )
    assert result.exit_code != 0
    assert "no plan-capture session" in result.output or "no plan-capture session" in result.stderr


def test_plan_show_human(tmp_path) -> None:
    db = tmp_path / "b.db"
    _seed_session(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        ["plan", "show", "plan-20260518T000000Z-aaa111", "--db", str(db)],
    )
    assert result.exit_code == 0
    out = result.output
    assert "plan-20260518T000000Z-aaa111" in out
    assert "s3:GetObject" in out
    # 3 call lines
    assert out.count("verdict=allow") == 3


def test_plan_show_json(tmp_path) -> None:
    db = tmp_path / "b.db"
    _seed_session(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        ["plan", "show", "plan-20260518T000000Z-aaa111", "--db", str(db), "--json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["session"]["call_count"] == 3
    assert len(data["calls"]) == 3
    assert all(c["service"] == "s3" for c in data["calls"])


# ---------------------------------------------------------------------------
# `plan export`
# ---------------------------------------------------------------------------


def test_plan_export_to_stdout(tmp_path) -> None:
    db = tmp_path / "b.db"
    _seed_session(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        ["plan", "export", "plan-20260518T000000Z-aaa111", "--db", str(db)],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "session" in data and "calls" in data
    assert data["session"]["session_id"] == "plan-20260518T000000Z-aaa111"


def test_plan_export_to_file(tmp_path) -> None:
    db = tmp_path / "b.db"
    _seed_session(db)
    out_file = tmp_path / "exported.json"
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        [
            "plan", "export", "plan-20260518T000000Z-aaa111",
            "--db", str(db), "--output", str(out_file),
        ],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["session"]["session_id"] == "plan-20260518T000000Z-aaa111"
    assert len(data["calls"]) == 3


def test_plan_export_unknown_session_exits_nonzero(tmp_path) -> None:
    db = tmp_path / "b.db"
    BouncerStore(db_path=str(db)).close()
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main, ["plan", "export", "nope", "--db", str(db)],
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Mode CLI option
# ---------------------------------------------------------------------------


def test_run_command_accepts_plan_capture_mode_in_help(tmp_path) -> None:
    """`ibounce run --help` should list plan-capture as a valid --mode
    choice. We use --help so we don't actually start a server."""
    runner = CliRunner()
    result = runner.invoke(ibounce_main, ["run", "--help"])
    assert result.exit_code == 0
    assert "plan-capture" in result.output
    assert "--plan-session-id" in result.output
