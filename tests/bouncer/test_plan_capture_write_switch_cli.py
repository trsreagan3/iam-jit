"""CLI tests for #145 plan-capture read->write switch UX surface.

Drives the ibounce CLI via click.testing.CliRunner to validate:
  - `ibounce prompts list` distinguishes plan-write prompts from
    deny-prompts (kind column + per-row session_id)
  - `ibounce prompts list --kind plan-write` filters correctly
  - `ibounce prompts answer ID --kind plan-write --decision approve`
    transitions the session phase + marks the prompt answered
  - `ibounce prompts answer ID --kind plan-write --decision reject`
    transitions the session phase to writes_rejected
  - `ibounce prompts answer ID --kind plan-write` without --decision
    fails with a clear message
  - `ibounce prompts answer ID --kind always` against a plan-write
    prompt id is refused (kind mismatch)
  - `ibounce plan show` includes phase + first_write_at + decision
    fields in both human + JSON output
  - `ibounce plan show --json` exposes the phase metadata for
    downstream tooling
"""

from __future__ import annotations

import json
import pathlib

from click.testing import CliRunner

from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main as ibounce_main


def _seed_session_with_plan_write_prompt(
    db_path: pathlib.Path,
    *,
    session_id: str = "plan-20260518T000000Z-aaa111",
) -> int:
    """Set up a plan-capture session with a pending plan-write prompt.
    Returns the prompt id so tests can answer it."""
    store = BouncerStore(db_path=str(db_path))
    try:
        store.ensure_plan_session(
            session_id=session_id, started_by="test", note="seed",
        )
        store.set_plan_session_write_switch_notify(session_id, "manual")
        # Simulate a read-then-write transition: first record a couple
        # of reads to make the transcript realistic, then the write +
        # phase transition + prompt.
        for path in ("/bucket/r1", "/bucket/r2"):
            store.record_plan_call(
                session_id=session_id,
                method="GET", host="s3.amazonaws.com", path=path,
                service="s3", action="GetObject",
                region="us-east-1", arn=None,
                verdict="allow", would_have_called="s3:GetObject",
                would_have_returned={"Body": "<empty in plan-capture>"},
                supported=True,
            )
        store.record_plan_call(
            session_id=session_id,
            method="POST", host="iam.amazonaws.com", path="/",
            service="iam", action="CreateRole",
            region=None, arn=None,
            verdict="allow", would_have_called="iam:CreateRole",
            would_have_returned={"RoleName": "test"},
            supported=True,
        )
        store.transition_plan_session_phase(
            session_id,
            new_phase="write_pending",
            first_write_at="2026-05-18T00:00:30Z",
        )
        pid = store.add_plan_write_prompt(
            session_id=session_id, service="iam", action="CreateRole",
            arn=None, region=None,
        )
        return pid
    finally:
        store.close()


# ---------------------------------------------------------------------------
# `ibounce prompts list` — distinguishes plan-write from deny-prompts
# ---------------------------------------------------------------------------


def test_prompts_list_shows_plan_write_kind(tmp_path):
    db = tmp_path / "b.db"
    _seed_session_with_plan_write_prompt(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main, ["prompts", "list", "--db", str(db)],
    )
    assert result.exit_code == 0, result.output
    # The kind column shows 'plan-write'
    assert "plan-write" in result.output
    assert "iam" in result.output
    assert "CreateRole" in result.output
    # The session id is rendered per-row
    assert "plan-20260518T000000Z-aaa111" in result.output


def test_prompts_list_renders_both_kinds_distinctly(tmp_path):
    """When both kinds are pending, the kind column distinguishes them
    so the operator can tell at a glance which is which."""
    db = tmp_path / "b.db"
    _seed_session_with_plan_write_prompt(db)
    # Also add a deny-prompt
    store = BouncerStore(db_path=str(db))
    try:
        store.add_pending_prompt(
            decision_id=999, service="s3", action="DeleteObject",
            arn="arn:aws:s3:::sensitive", region="us-east-1",
            deny_reason="profile deny",
        )
    finally:
        store.close()
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main, ["prompts", "list", "--db", str(db)],
    )
    assert result.exit_code == 0
    assert "deny-prompt" in result.output
    assert "plan-write" in result.output
    # Filter only plan-write
    result = runner.invoke(
        ibounce_main,
        ["prompts", "list", "--db", str(db), "--kind", "plan-write"],
    )
    assert result.exit_code == 0
    assert "plan-write" in result.output
    assert "DeleteObject" not in result.output


# ---------------------------------------------------------------------------
# `ibounce prompts answer --kind plan-write --decision X`
# ---------------------------------------------------------------------------


def test_prompts_answer_plan_write_approve(tmp_path):
    db = tmp_path / "b.db"
    pid = _seed_session_with_plan_write_prompt(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        [
            "prompts", "answer", str(pid), "--db", str(db),
            "--kind", "plan-write", "--decision", "approve",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "writes_approved" in result.output
    # Verify the session phase moved
    store = BouncerStore(db_path=str(db))
    try:
        phase = store.get_plan_session_phase("plan-20260518T000000Z-aaa111")
        assert phase["phase"] == "writes_approved"
        assert phase["write_decision"] == "approve"
        # And the prompt was marked answered
        prompt = store.get_pending_prompt(pid)
        assert prompt["status"] == "answered"
        assert prompt["answer_kind"] == "approve"
    finally:
        store.close()


def test_prompts_answer_plan_write_reject(tmp_path):
    db = tmp_path / "b.db"
    pid = _seed_session_with_plan_write_prompt(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        [
            "prompts", "answer", str(pid), "--db", str(db),
            "--kind", "plan-write", "--decision", "reject",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "writes_rejected" in result.output
    store = BouncerStore(db_path=str(db))
    try:
        phase = store.get_plan_session_phase("plan-20260518T000000Z-aaa111")
        assert phase["phase"] == "writes_rejected"
        assert phase["write_decision"] == "reject"
    finally:
        store.close()


def test_prompts_answer_plan_write_requires_decision(tmp_path):
    db = tmp_path / "b.db"
    pid = _seed_session_with_plan_write_prompt(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        [
            "prompts", "answer", str(pid), "--db", str(db),
            "--kind", "plan-write",
        ],
    )
    assert result.exit_code == 2
    assert "--decision" in result.output


def test_prompts_answer_deny_kind_against_plan_write_prompt_rejected(tmp_path):
    """An operator typo'ing `--kind always` against a plan-write prompt
    id must be refused — different answer semantics."""
    db = tmp_path / "b.db"
    pid = _seed_session_with_plan_write_prompt(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        [
            "prompts", "answer", str(pid), "--db", str(db),
            "--kind", "always",
        ],
    )
    assert result.exit_code == 2
    assert "plan-write" in result.output


def test_prompts_answer_plan_write_kind_against_deny_prompt_rejected(tmp_path):
    """And the converse: --kind plan-write against a deny-prompt id."""
    db = tmp_path / "b.db"
    store = BouncerStore(db_path=str(db))
    try:
        deny_id = store.add_pending_prompt(
            decision_id=42, service="s3", action="DeleteObject",
            arn="arn:aws:s3:::x", region="us-east-1",
            deny_reason="profile deny",
        )
    finally:
        store.close()
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        [
            "prompts", "answer", str(deny_id), "--db", str(db),
            "--kind", "plan-write", "--decision", "approve",
        ],
    )
    assert result.exit_code == 2
    assert "not 'plan-write'" in result.output


# ---------------------------------------------------------------------------
# `ibounce plan show` exposes phase metadata
# ---------------------------------------------------------------------------


def test_plan_show_human_includes_phase(tmp_path):
    db = tmp_path / "b.db"
    _seed_session_with_plan_write_prompt(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        ["plan", "show", "plan-20260518T000000Z-aaa111", "--db", str(db)],
    )
    assert result.exit_code == 0, result.output
    assert "phase=write_pending" in result.output
    assert "write-switch-notify=manual" in result.output
    assert "first-write-at: 2026-05-18T00:00:30Z" in result.output
    # Read + write counts should both be present
    assert "reads=2" in result.output
    assert "writes=1" in result.output


def test_plan_show_json_includes_phase(tmp_path):
    """The JSON export shape is stable for downstream consumers + must
    expose the #145 phase metadata."""
    db = tmp_path / "b.db"
    _seed_session_with_plan_write_prompt(db)
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        [
            "plan", "show", "plan-20260518T000000Z-aaa111",
            "--db", str(db), "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    session = payload["session"]
    assert session["phase"] == "write_pending"
    assert session["write_switch_notify"] == "manual"
    assert session["first_write_at"] == "2026-05-18T00:00:30Z"
    assert session["read_count"] == 2
    assert session["write_count"] == 1


def test_plan_show_after_approve_shows_decision(tmp_path):
    db = tmp_path / "b.db"
    pid = _seed_session_with_plan_write_prompt(db)
    runner = CliRunner()
    # Approve the prompt
    result = runner.invoke(
        ibounce_main,
        [
            "prompts", "answer", str(pid), "--db", str(db),
            "--kind", "plan-write", "--decision", "approve",
        ],
    )
    assert result.exit_code == 0
    # Now plan show shows the decision
    result = runner.invoke(
        ibounce_main,
        ["plan", "show", "plan-20260518T000000Z-aaa111", "--db", str(db)],
    )
    assert result.exit_code == 0
    assert "phase=writes_approved" in result.output
    assert "write-decision: approve" in result.output


def test_plan_export_includes_phase_metadata(tmp_path):
    """`ibounce plan export` writes the same JSON shape as plan show
    --json + must include the #145 phase metadata for downstream
    consumers."""
    db = tmp_path / "b.db"
    _seed_session_with_plan_write_prompt(db)
    out_path = tmp_path / "export.json"
    runner = CliRunner()
    result = runner.invoke(
        ibounce_main,
        [
            "plan", "export", "plan-20260518T000000Z-aaa111",
            "--db", str(db), "--output", str(out_path),
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(out_path.read_text())
    assert payload["session"]["phase"] == "write_pending"
    assert payload["session"]["write_switch_notify"] == "manual"
    assert payload["session"]["read_count"] == 2
    assert payload["session"]["write_count"] == 1
