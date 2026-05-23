"""#412 / §A56 — Weekly digest tests.

Covers:
  * per-bouncer aggregation from autopilot.status.json schema 1.1
  * deny classification breakdown (via structured_deny classifier)
  * lead-line uses caught-framing not error-framing
  * pending-approval count surfaces
  * improve-cycle summary surfaces
  * pattern-detected recommendations (5+ allows on same prefix)
  * JSON output schema valid
  * md export format
  * html export format
  * MCP tool bounce_digest_recent returns full shape
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
from click.testing import CliRunner

from iam_jit.cli import main
from iam_jit.cli_digest import digest_for_mcp
from iam_jit.digest import (
    DigestData,
    build_digest,
    render_html,
    render_json,
    render_markdown,
    render_terminal,
)
from iam_jit.digest.core import parse_window
from iam_jit.digest.render import build_webhook_payload
from iam_jit.profile_allow.denies import DenyRow


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_autopilot_dir(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Point the digest's autopilot-status reader at a temp dir."""
    autopilot_dir = tmp_path / "autopilot-home"
    autopilot_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("IAM_JIT_AUTOPILOT_DIR", str(autopilot_dir))
    # Also isolate pending queue path to tmp so test runs are independent.
    bouncer_dir = autopilot_dir / "bouncer"
    bouncer_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(
        "IAM_JIT_PROFILE_ALLOW_PENDING_PATH",
        str(bouncer_dir / "profile-allow-pending.jsonl"),
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    return autopilot_dir


def _write_status(autopilot_dir: pathlib.Path, body: dict[str, Any]) -> None:
    (autopilot_dir / "autopilot.status.json").write_text(json.dumps(body))


def _fake_fetch_denies(rows: list[DenyRow]):
    """Return a callable matching ``fetch_recent_denies``'s signature."""

    def _fn(**kwargs: Any):
        return list(rows), []

    return _fn


def _row(
    *,
    bouncer: str = "ibounce",
    action: str = "s3:GetObject",
    resource: str = "arn:aws:s3:::test-bucket/key",
    deny_reason: str = "not in profile 'safe-default'",
    deny_source: str = "safe_default",
    when: str = "2026-05-20T12:00:00Z",
) -> DenyRow:
    return DenyRow(
        when=when,
        bouncer=bouncer,
        agent_session_id="sess-1",
        action=action,
        resource=resource,
        deny_reason=deny_reason,
        deny_source=deny_source,
        rule_id_if_dynamic=None,
        suggested_allow_command="iam-jit profile allow --target ... --action ...",
    )


# ---------------------------------------------------------------------------
# Window parser
# ---------------------------------------------------------------------------


def test_parse_window_supports_week_short_form() -> None:
    f, t = parse_window("1w")
    assert f and t and f < t


def test_parse_window_default_is_week_when_empty() -> None:
    f, t = parse_window(None)
    f2, _ = parse_window("1w")
    # Allow second-level fuzz between two clock reads.
    assert f[:16] == f2[:16]


def test_parse_window_rejects_bogus() -> None:
    from iam_jit.digest import DigestError
    with pytest.raises(DigestError) as ei:
        parse_window("not-a-window")
    assert ei.value.code == "invalid_since"


# ---------------------------------------------------------------------------
# Per-bouncer aggregation from autopilot.status.json
# ---------------------------------------------------------------------------


def test_digest_aggregates_per_bouncer_from_status_file(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "schema_version": "1.1",
        "running": True,
        "bouncers": {
            "ibounce": {
                "name": "ibounce",
                "running": True,
                "healthz": {"decisions_count": 1847},
            },
            "kbouncer": {
                "name": "kbouncer",
                "running": True,
                "healthz": {"decisions_count": 200},
            },
        },
        "improve": {"last_results": []},
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    assert data.bouncers["ibounce"]["total_requests_audited"] == 1847
    assert data.bouncers["kbouncer"]["total_requests_audited"] == 200
    assert data.totals["total_requests_audited"] == 2047
    assert data.bouncers["ibounce"]["status"] == "ok"


def test_digest_handles_missing_status_file_gracefully(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    # No status file written.
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    assert any("autopilot status file not found" in n for n in data.notes)
    # Every default bouncer surfaces with status=no_data.
    for name in ("ibounce", "kbouncer", "dbounce", "gbounce"):
        assert data.bouncers[name]["status"] == "no_data"


# ---------------------------------------------------------------------------
# Deny classification breakdown
# ---------------------------------------------------------------------------


def test_digest_classifies_denies_via_classifier(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    """The classifier today is the structural heuristic shipped in #402
    (returns ``ambiguous`` for most rows). What matters is that the
    digest USES the same classifier as the agent-facing 403 — single
    source of truth — so the breakdown buckets sum to the deny count.
    """
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 500}}}
    })
    rows = [
        _row(bouncer="ibounce"),
        _row(bouncer="ibounce", action="s3:DeleteObject"),
        _row(bouncer="ibounce", action="iam:CreateUser"),
    ]
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies(rows),
    )
    block = data.bouncers["ibounce"]
    bucket_sum = sum(block["denies_by_classification"].values())
    assert block["total_denies"] == 3
    assert bucket_sum == 3, f"buckets must sum to total denies, got {block['denies_by_classification']}"


# ---------------------------------------------------------------------------
# Lead-line tone
# ---------------------------------------------------------------------------


def test_digest_lead_line_uses_caught_framing_not_error(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 100}}}
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([_row()]),
    )
    rendered = render_terminal(data)
    first_line = rendered.split("\n", 1)[0]
    # Caught-framing lead.
    assert "Your bouncer week in review" in first_line
    # Deficit-framing words must NEVER appear in the lead.
    forbidden = ("BLOCKED", "ERROR", "DENIED", "FAILED", "REJECTED")
    for word in forbidden:
        assert word not in first_line, (
            f"lead line must not contain {word!r}; got {first_line!r}"
        )


def test_digest_markdown_lead_uses_caught_framing(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 100}}}
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    md = render_markdown(data)
    # First heading is the caught-framing line.
    assert md.startswith("# Your bouncer week in review")
    # No deficit-framing words in the lead heading.
    head = md.split("\n", 1)[0]
    for forbidden in ("BLOCKED", "ERROR", "DENIED"):
        assert forbidden not in head


# ---------------------------------------------------------------------------
# Pending approval count
# ---------------------------------------------------------------------------


def test_digest_includes_pending_count(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    # Write 3 pending entries.
    qp = _isolate_autopilot_dir / "bouncer" / "profile-allow-pending.jsonl"
    qp.write_text("\n".join(
        json.dumps({"target": f"arn:aws:s3:::cache-{i}", "action": "s3:GetObject"})
        for i in range(3)
    ))
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 1}}}
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    assert data.totals["pending_approval_count"] == 3
    assert data.bouncers["ibounce"]["pending_approval_count"] == 3


# ---------------------------------------------------------------------------
# Improve cycle summary
# ---------------------------------------------------------------------------


def test_digest_includes_improve_cycle_summary(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 100}}},
        "improve": {
            "last_results": [
                {
                    "bouncer": "ibounce",
                    "status": "auto_installed",
                    "rules_added": 2,
                    "rules_removed": 0,
                    "change_size": 0.10,
                    "ran_at": "2026-05-20T12:00:00Z",
                },
                {
                    "bouncer": "ibounce",
                    "status": "pending_approval",
                    "rules_added": 0,
                    "rules_removed": 5,
                    "change_size": 0.40,
                    "ran_at": "2026-05-21T12:00:00Z",
                },
            ],
        },
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    block = data.bouncers["ibounce"]
    assert block["improve_cycles_run"] == 2
    assert block["improve_changes_auto_installed"] == 1
    assert block["improve_changes_pending"] == 1
    # noteworthy_events should reference the auto-install + the pending.
    descs = [ev.get("description", "") for ev in block["noteworthy_events"]]
    assert any("auto-installed" in d for d in descs)
    assert any("pending" in d for d in descs)


# ---------------------------------------------------------------------------
# Recommendation generation
# ---------------------------------------------------------------------------


def test_digest_recommendations_generated_when_pattern_detected(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    """5+ pending allows sharing a stable prefix should surface a
    generalize-this-pattern recommendation."""
    qp = _isolate_autopilot_dir / "bouncer" / "profile-allow-pending.jsonl"
    qp.write_text("\n".join(
        json.dumps({
            "target": f"arn:aws:s3:::staging-cache-{i}",
            "action": "s3:GetObject",
        })
        for i in range(6)
    ))
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 1}}}
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    joined = " | ".join(data.recommendations)
    assert "generalize" in joined.lower()
    assert "staging-cache-" in joined


def test_digest_recommendations_quiet_bouncer_suggestion(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    """A bouncer with audited > 0 + denies = 0 over a week triggers a
    "consider tightening the profile" recommendation."""
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {
            "ibounce": {"running": True, "healthz": {"decisions_count": 5000}}
        }
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    joined = " | ".join(data.recommendations)
    assert "tighten" in joined.lower()
    assert "ibounce" in joined


# ---------------------------------------------------------------------------
# JSON output schema valid
# ---------------------------------------------------------------------------


def test_digest_json_output_schema_valid(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 100}}},
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([_row()]),
    )
    blob = render_json(data)
    parsed = json.loads(blob)
    # Required top-level keys (per the documented MCP shape).
    for key in (
        "schema_version",
        "time_window",
        "bouncers",
        "totals",
        "recommendations",
    ):
        assert key in parsed, f"missing top-level key {key!r}"
    assert parsed["schema_version"] == "1.0"
    # Time window has from + to.
    assert "from" in parsed["time_window"] and "to" in parsed["time_window"]
    # Totals has the documented sub-keys.
    for k in (
        "total_requests_audited",
        "total_denies",
        "pending_approval_count",
    ):
        assert k in parsed["totals"]
    # Per-bouncer block has its required keys.
    ib = parsed["bouncers"]["ibounce"]
    for k in (
        "total_requests_audited",
        "total_denies",
        "denies_by_classification",
        "pending_approval_count",
        "improve_cycles_run",
        "improve_changes_auto_installed",
        "improve_changes_pending",
        "noteworthy_events",
    ):
        assert k in ib


# ---------------------------------------------------------------------------
# Markdown export format
# ---------------------------------------------------------------------------


def test_digest_md_export_format(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {
            "ibounce": {"running": True, "healthz": {"decisions_count": 100}},
            "kbouncer": {"running": True, "healthz": {"decisions_count": 50}},
        }
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    md = render_markdown(data)
    # Heading level 1 lead.
    assert md.startswith("# ")
    # Has the per-bouncer table when more than one bouncer.
    assert "| Bouncer | Status | Audited | Caught |" in md
    assert "ibounce" in md and "kbouncer" in md


# ---------------------------------------------------------------------------
# HTML export format
# ---------------------------------------------------------------------------


def test_digest_html_export_format(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 100}}}
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    h = render_html(data)
    assert h.startswith("<!doctype html>")
    assert "<h1>" in h and "Your bouncer week in review" in h
    # No inline JavaScript per the security baseline.
    assert "<script" not in h.lower()


# ---------------------------------------------------------------------------
# MCP tool shape
# ---------------------------------------------------------------------------


def test_mcp_tool_bounce_digest_recent_returns_full_shape(
    _isolate_autopilot_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 42}}}
    })
    # Stub the deny fetcher so the test doesn't try to reach real ports.
    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.fetch_recent_denies",
        lambda **kw: ([], []),
    )
    result = digest_for_mcp({"since": "1w"})
    assert result["status"] == "ok"
    assert result["schema_version"] == "1.0"
    assert "time_window" in result
    assert "bouncers" in result
    assert "totals" in result
    assert "recommendations" in result
    # The MCP wrapper adds a human summary so agents can surface text.
    assert "summary" in result
    assert "Your bouncer week in review" in result["summary"]


def test_mcp_tool_returns_error_payload_on_bad_since() -> None:
    result = digest_for_mcp({"since": "not-a-window"})
    assert result["status"] == "error"
    assert result["code"] == "invalid_since"


# ---------------------------------------------------------------------------
# Webhook payload
# ---------------------------------------------------------------------------


def test_webhook_payload_uses_caught_framing(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 100}}}
    })
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([]),
    )
    payload = build_webhook_payload(data)
    assert "Your bouncer week in review" in payload["text"]
    # Quiet week → color good.
    assert payload["attachments"][0]["color"] == "good"


def test_webhook_payload_colors_red_on_adversarial(
    _isolate_autopilot_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force a row through the classifier as 'appears_adversarial' so
    the webhook card surfaces color=danger per [[ibounce-honest-
    positioning]]."""
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 100}}}
    })
    # Stub the classifier so the test doesn't depend on the heuristic's
    # exact behavior; we only care that color=danger when adv > 0.
    monkeypatch.setattr(
        "iam_jit.structured_deny.response.classify_injection_likelihood",
        lambda **kw: ("appears_adversarial", None),
    )
    data = build_digest(
        since="1w",
        fetch_denies_fn=_fake_fetch_denies([_row()]),
    )
    payload = build_webhook_payload(data)
    assert payload["attachments"][0]["color"] == "danger"
    assert "adversarial" in payload["text"].lower()


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------


def test_cli_digest_runs_with_no_status_file(
    _isolate_autopilot_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Stub the deny fetcher to avoid real network.
    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.fetch_recent_denies",
        lambda **kw: ([], []),
    )
    runner = CliRunner()
    res = runner.invoke(main, ["digest", "--since", "1w"])
    assert res.exit_code == 0
    assert "Your bouncer week in review" in res.output


def test_cli_digest_json_output(
    _isolate_autopilot_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.fetch_recent_denies",
        lambda **kw: ([], []),
    )
    runner = CliRunner()
    res = runner.invoke(main, ["digest", "--since", "1w", "--json"])
    assert res.exit_code == 0
    parsed = json.loads(res.output)
    assert parsed["schema_version"] == "1.0"
    assert "totals" in parsed


def test_cli_digest_export_md_to_file(
    _isolate_autopilot_dir: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.fetch_recent_denies",
        lambda **kw: ([], []),
    )
    out = tmp_path / "digest.md"
    runner = CliRunner()
    res = runner.invoke(
        main,
        ["digest", "--export-format", "md", "--out", str(out)],
    )
    assert res.exit_code == 0
    assert out.exists()
    body = out.read_text()
    assert body.startswith("# Your bouncer week in review")


def test_cli_digest_exit_3_on_adversarial(
    _isolate_autopilot_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An adversarial-classified deny should cause exit code 3 so
    operator scripts can branch on 'did this week need attention'."""
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {"ibounce": {"running": True, "healthz": {"decisions_count": 100}}}
    })
    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.fetch_recent_denies",
        lambda **kw: ([_row()], []),
    )
    monkeypatch.setattr(
        "iam_jit.structured_deny.response.classify_injection_likelihood",
        lambda **kw: ("appears_adversarial", None),
    )
    runner = CliRunner()
    res = runner.invoke(main, ["digest", "--since", "1w"])
    assert res.exit_code == 3
    # Adversarial denies must surface in the output, not be buried.
    assert "adversarial" in res.output.lower()


def test_cli_digest_invalid_since_returns_2(
    _isolate_autopilot_dir: pathlib.Path,
) -> None:
    runner = CliRunner()
    res = runner.invoke(main, ["digest", "--since", "bogus"])
    assert res.exit_code == 2
    assert "invalid" in res.output.lower() or "invalid" in (res.stderr or "").lower()


def test_cli_digest_single_bouncer_filter(
    _isolate_autopilot_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_status(_isolate_autopilot_dir, {
        "bouncers": {
            "ibounce": {"running": True, "healthz": {"decisions_count": 100}},
            "kbouncer": {"running": True, "healthz": {"decisions_count": 50}},
        }
    })
    monkeypatch.setattr(
        "iam_jit.profile_allow.denies.fetch_recent_denies",
        lambda **kw: ([], []),
    )
    runner = CliRunner()
    res = runner.invoke(
        main, ["digest", "--since", "1w", "--bouncer", "ibounce", "--json"]
    )
    assert res.exit_code == 0
    parsed = json.loads(res.output)
    assert "ibounce" in parsed["bouncers"]
    assert "kbouncer" not in parsed["bouncers"]
