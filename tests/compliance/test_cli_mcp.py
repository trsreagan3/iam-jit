# ADOPT-2 / #716 — CLI + MCP surface tests for compliance-map.
"""Exercises the ``iam-jit compliance-map`` CLI and the
``iam_jit_compliance_map`` MCP backend end-to-end with the fan-out
fetch monkeypatched to a synthetic, cross-protocol session window.

Per ``docs/CONTRIBUTING.md`` state-verification: assert the observable
output (tags, coverage counts, partial flags) matches the synthetic
input, not just a status string.
"""

from __future__ import annotations

import json
import typing

from click.testing import CliRunner


def _ev(
    action: str,
    *,
    verdict: str = "allow",
    bouncer: str = "ibounce",
) -> dict[str, typing.Any]:
    svc = action.split(":")[0]
    return {
        "_bouncer": bouncer,
        "api": {"operation": action, "service": {"name": svc}},
        "unmapped": {"iam_jit": {"verdict": verdict,
                                 "agent": {"session_id": "sid"}}},
    }


# A cross-protocol window: AWS priv-esc deny + SQL drop + benign read.
_SESSION_EVENTS = [
    _ev("iam:AttachRolePolicy", verdict="deny"),
    _ev("postgres:DROP TABLE t", bouncer="dbounce"),
    _ev("s3:GetObject", verdict="allow"),
]


def _fake_fanout(**kwargs):
    return list(_SESSION_EVENTS), {"ibounce": ""}


def _fake_fanout_with_gap(**kwargs):
    return list(_SESSION_EVENTS), {"ibounce": "", "kbounce": "refused"}


def _fake_fanout_empty(**kwargs):
    return [], {"ibounce": ""}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_json_output(monkeypatch):
    import iam_jit.cli_compliance_map as cli_mod

    monkeypatch.setattr(
        cli_mod, "fetch_session_events_via_fanout", _fake_fanout,
    )
    runner = CliRunner()
    result = runner.invoke(
        cli_mod.compliance_map_command,
        ["--session", "SID-CLI", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["session_id"] == "SID-CLI"
    assert payload["events_analyzed"] == 3
    assert payload["framework_filter"] is None
    # Priv-esc deny event present with the right tags.
    actions = {te["action"]: te for te in payload["overlay"]}
    assert "iam:AttachRolePolicy" in actions
    assert "MITRE-T1098" in actions["iam:AttachRolePolicy"]["compliance_tags"]
    # SQL drop tagged destructive across protocol.
    drop = actions["postgres:DROP TABLE t"]
    assert drop["protocol"] == "sql"
    assert "MITRE-T1485" in drop["compliance_tags"]
    # All five frameworks present.
    assert len(payload["coverage"]) == 5
    assert payload["is_partial"] is False


def test_cli_summary_output(monkeypatch):
    import iam_jit.cli_compliance_map as cli_mod

    monkeypatch.setattr(
        cli_mod, "fetch_session_events_via_fanout", _fake_fanout,
    )
    runner = CliRunner()
    result = runner.invoke(
        cli_mod.compliance_map_command,
        ["--session", "SID-SUM", "--format", "summary"],
    )
    assert result.exit_code == 0, result.output
    assert "Compliance overlay" in result.output
    assert "OWASP Agentic AI Top 10 (2026)" in result.output
    assert "NOT a compliance certification" in result.output


def test_cli_framework_filter(monkeypatch):
    import iam_jit.cli_compliance_map as cli_mod

    monkeypatch.setattr(
        cli_mod, "fetch_session_events_via_fanout", _fake_fanout,
    )
    runner = CliRunner()
    result = runner.invoke(
        cli_mod.compliance_map_command,
        ["--session", "S", "--framework", "owasp", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["framework_filter"] == "owasp"
    assert len(payload["coverage"]) == 1
    assert payload["coverage"][0]["framework"] == "owasp"
    for te in payload["overlay"]:
        assert all(t.startswith("OWASP-") for t in te["compliance_tags"])


def test_cli_output_file(tmp_path, monkeypatch):
    import iam_jit.cli_compliance_map as cli_mod

    monkeypatch.setattr(
        cli_mod, "fetch_session_events_via_fanout", _fake_fanout,
    )
    out = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        cli_mod.compliance_map_command,
        ["--session", "S", "--format", "json", "-o", str(out)],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text())
    assert payload["session_id"] == "S"


def test_cli_empty_session_is_partial(monkeypatch):
    import iam_jit.cli_compliance_map as cli_mod

    monkeypatch.setattr(
        cli_mod, "fetch_session_events_via_fanout", _fake_fanout_empty,
    )
    runner = CliRunner()
    result = runner.invoke(
        cli_mod.compliance_map_command,
        ["--session", "EMPTY", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["events_analyzed"] == 0
    assert payload["is_partial"] is True


# ---------------------------------------------------------------------------
# MCP backend
# ---------------------------------------------------------------------------


def test_mcp_backend_ok(monkeypatch):
    import iam_jit.mcp_server as mcp

    monkeypatch.setattr(
        "iam_jit.agent_diff.fetch_session_events_via_fanout", _fake_fanout,
    )
    out = mcp._iam_jit_compliance_map_for_mcp({"session": "SID-MCP"})
    assert out["status"] == "ok"
    assert out["events_analyzed"] == 3
    assert len(out["coverage"]) == 5
    actions = {te["action"] for te in out["overlay"]}
    assert "iam:AttachRolePolicy" in actions


def test_mcp_backend_missing_session():
    import iam_jit.mcp_server as mcp

    out = mcp._iam_jit_compliance_map_for_mcp({})
    assert out["status"] == "error"
    assert out["code"] == "missing_session"


def test_mcp_backend_invalid_framework(monkeypatch):
    import iam_jit.mcp_server as mcp

    monkeypatch.setattr(
        "iam_jit.agent_diff.fetch_session_events_via_fanout", _fake_fanout,
    )
    out = mcp._iam_jit_compliance_map_for_mcp(
        {"session": "S", "framework": "bogus"}
    )
    assert out["status"] == "error"
    assert out["code"] == "invalid_framework"


def test_mcp_backend_framework_filter(monkeypatch):
    import iam_jit.mcp_server as mcp

    monkeypatch.setattr(
        "iam_jit.agent_diff.fetch_session_events_via_fanout", _fake_fanout,
    )
    out = mcp._iam_jit_compliance_map_for_mcp(
        {"session": "S", "framework": "NIST"}  # case-insensitive
    )
    assert out["status"] == "ok"
    assert out["framework_filter"] == "nist"
    assert len(out["coverage"]) == 1


def test_mcp_backend_bouncer_gap_partial(monkeypatch):
    import iam_jit.mcp_server as mcp

    monkeypatch.setattr(
        "iam_jit.agent_diff.fetch_session_events_via_fanout",
        _fake_fanout_with_gap,
    )
    out = mcp._iam_jit_compliance_map_for_mcp({"session": "S"})
    assert out["status"] == "ok"
    assert out["is_partial"] is True
    assert any("bouncer_gaps" in r for r in out["partial_reasons"])


def test_mcp_tool_registered():
    import iam_jit.mcp_server as mcp

    tool = next(
        (t for t in mcp.TOOLS if t["name"] == "iam_jit_compliance_map"),
        None,
    )
    assert tool is not None
    # enum lists all five frameworks.
    enum = tool["inputSchema"]["properties"]["framework"]["enum"]
    assert set(enum) == {"owasp", "mitre", "nist", "soc2", "eu-ai-act"}
