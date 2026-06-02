# #727 / BUILD-6 — CLI + MCP surface tests for role-usage.
"""Exercises the ``iam-jit role-usage`` CLI and ``iam_jit_role_usage``
MCP backend end-to-end with the fan-out fetch monkeypatched to a
synthetic session event window.

Per ``docs/CONTRIBUTING.md`` state-verification: assert the observable
output (counts, narrowed policy, caveats) matches the synthetic input,
not just a status string.
"""

from __future__ import annotations

import json
import typing

from click.testing import CliRunner


def _ev(action: str, resource: str | None = None) -> dict[str, typing.Any]:
    e: dict[str, typing.Any] = {
        "api": {
            "operation": action,
            "service": {"name": action.split(":")[0]},
        },
        "unmapped": {"iam_jit": {"verdict": "allow"}},
    }
    if resource:
        e["resources"] = [{"uid": resource, "name": resource}]
    return e


_SESSION_EVENTS = [
    _ev("s3:GetObject", "arn:aws:s3:::data/report.csv"),
    _ev("s3:ListBucket", "arn:aws:s3:::data"),
]

_GRANTED = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:*", "ec2:Describe*"],
         "Resource": "*"},
    ],
}


def _fake_fanout(**kwargs):
    # Returns the synthetic window + a clean per-bouncer notes dict.
    return list(_SESSION_EVENTS), {"ibounce": ""}


def test_cli_role_usage_json(tmp_path, monkeypatch):
    import iam_jit.cli_role_usage as cli_mod

    monkeypatch.setattr(
        cli_mod, "fetch_session_events_via_fanout", _fake_fanout,
    )
    policy_file = tmp_path / "granted.json"
    policy_file.write_text(json.dumps(_GRANTED))

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.role_usage_command,
        [
            "--session", "SID-CLI",
            "--granted-policy", str(policy_file),
            "--format", "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["session_id"] == "SID-CLI"
    assert payload["used_count"] == 2
    # s3:* expands large; granted_count must exceed used_count.
    assert payload["granted_count"] > payload["used_count"]
    used = {a["action"] for a in payload["used_actions"]}
    assert used == {"s3:GetObject", "s3:ListBucket"}
    # Narrowed policy contains exactly the used actions.
    narrowed_actions = {
        stmt["Action"][0] for stmt in payload["narrowed"]["policy"]["Statement"]
    }
    assert narrowed_actions == {"s3:GetObject", "s3:ListBucket"}
    assert payload["narrowed"]["policy"]["Statement"][0]["Resource"] != ["*"]
    # Floor caveat always present.
    assert any("floor" in c.lower() for c in payload["caveats"])


def test_cli_role_usage_table(tmp_path, monkeypatch):
    import iam_jit.cli_role_usage as cli_mod

    monkeypatch.setattr(
        cli_mod, "fetch_session_events_via_fanout", _fake_fanout,
    )
    policy_file = tmp_path / "granted.json"
    policy_file.write_text(json.dumps(_GRANTED))

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.role_usage_command,
        [
            "--session", "SID-TBL",
            "--granted-policy", str(policy_file),
            "--format", "table",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Used 2 of" in result.output
    assert "granted permissions" in result.output
    assert "s3:GetObject" in result.output
    assert "Proposed narrowed policy" in result.output
    assert "Caveats" in result.output


def test_cli_role_usage_malformed_json(tmp_path, monkeypatch):
    # Non-parseable granted policy must fail with a clean ClickException
    # (non-zero exit, friendly message), never a raw JSONDecodeError
    # traceback.
    import iam_jit.cli_role_usage as cli_mod

    monkeypatch.setattr(
        cli_mod, "fetch_session_events_via_fanout", _fake_fanout,
    )
    policy_file = tmp_path / "granted.json"
    policy_file.write_text("{ not valid json ]")

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.role_usage_command,
        [
            "--session", "SID-BAD",
            "--granted-policy", str(policy_file),
            "--format", "json",
        ],
    )
    assert result.exit_code != 0
    assert "not valid JSON" in result.output
    # No raw traceback leaked.
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(
        result.exception, SystemExit
    )


def test_mcp_role_usage_backend(monkeypatch):
    import iam_jit.agent_diff as agent_diff_mod
    import iam_jit.mcp_server as mcp

    monkeypatch.setattr(
        agent_diff_mod, "fetch_session_events_via_fanout", _fake_fanout,
    )

    result = mcp._iam_jit_role_usage_for_mcp({
        "session": "SID-MCP",
        "granted_policy": _GRANTED,
    })
    assert result["status"] == "ok"
    assert result["session_id"] == "SID-MCP"
    assert result["used_count"] == 2
    assert result["granted_count"] > 2
    assert set(
        stmt["Action"][0]
        for stmt in result["narrowed"]["policy"]["Statement"]
    ) == {"s3:GetObject", "s3:ListBucket"}


def test_mcp_role_usage_rejects_missing_granted_policy():
    import iam_jit.mcp_server as mcp

    r = mcp._iam_jit_role_usage_for_mcp({"session": "X"})
    assert r["status"] == "error"
    assert r["code"] == "missing_granted_policy"


def test_mcp_role_usage_rejects_missing_session():
    import iam_jit.mcp_server as mcp

    r = mcp._iam_jit_role_usage_for_mcp({"granted_policy": _GRANTED})
    assert r["status"] == "error"
    assert r["code"] == "missing_session"


def test_mcp_role_usage_tool_registered():
    import iam_jit.mcp_server as mcp

    names = {t["name"] for t in mcp.TOOLS}
    assert "iam_jit_role_usage" in names
    tool = next(t for t in mcp.TOOLS if t["name"] == "iam_jit_role_usage")
    assert tool["inputSchema"]["required"] == ["session", "granted_policy"]
