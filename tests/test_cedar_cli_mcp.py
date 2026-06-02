# ADOPT-5 / #719 — CLI + MCP surface tests for IAM <-> Cedar interop.
"""Tests the `iam-jit cedar {export,import}` CLI commands and the
`iam_jit_policy_translate` MCP tool wiring."""

from __future__ import annotations

import json

from click.testing import CliRunner

from iam_jit.cli import main
from iam_jit.mcp_server import TOOLS, _handle_request


_FAITHFUL = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/k"}
    ],
}
_LOSSY = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}


# ---------------------------------------------------------------------------
# CLI: export
# ---------------------------------------------------------------------------


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj) if isinstance(obj, dict) else obj, encoding="utf-8")
    return str(p)


def test_cli_export_faithful_exit_0(tmp_path):
    pf = _write(tmp_path, "p.json", _FAITHFUL)
    res = CliRunner().invoke(main, ["cedar", "export", "--policy", pf])
    assert res.exit_code == 0, res.output
    assert "permit (" in res.stdout
    assert 'Action::"s3:GetObject"' in res.stdout


def test_cli_export_lossy_exit_1(tmp_path):
    pf = _write(tmp_path, "na.json", _LOSSY)
    res = CliRunner().invoke(main, ["cedar", "export", "--policy", pf])
    assert res.exit_code == 1
    assert "// UNTRANSLATABLE: NotAction" in res.stdout


def test_cli_export_lossy_allow_lossy_exit_0(tmp_path):
    pf = _write(tmp_path, "na.json", _LOSSY)
    res = CliRunner().invoke(
        main, ["cedar", "export", "--policy", pf, "--allow-lossy"]
    )
    assert res.exit_code == 0


def test_cli_export_malformed_exit_2(tmp_path):
    pf = _write(tmp_path, "bad.json", "{not json")
    res = CliRunner().invoke(main, ["cedar", "export", "--policy", pf])
    assert res.exit_code == 2
    assert "ERROR" in res.stderr


def test_cli_export_json_format(tmp_path):
    pf = _write(tmp_path, "p.json", _FAITHFUL)
    res = CliRunner().invoke(
        main, ["cedar", "export", "--policy", pf, "--format", "json"]
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)
    assert payload["direction"] == "iam->cedar"
    assert "notes" in payload


# ---------------------------------------------------------------------------
# CLI: import
# ---------------------------------------------------------------------------


def test_cli_import_basic(tmp_path):
    cedar = 'permit ( principal, action == Action::"s3:GetObject", resource == IamResource::"arn:aws:s3:::b" );'
    cf = _write(tmp_path, "p.cedar", cedar)
    res = CliRunner().invoke(main, ["cedar", "import", "--in", cf])
    assert res.exit_code == 0, res.output
    policy = json.loads(res.stdout)
    assert policy["Statement"][0]["Action"] == "s3:GetObject"


def test_cli_import_lossy_exit_1(tmp_path):
    cedar = (
        'permit ( principal, action == Action::"s3:GetObject", resource )\n'
        'unless { context["x"] == "y" };'
    )
    cf = _write(tmp_path, "u.cedar", cedar)
    res = CliRunner().invoke(main, ["cedar", "import", "--in", cf])
    assert res.exit_code == 1


def test_cli_import_malformed_exit_2(tmp_path):
    cf = _write(tmp_path, "bad.cedar", "this is not cedar")
    res = CliRunner().invoke(main, ["cedar", "import", "--in", cf])
    assert res.exit_code == 2


def test_cli_roundtrip_via_files(tmp_path):
    pf = _write(tmp_path, "p.json", _FAITHFUL)
    cedar_out = str(tmp_path / "p.cedar")
    r1 = CliRunner().invoke(
        main, ["cedar", "export", "--policy", pf, "-o", cedar_out]
    )
    assert r1.exit_code == 0
    iam_out = str(tmp_path / "back.json")
    r2 = CliRunner().invoke(
        main, ["cedar", "import", "--in", cedar_out, "-o", iam_out]
    )
    assert r2.exit_code == 0
    back = json.loads((tmp_path / "back.json").read_text())
    assert back["Statement"][0]["Action"] == "s3:GetObject"
    assert back["Statement"][0]["Resource"] == "arn:aws:s3:::b/k"


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------


def _call(args):
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "iam_jit_policy_translate", "arguments": args},
    }
    return _handle_request(req)["result"]["structuredContent"]


def test_mcp_tool_registered():
    names = [t["name"] for t in TOOLS]
    assert "iam_jit_policy_translate" in names


def test_mcp_iam_to_cedar_ok():
    sc = _call({"direction": "iam_to_cedar", "policy": _FAITHFUL})
    assert sc["status"] == "ok"
    assert sc["is_lossy"] is False
    assert "permit (" in sc["output"]


def test_mcp_iam_to_cedar_untranslatable_flagged():
    sc = _call({"direction": "iam_to_cedar", "policy": _LOSSY})
    assert sc["status"] == "ok"
    assert sc["has_untranslatable"] is True
    assert "review_required" in sc


def test_mcp_cedar_to_iam_ok():
    cedar = 'permit ( principal, action == Action::"s3:GetObject", resource );'
    sc = _call({"direction": "cedar_to_iam", "cedar": cedar})
    assert sc["status"] == "ok"
    assert sc["policy"]["Statement"][0]["Action"] == "s3:GetObject"


def test_mcp_missing_direction():
    sc = _call({"policy": _FAITHFUL})
    assert sc["status"] == "error"
    assert sc["code"] == "invalid_direction"


def test_mcp_missing_policy():
    sc = _call({"direction": "iam_to_cedar"})
    assert sc["status"] == "error"
    assert sc["code"] == "missing_policy"


def test_mcp_missing_cedar():
    sc = _call({"direction": "cedar_to_iam"})
    assert sc["status"] == "error"
    assert sc["code"] == "missing_cedar"


def test_mcp_parse_error():
    sc = _call({"direction": "iam_to_cedar", "policy": {"Version": "2012-10-17"}})
    assert sc["status"] == "error"
    assert sc["code"] == "parse_error"
