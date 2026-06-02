# ADOPT-3 / #717 — `iam-jit inventory` + `iam_jit_inventory` MCP tool tests.
"""Covers the #717 test list:

  * inventory of a stub MCP config: servers + (own-server) tools enumerated
  * bouncer / port enumeration from a stubbed posture block
  * risk metadata (loopback_only / authed) present + correct
  * empty / honesty path: no config + no bouncer -> honest notes, no fabrication
  * JSON shape (schema_version + required keys)
  * NO token VALUE leaks into the output (the load-bearing security property)
  * CLI table + json formats render
  * MCP tool returns the same shape as the CLI --format json
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from iam_jit.cli import main as iam_jit_main
from iam_jit.inventory import (
    INVENTORY_SCHEMA_VERSION,
    capture_inventory,
    render_inventory_table,
)
from iam_jit.inventory.collect import inventory_for_mcp
from iam_jit.inventory.mcp_config import discover_mcp_servers


# ---------------------------------------------------------------------------
# Fixtures: a fake home with a stub Claude Code config + a stub posture.
# ---------------------------------------------------------------------------

# A realistic ~/.claude.json shape: top-level mcpServers + a project block,
# a stdio server with a credential env var, a remote server with a token in
# its url + an Authorization header, an unauthed stdio server, and iam-jit's
# own server (whose tools we DO know).
_SECRET_TOKEN = "sk-supersecrettokenvalue-AKIAIOSFODNN7EXAMPLE-shouldnotleak"

_STUB_CLAUDE_JSON = {
    "mcpServers": {
        "iam-jit": {
            "command": "iam-jit",
            "args": ["mcp", "serve"],
        },
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_TOKEN": _SECRET_TOKEN},
        },
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        },
        "remote-sse": {
            "type": "sse",
            "url": f"https://api.example.com/mcp?token={_SECRET_TOKEN}",
            "headers": {"Authorization": f"Bearer {_SECRET_TOKEN}"},
        },
    },
    "projects": {
        "/home/me/proj": {
            "mcpServers": {
                "proj-server": {
                    "command": "python",
                    "args": ["-m", "myserver"],
                    "env": {"MY_API_KEY": _SECRET_TOKEN},
                },
            },
        },
    },
}


@pytest.fixture
def stub_home(tmp_path):
    """Write a stub ~/.claude.json under a tmp home + return the path."""
    (tmp_path / ".claude.json").write_text(json.dumps(_STUB_CLAUDE_JSON))
    return tmp_path


# ---------------------------------------------------------------------------
# MCP-config discovery
# ---------------------------------------------------------------------------


def test_discover_mcp_servers_enumerates_servers(stub_home):
    result = discover_mcp_servers(home=stub_home)
    names = {s["name"] for s in result["servers"]}
    assert {"iam-jit", "github", "filesystem", "remote-sse", "proj-server"} <= names
    # The config we wrote is reported as scanned + parsed.
    scanned = [c for c in result["configs_scanned"] if c["present"]]
    assert any(c["parse_ok"] for c in scanned)


def test_own_server_tools_enumerated_others_unknown(stub_home):
    result = discover_mcp_servers(home=stub_home)
    by_name = {s["name"]: s for s in result["servers"]}
    # iam-jit's own server: tools come from the in-process TOOLS registry.
    assert isinstance(by_name["iam-jit"]["tools"], list)
    assert "iam_jit_inventory" in by_name["iam-jit"]["tools"]
    assert by_name["iam-jit"]["iam_jit_owned"] is True
    # A third-party server: tools are NOT enumerable from a static config.
    assert by_name["github"]["tools"] == "unknown — not enumerable from static config"
    assert by_name["github"]["iam_jit_owned"] is False


def test_authed_flag_and_credential_fields(stub_home):
    result = discover_mcp_servers(home=stub_home)
    by_name = {s["name"]: s for s in result["servers"]}
    # github: GITHUB_TOKEN env -> authed, field name reported.
    assert by_name["github"]["authed"] is True
    assert "env.GITHUB_TOKEN" in by_name["github"]["credential_fields"]
    # filesystem: no secret -> not authed.
    assert by_name["filesystem"]["authed"] is False
    assert by_name["filesystem"]["credential_fields"] == []
    # remote-sse: Authorization header + url token both detected.
    rs = by_name["remote-sse"]
    assert rs["authed"] is True
    assert "headers.Authorization" in rs["credential_fields"]
    assert "url.query_token" in rs["credential_fields"]
    assert rs["transport"] == "sse"
    # proj-server: per-project block, MY_API_KEY detected.
    assert by_name["proj-server"]["authed"] is True


def test_no_token_value_leaks_anywhere(stub_home):
    """The load-bearing security property: the secret token VALUE must
    never appear anywhere in the serialized inventory output."""
    snap = capture_inventory(home=stub_home)
    blob = json.dumps(snap)
    assert _SECRET_TOKEN not in blob
    # Also assert the credential-field NAMES are present (we report
    # whether-authed, not the value) — proves we didn't just drop info.
    assert "env.GITHUB_TOKEN" in blob
    assert "headers.Authorization" in blob
    # Rendered table form must also be clean.
    table = render_inventory_table(snap)
    assert _SECRET_TOKEN not in table
    # The remote host is surfaced WITHOUT the query token.
    by_name = {s["name"]: s for s in snap["mcp_servers"]}
    assert by_name["remote-sse"]["remote_host"] == "https://api.example.com"


def test_remote_host_strips_userinfo_credentials(tmp_path):
    cfg = {
        "mcpServers": {
            "creds-in-url": {
                "type": "http",
                "url": "https://user:p4ssw0rd@host.example.com/mcp",
            },
        },
    }
    (tmp_path / ".claude.json").write_text(json.dumps(cfg))
    snap = capture_inventory(home=tmp_path)
    blob = json.dumps(snap)
    assert "p4ssw0rd" not in blob
    by_name = {s["name"]: s for s in snap["mcp_servers"]}
    assert by_name["creds-in-url"]["remote_host"] == "https://host.example.com"
    assert "url.userinfo" in by_name["creds-in-url"]["credential_fields"]


# ---------------------------------------------------------------------------
# Bouncer / A2A enumeration (stubbed posture so the test is deterministic)
# ---------------------------------------------------------------------------


def _stub_bouncers(monkeypatch, *, ibounce_running=True):
    """Patch detect_all_bouncers to a deterministic block."""
    block = {
        "ibounce": {
            "running": ibounce_running,
            "port": 8767,
            "default_port": 8767,
            "env_var_pointing_here": "AWS_ENDPOINT_URL=http://127.0.0.1:8767"
            if ibounce_running
            else None,
            "misconfig": None,
        },
        "kbounce": {
            "running": False,
            "port": 8766,
            "env_var_pointing_here": None,
            "misconfig": None,
        },
        "dbounce": {
            "running": False,
            "port": 5433,
            "mgmt_port": 8768,
            "env_var_pointing_here": None,
            "misconfig": "PGHOST=127.0.0.1 but nothing listening",
        },
        "gbounce": {
            "running": False,
            "port": 8080,
            "mgmt_port": 8769,
            "env_var_pointing_here": None,
            "misconfig": None,
        },
    }
    monkeypatch.setattr(
        "iam_jit.inventory.collect.detect_all_bouncers", lambda: block
    )


def test_bouncer_enumeration_from_stub_posture(monkeypatch, tmp_path):
    _stub_bouncers(monkeypatch, ibounce_running=True)
    monkeypatch.delenv("IAM_JIT_A2A_ENDPOINT", raising=False)
    snap = capture_inventory(home=tmp_path)
    by_name = {b["name"]: b for b in snap["bouncers"]}
    assert {"ibounce", "kbounce", "dbounce", "gbounce"} == set(by_name)
    # ibounce is running -> wired, loopback_only True, endpoint surfaced.
    ib = by_name["ibounce"]
    assert ib["running"] is True
    assert ib["wired"] is True
    assert ib["loopback_only"] is True
    assert "127.0.0.1:8767" in ib["endpoints"]
    # dbounce has a misconfig -> surfaced + loopback unknown (not running).
    db = by_name["dbounce"]
    assert db["misconfig"]
    assert db["loopback_only"] == "unknown"
    # dbounce mgmt port is surfaced as a separate endpoint.
    assert any("mgmt" in e for e in db["endpoints"])
    # risk summary counts the misconfig + running bouncer.
    assert snap["risk_summary"]["bouncers_running"] == 1
    assert snap["risk_summary"]["bouncers_misconfigured"] == 1


def test_a2a_endpoints_include_running_bouncer_surface(monkeypatch, tmp_path):
    _stub_bouncers(monkeypatch, ibounce_running=True)
    monkeypatch.setenv("IAM_JIT_A2A_ENDPOINT", "https://peer.example.com:9000")
    snap = capture_inventory(home=tmp_path)
    kinds = {e["kind"] for e in snap["a2a_endpoints"]}
    assert "a2a-env" in kinds  # the explicit env var
    assert "bouncer-surface" in kinds  # the running ibounce
    env_ep = next(e for e in snap["a2a_endpoints"] if e["kind"] == "a2a-env")
    assert env_ep["loopback_only"] is False  # non-loopback peer flagged
    assert snap["risk_summary"]["a2a_non_loopback_count"] == 1


def test_a2a_env_endpoint_credential_never_leaks(monkeypatch, tmp_path):
    """Load-bearing security property for the A2A env-var surface: a URL
    with embedded userinfo creds + a ?token= query param must NEVER
    surface its secret in json OR table output — only scheme://host:port
    plus authed=True."""
    _stub_bouncers(monkeypatch, ibounce_running=False)
    monkeypatch.delenv("A2A_ENDPOINT", raising=False)
    monkeypatch.delenv("AGENT_TO_AGENT_ENDPOINT", raising=False)
    userinfo_secret = "a2asecretpw"
    query_secret = "A2AQUERYTOKENsecret123"
    monkeypatch.setenv(
        "IAM_JIT_A2A_ENDPOINT",
        f"https://agent:{userinfo_secret}@peer.example.com:8443/a2a"
        f"?token={query_secret}",
    )
    snap = capture_inventory(home=tmp_path)
    blob = json.dumps(snap)
    table = render_inventory_table(snap)
    # Neither the userinfo password nor the query token may appear in
    # ANY serialized form.
    for secret in (userinfo_secret, query_secret):
        assert secret not in blob, f"{secret} leaked into json"
        assert secret not in table, f"{secret} leaked into table"
    # The host:port IS reported (userinfo + path + query stripped).
    env_ep = next(
        e for e in snap["a2a_endpoints"] if e.get("kind") == "a2a-env"
    )
    assert env_ep["endpoint"] == "https://peer.example.com:8443"
    # Presence-of-secret reported honestly (not the value, not "unknown").
    assert env_ep["authed"] is True
    assert env_ep["loopback_only"] is False
    assert "peer.example.com:8443" in table


def test_remote_count_includes_sse_http_transports(monkeypatch, tmp_path):
    """The risk-summary remote tally must count every non-stdio wire —
    "remote", "sse", "http", "streamable-http" — not just the literal
    "remote" transport string (per-server records were already correct;
    this guards the rollup)."""
    _stub_bouncers(monkeypatch, ibounce_running=False)
    cfg = {
        "mcpServers": {
            "stdio-srv": {"command": "npx", "args": ["x"]},
            "sse-srv": {"type": "sse", "url": "https://sse.example.com/mcp"},
            "http-srv": {"type": "http", "url": "https://http.example.com/mcp"},
            "stream-srv": {
                "type": "streamable-http",
                "url": "https://stream.example.com/mcp",
            },
            "remote-srv": {
                "type": "remote",
                "url": "https://remote.example.com/mcp",
            },
        },
    }
    (tmp_path / ".claude.json").write_text(json.dumps(cfg))
    snap = capture_inventory(home=tmp_path)
    # 4 of the 5 servers are remote wires; the stdio one is not.
    assert snap["risk_summary"]["mcp_servers_remote"] == 4
    assert snap["risk_summary"]["mcp_server_count"] == 5


def test_empty_honesty_path(monkeypatch, tmp_path):
    """No MCP config + no bouncer running -> honest empty result with
    explanatory notes, never fabricated entries."""
    _stub_bouncers(monkeypatch, ibounce_running=False)
    monkeypatch.delenv("IAM_JIT_A2A_ENDPOINT", raising=False)
    monkeypatch.delenv("A2A_ENDPOINT", raising=False)
    monkeypatch.delenv("AGENT_TO_AGENT_ENDPOINT", raising=False)
    # tmp_path has no .claude.json -> no servers.
    snap = capture_inventory(home=tmp_path)
    assert snap["mcp_servers"] == []
    assert snap["a2a_endpoints"] == []
    # Honesty: notes explain the empty result rather than leaving it bare.
    assert any("no MCP harness config" in n for n in snap["mcp_notes"])
    assert any("no A2A endpoint" in n for n in snap["a2a_notes"])
    assert snap["risk_summary"]["mcp_server_count"] == 0


def test_malformed_config_is_non_fatal(tmp_path):
    (tmp_path / ".claude.json").write_text("{ this is not valid json ")
    result = discover_mcp_servers(home=tmp_path)
    assert result["servers"] == []
    assert any("not valid JSON" in n for n in result["notes"])


# ---------------------------------------------------------------------------
# JSON shape + schema
# ---------------------------------------------------------------------------


def test_json_shape(stub_home):
    snap = capture_inventory(home=stub_home)
    assert snap["schema_version"] == INVENTORY_SCHEMA_VERSION
    for key in (
        "captured_at",
        "mcp_servers",
        "mcp_configs_scanned",
        "bouncers",
        "a2a_endpoints",
        "risk_summary",
    ):
        assert key in snap, f"missing top-level key {key}"
    # Round-trips through JSON (no non-serializable values).
    json.dumps(snap)


# ---------------------------------------------------------------------------
# CLI + MCP parity
# ---------------------------------------------------------------------------


def test_cli_json_and_table(monkeypatch, stub_home):
    monkeypatch.setattr("pathlib.Path.home", lambda: stub_home)
    runner = CliRunner()
    res_json = runner.invoke(iam_jit_main, ["inventory", "--format", "json"])
    assert res_json.exit_code == 0, res_json.output
    payload = json.loads(res_json.output)
    assert payload["schema_version"] == INVENTORY_SCHEMA_VERSION
    assert _SECRET_TOKEN not in res_json.output

    res_table = runner.invoke(iam_jit_main, ["inventory"])
    assert res_table.exit_code == 0, res_table.output
    assert "MCP/A2A attack surface" in res_table.output
    assert _SECRET_TOKEN not in res_table.output


def test_mcp_tool_matches_cli(monkeypatch, stub_home):
    monkeypatch.setattr("pathlib.Path.home", lambda: stub_home)
    mcp_result = inventory_for_mcp({})
    assert mcp_result["schema_version"] == INVENTORY_SCHEMA_VERSION
    # Same top-level shape as the CLI snapshot.
    cli_snap = capture_inventory(home=stub_home)
    assert set(mcp_result.keys()) == set(cli_snap.keys())
