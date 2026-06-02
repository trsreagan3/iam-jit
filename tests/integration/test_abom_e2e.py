"""ADOPT-1 / #715 — integration tests for the CycloneDX 1.6 ABOM.

Exercises the FULL surface end-to-end without live bouncer binaries:

* CLI: `iam-jit audit query --session SID --format cyclonedx` — stubs
  the per-bouncer urlopen the same way the agent-diff e2e tests do, so
  the SAME fan-out + merge path the diff/extract features use produces
  the ABOM.
* MCP: `iam_jit_audit_export_abom` handler over the same stubbed
  fan-out, including the unreachable-bouncer partial-data path.

Asserts BOTH shape AND content + the partial-data honesty signals per
[[uat-tests-setup-end-to-end]] + [[ibounce-honest-positioning]].
"""

from __future__ import annotations

import json
from typing import Any

import click
from click.testing import CliRunner

import iam_jit.cli_audit_query as _audit_query_mod
from iam_jit.cli_audit_query import register_audit_query_group


_T_BASE = 1737590400000


def _query_cmd() -> click.Command:
    g = click.Group()
    register_audit_query_group(g)
    return g.commands["audit"].commands["query"]


def _ev(
    *,
    session: str,
    bouncer: str = "ibounce",
    service: str | None = None,
    operation: str | None = None,
    resource: str | None = None,
    verdict: str = "allow",
    role_arn: str | None = None,
    namespace: str | None = None,
    database: str | None = None,
    host: str | None = None,
    mcp_tool: str | None = None,
    t_offset: int = 0,
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "_bouncer": bouncer,
        "time": _T_BASE + t_offset,
        "metadata": {"product": {"name": bouncer}},
        "unmapped": {"iam_jit": {
            "verdict": verdict,
            "agent": {"session_id": session},
        }},
    }
    if service or operation:
        ev["api"] = {}
        if service:
            ev["api"]["service"] = {"name": service}
        if operation:
            ev["api"]["operation"] = operation
    if resource:
        ev["resources"] = [{"uid": resource}]
    iam = ev["unmapped"]["iam_jit"]
    if role_arn:
        iam["role_arn"] = role_arn
    if namespace:
        iam["namespace"] = namespace
    if database:
        iam["database"] = database
    if host:
        iam["host"] = host
        ev["dst_endpoint"] = {"hostname": host}
    if mcp_tool:
        iam["mcp"] = {"tool": mcp_tool}
    return ev


def _install_urlopen_stub(monkeypatch, events_by_session: dict[str, list[dict]]):
    """Per-bouncer urlopen stub. Routes events by both the
    session-filter in the URL AND the destination port so each
    bouncer (ibounce 8767 / kbounce 8766 / dbounce 8768 / gbounce
    8769) returns only its own events."""
    port_to_bouncer = {
        "8767": "ibounce",
        "8766": "kbounce",
        "8768": "dbounce",
        "8769": "gbounce",
    }

    class _FakeResp:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self._body

    def _stub(req, timeout=None):
        _ = timeout  # urlopen signature parity; per-bouncer timeout
        from urllib.parse import unquote
        url = req.full_url if hasattr(req, "full_url") else str(req)
        match_session = None
        for piece in url.split("&"):
            if "filter=" in piece:
                token = unquote(piece.split("filter=", 1)[1])
                if "session_id=" in token:
                    match_session = token.split("session_id=", 1)[1]
                    break
        this_bouncer = None
        for port, name in port_to_bouncer.items():
            if f":{port}" in url:
                this_bouncer = name
                break
        events = [
            e for e in events_by_session.get(match_session or "", [])
            if e.get("_bouncer") == this_bouncer
        ]
        body = "\n".join(json.dumps(e) for e in events).encode("utf-8")
        return _FakeResp(body)

    monkeypatch.setattr(_audit_query_mod, "_urlopen", _stub)


# ---------------------------------------------------------------------------
# CLI path
# ---------------------------------------------------------------------------


def test_cli_cyclonedx_cross_product_session(monkeypatch) -> None:
    sess = "sid-cross"
    events = [
        _ev(session=sess, service="s3", operation="GetObject",
            resource="arn:aws:s3:::reports/k", role_arn="arn:aws:iam::1:role/r"),
        _ev(session=sess, bouncer="kbounce", namespace="prod", t_offset=10),
        _ev(session=sess, bouncer="dbounce", database="orders",
            host="pg.int", operation="SELECT", verdict="deny", t_offset=20),
        _ev(session=sess, bouncer="gbounce", host="api.stripe.com", t_offset=30),
    ]
    _install_urlopen_stub(monkeypatch, {sess: events})

    runner = CliRunner()
    result = runner.invoke(
        _query_cmd(),
        ["--session", sess, "--format", "cyclonedx"],
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")

    # CycloneDX 1.6: data artifacts live in components[], network
    # services (aws_service / http_endpoint / mcp_tool) in services[].
    entities = list(doc.get("components", [])) + list(doc.get("services", []))
    kinds = {
        p["value"]
        for c in entities
        for p in c["properties"]
        if p["name"] == "iam-jit:component.kind"
    }
    # Cross-product: AWS role + AWS service + AWS resource + K8s ns +
    # DB + HTTP endpoint all present in ONE ABOM.
    assert {"iam_role", "aws_service", "aws_resource",
            "k8s_namespace", "database", "http_endpoint"} <= kinds
    # Service-ish kinds must NOT appear as components (spec-correctness).
    comp_kinds = {
        p["value"]
        for c in doc["components"]
        for p in c["properties"]
        if p["name"] == "iam-jit:component.kind"
    }
    assert not ({"aws_service", "http_endpoint", "mcp_tool"} & comp_kinds)
    # And every component carries a legal CycloneDX 1.6 component.type.
    for c in doc["components"]:
        assert c["type"] != "service"

    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["iam-jit:session.id"] == sess
    assert meta["iam-jit:observed.complete"] == "true"


def test_cli_cyclonedx_requires_session() -> None:
    runner = CliRunner()
    result = runner.invoke(_query_cmd(), ["--format", "cyclonedx"])
    assert result.exit_code != 0
    assert "requires --session" in result.output


def test_cli_cyclonedx_empty_session_is_honest(monkeypatch) -> None:
    _install_urlopen_stub(monkeypatch, {})  # no events for any session
    runner = CliRunner()
    result = runner.invoke(
        _query_cmd(),
        ["--session", "sid-empty", "--format", "cyclonedx"],
    )
    # All bouncers reachable but returned 0 events => exit 0, valid doc,
    # but flagged partial on stderr + in the doc.
    assert result.exit_code == 0, result.output
    # stdout = the ABOM; stderr notes are mixed by CliRunner by default,
    # so parse the JSON object from the output.
    start = result.output.index("{")
    doc = json.loads(result.output[start:])
    assert doc["components"] == []
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["iam-jit:observed.complete"] == "false"
    assert "partial ABOM" in result.output


# ---------------------------------------------------------------------------
# MCP path
# ---------------------------------------------------------------------------


def test_mcp_export_abom_ok(monkeypatch) -> None:
    from iam_jit.mcp_server import _iam_jit_audit_export_abom_for_mcp

    sess = "sid-mcp"
    events = [
        _ev(session=sess, service="s3", operation="GetObject",
            resource="arn:aws:s3:::b/k"),
        _ev(session=sess, mcp_tool="iam_jit_request_role", t_offset=5),
    ]
    _install_urlopen_stub(monkeypatch, {sess: events})

    out = _iam_jit_audit_export_abom_for_mcp({"session": sess})
    assert out["status"] == "ok"
    assert out["abom"]["specVersion"] == "1.6"
    assert out["events_analyzed"] == 2
    assert out["component_count"] >= 3  # service + resource + mcp_tool
    assert out["partial"]["is_partial"] is False


def test_mcp_export_abom_missing_session() -> None:
    from iam_jit.mcp_server import _iam_jit_audit_export_abom_for_mcp

    out = _iam_jit_audit_export_abom_for_mcp({})
    assert out["status"] == "error"
    assert out["code"] == "missing_session"


def test_mcp_export_abom_unreachable_bouncer_is_partial(monkeypatch) -> None:
    from iam_jit.mcp_server import _iam_jit_audit_export_abom_for_mcp

    sess = "sid-partial"

    def _boom(req, timeout=None):
        _ = (req, timeout)  # urlopen signature parity; always raises
        raise OSError("connection refused")

    monkeypatch.setattr(_audit_query_mod, "_urlopen", _boom)

    out = _iam_jit_audit_export_abom_for_mcp({"session": sess})
    # Fan-out errors surface as notes, not a fatal — the ABOM is still
    # produced (empty) and flagged partial.
    assert out["status"] == "ok"
    assert out["partial"]["is_partial"] is True
    reasons = " ".join(out["partial"]["reasons"])
    assert "bouncer_gaps" in reasons or "no_events_observed" in reasons
