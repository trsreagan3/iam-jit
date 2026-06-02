"""#728 — ghost-run / agent-shadow mode tests.

Covers the load-bearing invariants:
  * unit: session-id minting + path-safety + store capture/read/diff
  * unit: read/write classification routing decision
  * wiring (end-to-end, real proxy + fake-AWS backend):
      - a READ in ghost mode IS forwarded to AWS (agent sees real state)
      - a WRITE in ghost mode is NEVER forwarded + IS captured to the
        on-disk diff + returns a synthetic non-error response
      - default-off: cooperative mode is unaffected (reads + writes both
        forward; nothing is captured)
  * the captured diff review surface (shadow diff / list)
  * an OCSF audit event is emitted for the ghost-captured write
"""
from __future__ import annotations

import asyncio
import json
import socket

import pytest

from iam_jit import ghost_run
from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore


# ---------------------------------------------------------------------------
# Unit: sessions
# ---------------------------------------------------------------------------
def test_new_session_id_shape():
    sid = ghost_run.new_session_id()
    assert sid.startswith("shadow-")
    assert ghost_run.current_session_id() == sid
    ghost_run.reset_session_for_tests()
    assert ghost_run.current_session_id() is None


def test_set_session_id_rejects_path_traversal():
    with pytest.raises(ValueError):
        ghost_run.set_session_id("../escape")
    with pytest.raises(ValueError):
        ghost_run.set_session_id("a/b")
    with pytest.raises(ValueError):
        ghost_run.set_session_id("")
    # valid id accepted
    ghost_run.set_session_id("shadow-ok_1.2-3")
    assert ghost_run.current_session_id() == "shadow-ok_1.2-3"
    ghost_run.reset_session_for_tests()


def test_session_dir_rejects_unsafe_id(monkeypatch, tmp_path):
    monkeypatch.setenv("IAM_JIT_GHOST_RUNS_DIR", str(tmp_path))
    with pytest.raises(ghost_run.GhostRunError):
        ghost_run.session_dir("../../etc")


# ---------------------------------------------------------------------------
# Unit: store
# ---------------------------------------------------------------------------
def test_store_capture_read_diff(monkeypatch, tmp_path):
    monkeypatch.setenv("IAM_JIT_GHOST_RUNS_DIR", str(tmp_path))
    store = ghost_run.GhostRunStore()
    sid = "shadow-test-001"
    store.ensure_session(sid, started_by="tester", upstream=None)

    r1 = store.capture(
        sid, method="POST", service="iam", action="CreateRole",
        access_type="write", region="us-east-1",
        target="arn:aws:iam::123:role/foo",
        params={"body": {"RoleName": "foo"}},
        synthetic_response={"Arn": "arn:aws:iam::ghost:role/foo"},
    )
    r2 = store.capture(
        sid, method="POST", service="s3", action="PutObject",
        access_type="write", region="us-west-2",
        target="arn:aws:s3:::bucket/key",
        params={}, synthetic_response={"ETag": "plancapture..."},
    )
    assert r1.action_id == "act-0001"
    assert r2.action_id == "act-0002"

    actions = store.read_actions(sid)
    assert [a.action_id for a in actions] == ["act-0001", "act-0002"]
    assert actions[0].service == "iam"
    # honesty marker is always present + truthful
    assert actions[0].synthetic is True
    assert "NOT executed" in actions[0].honesty

    d = store.diff(sid)
    assert d["captured_writes"] == 2
    assert d["by_service"] == {"iam": 1, "s3": 1}
    assert d["by_action"]["iam:CreateRole"] == 1
    assert "were executed" in d["honesty"].lower()

    sessions = store.list_sessions()
    assert any(s["session_id"] == sid and s["captured_writes"] == 2
               for s in sessions)

    got = store.get_action(sid, "act-0002")
    assert got is not None and got.action == "PutObject"
    assert store.get_action(sid, "nope") is None


def test_store_read_missing_session_is_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("IAM_JIT_GHOST_RUNS_DIR", str(tmp_path))
    assert ghost_run.GhostRunStore().read_actions("shadow-missing") == []
    assert ghost_run.GhostRunStore().diff("shadow-missing")["actions"] == []


# ---------------------------------------------------------------------------
# Unit: read/write routing predicate (what the proxy branch consults)
# ---------------------------------------------------------------------------
def test_classification_routes_reads_vs_writes():
    from iam_jit.bouncer.plan_capture import is_write
    # reads forward
    assert is_write("sts", "GetCallerIdentity") is False
    assert is_write("s3", "ListBuckets") is False
    # writes capture
    assert is_write("iam", "CreateRole") is True
    assert is_write("s3", "PutObject") is True
    # unknown -> treated as write (captured, the safe direction)
    assert is_write("madeupservice", "FrobnicateThing") is True


# ---------------------------------------------------------------------------
# End-to-end wiring: a real proxy + a fake-AWS backend
# ---------------------------------------------------------------------------
_FAKE_STS_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::000000000000:user/iam-jit-test</Arn>
    <Account>000000000000</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>
"""


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _FakeAWS:
    def __init__(self):
        self.port = _free_port()
        self.received_requests: list[dict] = []
        self._runner = None

    async def start(self):
        from aiohttp import web

        async def handler(request):
            body = await request.read()
            self.received_requests.append({
                "method": request.method,
                "path": request.path_qs,
                "body": body,
            })
            return web.Response(
                body=_FAKE_STS_XML, status=200,
                headers={"content-type": "text/xml"},
            )

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self.port)
        await site.start()

    async def stop(self):
        if self._runner is not None:
            await self._runner.cleanup()


async def _wait_for_listen(host, port, *, retries=50):
    for _ in range(retries):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"nothing listening on {host}:{port}")


def _sigv4(service: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260602/us-east-1/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, Signature=fakesig"
    )


async def _run_ghost_proxy(tmp_path, monkeypatch, *, mode, captured_events):
    """Start a ghost-mode proxy + fake-AWS, send one READ + one WRITE,
    return (fake_aws, read_resp, write_resp, write_body)."""
    monkeypatch.setenv("IAM_JIT_GHOST_RUNS_DIR", str(tmp_path / "ghost"))
    ghost_run.reset_session_for_tests()
    ghost_run.set_session_id("shadow-e2e-001")

    # Capture emitted OCSF audit events.
    from iam_jit.bouncer import proxy as _proxy_mod

    def _spy_emit(event):
        captured_events.append(event)

    monkeypatch.setattr(_proxy_mod, "_emit_audit_event", _spy_emit)

    fake_aws = _FakeAWS()
    await fake_aws.start()
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.add_rule(
        ProxyRule(pattern="*", effect=Effect.ALLOW, arn_scope=None,
                  region_scope=None, note="allow all", origin="manual"),
        actor="test",
    )
    proxy_port = _free_port()

    def fake_endpoint_resolver(service, region):  # noqa: SD-2 test stub: DI signature must match (service, region); both params are intentionally ignored — every call routes to the one fake-AWS backend
        return f"127.0.0.1:{fake_aws.port}"

    config = ProxyConfig(
        host="127.0.0.1", port=proxy_port, mode=mode,
        default_policy=DefaultPolicy.ALLOW, forward_scheme="http",
        forward_host_override=None,
        aws_endpoint_resolver=fake_endpoint_resolver,
        ghost_session_id="shadow-e2e-001",
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        import aiohttp
        signed_host = f"127.0.0.1:{proxy_port}"
        async with aiohttp.ClientSession() as session:
            # READ: sts:GetCallerIdentity
            async with session.post(
                f"http://127.0.0.1:{proxy_port}/",
                headers={"host": signed_host, "authorization": _sigv4("sts"),
                         "content-type": "application/x-www-form-urlencoded",
                         "x-amz-date": "20260602T000000Z"},
                data=b"Action=GetCallerIdentity&Version=2011-06-15",
            ) as r:
                read_status = r.status
                read_body = await r.read()
                read_headers = dict(r.headers)
            # WRITE: iam:CreateRole
            async with session.post(
                f"http://127.0.0.1:{proxy_port}/",
                headers={"host": signed_host, "authorization": _sigv4("iam"),
                         "content-type": "application/x-www-form-urlencoded",
                         "x-amz-date": "20260602T000000Z"},
                data=b"Action=CreateRole&RoleName=ghosttest&Version=2010-05-08",
            ) as r:
                write_status = r.status
                write_body = await r.read()
                write_headers = dict(r.headers)
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:  # noqa: SD-1 expected: we cancelled the serve() task ourselves; swallowing its own CancelledError is the standard asyncio teardown idiom
            pass
        store.close()
        await fake_aws.stop()
    return {
        "fake_aws": fake_aws,
        "read_status": read_status, "read_body": read_body,
        "read_headers": read_headers,
        "write_status": write_status, "write_body": write_body,
        "write_headers": write_headers,
    }


@pytest.mark.asyncio
async def test_ghost_read_forwarded_write_captured_not_forwarded(
    tmp_path, monkeypatch,
):
    events: list[dict] = []
    out = await _run_ghost_proxy(
        tmp_path, monkeypatch, mode=ProxyMode.GHOST, captured_events=events,
    )
    fake_aws = out["fake_aws"]

    # (1) The READ reached fake-AWS (agent sees real state).
    forwarded = [r for r in fake_aws.received_requests
                 if b"GetCallerIdentity" in r["body"]]
    assert len(forwarded) == 1, (
        "ghost READ must forward to AWS so the agent sees real state"
    )
    assert out["read_status"] == 200
    assert out["read_body"] == _FAKE_STS_XML

    # (2) The WRITE did NOT reach fake-AWS — the load-bearing invariant.
    write_forwarded = [r for r in fake_aws.received_requests
                       if b"CreateRole" in r["body"]]
    assert len(write_forwarded) == 0, (
        "GHOST INVARIANT VIOLATED: a write reached AWS. Ghost mode must "
        "NEVER forward writes."
    )

    # (3) The agent got a synthetic NON-error response so it keeps going.
    assert out["write_status"] in (200, 201), out["write_status"]
    assert out["write_headers"].get("x-iam-jit-bouncer-mode") == "ghost"
    assert out["write_headers"].get("x-iam-jit-bouncer-ghost-captured") == "true"
    assert out["write_headers"].get("x-iam-jit-bouncer-ghost-forwarded") == "false"

    # (4) The write was captured to the on-disk diff.
    diff = ghost_run.GhostRunStore().diff("shadow-e2e-001")
    assert diff["captured_writes"] == 1
    captured = diff["actions"][0]
    assert captured["service"] == "iam"
    assert captured["action"] == "CreateRole"
    assert captured["synthetic"] is True
    assert "NOT executed" in captured["honesty"]

    # (5) An OCSF audit event was emitted for the ghost-captured write.
    ghost_events = [
        e for e in events
        if (e.get("unmapped", {}) or {}).get("iam_jit", {})
        .get("ext", {}).get("ghost_run")
        or "ghost_run" in json.dumps(e)
    ]
    assert ghost_events, "expected an OCSF event for the ghost-captured write"


@pytest.mark.asyncio
async def test_cooperative_mode_unaffected_default_off(tmp_path, monkeypatch):
    """Default-off: in cooperative mode BOTH the read AND the write
    forward to AWS, and NOTHING is captured to the ghost store."""
    events: list[dict] = []
    out = await _run_ghost_proxy(
        tmp_path, monkeypatch, mode=ProxyMode.COOPERATIVE,
        captured_events=events,
    )
    fake_aws = out["fake_aws"]
    # Both calls forwarded.
    assert any(b"GetCallerIdentity" in r["body"]
               for r in fake_aws.received_requests)
    assert any(b"CreateRole" in r["body"]
               for r in fake_aws.received_requests), (
        "cooperative mode must forward writes (ghost mode is opt-in)"
    )
    # Nothing captured.
    diff = ghost_run.GhostRunStore().diff("shadow-e2e-001")
    assert diff["captured_writes"] == 0


# ---------------------------------------------------------------------------
# CLI review surface: shadow list / diff / apply
# ---------------------------------------------------------------------------
def _seed(monkeypatch, tmp_path, sid="shadow-cli-1"):
    monkeypatch.setenv("IAM_JIT_GHOST_RUNS_DIR", str(tmp_path / "ghost"))
    s = ghost_run.GhostRunStore()
    s.ensure_session(sid, started_by="tester", upstream=None)
    s.capture(sid, method="POST", service="s3", action="PutObject",
              access_type="write", region="us-east-1",
              target="arn:aws:s3:::b/k", params={"body": {"K": "V"}},
              synthetic_response={"ETag": "plancapture..."})
    return sid


def test_cli_shadow_list_and_diff_and_apply(monkeypatch, tmp_path):
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main as ibounce_main

    sid = _seed(monkeypatch, tmp_path)
    runner = CliRunner()

    res = runner.invoke(ibounce_main, ["shadow", "list", "--json"])
    assert res.exit_code == 0, res.output
    rows = json.loads(res.output)
    assert any(r["session_id"] == sid for r in rows)

    res = runner.invoke(ibounce_main, ["shadow", "diff", sid, "--json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["captured_writes"] == 1
    assert payload["actions"][0]["action"] == "PutObject"

    res = runner.invoke(
        ibounce_main, ["shadow", "apply", sid, "--action", "act-0001", "--json"],
    )
    assert res.exit_code == 0, res.output
    summary = json.loads(res.output)
    assert summary["service"] == "s3"
    # honesty: apply NEVER claims to have mutated.
    assert "did NOT" in summary["note"] or "not execute" in summary["note"].lower()


def test_cli_shadow_diff_unknown_session_errors(monkeypatch, tmp_path):
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main as ibounce_main

    monkeypatch.setenv("IAM_JIT_GHOST_RUNS_DIR", str(tmp_path / "ghost"))
    runner = CliRunner()
    res = runner.invoke(ibounce_main, ["shadow", "diff", "shadow-nope"])
    assert res.exit_code == 2


# ---------------------------------------------------------------------------
# MCP visibility tools
# ---------------------------------------------------------------------------
def test_mcp_ghost_tools(monkeypatch, tmp_path):
    from iam_jit.mcp_server import (
        _bouncer_ghost_session_diff_for_mcp,
        _bouncer_ghost_session_list_for_mcp,
    )

    sid = _seed(monkeypatch, tmp_path)

    listed = _bouncer_ghost_session_list_for_mcp({})
    assert listed["count"] >= 1
    assert any(s["session_id"] == sid for s in listed["sessions"])

    diff = _bouncer_ghost_session_diff_for_mcp({"session_id": sid})
    assert diff["captured_writes"] == 1
    assert diff["actions"][0]["service"] == "s3"

    # unknown session -> error shape
    err = _bouncer_ghost_session_diff_for_mcp({"session_id": "shadow-nope"})
    assert "error" in err

    # the tool is registered in the discovery list
    from iam_jit.mcp_server import TOOLS
    names = {t["name"] for t in TOOLS}
    assert "bouncer_ghost_session_list" in names
    assert "bouncer_ghost_session_diff" in names
