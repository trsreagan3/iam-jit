"""Tests for plan-capture proxy mode (#132).

Validates that:
  - PLAN_CAPTURE never forwards to a backend (no-network invariant)
  - Every intercepted call writes a plan_calls row
  - Synthetic SDK-shaped responses come back with bouncer headers
  - Unsupported ops produce a 400 with the SDK-shaped error body
  - Session bookkeeping persists across the serve() lifecycle
  - The existing modes (cooperative / transparent / off) are
    unchanged
"""

from __future__ import annotations

import asyncio
import json
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.plan_capture import (
    new_session_id,
    reset_session_for_tests,
    set_session_id,
)
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    serve,
)
from iam_jit.bouncer.store import BouncerStore


def _sigv4_auth(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260518/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakesignature"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _wait_for_listen(host: str, port: int, *, retries: int = 50) -> None:
    for _ in range(retries):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"nothing listening on {host}:{port}")


class _ExplodingBackend:
    """Stand-in for the AWS backend that fails loudly if anyone tries
    to connect to it. Used to prove plan-capture mode never forwards."""

    def __init__(self) -> None:
        self.port = _free_port()
        self.connection_attempts = 0
        self._runner = None

    async def start(self) -> None:
        from aiohttp import web

        async def handler(request):
            self.connection_attempts += 1
            return web.Response(text="plan-capture violation", status=500)

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self.port)
        await site.start()

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()


@pytest.fixture(autouse=True)
def _isolate_session_slot():
    """Each test gets a clean in-process session slot — otherwise
    test order would leak the slot between cases."""
    reset_session_for_tests()
    yield
    reset_session_for_tests()


# ---------------------------------------------------------------------------
# Core invariant: PLAN_CAPTURE never forwards
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_plan_capture_never_forwards_to_backend(tmp_path) -> None:
    """PLAN_CAPTURE mode + a SigV4-signed S3 request → synthetic
    response back, ZERO connections to the backend."""
    backend = _ExplodingBackend()
    await backend.start()
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        proxy_port = _free_port()
        session_id = new_session_id()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.PLAN_CAPTURE,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            plan_session_id=session_id,
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            sig_v4 = _sigv4_auth(service="s3", region="us-east-1")
            async with aiohttp.ClientSession() as csession:
                async with csession.get(
                    f"http://127.0.0.1:{proxy_port}/",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": sig_v4,
                    },
                ) as resp:
                    body = await resp.read()
                    resp_headers = dict(resp.headers)
            assert resp.status == 200
            assert resp_headers["x-iam-jit-bouncer-mode"] == "plan-capture"
            assert resp_headers["x-iam-jit-bouncer-plan-session"] == session_id
            # The exploding backend recorded ZERO connections
            assert backend.connection_attempts == 0
            # The body is the synthetic S3 ListBuckets XML shape
            assert b"<ListAllMyBucketsResult" in body
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await backend.stop()


@pytest.mark.asyncio
async def test_plan_capture_records_plan_call_row(tmp_path) -> None:
    """Every intercepted call should land in plan_calls with the
    verdict the bouncer would have assigned."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    session_id = new_session_id()
    config = ProxyConfig(
        host="127.0.0.1", port=proxy_port,
        mode=ProxyMode.PLAN_CAPTURE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        plan_session_id=session_id,
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        import aiohttp
        sig_v4 = _sigv4_auth(service="iam", region="us-east-1")
        async with aiohttp.ClientSession() as csession:
            async with csession.post(
                f"http://127.0.0.1:{proxy_port}/",
                headers={
                    "host": "iam.amazonaws.com",
                    "authorization": sig_v4,
                    "content-type": "application/x-www-form-urlencoded",
                },
                data=b"Action=CreateRole&RoleName=plan-test-role&Version=2010-05-08",
            ) as resp:
                _body = await resp.read()
        calls = store.list_plan_calls(session_id)
        assert len(calls) == 1
        row = calls[0]
        assert row["service"] == "iam"
        assert row["action"] == "CreateRole"
        assert row["would_have_called"] == "iam:CreateRole"
        assert row["supported"] is True
        assert row["would_have_returned"]["RoleName"] == "plan-test-role"
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_plan_capture_unsupported_op_returns_sdk_error(tmp_path) -> None:
    """Ops the synthetic registry doesn't cover return 400 with a
    PlanCaptureUnsupportedOperation body — clear signal to the
    operator to switch modes if they need it to execute."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    session_id = new_session_id()
    config = ProxyConfig(
        host="127.0.0.1", port=proxy_port,
        mode=ProxyMode.PLAN_CAPTURE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        plan_session_id=session_id,
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        import aiohttp
        # DynamoDB PutItem is intentionally NOT in the minimum-viable
        # registry — see synthetics._REGISTRY. Use the JSON-RPC
        # `X-Amz-Target` header so the parser pulls action=PutItem.
        sig_v4 = _sigv4_auth(service="dynamodb", region="us-east-1")
        async with aiohttp.ClientSession() as csession:
            async with csession.post(
                f"http://127.0.0.1:{proxy_port}/",
                headers={
                    "host": "dynamodb.us-east-1.amazonaws.com",
                    "authorization": sig_v4,
                    "x-amz-target": "DynamoDB_20120810.PutItem",
                    "content-type": "application/x-amz-json-1.0",
                },
                data=b"{}",
            ) as resp:
                body = await resp.read()
        assert resp.status == 400
        payload = json.loads(body)
        assert payload["Error"]["Code"] == "PlanCaptureUnsupportedOperation"
        # Verdict on the plan-call row should be 'unsupported'
        calls = store.list_plan_calls(session_id)
        assert len(calls) == 1
        assert calls[0]["verdict"] == "unsupported"
        assert calls[0]["supported"] is False
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_serve_mints_session_id_when_none_supplied(tmp_path) -> None:
    """serve() with no plan_session_id should mint a fresh id and
    record the session header so `ibounce plan list` shows it."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    # Don't supply a plan_session_id — serve() should mint one.
    config = ProxyConfig(
        host="127.0.0.1", port=proxy_port,
        mode=ProxyMode.PLAN_CAPTURE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        plan_session_id=None,
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        sessions = store.list_plan_sessions()
        assert len(sessions) == 1
        sid = sessions[0]["session_id"]
        # The id has the documented prefix-shape
        assert sid.startswith("plan-")
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# Backward-compatibility: existing modes must be untouched
# ---------------------------------------------------------------------------


def test_proxymode_still_has_cooperative_and_transparent() -> None:
    """Sanity: the new mode is ADDITIVE — original enum values + their
    string forms must stay stable for v1.0 backward-compat."""
    assert ProxyMode.COOPERATIVE.value == "cooperative"
    assert ProxyMode.TRANSPARENT.value == "transparent"
    assert ProxyMode.PLAN_CAPTURE.value == "plan-capture"


def test_resolve_active_mode_accepts_plan_capture_via_env(monkeypatch) -> None:
    """The mode-introspection MCP tool should surface plan-capture
    when the env var is set."""
    from iam_jit.bouncer.proxy import (
        ACTIVE_MODE_ENV,
        resolve_active_mode,
        set_session_mode_override,
    )

    set_session_mode_override(None)
    monkeypatch.setenv(ACTIVE_MODE_ENV, "plan-capture")
    try:
        out = resolve_active_mode()
        assert out == {"mode": "plan-capture", "source": "env"}
    finally:
        set_session_mode_override(None)


def test_set_session_mode_override_accepts_plan_capture() -> None:
    from iam_jit.bouncer.proxy import resolve_active_mode, set_session_mode_override

    try:
        set_session_mode_override("plan-capture")
        out = resolve_active_mode()
        assert out == {"mode": "plan-capture", "source": "session_override"}
    finally:
        set_session_mode_override(None)


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------


def test_set_session_id_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="must be non-empty"):
        set_session_id("")


def test_set_session_id_rejects_overly_long_id() -> None:
    with pytest.raises(ValueError, match="too long"):
        set_session_id("plan-" + "x" * 200)


def test_new_session_id_generates_unique_ids() -> None:
    a = new_session_id()
    b = new_session_id()
    assert a != b
    assert a.startswith("plan-")
    assert b.startswith("plan-")
