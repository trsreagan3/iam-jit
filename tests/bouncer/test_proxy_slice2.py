"""Tests for the bouncer HTTP proxy — Slice 2 (SigV4-preserving forwarding).

Covers:
- Hop-by-hop header stripping (RFC 7230)
- ALLOW (cooperative or transparent) forwards request to backend +
  returns response verbatim
- DENY + TRANSPARENT returns 403 without forwarding
- DENY + COOPERATIVE forwards anyway, surfaces advisory header
- Forward failure returns 502 with iam-jit shape
- Unclassifiable request returns 400
- SigV4 Authorization header forwarded verbatim (never re-signed)
- Body + headers preserved through forwarding
- x-iam-jit-bouncer-verdict header surfaced on every response

Uses a mock-AWS aiohttp app + config.forward_scheme="http" so the
proxy forwards plaintext to the mock instead of HTTPS to real AWS.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    _strip_hop_headers,
    serve,
)
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore


def _sigv4_auth(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260517/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakesignature"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------------------
# _strip_hop_headers unit
# ---------------------------------------------------------------------------


def test_strip_hop_headers_removes_rfc_7230_hop_set() -> None:
    """RFC 7230 §6.1: hop-by-hop headers must not be forwarded."""
    raw = {
        "Authorization": "AWS4-HMAC...",
        "Host": "s3.amazonaws.com",
        "Connection": "keep-alive",
        "Keep-Alive": "timeout=5",
        "Proxy-Authenticate": "Basic",
        "Proxy-Authorization": "Bearer x",
        "TE": "trailers",
        "Trailers": "x-trailer",
        "Transfer-Encoding": "chunked",
        "Upgrade": "h2c",
        "Content-Length": "42",
        "X-Custom": "preserve me",
    }
    out = _strip_hop_headers(raw)
    # Hop-by-hop stripped
    assert "Connection" not in out
    assert "Keep-Alive" not in out
    assert "Proxy-Authenticate" not in out
    assert "Proxy-Authorization" not in out
    assert "TE" not in out
    assert "Trailers" not in out
    assert "Transfer-Encoding" not in out
    assert "Upgrade" not in out
    assert "Content-Length" not in out
    # End-to-end preserved
    assert out["Authorization"] == "AWS4-HMAC..."
    assert out["Host"] == "s3.amazonaws.com"
    assert out["X-Custom"] == "preserve me"


def test_strip_hop_headers_is_case_insensitive() -> None:
    raw = {"connection": "keep-alive", "CONTENT-length": "5"}
    out = _strip_hop_headers(raw)
    assert "connection" not in out
    assert "CONTENT-length" not in out


def test_strip_hop_headers_does_not_mutate_input() -> None:
    raw = {"Connection": "keep-alive", "Authorization": "x"}
    snapshot = dict(raw)
    _ = _strip_hop_headers(raw)
    assert raw == snapshot


# ---------------------------------------------------------------------------
# Mock-AWS backend + end-to-end forwarding integration
# ---------------------------------------------------------------------------


class _MockAWS:
    """Stands up a tiny aiohttp app that mimics the bare-minimum
    AWS endpoint shape for proxy-forwarding tests."""

    def __init__(self) -> None:
        self.port = _free_port()
        self.received_requests: list[dict] = []
        self.next_response_status = 200
        self.next_response_body = b'{"status":"ok"}'
        self.next_response_headers: dict[str, str] = {
            "content-type": "application/json",
        }
        self._runner = None

    async def start(self) -> None:
        from aiohttp import web

        async def handler(request):
            body = await request.read()
            self.received_requests.append({
                "method": request.method,
                "path": request.path_qs,
                "headers": dict(request.headers),
                "body": body,
            })
            return web.Response(
                body=self.next_response_body,
                status=self.next_response_status,
                headers=self.next_response_headers,
            )

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self.port)
        await site.start()

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()


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


@pytest.mark.asyncio
async def test_allow_forwards_to_backend_and_returns_response(tmp_path) -> None:
    """ALLOW verdict → proxy forwards to backend + returns the
    backend's response verbatim. SigV4 Authorization header reaches
    the backend unmodified."""
    backend = _MockAWS()
    await backend.start()
    backend.next_response_status = 201
    backend.next_response_body = b'{"x":"y"}'
    backend.next_response_headers = {"content-type": "application/json"}
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        # Add an allow rule so the verdict is ALLOW
        store.add_rule(
            ProxyRule(
                pattern="s3:*", effect=Effect.ALLOW,
                arn_scope=None, region_scope=None,
                note="test allow",
                origin="manual",
            ),
            actor="test",
        )
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",  # forward HTTP to mock-AWS, not HTTPS
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            sig_v4 = _sigv4_auth(service="s3", region="us-east-1")
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    f"http://127.0.0.1:{proxy_port}/my-bucket/key.txt",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": sig_v4,
                        "content-type": "application/octet-stream",
                    },
                    data=b"hello world",
                ) as resp:
                    body = await resp.read()
                    resp_headers = dict(resp.headers)
            # Backend's response surfaced verbatim
            assert resp.status == 201
            assert body == b'{"x":"y"}'
            # Bouncer-debug headers attached
            assert resp_headers.get("x-iam-jit-bouncer-verdict") == "allow"
            assert resp_headers.get("x-iam-jit-bouncer-mode") == "transparent"
            # Backend received the request with SigV4 auth intact
            assert len(backend.received_requests) == 1
            seen = backend.received_requests[0]
            assert seen["method"] == "PUT"
            assert seen["body"] == b"hello world"
            # SigV4 Authorization forwarded verbatim (never re-signed)
            assert seen["headers"].get("Authorization") == sig_v4
            # Host header preserved
            assert seen["headers"].get("Host") == f"127.0.0.1:{backend.port}"
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
async def test_transparent_deny_returns_403_without_forwarding(tmp_path) -> None:
    """DENY in transparent mode → 403, no forward attempt."""
    backend = _MockAWS()
    await backend.start()
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        # No rules → default-deny in transparent enforce mode
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4_auth(service="iam", region="us-east-1"),
                    },
                ) as resp:
                    body = await resp.json()
                    resp_headers = dict(resp.headers)
            assert resp.status == 403
            assert body["error"] == "iam-jit-bouncer DENY"
            assert body["decision_verdict"] == "deny"
            assert resp_headers.get("x-iam-jit-bouncer-verdict") == "deny"
            # No forward attempted
            assert backend.received_requests == []
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
async def test_cooperative_deny_still_forwards_with_advisory_header(tmp_path) -> None:
    """DENY in cooperative mode → forwarded anyway (advisory),
    advisory header surfaced so the user can see what transparent
    would block."""
    backend = _MockAWS()
    await backend.start()
    backend.next_response_status = 200
    backend.next_response_body = b'{"forwarded":"yes"}'
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        # No rules → would-deny in transparent; cooperative forwards anyway
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.COOPERATIVE,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4_auth(service="s3", region="us-east-1"),
                    },
                ) as resp:
                    body = await resp.read()
                    resp_headers = dict(resp.headers)
            # Forwarded; client sees backend's response
            assert resp.status == 200
            assert body == b'{"forwarded":"yes"}'
            # Advisory header surfaces the verdict
            assert resp_headers.get("x-iam-jit-bouncer-verdict") == "deny"
            assert resp_headers.get("x-iam-jit-bouncer-mode") == "cooperative"
            assert resp_headers.get("x-iam-jit-bouncer-advisory") == "would-deny-in-transparent"
            # Backend actually received the call
            assert len(backend.received_requests) == 1
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
async def test_unclassifiable_request_returns_400(tmp_path) -> None:
    """Request with no SigV4 auth → can't determine target endpoint
    to forward to; return 400 with iam-jit explanation."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            # No Authorization header → unclassifiable
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/",
                headers={"host": "127.0.0.1:9999"},
            ) as resp:
                body = await resp.json()
        # In transparent mode this would be 403; in cooperative we
        # can't classify so 400 (can't forward without knowing where)
        assert resp.status == 400
        assert "unclassifiable" in body["decision_reason"]
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_forward_failure_returns_502(tmp_path) -> None:
    """If forwarding fails (backend unreachable), return 502 with
    iam-jit-shaped explanation."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.add_rule(
        ProxyRule(
            pattern="s3:*", effect=Effect.ALLOW,
            arn_scope=None, region_scope=None,
            note="test allow", origin="manual",
        ),
        actor="test",
    )
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=proxy_port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        import aiohttp
        # Forward to a port nothing is listening on → connection refused
        unreachable_port = _free_port()
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/",
                headers={
                    "host": f"127.0.0.1:{unreachable_port}",
                    "authorization": _sigv4_auth(service="s3", region="us-east-1"),
                },
            ) as resp:
                body = await resp.json()
                resp_headers = dict(resp.headers)
        assert resp.status == 502
        assert "forward to AWS failed" in body["error"]
        assert resp_headers.get("x-iam-jit-bouncer-forward-error") == "true"
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()
