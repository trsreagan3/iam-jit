"""#300 regression — `--upstream` URL scheme + host override.

Surfaced by UAT 2026-05-22 (LocalStack + ibounce). The bug: the
proxy hard-coded `https://` for the outbound scheme + always
forwarded to the inbound SigV4-signed Host header, so pointing
ibounce at a plain-HTTP LocalStack endpoint failed.

This module covers:
  1. `parse_upstream_url` accepts http://HOST:PORT and returns
     ("http", "HOST:PORT").
  2. `parse_upstream_url` accepts https://HOST and returns
     ("https", "HOST").
  3. `parse_upstream_url` rejects non-http(s) schemes with
     UpstreamUrlError.
  4. `parse_upstream_url` rejects schemeless URLs with
     UpstreamUrlError (fail-safe: never default to https because
     the operator likely meant http — the LocalStack mistake).
  5. End-to-end: with ProxyConfig.forward_scheme="http" +
     forward_host_override pointed at a mock-LocalStack backend on
     a free port, a SigV4-signed request through the proxy reaches
     the backend via HTTP (not HTTPS). The inbound Host header is
     ignored in favour of the override.

Per [[creates-never-mutates]]: surgical fix, no refactor. The
existing forward_scheme="http" branch already had tests; this adds
the forward_host_override side.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    UpstreamUrlError,
    parse_upstream_url,
    serve,
)
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore


# ---------------------------------------------------------------------------
# parse_upstream_url — unit
# ---------------------------------------------------------------------------


def test_parse_upstream_url_http_with_port_returns_http_scheme():
    """Test 1: --upstream http://127.0.0.1:4566 → ('http', '127.0.0.1:4566').
    LocalStack default. Without this, ibounce can't talk to local
    mock-AWS endpoints (UAT 2026-05-22 launch blocker)."""
    scheme, host = parse_upstream_url("http://127.0.0.1:4566")
    assert scheme == "http"
    assert host == "127.0.0.1:4566"


def test_parse_upstream_url_https_without_port_returns_https_scheme():
    """Test 2: --upstream https://api.example.com → ('https',
    'api.example.com'). Existing real-AWS-style behaviour, but now
    explicit via --upstream."""
    scheme, host = parse_upstream_url("https://api.example.com")
    assert scheme == "https"
    assert host == "api.example.com"


def test_parse_upstream_url_https_with_port():
    scheme, host = parse_upstream_url("https://s3.us-east-1.amazonaws.com:443")
    assert scheme == "https"
    assert host == "s3.us-east-1.amazonaws.com:443"


def test_parse_upstream_url_rejects_ftp_scheme():
    """Test 3: --upstream ftp://invalid → UpstreamUrlError with a
    clear message. The proxy only forwards http or https; refusing
    weirder schemes fail-fast at startup avoids confusing aiohttp
    errors mid-request."""
    with pytest.raises(UpstreamUrlError) as exc_info:
        parse_upstream_url("ftp://invalid")
    assert "ftp" in str(exc_info.value).lower()
    assert "http" in str(exc_info.value).lower()


def test_parse_upstream_url_rejects_file_scheme():
    with pytest.raises(UpstreamUrlError):
        parse_upstream_url("file:///etc/passwd")


def test_parse_upstream_url_rejects_ws_scheme():
    with pytest.raises(UpstreamUrlError):
        parse_upstream_url("ws://example.com")


def test_parse_upstream_url_rejects_schemeless_url():
    """Test 4: --upstream 127.0.0.1:4566 (no scheme) → fails with a
    clear error. Per the task spec we picked the SAFER fail-fast
    option over silently defaulting to https — operators pointing
    at LocalStack typically forget the scheme + the resulting
    'connection reset by peer' from HTTPS-talking-to-HTTP wasted
    hours during UAT. Explicit scheme is now mandatory."""
    with pytest.raises(UpstreamUrlError) as exc_info:
        parse_upstream_url("127.0.0.1:4566")
    # urlparse treats "127.0.0.1:4566" as scheme="127.0.0.1",
    # path="4566" — either way our check rejects it.
    msg = str(exc_info.value)
    assert "scheme" in msg.lower() or "http" in msg.lower()


def test_parse_upstream_url_rejects_empty_string():
    with pytest.raises(UpstreamUrlError):
        parse_upstream_url("")


def test_parse_upstream_url_rejects_none():
    with pytest.raises(UpstreamUrlError):
        parse_upstream_url(None)  # type: ignore[arg-type]


def test_parse_upstream_url_rejects_https_with_no_host():
    with pytest.raises(UpstreamUrlError):
        parse_upstream_url("https://")


# ---------------------------------------------------------------------------
# CLI surface — `ibounce run --upstream URL` validation
# ---------------------------------------------------------------------------


def test_cli_rejects_ftp_upstream_at_startup(tmp_path):
    """CLI catches the parse error early + surfaces the message."""
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main

    runner = CliRunner()
    db_path = str(tmp_path / "state.db")
    runner.invoke(main, ["init", "--db", db_path])
    result = runner.invoke(
        main,
        ["run", "--db", db_path, "--port", "0",
         "--upstream", "ftp://nope.example.com"],
    )
    assert result.exit_code == 2
    assert "--upstream" in result.output
    assert "ftp" in result.output.lower()


def test_cli_rejects_schemeless_upstream_at_startup(tmp_path):
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main

    runner = CliRunner()
    db_path = str(tmp_path / "state.db")
    runner.invoke(main, ["init", "--db", db_path])
    result = runner.invoke(
        main,
        ["run", "--db", db_path, "--port", "0",
         "--upstream", "127.0.0.1:4566"],
    )
    assert result.exit_code == 2
    assert "--upstream" in result.output


# ---------------------------------------------------------------------------
# End-to-end: ProxyConfig.forward_host_override actually forwards
# to the override target (not the inbound Host header)
# ---------------------------------------------------------------------------


def _sigv4_auth(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260522/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakesignature"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _MockLocalStack:
    """Tiny aiohttp app that stands in for LocalStack at a known
    port. Records every received request so the test can prove the
    proxy forwarded HERE (via the override) instead of to the
    inbound Host header."""

    def __init__(self):
        self.port = _free_port()
        self.received_requests: list[dict] = []
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
                body=b'{"localstack":"received"}',
                status=200,
                headers={"content-type": "application/json"},
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
async def test_upstream_override_forwards_to_localstack_not_signed_host(tmp_path):
    """Test 5 (end-to-end): with forward_host_override set, the
    proxy forwards to the OVERRIDE target via the OVERRIDE scheme,
    NOT to the SigV4-signed Host header.

    This is the bug-fix for #300: pre-fix, even passing
    forward_scheme="http" wouldn't help because the proxy
    forwarded to the SigV4-signed Host (which for boto3 +
    AWS_ENDPOINT_URL=http://127.0.0.1:PROXY is the PROXY's own
    port, causing an infinite loop). The override decouples the
    forward target from the signed Host so LocalStack works."""
    localstack = _MockLocalStack()
    await localstack.start()
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
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
        # Simulate `ibounce run --upstream http://127.0.0.1:{LS_PORT}`
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            forward_host_override=f"127.0.0.1:{localstack.port}",
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            # SDK client signs with the proxy's own Host (that's what
            # boto3 + AWS_ENDPOINT_URL produces in the LocalStack flow).
            # Pre-fix this would forward back to itself; post-fix the
            # override redirects to localstack.port.
            sig_v4 = _sigv4_auth(service="s3", region="us-east-1")
            signed_host = f"127.0.0.1:{proxy_port}"
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    f"http://127.0.0.1:{proxy_port}/my-bucket/key.txt",
                    headers={
                        "host": signed_host,
                        "authorization": sig_v4,
                        "content-type": "application/octet-stream",
                    },
                    data=b"localstack body",
                ) as resp:
                    body = await resp.read()
            # Backend received the call (proves override took effect)
            assert resp.status == 200
            assert body == b'{"localstack":"received"}'
            assert len(localstack.received_requests) == 1
            seen = localstack.received_requests[0]
            assert seen["method"] == "PUT"
            assert seen["body"] == b"localstack body"
            # SigV4 signature forwarded verbatim (not re-signed)
            assert seen["headers"].get("Authorization") == sig_v4
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await localstack.stop()


@pytest.mark.asyncio
async def test_no_upstream_override_preserves_signed_host_forwarding(tmp_path):
    """Regression-guard: when forward_host_override is None (the
    default; real-AWS shape), the proxy still forwards to the
    SigV4-signed Host header. The #300 fix MUST NOT change existing
    behaviour for operators not passing --upstream."""
    backend = _MockLocalStack()
    await backend.start()
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
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
        # No override; just forward_scheme="http" (existing test shape).
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            forward_host_override=None,  # explicit: no override
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            sig_v4 = _sigv4_auth(service="s3", region="us-east-1")
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    f"http://127.0.0.1:{proxy_port}/bucket/key.txt",
                    headers={
                        # Signed Host points DIRECTLY at the backend;
                        # without override, that's where forwarding lands.
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": sig_v4,
                    },
                    data=b"data",
                ) as resp:
                    body = await resp.read()
            assert resp.status == 200
            assert body == b'{"localstack":"received"}'
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
