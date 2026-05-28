"""#687 regression — the canonical `iam-jit attach` forward path.

THIS IS THE TEST THAT WOULD HAVE CAUGHT #687. Per the prior session's
process audit, every existing forward test used ``forward_host_override``
(the LocalStack #300 path), masking the bug for the default no-override
shape that every real `iam-jit attach` user hits.

The setup an operator actually runs:

  1. Start ibounce on 127.0.0.1:PROXY (no --upstream).
  2. `iam-jit attach` writes ``endpoint_url=http://127.0.0.1:PROXY``
     into ~/.aws/config.
  3. The AWS SDK now sends every call to PROXY with
     ``Host: 127.0.0.1:PROXY`` — pointing at the bouncer ITSELF.

Pre-#687, the proxy did ``forward_target_host = override or host_header``,
which in this shape made it dial its own listener (over HTTPS, because
``forward_scheme="https"``) → SSL recursion → 502 to the SDK on every
call. ``decisions_count`` ticked (audit happened) so prior UATs reported
"works", but the agent's actual call was always broken.

This test exercises that exact shape and asserts:

  * The proxy resolves the upstream from the SigV4 credential scope
    (not the inbound Host).
  * The fake-AWS backend receives the forwarded request with the
    original SigV4 signature intact.
  * The SDK gets a real-shape AWS response body (status 200 + the
    bytes the backend returned).

Without the #687 fix this test would either time out (recursing) or
return ``UPSTREAM_FORWARD_FAILED``; with the fix it passes.
"""
from __future__ import annotations

import asyncio
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore


# The body the fake-AWS server returns — shaped like the canonical
# sts:GetCallerIdentity success response so a smarter SDK (e.g.
# botocore) could parse it without crashing. Tests assert the raw
# bytes round-trip, which is the bouncer's job — XML correctness
# is AWS's job, not ibounce's.
_FAKE_STS_GETCALLERIDENTITY_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::000000000000:user/iam-jit-test</Arn>
    <UserId>AIDAFAKEFAKEFAKEFAKE</UserId>
    <Account>000000000000</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>fake-request-id-687</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
"""


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _FakeAWS:
    """Tiny aiohttp server pretending to be sts.us-east-1.amazonaws.com.
    Records every received request so the test can prove ibounce
    forwarded HERE — derived from the SigV4 scope — instead of dialling
    its own listener (the #687 recursion shape)."""

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
                "host_header": request.headers.get("Host"),
                "authorization": request.headers.get("Authorization"),
                "body": body,
            })
            return web.Response(
                body=_FAKE_STS_GETCALLERIDENTITY_XML,
                status=200,
                headers={"content-type": "text/xml"},
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


def _sigv4_auth_for_sts() -> str:
    """A SigV4-shaped Authorization header that the bouncer's
    request_parser will classify as sts/us-east-1. We don't care about
    cryptographic validity — ibounce never validates SigV4 (AWS does)."""
    return (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIAEXAMPLE/20260528/us-east-1/sts/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakesignature687"
    )


@pytest.mark.asyncio
async def test_687_attach_path_forwards_to_canonical_aws_endpoint(tmp_path):
    """THE #687 LITERAL REPRO + REGRESSION GUARD.

    SDK Host header = bouncer's own listen address (the canonical
    `iam-jit attach` shape). SigV4 credential scope says sts/us-east-1.
    Pre-fix: ibounce dialled itself → 502. Post-fix: ibounce resolves
    via SigV4 scope → fake-AWS server (DI'd to stand in for the
    canonical endpoint) → SDK gets the real-shape 200 response.
    """
    fake_aws = _FakeAWS()
    await fake_aws.start()
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        store.add_rule(
            ProxyRule(
                pattern="sts:*", effect=Effect.ALLOW,
                arn_scope=None, region_scope=None,
                note="test allow", origin="manual",
            ),
            actor="test",
        )
        proxy_port = _free_port()
        # Build a ProxyConfig that mirrors the canonical `iam-jit attach`
        # production shape: NO --upstream override, forward_scheme=http
        # (testing without real TLS), and a DI'd endpoint resolver
        # standing in for botocore's canonical-endpoint catalog —
        # pointing at our fake-AWS server.
        def fake_endpoint_resolver(service, region):
            assert service == "sts"
            assert region == "us-east-1"
            return f"127.0.0.1:{fake_aws.port}"

        config = ProxyConfig(
            host="127.0.0.1",
            port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            forward_host_override=None,  # CRITICAL — the bug-masking knob
            aws_endpoint_resolver=fake_endpoint_resolver,
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            signed_host = f"127.0.0.1:{proxy_port}"  # the iam-jit attach shape
            sig_v4 = _sigv4_auth_for_sts()
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{proxy_port}/",
                    headers={
                        "host": signed_host,
                        "authorization": sig_v4,
                        "content-type": "application/x-www-form-urlencoded",
                        "x-amz-date": "20260528T000000Z",
                    },
                    data=b"Action=GetCallerIdentity&Version=2011-06-15",
                ) as resp:
                    body = await resp.read()

            # ============== The assertions that would have caught #687 ===============
            # (1) The SDK got a 200 — not a 502 UPSTREAM_FORWARD_FAILED.
            assert resp.status == 200, (
                f"#687 regression: SDK got {resp.status} (expected 200). "
                f"Body: {body[:300]!r}"
            )
            # (2) The SDK got the REAL backend body — not an ibounce error envelope.
            assert body == _FAKE_STS_GETCALLERIDENTITY_XML, (
                f"#687 regression: body wasn't the backend response. "
                f"Got: {body[:300]!r}"
            )
            # (3) The fake-AWS backend actually received the forwarded call.
            assert len(fake_aws.received_requests) == 1, (
                "#687 regression: fake-AWS got 0 requests — ibounce dialled "
                "itself instead of the canonical endpoint."
            )
            seen = fake_aws.received_requests[0]
            assert seen["method"] == "POST"
            assert seen["body"] == b"Action=GetCallerIdentity&Version=2011-06-15"
            # (4) The SigV4 signature was forwarded verbatim (proves the
            # bouncer didn't re-sign + that the resolver swap didn't
            # break the request shape).
            assert seen["authorization"] == sig_v4
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await fake_aws.stop()


@pytest.mark.asyncio
async def test_687_self_host_unresolvable_returns_clean_502_not_recursion(tmp_path):
    """Honest-failure branch: when the SDK points at us AND we can't
    derive the canonical endpoint (DI'd resolver returns None), the
    proxy MUST return a structured 502 UPSTREAM_RESOLUTION_FAILED
    instead of silently recursing into its own listener.

    This is the [[ibounce-honest-positioning]] guard: surface failure,
    don't loop.
    """
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.add_rule(
        ProxyRule(
            pattern="sts:*", effect=Effect.ALLOW,
            arn_scope=None, region_scope=None,
            note="test allow", origin="manual",
        ),
        actor="test",
    )
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        forward_host_override=None,
        aws_endpoint_resolver=lambda s, r: None,  # cannot resolve
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        import aiohttp
        import json as _json
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://127.0.0.1:{proxy_port}/",
                headers={
                    "host": f"127.0.0.1:{proxy_port}",
                    "authorization": _sigv4_auth_for_sts(),
                    "content-type": "application/x-www-form-urlencoded",
                    "x-amz-date": "20260528T000000Z",
                },
                data=b"Action=GetCallerIdentity&Version=2011-06-15",
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                body = await resp.read()
        # Honest 502 with structured shape — not a hang, not a recursion.
        assert resp.status == 502
        payload = _json.loads(body)
        assert payload["code"] == "UPSTREAM_RESOLUTION_FAILED"
        assert payload["recommended_action"] == "configure_upstream"
        assert "sts" in (payload.get("service") or "")
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()
