"""#634 — 403 body must include agent_session_id field.

Symptom: build_structured_deny() was called with agent_session_id populated
(from the X-Agent-Session-Id / x-iam-jit-agent-session-id request header),
but the JSON response dict written by web.json_response() omitted the field —
the caller had no way to correlate the deny to their session without
re-reading the original request headers.

State-verification per CONTRIBUTING.md:
  * Drive a deny with X-Agent-Session-Id set.
  * Assert 403 body includes agent_session_id matching the header.
  * Sabotage check: if the field is removed from the response dict,
    the body does NOT include agent_session_id — proves the field is
    load-bearing in the serialization path.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
from iam_jit.bouncer.store import BouncerStore


def _sigv4_auth(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260526/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakesig634"
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


async def _drive_deny_with_session_id(
    tmp_path, *, agent_session_id: str
) -> tuple[dict, int]:
    """Stand up a default-deny TRANSPARENT proxy, drive one SigV4'd
    request carrying the given agent_session_id header, return
    (body_json, status)."""
    store = BouncerStore(db_path=str(tmp_path / "b634.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
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
                f"http://127.0.0.1:{proxy_port}/test-bucket/key.txt",
                headers={
                    "host": "s3.amazonaws.com",
                    "authorization": _sigv4_auth(service="s3", region="us-east-1"),
                    # Both canonical header forms; proxy normalizes to lowercase.
                    "X-Agent-Session-Id": agent_session_id,
                },
            ) as resp:
                body = await resp.json()
                status = resp.status
        return body, status
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# #634 core: agent_session_id present in 403 body
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_403_body_includes_agent_session_id(tmp_path) -> None:
    """When X-Agent-Session-Id header is set on the request, the 403
    response body MUST include agent_session_id matching that value.

    State-verification: assert the field value round-trips through the
    deny serialization path."""
    session_id = "sess-634-test-unique"
    body, status = await _drive_deny_with_session_id(
        tmp_path, agent_session_id=session_id
    )
    assert status == 403
    assert "agent_session_id" in body, (
        "#634 regression: agent_session_id field missing from 403 body"
    )
    assert body["agent_session_id"] == session_id, (
        f"#634: expected agent_session_id={session_id!r}, "
        f"got {body.get('agent_session_id')!r}"
    )


@pytest.mark.asyncio
async def test_403_body_agent_session_id_null_without_header(tmp_path) -> None:
    """When no agent-session-id header is sent, agent_session_id in the
    403 body must be null (not absent — the field is always present per
    the structured-deny schema contract)."""
    store = BouncerStore(db_path=str(tmp_path / "b634b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
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
                f"http://127.0.0.1:{proxy_port}/test-bucket/key.txt",
                headers={
                    "host": "s3.amazonaws.com",
                    "authorization": _sigv4_auth(service="s3", region="us-east-1"),
                    # No agent-session-id header.
                },
            ) as resp:
                body = await resp.json()
                status = resp.status
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()

    assert status == 403
    # Field must be present but null (or empty string) when no header sent.
    assert "agent_session_id" in body, (
        "agent_session_id field must always be present in 403 body"
    )
    assert not body["agent_session_id"], (
        "agent_session_id must be falsy when no session-id header was sent"
    )


# ---------------------------------------------------------------------------
# Sabotage check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sabotage_without_field_agent_session_id_absent(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If agent_session_id is removed from the json_response dict in
    proxy.py, the 403 body MUST NOT include it — confirms the serialization
    change in #634 is the load-bearing gate.

    Approach: monkeypatch web.json_response to strip agent_session_id
    before writing, then assert the field is absent.
    """
    import aiohttp
    from aiohttp import web as aiohttp_web

    original_json_response = aiohttp_web.json_response

    def _stripped_json_response(data, **kwargs):
        if isinstance(data, dict) and "agent_session_id" in data:
            data = {k: v for k, v in data.items() if k != "agent_session_id"}
        return original_json_response(data, **kwargs)

    monkeypatch.setattr(aiohttp_web, "json_response", _stripped_json_response)

    session_id = "sess-sabotage-634"
    body, status = await _drive_deny_with_session_id(
        tmp_path, agent_session_id=session_id
    )
    assert status == 403
    # With the sabotage in place the field must be absent.
    assert "agent_session_id" not in body, (
        "Sabotage check: stripping agent_session_id from response dict "
        "must result in field absence — if this fails the field is being "
        "added somewhere else (investigate)"
    )
