"""#516 — /posture + /ui HTTP endpoints on the ibounce mgmt (proxy) port.

Verifies:
  * GET /posture → 200 + valid JSON with the documented field set.
  * GET /ui      → 200 + Content-Type text/html (TUI-equivalent page).

Both endpoints must be registered BEFORE the "/{tail:.*}" catch-all so
they are reachable without being shadowed by the proxy handler.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
from iam_jit.bouncer.store import BouncerStore


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


# ---------------------------------------------------------------------------
# /posture endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_posture_endpoint_returns_200_with_required_fields(tmp_path) -> None:
    """GET /posture → 200 + JSON body with all documented fields.

    Required fields per #516 spec:
      kind, mode, default_mode, active_profile, port, pid, decisions_count,
      started_at, version, healthz_summary.
    """
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/posture") as resp:
                assert resp.status == 200, await resp.text()
                assert resp.headers.get("Content-Type", "").startswith(
                    "application/json"
                )
                body = await resp.json()

        # Documented field set per #516.
        assert body["kind"] == "ibounce"
        assert body["mode"] == "cooperative"
        assert "default_mode" in body
        assert "active_profile" in body
        assert body["port"] == port
        assert isinstance(body["pid"], int)
        assert body["pid"] > 0
        assert isinstance(body["decisions_count"], int)
        assert body["started_at"] is not None
        assert "T" in body["started_at"]  # ISO 8601 shape
        assert "version" in body
        assert isinstance(body["healthz_summary"], dict)
        assert "status" in body["healthz_summary"]
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_posture_endpoint_reflects_configured_mode(tmp_path) -> None:
    """GET /posture ``mode`` field matches the ProxyConfig mode."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/posture") as resp:
                assert resp.status == 200
                body = await resp.json()
        assert body["mode"] == "transparent"
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# /ui endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ui_endpoint_returns_200_html(tmp_path) -> None:
    """GET /ui → 200 + Content-Type text/html.

    The /ui alias must serve the same TUI-equivalent HTML as GET /
    (the audit-stream page from #272) and must NOT be shadowed by the
    AWS proxy catch-all handler.
    """
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/ui") as resp:
                assert resp.status == 200, await resp.text()
                ct = resp.headers.get("Content-Type", "")
                assert "text/html" in ct, f"expected text/html, got {ct!r}"
                body = await resp.text()
        # The page must contain at least minimal HTML markers.
        assert "<html" in body.lower() or "<!doctype" in body.lower(), (
            "Response does not look like an HTML page"
        )
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
