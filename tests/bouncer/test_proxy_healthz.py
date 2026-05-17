"""Tests for the /healthz liveness endpoint on the bouncer proxy.

The endpoint exists so monit / k8s liveness probes / supervisor
scripts can poll the proxy without polluting the audit log. Two
critical properties:

1. /healthz returns 200 + JSON with status/mode/profile/decisions_count
2. /healthz does NOT generate an audit-decision row

Mirrors kbouncer's healthz test shape for cross-product symmetry.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.profiles import load_profiles
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


@pytest.mark.asyncio
async def test_healthz_returns_200_with_status_payload(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/healthz") as resp:
                assert resp.status == 200
                assert resp.headers.get("Content-Type", "").startswith("application/json")
                body = await resp.json()
        assert body["status"] == "ok"
        assert body["mode"] == "cooperative"
        assert body["default_policy"] == "deny"
        assert body["active_profile"] == ""
        assert body["decisions_count"] == 0
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_healthz_does_not_write_audit_row(tmp_path) -> None:
    """The audit log is reserved for proxy decisions, not liveness
    probes. A monitoring rig polling /healthz every 5 seconds would
    otherwise drown the operator's `logs tail` view in noise."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(host="127.0.0.1", port=port)
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            for _ in range(5):
                async with session.get(f"http://127.0.0.1:{port}/healthz") as resp:
                    await resp.read()
        assert store.count_decisions() == 0, \
            "/healthz must not write to the decisions audit log"
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_healthz_reports_active_profile_name(tmp_path) -> None:
    """Post Bounce-suite rename (2026-05-17): `staging-work` is no
    longer a built-in (moved to tools/community-profiles/); use the
    shipped `readonly` cross-product default for the healthz
    name-reporting assertion."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    profiles = load_profiles()
    readonly = profiles["readonly"]
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=readonly,
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/healthz") as resp:
                body = await resp.json()
        assert body["active_profile"] == "readonly"
        assert body["mode"] == "transparent"
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
