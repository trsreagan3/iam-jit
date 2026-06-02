"""#725 — smoke tests for proxy.py wiring of the cost circuit breaker.

The module's own unit tests (tests/circuit_breaker/) exercise trip /
reset / config in isolation. These tests verify the OBSERVABLE
end-to-end behaviour through serve():

* enabled + block mode + a runaway session → once the breaker trips,
  the proxy tightens ALLOW→DENY (403) for further calls, the 403 body
  carries deny_source_classified = cost_circuit_breaker, and a
  COST_CIRCUIT_TRIPPED OCSF event lands on the audit-log channel.
* default-off → breaker not installed; /healthz reports
  {"enabled": false}; a flood of calls never 403s on the breaker.

Per [[ibounce-honest-positioning]] these assert the actual on-wire +
on-disk artefacts, not status-string claims.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    register_audit_log_writer,
    serve,
)
from iam_jit.bouncer.store import BouncerStore
from iam_jit.circuit_breaker import (
    register_cost_circuit_breaker,
    reset_for_tests as reset_breaker_for_tests,
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260523/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fake"
    )


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


async def _drive(
    proxy_port: int,
    *,
    service: str = "sts",
    region: str = "us-east-1",
    path: str = "/?Action=GetCallerIdentity&Version=2011-06-15",
    session_id: str = "runaway-session-1",
):
    import aiohttp
    session = aiohttp.ClientSession()
    try:
        try:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}{path}",
                headers={
                    "host": f"{service}.{region}.amazonaws.com",
                    "authorization": _sigv4(service=service, region=region),
                    "x-amz-date": "20260523T000000Z",
                    "user-agent": "cost-breaker-smoke",
                    "x-agent-session-id": session_id,
                },
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                body = await resp.read()
                return resp.status, body
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return 0, b""
    finally:
        await session.close()


async def _fetch_healthz(proxy_port: int) -> dict:
    import aiohttp
    session = aiohttp.ClientSession()
    try:
        async with session.get(
            f"http://127.0.0.1:{proxy_port}/healthz",
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            return json.loads(await resp.read())
    finally:
        await session.close()


@pytest.fixture
def restore_breaker():
    yield
    register_audit_log_writer(None)
    reset_breaker_for_tests()


@pytest.mark.asyncio
async def test_block_mode_trips_and_tightens_allow_to_deny(
    tmp_path, restore_breaker,
):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.TRANSPARENT,
        # Default-allow so the floor returns ALLOW; the breaker tightens
        # to DENY once tripped. Isolates the breaker wiring.
        default_policy=DefaultPolicy.ALLOW,
        audit_log_path=str(log_path),
        # Tiny cap so a couple of driven requests trip it.
        cost_circuit_breaker={
            "enabled": True,
            "mode": "block",
            "max_calls_per_window": 2,
            "max_usd_per_window": 0,  # disable cost dimension
            "window": "1h",
        },
    )

    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)

        # Healthz reports the breaker enabled.
        hz = await _fetch_healthz(proxy_port)
        assert hz["cost_circuit_breaker"]["enabled"] is True
        assert hz["cost_circuit_breaker"]["usd_is_estimated"] is True

        # First 2 calls: under cap → ALLOW (proxy forwards; upstream is
        # unreachable in the test so status is 0/502-ish, but crucially
        # NOT a breaker 403). The 2nd call crosses the cap + trips.
        for _ in range(2):
            await _drive(proxy_port)

        # 3rd call: breaker is tripped → proxy 403s with the
        # cost_circuit_breaker deny source.
        status, body = await _drive(proxy_port)
        assert status == 403, (
            f"#725 — breaker tripped but proxy did NOT tighten to DENY; "
            f"HTTP {status}, body={body[:200]!r}"
        )
        payload = json.loads(body.decode("utf-8"))
        assert payload.get("caught_by_bouncer") == "ibounce", payload
        assert payload.get("deny_source_classified") == \
            "cost_circuit_breaker", payload

        # COST_CIRCUIT_TRIPPED event landed on the audit-log channel.
        deadline = asyncio.get_event_loop().time() + 5.0
        tripped_events = []
        while asyncio.get_event_loop().time() < deadline:
            if log_path.is_file():
                for ln in log_path.read_text().splitlines():
                    if not ln.strip():
                        continue
                    ev = json.loads(ln)
                    if (
                        ev.get("unmapped", {}).get("iam_jit", {}).get("event_type")
                        == "COST_CIRCUIT_TRIPPED"
                    ):
                        tripped_events.append(ev)
                if tripped_events:
                    break
            await asyncio.sleep(0.05)
        assert tripped_events, "no COST_CIRCUIT_TRIPPED event on audit channel"
        assert tripped_events[0]["severity_id"] == 4  # High

        # Healthz now shows a tripped session.
        hz = await _fetch_healthz(proxy_port)
        assert hz["cost_circuit_breaker"]["tripped_sessions_count"] >= 1
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_default_off_breaker_not_installed(tmp_path, restore_breaker):
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.ALLOW,
        # cost_circuit_breaker left at default None → disabled.
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        hz = await _fetch_healthz(proxy_port)
        assert hz["cost_circuit_breaker"] == {"enabled": False}

        # A flood of calls never produces a BREAKER 403. The proxy
        # forwards to real STS (default-allow) which itself returns a
        # 403 XML SignatureDoesNotMatch error — that's an UPSTREAM 403,
        # not a breaker deny. We only fail if a breaker-shaped JSON deny
        # appears (which it must not, since the breaker is uninstalled).
        for _ in range(10):
            status, body = await _drive(proxy_port)
            if status == 403:
                try:
                    payload = json.loads(body.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue  # upstream XML error, not a breaker deny
                assert payload.get("deny_source_classified") != \
                    "cost_circuit_breaker", payload
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()
