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
    """Post Bounce-suite rename + safe-default reshape (2026-05-17):
    `staging-work` is no longer a built-in (moved to
    tools/community-profiles/); use the shipped `safe-default`
    cross-product default for the healthz name-reporting assertion.
    The pre-reshape names `readonly` + `prod-readonly` still resolve
    via deprecation aliases but the canonical Profile.name is
    `safe-default`."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    profiles = load_profiles()
    safe_default = profiles["safe-default"]
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=safe_default,
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/healthz") as resp:
                body = await resp.json()
        assert body["active_profile"] == "safe-default"
        assert body["mode"] == "transparent"
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# §A102+ / MRR-5 M2 + M3 — chain_initialized + llm_budget /healthz fields.
# State-verification per docs/CONTRIBUTING.md: tests assert the observable
# /healthz JSON body (not function return values).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthz_chain_initialized_false_when_chain_not_ready(
    tmp_path,
) -> None:
    """M2 — fresh state with no audit log configured at all. /healthz
    reports chain_initialized=false so monitoring can detect the
    chain-not-ready state without grepping bouncer logs."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(host="127.0.0.1", port=port)
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz"
            ) as resp:
                body = await resp.json()
        assert "chain_initialized" in body
        assert body["chain_initialized"] is False
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_healthz_includes_chain_initialized_true_when_chain_ready(
    tmp_path,
) -> None:
    """M2 — when ``--audit-chain`` is enabled + the writer is wired,
    /healthz reports chain_initialized=true so cold-start monitoring
    can confirm the chain is ready to stamp events (closes the B3
    gap noted in docs/MRR-5-MONITORING-RUNBOOK.md §4)."""
    audit_log_path = tmp_path / "audit" / "ibounce.jsonl"
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    audit_log_path.write_text("")
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        audit_log_path=str(audit_log_path),
        audit_chain_enabled=True,
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        # Let the audit writer finish start() before probing — chain
        # state is set up during writer construction inside serve().
        await asyncio.sleep(0.2)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz"
            ) as resp:
                body = await resp.json()
        assert body["chain_initialized"] is True, (
            f"audit_chain_enabled=True but chain_initialized={body.get('chain_initialized')!r}; "
            f"audit_export={body.get('audit_export')!r}"
        )
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
        # Clear the global registry between tests so the next test
        # sees a clean slate (matches the test_disk_pressure_circuit_breaker.py
        # convention for register_disk_pressure_state(None)).
        from iam_jit.bouncer.proxy import register_audit_log_writer
        register_audit_log_writer(None)


@pytest.mark.asyncio
async def test_healthz_includes_llm_budget_shape(tmp_path) -> None:
    """M3 — /healthz always includes a top-level llm_budget block
    (always-present convention; external monitoring branches on
    llm_budget.enabled without checking block-presence first)."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(host="127.0.0.1", port=port)
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz"
            ) as resp:
                body = await resp.json()
        assert "llm_budget" in body
        block = body["llm_budget"]
        assert "enabled" in block
        assert isinstance(block["enabled"], bool)
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_healthz_llm_budget_disabled_when_not_configured(
    tmp_path, monkeypatch,
) -> None:
    """M3 — per [[ibounce-honest-positioning]] the block reports
    {"enabled": false} when side-LLM is NOT opted in (the default).
    No silent omission; monitoring sees a deliberate "off" state."""
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(host="127.0.0.1", port=port)
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz"
            ) as resp:
                body = await resp.json()
        assert body["llm_budget"] == {"enabled": False}
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_healthz_llm_budget_under_threshold(
    tmp_path, monkeypatch,
) -> None:
    """M3 — used=50% of cap, approaching_limit=false. State-verification
    pattern: assert OBSERVABLE /healthz JSON body, not return values."""
    from iam_jit.llm import llm_spend_tracker
    llm_spend_tracker.reset_for_tests()
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    monkeypatch.setenv("IAM_JIT_LLM_BUDGET_USD_PER_DAY", "1.00")
    llm_spend_tracker.record_spend(0.50)  # 50% of $1.00 cap
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(host="127.0.0.1", port=port)
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz"
            ) as resp:
                body = await resp.json()
        block = body["llm_budget"]
        assert block["enabled"] is True
        assert block["used_today_usd"] == 0.50
        assert block["cap_per_day_usd"] == 1.00
        assert block["remaining_usd"] == 0.50
        assert block["percent_consumed"] == 50.0
        assert block["approaching_limit"] is False
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
        llm_spend_tracker.reset_for_tests()


@pytest.mark.asyncio
async def test_healthz_llm_budget_approaching_limit_at_80pct(
    tmp_path, monkeypatch,
) -> None:
    """M3 — used=80% of cap → approaching_limit=true. Operator's
    monitor catches the warning state ~20% before the cap actually
    hits, giving room to react before C7 (LLM cost-cap breach) fires."""
    from iam_jit.llm import llm_spend_tracker
    llm_spend_tracker.reset_for_tests()
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    monkeypatch.setenv("IAM_JIT_LLM_BUDGET_USD_PER_DAY", "1.00")
    llm_spend_tracker.record_spend(0.80)  # 80% — at threshold
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(host="127.0.0.1", port=port)
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz"
            ) as resp:
                body = await resp.json()
        block = body["llm_budget"]
        assert block["enabled"] is True
        assert block["used_today_usd"] == 0.80
        assert block["percent_consumed"] == 80.0
        assert block["approaching_limit"] is True, (
            f"used=0.80, cap=1.00, expected approaching_limit=True; got block={block!r}"
        )
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
        llm_spend_tracker.reset_for_tests()
