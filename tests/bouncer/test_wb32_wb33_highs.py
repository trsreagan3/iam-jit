"""Tests for the WB32 + WB33 HIGH closures (commit follow-up).

Covers:
- HIGH-32-01: unclassifiable requests now write to the audit log
- HIGH-32-02 (also HIGH-33-02): /healthz pause-reason sanitization
- HIGH-32-05: pause-lookup error counter surfaces on /healthz
- HIGH-33-03: 'always' prompt-answer refused when arn is null
- MED-33-06: pause start strips control chars + caps reason length
"""

from __future__ import annotations

import asyncio
import socket
from unittest import mock

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    _bump_pause_lookup_error_counter,
    _pause_lookup_error_count,
    _reset_pause_lookup_error_counter_for_tests,
    evaluate_request,
    serve,
)
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260517/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fake"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


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


# ---------------------------------------------------------------------------
# HIGH-32-01 — unclassifiable requests write to the audit log
# ---------------------------------------------------------------------------


def test_unclassifiable_request_writes_audit_row(tmp_path) -> None:
    """Before this fix: an unclassifiable request (no SigV4 auth)
    returned a synthetic DENY without persisting anything to the
    audit log. Operators running `bouncer logs tail` saw nothing
    for probe traffic / scanner traffic / misconfigured clients."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    assert store.count_decisions() == 0
    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/",
        headers={"host": "s3.us-east-1.amazonaws.com"},  # NO authorization
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
    )
    assert obs.decision_verdict == "deny"
    assert "unclassifiable" in obs.decision_reason
    # NEW: this should now write an audit row
    assert store.count_decisions() == 1
    store.close()


# ---------------------------------------------------------------------------
# HIGH-32-02 / HIGH-33-02 — /healthz reason sanitization
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthz_strips_control_chars_from_pause_reason(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    # Pause with a malicious reason that contains a newline + NULL byte.
    # MED-33-06 strips them at start_pause; this test confirms /healthz
    # also strips them on output (defense in depth).
    store.start_pause(
        duration_seconds=600,
        reason="legit\x00\nFAKE_LINE: pwned\nmore",
        started_by="t",
    )
    port = _free_port()
    config = ProxyConfig(host="127.0.0.1", port=port)
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/healthz") as resp:
                body = await resp.json()
        reason = body["pause"]["reason"]
        # No newlines / NULL bytes that could break monitor parsing
        assert "\n" not in reason
        assert "\x00" not in reason
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# HIGH-32-05 — pause-lookup error counter surfaces on /healthz
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pause_lookup_errors_surface_on_healthz(tmp_path) -> None:
    """If get_active_pause raises (DB corruption, schema drift,
    storage full), the proxy silently enforces through what should
    be a bypass window. The counter exposed on /healthz lets
    monitors alert."""
    _reset_pause_lookup_error_counter_for_tests()
    _bump_pause_lookup_error_counter()
    _bump_pause_lookup_error_counter()
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(host="127.0.0.1", port=port)
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/healthz") as resp:
                body = await resp.json()
        assert body["pause_lookup_errors_total"] == 2
        # status should flip to degraded when count > 0
        assert body["status"] == "degraded"
    finally:
        _reset_pause_lookup_error_counter_for_tests()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


def test_pause_lookup_counter_starts_at_zero() -> None:
    _reset_pause_lookup_error_counter_for_tests()
    assert _pause_lookup_error_count() == 0


# ---------------------------------------------------------------------------
# HIGH-33-03 — 'always' answer refused when arn is null
# ---------------------------------------------------------------------------


def test_prompts_answer_always_refused_when_arn_is_null(tmp_path) -> None:
    """Without an ARN, 'always' would write a global ALLOW with
    arn_scope=None — matches ANY arn for that action, far broader
    than the operator likely intends."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    pid = store.add_pending_prompt(
        decision_id=99, service="s3", action="ListBuckets",
        arn=None, region="us-east-1", deny_reason="test",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["prompts", "answer", str(pid), "--kind", "always",
         "--db", str(tmp_path / "b.db")],
        catch_exceptions=False,
    )
    assert result.exit_code == 2
    assert "no ARN scope" in result.output
    assert "HIGH-33-03" in result.output
    store.close()


def test_prompts_answer_always_works_when_arn_present(tmp_path) -> None:
    """With an ARN, 'always' should still succeed."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    pid = store.add_pending_prompt(
        decision_id=100, service="s3", action="GetObject",
        arn="arn:aws:s3:::my-bucket/file.txt",
        region="us-east-1", deny_reason="test",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["prompts", "answer", str(pid), "--kind", "always",
         "--db", str(tmp_path / "b.db")],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "answered" in result.output
    store.close()


# ---------------------------------------------------------------------------
# MED-33-06 — pause reason is sanitized at store level
# ---------------------------------------------------------------------------


def test_start_pause_strips_control_chars_from_reason(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.start_pause(
        duration_seconds=60,
        reason="ok\nBAD: x\x00\x01end",
        started_by="t",
    )
    active = store.get_active_pause()
    assert active is not None
    # Control chars stripped; readable text preserved
    assert "\n" not in active["reason"]
    assert "\x00" not in active["reason"]
    assert "\x01" not in active["reason"]
    assert "ok" in active["reason"]
    assert "end" in active["reason"]
    store.close()


def test_start_pause_caps_reason_length(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    huge = "x" * 5000
    store.start_pause(
        duration_seconds=60, reason=huge, started_by="t",
    )
    active = store.get_active_pause()
    # Capped at 500 chars
    assert len(active["reason"]) <= 500
    store.close()
