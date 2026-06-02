"""End-to-end denial-receipt wiring through serve() — #731 / BUILD-10.

Per [[uat-tests-setup-end-to-end]] the UAT shape is:
  (a) trigger a real DENY through the live proxy
  (b) confirm the 403 carries a signed receipt that verifies
  (c) restart the bouncer
  (d) replay the receipt's nonce against the persistent store → REJECTED

This test exercises the full serve() path (config field → ReceiptSigner
construction → 403 body attach → persistent SQLite nonce store) rather
than the signer in isolation (that's tests/test_denial_receipts.py), so
a future regression in proxy.py wiring is caught at PR time per the
docs/CONTRIBUTING.md state-verification convention.
"""

from __future__ import annotations

import asyncio
import pathlib
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    register_receipt_signer,
    serve,
)
from iam_jit.bouncer.store import BouncerStore
from iam_jit.receipts import DenialReceipt, open_nonce_store, verify_receipt
from iam_jit.receipts.nonce_store import DEFAULT_NONCE_DB_NAME


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


def _sigv4_auth_header(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260603/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakefakefake"
    )


def _config(tmp_path: pathlib.Path, port: int) -> tuple[ProxyConfig, pathlib.Path]:
    audit_log_path = tmp_path / "audit" / "ibounce.jsonl"
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    audit_log_path.write_text("")
    cfg = ProxyConfig(
        host="127.0.0.1",
        port=port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        audit_log_path=str(audit_log_path),
        deny_receipts_enabled=True,
        deny_receipt_keypair_dir=str(tmp_path / "keys"),
    )
    return cfg, audit_log_path.parent


@pytest.mark.asyncio
async def test_deny_403_carries_signed_receipt_then_replay_rejected_after_restart(
    tmp_path: pathlib.Path,
) -> None:
    import aiohttp

    port = _free_port()
    cfg, log_dir = _config(tmp_path, port)
    nonce_db = log_dir / DEFAULT_NONCE_DB_NAME
    store = BouncerStore(db_path=str(tmp_path / "b.db"))

    receipt_dict = None
    # ---- (a)+(b): boot, trigger DENY, capture + verify the receipt ----
    task = asyncio.create_task(serve(cfg, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        await asyncio.sleep(0.2)
        async with aiohttp.ClientSession() as session:
            # A classifiable SigV4 S3 request under default-DENY +
            # transparent mode → 403 deny.
            async with session.get(
                f"http://127.0.0.1:{port}/some-bucket/key.txt",
                headers={
                    "host": "s3.us-east-1.amazonaws.com",
                    "authorization": _sigv4_auth_header(
                        service="s3", region="us-east-1"
                    ),
                    "x-amz-date": "20260603T000000Z",
                    "X-Agent-Session-Id": "sess-xyz",
                },
            ) as resp:
                assert resp.status == 403, await resp.text()
                body = await resp.json()
                assert body["decision_verdict"] == "deny"
                receipt_dict = body.get("denial_receipt")
                assert receipt_dict is not None, (
                    "403 body must carry a denial_receipt when receipts "
                    f"are enabled; body keys={list(body.keys())}"
                )
                # Receipt's deny_id ties to the structured-deny event id.
                assert receipt_dict["deny_id"] == body["deny_event_id"]
                assert receipt_dict["verdict"] == "deny"
                assert receipt_dict["agent_session"] == "sess-xyz"
                assert "s3" in receipt_dict["action"].lower()
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
        register_receipt_signer(None)

    assert receipt_dict is not None
    receipt = DenialReceipt.from_dict(receipt_dict)
    ok, reason, key_trust = verify_receipt(
        receipt, keypair_dir=str(tmp_path / "keys"),
    )
    assert ok, f"receipt from live 403 must verify: {reason}"
    # The signing keypair lives on this host (tmp_path/keys) so the
    # verifier auto-pins to the LOCAL key — issuer trust established.
    assert key_trust == "local", key_trust

    # The nonce must have been persisted to the on-disk SQLite store.
    assert nonce_db.is_file(), "persistent nonce store must exist on disk"

    # ---- (c) RESTART: a fresh nonce-store object on the same file ----
    # (Equivalent to a process restart — the durable store reloads the
    # nonce minted by the now-dead serve() instance.)
    restarted_store = open_nonce_store(str(nonce_db))

    # ---- (d) replay the receipt's nonce → first consume legit, second
    # consume = REPLAY, proving cross-restart replay detection. ----
    first = restarted_store.check_and_consume(receipt.nonce)
    assert first.known is True, (
        "after restart the durable store must still recognise the nonce "
        "minted before the restart"
    )
    second = restarted_store.check_and_consume(receipt.nonce)
    assert second.replay is True, (
        "replaying the same receipt nonce after a restart MUST be detected "
        "— this is the headline replay-resistance property"
    )


@pytest.mark.asyncio
async def test_deny_receipts_disabled_no_receipt_in_body(
    tmp_path: pathlib.Path,
) -> None:
    """With --no-deny-receipts the 403 still fires but carries a null
    denial_receipt (fail-soft / opt-out path)."""
    import aiohttp

    port = _free_port()
    cfg, _ = _config(tmp_path, port)
    cfg = ProxyConfig(
        **{**cfg.__dict__, "deny_receipts_enabled": False}
    )
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    task = asyncio.create_task(serve(cfg, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        await asyncio.sleep(0.2)
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/some-bucket/key.txt",
                headers={
                    "host": "s3.us-east-1.amazonaws.com",
                    "authorization": _sigv4_auth_header(
                        service="s3", region="us-east-1"
                    ),
                    "x-amz-date": "20260603T000000Z",
                },
            ) as resp:
                assert resp.status == 403
                body = await resp.json()
                assert body["decision_verdict"] == "deny"
                assert body.get("denial_receipt") is None
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
        register_receipt_signer(None)
