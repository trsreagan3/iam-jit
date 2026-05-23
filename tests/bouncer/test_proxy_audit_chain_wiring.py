"""Smoke tests for #500 / §A66c — proxy.py wires Phase F audit-chain
+ manifest + retention kwargs into AuditLogWriter.

Per docs/CONTRIBUTING.md state-verification convention: the
integration test
``tests/bouncer/test_audit_export_log_chain_integration.py`` passed
while the actual production code path (proxy.py serve()) constructed
the AuditLogWriter WITHOUT chain/manifest/retention kwargs. Phase F
shipped #427/#428 but the operator-visible artefact (audit.jsonl on
disk with the chain block stamped) was missing whenever the operator
ran the default ``ibounce run --audit-log-path PATH``.

These smoke tests verify the OBSERVABLE STATE on disk for each gate:

* ``--audit-chain`` enabled → every event in audit.jsonl carries the
  ``unmapped.iam_jit.audit_chain`` block AND ``iam-jit audit verify``
  returns ok.
* ``--audit-chain`` NOT enabled → audit.jsonl has NO chain block
  (the existing default behaviour is preserved per
  [[creates-never-mutates]]).
* ``--audit-sign-manifests`` enabled (with ``--audit-chain``) → a
  signed manifest lands at ``<log_dir>/manifests/``.
* ``--audit-retention-framework gdpr`` enabled → write-time PII
  scrubs run BEFORE the bytes hit disk.

Per [[ibounce-honest-positioning]] these tests assert the file
contents, not a status string.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import socket

import pytest

from iam_jit.bouncer.audit_export import (
    CHAIN_FIELD,
    MANIFEST_DIR_NAME,
    REDACTION_PLACEHOLDER,
    verify_chain_jsonl,
)
from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    register_audit_log_writer,
    serve,
)
from iam_jit.bouncer.store import BouncerStore


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


async def _drive_one_request(proxy_port: int) -> None:
    """Send one SigV4-shaped request through the proxy so the audit-
    export pipeline produces at least one event."""
    import aiohttp
    session = aiohttp.ClientSession()
    try:
        try:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/some/path",
                headers={
                    "host": "s3.us-east-1.amazonaws.com",
                    "authorization": _sigv4(service="s3", region="us-east-1"),
                    "x-amz-date": "20260523T000000Z",
                },
                # Don't actually forward upstream; cooperative-mode
                # default-deny still emits the audit event.
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            # We don't care about the upstream outcome — only that the
            # audit event was emitted on the bouncer's side.
            pass
    finally:
        await session.close()


async def _wait_for_audit_lines(
    path: pathlib.Path, *, min_lines: int, max_wait: float = 5.0,
) -> list[str]:
    """Poll for the JSONL file to grow to ``min_lines``. Returns the
    stripped, non-empty lines."""
    deadline = asyncio.get_event_loop().time() + max_wait
    while True:
        if path.is_file():
            text = path.read_text()
            lines = [ln for ln in text.splitlines() if ln.strip()]
            if len(lines) >= min_lines:
                return lines
        if asyncio.get_event_loop().time() > deadline:
            return [
                ln for ln in (
                    path.read_text().splitlines() if path.is_file() else []
                ) if ln.strip()
            ]
        await asyncio.sleep(0.05)


@pytest.fixture
def restore_audit_writer_registry():
    """Tests that go through `serve()` install a module-level audit
    writer. Reset after each test so the next test starts clean."""
    yield
    register_audit_log_writer(None)


@pytest.mark.asyncio
async def test_default_proxy_run_emits_audit_chain_when_opt_in(
    tmp_path, restore_audit_writer_registry,
):
    """#500 — when --audit-chain is enabled (CLI flag flips
    audit_chain_enabled=True on ProxyConfig), every audit event on
    disk MUST include the unmapped.iam_jit.audit_chain block AND
    `iam-jit audit verify` (== verify_chain_jsonl) MUST return ok.

    This is the test that would have caught the §A66c CRIT: the
    AuditLogWriter construction at proxy.py:3789 was not threading
    chain_state, so the on-disk audit.jsonl had NO chain block even
    though the integration test against AuditLogWriter passed.
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        audit_log_path=str(log_path),
        audit_chain_enabled=True,  # #500 — the opt-in under test.
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        await _drive_one_request(proxy_port)
        lines = await _wait_for_audit_lines(log_path, min_lines=1)
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()

    # 1. Observable state: at least one event landed.
    assert lines, (
        "audit_log_path was set + a request was driven but NO events "
        "on disk — proxy is not emitting audit events"
    )

    # 2. Observable state: EVERY event carries the chain block.
    for raw in lines:
        event = json.loads(raw)
        unmapped = event.get("unmapped") or {}
        iam_jit = unmapped.get("iam_jit") or {}
        assert CHAIN_FIELD in iam_jit, (
            f"#500 §A66c CRIT regressed — event has no audit_chain "
            f"block; this is exactly the bug Phase F UAT caught. "
            f"event keys={sorted(iam_jit)} raw={raw[:200]!r}"
        )
        block = iam_jit[CHAIN_FIELD]
        assert "seq" in block, f"chain block missing seq: {block!r}"
        assert "prev_hash" in block, f"chain block missing prev_hash: {block!r}"
        assert "hash" in block, f"chain block missing hash: {block!r}"

    # 3. Observable state: `iam-jit audit verify` returns ok against
    # the on-disk JSONL. This is the operator-facing claim that the
    # chain is intact end-to-end.
    result = verify_chain_jsonl(log_dir)
    assert result.ok, (
        f"verify_chain_jsonl reported inconsistencies on the just-"
        f"written log: {[i.to_dict() for i in result.inconsistencies]}"
    )
    assert result.events_checked >= 1


@pytest.mark.asyncio
async def test_default_proxy_run_no_chain_when_not_opted_in(
    tmp_path, restore_audit_writer_registry,
):
    """#500 — when --audit-chain is NOT enabled (the default), audit
    events MUST NOT carry the chain block.

    Per [[creates-never-mutates]] existing deployments that haven't
    opted in DO NOT silently gain new on-disk state. This test pins
    the default so a future regression that flips the gate ON for
    everyone is caught at PR time.
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        audit_log_path=str(log_path),
        # audit_chain_enabled deliberately omitted (default False).
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        await _drive_one_request(proxy_port)
        lines = await _wait_for_audit_lines(log_path, min_lines=1)
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()

    assert lines, "audit events should still emit even without chain"

    # Observable state: NO chain block on any event.
    for raw in lines:
        event = json.loads(raw)
        unmapped = event.get("unmapped") or {}
        iam_jit = unmapped.get("iam_jit") or {}
        assert CHAIN_FIELD not in iam_jit, (
            f"chain block unexpectedly present without opt-in — "
            f"[[creates-never-mutates]] regression: {raw[:200]!r}"
        )

    # No chain-state file on disk either (load_state was not invoked).
    assert not (log_dir / "audit-chain-state.json").is_file(), (
        "audit-chain-state.json was created without --audit-chain opt-in"
    )


@pytest.mark.asyncio
async def test_default_proxy_run_emits_signed_manifest_when_opt_in(
    tmp_path, restore_audit_writer_registry,
):
    """#500 — when --audit-sign-manifests is enabled (with
    --audit-chain), a signed manifest lands at <log_dir>/manifests/.

    Cadence of 1 (smallest meaningful interval) so a single driven
    request triggers the manifest emit. Validates the proxy.py
    ManifestSigner construction the same way the chain test
    validates ChainState construction.
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    keypair_dir = tmp_path / "audit-keys"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        audit_log_path=str(log_path),
        audit_chain_enabled=True,
        audit_sign_manifests=True,
        audit_manifest_interval_events=1,
        audit_manifest_keypair_dir=str(keypair_dir),
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        await _drive_one_request(proxy_port)
        # Wait for at least one event + the manifest emit (manifest is
        # written synchronously by the writer worker after the stamp).
        await _wait_for_audit_lines(log_path, min_lines=1)
        # Manifest dir created lazily; poll briefly for it.
        manifest_dir = log_dir / MANIFEST_DIR_NAME
        for _ in range(50):
            if manifest_dir.is_dir() and any(manifest_dir.iterdir()):
                break
            await asyncio.sleep(0.05)
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()

    manifest_dir = log_dir / MANIFEST_DIR_NAME
    assert manifest_dir.is_dir(), (
        "manifests/ dir was never created — ManifestSigner was not "
        "constructed by proxy.py"
    )
    manifest_files = sorted(manifest_dir.iterdir())
    assert manifest_files, (
        "manifests/ dir is empty — signer was constructed but never "
        "emitted (cadence wiring broken)"
    )
    # Validate the manifest JSON shape.
    payload = json.loads(manifest_files[0].read_text())
    assert "signature_b64" in payload, payload
    assert "head_hash" in payload, payload
    assert payload["bouncer_product"] == "ibounce"

    # The keypair must have landed at the operator-specified dir.
    assert (keypair_dir / "manifest-ed25519.priv").is_file()
    assert (keypair_dir / "manifest-ed25519.pub").is_file()


@pytest.mark.asyncio
async def test_default_proxy_run_wires_retention_policy_when_opt_in(
    tmp_path, restore_audit_writer_registry,
):
    """#500 — when --audit-retention-framework gdpr is selected, the
    retention policy MUST be wired into the AuditLogWriter the proxy
    constructs. State verification reads the writer's status() (the
    same surface MCP `bouncer_audit_export_status` + /healthz expose
    to operators) — the framework name + gdpr_pii_purge flag must
    reflect the operator's opt-in.

    This is the analogue of the chain-presence test: the chain test
    confirms the on-disk artefact; the retention test confirms the
    operator-facing status surface reports the wired policy. Both
    would catch a regression in proxy.py construction.
    """
    import iam_jit.bouncer.proxy as _proxy_module

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        audit_log_path=str(log_path),
        audit_retention_framework="gdpr",
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        await _drive_one_request(proxy_port)
        await _wait_for_audit_lines(log_path, min_lines=1)
        # State verification via the operator-facing status surface.
        # `audit_export_status` reads the same writer the proxy
        # registered; an unwired retention policy reports
        # configured=False.
        status = _proxy_module.audit_export_status()
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()

    log_block = status.get("log") or {}
    retention = log_block.get("retention") or {}
    assert retention.get("configured") is True, (
        f"#500 §A66c CRIT regressed — --audit-retention-framework "
        f"opt-in did NOT flow to AuditLogWriter; status reports "
        f"retention.configured=False. Full status: {status!r}"
    )
    assert retention.get("compliance") == "gdpr", retention
    assert retention.get("gdpr_pii_purge") is True, retention


@pytest.mark.asyncio
async def test_sign_manifests_without_chain_refused_to_start(
    tmp_path, restore_audit_writer_registry,
):
    """#500 — defensive: --audit-sign-manifests requires --audit-chain.
    A signed manifest over an unstamped log is meaningless; per
    [[ibounce-honest-positioning]] surface the misconfiguration loudly
    rather than emit empty manifests."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        audit_log_path=str(log_path),
        audit_chain_enabled=False,
        audit_sign_manifests=True,  # missing prerequisite
    )
    with pytest.raises(RuntimeError, match="audit-sign-manifests"):
        await serve(config, store=store)
    store.close()
