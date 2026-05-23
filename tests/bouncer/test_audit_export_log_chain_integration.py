"""Integration: AuditLogWriter stamps chain + emits signed manifests.

Covers the wiring slice that connects #427/§A66 + #428/§A67 into
the writer. The unit-level chain/manifest/retention behavior is
covered in the focused test_audit_export_{chain,manifest,retention}
modules; this file exercises end-to-end through the AuditLogWriter.
"""

from __future__ import annotations

import asyncio
import json
import pathlib

import pytest

from iam_jit.bouncer.audit_export import (
    CHAIN_FIELD,
    AuditLogWriter,
    ChainState,
    ManifestSigner,
    RetentionPolicy,
    REDACTION_PLACEHOLDER,
    retention_policy_for_framework,
    verify_chain_jsonl,
)
from iam_jit.bouncer.audit_export.retention import FRAMEWORK_GDPR


@pytest.mark.asyncio
async def test_writer_stamps_chain_on_every_event(tmp_path):
    """Wired chain_state results in every written event carrying an
    unmapped.iam_jit.audit_chain block."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    writer = AuditLogWriter(
        path=log_dir / "audit.jsonl",
        chain_state=state,
    )
    await writer.start()
    try:
        for i in range(3):
            writer.write({
                "metadata": {"version": "1.1.0", "product": {"name": "ibounce"}},
                "class_uid": 6003,
                "activity_name": "Read",
                "time": 1_700_000_000_000 + i,
                "unmapped": {"iam_jit": {"verdict": "ALLOW"}},
            })
        # Drain.
        for _ in range(30):
            if writer.status()["total_events"] >= 3:
                break
            await asyncio.sleep(0.01)
    finally:
        await writer.stop()
    raw = (log_dir / "audit.jsonl").read_text().splitlines()
    assert len(raw) == 3
    for line in raw:
        event = json.loads(line)
        assert CHAIN_FIELD in event["unmapped"]["iam_jit"]
        block = event["unmapped"]["iam_jit"][CHAIN_FIELD]
        assert "seq" in block and "hash" in block and "prev_hash" in block
    # Now verify the chain holds.
    result = verify_chain_jsonl(log_dir)
    assert result.ok, result.inconsistencies
    assert result.events_checked == 3


@pytest.mark.asyncio
async def test_writer_emits_manifest_at_interval(tmp_path):
    """ManifestSigner wired into the writer emits a manifest every
    `interval` events."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    keypair_dir = tmp_path / "keys"
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=3,
        keypair_dir=str(keypair_dir),
    )
    captured: list = []
    writer = AuditLogWriter(
        path=log_dir / "audit.jsonl",
        chain_state=state,
        manifest_signer=signer,
        on_manifest=captured.append,
    )
    await writer.start()
    try:
        for i in range(5):
            writer.write({
                "metadata": {"version": "1.1.0", "product": {"name": "ibounce"}},
                "class_uid": 6003,
                "activity_name": "Read",
                "time": 1_700_000_000_000 + i,
                "unmapped": {"iam_jit": {"verdict": "ALLOW"}},
            })
        for _ in range(40):
            if writer.status()["total_events"] >= 5:
                break
            await asyncio.sleep(0.01)
    finally:
        await writer.stop()
    # One manifest emitted (at seq 2, covering [0, 2]). Subsequent
    # events advance the chain; no second manifest until seq 5.
    assert signer.manifests_emitted == 1
    assert captured[0].seq_start == 0
    assert captured[0].seq_end == 2
    # Writer status surfaces the chain head.
    status = writer.status()
    assert status["chain"]["configured"] is True
    assert status["chain"]["head_seq"] == 4
    assert status["manifest"]["manifests_emitted"] == 1


@pytest.mark.asyncio
async def test_writer_runs_pii_redaction_at_write_time(tmp_path):
    """Wired retention policy with gdpr_pii_purge=True scrubs PII
    BEFORE the event lands on disk."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    policy = retention_policy_for_framework(FRAMEWORK_GDPR)
    writer = AuditLogWriter(
        path=log_dir / "audit.jsonl",
        retention_policy=policy,
    )
    await writer.start()
    try:
        writer.write({
            "metadata": {"version": "1.1.0"},
            "unmapped": {"iam_jit": {"creds": {
                "key": "AKIAIOSFODNN7EXAMPLE",
                "auth": "Bearer abc123.def456.xyz_789",
            }}},
        })
        for _ in range(30):
            if writer.status()["total_events"] >= 1:
                break
            await asyncio.sleep(0.01)
    finally:
        await writer.stop()
    raw = (log_dir / "audit.jsonl").read_text()
    assert "AKIAIOSFODNN7EXAMPLE" not in raw
    assert "Bearer abc123" not in raw
    assert REDACTION_PLACEHOLDER.format(kind="aws_access_key_id") in raw
    assert REDACTION_PLACEHOLDER.format(kind="bearer_token") in raw
    # Retention block surfaces in status().
    status = writer.status()
    assert status["retention"]["configured"] is True
    assert status["retention"]["compliance"] == "gdpr"
    assert status["retention"]["gdpr_pii_purge"] is True
