# ADOPT-7 / #721 — END-TO-END: the bouncer audit redaction path applies
# the operator's custom-PII entities (not just the `iam-jit pii` CLI).
"""These assert the wiring completed in the harden pass: the custom-PII
layer is threaded into the REAL ``redact_event_pii`` callers — the async
audit-log worker (``log.py``) and the offline archive scrub
(``retention._scrub_archive_pii``) — via the
``IAM_JIT_CUSTOM_PII_CONFIG`` env plumb + cached
``get_audit_extra_redactor``.

Default-off is the headline: with NO env var, a custom entity (EMP-12345)
flows through the SAME persisted-redaction path UN-redacted by the custom
layer. With the env var set + redaction enabled, it is redacted in the
PERSISTED event.

The presidio-requiring cases are importorskip-guarded so CI without the
optional extra skips cleanly. The default-off + cap cases are
dependency-free.
"""

from __future__ import annotations

import asyncio
import dataclasses
import gzip
import json
import os
import pathlib

import pytest

from iam_jit.bouncer.audit_export.retention import (
    _scrub_archive_pii,
    default_policy,
)
from iam_jit.pii import bouncer_hook


def _gdpr_policy():
    # default_policy() is PCI (gdpr_pii_purge False); flip the flag so the
    # archive scrub actually redacts.
    return dataclasses.replace(default_policy(), gdpr_pii_purge=True)


@pytest.fixture(autouse=True)
def _clean_pii_cache(monkeypatch):
    """Each test starts with the redactor cache cleared + the env var
    unset, so cross-test state can't leak through the module cache."""
    monkeypatch.delenv(bouncer_hook.CONFIG_ENV_VAR, raising=False)
    bouncer_hook._reset_cache_for_tests()
    yield
    bouncer_hook._reset_cache_for_tests()


def _write_hot_archive(path: pathlib.Path, events: list[dict]) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def _read_warm_archive(path: pathlib.Path) -> list[dict]:
    out = []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out


# ---------------------------------------------------------------------------
# DEFAULT-OFF — dependency-free. No env var => custom layer never applied,
# even on the real persisted-redaction path.
# ---------------------------------------------------------------------------


def test_archive_scrub_default_off_leaves_custom_entity(
    tmp_path: pathlib.Path,
) -> None:
    # No IAM_JIT_CUSTOM_PII_CONFIG set. EMP-12345 is NOT a built-in
    # credential/PII pattern, so it must survive the scrub (the custom
    # layer is inactive). Built-in email redaction still proves the path
    # ran.
    src = tmp_path / "hot.jsonl.gz"
    dst = tmp_path / "warm.jsonl.gz"
    _write_hot_archive(
        src, [{"detail": {"body": "badge EMP-12345 mail a@b.com"}}]
    )
    _scrub_archive_pii(src, dst, _gdpr_policy())

    [event] = _read_warm_archive(dst)
    body = event["detail"]["body"]
    assert "EMP-12345" in body  # custom layer OFF => not redacted
    assert "a@b.com" not in body  # built-in path DID run


@pytest.mark.asyncio
async def test_log_worker_default_off_leaves_custom_entity(
    tmp_path: pathlib.Path,
) -> None:
    from iam_jit.bouncer.audit_export import AuditLogWriter

    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path, retention_policy=_gdpr_policy())
    await writer.start()
    try:
        writer.write({"detail": {"body": "badge EMP-12345 mail a@b.com"}})
        # drain
        for _ in range(200):
            if writer.status()["total_events"] >= 1:
                break
            await asyncio.sleep(0.01)
    finally:
        await writer.stop()

    [line] = log_path.read_text().splitlines()
    event = json.loads(line)
    body = event["detail"]["body"]
    assert "EMP-12345" in body  # custom layer OFF
    assert "a@b.com" not in body  # built-in path ran


# ---------------------------------------------------------------------------
# ENV-ON end-to-end — requires presidio. Custom entity redacted in the
# PERSISTED event via the REAL caller path (NOT the CLI).
# ---------------------------------------------------------------------------


def _write_cfg(path: pathlib.Path) -> None:
    path.write_text(
        "schema_version: 1\n"
        "entities:\n"
        "  - name: EMP_BADGE\n"
        '    patterns: ["EMP-\\\\d{5}"]\n'
        "    score: 0.9\n"
    )


def test_archive_scrub_env_on_redacts_custom_entity(
    tmp_path: pathlib.Path, monkeypatch
) -> None:
    pytest.importorskip("presidio_analyzer")
    cfg = tmp_path / "pii.yaml"
    _write_cfg(cfg)
    monkeypatch.setenv(bouncer_hook.CONFIG_ENV_VAR, str(cfg))
    bouncer_hook._reset_cache_for_tests()

    src = tmp_path / "hot.jsonl.gz"
    dst = tmp_path / "warm.jsonl.gz"
    _write_hot_archive(src, [{"detail": {"body": "badge EMP-12345 here"}}])
    _scrub_archive_pii(src, dst, _gdpr_policy())

    [event] = _read_warm_archive(dst)
    body = event["detail"]["body"]
    assert "EMP-12345" not in body  # custom layer ON => redacted in PERSISTED event
    assert "[REDACTED:EMP_BADGE]" in body


@pytest.mark.asyncio
async def test_log_worker_env_on_redacts_custom_entity(
    tmp_path: pathlib.Path, monkeypatch
) -> None:
    pytest.importorskip("presidio_analyzer")
    from iam_jit.bouncer.audit_export import AuditLogWriter

    cfg = tmp_path / "pii.yaml"
    _write_cfg(cfg)
    monkeypatch.setenv(bouncer_hook.CONFIG_ENV_VAR, str(cfg))
    bouncer_hook._reset_cache_for_tests()

    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path, retention_policy=_gdpr_policy())
    await writer.start()
    try:
        writer.write({"detail": {"body": "badge EMP-12345 here"}})
        for _ in range(200):
            if writer.status()["total_events"] >= 1:
                break
            await asyncio.sleep(0.01)
    finally:
        await writer.stop()

    [line] = log_path.read_text().splitlines()
    body = json.loads(line)["detail"]["body"]
    assert "EMP-12345" not in body  # PERSISTED event redacted by custom layer
    assert "[REDACTED:EMP_BADGE]" in body


def test_redaction_gate_respected_when_env_on(
    tmp_path: pathlib.Path, monkeypatch
) -> None:
    # Even with the env var set, gdpr_pii_purge=False (default PCI policy)
    # must NOT redact — the existing redaction gate is respected.
    pytest.importorskip("presidio_analyzer")
    cfg = tmp_path / "pii.yaml"
    _write_cfg(cfg)
    monkeypatch.setenv(bouncer_hook.CONFIG_ENV_VAR, str(cfg))
    bouncer_hook._reset_cache_for_tests()

    src = tmp_path / "hot.jsonl.gz"
    dst = tmp_path / "warm.jsonl.gz"
    _write_hot_archive(src, [{"detail": {"body": "badge EMP-12345 here"}}])
    # default_policy() => gdpr_pii_purge False
    _scrub_archive_pii(src, dst, default_policy())

    [event] = _read_warm_archive(dst)
    assert "EMP-12345" in event["detail"]["body"]  # gate off => untouched


# ---------------------------------------------------------------------------
# FAIL-SOFT — a broken config must not break the cache fetch (returns None,
# audit writes proceed with built-in redaction only).
# ---------------------------------------------------------------------------


def test_broken_config_fails_soft_to_none(tmp_path: pathlib.Path, monkeypatch):
    bad = tmp_path / "broken.yaml"
    bad.write_text("schema_version: 1\nentities: [ this is : not valid }\n")
    monkeypatch.setenv(bouncer_hook.CONFIG_ENV_VAR, str(bad))
    bouncer_hook._reset_cache_for_tests()
    # Must NOT raise; returns None so audit writes proceed unbroken.
    assert bouncer_hook.get_audit_extra_redactor() is None


def test_missing_config_path_fails_soft_to_none(monkeypatch):
    monkeypatch.setenv(
        bouncer_hook.CONFIG_ENV_VAR, "/no/such/custom-pii-config.yaml"
    )
    bouncer_hook._reset_cache_for_tests()
    assert bouncer_hook.get_audit_extra_redactor() is None


def test_cache_rebuilds_on_env_change(tmp_path: pathlib.Path, monkeypatch):
    pytest.importorskip("presidio_analyzer")
    cfg = tmp_path / "pii.yaml"
    _write_cfg(cfg)
    # Off first.
    bouncer_hook._reset_cache_for_tests()
    assert bouncer_hook.get_audit_extra_redactor() is None
    # Turn on — cache must rebuild because the resolved path changed.
    monkeypatch.setenv(bouncer_hook.CONFIG_ENV_VAR, str(cfg))
    r = bouncer_hook.get_audit_extra_redactor()
    assert r is not None
    assert "[REDACTED:EMP_BADGE]" in r("EMP-12345")
