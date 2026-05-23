"""Tests for the `iam-jit audit verify` CLI (cli_audit_verify.py)."""

from __future__ import annotations

import gzip
import json
import pathlib

import click
import pytest
from click.testing import CliRunner

from iam_jit.bouncer.audit_export import (
    CHAIN_FIELD,
    ChainState,
    ManifestSigner,
    stamp_chain_event,
)
from iam_jit.cli_audit_verify import (
    register_audit_retention_command,
    register_audit_verify_command,
)


def _ocsf_event(i: int = 0) -> dict:
    return {
        "metadata": {"version": "1.1.0", "product": {"name": "ibounce"}},
        "class_uid": 6003,
        "activity_name": "Read",
        "time": 1_700_000_000_000 + i,
        "unmapped": {"iam_jit": {"verdict": "ALLOW", "i": i}},
    }


@pytest.fixture
def audit_verify_cmd():
    """A standalone audit group with verify registered for invocation."""
    @click.group()
    def root() -> None:
        pass

    @root.group("audit")
    def audit_group() -> None:
        pass

    register_audit_verify_command(audit_group)
    register_audit_retention_command(audit_group)
    return root, audit_group


def test_audit_verify_clean_chain_exits_zero(tmp_path, audit_verify_cmd):
    """Clean chain + no manifests → exit 0, ok message."""
    root, _ = audit_verify_cmd
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    events = [_ocsf_event(i) for i in range(3)]
    for e in events:
        stamp_chain_event(e, state)
    with (log_dir / "audit.jsonl").open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    runner = CliRunner()
    result = runner.invoke(root, ["audit", "verify", "--log-dir", str(log_dir)])
    assert result.exit_code == 0, result.output
    assert "RESULT: ok" in result.output


def test_audit_verify_tampered_chain_exits_one(tmp_path, audit_verify_cmd):
    """Tampered chain → exit 1, findings printed."""
    root, _ = audit_verify_cmd
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    events = [_ocsf_event(i) for i in range(3)]
    for e in events:
        stamp_chain_event(e, state)
    # Tamper with one event before persisting.
    events[1]["unmapped"]["iam_jit"]["verdict"] = "DENY"
    with (log_dir / "audit.jsonl").open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    runner = CliRunner()
    result = runner.invoke(root, ["audit", "verify", "--log-dir", str(log_dir)])
    assert result.exit_code == 1
    assert "RESULT: FAILED" in result.output
    assert "reason=" in result.output


def test_audit_verify_json_output(tmp_path, audit_verify_cmd):
    """--json emits the structured report on stdout."""
    root, _ = audit_verify_cmd
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    events = [_ocsf_event(i) for i in range(2)]
    for e in events:
        stamp_chain_event(e, state)
    with (log_dir / "audit.jsonl").open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    runner = CliRunner()
    result = runner.invoke(root, [
        "audit", "verify", "--log-dir", str(log_dir), "--json",
    ])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["chain"]["events_checked"] == 2
    assert payload["chain"]["ok"] is True


def test_audit_verify_verifies_manifest_signature(tmp_path, audit_verify_cmd):
    """A clean manifest's signature verifies → exit 0."""
    root, _ = audit_verify_cmd
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    keypair_dir = tmp_path / "keys"
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=1,
        keypair_dir=str(keypair_dir),
    )
    e = _ocsf_event(0)
    stamp_chain_event(e, state)
    with (log_dir / "audit.jsonl").open("w") as f:
        f.write(json.dumps(e) + "\n")
    signer.emit(state)
    runner = CliRunner()
    result = runner.invoke(root, ["audit", "verify", "--log-dir", str(log_dir)])
    assert result.exit_code == 0, result.output
    # The manifest count surfaces in human output.
    assert "manifests checked: 1" in result.output


def test_audit_verify_detects_bad_manifest_signature(tmp_path, audit_verify_cmd):
    """Tampering with a manifest's payload after signing → exit 1."""
    root, _ = audit_verify_cmd
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    keypair_dir = tmp_path / "keys"
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=1,
        keypair_dir=str(keypair_dir),
    )
    e = _ocsf_event(0)
    stamp_chain_event(e, state)
    with (log_dir / "audit.jsonl").open("w") as f:
        f.write(json.dumps(e) + "\n")
    signer.emit(state)
    # Tamper with the manifest on disk.
    mfile = list((log_dir / "manifests").iterdir())[0]
    raw = json.loads(mfile.read_text())
    raw["seq_end"] += 99
    mfile.write_text(json.dumps(raw, indent=2))
    runner = CliRunner()
    result = runner.invoke(root, ["audit", "verify", "--log-dir", str(log_dir)])
    assert result.exit_code == 1
    assert "manifest failures" in result.output


def test_audit_retention_apply_dry_run_default(tmp_path, audit_verify_cmd):
    """`iam-jit audit retention apply` defaults to dry-run; the
    resolved policy is printed but no mutation happens."""
    root, _ = audit_verify_cmd
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    runner = CliRunner()
    result = runner.invoke(root, [
        "audit", "retention", "apply",
        "--framework", "hipaa",
        "--log-dir", str(log_dir),
    ])
    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in result.output
    assert "hipaa" in result.output
    assert "hot<=30" in result.output  # HIPAA default


def test_audit_retention_apply_with_config_overrides(tmp_path, audit_verify_cmd):
    """--config reads a retention block + applies overrides on top."""
    root, _ = audit_verify_cmd
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    cfg = tmp_path / "retention.yaml"
    cfg.write_text(
        "iam-jit:\n"
        "  enabled: true\n"
        "  retention:\n"
        "    compliance: gdpr\n"
        "    hot_days: 7\n"
    )
    runner = CliRunner()
    result = runner.invoke(root, [
        "audit", "retention", "apply",
        "--config", str(cfg),
        "--log-dir", str(log_dir),
    ])
    assert result.exit_code == 0, result.output
    assert "gdpr" in result.output
    assert "hot<=7" in result.output
    assert "gdpr_pii_purge=True" in result.output


def test_audit_retention_apply_framework_and_config_mutex(tmp_path, audit_verify_cmd):
    """--framework + --config together → UsageError exit 2."""
    root, _ = audit_verify_cmd
    cfg = tmp_path / "retention.yaml"
    cfg.write_text("iam-jit:\n  enabled: true\n")
    runner = CliRunner()
    result = runner.invoke(root, [
        "audit", "retention", "apply",
        "--framework", "pci",
        "--config", str(cfg),
    ])
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_audit_verify_skip_manifests_flag(tmp_path, audit_verify_cmd):
    """--skip-manifests bypasses signature checks (chain-only mode)."""
    root, _ = audit_verify_cmd
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    events = [_ocsf_event(i) for i in range(2)]
    for e in events:
        stamp_chain_event(e, state)
    with (log_dir / "audit.jsonl").open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    runner = CliRunner()
    result = runner.invoke(root, [
        "audit", "verify", "--log-dir", str(log_dir),
        "--skip-manifests", "--json",
    ])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["manifests_checked"] == 0
