"""Tests for #427 / §A66 — Ed25519-signed manifests (manifest.py).

Coverage matrix from the brief:
- test_signed_manifest_emitted_every_N_entries
- test_signed_manifest_ed25519_verifies_externally
- test_webhook_adapters_emit_signed_checkpoints
"""

from __future__ import annotations

import json
import pathlib

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from iam_jit.bouncer.audit_export import (
    CHAIN_FIELD,
    ChainState,
    Manifest,
    ManifestSigner,
    MANIFEST_OCSF_ACTIVITY_NAME,
    list_manifests,
    load_manifest_file,
    stamp_chain_event,
    verify_manifest,
)


def _ocsf_event() -> dict:
    return {
        "metadata": {"version": "1.1.0", "product": {"name": "ibounce"}},
        "class_uid": 6003,
        "activity_name": "Read",
        "time": 1_700_000_000_000,
        "unmapped": {"iam_jit": {"verdict": "ALLOW"}},
    }


@pytest.fixture
def keypair_dir(tmp_path):
    """Operator-local keypair directory; isolated per test."""
    d = tmp_path / "keys"
    return d


def test_signed_manifest_emitted_every_N_entries(tmp_path, keypair_dir):
    """ManifestSigner.should_emit fires once N events have stamped."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=5,
        keypair_dir=str(keypair_dir),
    )
    # Below interval — no emit.
    for _ in range(4):
        stamp_chain_event(_ocsf_event(), state)
        assert not signer.should_emit(state)
    # At interval — emit fires.
    stamp_chain_event(_ocsf_event(), state)
    assert signer.should_emit(state)
    manifest = signer.emit(state)
    assert manifest is not None
    assert manifest.seq_start == 0
    assert manifest.seq_end == 4
    assert manifest.head_hash == state.last_hash
    assert signer.manifests_emitted == 1
    # Now should_emit goes back to False until the next interval.
    assert not signer.should_emit(state)
    for _ in range(5):
        stamp_chain_event(_ocsf_event(), state)
    assert signer.should_emit(state)


def test_signed_manifest_ed25519_verifies_externally(tmp_path, keypair_dir):
    """An external verifier holding ONLY the public key can verify
    the signature. The verifier round-trips through load_manifest_file
    so it sees exactly what an out-of-band party would see."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=1,
        keypair_dir=str(keypair_dir),
    )
    stamp_chain_event(_ocsf_event(), state)
    manifest = signer.emit(state)
    assert manifest is not None
    # Manifest file landed on disk.
    files = list_manifests(log_dir)
    assert len(files) == 1
    loaded = load_manifest_file(files[0])
    # Verify with the manifest's embedded key (auto_pin_local=False so
    # the keypair_dir local key doesn't auto-pin and cloud the trust level).
    ok, reason, key_trust = verify_manifest(loaded, auto_pin_local=False)
    assert ok, reason
    assert key_trust == "embedded_unpinned"
    # Verify with the pub key from disk (pinned out-of-band).
    pub_pem = (keypair_dir / "manifest-ed25519.pub").read_bytes()
    pub = serialization.load_pem_public_key(pub_pem)
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import base64
    pinned_b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    ok2, reason2, key_trust2 = verify_manifest(
        loaded, public_key_override_b64=pinned_b64,
    )
    assert ok2, reason2
    assert key_trust2 == "pinned"
    # Tamper with the manifest: the verifier MUST detect it.
    tampered = manifest.__class__(
        schema_version=loaded.schema_version,
        seq_start=loaded.seq_start,
        seq_end=loaded.seq_end + 1,  # CHANGED
        head_hash=loaded.head_hash,
        generated_at_iso=loaded.generated_at_iso,
        bouncer_product=loaded.bouncer_product,
        log_dir=loaded.log_dir,
        signature_b64=loaded.signature_b64,
        public_key_b64=loaded.public_key_b64,
    )
    ok3, reason3, _ = verify_manifest(tampered, auto_pin_local=False)
    assert not ok3
    assert reason3 is not None and "tampered" in reason3


def test_webhook_adapters_emit_signed_checkpoints(tmp_path, keypair_dir):
    """ManifestSigner.build_ocsf_event wraps a manifest as an OCSF
    event suitable for the existing webhook + S3 transport. Verifies
    the shape so the webhook adapter contract is fixed in tests."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=1,
        keypair_dir=str(keypair_dir),
    )
    stamp_chain_event(_ocsf_event(), state)
    manifest = signer.emit(state)
    assert manifest is not None
    event = signer.build_ocsf_event(manifest)
    # OCSF top-level invariants.
    assert event["class_uid"] == 6003
    assert event["category_uid"] == 6
    assert event["activity_name"] == MANIFEST_OCSF_ACTIVITY_NAME
    assert event["metadata"]["product"]["name"] == "ibounce"
    assert event["metadata"]["product"]["vendor_name"] == "iam-jit"
    # Manifest payload rides under unmapped.iam_jit.manifest so the
    # existing audit-export consumers don't need to learn a new
    # top-level field.
    assert event["unmapped"]["iam_jit"]["manifest"]["head_hash"] == manifest.head_hash
    assert event["unmapped"]["iam_jit"]["manifest"]["signature_b64"] == manifest.signature_b64
    assert event["unmapped"]["iam_jit"]["manifest"]["public_key_b64"] == manifest.public_key_b64


def test_manifest_keypair_perms_are_restrictive(keypair_dir):
    """Generated private key file MUST be 0o600 so non-owner processes
    can't read it. Public key may be 0o644."""
    from iam_jit.bouncer.audit_export import load_or_generate_manifest_keypair
    import os
    load_or_generate_manifest_keypair(dir=str(keypair_dir))
    priv_path = keypair_dir / "manifest-ed25519.priv"
    pub_path = keypair_dir / "manifest-ed25519.pub"
    assert priv_path.is_file()
    assert pub_path.is_file()
    priv_mode = priv_path.stat().st_mode & 0o777
    assert priv_mode == 0o600, oct(priv_mode)


def test_manifest_signer_status_surfaces_counters(tmp_path, keypair_dir):
    """The status() snapshot exposes the fields /healthz consumes."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=2,
        keypair_dir=str(keypair_dir),
    )
    status = signer.status()
    assert status["configured"] is True
    assert status["manifests_emitted"] == 0
    assert status["last_emitted_seq"] is None
    assert status["interval_events"] == 2
    assert "public_key_b64" in status
    # Drive one manifest.
    stamp_chain_event(_ocsf_event(), state)
    stamp_chain_event(_ocsf_event(), state)
    assert signer.should_emit(state)
    signer.emit(state)
    status = signer.status()
    assert status["manifests_emitted"] == 1
    assert status["last_emitted_seq"] == 1
