"""Tests for #58 — manifest verifier key_trust / auto-pin treatment.

Mirrors the receipt key_trust tests in ``tests/test_denial_receipts.py``
exactly as the issue spec requires.  Three scenarios:

1. Genuine manifest + local on-disk key present → key_trust="local", ok.
2. Forged manifest (attacker's key) against local pinned key → FAILS;
   key_trust="local" (forged issuer caught).
3. Forged manifest, no local key, no pin (embedded only) →
   key_trust="embedded_unpinned" + caveat; ok=True (gap demonstrated) +
   the issuer is explicitly NOT verified.

Also verifies the CLI surface (``iam-jit audit verify``) surfaces
key_trust and the embedded_unpinned caveat in the JSON report.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from iam_jit.bouncer.audit_export import (
    ChainState,
    ManifestSigner,
    stamp_chain_event,
    list_manifests,
    load_manifest_file,
    verify_manifest,
    MANIFEST_EMBEDDED_UNPINNED_CAVEAT,
    MANIFEST_KEY_TRUST_EMBEDDED_UNPINNED,
    MANIFEST_KEY_TRUST_LOCAL,
    MANIFEST_KEY_TRUST_PINNED,
)
from iam_jit.bouncer.audit_export.manifest import (
    DEFAULT_KEYPAIR_NAME,
    PUBLIC_KEY_SUFFIX,
    _b64u,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ocsf_event() -> dict:
    return {
        "metadata": {"version": "1.1.0", "product": {"name": "ibounce"}},
        "class_uid": 6003,
        "activity_name": "Read",
        "time": 1_700_000_000_000,
        "unmapped": {"iam_jit": {"verdict": "ALLOW"}},
    }


def _make_manifest(tmp_path: pathlib.Path, keypair_dir: pathlib.Path):
    """Emit one signed manifest into *tmp_path/logs* using *keypair_dir*."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=1,
        keypair_dir=str(keypair_dir),
    )
    stamp_chain_event(_ocsf_event(), state)
    m = signer.emit(state)
    assert m is not None
    files = list_manifests(log_dir)
    assert len(files) == 1
    return load_manifest_file(files[0])


def _forge_manifest(genuine, attacker_priv: Ed25519PrivateKey, attacker_pub_b64: str):
    """Re-sign *genuine* with the ATTACKER's key and embed the attacker's
    public key — self-consistent forgery."""
    unsigned = dataclasses.replace(
        genuine,
        public_key_b64=attacker_pub_b64,
        signature_b64="",
    )
    sig = attacker_priv.sign(unsigned.signing_payload())
    return dataclasses.replace(unsigned, signature_b64=_b64u(sig))


@pytest.fixture
def keypair_dir(tmp_path):
    """Isolated on-disk keypair directory for the legitimate signer."""
    d = tmp_path / "legit-keys"
    d.mkdir()
    return d


@pytest.fixture
def attacker_keys(tmp_path):
    """Fresh keypair for the attacker (never written to the local dir)."""
    from cryptography.hazmat.primitives import serialization as _ser

    d = tmp_path / "attacker-keys"
    d.mkdir()
    signer = ManifestSigner(
        log_dir=str(tmp_path / "attacker-log"),
        interval=1,
        keypair_dir=str(d),
    )
    # Materialise the keypair by forcing a sign/emit cycle so the attacker's
    # .pub exists under d.  We only need the private key object though.
    priv = signer._private  # noqa: SLF001
    pub_raw = signer._public.public_bytes(  # noqa: SLF001
        encoding=_ser.Encoding.Raw,
        format=_ser.PublicFormat.Raw,
    )
    pub_b64 = _b64u(pub_raw)
    return priv, pub_b64


# ---------------------------------------------------------------------------
# Core key_trust tests
# ---------------------------------------------------------------------------


def test_genuine_manifest_local_pinned_reports_key_trust_local(
    tmp_path: pathlib.Path, keypair_dir: pathlib.Path
) -> None:
    """Genuine manifest + local on-disk key → key_trust=local, ok."""
    manifest = _make_manifest(tmp_path / "run", keypair_dir)
    ok, reason, key_trust = verify_manifest(
        manifest, keypair_dir=str(keypair_dir),
    )
    assert ok, reason
    assert key_trust == MANIFEST_KEY_TRUST_LOCAL


def test_forged_manifest_fails_against_local_pinned_key(
    tmp_path: pathlib.Path, keypair_dir: pathlib.Path, attacker_keys
) -> None:
    """Forged manifest (attacker keypair) verified against the LOCAL on-disk
    key MUST FAIL — the forged issuer is caught.

    This is the security-critical test: without auto-pin a forged manifest
    self-verifies (embedded ok, embedded_unpinned).  With auto-pin it fails.
    """
    attacker_priv, attacker_pub_b64 = attacker_keys
    genuine = _make_manifest(tmp_path / "run", keypair_dir)
    forged = _forge_manifest(genuine, attacker_priv, attacker_pub_b64)

    # Self-verify (embedded, no local key) would PASS — demonstrate the gap.
    empty_dir = tmp_path / "no-keys"
    empty_dir.mkdir()
    ok_embed, _, trust_embed = verify_manifest(
        forged, keypair_dir=str(empty_dir), auto_pin_local=True,
    )
    assert ok_embed is True
    assert trust_embed == MANIFEST_KEY_TRUST_EMBEDDED_UNPINNED

    # Auto-pinned to the local (legitimate) key → FAILS, forged issuer caught.
    ok, reason, key_trust = verify_manifest(
        forged, keypair_dir=str(keypair_dir),
    )
    assert ok is False
    assert key_trust == MANIFEST_KEY_TRUST_LOCAL
    assert reason is not None and "different" in reason.lower()


def test_forged_manifest_embedded_unpinned_reports_caveat(
    tmp_path: pathlib.Path, keypair_dir: pathlib.Path, attacker_keys
) -> None:
    """No local key, no pin → embedded_unpinned.  A forged manifest
    self-verifies but key_trust must flag the issuer is NOT verified."""
    attacker_priv, attacker_pub_b64 = attacker_keys
    genuine = _make_manifest(tmp_path / "run", keypair_dir)
    forged = _forge_manifest(genuine, attacker_priv, attacker_pub_b64)

    empty_dir = tmp_path / "no-keys"
    empty_dir.mkdir()
    ok, reason, key_trust = verify_manifest(
        forged, keypair_dir=str(empty_dir),
    )
    assert ok is True  # well-formed signature...
    assert key_trust == MANIFEST_KEY_TRUST_EMBEDDED_UNPINNED  # ...but UNVERIFIED
    assert "issuer" in MANIFEST_EMBEDDED_UNPINNED_CAVEAT.lower()
    assert "not verified" in MANIFEST_EMBEDDED_UNPINNED_CAVEAT.lower()


def test_genuine_manifest_pinned_key_reports_key_trust_pinned(
    tmp_path: pathlib.Path, keypair_dir: pathlib.Path
) -> None:
    """Explicit --public-key override → key_trust=pinned, ok."""
    from cryptography.hazmat.primitives import serialization

    manifest = _make_manifest(tmp_path / "run", keypair_dir)
    pub_pem = (
        keypair_dir / f"{DEFAULT_KEYPAIR_NAME}{PUBLIC_KEY_SUFFIX}"
    ).read_bytes()
    pub = serialization.load_pem_public_key(pub_pem)
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import base64
    pinned_b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    ok, reason, key_trust = verify_manifest(
        manifest, public_key_override_b64=pinned_b64,
    )
    assert ok, reason
    assert key_trust == MANIFEST_KEY_TRUST_PINNED


def test_auto_pin_local_false_falls_back_to_embedded(
    tmp_path: pathlib.Path, keypair_dir: pathlib.Path
) -> None:
    """auto_pin_local=False disables local-key lookup → embedded_unpinned
    even when the local key exists."""
    manifest = _make_manifest(tmp_path / "run", keypair_dir)
    ok, reason, key_trust = verify_manifest(
        manifest, keypair_dir=str(keypair_dir), auto_pin_local=False,
    )
    assert ok, reason
    assert key_trust == MANIFEST_KEY_TRUST_EMBEDDED_UNPINNED


# ---------------------------------------------------------------------------
# CLI surface — `iam-jit audit verify` --json exposes key_trust
# ---------------------------------------------------------------------------


def test_cli_audit_verify_json_surfaces_manifest_key_trust(
    tmp_path: pathlib.Path, keypair_dir: pathlib.Path
) -> None:
    """The ``iam-jit audit verify --json`` report includes
    ``manifest_unpinned_warnings`` entries for embedded_unpinned manifests."""
    from click.testing import CliRunner

    from iam_jit.cli_audit_verify import register_audit_verify_command
    import click as _click

    # Emit one manifest in a log dir.
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    # Write a minimal chain state + JSONL so "nothing checked" is avoided.
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=1,
        keypair_dir=str(keypair_dir),
    )
    stamp_chain_event(_ocsf_event(), state)
    from iam_jit.bouncer.audit_export import save_chain_state
    save_chain_state(state)
    # Write the JSONL file so verify_chain_jsonl finds events.
    jsonl_path = log_dir / "audit.jsonl"
    import time as _time
    event = _ocsf_event()
    stamp_chain_event(event, state)
    save_chain_state(state)
    # Actually write an event so events_checked > 0.
    with jsonl_path.open("w") as f:
        import json as _json
        f.write(_json.dumps(event) + "\n")
    signer.emit(state)

    # Build a CLI command + invoke against an EMPTY keypair_dir so it
    # falls through to embedded_unpinned.
    empty_key_dir = tmp_path / "no-keys"
    empty_key_dir.mkdir()

    audit_group = _click.Group("audit")
    cmd = register_audit_verify_command(audit_group)

    # Monkeypatch DEFAULT_KEYPAIR_DIR in manifest module so auto-pin finds
    # the empty dir.
    import iam_jit.bouncer.audit_export.manifest as _m
    old = _m.DEFAULT_KEYPAIR_DIR
    _m.DEFAULT_KEYPAIR_DIR = str(empty_key_dir)
    try:
        res = CliRunner().invoke(
            cmd, ["--log-dir", str(log_dir), "--json"],
        )
    finally:
        _m.DEFAULT_KEYPAIR_DIR = old

    try:
        payload = json.loads(res.output)
    except json.JSONDecodeError:
        pytest.fail(f"Non-JSON output:\n{res.output}")

    # The unpinned warnings list must be present (even if empty with
    # 0 manifests; with 1 manifest it must have 1 entry).
    assert "manifest_unpinned_warnings" in payload
    warnings = payload["manifest_unpinned_warnings"]
    if payload["manifests_checked"] > 0:
        assert len(warnings) == 1
        assert warnings[0]["key_trust"] == MANIFEST_KEY_TRUST_EMBEDDED_UNPINNED
        assert "issuer" in warnings[0]["caveat"].lower()


def test_cli_audit_verify_json_forged_manifest_fails_with_local_key(
    tmp_path: pathlib.Path, keypair_dir: pathlib.Path, attacker_keys
) -> None:
    """``iam-jit audit verify --json`` reports manifest_findings with
    the failing manifest when verified against the legit local key."""
    import json as _json
    from click.testing import CliRunner
    import click as _click
    from iam_jit.cli_audit_verify import register_audit_verify_command
    from iam_jit.bouncer.audit_export import save_chain_state

    attacker_priv, attacker_pub_b64 = attacker_keys
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    signer = ManifestSigner(
        log_dir=str(log_dir),
        interval=1,
        keypair_dir=str(keypair_dir),
    )
    stamp_chain_event(_ocsf_event(), state)
    save_chain_state(state)
    # Write events to JSONL so events_checked > 0.
    event = _ocsf_event()
    stamp_chain_event(event, state)
    save_chain_state(state)
    jsonl_path = log_dir / "audit.jsonl"
    with jsonl_path.open("w") as f:
        f.write(_json.dumps(event) + "\n")

    # Emit + load manifest, forge it, overwrite on disk.
    signer.emit(state)
    manifest_files = list_manifests(log_dir)
    assert len(manifest_files) == 1
    genuine = load_manifest_file(manifest_files[0])
    forged = _forge_manifest(genuine, attacker_priv, attacker_pub_b64)
    manifest_files[0].write_text(
        _json.dumps(forged.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # Now run audit verify pointing at keypair_dir → should detect forgery.
    import iam_jit.bouncer.audit_export.manifest as _m
    old = _m.DEFAULT_KEYPAIR_DIR
    _m.DEFAULT_KEYPAIR_DIR = str(keypair_dir)
    try:
        audit_group = _click.Group("audit")
        cmd = register_audit_verify_command(audit_group)
        res = CliRunner().invoke(
            cmd, ["--log-dir", str(log_dir), "--json"],
        )
    finally:
        _m.DEFAULT_KEYPAIR_DIR = old

    assert res.exit_code == 1, res.output
    try:
        payload = _json.loads(res.output)
    except _json.JSONDecodeError:
        pytest.fail(f"Non-JSON output:\n{res.output}")

    assert payload["ok"] is False
    findings = payload["manifest_findings"]
    assert len(findings) >= 1
    f = findings[0]
    assert f["ok"] is False
    assert f.get("key_trust") == MANIFEST_KEY_TRUST_LOCAL
    # issuer_unverified=False: the local key IS the verified issuer —
    # the failure is a signature mismatch (forged by a different key),
    # not an absence of issuer trust.
    assert f.get("issuer_unverified") is False
    assert "different" in f.get("reason", "").lower()
