"""#407 / §A51 — Threat-feed signing + verification.

Two signing modes (per #441 Sysdig research):

  1. **Ed25519 (canonical, no extra deps)** — publisher generates an
     Ed25519 keypair, signs each entry's canonical payload, distributes
     the pubkey out-of-band; operator pins the pubkey in the
     declarative config. Lightweight, ships with everything we already
     depend on (``cryptography`` ships transitively via PyJWT[crypto]).

  2. **cosign keyless (additive)** — operator who doesn't want to
     manage keys can verify entries signed via Sigstore's cosign
     keyless flow (publisher's signature includes the Sigstore-issued
     cert + Rekor bundle; operator just needs ``cosign`` on PATH +
     pins the publisher's identity (e.g. OIDC subject email +
     issuer)). This is a verify-only path; we never *create* cosign
     signatures from inside iam-jit (cosign-the-tool does it).

Per [[independence-as-security-property]] both modes are operator-pinned;
neither phones home (Rekor IS public, but cosign-verify does the
inclusion-proof check locally against the bundle so an operator who
doesn't want a Rekor round-trip CAN supply a bundle-only verify).

Canonical payload bytes (the thing actually signed) is the entry's
``as_dict()`` MINUS the ``signature`` field itself, then serialized
with ``json.dumps(payload, sort_keys=True, separators=(',', ':'))``
encoded as UTF-8. This is the ONLY canonicalization on the wire so
both publisher + verifier produce byte-identical payloads.

Per [[ibounce-honest-positioning]] unsigned entries are REFUSED at the
applier — no fallback to "trust the URL". The verifier returns a
structured :class:`~iam_jit.threat_feed.models.VerificationResult` that
the applier maps to a per-entry refusal-event.

Per [[push-policy-public-repo]] we NEVER ship a private key into the
repo. Tests that need a keypair generate one ephemerally in
``tmp_path``; the test fixtures + ``feeds/`` directory contain ONLY
public keys + signed bundles.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import logging
import shutil
import subprocess
import tempfile
import typing

from .models import FeedEntry, VerificationResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SigningError(RuntimeError):
    """Raised by publisher-side signing functions on failure (e.g.
    key parse error, signing operation failed)."""


class VerificationFailed(RuntimeError):
    """Raised by the verifier when verification *fundamentally* fails
    (malformed signature block, missing required fields, cosign
    binary not on PATH when required). Per-entry signature mismatches
    return a :class:`VerificationResult` with ``verified=False`` rather
    than raising — the applier wants to log + skip those entries, not
    crash the whole fetch."""


# ---------------------------------------------------------------------------
# Canonical payload
# ---------------------------------------------------------------------------


def canonical_payload_bytes(entry: FeedEntry) -> bytes:
    """Return the deterministic byte string that is signed.

    Excludes ``signature`` (you can't sign the thing-to-be-signed) and
    sorts keys / drops whitespace so publisher + verifier produce
    byte-identical inputs.

    NOTE: nested arrays (``action``, ``applies_to_bouncers``,
    ``compliance_tags``) preserve their on-the-wire order — the
    publisher tool sorts them deterministically when bundling so the
    canonicalization is unambiguous.
    """
    payload = entry.as_dict()
    payload.pop("signature", None)
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Ed25519 keygen + sign + verify
# ---------------------------------------------------------------------------


def ed25519_keygen() -> tuple[str, str]:
    """Generate a fresh Ed25519 keypair.

    Returns ``(private_key_pem, public_key_pem)`` — both PEM-encoded
    strings so the publisher tool can save them to disk + display the
    pubkey for distribution. Per [[push-policy-public-repo]] the
    private key MUST NOT be committed.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:  # pragma: no cover
        raise SigningError(
            f"cryptography library required for Ed25519 keygen: {e}"
        ) from e
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


def _load_ed25519_private(private_key_pem: str):
    from cryptography.hazmat.primitives import serialization

    try:
        return serialization.load_pem_private_key(
            private_key_pem.encode("ascii"), password=None,
        )
    except Exception as e:
        raise SigningError(f"failed to parse private key PEM: {e}") from e


def _load_ed25519_public(public_key_pem_or_b64: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    val = (public_key_pem_or_b64 or "").strip()
    if not val:
        raise VerificationFailed("empty public key")
    if val.startswith("-----BEGIN"):
        try:
            return serialization.load_pem_public_key(val.encode("ascii"))
        except Exception as e:
            raise VerificationFailed(
                f"failed to parse public key PEM: {e}"
            ) from e
    # Bare base64 (the ``ed25519:<b64>`` shape from the declaration is
    # also accepted; strip the prefix).
    if val.startswith("ed25519:"):
        val = val[len("ed25519:"):]
    try:
        raw = base64.b64decode(val, validate=True)
    except Exception as e:
        raise VerificationFailed(
            f"failed to base64-decode public key: {e}"
        ) from e
    if len(raw) != 32:
        raise VerificationFailed(
            f"Ed25519 raw public key must be 32 bytes, got {len(raw)}"
        )
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def ed25519_sign_entry(
    entry: FeedEntry,
    *,
    private_key_pem: str,
    publisher: str,
    key_id: str = "",
) -> FeedEntry:
    """Sign one entry with an Ed25519 private key + return a new
    :class:`FeedEntry` carrying the signature block.

    The signature block shape::

        {
          "algorithm": "ed25519",
          "value":     "<base64 sig>",
          "publisher": "<publisher name>",
          "key_id":    "<optional key id>"
        }
    """
    key = _load_ed25519_private(private_key_pem)
    payload = canonical_payload_bytes(entry)
    try:
        sig = key.sign(payload)
    except Exception as e:
        raise SigningError(f"signing operation failed: {e}") from e
    sig_block: dict[str, typing.Any] = {
        "algorithm": "ed25519",
        "value": base64.b64encode(sig).decode("ascii"),
        "publisher": publisher,
    }
    if key_id:
        sig_block["key_id"] = key_id
    return dataclasses.replace(entry, signature=sig_block)


def ed25519_verify_entry(
    entry: FeedEntry,
    *,
    publisher_pubkey: str,
) -> VerificationResult:
    """Verify one entry's Ed25519 signature.

    ``publisher_pubkey`` may be a PEM string OR the bare-base64 /
    ``ed25519:<b64>`` short form used in the declaration.

    Returns a :class:`VerificationResult` (never raises for per-entry
    failures — the applier wants to skip-and-log, not crash).
    """
    sig = entry.signature or {}
    if not sig:
        return VerificationResult(
            rule_id=entry.rule_id,
            verified=False,
            algorithm="",
            publisher="",
            reason="unsigned",
        )
    algorithm = str(sig.get("algorithm") or "").lower()
    if algorithm != "ed25519":
        return VerificationResult(
            rule_id=entry.rule_id,
            verified=False,
            algorithm=algorithm,
            publisher=str(sig.get("publisher") or ""),
            reason="algorithm_mismatch_expected_ed25519",
        )
    sig_value_b64 = str(sig.get("value") or "")
    if not sig_value_b64:
        return VerificationResult(
            rule_id=entry.rule_id,
            verified=False,
            algorithm=algorithm,
            publisher=str(sig.get("publisher") or ""),
            reason="signature_value_empty",
        )
    try:
        sig_bytes = base64.b64decode(sig_value_b64, validate=True)
    except Exception:
        return VerificationResult(
            rule_id=entry.rule_id,
            verified=False,
            algorithm=algorithm,
            publisher=str(sig.get("publisher") or ""),
            reason="signature_value_not_base64",
        )
    try:
        pubkey = _load_ed25519_public(publisher_pubkey)
    except VerificationFailed as e:
        return VerificationResult(
            rule_id=entry.rule_id,
            verified=False,
            algorithm=algorithm,
            publisher=str(sig.get("publisher") or ""),
            reason=f"pubkey_parse_failed:{e}",
        )
    payload = canonical_payload_bytes(entry)
    try:
        pubkey.verify(sig_bytes, payload)
    except Exception:
        return VerificationResult(
            rule_id=entry.rule_id,
            verified=False,
            algorithm=algorithm,
            publisher=str(sig.get("publisher") or ""),
            reason="signature_mismatch",
        )
    return VerificationResult(
        rule_id=entry.rule_id,
        verified=True,
        algorithm=algorithm,
        publisher=str(sig.get("publisher") or ""),
        reason="ok",
    )


# ---------------------------------------------------------------------------
# Cosign keyless verify (additive)
# ---------------------------------------------------------------------------


def cosign_verify_entry(
    entry: FeedEntry,
    *,
    expected_identity: str,
    expected_issuer: str,
    cosign_binary: str = "cosign",
) -> VerificationResult:
    """Verify one entry signed via cosign keyless.

    The entry's ``signature`` block must include:

      * ``algorithm``: ``"cosign-keyless"``
      * ``value``:     base64 signature (cosign's ``--signature``)
      * ``cosign_certificate``: PEM-encoded Sigstore-issued cert
      * ``cosign_bundle``: cosign's Rekor bundle (offline verify)

    ``expected_identity`` (e.g. ``"trsreagan3@gmail.com"``) and
    ``expected_issuer`` (e.g. ``"https://accounts.google.com"``) come
    from the operator's declarative config — they pin WHO is allowed
    to publish to this feed.

    Requires the ``cosign`` binary on PATH. Returns a
    :class:`VerificationResult` with ``reason="cosign_binary_missing"``
    when absent so an operator who doesn't use cosign sees a clear
    diagnostic rather than a stack trace.
    """
    sig = entry.signature or {}
    algorithm = str(sig.get("algorithm") or "").lower()
    if algorithm != "cosign-keyless":
        return VerificationResult(
            rule_id=entry.rule_id,
            verified=False,
            algorithm=algorithm,
            publisher=str(sig.get("publisher") or ""),
            reason="algorithm_mismatch_expected_cosign_keyless",
        )

    if not shutil.which(cosign_binary):
        return VerificationResult(
            rule_id=entry.rule_id,
            verified=False,
            algorithm=algorithm,
            publisher=str(sig.get("publisher") or ""),
            reason="cosign_binary_missing",
        )

    sig_value = str(sig.get("value") or "")
    cert_pem = str(sig.get("cosign_certificate") or "")
    bundle_json = str(sig.get("cosign_bundle") or "")
    if not (sig_value and cert_pem and bundle_json):
        return VerificationResult(
            rule_id=entry.rule_id,
            verified=False,
            algorithm=algorithm,
            publisher=str(sig.get("publisher") or ""),
            reason="cosign_block_incomplete",
        )

    payload = canonical_payload_bytes(entry)
    with tempfile.TemporaryDirectory() as td:
        import pathlib
        td_p = pathlib.Path(td)
        blob = td_p / "payload.bin"
        sigf = td_p / "sig.b64"
        cert = td_p / "cert.pem"
        bundle = td_p / "bundle.json"
        blob.write_bytes(payload)
        sigf.write_text(sig_value)
        cert.write_text(cert_pem)
        bundle.write_text(bundle_json)
        cmd = [
            cosign_binary, "verify-blob",
            "--signature", str(sigf),
            "--certificate", str(cert),
            "--bundle", str(bundle),
            "--certificate-identity", expected_identity,
            "--certificate-oidc-issuer", expected_issuer,
            "--offline",
            str(blob),
        ]
        try:
            res = subprocess.run(  # noqa: S603 — known command, no shell
                cmd,
                check=False,
                capture_output=True,
                timeout=10.0,
            )
        except (OSError, subprocess.SubprocessError) as e:
            return VerificationResult(
                rule_id=entry.rule_id,
                verified=False,
                algorithm=algorithm,
                publisher=str(sig.get("publisher") or ""),
                reason=f"cosign_invoke_failed:{e}",
            )
        if res.returncode != 0:
            err = (res.stderr or b"").decode("utf-8", errors="replace")[:400]
            return VerificationResult(
                rule_id=entry.rule_id,
                verified=False,
                algorithm=algorithm,
                publisher=str(sig.get("publisher") or ""),
                reason=f"cosign_verify_failed:{err}",
            )

    return VerificationResult(
        rule_id=entry.rule_id,
        verified=True,
        algorithm=algorithm,
        publisher=str(sig.get("publisher") or ""),
        reason="ok",
    )


__all__ = [
    "SigningError",
    "VerificationFailed",
    "canonical_payload_bytes",
    "cosign_verify_entry",
    "ed25519_keygen",
    "ed25519_sign_entry",
    "ed25519_verify_entry",
]
