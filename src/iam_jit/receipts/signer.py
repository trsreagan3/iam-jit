"""Ed25519-signed denial receipts — #731 / BUILD-10.

When the bouncer DENIES a request it can emit a *denial receipt*: a
tamper-evident, Ed25519-signed JSON document recording that iam-jit
denied action X at time T for reason R, carrying a unique nonce so a
replayed receipt is detectable. An operator or auditor holding the
public key can later verify the receipt OFFLINE (no network) — and the
agent that triggered the deny cannot forge a receipt for a deny that
never happened, nor replay an old receipt as proof of a fresh one.

Honest framing — per ``[[ibounce-honest-positioning]]``:
    A receipt proves iam-jit's RECORD of the denial — that THIS bouncer
    denied THIS action at THIS time. It does NOT prove the agent was
    unable to act through some other channel, and it does NOT prove
    enforcement at the wire (a cooperative-mode deny is advisory). The
    receipt is proof-of-deny-record, not proof-of-prevention. The
    verifier output says so explicitly.

Crypto reuse — per the build spec we do NOT reinvent crypto. The
keypair management (``load_or_generate_keypair``), the URL-safe-base64
helpers, the canonical-JSON signing-payload discipline, and the
public-key embedding all mirror
``iam_jit.bouncer.audit_export.manifest``. The only divergence is the
default key NAME (``denial-receipt-ed25519``) so receipt-signing and
manifest-signing keys are separable by operators who want distinct
identities; an operator can point both at the same key by passing
``keypair_name="manifest-ed25519"``.

Composes with:
  * #427 / §A66 audit-chain + signed manifests (same crypto pattern)
  * #443 / §A48b structured-deny (the receipt's ``deny_id`` is the
    structured-deny ``deny_event_id`` so a 403 body, an audit row, and
    a receipt all share one correlation handle)
  * #463 audit-verify CLI (the receipt verifier mounts on the same
    ``iam-jit audit`` group as ``iam-jit audit verify-receipt``)

Per ``[[v1-scope-bar]]`` this slice is THIN: one signed payload per
deny, one persistent nonce store, one offline verifier. No key
rotation policy beyond "operator replaces the keypair"; no certificate
chains.

Per ``[[creates-never-mutates]]`` receipt emission is ADDITIVE — it
never mutates an existing deny decision or audit row. A receipt-signing
or nonce-store failure is FAIL-SOFT: it is logged + counted but NEVER
changes the deny verdict or breaks the hot path (the deny still
happens; the agent simply gets a deny without an attached receipt).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import logging
import os
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# REUSE the audit-export crypto primitives — do not reinvent. These are
# the exact helpers the signed-manifest path uses (#427).
from ..bouncer.audit_export import (
    load_or_generate_manifest_keypair as _load_or_generate_keypair,
    manifest_public_key_bytes as _public_key_bytes,
)
from ..bouncer.audit_export.manifest import _b64u, _b64u_decode

logger = logging.getLogger(__name__)

# Default key NAME under the shared ~/.iam-jit/audit-keys dir. Distinct
# from the manifest key name so the two signing identities are
# separable; operators wanting one identity pass keypair_name to match.
DEFAULT_RECEIPT_KEY_NAME = "denial-receipt-ed25519"

# Receipt payload schema version. Bump only when the SIGNED payload
# shape changes incompatibly. Verifiers reject unknown versions (a
# downgrade attack could otherwise strip a future safety field).
RECEIPT_SCHEMA_VERSION = 1

# Receipt verdict is always "deny" — we only mint receipts for denies.
RECEIPT_VERDICT = "deny"


def _public_key_fingerprint(pub_raw: bytes) -> str:
    """Short, stable fingerprint of an Ed25519 public key.

    SHA-256 of the 32 raw key bytes, hex, first 16 chars. Lets an
    operator eyeball "this receipt was signed by the same key as that
    one" without comparing full base64 blobs. Not load-bearing for
    verification (the embedded full key is) — purely a human aid.
    """
    return hashlib.sha256(pub_raw).hexdigest()[:16]


@dataclasses.dataclass(frozen=True)
class DenialReceipt:
    """A signed denial receipt.

    ``signature_b64`` covers the canonical-JSON of every field EXCEPT
    ``signature_b64`` + ``public_key_b64`` (the key is embedded for
    offline verification convenience but is not itself signed — pinning
    a key out-of-band defends against a swapped-keypair attacker).
    """

    schema_version: int
    deny_id: str
    """Correlation handle — the structured-deny ``deny_event_id``. Ties
    this receipt to the 403 body + the audit row for the same deny."""

    agent_session: str
    """Agent session id from the request (or "" when unknown). Lets an
    auditor group every deny issued against one agent run."""

    action: str
    """The denied action, e.g. ``s3:DeleteBucket`` (service:action) or
    bare action when the service is unknown."""

    resource: str
    """The target ARN/resource, or "" when not parsed."""

    reason: str
    """Short human label for WHY the deny fired."""

    verdict: str
    """Always ``"deny"`` (``RECEIPT_VERDICT``). Present in the signed
    payload so a verifier can assert it + so the shape is self-describing."""

    nonce: str
    """Cryptographically-random unique nonce (URL-safe base64). The
    persistent nonce store records every minted nonce; a receipt whose
    nonce is already recorded as *seen at verify time* is a replay."""

    timestamp: str
    """ISO-8601 UTC instant the deny was recorded (``...Z``)."""

    bouncer_product: str
    """Which Bounce product minted this (matches OCSF product name)."""

    public_key_fingerprint: str
    """SHA-256[:16] of the signing public key — human correlation aid."""

    signature_b64: str
    """URL-safe base64 (no padding) Ed25519 signature over
    :meth:`signing_payload`."""

    public_key_b64: str
    """URL-safe base64 (no padding) raw 32-byte Ed25519 public key."""

    def signing_payload(self) -> bytes:
        """Canonical-JSON bytes the signature covers. Used by both the
        signer (pre-sign) and the verifier (pre-verify)."""
        import json
        d = {
            "schema_version": self.schema_version,
            "deny_id": self.deny_id,
            "agent_session": self.agent_session,
            "action": self.action,
            "resource": self.resource,
            "reason": self.reason,
            "verdict": self.verdict,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "bouncer_product": self.bouncer_product,
            "public_key_fingerprint": self.public_key_fingerprint,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        """Operator-readable serialisable form (403 body, on-disk,
        webhook)."""
        return {
            "schema_version": self.schema_version,
            "deny_id": self.deny_id,
            "agent_session": self.agent_session,
            "action": self.action,
            "resource": self.resource,
            "reason": self.reason,
            "verdict": self.verdict,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "bouncer_product": self.bouncer_product,
            "public_key_fingerprint": self.public_key_fingerprint,
            "signature_b64": self.signature_b64,
            "public_key_b64": self.public_key_b64,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DenialReceipt":
        """Parse a receipt dict. Raises ValueError on unknown schema
        version (downgrade-attack guard, mirroring load_manifest_file)."""
        sv = raw.get("schema_version")
        if sv != RECEIPT_SCHEMA_VERSION:
            raise ValueError(
                f"denial receipt has unknown schema_version {sv!r}; "
                f"expected {RECEIPT_SCHEMA_VERSION}. Refusing to load — a "
                "downgrade attack could strip safety fields."
            )
        return cls(
            schema_version=int(raw["schema_version"]),
            deny_id=str(raw["deny_id"]),
            agent_session=str(raw.get("agent_session", "")),
            action=str(raw.get("action", "")),
            resource=str(raw.get("resource", "")),
            reason=str(raw.get("reason", "")),
            verdict=str(raw["verdict"]),
            nonce=str(raw["nonce"]),
            timestamp=str(raw["timestamp"]),
            bouncer_product=str(raw.get("bouncer_product", "")),
            public_key_fingerprint=str(raw.get("public_key_fingerprint", "")),
            signature_b64=str(raw["signature_b64"]),
            public_key_b64=str(raw["public_key_b64"]),
        )


class ReceiptSigner:
    """Stateful denial-receipt minter.

    Constructed once at proxy startup (when receipts are enabled); its
    :meth:`sign_deny` is called on each DENY decision to mint a receipt.
    Reads (or generates on first use) the Ed25519 keypair via the SAME
    primitive the manifest signer uses.

    Per ``[[ibounce-honest-positioning]]`` + the build's fail-soft
    requirement: :meth:`sign_deny` NEVER raises into the deny hot path.
    On any signing or nonce-store error it returns ``None`` (the caller
    proceeds with a receipt-less deny), logs a warning, and bumps
    ``receipts_failed`` so a SIEM/healthz dashboard can detect a
    degraded signer.
    """

    def __init__(
        self,
        *,
        bouncer_product: str = "ibounce",
        nonce_store: Any | None = None,
        keypair_dir: str | os.PathLike | None = None,
        keypair_name: str = DEFAULT_RECEIPT_KEY_NAME,
    ) -> None:
        self.bouncer_product = bouncer_product
        self.nonce_store = nonce_store
        kw: dict[str, Any] = {"name": keypair_name}
        if keypair_dir is not None:
            kw["dir"] = keypair_dir
        # Eager load/generate so an unwritable keypair-dir surfaces at
        # startup, not on the first deny.
        self._private, self._public = _load_or_generate_keypair(**kw)
        self._pub_raw = _public_key_bytes(self._public)
        self._pub_b64 = _b64u(self._pub_raw)
        self._fingerprint = _public_key_fingerprint(self._pub_raw)
        self.receipts_issued = 0
        self.receipts_failed = 0

    @property
    def public_key_b64(self) -> str:
        return self._pub_b64

    @property
    def public_key_fingerprint(self) -> str:
        return self._fingerprint

    def sign_deny(
        self,
        *,
        deny_id: str,
        action: str,
        reason: str,
        agent_session: str = "",
        resource: str = "",
        timestamp: str | None = None,
    ) -> DenialReceipt | None:
        """Mint a signed receipt for one DENY. Returns the receipt, or
        ``None`` on any failure (FAIL-SOFT — the deny still happens).

        Records the freshly-minted nonce in the persistent store so a
        later replay (same nonce presented twice at verify time) is
        detectable. A nonce-store write failure is non-fatal: we still
        return a valid signed receipt (the operator loses replay
        detection for that one receipt, but never the deny itself or the
        signature). The failure is logged + counted.
        """
        try:
            ts = timestamp or (
                _dt.datetime.now(tz=_dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
            # 256 bits of entropy → collision-free for any realistic
            # deny volume; URL-safe so the receipt JSON stays greppable.
            nonce = _b64u(secrets.token_bytes(32))
            unsigned = DenialReceipt(
                schema_version=RECEIPT_SCHEMA_VERSION,
                deny_id=str(deny_id),
                agent_session=str(agent_session or ""),
                action=str(action or ""),
                resource=str(resource or ""),
                reason=str(reason or ""),
                verdict=RECEIPT_VERDICT,
                nonce=nonce,
                timestamp=ts,
                bouncer_product=self.bouncer_product,
                public_key_fingerprint=self._fingerprint,
                signature_b64="",
                public_key_b64=self._pub_b64,
            )
            sig = self._private.sign(unsigned.signing_payload())
            signed = dataclasses.replace(unsigned, signature_b64=_b64u(sig))
        except Exception as e:  # noqa: BLE001 — fail-soft is the contract
            self.receipts_failed += 1
            logger.warning("denial-receipt signing failed (deny still issued): %s", e)
            return None

        # Record the nonce as MINTED. This is separate from the signing
        # try-block so a store failure doesn't void an already-good
        # signature: we still return the receipt.
        if self.nonce_store is not None:
            try:
                self.nonce_store.record_minted(nonce, deny_id=signed.deny_id, ts=ts)
            except Exception as e:  # noqa: BLE001 — fail-soft
                self.receipts_failed += 1
                logger.warning(
                    "denial-receipt nonce-store write failed (receipt still "
                    "issued; replay-detection unavailable for nonce): %s", e,
                )

        self.receipts_issued += 1
        return signed

    def status(self) -> dict[str, Any]:
        """Snapshot for /healthz + the MCP status tool."""
        return {
            "configured": True,
            "bouncer_product": self.bouncer_product,
            "receipts_issued": self.receipts_issued,
            "receipts_failed": self.receipts_failed,
            "public_key_b64": self._pub_b64,
            "public_key_fingerprint": self._fingerprint,
            "nonce_store": (
                self.nonce_store.status()
                if self.nonce_store is not None
                and hasattr(self.nonce_store, "status")
                else None
            ),
        }


def verify_receipt(
    receipt: DenialReceipt,
    *,
    public_key_override_b64: str | None = None,
) -> tuple[bool, str | None]:
    """Verify the Ed25519 signature on ``receipt`` (signature only —
    replay detection is the caller's separate nonce-store check).

    By default uses the embedded public key. Operators with stricter
    posture pass ``public_key_override_b64`` (pinned out-of-band).

    Returns ``(ok, reason)``; ``reason`` is None on success. Mirrors
    :func:`iam_jit.bouncer.audit_export.manifest.verify_manifest`.
    """
    if receipt.verdict != RECEIPT_VERDICT:
        return False, (
            f"receipt verdict is {receipt.verdict!r}, not "
            f"{RECEIPT_VERDICT!r} — only deny receipts are valid"
        )
    pub_b64 = public_key_override_b64 or receipt.public_key_b64
    try:
        pub_bytes = _b64u_decode(pub_b64)
    except Exception as e:  # noqa: BLE001
        return False, f"public key base64 decode failed: {e}"
    if len(pub_bytes) != 32:
        return False, (
            f"public key length {len(pub_bytes)} != 32 (Ed25519 raw key "
            "must be exactly 32 bytes)"
        )
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as e:  # noqa: BLE001
        return False, f"public key parse failed: {e}"
    try:
        sig_bytes = _b64u_decode(receipt.signature_b64)
    except Exception as e:  # noqa: BLE001
        return False, f"signature base64 decode failed: {e}"
    try:
        pub.verify(sig_bytes, receipt.signing_payload())
    except InvalidSignature:
        return False, (
            "signature does not match payload — receipt was tampered with "
            "or signed by a different key"
        )
    except Exception as e:  # noqa: BLE001
        return False, f"signature verification raised: {e}"
    return True, None


__all__ = [
    "DEFAULT_RECEIPT_KEY_NAME",
    "RECEIPT_SCHEMA_VERSION",
    "RECEIPT_VERDICT",
    "DenialReceipt",
    "ReceiptSigner",
    "verify_receipt",
]
