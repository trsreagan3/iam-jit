"""Ed25519-signed chain-checkpoint manifests — #427 / §A66.

Closes the second half of the §A66 LAUNCH-BLOCKER (the first half
is the hash-chain itself in ``chain.py``). The hash-chain on its
own detects in-place edits + reordering + deletion in the MIDDLE
of the chain. It does NOT detect TRUNCATION OF THE TAIL — an
attacker who can append arbitrary rows to the JSONL can build a
forged chain that re-verifies clean, just shorter than reality.

The fix (standard pattern from Splunk / OSSEC / Wazuh) is
periodic SIGNED MANIFESTS shipped to an external party. Each
manifest is an Ed25519-signed JSON document recording the chain
head's (seq, hash) at the moment of emission. Anyone holding the
public key can verify post-hoc that the JSONL file's chain head
at any historical manifest's seq has the matching hash; a quietly-
truncated chain shows a missing seq or a hash mismatch.

Per ``[[v1-scope-bar]]`` this slice is THIN: one keypair, one
signed payload per checkpoint, one verifier. No certificate
chains, no rotation policy beyond "operator replaces the keypair
when their security policy dictates". The full lifecycle (key
rotation, hardware-token signing, etc.) is post-launch.

Per ``[[creates-never-mutates]]`` the manifest emission is ADDITIVE
— it never modifies an existing event. Manifests land in
``<log_dir>/manifests/manifest-{seq_start}-{seq_end}-{ts}.json``;
the JSONL stream is untouched.

Per ``[[push-policy-public-repo]]`` the private key is NEVER
committed. ``load_or_generate_keypair`` writes to
``~/.iam-jit/audit-keys/manifest-ed25519.{priv,pub}`` with
0o600/0o644 perms; the .gitignore in this repo excludes
``~/.iam-jit/`` by definition (operator-local state, never
in-tree).

Per ``[[no-hosted-saas]]`` iam-jit-the-company NEVER receives the
manifest — the operator decides where to ship it (S3 with object-
lock, GitHub Actions secret, Splunk index, a Slack channel ...).

Composes with #257 webhook adapters: manifests are themselves
OCSF-shaped events that can ride the same webhook channel as
decision events (``activity_name=audit_chain_checkpoint``). The
``ChainCheckpointEvent`` builder makes that easy.

Composes with #235 Ed25519 license keygen (founder-pending): when
that lands, this module will REUSE the same keypair-generation
pattern (currently inlined here as a placeholder so the launch-
blocker doesn't sit on #235). See the docstring on
``load_or_generate_keypair`` for the migration path.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import logging
import os
import pathlib
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .chain import CHAIN_STATE_SCHEMA_VERSION, ChainState

logger = logging.getLogger(__name__)

# Default keypair location. Per the docstring this is operator-local
# state (~/.iam-jit/) so it never ends up in-tree. The two files are
# the conventional split: .priv for the private key (0o600), .pub for
# the public key (0o644, may be shared with verifiers).
DEFAULT_KEYPAIR_DIR = "~/.iam-jit/audit-keys"
DEFAULT_KEYPAIR_NAME = "manifest-ed25519"
PRIVATE_KEY_SUFFIX = ".priv"
PUBLIC_KEY_SUFFIX = ".pub"

# Default checkpoint cadence: emit a manifest every N events. 1000
# matches the §A66 spec ("every N entries, default 1000"). Operators
# can tune via the ManifestSigner's `interval` arg.
DEFAULT_MANIFEST_INTERVAL_EVENTS = 1000

# Where manifests land inside the audit log dir. Filename includes
# the seq range so a `ls` shows the chronological coverage at a
# glance + so external archiving doesn't need to read each file
# to determine which range it covers.
MANIFEST_DIR_NAME = "manifests"
MANIFEST_FILENAME_TEMPLATE = "manifest-{seq_start:012d}-{seq_end:012d}-{ts}.json"

# Manifest payload schema version. Bump when (and only when) the
# signed-payload shape changes in a way an older verifier can't
# read. Verifiers MUST treat unknown versions as failure (not as
# "old verifier ignoring new fields") so a downgrade attack can't
# strip a new safety field.
MANIFEST_SCHEMA_VERSION = 1

# Constant strings for the OCSF event surface (when the operator
# pushes manifests through the webhook channel alongside decision
# events). Class 6003 (API Activity) is reused because the existing
# audit-export pipeline already speaks it; activity_name is a fresh
# value so SIEM rules can pattern-match on this event class.
MANIFEST_OCSF_ACTIVITY_NAME = "audit_chain_checkpoint"
MANIFEST_OCSF_TYPE_NAME = "API Activity: audit_chain_checkpoint"


@dataclasses.dataclass(frozen=True)
class Manifest:
    """An emitted (signed) chain-checkpoint manifest.

    Both ``signature`` and ``public_key_b64`` are base64-encoded
    (URL-safe, no padding) so the JSON payload is operator-friendly
    in CLI output + greppable for forensics. The hash chain itself
    uses hex; the keypair stuff uses base64 because that's the
    convention every Ed25519 library / SSH tool defaults to.
    """

    schema_version: int
    """Always equals ``MANIFEST_SCHEMA_VERSION`` at emit time. The
    verifier rejects unknown versions."""

    seq_start: int
    """Earliest chain seq covered by this manifest (inclusive).
    Genesis manifest = 0; subsequent manifests start at the previous
    manifest's ``seq_end + 1`` but that adjacency is OPTIONAL — the
    operator is free to emit manifests on any cadence."""

    seq_end: int
    """Latest chain seq covered (inclusive). Equals chain head at
    emit time."""

    head_hash: str
    """Hash of the row at ``seq_end``. Verifiers compare this against
    the JSONL row at the same seq to detect tail truncation +
    historical edits at or before ``seq_end``."""

    generated_at_iso: str
    """ISO-8601 UTC timestamp of emit. Informational; verification
    relies on hash + seq, not on this timestamp."""

    bouncer_product: str
    """Which Bounce product emitted this. Same string as
    ``metadata.product.name`` in OCSF events."""

    log_dir: str
    """The audit log directory the manifest anchors. Used by the
    verifier to find the JSONL when given a manifest alone."""

    signature_b64: str
    """URL-safe base64 (no padding) of the Ed25519 signature over
    the canonical-JSON-serialised payload (everything in this
    dataclass except signature_b64 + public_key_b64)."""

    public_key_b64: str
    """URL-safe base64 (no padding) of the Ed25519 public key bytes.
    Embedded in every manifest so the verifier doesn't need an
    external truststore for the common case. Operators with stricter
    posture can ignore this field + pin a key out-of-band."""

    def signing_payload(self) -> bytes:
        """Re-derive the bytes that ``signature_b64`` covers.

        Used by both the signer (right before calling ``sign()``) and
        the verifier (right before calling ``verify()``). The payload
        is canonical-JSON-encoded so byte-equality is recoverable
        across Python versions + JSON encoder differences.
        """
        d = {
            "schema_version": self.schema_version,
            "seq_start": self.seq_start,
            "seq_end": self.seq_end,
            "head_hash": self.head_hash,
            "generated_at_iso": self.generated_at_iso,
            "bouncer_product": self.bouncer_product,
            "log_dir": self.log_dir,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        """Serialisable form (operator-readable; safe for webhook
        bodies + on-disk persistence)."""
        return {
            "schema_version": self.schema_version,
            "seq_start": self.seq_start,
            "seq_end": self.seq_end,
            "head_hash": self.head_hash,
            "generated_at_iso": self.generated_at_iso,
            "bouncer_product": self.bouncer_product,
            "log_dir": self.log_dir,
            "signature_b64": self.signature_b64,
            "public_key_b64": self.public_key_b64,
        }


def _b64u(data: bytes) -> str:
    """URL-safe base64 with stripped padding (RFC 4648 §5)."""
    import base64
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    """Inverse of ``_b64u``."""
    import base64
    # Restore padding for the stdlib decoder.
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def load_or_generate_keypair(
    *,
    dir: str | os.PathLike = DEFAULT_KEYPAIR_DIR,
    name: str = DEFAULT_KEYPAIR_NAME,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Load the operator's manifest-signing keypair, generating it
    on first call.

    Per ``[[push-policy-public-repo]]`` the private key is NEVER
    committed: the default ``dir`` is under ``~/.iam-jit/`` which
    lives outside any source tree by convention. ``dir`` is
    created with 0o700 if absent. The .priv file is 0o600; .pub is
    0o644.

    Per ``[[v1-scope-bar]]`` we generate a fresh keypair on first
    use rather than waiting on #235 (Ed25519 license keygen) to
    ship. When #235 lands, this function migrates to reuse the
    SAME keypair-generation primitive — see the migration TODO in
    the module docstring.

    Returns ``(private_key, public_key)`` for the in-process signer.
    The next call (same dir + name) returns the SAME keypair so
    every manifest signs with one stable identity.
    """
    d = pathlib.Path(os.path.expanduser(str(dir)))
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        # Operator umask may refuse; not fatal — the key files
        # themselves carry the 0o600 perm which is what actually
        # protects the secret.
        pass
    priv_path = d / f"{name}{PRIVATE_KEY_SUFFIX}"
    pub_path = d / f"{name}{PUBLIC_KEY_SUFFIX}"
    if priv_path.is_file():
        priv_bytes = priv_path.read_bytes()
        priv = serialization.load_pem_private_key(
            priv_bytes, password=None,
        )
        if not isinstance(priv, Ed25519PrivateKey):
            raise RuntimeError(
                f"key at {priv_path} is not Ed25519 — refusing to use. "
                "Move it aside and re-run to regenerate, or point "
                "the bouncer at a different --audit-manifest-keypair-dir."
            )
        return priv, priv.public_key()
    # Generate a fresh keypair. The PEM serialisation is the form
    # other operator tooling (openssl, ssh-keygen, age) recognises;
    # ed25519-specific raw-bytes serialisation is less interop-
    # friendly.
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Write atomically with the right perms.
    priv_fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(priv_fd, priv_pem)
    finally:
        os.close(priv_fd)
    pub_fd = os.open(str(pub_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(pub_fd, pub_pem)
    finally:
        os.close(pub_fd)
    logger.info(
        "generated Ed25519 manifest-signing keypair at %s (.priv 0o600, "
        ".pub 0o644). Operator should replace post-launch per "
        "audit-key-rotation policy.",
        d,
    )
    return priv, pub


def public_key_bytes(pub: Ed25519PublicKey) -> bytes:
    """Raw 32-byte public key for embedding in manifests."""
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class ManifestSigner:
    """Stateful manifest emitter wired into the audit-log writer.

    Lifecycle::

        signer = ManifestSigner(
            log_dir="/var/log/ibounce",
            bouncer_product="ibounce",
            interval=1000,
        )
        # After every successful stamped event:
        if signer.should_emit(chain_state):
            signer.emit(chain_state)

    The emitted manifest covers ``[last_emitted_seq + 1, head_seq]``
    so each manifest's range is contiguous with the previous one.
    The genesis manifest covers ``[0, head_seq]``.

    The signer reads its keypair from disk on construction; if
    absent it generates one. Per ``[[deliberate-feature-completion]]``
    the operator's first run lands a usable keypair + the .pub file
    is greppable for exfiltration to their verifier.

    Per ``[[ibounce-honest-positioning]]`` emit failures are
    logged + counted; they do NOT block the chain. A SIEM dashboard
    can monitor ``manifests_failed`` to detect a degraded signer.
    """

    def __init__(
        self,
        *,
        log_dir: str | os.PathLike,
        bouncer_product: str = "ibounce",
        interval: int = DEFAULT_MANIFEST_INTERVAL_EVENTS,
        keypair_dir: str | os.PathLike = DEFAULT_KEYPAIR_DIR,
        keypair_name: str = DEFAULT_KEYPAIR_NAME,
    ) -> None:
        self.log_dir = str(log_dir)
        self.bouncer_product = bouncer_product
        self.interval = max(1, int(interval))
        self._private, self._public = load_or_generate_keypair(
            dir=keypair_dir, name=keypair_name,
        )
        self._pub_b64 = _b64u(public_key_bytes(self._public))
        self.last_emitted_seq: int | None = None
        """Seq of the head of the most-recent emitted manifest, or
        None when no manifest has been emitted yet."""
        self.manifests_emitted = 0
        self.manifests_failed = 0
        # Manifest output dir; created lazily on first emit.
        self.manifest_dir = pathlib.Path(self.log_dir) / MANIFEST_DIR_NAME

    def should_emit(self, state: ChainState) -> bool:
        """True when the chain head has advanced ``interval`` events
        past the last emitted manifest. Genesis manifest fires once
        the first ``interval`` events have been stamped.

        Defensive: the comparison is "has the head advanced by
        interval since last emit" rather than "is head a multiple
        of interval" so a chain that restarts mid-interval still
        emits on cadence.
        """
        head = state.next_seq - 1  # seq of the last stamped event
        if head < 0:
            return False
        if self.last_emitted_seq is None:
            return head + 1 >= self.interval
        return (head - self.last_emitted_seq) >= self.interval

    def emit(self, state: ChainState) -> Manifest | None:
        """Sign + persist a manifest covering the current chain head.

        Returns the emitted Manifest, or None on failure (which is
        also surfaced via ``manifests_failed``). Idempotency:
        callers should gate on ``should_emit`` first; calling
        ``emit`` on a chain that hasn't advanced is allowed but
        produces a manifest with seq_start = seq_end.

        Per ``[[ibounce-honest-positioning]]`` failures are visible
        via the counter; we never silently swallow a failed emit.
        """
        head = state.next_seq - 1
        if head < 0 or state.last_hash is None:
            return None
        seq_start = (
            self.last_emitted_seq + 1
            if self.last_emitted_seq is not None
            else 0
        )
        seq_end = head
        if seq_start > seq_end:
            seq_start = seq_end
        generated_at = (
            _dt.datetime.now(tz=_dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        # Build the manifest WITHOUT signature first, then derive the
        # signing payload + sign. We assemble the final manifest with
        # the signature attached.
        unsigned = Manifest(
            schema_version=MANIFEST_SCHEMA_VERSION,
            seq_start=seq_start,
            seq_end=seq_end,
            head_hash=state.last_hash,
            generated_at_iso=generated_at,
            bouncer_product=self.bouncer_product,
            log_dir=self.log_dir,
            signature_b64="",
            public_key_b64=self._pub_b64,
        )
        try:
            sig_bytes = self._private.sign(unsigned.signing_payload())
        except Exception as e:
            self.manifests_failed += 1
            logger.warning("manifest signing failed: %s", e)
            return None
        signed = dataclasses.replace(unsigned, signature_b64=_b64u(sig_bytes))
        try:
            self.manifest_dir.mkdir(parents=True, exist_ok=True)
            ts_for_filename = generated_at.replace(":", "").replace("-", "")
            out = self.manifest_dir / MANIFEST_FILENAME_TEMPLATE.format(
                seq_start=seq_start,
                seq_end=seq_end,
                ts=ts_for_filename,
            )
            tmp = out.with_suffix(out.suffix + ".tmp")
            fd = os.open(
                str(tmp),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o644,
            )
            try:
                os.write(
                    fd,
                    (json.dumps(signed.to_dict(), indent=2, sort_keys=True) + "\n")
                    .encode("utf-8"),
                )
            finally:
                os.close(fd)
            os.replace(str(tmp), str(out))
        except OSError as e:
            self.manifests_failed += 1
            logger.warning("manifest persist failed: %s", e)
            return None
        self.manifests_emitted += 1
        self.last_emitted_seq = seq_end
        return signed

    def build_ocsf_event(self, manifest: Manifest) -> dict[str, Any]:
        """Wrap a manifest as an OCSF event suitable for emit on the
        existing audit-export channels (JSONL + webhook + S3).

        This is the integration seam for #257 webhook adapters: the
        operator's Splunk/Datadog/SIEM pipeline receives a signed
        checkpoint inline with the decision events it's already
        consuming, no separate transport needed.
        """
        ts_ms = int(time.time() * 1000)
        return {
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": self.bouncer_product,
                    "vendor_name": "iam-jit",
                },
            },
            "class_uid": 6003,
            "class_name": "API Activity",
            "category_uid": 6,
            "category_name": "Application Activity",
            "activity_id": 99,
            "activity_name": MANIFEST_OCSF_ACTIVITY_NAME,
            "type_uid": 600399,
            "type_name": MANIFEST_OCSF_TYPE_NAME,
            "severity_id": 1,
            "severity": "Informational",
            "time": ts_ms,
            "status_id": 1,
            "status": "Success",
            "unmapped": {
                "iam_jit": {
                    "manifest": manifest.to_dict(),
                    "chain_state_schema_version": CHAIN_STATE_SCHEMA_VERSION,
                },
            },
        }

    def status(self) -> dict[str, Any]:
        """Snapshot for /healthz + the MCP status tool."""
        return {
            "configured": True,
            "interval_events": self.interval,
            "last_emitted_seq": self.last_emitted_seq,
            "manifests_emitted": self.manifests_emitted,
            "manifests_failed": self.manifests_failed,
            "manifest_dir": str(self.manifest_dir),
            "public_key_b64": self._pub_b64,
        }


def load_manifest_file(path: str | os.PathLike) -> Manifest:
    """Read + parse a manifest from disk. Does NOT verify the
    signature — see ``verify_manifest``."""
    p = pathlib.Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    if raw.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            f"manifest at {p} has unknown schema_version "
            f"{raw.get('schema_version')!r}; expected "
            f"{MANIFEST_SCHEMA_VERSION}. Refusing to load — a downgrade "
            "attack could strip safety fields."
        )
    return Manifest(
        schema_version=raw["schema_version"],
        seq_start=int(raw["seq_start"]),
        seq_end=int(raw["seq_end"]),
        head_hash=raw["head_hash"],
        generated_at_iso=raw["generated_at_iso"],
        bouncer_product=raw["bouncer_product"],
        log_dir=raw["log_dir"],
        signature_b64=raw["signature_b64"],
        public_key_b64=raw["public_key_b64"],
    )


# key_trust values surfaced by :func:`verify_manifest`. Mirror the
# exact values used by the receipt verifier (``receipts.signer``) so
# callers treat them identically.
#   * "pinned"            — caller passed an explicit out-of-band key
#                           (``public_key_override_b64``). Strongest:
#                           the operator asserted the expected issuer.
#   * "local"             — no explicit pin, but the local on-disk
#                           ``manifest-ed25519.pub`` existed and we
#                           auto-pinned to IT (the common same-host
#                           verify case: you're verifying on the box
#                           that signed). Issuer trust = "this host's
#                           key".
#   * "embedded_unpinned" — no pin AND no local key; we fell back to
#                           the manifest's OWN embedded key. The
#                           signature may be well-formed, but a forged
#                           manifest carries a forged keypair — the
#                           ISSUER IS NOT VERIFIED.
KEY_TRUST_PINNED = "pinned"
KEY_TRUST_LOCAL = "local"
KEY_TRUST_EMBEDDED_UNPINNED = "embedded_unpinned"

# Human-facing caveat appended whenever trust is embedded_unpinned.
# Both the CLI and MCP surfaces reuse this exact string so the honest
# framing is identical everywhere.
MANIFEST_EMBEDDED_UNPINNED_CAVEAT = (
    "signature is well-formed but the ISSUER is NOT verified — pin the "
    "expected key (--public-key) or verify on the signing host to "
    "establish issuer trust"
)


def _load_local_manifest_public_key_b64(
    *,
    keypair_dir: str | os.PathLike | None = None,
    keypair_name: str = DEFAULT_KEYPAIR_NAME,
) -> str | None:
    """Return the URL-safe-base64 raw public key of the LOCAL on-disk
    manifest-signing key, or ``None`` if no local key exists.

    This is the auto-pin source for the common same-host verify case:
    the operator verifies a manifest on the very host that signed it,
    so the on-disk ``manifest-ed25519.pub`` is the authoritative
    issuer key — strictly better than trusting the manifest's own
    embedded key. We READ ONLY; we never generate a key here
    (generating would defeat the point — a missing key must surface as
    ``embedded_unpinned``, not silently mint a new trust anchor).
    """
    d = pathlib.Path(
        os.path.expanduser(
            str(keypair_dir if keypair_dir is not None else DEFAULT_KEYPAIR_DIR)
        )
    )
    pub_path = d / f"{keypair_name}{PUBLIC_KEY_SUFFIX}"
    if not pub_path.is_file():
        return None
    try:
        pub = serialization.load_pem_public_key(pub_path.read_bytes())
        if not isinstance(pub, Ed25519PublicKey):
            return None
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64u(raw)
    except Exception as e:  # noqa: BLE001 — a corrupt local key falls back
        logger.warning(
            "local manifest public key at %s unreadable; falling back to "
            "embedded key (issuer unverified): %s", pub_path, e,
        )
        return None  # noqa: SD-4 — intentional fallback; caller treats None as "no local key"


def verify_manifest(
    manifest: Manifest,
    *,
    public_key_override_b64: str | None = None,
    keypair_dir: str | os.PathLike | None = None,
    keypair_name: str = DEFAULT_KEYPAIR_NAME,
    auto_pin_local: bool = True,
) -> tuple[bool, str | None, str]:
    """Verify the Ed25519 signature on ``manifest``.

    TRUST ESTABLISHMENT (the security-load-bearing part — NOT a crypto
    change). A well-formed signature only proves SOMEONE signed the
    payload; it does not prove iam-jit signed it, because a forged
    manifest carries the attacker's OWN public key. We therefore
    choose the verifying key in this priority order and report which
    we used via the returned ``key_trust``:

      1. ``public_key_override_b64`` — explicit out-of-band pin →
         ``key_trust="pinned"`` (strongest).
      2. else, if ``auto_pin_local`` and the local on-disk
         ``manifest-ed25519.pub`` exists → auto-pin to THAT key →
         ``key_trust="local"`` (closes the gap for the common case of
         verifying on the signing host).
      3. else, the manifest's OWN embedded key →
         ``key_trust="embedded_unpinned"``. The signature may verify
         but the ISSUER IS NOT VERIFIED; callers MUST surface
         :data:`MANIFEST_EMBEDDED_UNPINNED_CAVEAT`.

    Returns ``(ok, reason, key_trust)``; ``reason`` is None on
    success.
    """
    if public_key_override_b64:
        pub_b64 = public_key_override_b64
        key_trust = KEY_TRUST_PINNED
    else:
        local_b64 = (
            _load_local_manifest_public_key_b64(
                keypair_dir=keypair_dir, keypair_name=keypair_name,
            )
            if auto_pin_local
            else None
        )
        if local_b64 is not None:
            pub_b64 = local_b64
            key_trust = KEY_TRUST_LOCAL
        else:
            pub_b64 = manifest.public_key_b64
            key_trust = KEY_TRUST_EMBEDDED_UNPINNED
    try:
        pub_bytes = _b64u_decode(pub_b64)
    except Exception as e:  # noqa: BLE001
        return False, f"public key base64 decode failed: {e}", key_trust
    if len(pub_bytes) != 32:
        return False, (
            f"public key length {len(pub_bytes)} != 32 (Ed25519 raw "
            "key must be exactly 32 bytes)"
        ), key_trust
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as e:  # noqa: BLE001
        return False, f"public key parse failed: {e}", key_trust
    try:
        sig_bytes = _b64u_decode(manifest.signature_b64)
    except Exception as e:  # noqa: BLE001
        return False, f"signature base64 decode failed: {e}", key_trust
    try:
        pub.verify(sig_bytes, manifest.signing_payload())
    except InvalidSignature:
        # When we auto-pinned to the local key, a mismatch is the
        # forged-issuer case: the manifest was signed by a DIFFERENT
        # key than this host's. Make that explicit.
        if key_trust == KEY_TRUST_LOCAL:
            return False, (
                "signature does not match payload under the LOCAL signing "
                "key — manifest was tampered with or signed by a different "
                "(possibly forged) key than this host's manifest-ed25519"
            ), key_trust
        return False, (
            "signature does not match payload — manifest was tampered with "
            "or signed by a different key"
        ), key_trust
    except Exception as e:  # noqa: BLE001
        return False, f"signature verification raised: {e}", key_trust
    return True, None, key_trust


def list_manifests(log_dir: str | os.PathLike) -> list[pathlib.Path]:
    """Return all manifest files under ``log_dir/manifests/`` sorted
    by seq_start. Empty list when the dir is missing or empty."""
    p = pathlib.Path(log_dir) / MANIFEST_DIR_NAME
    if not p.is_dir():
        return []
    out: list[pathlib.Path] = []
    for child in p.iterdir():
        if child.name.startswith("manifest-") and child.name.endswith(".json"):
            out.append(child)
    out.sort(key=lambda c: c.name)
    return out


__all__ = [
    "DEFAULT_KEYPAIR_DIR",
    "DEFAULT_KEYPAIR_NAME",
    "DEFAULT_MANIFEST_INTERVAL_EVENTS",
    "KEY_TRUST_EMBEDDED_UNPINNED",
    "KEY_TRUST_LOCAL",
    "KEY_TRUST_PINNED",
    "MANIFEST_DIR_NAME",
    "MANIFEST_EMBEDDED_UNPINNED_CAVEAT",
    "MANIFEST_FILENAME_TEMPLATE",
    "MANIFEST_OCSF_ACTIVITY_NAME",
    "MANIFEST_OCSF_TYPE_NAME",
    "MANIFEST_SCHEMA_VERSION",
    "PRIVATE_KEY_SUFFIX",
    "PUBLIC_KEY_SUFFIX",
    "Manifest",
    "ManifestSigner",
    "list_manifests",
    "load_manifest_file",
    "load_or_generate_keypair",
    "public_key_bytes",
    "verify_manifest",
]
