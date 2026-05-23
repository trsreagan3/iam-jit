"""#409 / §A53 — Threat-feed publisher tooling library.

Pure-library backend for ``iam-jit-feed-publish`` (the operator-facing
CLI in :mod:`iam_jit.threat_feed.cli_publisher`).

Workflow a publisher uses:

  1. ``init``  — generate an Ed25519 keypair + write private/public PEM
  2. ``sign``  — sign one rule YAML/JSON file → emit signed entry JSON
  3. ``bundle`` — bundle N signed entries into a feed.json
  4. ``verify`` — verify a feed.json against a pinned pubkey

Per [[push-policy-public-repo]] the private key MUST live OUTSIDE
the repo. The CLI defaults the private key path to
``~/.iam-jit/threat_feed/publisher.ed25519.pem`` and writes it 0600;
the public key goes to ``publisher.ed25519.pub`` (PEM) +
``publisher.ed25519.short`` (the ``ed25519:<b64>`` short-form
operators paste into their declarative config).

Per [[no-hosted-saas]] the publisher tool never talks to a server;
operators host their own feed JSON anywhere they like (S3, GitHub,
internal HTTP).
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import hashlib
import json
import logging
import pathlib
import typing

from .models import Feed, FeedEntry, parse_feed_dict, parse_feed_entry
from .signing import (
    SigningError,
    canonical_payload_bytes,
    ed25519_keygen,
    ed25519_sign_entry,
    ed25519_verify_entry,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PublisherError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Keygen
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class KeygenResult:
    private_pem_path: pathlib.Path
    public_pem_path: pathlib.Path
    public_short_path: pathlib.Path
    publisher: str
    short_form_pubkey: str

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "private_pem_path": str(self.private_pem_path),
            "public_pem_path": str(self.public_pem_path),
            "public_short_path": str(self.public_short_path),
            "publisher": self.publisher,
            "short_form_pubkey": self.short_form_pubkey,
        }


def _pem_to_short_form(public_pem: str) -> str:
    """Convert a PEM-encoded Ed25519 pubkey to the ``ed25519:<b64>``
    short form an operator pastes into the declarative config."""
    from cryptography.hazmat.primitives import serialization

    try:
        pk = serialization.load_pem_public_key(public_pem.encode("ascii"))
    except Exception as e:
        raise PublisherError(f"failed to parse public PEM: {e}") from e
    raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def publisher_init(
    *,
    out_dir: pathlib.Path,
    publisher: str,
    overwrite: bool = False,
) -> KeygenResult:
    """Generate + persist a fresh Ed25519 keypair for ``publisher``.

    Creates ``<out_dir>/publisher.ed25519.pem`` (private, 0600),
    ``<out_dir>/publisher.ed25519.pub`` (public PEM, 0644), and
    ``<out_dir>/publisher.ed25519.short`` (the short-form pubkey the
    operator pastes into the declarative config).

    Refuses to overwrite an existing private key unless
    ``overwrite=True`` — prevents accidental key rotation.
    """
    out_dir = out_dir.expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    private_path = out_dir / "publisher.ed25519.pem"
    public_path = out_dir / "publisher.ed25519.pub"
    short_path = out_dir / "publisher.ed25519.short"
    if private_path.exists() and not overwrite:
        raise PublisherError(
            f"refusing to overwrite existing private key at {private_path}; "
            f"pass overwrite=True to rotate"
        )
    private_pem, public_pem = ed25519_keygen()
    private_path.write_text(private_pem)
    try:
        private_path.chmod(0o600)
    except OSError:
        pass
    public_path.write_text(public_pem)
    short_form = _pem_to_short_form(public_pem)
    short_path.write_text(short_form + "\n")
    return KeygenResult(
        private_pem_path=private_path,
        public_pem_path=public_path,
        public_short_path=short_path,
        publisher=publisher,
        short_form_pubkey=short_form,
    )


# ---------------------------------------------------------------------------
# Rule-file loading
# ---------------------------------------------------------------------------


def _load_rule_dict(path: pathlib.Path) -> dict[str, typing.Any]:
    """Load a rule file (JSON or YAML) into a dict."""
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".json",):
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise PublisherError(f"{path}: invalid JSON: {e}") from e
    if suffix in (".yaml", ".yml"):
        try:
            from ruamel.yaml import YAML  # type: ignore

            yaml = YAML(typ="safe")
            return yaml.load(text)
        except Exception as e:
            raise PublisherError(f"{path}: invalid YAML: {e}") from e
    # Default: try JSON first then YAML.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            from ruamel.yaml import YAML  # type: ignore

            yaml = YAML(typ="safe")
            return yaml.load(text)
        except Exception as e:
            raise PublisherError(f"{path}: could not parse as JSON or YAML: {e}") from e


def sign_rule_file(
    rule_path: pathlib.Path,
    *,
    private_key_pem: str,
    publisher: str,
    key_id: str = "",
) -> FeedEntry:
    """Load + sign one rule file. Returns the signed :class:`FeedEntry`.

    The input file's ``signature`` field is IGNORED (if present);
    callers typically author rules without one + this function fills
    it in.
    """
    raw = _load_rule_dict(rule_path)
    if "signature" in raw:
        raw = dict(raw)
        raw.pop("signature", None)
    entry = parse_feed_entry(raw)
    return ed25519_sign_entry(
        entry,
        private_key_pem=private_key_pem,
        publisher=publisher,
        key_id=key_id,
    )


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _manifest_sha256(entries: typing.Sequence[FeedEntry]) -> str:
    """Stable hash over the bundle's signed payloads — drives the
    fetcher's change-detection."""
    h = hashlib.sha256()
    for e in entries:
        h.update(canonical_payload_bytes(e))
        sig_val = (e.signature or {}).get("value", "")
        h.update(b"|")
        h.update(str(sig_val).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def bundle_entries(
    entries: typing.Sequence[FeedEntry],
    *,
    feed_id: str,
    publisher: str,
    schema_version: str = "1.0",
) -> Feed:
    """Bundle pre-signed entries into a :class:`Feed`."""
    manifest = _manifest_sha256(entries)
    return Feed(
        schema_version=schema_version,
        feed_id=feed_id,
        publisher=publisher,
        generated_at=_now_iso(),
        entries=tuple(entries),
        manifest_sha256=manifest,
    )


def write_bundle(
    feed: Feed,
    out_path: pathlib.Path,
) -> pathlib.Path:
    """Serialize a feed to disk as canonical JSON. Returns the path."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(feed.as_dict(), indent=2, sort_keys=True),
    )
    return out_path


# ---------------------------------------------------------------------------
# Verify a bundle file
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class VerifyBundleResult:
    feed_id: str
    publisher: str
    entry_count: int
    verified: int
    failed: int
    failures: tuple[tuple[str, str], ...]

    @property
    def all_verified(self) -> bool:
        return self.failed == 0 and self.verified > 0

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "feed_id": self.feed_id,
            "publisher": self.publisher,
            "entry_count": self.entry_count,
            "verified": self.verified,
            "failed": self.failed,
            "all_verified": self.all_verified,
            "failures": [
                {"rule_id": rid, "reason": reason}
                for rid, reason in self.failures
            ],
        }


def verify_bundle(
    bundle_path: pathlib.Path,
    *,
    pubkey: str,
) -> VerifyBundleResult:
    """Verify every entry in a bundle file against a pinned pubkey.

    Returns a structured outcome. ``failures`` enumerates per-entry
    rejection reasons so a publisher debugging a botched signing run
    can see exactly which entries failed."""
    raw = json.loads(bundle_path.read_text(encoding="utf-8"))
    feed = parse_feed_dict(raw)
    verified = 0
    failures: list[tuple[str, str]] = []
    for entry in feed.entries:
        r = ed25519_verify_entry(entry, publisher_pubkey=pubkey)
        if r.verified:
            verified += 1
        else:
            failures.append((entry.rule_id, r.reason))
    return VerifyBundleResult(
        feed_id=feed.feed_id,
        publisher=feed.publisher,
        entry_count=len(feed.entries),
        verified=verified,
        failed=len(failures),
        failures=tuple(failures),
    )


__all__ = [
    "KeygenResult",
    "PublisherError",
    "VerifyBundleResult",
    "bundle_entries",
    "publisher_init",
    "sign_rule_file",
    "verify_bundle",
    "write_bundle",
]
