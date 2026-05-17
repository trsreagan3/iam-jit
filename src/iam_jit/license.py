"""License-file scaffolding + 25-user soft cap.

Implements [[user-count-soft-cap]]: Free tier supports up to 25
users; beyond that, the user-store rejects new user creation with a
clear message. An offline-signed Ed25519 license file raises the
cap. No phone home, no telemetry, no licensing call-back — per
[[self-host-zero-billing-dependency]].

Trust model:
- The product binary embeds the **public** verification key.
- The founder holds the **private** key offline and signs license
  files for paying customers.
- License files are JSON with an `ed25519` detached signature over
  the canonical payload bytes.
- Verification is fully local: signature check + expiry check, no
  network call. A user without a license file just gets the Free
  tier (cap=25).

License-file shape (`~/.iam-jit/license.json` by default, or path
in `IAM_JIT_LICENSE_FILE`):

  {
    "payload": {
      "tier": "enterprise" | "team" | "pro",
      "issued_to": "Customer Co.",
      "issued_at": "2026-05-17T00:00:00Z",
      "expires_at": "2027-05-17T00:00:00Z",
      "max_users": 250,
      "license_id": "lic_<random>"
    },
    "signature": "<base64 ed25519 signature over canonical_json(payload)>"
  }

Bypass-honest: anyone with the source can patch out the gate; the
contract is the legal artifact, not the code. The cap exists to
make accidental over-use friction-visible (Sentry / Mattermost
pattern). See [[user-count-soft-cap]].
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import json
import logging
import os
import pathlib
from typing import Any

logger = logging.getLogger(__name__)

# WB30+: this is the PRODUCTION verification public key. It is bytes
# (raw Ed25519 public key, 32 bytes, base64-encoded for embedding in
# source). The corresponding private key MUST NOT be committed to the
# repo and MUST be held offline by the founder for signing license
# files. Rotating this constant invalidates all previously-issued
# licenses; do so only with a customer-comms plan.
#
# Placeholder format (32-byte all-zero key). Replace with the real
# production key before the v1.0 release tag. Until then, no real
# license can verify; everyone runs on the Free tier (which is what
# we want pre-launch anyway).
PRODUCTION_PUBLIC_KEY_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# WB31 CRIT-31-00 closure: defense-in-depth against the placeholder
# slipping into a release build. If the production key is still the
# all-zero sentinel, `verify_license_bytes` refuses to verify ANYTHING
# — preventing the "appears-to-work, silently-accepts-nothing" failure
# mode where a forked Ed25519 implementation (e.g. older pynacl, some
# Go impls) might accept trivial forges against the identity pubkey.
#
# The CI release gate (`tests/test_license_placeholder_gate.py`)
# greps for this constant and fails the build if it's still the
# sentinel — that's the launch-block enforcement. This runtime guard
# is the defense-in-depth layer.
_PLACEHOLDER_KEY_SENTINEL = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
_PLACEHOLDER_KEY_IN_USE = (PRODUCTION_PUBLIC_KEY_B64 == _PLACEHOLDER_KEY_SENTINEL)
if _PLACEHOLDER_KEY_IN_USE:
    logger.warning(
        "iam-jit license: PRODUCTION_PUBLIC_KEY_B64 is the all-zero "
        "placeholder. License verification will refuse all licenses "
        "(Free-tier-only build). This is correct for pre-launch but "
        "MUST be replaced with the real production key before the "
        "v1.0 release tag."
    )

# Free-tier soft cap. Aligned with Sentry's 100 users (we run lower
# because iam-jit's per-user surface is heavier per [[no-hosted-saas]]
# self-host-only positioning + audit-chain growth).
FREE_TIER_MAX_USERS = 25

# Environment variable that overrides the license file path. Set
# this in `iam-jit serve` deployments to point at the bundled
# license. If unset, the default path is `~/.iam-jit/license.json`.
LICENSE_PATH_ENV = "IAM_JIT_LICENSE_FILE"

# Tier vocabulary. Aligned with [[no-hosted-saas]] tier shape.
KNOWN_TIERS = frozenset({"free", "pro", "team", "enterprise"})


class LicenseError(Exception):
    """Base class for license-related errors."""


class LicenseInvalidError(LicenseError):
    """License file exists but failed verification — bad signature,
    expired, malformed, or wrong public key. Caller falls back to
    Free tier."""


class UserCapExceededError(Exception):
    """Raised by the user store when a new-user creation would put
    the total over the current license cap.

    Existing users keep working; only the *next* creation is gated.
    Message is admin-facing — include the cap + tier so the operator
    knows how to act."""


@dataclasses.dataclass(frozen=True)
class License:
    """An accepted (verified) license. Fields are derived from the
    signed payload; the consumer never has to call back into the
    file."""

    tier: str
    issued_to: str
    issued_at: _dt.datetime
    expires_at: _dt.datetime
    max_users: int
    license_id: str

    def is_active(self, *, now: _dt.datetime | None = None) -> bool:
        now = now or _dt.datetime.now(_dt.UTC)
        if now < self.issued_at:
            return False
        if now > self.expires_at:
            return False
        return True

    @property
    def days_until_expiry(self) -> int:
        delta = self.expires_at - _dt.datetime.now(_dt.UTC)
        return delta.days


def _canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    """Build the exact bytes that get signed. Canonical = sort keys,
    no whitespace, no trailing newline, ensure_ascii=True. Both the
    signer and the verifier MUST produce identical bytes."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _parse_iso(s: str) -> _dt.datetime:
    """ISO-8601 datetime parser that handles `Z` suffix + offset.

    WB31 HIGH-31-01 closure: must REJECT naive (offset-less)
    datetimes. A naive datetime in the license payload would later
    crash downstream comparisons in `is_active()` (TypeError:
    can't compare offset-naive and offset-aware datetimes), and
    that crash propagates through `current_user_cap()` past the
    "opaque failures only" trust boundary at `verify_license_bytes`.
    Reject at parse time so the caller's `except ValueError` (which
    becomes `LicenseInvalidError`) catches it.
    """
    if not isinstance(s, str):
        raise ValueError(f"datetime must be a string, got {type(s).__name__}")
    parsed = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(
            f"naive datetime {s!r} not allowed; must include timezone "
            "(use 'Z' suffix or '+00:00' offset)"
        )
    return parsed


def verify_license_bytes(
    raw: bytes,
    *,
    public_key_b64: str | None = None,
) -> License:
    """Parse + verify a license file's raw bytes. Returns the
    typed `License` on success. Raises `LicenseInvalidError` on any
    failure (bad JSON, missing fields, bad signature, expired,
    wrong tier). Never raises a different exception type — this is
    the trust boundary; opaque failures only.

    `public_key_b64` defaults to `PRODUCTION_PUBLIC_KEY_B64`; tests
    override.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    pub_b64 = public_key_b64 or PRODUCTION_PUBLIC_KEY_B64

    # WB31 CRIT-31-00 defense-in-depth: refuse to verify against the
    # all-zero sentinel. This prevents the "appears-to-work" failure
    # mode where a non-RFC-compliant Ed25519 implementation might
    # accept trivial forges. Real OpenSSL rejects identity-pubkey
    # signatures per spec; this guard is for non-OpenSSL consumers.
    # Tests can still inject their own keypair via `public_key_b64=`.
    if pub_b64 == _PLACEHOLDER_KEY_SENTINEL:
        raise LicenseInvalidError(
            "license verification disabled: the embedded production "
            "key is the all-zero placeholder. This build cannot "
            "verify any license; running on Free tier only. Install "
            "a build with the real production key embedded."
        )

    try:
        outer = json.loads(raw)
    except Exception as e:
        raise LicenseInvalidError(f"license file is not valid JSON: {e}") from e

    if not isinstance(outer, dict):
        raise LicenseInvalidError("license file must be a JSON object")
    # WB31 LOW-31-03 closure: strict envelope schema. Extra fields
    # at the outer level (e.g. a hypothetical v2 `kid`/`alg`) must
    # be explicitly rejected so old verifiers don't silently accept
    # licenses from a newer file format they don't actually
    # understand. Once a new envelope field is added, the allowlist
    # here grows along with it.
    _envelope_fields = {"payload", "signature"}
    _extra_envelope = set(outer) - _envelope_fields
    if _extra_envelope:
        raise LicenseInvalidError(
            f"unknown envelope fields: {sorted(_extra_envelope)}"
        )
    payload = outer.get("payload")
    signature_b64 = outer.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature_b64, str):
        raise LicenseInvalidError(
            "license file must contain 'payload' (object) + 'signature' (string)"
        )
    # WB31 LOW-31-02 closure: same strict-mode at the payload level.
    _payload_fields = {
        "tier", "issued_to", "issued_at", "expires_at",
        "max_users", "license_id",
    }
    _extra_payload = set(payload) - _payload_fields
    if _extra_payload:
        raise LicenseInvalidError(
            f"unknown payload fields: {sorted(_extra_payload)}"
        )

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as e:
        raise LicenseInvalidError(f"signature is not valid base64: {e}") from e

    try:
        pub_key_bytes = base64.b64decode(pub_b64, validate=True)
    except Exception as e:
        raise LicenseInvalidError(f"embedded public key is malformed: {e}") from e
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
    except Exception as e:
        raise LicenseInvalidError(f"embedded public key rejected: {e}") from e

    canonical = _canonical_payload_bytes(payload)
    try:
        pub_key.verify(signature, canonical)
    except InvalidSignature as e:
        raise LicenseInvalidError("signature does not verify against embedded public key") from e

    # Field-by-field validation: every field is required + typed.
    tier = payload.get("tier")
    if tier not in KNOWN_TIERS:
        raise LicenseInvalidError(f"tier {tier!r} not in {sorted(KNOWN_TIERS)}")
    if tier == "free":
        raise LicenseInvalidError("'free' tier should not be signed; remove the license file")

    issued_to = payload.get("issued_to")
    if not isinstance(issued_to, str) or not issued_to.strip():
        raise LicenseInvalidError("issued_to is required and must be a non-empty string")

    try:
        issued_at = _parse_iso(payload["issued_at"])
        expires_at = _parse_iso(payload["expires_at"])
    except (KeyError, ValueError, TypeError) as e:
        raise LicenseInvalidError(f"issued_at/expires_at must be ISO-8601: {e}") from e

    max_users = payload.get("max_users")
    # WB31 MED-31-02 closure: Python bool is a subclass of int; without
    # the isinstance(..., bool) guard, `max_users: true` in JSON would
    # be accepted as 1 — silently downgrading a deployment to a
    # 1-user cap. Reject explicitly.
    if (
        not isinstance(max_users, int)
        or isinstance(max_users, bool)
        or max_users < 1
        or max_users > 1_000_000
    ):
        raise LicenseInvalidError("max_users must be an integer in [1, 1_000_000]")

    license_id = payload.get("license_id")
    if not isinstance(license_id, str) or not license_id.strip():
        raise LicenseInvalidError("license_id is required and must be a non-empty string")

    lic = License(
        tier=tier,
        issued_to=issued_to,
        issued_at=issued_at,
        expires_at=expires_at,
        max_users=max_users,
        license_id=license_id,
    )

    if not lic.is_active():
        raise LicenseInvalidError(
            f"license expired at {lic.expires_at.isoformat()} "
            f"(now={_dt.datetime.now(_dt.UTC).isoformat()})"
        )

    return lic


def _default_license_path() -> pathlib.Path:
    return pathlib.Path.home() / ".iam-jit" / "license.json"


def load_license(
    path: str | pathlib.Path | None = None,
    *,
    public_key_b64: str | None = None,
) -> License | None:
    """Load + verify the license file at `path` (or
    `IAM_JIT_LICENSE_FILE`, or default). Returns the verified
    License, or None if no license is configured.

    Raises `LicenseInvalidError` ONLY if a license file exists at
    the resolved path but fails verification. "No file" is not an
    error — it just means Free tier.
    """
    if path is None:
        env = os.environ.get(LICENSE_PATH_ENV)
        if env:
            path = pathlib.Path(env)
        else:
            path = _default_license_path()
    else:
        path = pathlib.Path(path)

    try:
        # WB31 LOW-31-01 closure: warn if the license path is a
        # symlink, so an operator who installed a license at a
        # symlinked path knows the actual on-disk location is
        # somewhere else. We don't refuse to read symlinks
        # (some legitimate setups use them for centrally-managed
        # licenses pointed at by per-host symlinks), just surface
        # the indirection so it's auditable.
        if path.is_symlink():
            try:
                resolved = path.resolve()
                if resolved != path:
                    logger.warning(
                        "license file %s is a symlink to %s",
                        path, resolved,
                    )
            except OSError:
                pass
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as e:
        # Permission denied / not-a-file — treat as "no license" but
        # log so the operator can spot the misconfiguration.
        logger.warning("license file at %s is unreadable: %s", path, e)
        return None

    return verify_license_bytes(raw, public_key_b64=public_key_b64)


def current_user_cap(license_obj: License | None = None) -> int:
    """Return the active user-cap for this deployment.

    `license_obj` defaults to `load_license()`. Surfaces the cap as
    a single integer the user-store can compare against without
    needing to know the license shape.
    """
    if license_obj is None:
        try:
            license_obj = load_license()
        except LicenseInvalidError as e:
            # Invalid license -> Free tier. Log but don't crash; an
            # admin staring at "why am I gated at 25?" can run
            # `iam-jit license show` to see the verification error.
            logger.warning("license rejected; running on Free tier cap (%s)", e)
            license_obj = None
    if license_obj is None:
        return FREE_TIER_MAX_USERS
    return license_obj.max_users


def current_tier(license_obj: License | None = None) -> str:
    """Active tier name — `free` if no valid license, else the
    license's tier."""
    if license_obj is None:
        try:
            license_obj = load_license()
        except LicenseInvalidError:
            license_obj = None
    return license_obj.tier if license_obj else "free"


def enforce_user_creation_cap(
    *,
    current_user_count: int,
    license_obj: License | None = None,
) -> None:
    """Call this BEFORE inserting a new user into the user-store.
    Raises `UserCapExceededError` if the creation would put the
    deployment over the cap.

    `current_user_count` is the number of users that ALREADY exist
    in the store (not including the one being created). Updates to
    existing users do NOT need to pass through this gate; only new
    creations.

    WB31 MED-31-03 closure: load the license ONCE up-front so the
    `cap` and `tier` derivations both come from the same snapshot.
    Otherwise a license-file replacement between `current_user_cap()`
    and `current_tier()` would produce an inconsistent error message
    (cap from old license, tier from new).
    """
    if license_obj is None:
        try:
            license_obj = load_license()
        except LicenseInvalidError:
            license_obj = None
    cap = current_user_cap(license_obj)
    if current_user_count >= cap:
        tier = current_tier(license_obj)
        if tier == "free":
            msg = (
                f"Free tier supports up to {cap} users. You currently have "
                f"{current_user_count}. To raise the cap, install an iam-jit "
                f"Enterprise license file at "
                f"{os.environ.get(LICENSE_PATH_ENV) or _default_license_path()}. "
                f"Existing users continue to work; only new user creation is gated."
            )
        else:
            msg = (
                f"Your iam-jit {tier} license is provisioned for {cap} users; "
                f"you currently have {current_user_count}. Contact sales to "
                f"raise the cap. Existing users continue to work; only new user "
                f"creation is gated."
            )
        raise UserCapExceededError(msg)
