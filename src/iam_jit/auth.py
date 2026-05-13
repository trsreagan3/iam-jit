"""Authentication primitives.

Two auth modes share most of this module:

  - `local` mode: magic-link login (server emails a single-use signed
    token; click sets a session cookie). Session lives in a signed cookie
    only — no server-side session store. The cookie's signature is
    HS256-validated against `IAM_JIT_MAGIC_LINK_SECRET`.

  - `aws_iam` mode: the Function URL validates SigV4 itself; this module's
    `extract_iam_principal` reads the resulting principal ARN out of the
    Lambda event context. No magic links / cookies in this mode.

Per-user API tokens (used by agents) are HMAC-signed strings of the same
shape as the session cookie. Tokens never expire automatically; admins
revoke them by removing the token row.
"""

from __future__ import annotations

import dataclasses
import hashlib
import secrets
import time
from typing import Any

from itsdangerous import BadSignature, TimestampSigner

# How long a session cookie remains valid (1 day).
_SESSION_TTL_SECONDS = 24 * 60 * 60

# How long a magic-link token remains valid (15 minutes).
_MAGIC_LINK_TTL_SECONDS = 15 * 60


@dataclasses.dataclass(frozen=True)
class IssuedToken:
    """An API token + the metadata stored alongside it."""

    raw: str             # The bearer token to give the user — never stored
    hash: str            # The token_hash stored in DynamoDB (sha256 of raw)
    user_id: str
    created_at: int      # epoch seconds
    label: str | None    # human-readable label (e.g., 'claude-code laptop')


def make_signer(secret: str) -> TimestampSigner:
    """Return a TimestampSigner for session/magic-link cookies."""
    if not secret:
        raise ValueError(
            "IAM_JIT_MAGIC_LINK_SECRET is empty. Generate one with "
            "`openssl rand -hex 32` and set it on the Lambda."
        )
    return TimestampSigner(secret, salt="iam-jit-session")


def sign_session(secret: str, user_id: str) -> str:
    """Issue a session cookie value for the given user."""
    return make_signer(secret).sign(user_id.encode("utf-8")).decode("ascii")


def verify_session(secret: str, cookie_value: str, *, max_age: int = _SESSION_TTL_SECONDS) -> str:
    """Return the user_id from a session cookie, or raise BadSignature."""
    try:
        raw = make_signer(secret).unsign(cookie_value.encode("ascii"), max_age=max_age)
    except BadSignature as e:
        raise BadSignature(f"Invalid session cookie: {e}") from e
    return raw.decode("utf-8")


def sign_intake_state(secret: str, payload: str) -> str:
    """Sign a short-lived intake conversation blob.

    The conversation lives entirely in the signed cookie / form field —
    no server-side store. Signature prevents tampering; max_age on verify
    bounds replay.
    """
    signer = TimestampSigner(secret, salt="iam-jit-intake")
    return signer.sign(payload.encode("utf-8")).decode("ascii")


def verify_intake_state(secret: str, signed: str, *, max_age: int = 30 * 60) -> str:
    signer = TimestampSigner(secret, salt="iam-jit-intake")
    try:
        raw = signer.unsign(signed.encode("ascii"), max_age=max_age)
    except BadSignature as e:
        raise BadSignature(f"invalid intake token: {e}") from e
    return raw.decode("utf-8")


def sign_magic_link(secret: str, email: str) -> str:
    """Issue a single-use magic-link token for the given email."""
    signer = TimestampSigner(secret, salt="iam-jit-magic-link")
    nonce = secrets.token_urlsafe(8)
    payload = f"{email}|{nonce}".encode("utf-8")
    return signer.sign(payload).decode("ascii")


def verify_magic_link(
    secret: str, token: str, *, max_age: int = _MAGIC_LINK_TTL_SECONDS
) -> str:
    """Return the email from a magic-link token, or raise BadSignature.

    Single-use enforcement is handled by the route handler via
    `magic_link_nonces.consume_or_reject` — verify_magic_link only
    checks the signature + expiry. We split the responsibilities so
    tests of the cryptographic step don't have to manage a nonce
    store.
    """
    signer = TimestampSigner(secret, salt="iam-jit-magic-link")
    raw = signer.unsign(token.encode("ascii"), max_age=max_age).decode("utf-8")
    email, _, _ = raw.partition("|")
    if not email:
        raise BadSignature("magic-link payload had no email")
    return email


def magic_link_token_id(token: str) -> str:
    """Stable identifier for a magic-link token, used as the key in
    the consumed-nonce store. Hash of the token so the store doesn't
    keep raw tokens (which are still valid until their TTL expires)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_token(raw_token: str) -> str:
    """Return the storage hash of an API bearer token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def issue_api_token(user_id: str, *, label: str | None = None) -> IssuedToken:
    """Mint a new API token for the given user_id.

    The raw token is shown to the user once at creation; only its hash is
    stored. Format: 32 url-safe random bytes prefixed with `iamjit_`.
    """
    raw = "iamjit_" + secrets.token_urlsafe(32)
    return IssuedToken(
        raw=raw,
        hash=hash_token(raw),
        user_id=user_id,
        created_at=int(time.time()),
        label=label,
    )


def extract_iam_principal(event: dict[str, Any]) -> str | None:
    """Pull the SigV4-authenticated caller's IAM ARN from a Lambda event.

    Function URLs with `AuthType: AWS_IAM` populate
    `event.requestContext.authorizer.iam.userArn`. Returns None on any
    other shape (e.g., local invocation during tests).
    """
    rc = event.get("requestContext") or {}
    authz = rc.get("authorizer") or {}
    iam = authz.get("iam") or {}
    arn = iam.get("userArn")
    if isinstance(arn, str) and arn.startswith("arn:"):
        return arn
    return None


def normalize_iam_id(arn: str) -> str:
    """Convert a raw IAM ARN to the user_id format used in the user store.

    Identity Center session ARNs look like:
      arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_DevOps_xxx/alice@example.com
    These map back to the *role* (not the session) for authorization, since
    a single role has many concurrent sessions.
    """
    if "assumed-role" in arn:
        # arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION
        parts = arn.split("/")
        if len(parts) >= 2:
            account = arn.split(":")[4]
            role_name = parts[1]
            return f"iam:arn:aws:iam::{account}:role/{role_name}"
    return f"iam:{arn}"
