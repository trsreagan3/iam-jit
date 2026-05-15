"""MFA freshness gate — Layer C of [[mfa-compliance-strategy]].

Layer A is the OIDC AMR check at login (already shipped in `oidc.py`).
Layer B is the customer-side `aws:MultiFactorAuthPresent` trust-policy
condition on the provisioner role (documented in
`docs/recipes/MFA-PROPAGATION.md`).

This module is Layer C: for HIGH-RISK grants, require recent MFA
on the requester's session. A grant with score >= the high-risk
floor cannot proceed unless the user's `iam_jit_session_mfa`
cookie:

  1. exists,
  2. is signed by us,
  3. is bound to the requesting user.id (WB9-01 invariant), and
  4. was minted within `step_up_max_age_seconds` (default 5 min).

If any check fails, the route returns 403 with a structured body
telling the agent / UI to redirect through a fresh OIDC login.

Why "freshness" instead of TOTP step-up: re-issuing OIDC against
the customer's IdP is cheaper to ship + audit, and the IdP is
already the source of truth for what MFA means. Customers who
want a TOTP add-on can layer it via the IdP.

The `high_risk_score_floor` is read from env
`IAM_JIT_MFA_STEP_UP_AT_SCORE` (default 7).
"""

from __future__ import annotations

import dataclasses
import os
import time
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, TimestampSigner

# Salt is the same value oidc.py uses when signing the cookie.
_MFA_SALT = "oidc-mfa"

# Defaults.
_DEFAULT_MAX_AGE_SECONDS = 5 * 60  # 5 min
_DEFAULT_HIGH_RISK_SCORE = 7


@dataclasses.dataclass(frozen=True)
class MFAVerification:
    """Result of an MFA freshness check.

    `present` — is the cookie valid + bound to this user?
    `age_seconds` — None if no cookie or cookie invalid; otherwise
                    age in seconds at check time
    `reason` — short tag describing why MFA is/isn't satisfied
    """

    present: bool
    age_seconds: int | None
    reason: str

    def as_audit_dict(self) -> dict[str, Any]:
        return {
            "mfa_present": self.present,
            "mfa_age_seconds": self.age_seconds,
            "mfa_reason": self.reason,
        }


def verify(
    *,
    cookie_value: str | None,
    secret: str,
    expected_user_id: str,
    max_age_seconds: int | None = None,
    now: int | None = None,
) -> MFAVerification:
    """Validate an MFA cookie value against the expected user id.

    The cookie was minted by `oidc.py` via
    `TimestampSigner(secret, salt="oidc-mfa").sign(f"mfa:{user.id}")`.

    Returns an MFAVerification describing the outcome. Never raises.
    """
    if not cookie_value:
        return MFAVerification(
            present=False, age_seconds=None, reason="no_mfa_cookie",
        )
    if max_age_seconds is None:
        max_age_seconds = _DEFAULT_MAX_AGE_SECONDS

    signer = TimestampSigner(secret, salt=_MFA_SALT)
    try:
        # `unsign` with `return_timestamp=True` returns (payload, ts)
        # where ts is the unix epoch of when the cookie was signed.
        payload, ts = signer.unsign(
            cookie_value.encode(),
            max_age=max_age_seconds,
            return_timestamp=True,
        )
    except SignatureExpired as e:
        # Cookie is signed, but too old.
        age = None
        try:
            age = int((now or time.time()) - e.date_signed.timestamp())  # type: ignore[attr-defined]
        except Exception:
            pass
        return MFAVerification(
            present=False, age_seconds=age, reason="mfa_too_stale",
        )
    except BadSignature:
        return MFAVerification(
            present=False, age_seconds=None,
            reason="mfa_signature_invalid",
        )

    # WB9-01: payload must be `mfa:<user.id>`. A captured cookie from
    # user A cannot authorize a request as user B.
    decoded = payload.decode() if isinstance(payload, (bytes, bytearray)) else str(payload)
    expected = f"mfa:{expected_user_id}"
    if decoded != expected:
        return MFAVerification(
            present=False, age_seconds=None,
            reason="mfa_user_mismatch",
        )

    try:
        age = int((now or time.time()) - ts.timestamp())
    except Exception:
        age = 0
    return MFAVerification(
        present=True, age_seconds=age, reason="ok",
    )


def is_high_risk(score: int) -> bool:
    """True if `score` triggers the MFA step-up gate."""
    floor = _high_risk_score_floor()
    return score >= floor


def _high_risk_score_floor() -> int:
    raw = (os.environ.get("IAM_JIT_MFA_STEP_UP_AT_SCORE") or "").strip()
    try:
        return int(raw) if raw else _DEFAULT_HIGH_RISK_SCORE
    except ValueError:
        return _DEFAULT_HIGH_RISK_SCORE


def step_up_max_age_seconds() -> int:
    raw = (os.environ.get("IAM_JIT_MFA_STEP_UP_MAX_AGE_SECONDS") or "").strip()
    try:
        return int(raw) if raw else _DEFAULT_MAX_AGE_SECONDS
    except ValueError:
        return _DEFAULT_MAX_AGE_SECONDS
