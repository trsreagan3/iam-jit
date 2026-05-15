"""Tests for the MFA freshness gate (Layer C of mfa-compliance-strategy)."""

from __future__ import annotations

import time

import pytest
from itsdangerous import TimestampSigner

from iam_jit import mfa_gate


SECRET = "test-secret-32-bytes-of-entropy-please-yes"
USER_ID = "email:alice@example.com"


def _sign(user_id: str, secret: str = SECRET, salt: str = "oidc-mfa") -> str:
    return TimestampSigner(secret, salt=salt).sign(f"mfa:{user_id}".encode()).decode()


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------


def test_verify_returns_present_for_fresh_cookie() -> None:
    cookie = _sign(USER_ID)
    result = mfa_gate.verify(
        cookie_value=cookie,
        secret=SECRET,
        expected_user_id=USER_ID,
        max_age_seconds=300,
    )
    assert result.present is True
    assert result.age_seconds is not None
    assert 0 <= result.age_seconds < 5
    assert result.reason == "ok"


def test_verify_no_cookie_returns_absent() -> None:
    result = mfa_gate.verify(
        cookie_value=None,
        secret=SECRET,
        expected_user_id=USER_ID,
    )
    assert result.present is False
    assert result.age_seconds is None
    assert result.reason == "no_mfa_cookie"


def test_verify_empty_cookie_returns_absent() -> None:
    result = mfa_gate.verify(
        cookie_value="",
        secret=SECRET,
        expected_user_id=USER_ID,
    )
    assert result.present is False
    assert result.reason == "no_mfa_cookie"


def test_verify_wrong_secret_fails_signature() -> None:
    cookie = _sign(USER_ID, secret="other-secret")
    result = mfa_gate.verify(
        cookie_value=cookie,
        secret=SECRET,
        expected_user_id=USER_ID,
    )
    assert result.present is False
    assert result.reason == "mfa_signature_invalid"


def test_verify_user_mismatch_blocks_transplant() -> None:
    """WB9-01: a cookie minted for user A cannot authorize user B."""
    cookie_for_alice = _sign("email:alice@example.com")
    result = mfa_gate.verify(
        cookie_value=cookie_for_alice,
        secret=SECRET,
        expected_user_id="email:bob@example.com",  # different user
    )
    assert result.present is False
    assert result.reason == "mfa_user_mismatch"


def test_verify_stale_cookie_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cookie older than max_age must be rejected with mfa_too_stale.

    Strategy: sign with a TimestampSigner whose `get_timestamp` is
    pinned 10 min in the past, so the cookie's embedded ts is stale
    when we unsign it with max_age=300.
    """
    from itsdangerous import TimestampSigner

    signer = TimestampSigner(SECRET, salt="oidc-mfa")
    monkeypatch.setattr(
        signer, "get_timestamp", lambda: int(time.time()) - 600
    )
    cookie = signer.sign(f"mfa:{USER_ID}".encode()).decode()

    result = mfa_gate.verify(
        cookie_value=cookie,
        secret=SECRET,
        expected_user_id=USER_ID,
        max_age_seconds=300,
    )
    assert result.present is False
    assert result.reason == "mfa_too_stale"


def test_verify_wrong_salt_rejected() -> None:
    cookie = TimestampSigner(SECRET, salt="some-other-salt").sign(
        f"mfa:{USER_ID}".encode()
    ).decode()
    result = mfa_gate.verify(
        cookie_value=cookie,
        secret=SECRET,
        expected_user_id=USER_ID,
    )
    assert result.present is False
    assert result.reason == "mfa_signature_invalid"


def test_audit_dict_shape() -> None:
    cookie = _sign(USER_ID)
    result = mfa_gate.verify(
        cookie_value=cookie,
        secret=SECRET,
        expected_user_id=USER_ID,
    )
    audit = result.as_audit_dict()
    assert "mfa_present" in audit
    assert "mfa_age_seconds" in audit
    assert "mfa_reason" in audit


# ---------------------------------------------------------------------------
# is_high_risk + env-tunable floor.
# ---------------------------------------------------------------------------


def test_is_high_risk_default_floor_is_7() -> None:
    assert mfa_gate.is_high_risk(7) is True
    assert mfa_gate.is_high_risk(6) is False
    assert mfa_gate.is_high_risk(10) is True


def test_is_high_risk_respects_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_MFA_STEP_UP_AT_SCORE", "5")
    assert mfa_gate.is_high_risk(5) is True
    assert mfa_gate.is_high_risk(4) is False


def test_is_high_risk_invalid_env_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_MFA_STEP_UP_AT_SCORE", "not-an-int")
    assert mfa_gate.is_high_risk(7) is True
    assert mfa_gate.is_high_risk(6) is False


def test_step_up_max_age_default() -> None:
    assert mfa_gate.step_up_max_age_seconds() == 300


def test_step_up_max_age_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_MFA_STEP_UP_MAX_AGE_SECONDS", "60")
    assert mfa_gate.step_up_max_age_seconds() == 60
