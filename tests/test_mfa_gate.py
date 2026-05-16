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


# ---------------------------------------------------------------------------
# WB13-10 regression: env-tunable score-floor + max-age clamp boundaries.
# The clamps were added in WB12-03 (round-12 closure) but no test pinned
# the exact boundary behaviour. WB13-10 (MED, round-13) flagged the gap.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env_value,expected", [
    ("999", 10),   # too high → clamp to 10
    ("11", 10),    # just above 10 → clamp to 10
    ("10", 10),   # at upper bound → passes through
    ("7", 7),     # within range → passes through
    ("1", 1),     # at lower bound → passes through
    ("0", 1),     # below 1 → clamp to 1
    ("-5", 1),    # negative → clamp to 1
    ("not-int", 7),  # invalid → default 7
    ("", 7),       # empty → default 7
])
def test_high_risk_score_floor_clamp_boundaries(
    env_value: str, expected: int, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_MFA_STEP_UP_AT_SCORE", env_value)
    assert mfa_gate._high_risk_score_floor() == expected


@pytest.mark.parametrize("env_value,expected", [
    ("86401", 86400),  # too high → clamp to 86400 (1 day)
    ("86400", 86400),  # at upper bound
    ("3600", 3600),    # within range (1 hour)
    ("300", 300),      # default-equal
    ("30", 30),        # at lower bound
    ("29", 30),        # below 30 → clamp to 30
    ("0", 30),         # zero → clamp to 30
    ("-100", 30),      # negative → clamp to 30
    ("not-int", 300),  # invalid → default 300
])
def test_step_up_max_age_seconds_clamp_boundaries(
    env_value: str, expected: int, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_MFA_STEP_UP_MAX_AGE_SECONDS", env_value)
    assert mfa_gate.step_up_max_age_seconds() == expected


# ---------------------------------------------------------------------------
# Phase-1 closure: evaluate_for_route — cookie + bearer-token-issuance
# resolution chain per [[mfa-compliance-strategy]] PCI §8.6.
# ---------------------------------------------------------------------------


class _FakeTokenRecord:
    """Minimal duck-type stand-in for APITokenRecord."""

    def __init__(self, mfa_at_issuance: int | None) -> None:
        self.mfa_at_issuance = mfa_at_issuance


def test_evaluate_for_route_cookie_path_present() -> None:
    cookie = _sign(USER_ID)
    result = mfa_gate.evaluate_for_route(
        cookie_value=cookie,
        secret=SECRET,
        user_id=USER_ID,
        risk_score=8,
        api_token_record=None,
    )
    assert result["mfa_present"] is True
    assert result["mfa_source"] == "cookie"
    assert result["would_require_mfa"] is True


def test_evaluate_for_route_no_cookie_no_token_absent() -> None:
    result = mfa_gate.evaluate_for_route(
        cookie_value=None,
        secret=SECRET,
        user_id=USER_ID,
        risk_score=8,
        api_token_record=None,
    )
    assert result["mfa_present"] is False
    assert result["mfa_source"] == "absent"
    assert result["mfa_reason"] == "no_mfa_cookie"


def test_evaluate_for_route_bearer_token_fresh_issuance_satisfies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bearer token minted 60s ago with MFA → counts as MFA-present
    even when cookie absent. Agent inherits the human's MFA per PCI §8.6."""
    import time as _t
    monkeypatch.setenv("IAM_JIT_MFA_STEP_UP_MAX_AGE_SECONDS", "300")
    now = int(_t.time())
    token = _FakeTokenRecord(mfa_at_issuance=now - 60)
    result = mfa_gate.evaluate_for_route(
        cookie_value=None,
        secret=SECRET,
        user_id=USER_ID,
        risk_score=8,
        api_token_record=token,
    )
    assert result["mfa_present"] is True
    assert result["mfa_source"] == "token_at_issuance"
    assert result["mfa_reason"] == "ok_via_token_issuance"
    assert 60 <= result["mfa_age_seconds"] <= 65


def test_evaluate_for_route_bearer_token_stale_issuance_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bearer token minted 1 hour ago + 5 min freshness window → stale."""
    import time as _t
    monkeypatch.setenv("IAM_JIT_MFA_STEP_UP_MAX_AGE_SECONDS", "300")
    now = int(_t.time())
    token = _FakeTokenRecord(mfa_at_issuance=now - 3600)
    result = mfa_gate.evaluate_for_route(
        cookie_value=None,
        secret=SECRET,
        user_id=USER_ID,
        risk_score=8,
        api_token_record=token,
    )
    assert result["mfa_present"] is False
    assert result["mfa_source"] == "token_at_issuance_stale"
    assert result["mfa_reason"] == "token_mfa_too_stale"


def test_evaluate_for_route_bearer_token_no_mfa_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bearer token minted before MFA-at-issuance tracking shipped
    (mfa_at_issuance=None). Distinct audit reason from 'no cookie'."""
    token = _FakeTokenRecord(mfa_at_issuance=None)
    result = mfa_gate.evaluate_for_route(
        cookie_value=None,
        secret=SECRET,
        user_id=USER_ID,
        risk_score=8,
        api_token_record=token,
    )
    assert result["mfa_present"] is False
    assert result["mfa_source"] == "token_no_mfa"
    assert result["mfa_reason"] == "token_lacks_mfa_evidence"


def test_evaluate_for_route_cookie_wins_over_token() -> None:
    """If both cookie AND token have evidence, cookie wins (the more
    recent of the two; cookie is a per-session live assertion)."""
    import time as _t
    cookie = _sign(USER_ID)
    token = _FakeTokenRecord(mfa_at_issuance=int(_t.time()) - 100)
    result = mfa_gate.evaluate_for_route(
        cookie_value=cookie,
        secret=SECRET,
        user_id=USER_ID,
        risk_score=8,
        api_token_record=token,
    )
    assert result["mfa_source"] == "cookie"


def test_evaluate_for_route_low_risk_score_would_require_false() -> None:
    """At low scores, would_require_mfa is False (MFA gate won't fire
    even if mfa_present is False)."""
    result = mfa_gate.evaluate_for_route(
        cookie_value=None,
        secret=SECRET,
        user_id=USER_ID,
        risk_score=2,
        api_token_record=None,
    )
    assert result["would_require_mfa"] is False
    assert result["mfa_present"] is False  # truthful annotation
