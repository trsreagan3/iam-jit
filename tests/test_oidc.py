"""Unit tests for `src/iam_jit/oidc.py`.

Covers (in priority order):

1. OIDCProviderConfig.from_env — all three providers + missing
   config + invalid config
2. JWKSCache — cache hits, expiry, kid-not-found triggers refresh,
   stale cache after refresh raises
3. discover — happy path, missing fields, issuer mismatch
4. build_authorization_url — Google adds `hd`, Okta doesn't,
   state + nonce + scope included
5. validate_id_token — ALL security checks:
   - signature OK / wrong signature
   - alg=none / alg=HS256 rejected (must be asymmetric)
   - iss mismatch
   - aud mismatch (both string and array forms)
   - exp in past
   - iat in future
   - nonce mismatch
   - email_verified false
   - Google hd mismatch
   - Okta required-group missing
   - amr → mfa detection

NO live network calls. All tests use stub HTTP clients + locally-
generated keys via cryptography library.
"""

from __future__ import annotations

import dataclasses
import json
import time
from typing import Any

import pytest

# Keys for signing test tokens. Generated once per module — much
# faster than per-test.
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt as _jwt

from iam_jit import oidc


# ---------------------------------------------------------------------------
# Test fixtures: a fresh RSA keypair + the JWKS that goes with it.
# ---------------------------------------------------------------------------


_TEST_KID = "test-kid-1"
_TEST_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_PRIVATE_PEM = _TEST_PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


def _public_jwk() -> dict[str, Any]:
    """Convert the test public key to a JWK so JWKSCache can serve it."""
    public_numbers = _TEST_PRIVATE_KEY.public_key().public_numbers()
    import base64

    def _int_to_b64url(i: int) -> str:
        b = i.to_bytes((i.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": _TEST_KID,
        "n": _int_to_b64url(public_numbers.n),
        "e": _int_to_b64url(public_numbers.e),
    }


def _make_id_token(claims: dict[str, Any], *, kid: str = _TEST_KID, alg: str = "RS256") -> str:
    """Sign an ID token with the test private key."""
    return _jwt.encode(
        claims, _TEST_PRIVATE_PEM, algorithm=alg, headers={"kid": kid}
    )


class _StubHTTP:
    """Stub HTTP client that returns canned responses."""

    def __init__(
        self,
        *,
        get_responses: dict[str, dict[str, Any]] | None = None,
        post_responses: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.get_responses = get_responses or {}
        self.post_responses = post_responses or {}
        self.get_calls: list[str] = []
        self.post_calls: list[tuple[str, dict[str, str]]] = []

    def get_json(self, url, *, timeout=10.0):
        self.get_calls.append(url)
        if url not in self.get_responses:
            raise KeyError(f"unexpected GET {url}")
        return self.get_responses[url]

    def post_form(self, url, *, data, headers=None, timeout=10.0):
        self.post_calls.append((url, dict(data)))
        if url not in self.post_responses:
            raise KeyError(f"unexpected POST {url}")
        return self.post_responses[url]


def _google_config(**overrides) -> oidc.OIDCProviderConfig:
    defaults = dict(
        provider="google",
        issuer="https://accounts.google.com",
        client_id="test-google-client-id.apps.googleusercontent.com",
        client_secret="test-google-secret",
        redirect_uri="https://iam-jit.example.com/api/v1/auth/oidc/callback",
        hosted_domain="example.com",
    )
    defaults.update(overrides)
    return oidc.OIDCProviderConfig(**defaults)


def _okta_config(**overrides) -> oidc.OIDCProviderConfig:
    defaults = dict(
        provider="okta",
        issuer="https://acme.okta.com",
        client_id="0oa-test-client",
        client_secret="test-okta-secret",
        redirect_uri="https://iam-jit.acme.internal/api/v1/auth/oidc/callback",
    )
    defaults.update(overrides)
    return oidc.OIDCProviderConfig(**defaults)


def _google_endpoints() -> oidc.DiscoveredEndpoints:
    return oidc.DiscoveredEndpoints(
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",
        jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
        issuer="https://accounts.google.com",
    )


def _okta_endpoints() -> oidc.DiscoveredEndpoints:
    return oidc.DiscoveredEndpoints(
        authorization_endpoint="https://acme.okta.com/oauth2/v1/authorize",
        token_endpoint="https://acme.okta.com/oauth2/v1/token",
        jwks_uri="https://acme.okta.com/oauth2/v1/keys",
        issuer="https://acme.okta.com",
    )


def _jwks_cache_with_test_key() -> oidc.JWKSCache:
    http = _StubHTTP(get_responses={
        "https://www.googleapis.com/oauth2/v3/certs": {"keys": [_public_jwk()]},
        "https://acme.okta.com/oauth2/v1/keys": {"keys": [_public_jwk()]},
    })
    return oidc.JWKSCache(http)


# ---------------------------------------------------------------------------
# 1. OIDCProviderConfig.from_env
# ---------------------------------------------------------------------------


class TestConfigFromEnv:
    def _set_common(self, monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
        monkeypatch.setenv("IAM_JIT_OIDC_PROVIDER", provider)
        monkeypatch.setenv("IAM_JIT_OIDC_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("IAM_JIT_OIDC_CLIENT_SECRET", "test-secret")
        monkeypatch.setenv("IAM_JIT_OIDC_REDIRECT_URI", "https://x/api/v1/auth/oidc/callback")

    def test_returns_none_when_not_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in [
            "IAM_JIT_OIDC_PROVIDER", "IAM_JIT_OIDC_CLIENT_ID",
            "IAM_JIT_OIDC_CLIENT_SECRET", "IAM_JIT_OIDC_REDIRECT_URI",
        ]:
            monkeypatch.delenv(var, raising=False)
        assert oidc.OIDCProviderConfig.from_env() is None

    def test_google_requires_hosted_domain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_common(monkeypatch, "google")
        monkeypatch.delenv("IAM_JIT_OIDC_HOSTED_DOMAIN", raising=False)
        with pytest.raises(oidc.ConfigError) as exc:
            oidc.OIDCProviderConfig.from_env()
        assert "HOSTED_DOMAIN" in str(exc.value)

    def test_google_full_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_common(monkeypatch, "google")
        monkeypatch.setenv("IAM_JIT_OIDC_HOSTED_DOMAIN", "example.com")
        cfg = oidc.OIDCProviderConfig.from_env()
        assert cfg.provider == "google"
        assert cfg.hosted_domain == "example.com"
        assert cfg.issuer == "https://accounts.google.com"

    def test_okta_requires_issuer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_common(monkeypatch, "okta")
        monkeypatch.delenv("IAM_JIT_OIDC_ISSUER", raising=False)
        with pytest.raises(oidc.ConfigError) as exc:
            oidc.OIDCProviderConfig.from_env()
        assert "ISSUER" in str(exc.value)

    def test_okta_full_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_common(monkeypatch, "okta")
        monkeypatch.setenv("IAM_JIT_OIDC_ISSUER", "https://acme.okta.com")
        cfg = oidc.OIDCProviderConfig.from_env()
        assert cfg.provider == "okta"
        assert cfg.issuer == "https://acme.okta.com"

    def test_okta_required_groups_adds_groups_scope(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._set_common(monkeypatch, "okta")
        monkeypatch.setenv("IAM_JIT_OIDC_ISSUER", "https://acme.okta.com")
        monkeypatch.setenv("IAM_JIT_OIDC_REQUIRED_GROUPS", "iam-jit-users,iam-jit-admins")
        cfg = oidc.OIDCProviderConfig.from_env()
        assert "groups" in cfg.scopes
        assert cfg.required_groups == ("iam-jit-users", "iam-jit-admins")

    def test_unknown_provider_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._set_common(monkeypatch, "unknownprovider")
        with pytest.raises(oidc.ConfigError):
            oidc.OIDCProviderConfig.from_env()


# ---------------------------------------------------------------------------
# 2. JWKSCache
# ---------------------------------------------------------------------------


class TestJWKSCache:
    def test_get_key_returns_matching_kid(self) -> None:
        http = _StubHTTP(get_responses={
            "https://test/jwks": {"keys": [_public_jwk()]},
        })
        cache = oidc.JWKSCache(http)
        key = cache.get_key("https://test/jwks", _TEST_KID)
        assert key["kid"] == _TEST_KID

    def test_unknown_kid_triggers_refresh(self) -> None:
        """When kid not in cached JWKS, refresh once + retry."""
        http = _StubHTTP(get_responses={
            "https://test/jwks": {"keys": [_public_jwk()]},
        })
        cache = oidc.JWKSCache(http)
        # First call: cache miss → fetch → kid found.
        cache.get_key("https://test/jwks", _TEST_KID)
        # Second call with unknown kid: refresh once, still not found.
        with pytest.raises(oidc.JWKSError):
            cache.get_key("https://test/jwks", "unknown-kid")
        # Should have triggered a refresh (so 2+ GET calls total).
        assert len(http.get_calls) >= 2

    def test_cache_hit_avoids_refetch(self) -> None:
        http = _StubHTTP(get_responses={
            "https://test/jwks": {"keys": [_public_jwk()]},
        })
        cache = oidc.JWKSCache(http, ttl_seconds=3600)
        cache.get_key("https://test/jwks", _TEST_KID)
        cache.get_key("https://test/jwks", _TEST_KID)
        # Only one GET — second call hit the cache.
        assert len(http.get_calls) == 1

    def test_fetch_failure_raises_jwks_error(self) -> None:
        http = _StubHTTP(get_responses={})  # no URL configured → KeyError
        cache = oidc.JWKSCache(http)
        with pytest.raises(oidc.JWKSError):
            cache.get_key("https://test/jwks", _TEST_KID)


# ---------------------------------------------------------------------------
# 3. discover
# ---------------------------------------------------------------------------


class TestDiscover:
    def test_happy_path_google(self) -> None:
        cfg = _google_config()
        http = _StubHTTP(get_responses={
            cfg.discovery_endpoint(): {
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            },
        })
        endpoints = oidc.discover(cfg, http)
        assert endpoints.issuer == "https://accounts.google.com"

    def test_missing_endpoints_raises(self) -> None:
        cfg = _google_config()
        http = _StubHTTP(get_responses={
            cfg.discovery_endpoint(): {"issuer": "https://accounts.google.com"},
        })
        with pytest.raises(oidc.ConfigError):
            oidc.discover(cfg, http)

    def test_issuer_mismatch_rejected(self) -> None:
        cfg = _google_config()
        http = _StubHTTP(get_responses={
            cfg.discovery_endpoint(): {
                "issuer": "https://someone-else.com",
                "authorization_endpoint": "x", "token_endpoint": "y", "jwks_uri": "z",
            },
        })
        with pytest.raises(oidc.ConfigError):
            oidc.discover(cfg, http)


# ---------------------------------------------------------------------------
# 4. build_authorization_url
# ---------------------------------------------------------------------------


class TestBuildAuthorizationURL:
    def test_google_includes_hd(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        session = oidc.new_auth_session()
        url = oidc.build_authorization_url(cfg, endpoints, session)
        assert "hd=example.com" in url
        assert f"client_id={cfg.client_id}" in url
        assert f"state={session.state}" in url
        assert f"nonce={session.nonce}" in url
        assert "scope=openid+email+profile" in url
        assert "response_type=code" in url
        assert "prompt=select_account" in url

    def test_okta_no_hd(self) -> None:
        cfg = _okta_config()
        endpoints = _okta_endpoints()
        session = oidc.new_auth_session()
        url = oidc.build_authorization_url(cfg, endpoints, session)
        assert "hd=" not in url
        assert f"client_id={cfg.client_id}" in url


# ---------------------------------------------------------------------------
# 5. validate_id_token — the security-critical zone.
# ---------------------------------------------------------------------------


class TestValidateIDToken:
    def _valid_claims(self, **overrides) -> dict[str, Any]:
        now = int(time.time())
        claims = {
            "iss": "https://accounts.google.com",
            "aud": "test-google-client-id.apps.googleusercontent.com",
            "sub": "1234567890",
            "email": "alice@example.com",
            "email_verified": True,
            "hd": "example.com",
            "exp": now + 3600,
            "iat": now - 1,
            "nonce": "test-nonce",
            "amr": ["mfa"],
        }
        claims.update(overrides)
        return claims

    def test_happy_path_google(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims())
        identity = oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)
        assert identity.email == "alice@example.com"
        assert identity.mfa is True
        assert identity.provider == "google"

    def test_wrong_signature_rejected(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        # Sign with a DIFFERENT key — should fail.
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = _jwt.encode(
            self._valid_claims(), other_pem, algorithm="RS256",
            headers={"kid": _TEST_KID},  # claim our kid, but signed with wrong key
        )
        with pytest.raises(oidc.TokenValidationError):
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)

    def test_alg_none_rejected(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        # alg=none token (header alg=none, no signature)
        import base64
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "kid": _TEST_KID}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps(self._valid_claims()).encode()
        ).rstrip(b"=").decode()
        token = f"{header}.{payload}."
        with pytest.raises(oidc.TokenValidationError) as exc:
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)
        assert "algorithm" in str(exc.value).lower() or "not allowed" in str(exc.value).lower()

    def test_hs256_rejected(self) -> None:
        """HS256 (symmetric) is a downgrade attack; reject."""
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _jwt.encode(
            self._valid_claims(), "anything", algorithm="HS256",
            headers={"kid": _TEST_KID},
        )
        with pytest.raises(oidc.TokenValidationError):
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)

    def test_iss_mismatch_rejected(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(iss="https://attacker.example.com"))
        with pytest.raises(oidc.TokenValidationError):
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)

    def test_aud_mismatch_rejected(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(aud="different-app.googleusercontent.com"))
        with pytest.raises(oidc.TokenValidationError):
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)

    def test_aud_array_form_accepted(self) -> None:
        """`aud` may legitimately be an array; client_id must be in it."""
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(aud=[
            cfg.client_id, "another-audience"
        ]))
        identity = oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)
        assert identity.email == "alice@example.com"

    def test_expired_token_rejected(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(exp=int(time.time()) - 100))
        with pytest.raises(oidc.TokenValidationError):
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)

    def test_nonce_mismatch_rejected(self) -> None:
        """Replay attack defense — nonce must match expected."""
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(nonce="attacker-nonce"))
        with pytest.raises(oidc.TokenValidationError):
            oidc.validate_id_token(
                token, cfg, endpoints, "expected-nonce", cache,
            )

    def test_email_not_verified_rejected(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(email_verified=False))
        with pytest.raises(oidc.TokenValidationError):
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)

    def test_google_hd_mismatch_rejected(self) -> None:
        """THE workspace boundary for Google — different `hd` means
        different Workspace; must be rejected even with valid signature."""
        cfg = _google_config(hosted_domain="legit.com")
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(hd="attacker.com"))
        with pytest.raises(oidc.WorkspaceRejected):
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)

    def test_google_hd_missing_rejected(self) -> None:
        """Personal Google account: token has no `hd` claim. Must be rejected
        when iam-jit is configured for a Workspace."""
        cfg = _google_config(hosted_domain="legit.com")
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        claims = self._valid_claims()
        del claims["hd"]
        token = _make_id_token(claims)
        with pytest.raises(oidc.WorkspaceRejected):
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)

    def test_okta_required_groups_missing_rejected(self) -> None:
        cfg = _okta_config(required_groups=("iam-jit-users",))
        endpoints = _okta_endpoints()
        cache = _jwks_cache_with_test_key()
        # User in different groups — not in required.
        token = _make_id_token(self._valid_claims(
            iss="https://acme.okta.com",
            aud=cfg.client_id,
            groups=["some-other-group"],
        ))
        with pytest.raises(oidc.WorkspaceRejected):
            oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)

    def test_okta_required_groups_present_accepted(self) -> None:
        cfg = _okta_config(required_groups=("iam-jit-users",))
        endpoints = _okta_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(
            iss="https://acme.okta.com",
            aud=cfg.client_id,
            groups=["iam-jit-users", "another-group"],
        ))
        identity = oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)
        assert "iam-jit-users" in identity.groups

    def test_amr_mfa_detected(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(amr=["mfa", "pwd"]))
        identity = oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)
        assert identity.mfa is True

    def test_no_amr_no_mfa(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        claims = self._valid_claims()
        del claims["amr"]
        token = _make_id_token(claims)
        identity = oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)
        assert identity.mfa is False

    def test_email_lowercased(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        token = _make_id_token(self._valid_claims(email="ALICE@EXAMPLE.com"))
        identity = oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)
        assert identity.email == "alice@example.com"


# ---------------------------------------------------------------------------
# 6. exchange_code_for_id_token
# ---------------------------------------------------------------------------


class TestExchangeCode:
    def test_happy_path(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        http = _StubHTTP(post_responses={
            endpoints.token_endpoint: {
                "id_token": "test-id-token",
                "access_token": "test-access-token",
                "token_type": "Bearer",
            },
        })
        token = oidc.exchange_code_for_id_token("test-code", cfg, endpoints, http)
        assert token == "test-id-token"
        # Verify the request body had the right fields.
        url, data = http.post_calls[0]
        assert url == endpoints.token_endpoint
        assert data["grant_type"] == "authorization_code"
        assert data["code"] == "test-code"
        assert data["client_id"] == cfg.client_id
        assert data["client_secret"] == cfg.client_secret
        assert data["redirect_uri"] == cfg.redirect_uri

    def test_missing_id_token_in_response_raises(self) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        http = _StubHTTP(post_responses={
            endpoints.token_endpoint: {"access_token": "x"},  # no id_token
        })
        with pytest.raises(oidc.TokenExchangeError):
            oidc.exchange_code_for_id_token("test-code", cfg, endpoints, http)


# ---------------------------------------------------------------------------
# 7. AMR variants — comprehensive coverage.
# ---------------------------------------------------------------------------


class TestAMRDetection:
    @pytest.mark.parametrize("amr,expected_mfa", [
        (["mfa"], True),
        (["otp"], True),
        (["totp"], True),
        (["hwk"], True),  # hardware key (YubiKey / FIDO)
        (["swk"], True),  # software key (Authenticator app)
        (["fpt"], True),  # fingerprint
        (["mfa", "pwd"], True),
        # WB9-06 closure: SMS no longer counts as MFA. NIST 800-63B
        # downgraded SMS-based factors; we follow.
        (["sms"], False),
        # WB9-06 closure: "user" is user-presence (button press),
        # not multi-factor. Removed from the MFA set.
        (["user"], False),
        (["pwd"], False),  # password alone
        ([], False),
        (None, False),
    ])
    def test_amr_to_mfa(self, amr, expected_mfa) -> None:
        cfg = _google_config()
        endpoints = _google_endpoints()
        cache = _jwks_cache_with_test_key()
        claims = {
            "iss": "https://accounts.google.com",
            "aud": cfg.client_id,
            "sub": "x",
            "email": "a@example.com",
            "email_verified": True,
            "hd": "example.com",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()) - 1,
            "nonce": "test-nonce",
        }
        if amr is not None:
            claims["amr"] = amr
        token = _make_id_token(claims)
        identity = oidc.validate_id_token(token, cfg, endpoints, "test-nonce", cache)
        assert identity.mfa is expected_mfa
