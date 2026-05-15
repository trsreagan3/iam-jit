"""OIDC SSO (multi-provider) — generic OIDC client + provider configs.

Implements the standard OAuth 2.0 + OpenID Connect authorization-code
flow:
  1. iam-jit redirects user to provider's authorization endpoint
     with state + nonce
  2. Provider authenticates user (with MFA), redirects back with
     `code`
  3. iam-jit exchanges `code` for an `id_token` (JWT) via token
     endpoint
  4. iam-jit validates the ID token:
       - signature (against provider's JWKS, cached + rotated)
       - issuer (iss claim matches expected)
       - audience (aud claim matches client_id)
       - expiry (exp in future, iat in past)
       - nonce (matches cookie value, replay protection)
       - provider-specific claims (Google `hd`, Okta groups, etc.)
       - email_verified == true
  5. iam-jit resolves the verified email → iam-jit User
  6. iam-jit issues a session cookie

Providers supported as of v1:
  - Google Workspace (Omise's IdP) — `hd` claim verification
  - Okta — issuer URL is per-customer; optional group requirements

Future providers (Azure AD, Auth0, JumpCloud, OneLogin, Keycloak)
are small additions: subclass `OIDCProviderConfig` and register
via `get_provider_config()`.

Per [[mfa-compliance-strategy]]: the `amr` (Authentication Method
Reference) claim is read for MFA assertion propagation. Recorded
on the session so downstream AssumeRole calls can attach
`aws:MultiFactorAuthPresent: true` Condition.

CRITICAL security checks (all MUST pass for sign-in to succeed):
  - JWKS signature verification (foundation of everything)
  - `iss` matches expected
  - `aud` matches client_id
  - `exp` is in the future
  - `nonce` matches state cookie
  - `email_verified == true`
  - Provider-specific (Google `hd`, Okta optional groups)
"""

from __future__ import annotations

import dataclasses
import logging
import os
import secrets as _secrets
import time
from typing import Any, Protocol
from urllib.parse import urlencode

logger = logging.getLogger("iam_jit.oidc")


# ---------------------------------------------------------------------------
# Exceptions.
# ---------------------------------------------------------------------------


class OIDCError(Exception):
    """Base for all OIDC-related failures."""


class ConfigError(OIDCError):
    """Missing or invalid OIDC configuration (env vars, etc.)."""


class TokenValidationError(OIDCError):
    """An ID token failed one of the validation checks."""


class JWKSError(OIDCError):
    """JWKS fetch or key lookup failure."""


class TokenExchangeError(OIDCError):
    """Failed to exchange authorization code for an ID token."""


class StateMismatch(OIDCError):
    """CSRF protection — state cookie doesn't match query parameter."""


class WorkspaceRejected(OIDCError):
    """Provider-specific workspace gate failed (e.g., Google `hd`
    claim doesn't match configured hosted domain)."""


# ---------------------------------------------------------------------------
# Provider config.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class OIDCProviderConfig:
    """Per-provider OIDC configuration.

    Generic fields are required for any OIDC provider. Provider-
    specific fields (hosted_domain, required_groups, etc.) live
    here for convenience even though not every provider uses them
    — keeps the config a single dataclass rather than a union of
    types.
    """

    provider: str  # "google" | "okta" | "azure" | "auth0" | "generic"
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    # Discovery URL (.well-known/openid-configuration). Computed from
    # issuer if not specified — Okta uses non-standard pathing in some
    # configurations so it's overridable.
    discovery_url: str = ""

    # Google-specific: restricts the OIDC flow to a single Google
    # Workspace via the `hd` claim. CRITICAL security gate when
    # provider=="google" — sign-in fails closed if not set.
    hosted_domain: str | None = None

    # Okta / Azure / Auth0 optional: require user to be in specific
    # group(s) (read from `groups` claim on ID token).
    required_groups: tuple[str, ...] = ()

    # Common: scopes to request. Most providers need `openid email
    # profile` at minimum; some need `groups` for Okta group claims.
    scopes: tuple[str, ...] = ("openid", "email", "profile")

    def discovery_endpoint(self) -> str:
        if self.discovery_url:
            return self.discovery_url
        return f"{self.issuer.rstrip('/')}/.well-known/openid-configuration"

    @classmethod
    def from_env(cls) -> OIDCProviderConfig | None:
        """Build from environment variables. Returns None if OIDC
        isn't configured (so the deployment falls back to magic-
        link mode).

        Required env vars:
          IAM_JIT_OIDC_PROVIDER     google | okta | generic
          IAM_JIT_OIDC_CLIENT_ID
          IAM_JIT_OIDC_CLIENT_SECRET
          IAM_JIT_OIDC_REDIRECT_URI

        Provider-specific:
          IAM_JIT_OIDC_ISSUER          (required for okta / generic)
          IAM_JIT_OIDC_HOSTED_DOMAIN   (required for google)
          IAM_JIT_OIDC_REQUIRED_GROUPS (optional; comma-separated)
        """
        provider = (os.environ.get("IAM_JIT_OIDC_PROVIDER") or "").lower().strip()
        client_id = (os.environ.get("IAM_JIT_OIDC_CLIENT_ID") or "").strip()
        client_secret = (os.environ.get("IAM_JIT_OIDC_CLIENT_SECRET") or "").strip()
        redirect_uri = (os.environ.get("IAM_JIT_OIDC_REDIRECT_URI") or "").strip()

        if not (provider and client_id and client_secret and redirect_uri):
            return None

        if provider not in {"google", "okta", "generic"}:
            raise ConfigError(
                f"unknown IAM_JIT_OIDC_PROVIDER {provider!r}; "
                "supported: google, okta, generic"
            )

        if provider == "google":
            issuer = "https://accounts.google.com"
            hosted_domain = (os.environ.get("IAM_JIT_OIDC_HOSTED_DOMAIN") or "").strip()
            if not hosted_domain:
                raise ConfigError(
                    "IAM_JIT_OIDC_HOSTED_DOMAIN is REQUIRED when "
                    "IAM_JIT_OIDC_PROVIDER=google. Without it, ANY "
                    "Google account can sign in. Set it to the "
                    "Workspace domain (e.g., 'company.com')."
                )
        elif provider == "okta":
            issuer = (os.environ.get("IAM_JIT_OIDC_ISSUER") or "").strip()
            if not issuer:
                raise ConfigError(
                    "IAM_JIT_OIDC_ISSUER is REQUIRED when "
                    "IAM_JIT_OIDC_PROVIDER=okta. Set it to your "
                    "Okta org URL (e.g., 'https://acme.okta.com')."
                )
            hosted_domain = None
        else:  # generic
            issuer = (os.environ.get("IAM_JIT_OIDC_ISSUER") or "").strip()
            if not issuer:
                raise ConfigError(
                    "IAM_JIT_OIDC_ISSUER is REQUIRED when "
                    "IAM_JIT_OIDC_PROVIDER=generic."
                )
            hosted_domain = None

        required_groups_raw = (os.environ.get("IAM_JIT_OIDC_REQUIRED_GROUPS") or "").strip()
        required_groups = tuple(
            g.strip() for g in required_groups_raw.split(",") if g.strip()
        )

        scopes = ["openid", "email", "profile"]
        if required_groups:
            # WB9-08 closure: previously only auto-added the
            # 'groups' scope for Okta. Operators configuring
            # Google + required_groups got cryptic 403s because
            # the token had no groups claim. Now we auto-add
            # 'groups' scope whenever the operator declared
            # required_groups regardless of provider. Providers
            # that don't recognize the scope simply ignore it.
            scopes.append("groups")

        return cls(
            provider=provider,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            hosted_domain=hosted_domain,
            required_groups=required_groups,
            scopes=tuple(scopes),
        )


# ---------------------------------------------------------------------------
# JWKS cache.
# ---------------------------------------------------------------------------


class HTTPClient(Protocol):
    """Minimal HTTP surface we use. Lets tests inject stubs."""

    def get_json(self, url: str, *, timeout: float = 10.0) -> dict[str, Any]: ...

    def post_form(
        self,
        url: str,
        *,
        data: dict[str, str],
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]: ...


class HttpxClient:
    """Production HTTP client backed by httpx."""

    def get_json(self, url: str, *, timeout: float = 10.0) -> dict[str, Any]:
        import httpx

        resp = httpx.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def post_form(
        self,
        url: str,
        *,
        data: dict[str, str],
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        import httpx

        resp = httpx.post(url, data=data, headers=headers or {}, timeout=timeout)
        resp.raise_for_status()
        return resp.json()


class JWKSCache:
    """Caches the provider's JSON Web Key Set with kid-based
    rotation. Refreshes on cache miss for an unknown `kid`.

    Why cache: every ID-token verification needs the JWKS to verify
    the signature. JWKS fetch is ~100ms over network; caching makes
    sign-in fast.

    Why refresh on unknown kid: providers rotate keys; the new key
    will appear in JWKS under a new kid. Our cache must refresh
    when we see a `kid` it doesn't know.
    """

    def __init__(self, http_client: HTTPClient, ttl_seconds: int = 3600) -> None:
        self._client = http_client
        self._ttl = ttl_seconds
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}  # jwks_url -> (expires_at, jwks)

    def get_key(self, jwks_url: str, kid: str) -> dict[str, Any]:
        """Return the JWK with the given kid.

        Refreshes the cache (a) when expired, (b) when the kid
        isn't found (provider rotated keys). Raises JWKSError if
        the kid still isn't found after refresh.
        """
        jwks = self._get_jwks(jwks_url)
        key = _find_key(jwks, kid)
        if key is not None:
            return key
        # kid not found — refresh and retry once. Providers rotate
        # keys periodically; a not-found kid usually means rotation.
        self._cache.pop(jwks_url, None)
        jwks = self._get_jwks(jwks_url)
        key = _find_key(jwks, kid)
        if key is None:
            raise JWKSError(
                f"key with kid={kid!r} not found in JWKS at {jwks_url} "
                "(even after refresh)"
            )
        return key

    def _get_jwks(self, jwks_url: str) -> dict[str, Any]:
        now = time.time()
        cached = self._cache.get(jwks_url)
        if cached is not None and cached[0] > now:
            return cached[1]
        try:
            jwks = self._client.get_json(jwks_url)
        except Exception as e:
            raise JWKSError(f"JWKS fetch from {jwks_url} failed: {e}") from e
        self._cache[jwks_url] = (now + self._ttl, jwks)
        return jwks


def _find_key(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
    for key in jwks.get("keys") or []:
        if isinstance(key, dict) and key.get("kid") == kid:
            return key
    return None


# ---------------------------------------------------------------------------
# Discovery (.well-known/openid-configuration).
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class DiscoveredEndpoints:
    """The pieces of the provider's discovery document we use."""

    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    issuer: str
    # Some providers (Okta) include `end_session_endpoint`; we don't
    # use it at v1 but it's worth knowing about for logout-via-IdP.
    end_session_endpoint: str | None = None


def discover(config: OIDCProviderConfig, client: HTTPClient) -> DiscoveredEndpoints:
    """Fetch + parse the OIDC discovery document.

    Raises ConfigError if the discovery document is missing
    required fields or doesn't match the configured issuer.
    """
    try:
        doc = client.get_json(config.discovery_endpoint())
    except Exception as e:
        raise ConfigError(
            f"OIDC discovery failed at {config.discovery_endpoint()}: {e}"
        ) from e

    issuer = doc.get("issuer")
    # WB9-05 same closure: defensive check before .rstrip().
    if not isinstance(issuer, str) or not issuer:
        raise ConfigError("discovery doc has missing or non-string issuer")
    if issuer != config.issuer:
        # Some providers return issuer without trailing slash; tolerate.
        if issuer.rstrip("/") != config.issuer.rstrip("/"):
            raise ConfigError(
                f"discovery doc issuer {issuer!r} does not match "
                f"configured issuer {config.issuer!r}"
            )

    auth = doc.get("authorization_endpoint")
    token = doc.get("token_endpoint")
    jwks = doc.get("jwks_uri")
    if not (auth and token and jwks):
        raise ConfigError(
            "discovery doc missing required endpoints "
            "(authorization_endpoint / token_endpoint / jwks_uri)"
        )

    return DiscoveredEndpoints(
        authorization_endpoint=auth,
        token_endpoint=token,
        jwks_uri=jwks,
        issuer=issuer,
        end_session_endpoint=doc.get("end_session_endpoint"),
    )


# ---------------------------------------------------------------------------
# Authorization URL + state/nonce.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class AuthSession:
    """Server-side state we keep across the redirect.

    Stored as a signed cookie (or server-side session if we add
    one later). The signature prevents tampering; max_age bounds
    replay.
    """

    state: str  # CSRF nonce — matches against query param on callback
    nonce: str  # OIDC nonce claim — embedded in ID token, verified on callback
    issued_at: int  # epoch seconds


def build_authorization_url(
    config: OIDCProviderConfig,
    endpoints: DiscoveredEndpoints,
    session: AuthSession,
    *,
    extra_params: dict[str, str] | None = None,
) -> str:
    """Build the URL to redirect the user to for authentication."""
    params = {
        "client_id": config.client_id,
        "response_type": "code",
        "scope": " ".join(config.scopes),
        "redirect_uri": config.redirect_uri,
        "state": session.state,
        "nonce": session.nonce,
        # Force the user to pick / re-confirm an account each time.
        # Prevents silent re-login under a different identity.
        "prompt": "select_account",
    }
    if config.provider == "google" and config.hosted_domain:
        # `hd` is HINT-only; the server-side `hd` claim check on the
        # returned ID token is the actual workspace boundary.
        params["hd"] = config.hosted_domain
    if extra_params:
        params.update(extra_params)
    return f"{endpoints.authorization_endpoint}?{urlencode(params)}"


def new_auth_session() -> AuthSession:
    """Mint a fresh state + nonce pair for a new login attempt."""
    return AuthSession(
        state=_secrets.token_urlsafe(32),
        nonce=_secrets.token_urlsafe(32),
        issued_at=int(time.time()),
    )


# ---------------------------------------------------------------------------
# Token exchange + ID token validation.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ValidatedIdentity:
    """The result of a successful sign-in.

    `email` is the verified email address (lowercased). `mfa` is
    True if the provider's amr claim indicates MFA was used —
    propagates downstream to AWS via aws:MultiFactorAuthPresent
    Condition per [[mfa-compliance-strategy]].
    """

    email: str
    sub: str  # provider-stable user identifier
    mfa: bool
    groups: tuple[str, ...]  # empty when provider doesn't expose group claim
    provider: str
    issued_at: int


# WB9-06 closure: only AMR values that genuinely indicate
# multi-factor authentication. Per RFC 8176:
#   "mfa"  — multi-factor (explicit)
#   "otp"  — one-time password
#   "totp" — time-based OTP
#   "hwk"  — hardware key (e.g., FIDO/U2F/YubiKey)
#   "swk"  — software key
#   "wia"  — Windows Integrated Authentication (Kerberos)
#   "fpt"  — fingerprint biometric
#   "iris" — iris biometric
#   "face" — face biometric
#   "pop"  — proof-of-possession (e.g., DPoP)
#
# Removed:
#   "sms"  — SMS-based is technically a factor but is weak/spoofable;
#            no longer counts as MFA per NIST 800-63B for high-risk.
#            If a customer specifically wants to count SMS, they can
#            override IAM_JIT_OIDC_AMR_MFA_VALUES (future feature).
#   "user" — user-presence (e.g., button push) is NOT a factor; it's
#            a liveness check. Including it conflated MFA with mere
#            "the user clicked something."
_AMR_MFA_VALUES = frozenset({
    "mfa", "otp", "totp", "hwk", "swk", "wia", "fpt", "iris", "face", "pop",
})


def exchange_code_for_id_token(
    code: str,
    config: OIDCProviderConfig,
    endpoints: DiscoveredEndpoints,
    client: HTTPClient,
) -> str:
    """Exchange the authorization code for an ID token (JWT)."""
    try:
        resp = client.post_form(
            endpoints.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": config.redirect_uri,
                "client_id": config.client_id,
                "client_secret": config.client_secret,
            },
            headers={"Accept": "application/json"},
        )
    except Exception as e:
        raise TokenExchangeError(
            f"token exchange at {endpoints.token_endpoint} failed: {e}"
        ) from e

    id_token = resp.get("id_token")
    if not id_token or not isinstance(id_token, str):
        # WB9-02 closure: don't interpolate the entire response into
        # the exception message — it includes the access_token,
        # which would land in CloudWatch logs as a credential leak.
        # Log ONLY the keys present (structural info, no values).
        keys_present = sorted(resp.keys()) if isinstance(resp, dict) else []
        raise TokenExchangeError(
            f"token response missing id_token (keys present: {keys_present})"
        )
    return id_token


def validate_id_token(
    id_token: str,
    config: OIDCProviderConfig,
    endpoints: DiscoveredEndpoints,
    expected_nonce: str,
    jwks_cache: JWKSCache,
    *,
    now: float | None = None,
) -> ValidatedIdentity:
    """Validate the ID token and extract the verified identity.

    Performs all OIDC mandatory checks:
      - signature against JWKS
      - `iss` matches expected
      - `aud` matches client_id
      - `exp` in future, `iat` in past
      - `nonce` matches expected
      - `email_verified == true`
      - Provider-specific: Google `hd` claim matches hosted_domain;
        Okta optional `groups` membership

    Raises TokenValidationError on any failure.
    """
    import jwt
    from jwt.exceptions import (
        InvalidTokenError,
        ExpiredSignatureError,
        InvalidSignatureError,
        DecodeError,
    )

    # Pull the kid from the unverified header so we can find the
    # right JWKS entry.
    try:
        header = jwt.get_unverified_header(id_token)
    except DecodeError as e:
        raise TokenValidationError(f"malformed ID token header: {e}") from e

    kid = header.get("kid")
    alg = header.get("alg")
    if not kid:
        raise TokenValidationError("ID token header missing kid")
    if alg not in {"RS256", "RS384", "RS512", "ES256", "ES384"}:
        # Reject HS256 + none + others — providers use asymmetric.
        raise TokenValidationError(
            f"ID token algorithm {alg!r} is not allowed "
            f"(must be RS256/384/512 or ES256/384)"
        )

    # Fetch the JWK from cache (auto-refreshes on unknown kid).
    try:
        jwk = jwks_cache.get_key(endpoints.jwks_uri, kid)
    except JWKSError as e:
        raise TokenValidationError(f"key lookup failed: {e}") from e

    # Convert JWK → PEM-public-key for PyJWT.
    try:
        from jwt.algorithms import RSAAlgorithm, ECAlgorithm

        if alg.startswith("RS"):
            public_key = RSAAlgorithm.from_jwk(jwk)
        else:
            public_key = ECAlgorithm.from_jwk(jwk)
    except Exception as e:
        raise TokenValidationError(f"could not convert JWK to public key: {e}") from e

    # Verify signature + standard claims.
    try:
        # We DON'T let PyJWT validate `aud` automatically because we
        # want to give a clear error per-claim. Pass options to
        # disable PyJWT's iss/aud checks and do them ourselves.
        claims = jwt.decode(
            id_token,
            key=public_key,
            algorithms=[alg],
            options={"verify_aud": False, "verify_iss": False},
        )
    except ExpiredSignatureError as e:
        raise TokenValidationError(f"ID token expired: {e}") from e
    except InvalidSignatureError as e:
        raise TokenValidationError(f"ID token signature invalid: {e}") from e
    except InvalidTokenError as e:
        raise TokenValidationError(f"ID token invalid: {e}") from e

    current = now if now is not None else time.time()

    # `iss` check.
    issuer = claims.get("iss")
    # WB9-05 closure: iss missing or non-string previously raised
    # AttributeError on .rstrip() — return a clean validation error.
    if not isinstance(issuer, str) or not issuer:
        raise TokenValidationError("ID token missing or non-string iss claim")
    if issuer != endpoints.issuer:
        if issuer.rstrip("/") != endpoints.issuer.rstrip("/"):
            raise TokenValidationError(
                f"iss {issuer!r} does not match expected {endpoints.issuer!r}"
            )

    # `aud` check.
    aud = claims.get("aud")
    # `aud` can be a string or an array; either way, client_id must be in it.
    if isinstance(aud, str):
        aud_ok = aud == config.client_id
    elif isinstance(aud, list):
        aud_ok = config.client_id in aud
    else:
        aud_ok = False
    if not aud_ok:
        raise TokenValidationError(
            f"aud {aud!r} does not include client_id {config.client_id!r}"
        )

    # `exp` and `iat`.
    exp = claims.get("exp")
    iat = claims.get("iat")
    if not isinstance(exp, (int, float)) or exp < current:
        raise TokenValidationError(f"ID token expired (exp={exp}, now={int(current)})")
    if not isinstance(iat, (int, float)) or iat > current + 60:
        # Tolerate 60s of clock skew on iat-in-future.
        raise TokenValidationError(f"ID token iat is in the future (iat={iat}, now={int(current)})")

    # `nonce` check (replay protection).
    token_nonce = claims.get("nonce")
    if token_nonce != expected_nonce:
        raise TokenValidationError(
            "ID token nonce does not match the expected value "
            "(replay attempt or state-cookie mismatch?)"
        )

    # `email_verified` check.
    email = claims.get("email")
    if not isinstance(email, str) or not email:
        raise TokenValidationError("ID token missing email claim")
    email_verified = claims.get("email_verified")
    if email_verified is not True:
        raise TokenValidationError(
            f"email_verified is not true ({email_verified!r}). "
            "iam-jit requires the provider to verify the email."
        )

    # Provider-specific gates.
    if config.provider == "google":
        # `hd` claim verification — THE workspace boundary for Google.
        hd = claims.get("hd")
        if config.hosted_domain and hd != config.hosted_domain:
            raise WorkspaceRejected(
                f"Google `hd` claim {hd!r} does not match configured "
                f"hosted_domain {config.hosted_domain!r}. Workspace not allowed."
            )

    if config.required_groups:
        # Okta / Azure / Auth0: gate on group membership.
        # Different providers expose group claims slightly differently;
        # accept the common variants.
        groups = claims.get("groups") or claims.get("roles") or []
        if not isinstance(groups, list):
            groups = []
        groups_set = {str(g) for g in groups}
        required = set(config.required_groups)
        if not (groups_set & required):
            raise WorkspaceRejected(
                f"user not in any required group {sorted(required)!r}; "
                f"user groups: {sorted(groups_set)!r}"
            )

    # MFA detection via amr.
    amr = claims.get("amr") or []
    if isinstance(amr, str):
        amr = [amr]
    mfa = any(v in _AMR_MFA_VALUES for v in amr if isinstance(v, str))

    # Capture groups for downstream use (audit, future role mapping).
    # WB9-09 closure: accept BOTH `groups` and `roles` claim names
    # for downstream propagation. Different IdPs name this differently
    # (Okta = `groups`; some Azure setups = `roles`; Auth0 varies).
    groups_raw = claims.get("groups") or claims.get("roles") or []
    if not isinstance(groups_raw, list):
        groups_raw = []
    groups_tuple = tuple(str(g) for g in groups_raw)

    return ValidatedIdentity(
        email=email.strip().lower(),
        sub=str(claims.get("sub") or ""),
        mfa=mfa,
        groups=groups_tuple,
        provider=config.provider,
        issued_at=int(claims.get("iat") or current),
    )
