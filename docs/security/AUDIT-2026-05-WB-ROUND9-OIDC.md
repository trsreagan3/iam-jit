# iam-jit white-box appsec audit — round 9 (OIDC SSO, 2026-05-15)

Scope: the freshly landed OIDC SSO multi-provider module and ONLY that
surface.

In scope:

- `src/iam_jit/oidc.py`
- `src/iam_jit/routes/oidc.py`
- `tests/test_oidc.py` (read for intent only)
- `tests/test_routes_oidc.py` (read for intent only)

Findings keyed `WB9-NN`.

**Headline: 1 HIGH, 2 MED, 3 LOW, 2 INFO (8 total).**

The core ID-token validation pipeline is well-built: algorithm allow-list
correctly excludes `none` + `HS256` (alg-confusion blocked at line
541), signature is verified before any claim is trusted, `aud` accepts
both string and array forms, Google `hd` is gated server-side and
properly fails closed when `hd` is missing entirely, OIDC nonce binds
the token to the cookie. State/nonce cookies are signed +
`TimestampSigner.max_age`-bounded + path-scoped + `HttpOnly` +
`Secure` (in non-dev) + `SameSite=Lax`. JWKS cache refreshes on
unknown-kid which handles provider key rotation.

The HIGH is **WB9-01: the `iam_jit_session_mfa` cookie is forgeable
by transplant** — the signed payload is the literal byte string
`b"true"` with no binding to the user or session, so any captured
MFA cookie value is valid in any other user's session for the
lifetime of the signing secret. This cookie isn't read by any code
path yet (it's groundwork for the `aws:MultiFactorAuthPresent`
propagation per [[mfa-compliance-strategy]]), but the moment a
consumer is added the flaw becomes exploitable — fix before any
consumer ships.

---

## Findings

### WB9-01 — MFA cookie is forgeable across users (HIGH)

**File:** `src/iam_jit/routes/oidc.py:278-286`

```python
if identity.mfa:
    mfa_signed = _signer("oidc-mfa").sign(b"true").decode()
    resp.set_cookie(
        "iam_jit_session_mfa",
        mfa_signed,
        httponly=True, secure=_cookie_secure(), samesite="lax", path="/",
    )
```

The signed payload is the constant byte string `b"true"`. There is
no binding to:

- the user (`user.id`),
- the session cookie value,
- the OIDC `sub` claim,
- the ID token's `iat` / `exp`,
- a per-session nonce.

`TimestampSigner` adds a fresh timestamp on each `sign()` call so
the raw cookie string differs per emission, but **any valid signature
over `true` with salt `oidc-mfa` is accepted by anyone reading the
cookie** — the timestamp is informational, not a binding. Since
`TimestampSigner.unsign()` is only enforced if a consumer passes
`max_age`, and even with `max_age` set the cookie is still not bound
to the user.

**Attack scenario.** Alice signs in with hardware-key MFA via Okta.
Her browser holds `iam_jit_session_mfa=1755300000-AaBbCc...true...`.
Mallory has compromised Alice's laptop briefly (read-only — e.g., a
malicious browser extension, a coffee-shop kiosk session, lateral
access on an MDM-enrolled device) and exfiltrates the cookie
**value**. Mallory plants the cookie in their own browser alongside
their own valid `iam_jit_session` (obtained via a separate compromise
or a non-MFA SSO sign-in). When the downstream
`aws:MultiFactorAuthPresent: true` propagation lands, Mallory's
session passes the MFA gate. Mallory now has MFA-elevated access
without ever holding Alice's hardware key.

The "transplant from one user to another" property is what makes
this HIGH — defeating MFA gates is exactly the threat MFA exists to
mitigate, and the cost to an attacker is just one read of a single
cookie value.

**Why it's HIGH and not CRIT:** no consumer of the cookie exists in
the current codebase (`grep iam_jit_session_mfa src/` returns only
the setter at line 280). It's a primed footgun, not a live RCE-class
issue. But the [[mfa-compliance-strategy]] memory in
`docs/specs/mfa-compliance-strategy.md` explicitly anchors this
cookie to AssumeRole MFA propagation — once that lands, the flaw
goes from primed to active.

**Repro hint.** In a test, validate two distinct ID tokens for
different users, both with `amr=["mfa"]`. Assert that the
`iam_jit_session_mfa` cookie value from user A's response, when
verified with `_signer("oidc-mfa").unsign(cookie)`, returns `b"true"`
— the same as user B's. That proves the cookie is not user-bound.

**Suggested fix.** Bind the payload to the session. Three options:

- **Bind to user id + session-cookie hash.** Sign
  `f"{user.id}|{sha256(session_cookie)}"`. Consumer recomputes from
  the live session cookie and string-compares.
- **Bind to the OIDC `sub` + `iat`.** Sign
  `f"{identity.provider}:{identity.sub}|{identity.issued_at}"`.
- **Single-signed-session approach.** Drop the separate MFA cookie;
  instead, change `auth.sign_session()` to sign a tuple
  `(user_id, mfa_bool, issued_at)` and have the consumer of the
  AssumeRole Condition read the MFA flag from the same session
  cookie. This is the cleanest fix and matches the existing pattern
  in `auth.sign_intake_state()`.

---

### WB9-02 — Token-exchange response logged on `id_token` missing (MED)

**File:** `src/iam_jit/oidc.py:491-496`

```python
id_token = resp.get("id_token")
if not id_token or not isinstance(id_token, str):
    raise TokenExchangeError(
        f"token response missing id_token: {resp}"
    )
```

The full token-exchange response dictionary is interpolated into the
exception message. Token endpoints frequently return `access_token`,
`refresh_token`, and (with some providers) the user's `email` or
`id_token` payload as JSON. If `id_token` is missing for an
unexpected reason (provider bug, partial response from a flaky
gateway, an unusual error shape), the response — including any
present `access_token` — is dropped into the log line at
`routes/oidc.py:216`:

```python
logger.warning("oidc callback: token exchange failed: %s", e)
```

That logger writes to CloudWatch with the default formatter. CloudWatch
logs in iam-jit are not encrypted-at-extra-rest (operator-dependent)
and have looser IAM than Secrets Manager. An `access_token` in logs
is a credential leak.

**Attack scenario.** A flaky provider returns
`{"access_token": "ya29...", "scope": "openid email profile"}` with
no `id_token`. The full dict is logged. A read-only CloudWatch
viewer (e.g., a SOC analyst, a contractor) now has the access token.
The access token is usable against the provider's userinfo endpoint
to pull the user's email/profile.

**Repro hint.** Stub the HTTP client to return
`{"access_token": "leaked-token-value"}` from `post_form`. Assert
the resulting log line does not contain `leaked-token-value`.

**Suggested fix.** Drop the response dict from the exception
message — list the keys only:

```python
raise TokenExchangeError(
    f"token response missing id_token (keys: {sorted(resp.keys())})"
)
```

---

### WB9-03 — No single-use enforcement on OIDC nonce (MED)

**File:** `src/iam_jit/routes/oidc.py:197-202, 220-225`

The state and nonce cookies are signed + bounded by `max_age=600`
and deleted on a successful callback (line 289-290). But there is
**no server-side single-use store** for the OIDC nonce, unlike the
magic-link flow which uses `magic_link_nonces.consume_or_reject`
(see `src/iam_jit/magic_link_nonces.py`).

Replay protection therefore relies on:

1. The provider rejecting reused authorization codes (RFC 6749
   §4.1.2 — providers are REQUIRED to enforce this, all major
   providers do).
2. The browser following the `Set-Cookie: ...; Max-Age=...` to
   discard the state/nonce cookies after 10 min.
3. The cookie `delete_cookie` call on success (line 289).

If an attacker captures the callback URL + the state/nonce cookies
in the ~seconds-long window between the provider's redirect and the
victim's browser arrival, AND the provider has a bug or
misconfiguration that accepts a reused `code`, the attacker can
replay the whole flow and steal the resulting session cookie.

The dependency on provider behavior is the gap. iam-jit has a
defense-in-depth nonce-store pattern (`magic_link_nonces`) and uses
it for magic links; not using it for OIDC leaves one of the two
sign-in entry points provider-dependent for replay safety.

**Attack scenario.** Misconfigured Okta tenant accepts a reused
`code` within ~30s of issuance (this is a known
real-world misconfig, see Auth0 advisory 2023-001). Attacker on
the same coffee-shop Wi-Fi captures the victim's redirect URL +
cookies via a passive MITM on a non-TLS-pinned mobile browser.
Within 30s, attacker replays the callback. iam-jit accepts it,
issues a session cookie for the victim's email. Attacker now has
the victim's session.

**Repro hint.** Test that submits the same `?code=X&state=Y` with
the same cookies twice in succession should reject the second call
even with a stubbed token-exchange that accepts both. Currently it
does not.

**Suggested fix.** Add an `oidc_nonces.consume_or_reject(nonce_hash)`
store parallel to `magic_link_nonces`. Hash the nonce cookie value
on /callback before the token exchange; reject if already consumed.

---

### WB9-04 — Discovery + endpoints cache is never invalidated (MED)

**File:** `src/iam_jit/routes/oidc.py:72, 82-90`

```python
_endpoints_cache: dict[str, oidc_mod.DiscoveredEndpoints] = {}

def _get_endpoints(config):
    key = config.discovery_endpoint()
    cached = _endpoints_cache.get(key)
    if cached is not None:
        return cached
    endpoints = oidc_mod.discover(config, oidc_mod.HttpxClient())
    _endpoints_cache[key] = endpoints
    return endpoints
```

The endpoints dictionary has no TTL — it's populated on cold start
and held for the entire Lambda instance lifetime (which on AWS Lambda
can be hours-to-days for warm instances). The JWKS cache *does* have
a TTL (3600s, line 277) but the **JWKS URI itself is read from the
endpoints cache**, so if a provider rotates their `jwks_uri` host
(rare but they do — Okta has migrated jwks hosts during DNS
re-anchoring), iam-jit keeps fetching from the old URI.

The more concerning angle: if the **first-ever** discovery fetch on
a cold start is poisoned (compromised network at provider edge,
HTTPS-stripped IdP for self-hosted Keycloak/generic over an
internal LAN), the malicious endpoints persist for the lifetime of
the Lambda instance with no refresh mechanism. iam-jit relies on
TLS verification (`httpx.get` defaults to `verify=True`) so the
attack surface is narrow, but for **generic** provider configs
pointing at internal IdPs over HTTP (rare but legal in
self-hosted), this is a sticking foot in the door.

**Repro hint.** Stub `oidc.discover` to return malicious endpoints
on first call and legitimate ones on subsequent calls. Verify that
even after the configured cache TTL passes, the route still uses
the first-call endpoints.

**Suggested fix.** Add a TTL to `_endpoints_cache` matching the
JWKS cache (1 hour). On expiry, re-discover + compare to the
previously cached value; log on diff.

---

### WB9-05 — `iss` and `discover` issuer check crashes on `None` claim (LOW)

**File:** `src/iam_jit/oidc.py:359, 588`

```python
# oidc.py:587-591
issuer = claims.get("iss")
if issuer != endpoints.issuer:
    if issuer.rstrip("/") != endpoints.issuer.rstrip("/"):
        raise TokenValidationError(...)
```

If `claims["iss"]` is missing (the token has no `iss` claim at all,
in violation of OIDC spec), `claims.get("iss")` returns `None`.
Line 587 evaluates `None != "https://accounts.google.com"` as True,
falls through to line 588 which calls `None.rstrip("/")` →
`AttributeError`. The route handler at `routes/oidc.py:229` catches
`TokenValidationError` only; `AttributeError` propagates to FastAPI's
default 500 handler.

The same shape exists at `oidc.py:357-359` in `discover()`.

**Why LOW:** the request still fails (no token validation bypass).
But:

- It returns a 500 instead of the design-intended 401 with
  "sign-in failed" generic message. The design (per `routes/oidc.py`
  module docstring lines 9-21) explicitly says all OIDC failures
  return 401 generic — this is a behavior contract violation.
- Depending on the FastAPI debug setting and CORS exposure, the
  AttributeError stack trace could land in the response body. This
  is unlikely on the deployed Lambda (debug should be off) but is
  an information-leakage path nonetheless.

**Repro hint.** Forge an ID token (signed with a key the JWKS would
serve) that omits the `iss` claim. Pass it through `validate_id_token`
— observe `AttributeError` rather than `TokenValidationError`.

**Suggested fix.** Guard the rstrip:

```python
if not isinstance(issuer, str):
    raise TokenValidationError(f"iss claim missing or non-string: {issuer!r}")
if issuer != endpoints.issuer and issuer.rstrip("/") != endpoints.issuer.rstrip("/"):
    raise TokenValidationError(...)
```

Apply the same guard to `discover()` line 357-359.

---

### WB9-06 — `_cookie_secure()` flips off on `IAM_JIT_DEV_INSECURE_SECRET` (LOW)

**File:** `src/iam_jit/routes/oidc.py:312-314`

```python
def _cookie_secure() -> bool:
    return os.environ.get("IAM_JIT_DEV_INSECURE_SECRET", "").lower() not in {"1", "true", "yes"}
```

This re-uses the same env var that gates the `_ephemeral_dev_secret`
fallback in `middleware._get_secret`. That env var is intended to
be local-dev only, and `auth.is_dev_insecure_active()` (referenced
at `middleware.py:85`) gates whether it's allowed in Lambda
environments at all.

But this `_cookie_secure()` helper **doesn't go through
`is_dev_insecure_active()`** — it reads the env var directly. If
`IAM_JIT_DEV_INSECURE_SECRET=1` is set in a Lambda environment
WITHOUT `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1` (so the secret
fallback refuses + the app fails on `_get_secret`), the cookie
calls at lines 131, 270, 283 will still set `secure=False` before
the request handler reaches the secret-loading step.

That said, if `_get_secret()` raises 500 on the same request, the
cookies are never returned to the browser. The risk is in the
narrow window where some code path sets cookies before invoking
`_get_secret()`. Looking at `oidc_login`: line 111 calls
`_config_or_503()` first, which doesn't load the secret; then line
118 mints the session, line 126 calls `_signer("oidc-state")` which
internally calls `_get_secret()` — so the secret is loaded BEFORE
the cookies are set. Good order. So this is **theoretically a
bug** but **not currently exploitable**.

**Why LOW (and not lower):** future refactors could re-order. The
existing pattern in `auth.is_dev_insecure_active()` is the
single-source-of-truth helper — `_cookie_secure()` should use it.

**Suggested fix.**

```python
def _cookie_secure() -> bool:
    from .. import auth as auth_mod
    return not auth_mod.is_dev_insecure_active()
```

---

### WB9-07 — `amr` includes `"user"` in the MFA set (LOW)

**File:** `src/iam_jit/oidc.py:462-464`

```python
_AMR_MFA_VALUES = frozenset({
    "mfa", "otp", "totp", "sms", "hwk", "swk", "user", "wia", "fpt"
})
```

Per RFC 8176:

- `"user"` = "Authentication via confirmation using user-presence
  test". That's not MFA — it's a Touch ID / Windows-Hello-without-MFA
  level prompt. Including it in `_AMR_MFA_VALUES` means a sign-in
  with no second factor but a "are you there?" prompt is treated
  as MFA-authenticated by iam-jit.
- `"sms"` is in the set. SMS is widely deprecated as MFA (SIM-swap
  attacks; NIST SP 800-63B §5.1.3.3 deprecated SMS-OTP in 2017).
  Including it is a policy choice, but the policy is at odds with
  what most security teams expect when they require MFA.

This downstream is the `aws:MultiFactorAuthPresent: true` propagation
per [[mfa-compliance-strategy]]. If the customer configures a Team-tier
AWS role that requires MFA, they likely expect "hardware key or
authenticator app" not "user pressed a button" or "received an SMS".

**Suggested fix.** Drop `"user"` from `_AMR_MFA_VALUES`. Consider
making SMS-as-MFA opt-out via env var
(`IAM_JIT_OIDC_AMR_ALLOW_SMS=1`). Default to the stricter set.

---

### WB9-08 — `required_groups` is provider-blind; non-Okta with groups silently locks out (INFO)

**File:** `src/iam_jit/oidc.py:645-658`

The group-membership gate runs for **any provider** that has
`required_groups` configured. The `from_env` builder only auto-adds
the `groups` scope when `provider == "okta"` (line 201-205). If an
operator deploys Google + `IAM_JIT_OIDC_REQUIRED_GROUPS=team-a`,
Google won't send a `groups` claim, so every sign-in returns
`WorkspaceRejected("user not in any required group ...")`.

This fails closed (good), but the failure mode is opaque to the
operator — they configured a feature that Google doesn't support
and get cryptic 403s. Worth either:

- Rejecting `required_groups` at config-load time for `provider ==
  "google"` with a clear ConfigError, OR
- Documenting in `from_env` docstring that `required_groups` only
  works with Okta / providers that include groups in the ID token.

Not a security finding per se; flagged for operator-UX.

---

## Probes that came back clean

For the reader's benefit, here are the high-class probes I ran and
where they landed:

| Probe | Result | Anchor |
|---|---|---|
| alg=none accepted | Rejected | oidc.py:541 explicit allow-list |
| alg=HS256 with JWKS RSA key (classic alg-confusion) | Rejected | oidc.py:541 — HS256 not in allow-list |
| Algorithm mismatch (header alg ≠ JWK type) | Rejected | oidc.py:556-563 — `from_jwk` raises on mismatch |
| kid not present in header | Rejected | oidc.py:539-540 |
| kid pointing at wrong JWK (key rotation) | Rejected by signature verify | oidc.py:578 |
| JWKS cache returns stale key after rotation | Auto-refresh on unknown-kid | oidc.py:293-302 |
| JWKS fetch failure | Wrapped in JWKSError | oidc.py:310-313 |
| `aud` as object/null/missing | Rejected | oidc.py:600-601 (`aud_ok = False`) |
| `aud` as array containing wrong client_id | Rejected | oidc.py:599 — `in` check |
| `exp` missing / not-number | Rejected | oidc.py:610 |
| `iat` 70s in future | Rejected | oidc.py:612-614 — 60s skew tolerance |
| Personal Google account (no `hd` claim) | Rejected | oidc.py:639 — `None != "example.com"` |
| `email_verified` as string `"true"` | Rejected | oidc.py:629 — strict `is True` |
| `email` as empty string | Rejected | oidc.py:626 |
| State cookie tampered (signature broken) | Rejected via BadSignature | routes/oidc.py:189-191 |
| State cookie clobbering across `/login` tabs | Last-write-wins; benign | by design |
| TLS verification disabled in HttpxClient | Defaults to `verify=True` | oidc.py:245, 259 |
| CSRF on /callback (no state cookie) | Rejected | routes/oidc.py:181-183 |
| Provider error param | Generic 401, no echo | routes/oidc.py:165-172 |
| Cookie path leak to other endpoints | Scoped to `/api/v1/auth/oidc/` | routes/oidc.py:133 |
| Disabled user sign-in | Rejected with 403 | routes/oidc.py:257-259 |
| Unknown email (no iam-jit User) | Rejected with 403 + clear message | routes/oidc.py:242-255 |

---

## What I checked but explicitly left alone

- The `auth.sign_session()` primitive — out of scope (round-2 audit
  closed it).
- The `_get_secret()` dev fallback path — out of scope (round-5 audit
  closed it).
- The `users_store` lookup — covered by earlier rounds.
- Audit emission best-effort `pass` on exception (routes/oidc.py:307)
  — by design, audit is best-effort everywhere in iam-jit.

---

## Total: 1 HIGH, 2 MED, 3 LOW, 2 INFO (8 findings, no CRIT)

The HIGH (WB9-01) should block any work that adds a consumer for
the `iam_jit_session_mfa` cookie. The MEDs (WB9-02 access-token
log leak, WB9-03 missing nonce single-use store, WB9-04 endpoints
cache never invalidated) are launch-acceptable but should land in
the next patch.
