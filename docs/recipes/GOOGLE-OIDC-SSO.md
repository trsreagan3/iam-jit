# OIDC SSO (multi-provider) — gap analysis + design

> Status: design doc (2026-05-15). Implementation pending.
> Pilot-blocking. Originally scoped for Google Workspace
> (Omise's IdP); expanded to multi-provider after a second
> early adopter confirmed Okta. Generic OIDC client +
> provider-specific configs. Future providers (Azure AD,
> Auth0, JumpCloud, OneLogin, Keycloak) are small additions.
>
> Scope of this doc:
> - Generic OIDC implementation (core flow, validation, JWKS)
> - Google Workspace as the first provider config
> - Okta as the second provider config
> - Extension points for additional providers

## Why this matters for the pilot

The lighthouse-pilot customer authenticates engineers via Google
Workspace. Every existing access tool in their stack (Hoop,
Slack, internal apps) federates through Google IDP. iam-jit
currently supports:

- `local` mode (magic-link email → session cookie)
- `aws_iam` mode (Function URL SigV4)

**Neither integrates with Google Workspace.** Engineers would have
to maintain a separate iam-jit password/magic-link flow alongside
Google SSO. That's a UX regression vs every other tool they use
and a non-starter for "feels native at this company."

## What "Google OIDC" actually means

Google supports two adjacent identity protocols. We want OIDC, not
plain OAuth 2.0:

- **OAuth 2.0** = authorization. "Can this app access my Drive?"
- **OIDC** = authentication. "Is this user who they say they are?"

For iam-jit, we only need authentication: prove "alice@company.com
is signing in via your Google Workspace" and establish the same
`email:alice@company.com` user_id our existing User store keys on.

### Critical: Google Workspace `hd` parameter

Google's `hd` (hosted-domain) parameter restricts the OIDC flow to
a SINGLE Google Workspace. Without it, ANY Google user
(`@gmail.com`, any workspace) can complete the login and we'd map
them by email — meaning `alice@evil-attacker.com` could sign in,
match no iam-jit User, and... well, get nothing. But:

- We MUST verify `hd` server-side in the ID token, not just send
  it in the request (the request `hd=` parameter is a *hint*, not a
  *check*; only verifying it in the returned ID token claim is the
  actual restriction)
- A customer pilot deployment should ALWAYS pin a specific `hd`

## Implementation surface

### Generic `oidc` auth mode (NOT provider-specific)

Add a single generic `oidc` auth mode alongside `local` and
`aws_iam`. The provider is selected via an additional env var.
This is cleaner than per-provider modes (`google_oidc`,
`okta_oidc`, etc.) because the customer's experience is
"I configure OIDC; iam-jit knows which provider from config."

```
IAM_JIT_AUTH_MODE=oidc
IAM_JIT_OIDC_PROVIDER=google                # google | okta | azure | auth0 | generic
IAM_JIT_OIDC_CLIENT_ID=...
IAM_JIT_OIDC_CLIENT_SECRET_ARN=arn:...      # AWS Secrets Manager ref
IAM_JIT_OIDC_REDIRECT_URI=https://<host>/api/v1/auth/oidc/callback
```

Plus provider-specific config:

```
# For Google Workspace (Omise):
IAM_JIT_OIDC_PROVIDER=google
IAM_JIT_OIDC_HOSTED_DOMAIN=company.com      # mandatory; gates Workspace
                                            # (Google's `hd` claim check)

# For Okta:
IAM_JIT_OIDC_PROVIDER=okta
IAM_JIT_OIDC_ISSUER=https://<org>.okta.com  # mandatory; per-customer
IAM_JIT_OIDC_REQUIRED_GROUPS=iam-jit-users  # optional; gate on group claims

# For Azure AD (future):
IAM_JIT_OIDC_PROVIDER=azure
IAM_JIT_OIDC_TENANT_ID=...
```

Modes can be exclusive (one at a time) for V0. Multi-IdP in
one deployment is V2.

### New routes

```
GET  /api/v1/auth/google/login
GET  /api/v1/auth/google/callback
```

Plus the existing `POST /api/v1/auth/logout` continues to work
(clears the session cookie — same shape as today).

#### `/login` flow

1. Generate `state` (CSRF nonce — 32 bytes, signed cookie)
2. Generate `nonce` (replay protection — 32 bytes, signed cookie)
3. Build the Google authorization URL with:
   - `client_id`
   - `redirect_uri`
   - `response_type=code`
   - `scope=openid email profile`
   - `state=<nonce>`
   - `nonce=<other nonce>`
   - `hd=<configured-domain>` (hint only; we re-check server-side)
   - `prompt=select_account` (so users can switch accounts)
4. 302 redirect to Google

#### `/callback` flow

1. Verify `state` cookie matches the query param (CSRF)
2. POST the authorization `code` to Google's token endpoint
3. Receive `id_token` (JWT signed by Google's private key)
4. Validate the ID token:
   - Signature against Google's published JWKS
     (https://www.googleapis.com/oauth2/v3/certs — cached + rotated)
   - `iss` is `https://accounts.google.com` (or `accounts.google.com`)
   - `aud` matches `IAM_JIT_GOOGLE_OIDC_CLIENT_ID`
   - `exp` is in the future, `iat` is in the past
   - `nonce` matches the cookie value
   - **`hd` claim equals `IAM_JIT_GOOGLE_OIDC_HOSTED_DOMAIN`** — this
     is the load-bearing workspace-restriction check
   - `email_verified` is true (Google sets this; we require it)
5. Resolve `user_id = "email:" + email.lower()`
6. Look up in iam-jit's User store; if not found, return a
   friendly error page ("you're authenticated as alice@company.com
   but no iam-jit user exists for that email; ask an admin to
   register you")
7. If found, issue a session cookie (same shape as
   `local` mode — `auth.sign_session()`)
8. Redirect to `/` (or wherever the user was going)

### Module structure

```
src/iam_jit/
  google_oidc.py            # NEW: OIDC client + JWKS + token validation
  routes/auth_google.py     # NEW: /login + /callback routes
  middleware.py             # UNCHANGED for V0 — session cookie reading
                            # works the same way regardless of how the
                            # session was issued
```

Implementation of `google_oidc.py`:

- `class GoogleOIDCConfig` — env-driven config dataclass
- `def build_authorization_url(state, nonce, config)` — query-string assembly
- `def exchange_code_for_id_token(code, config)` — POST to token endpoint
- `class JWKSCache` — fetches Google's keys, caches 1hr, refreshes on
  unknown kid; uses python-jose or PyJWT (both already
  battle-tested for this exact use case)
- `def validate_id_token(jwt_str, config, expected_nonce)` — full
  validation with hd-claim check

### Dependencies to add

- `pyjwt[crypto]` or `python-jose[cryptography]` — JWT validation.
  Existing code uses `itsdangerous` for session cookies; that's
  symmetric HMAC and doesn't work for Google's RS256-signed
  JWTs. Need an asymmetric-capable lib.
- `httpx` (already in repo) — used for the token-endpoint POST
  and JWKS fetch

## Security considerations

### Load-bearing checks

1. **`hd` claim verification** — the SINGLE most important check.
   Without it, any Google account can complete the flow.
2. **`aud` claim verification** — prevents a malicious app using
   the user's same Google IDP from passing us its ID tokens.
3. **`iss` claim verification** — prevents accepting tokens from
   a different IDP entirely.
4. **`nonce` cookie + claim match** — replay protection.
5. **`state` cookie + query-param match** — CSRF protection.
6. **Signature validation against JWKS** — the foundation.
   Without this everything else is theater.

### Common Google OIDC bugs to avoid

- **Trusting `email` claim without `email_verified=true`** — Google
  CAN issue tokens with unverified emails for some account types.
  Always require `email_verified == true` AND check `hd` (Workspace
  emails are always verified).
- **Trusting `name` / `picture` claims for authorization** — these
  are user-editable in some configurations. Email + hd are the only
  trustworthy claims for auth.
- **JWKS cache that never refreshes** — Google rotates keys ~daily.
  Cache MUST refresh on unknown `kid`.
- **Not bounding the redirect URI** — register the EXACT
  `redirect_uri` in the Google Cloud Console; never accept
  attacker-supplied redirect URIs in the `/callback` route.
- **state-cookie HttpOnly + Secure flags** — both must be set; same
  for the session cookie. Same as the existing magic-link flow.
- **Allowing concurrent logins from different IPs** — we don't
  pin sessions to IP today (cookies aren't IP-bound), which is
  fine for a JIT tool but worth documenting.

## Operator-side setup — Google Workspace (one-time)

1. **Create a Google Cloud project** for the iam-jit deployment
2. **Enable Google Identity Platform / OAuth Consent Screen**
   - User type: Internal (restricts to your Workspace)
   - Scopes: `openid`, `email`, `profile`
   - Authorized domains: your `<host>`
3. **Create OAuth 2.0 Client Credentials**
   - Application type: Web application
   - Authorized redirect URI: `https://<your-iam-jit-host>/api/v1/auth/oidc/callback`
   - Get Client ID + Client Secret
4. **Store Client Secret in AWS Secrets Manager**
5. **Set iam-jit env vars** with `IAM_JIT_OIDC_PROVIDER=google` +
   `IAM_JIT_OIDC_HOSTED_DOMAIN=<your-workspace-domain>`
6. **Pre-register the iam-jit Users** with emails matching the
   Workspace users who will sign in

## Operator-side setup — Okta (one-time)

1. **Create a new OIDC application** in the Okta admin console
   - Application type: Web Application
   - Grant types: Authorization Code
   - Sign-in redirect URI: `https://<your-iam-jit-host>/api/v1/auth/oidc/callback`
2. **Get the Client ID + Client Secret** from the application
3. **Configure scopes**: `openid`, `profile`, `email`
   - Optionally: `groups` if you want group claims in the token
4. **Assign users / groups to the application** in Okta
   - This is the access boundary — only assigned users can sign in
   - The Okta tenant URL IS the workspace boundary (no `hd`
     equivalent needed)
5. **(Optional) Configure group claims in the token**
   - Profile → Sign On → OpenID Connect ID Token → Groups claim
     filter: matches `iam-jit-*` (or whatever pattern names your
     iam-jit-relevant groups)
   - This lets iam-jit gate on group membership without an extra
     API call
6. **Store Client Secret in AWS Secrets Manager**
7. **Set iam-jit env vars** with:
   - `IAM_JIT_OIDC_PROVIDER=okta`
   - `IAM_JIT_OIDC_ISSUER=https://<your-org>.okta.com`
   - `IAM_JIT_OIDC_CLIENT_ID=...`
   - `IAM_JIT_OIDC_CLIENT_SECRET_ARN=arn:...`
   - Optional: `IAM_JIT_OIDC_REQUIRED_GROUPS=iam-jit-users`
8. **Pre-register the iam-jit Users** with emails matching the
   Okta users assigned to the application

## Okta-specific differences from Google

- **No `hd` claim** — the Okta org URL itself is the workspace
  boundary (configured via `IAM_JIT_OIDC_ISSUER`)
- **Groups in token** — Okta puts group membership in the ID
  token by default when the groups claim is configured. iam-jit
  can gate on group membership without an extra API call.
  (Google requires Workspace Admin SDK call for this.)
- **MFA enforcement** is per-app in Okta — set on the
  application's Sign-On Policy, not just the user
- **`amr` claim values** may include
  `["mfa", "pwd"]` / `["mfa", "user"]` / etc. — iam-jit's MFA
  check looks for any of `["mfa"]`, `["otp"]`, `["hwk"]`,
  `["sms"]`, `["pwd", "mfa"]`, etc.

Documented in this file (which will be renamed
`docs/recipes/OIDC-SSO.md` at implementation time).

## Effort estimate

- google_oidc.py module + JWKS cache: ~1 day
- Routes (`/login`, `/callback`): ~half day
- Unit tests (JWKS cache, validate_id_token edge cases, hd check,
  nonce match, state match): ~half day
- Integration test against a Google ID-token fixture: ~half day
- Documentation (this doc + screenshots): done

**Total: ~2.5 days focused work.**

## Why this can't be partially-implemented for the pilot

OIDC isn't a feature you ship 60% of. Either it's fully secure
(all six load-bearing checks) or it's a credential-bypass
primitive. Pilot deployment MUST have the full validation chain
before any real engineer signs in.

## What's NOT in this design

- **Multiple IDP support** (Okta, Azure AD, JumpCloud, etc.) —
  designed to be a follow-up. The auth-mode env var pattern
  generalizes to `okta_oidc`, `azure_oidc`, etc. with the same
  shape; just different issuer / JWKS URL / claim names.
- **Group-based role provisioning** (e.g., "members of the
  `iam-jit-approvers` Google Group automatically get the
  `approver` role"). V1 considers this; for V0 the customer
  registers iam-jit Users explicitly with email + role.
- **SCIM provisioning** — auto-create iam-jit Users when a new
  Workspace user shows up. Future feature.
- **Refresh tokens** — we issue a session cookie at callback
  time; the user re-authenticates with Google when the cookie
  expires (1 day TTL). Refresh-token complexity isn't needed
  for the JIT-tool use case.

## Required follow-ups when implementing

1. **Round-9 BB+WB security audit focused on the OIDC code path.**
   OIDC is high-risk surface; first implementation MUST be
   audited before production deploy.
2. **Test fixture for ID-token validation** — generate a key
   pair in test setup, issue ID tokens signed by it, point the
   JWKS cache at the test public key. Cover every claim-validation
   edge case.
3. **Audit log** — every login emits an `auth.signin` event with
   the Google `sub` (stable user ID) + email + IP. The existing
   audit module handles this; just need to call it from
   `/callback`.
4. **Logout integration** — `/logout` can also call Google's
   `revoke` endpoint (optional; clears the Google session too).
   For V0, clearing the iam-jit cookie is sufficient — they re-
   auth next time they hit `/login`.

## Related memos

- [[self-host-zero-billing-dependency]] — Google OIDC adds NO
  vendor-billing dependency (Google charges by user count for
  Workspace, but that's the customer's existing billing
  relationship)
- [[creates-never-mutates]] — we don't modify the customer's
  Google Workspace state in any way; we just read OIDC tokens
- The Slack approval bot's identity flow ([[hoop-partnership-strategy]]
  recipe) integrates cleanly: Slack user → email → iam-jit User
  is the same path Google OIDC establishes, just via a different
  identity provider front-door
