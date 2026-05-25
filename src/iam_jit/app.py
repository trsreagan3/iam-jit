"""FastAPI application factory.

`create_app(...)` returns a configured FastAPI instance. The same factory
is used by:

  - `iam-jit serve` for local dev (uvicorn + auto-reload, FilesystemStore,
    optional FileUserStore loaded from a local users.yaml).

  - The Lambda handler (`lambda_handler.py`) for production (S3Store,
    DynamoDBUserStore or FileUserStore over s3://).

Stores are passed in or constructed from env vars so tests can inject
fakes without touching environment.
"""

from __future__ import annotations

import os
import pathlib

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import __version__
from .accounts_store import (
    AccountStore,
    FileAccountStore,
    InMemoryAccountStore,
)
from .api_tokens_store import APITokenStore, InMemoryAPITokenStore
from .routes.accounts import router as accounts_router
from .routes.admin import router as admin_router
from .routes.audit_events import router as audit_events_router
from .routes.auth import router as auth_router
# NOTE: intake_router deleted in Stage 4 of [[no-nl-synthesis]].
# Conversational LLM intake was part of the synthesis-from-prompt
# pattern that measured joint sufficiency below the calibration bar. Replaced by raw-JSON
# submit via the existing request-creation endpoint + MCP submit_policy.
from .routes.health import router as health_router
from .routes.policy import router as policy_router
from .routes.reports import router as reports_router
from .routes.requests import router as requests_router
from .routes.tokens import router as tokens_router
from .routes.users import router as users_router
from .routes.web import router as web_router
from .routes.webhooks_stripe import router as webhooks_stripe_router
from .routes.blacklist import router as blacklist_router
from .routes.feedback import router as feedback_router
from .routes.slack import router as slack_router
from .routes.oidc import router as oidc_router
from .store import FilesystemStore, RequestStore
from .users_store import FileUserStore, UserStore


def _build_user_store_from_env() -> UserStore:
    source = (os.environ.get("IAM_JIT_USER_CONFIG_SOURCE") or "dynamodb").lower()
    if source == "file":
        bucket = os.environ.get("IAM_JIT_STATE_BUCKET")
        key = os.environ.get("IAM_JIT_USER_CONFIG_FILE_KEY") or "users.yaml"
        local = os.environ.get("IAM_JIT_USERS_FILE_LOCAL_PATH")
        if local:
            return FileUserStore(local)
        if bucket:
            return FileUserStore(f"s3://{bucket}/{key}")
        raise RuntimeError(
            "IAM_JIT_USER_CONFIG_SOURCE=file requires IAM_JIT_STATE_BUCKET "
            "(or IAM_JIT_USERS_FILE_LOCAL_PATH for dev)."
        )
    # dynamodb (default) — defer import to avoid hard boto3 init in tests
    from .users_store import DynamoDBUserStore

    table = os.environ.get("IAM_JIT_USERS_TABLE")
    if not table:
        raise RuntimeError("IAM_JIT_USERS_TABLE is not configured")
    return DynamoDBUserStore(table)


def _build_request_store_from_env() -> RequestStore:
    """Build the request store from env, preferring stronger backends.

    Precedence:
      1. IAM_JIT_REQUESTS_TABLE  → DynamoDBStore (production default)
      2. IAM_JIT_STATE_BUCKET    → S3Store (legacy / large-blob storage)
      3. IAM_JIT_REQUESTS_DIR    → FilesystemStore (local dev)
    """
    table = os.environ.get("IAM_JIT_REQUESTS_TABLE")
    if table:
        from .store import DynamoDBStore

        return DynamoDBStore(table)
    bucket = os.environ.get("IAM_JIT_STATE_BUCKET")
    if bucket:
        from .store import S3Store

        return S3Store(bucket)
    local_dir = os.environ.get("IAM_JIT_REQUESTS_DIR") or "requests"
    return FilesystemStore(pathlib.Path(local_dir))


def _build_accounts_store_from_env() -> AccountStore:
    """Build the accounts store, mirroring the user-store backend choice.

    Precedence:
      - IAM_JIT_ACCOUNTS_FILE_LOCAL_PATH       → FileAccountStore (local YAML)
      - IAM_JIT_STATE_BUCKET + IAM_JIT_ACCOUNTS_FILE_KEY → FileAccountStore (S3)
      - IAM_JIT_ACCOUNTS_TABLE                 → DynamoDBAccountStore
      - otherwise                              → InMemoryAccountStore (dev)
    """
    local = os.environ.get("IAM_JIT_ACCOUNTS_FILE_LOCAL_PATH")
    if local:
        return FileAccountStore(local)
    bucket = os.environ.get("IAM_JIT_STATE_BUCKET")
    key = os.environ.get("IAM_JIT_ACCOUNTS_FILE_KEY")
    if bucket and key:
        return FileAccountStore(f"s3://{bucket}/{key}")
    table = os.environ.get("IAM_JIT_ACCOUNTS_TABLE")
    if table:
        from .accounts_store import DynamoDBAccountStore

        return DynamoDBAccountStore(table)
    return InMemoryAccountStore()


def _build_api_tokens_store_from_env() -> APITokenStore:
    table = os.environ.get("IAM_JIT_API_TOKENS_TABLE")
    if not table:
        # Local-dev fallback: in-memory tokens. They survive only while the
        # process is alive; that's fine for `iam-jit serve` testing.
        return InMemoryAPITokenStore()
    from .api_tokens_store import DynamoDBAPITokenStore

    return DynamoDBAPITokenStore(table)


def _build_processed_events_store_from_env():
    """Idempotency store for Stripe webhook events. Closes audit
    finding STRIPE-NO-IDEMPOTENCY (round 1 WB) AND the round-4
    STRIPE-DDB-PROCESSED-EVENTS-UNWIRED HIGH (the DDB-backed
    implementation now actually ships).

    Production: set `IAM_JIT_PROCESSED_EVENTS_TABLE` to a DynamoDB
    table with TTL on `expires_at`. Local-dev / single-instance:
    in-memory cache (default).
    """
    from .stripe_webhook import (
        DynamoDBProcessedEventsStore,
        InMemoryProcessedEventsStore,
    )

    table = (os.environ.get("IAM_JIT_PROCESSED_EVENTS_TABLE") or "").strip()
    if table:
        return DynamoDBProcessedEventsStore(table)
    return InMemoryProcessedEventsStore()


def create_app(
    *,
    request_store: RequestStore | None = None,
    user_store: UserStore | None = None,
    api_tokens_store: APITokenStore | None = None,
    accounts_store: AccountStore | None = None,
) -> FastAPI:
    app = FastAPI(
        title="iam-jit",
        version=__version__,
        description="Self-hosted, AI-native, time-bound, least-privilege IAM grants.",
    )

    # Body-size guard: refuse any inbound request with a Content-Length
    # over IAM_JIT_MAX_BODY_BYTES (default 256 KiB). Legitimate iam-jit
    # payloads are tiny (a few KiB at most for a request submission); a
    # caller sending megabytes is either misusing the API or trying to
    # OOM the Lambda. Returns 413 before the route handler runs.
    _max_body_bytes = int(os.environ.get("IAM_JIT_MAX_BODY_BYTES") or 256 * 1024)

    # Source-IP / CIDR allowlist. No-op until the operator sets
    # IAM_JIT_ALLOWED_SOURCE_CIDRS. When set, every non-exempt path
    # is checked against the allowlist BEFORE auth, body parsing, or
    # rate limiting — keep it cheap enough to run on every request.
    @app.middleware("http")
    async def _enforce_source_cidr(request, call_next):
        from fastapi.responses import JSONResponse

        from . import network_acl

        client_host = request.client.host if request.client else None
        decision = network_acl.evaluate(
            path=request.url.path,
            request_client_host=client_host,
            xff_header=request.headers.get("x-forwarded-for"),
        )
        if not decision.allowed:
            import logging

            logging.getLogger("iam_jit.network_acl").warning(
                "blocked request: path=%s source_ip=%s reason=%s",
                request.url.path, decision.source_ip, decision.reason,
            )
            # Per #609: if the operator just locked themselves out
            # via /admin/network, give them the recovery procedure in
            # the response body rather than leaving them stranded with
            # a bare "denied" message.
            return JSONResponse(
                {
                    "detail": "source IP is not in the configured allowlist",
                    "source_ip": decision.source_ip,
                    "reason": decision.reason,
                    "recovery_hint": (
                        "If you locked yourself out via /admin/network, "
                        "restart iam-jit with --skip-network-allowlist "
                        "OR edit ~/.iam-jit/network-allowlist.yaml (or "
                        "your --data-dir/network_cidrs.json) and restart. "
                        "See docs/MRR-4-UNINSTALL.md for full recovery."
                    ),
                },
                status_code=403,
            )
        return await call_next(request)

    # CSRF defense. Cookie-authenticated state-changing requests must
    # carry an Origin or Referer header that matches the application's
    # own host. Cross-site form posts triggered by an attacker page
    # cannot forge these headers (they're set by the browser per spec).
    # Bearer-token and SigV4 requests are exempt — the token itself is
    # the CSRF protection (an attacker page cannot read it).
    # Audit findings: WEB-NO-CSRF-TOKEN (round 1 WB, MED elevated to
    # HIGH by round 1 BB after end-to-end verification on /approve and
    # /tokens endpoints).
    _CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    _CSRF_EXEMPT_PATH_PREFIXES = (
        "/api/v1/webhooks/stripe",  # Stripe has its own signature verification
        "/healthz",
    )

    @app.middleware("http")
    async def _enforce_csrf(request, call_next):
        from fastapi.responses import JSONResponse
        from urllib.parse import urlparse

        # Dev / test mode bypass. Tests use TestClient which doesn't
        # send Origin/Referer headers; production uses real browsers
        # that always set them on form POSTs per spec.
        # `auth.is_dev_insecure_active()` returns True only when the
        # dev flag is set AND we're not in Lambda (or operator
        # opted in). Closes the CSRF leg of DEV-INSECURE-SECRET-
        # MULTI-EFFECT-FOOTGUN.
        from .auth import is_dev_insecure_active

        if is_dev_insecure_active():
            return await call_next(request)

        # Safe methods don't change state — no CSRF risk.
        if request.method in _CSRF_SAFE_METHODS:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(p) for p in _CSRF_EXEMPT_PATH_PREFIXES):
            return await call_next(request)

        # Bearer / SigV4 auth = CSRF-safe (attacker can't read the token
        # to forge the request). Cookie-only auth = needs origin check.
        auth_header = request.headers.get("authorization") or ""
        if auth_header.startswith("Bearer ") or auth_header.startswith("AWS4-HMAC"):
            return await call_next(request)

        # No cookie at all = unauthenticated request; route handler will
        # 401 as appropriate. No need to CSRF-check here.
        if not request.cookies.get("iam_jit_session"):
            return await call_next(request)

        # Cookie-based request: require Origin or Referer to match host.
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        expected_host = (request.headers.get("host") or "").lower()
        # Also accept the explicit env-configured base URL if set.
        configured_base = os.environ.get("IAM_JIT_BASE_URL", "")

        def _host_matches(value: str) -> bool:
            if not value:
                return False
            try:
                parsed_host = (urlparse(value).netloc or "").lower()
            except Exception:
                return False
            if expected_host and parsed_host == expected_host:
                return True
            if configured_base:
                try:
                    cfg_host = (urlparse(configured_base).netloc or "").lower()
                except Exception:
                    cfg_host = ""
                if cfg_host and parsed_host == cfg_host:
                    return True
            return False

        if origin and origin != "null":
            if not _host_matches(origin):
                import logging as _logging
                _logging.getLogger("iam_jit.csrf").warning(
                    "rejecting cookie-based %s %s: Origin %r != host %r",
                    request.method, path, origin, expected_host,
                )
                return JSONResponse(
                    {"detail": "CSRF check failed: Origin does not match host"},
                    status_code=403,
                )
        elif referer:
            if not _host_matches(referer):
                import logging as _logging
                _logging.getLogger("iam_jit.csrf").warning(
                    "rejecting cookie-based %s %s: Referer %r != host %r",
                    request.method, path, referer, expected_host,
                )
                return JSONResponse(
                    {"detail": "CSRF check failed: Referer does not match host"},
                    status_code=403,
                )
        else:
            # Neither Origin nor Referer present on a cookie-authenticated
            # state-changing request. Browsers always send at least one
            # for cross-origin form posts; the absence usually indicates
            # a hand-crafted request (curl, attacker script bypassing the
            # browser security model). Reject conservatively.
            import logging as _logging
            _logging.getLogger("iam_jit.csrf").warning(
                "rejecting cookie-based %s %s: no Origin or Referer header",
                request.method, path,
            )
            return JSONResponse(
                {"detail": "CSRF check failed: missing Origin and Referer"},
                status_code=403,
            )

        return await call_next(request)

    @app.middleware("http")
    async def _enforce_max_body_size(request, call_next):
        from fastapi.responses import JSONResponse

        # BODY-SIZE-GUARD-CHUNKED-BYPASS (round 3 WB MED) closure:
        # `Transfer-Encoding: chunked` requests omit Content-Length
        # and previously bypassed this gate. Refuse chunked-encoded
        # requests here so route handlers don't see unbounded
        # bodies. Lambda Function URLs and CloudFront both forward
        # Content-Length on regular POSTs; chunked is unusual for
        # an API caller and an obvious DoS amplification vector.
        te = (request.headers.get("transfer-encoding") or "").lower()
        if "chunked" in te:
            return JSONResponse(
                {
                    "detail": (
                        "chunked Transfer-Encoding is not supported; "
                        "send a Content-Length-bounded request body."
                    )
                },
                status_code=411,
            )

        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > _max_body_bytes:
                    return JSONResponse(
                        {"detail": "request body exceeds maximum size"},
                        status_code=413,
                    )
            except ValueError:
                return JSONResponse(
                    {"detail": "invalid Content-Length header"},
                    status_code=400,
                )
        else:
            # No Content-Length AND no chunked Transfer-Encoding —
            # this should not happen for a real POST; refuse rather
            # than process an unbounded body via streaming.
            if request.method in {"POST", "PUT", "PATCH"}:
                return JSONResponse(
                    {
                        "detail": (
                            "missing Content-Length on a body-bearing "
                            "request method."
                        )
                    },
                    status_code=411,
                )
        return await call_next(request)

    @app.middleware("http")
    async def _enforce_auth_cache_control(request, call_next):
        """BB4-02 closure: auth'd PII responses get
        `Cache-Control: no-store, private` so browser bfcache /
        corporate proxies don't stale-serve one user's response to
        another. Static assets, /healthz, and the docs UI get no
        override.

        (The previous /api/v1/score exemption was dropped on
        2026-05-24 when the hosted scoring Lambda + REST endpoint
        were removed per [[no-hosted-saas]] restoration. The
        offline `iam-risk-score` CLI is the supported entry
        point.)
        """
        response = await call_next(request)
        path = request.url.path
        # Exempt paths that have their own caching contract.
        if path.startswith("/static/") or path == "/healthz":
            return response
        if path in {"/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"}:
            return response
        # Only add the header on auth'd routes (any /api/v1/* or
        # any non-public web route). Don't trample if the route
        # already set one.
        if "cache-control" in {k.lower() for k in response.headers.keys()}:
            return response
        if path.startswith("/api/v1/") or path.startswith("/admin"):
            response.headers["Cache-Control"] = "no-store, private"
        return response

    # Security headers applied to every response. Defenses:
    #   - X-Frame-Options: DENY — prevents the iam-jit UI from being
    #     embedded in an attacker-controlled iframe (clickjacking).
    #   - X-Content-Type-Options: nosniff — browsers won't second-guess
    #     declared content types (mitigates MIME confusion attacks
    #     where an HTML response gets served as a static asset).
    #   - Referrer-Policy: same-origin — outbound clicks from iam-jit
    #     pages don't leak the request URL (which contains request ids
    #     and sometimes signed tokens) to third parties.
    #   - Content-Security-Policy: strict baseline. iam-jit serves
    #     same-origin assets only and never eval()s untrusted strings.
    #     `unsafe-inline` is allowed for `style-src` because the
    #     base-template inlines a small amount of CSS for the
    #     thinking-spinner animation; `script-src` is locked down to
    #     same-origin.
    #   - Strict-Transport-Security: only sent when the request was
    #     actually served over HTTPS (Function URL behind CloudFront);
    #     1-year max-age + includeSubDomains is the OWASP-recommended
    #     baseline. Skipped for plain HTTP so dev mode still works.
    @app.middleware("http")
    async def _security_headers(request, call_next):
        # BB6-01 closure: even when call_next raises (e.g.
        # RecursionError on deeply-nested JSON), the response we
        # return MUST carry the security-headers baseline. Without
        # this, an uncaught exception in pydantic/JSON validation
        # produced a 500 text/plain "Internal Server Error" with
        # NO CSP / X-Frame-Options / X-Content-Type-Options. The
        # round-1 invariant "security headers on every response"
        # regressed on every uncaught-exception path.
        from fastapi.responses import JSONResponse

        try:
            response = await call_next(request)
        except RecursionError:
            import logging as _logging

            _logging.getLogger("iam_jit").warning(
                "uncaught RecursionError on %s — likely deep-nesting JSON; "
                "returning 400",
                request.url.path,
            )
            response = JSONResponse(
                {"detail": "request body nesting is too deep"},
                status_code=400,
            )
        except Exception:
            import logging as _logging

            # MRR-2 F2 closure (CRIT from
            # docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md): the
            # previous catch-all returned ``{"detail": "internal
            # server error"}`` with no fields the operator could
            # use to correlate the 500 with a server-side log
            # entry. We now generate a stable error_id (ULID,
            # zero-dependency Crockford base32 — same generator
            # the dynamic-denies module uses) and surface it as a
            # structured payload while logging the full traceback
            # against the same id server-side. Inner exception
            # text is NEVER returned to the client (info-disclosure
            # mitigation for the work-AWS deploy).
            from .dynamic_denies.store import new_rule_id

            error_id = "err_" + new_rule_id().removeprefix("dd_")
            route_path = request.url.path or "<unknown>"
            _logging.getLogger("iam_jit").exception(
                "uncaught exception on %s — returning 500 with security headers "
                "(error_id=%s)",
                route_path,
                error_id,
            )
            response = JSONResponse(
                {
                    "detail": "internal server error",
                    "error_id": error_id,
                    "error_code": "UNHANDLED_EXCEPTION",
                    "route_path": route_path,
                    "recommended_action": (
                        f"Report error_id={error_id} to support; "
                        f"server-side logs contain the full traceback "
                        f"correlated by this error_id."
                    ),
                },
                status_code=500,
            )

        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        scheme = request.url.scheme if request.url else ""
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        if scheme == "https" or forwarded_proto == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    app.state.request_store = request_store or _build_request_store_from_env()
    if user_store is not None:
        app.state.user_store = user_store
    else:
        try:
            app.state.user_store = _build_user_store_from_env()
        except Exception:
            app.state.user_store = None  # type: ignore[assignment]
    app.state.api_tokens_store = api_tokens_store or _build_api_tokens_store_from_env()
    app.state.accounts_store = accounts_store or _build_accounts_store_from_env()
    # Stripe idempotency store (audit finding STRIPE-NO-IDEMPOTENCY).
    app.state.processed_events_store = _build_processed_events_store_from_env()

    # First-admin bootstrap (production dead-lock fix).
    # When IAM_JIT_ADMIN_BOOTSTRAP_EMAIL is set AND that user doesn't
    # already exist in the user store, seed them as admin. Idempotent:
    # if they already exist (any subsequent deploy / cold-start) this
    # is a no-op. Without this, a fresh DynamoDB-backed deployment has
    # no way to reach the first admin from inside the system.
    try:
        from . import user_bootstrap

        result = user_bootstrap.maybe_seed_at_startup(app.state.user_store)
        if result.seeded:
            import logging

            logging.getLogger("iam_jit.bootstrap").warning(
                "bootstrap admin seeded at startup: %s — sign in with this "
                "address, add additional admins via the UI, then optionally "
                "clear IAM_JIT_ADMIN_BOOTSTRAP_EMAIL.",
                result.user_id,
            )
        else:
            # Email path didn't seed (no env var or user already exists).
            # Try the random-fallback path. It's a hard no-op unless
            # IAM_JIT_ALLOW_RANDOM_BOOTSTRAP=1 AND the store is empty,
            # so this is safe to call on every cold-start.
            secret = os.environ.get("IAM_JIT_MAGIC_LINK_SECRET") or ""
            public_url = (
                os.environ.get("IAM_JIT_PUBLIC_URL")
                or "http://127.0.0.1:8000"
            )
            if secret:
                random_result = user_bootstrap.maybe_seed_random_at_startup(
                    app.state.user_store,
                    public_url=public_url,
                    secret=secret,
                )
                if random_result.seeded:
                    import logging

                    logging.getLogger("iam_jit.bootstrap").warning(
                        "RANDOM bootstrap admin seeded: %s. Sign-in URL "
                        "written to %s — open it once, add a real admin, "
                        "then delete this user.",
                        random_result.user_id,
                        random_result.written_to or "(see logs)",
                    )
    except Exception:
        import logging

        logging.getLogger("iam_jit.bootstrap").exception(
            "bootstrap-admin step crashed; continuing without seeding"
        )

    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(requests_router)
    app.include_router(tokens_router)
    app.include_router(users_router)
    app.include_router(reports_router)
    app.include_router(policy_router)
    app.include_router(accounts_router)
    app.include_router(admin_router)
    # #620 — `/audit/events` on iam-jit serve mirrors the bouncer wire
    # shape so `iam-jit audit query` can fan-out to serve as one more
    # surface (closes the doc-lie from #613's OUTSTANDING-REQUEST-CAP
    # recipe + the parallel UAT-Web-Admin-06 gap).
    app.include_router(audit_events_router)
    # intake_router removed in Stage 4 of [[no-nl-synthesis]]
    app.include_router(webhooks_stripe_router)
    app.include_router(blacklist_router)
    app.include_router(feedback_router)
    app.include_router(slack_router)
    app.include_router(oidc_router)
    app.include_router(web_router)

    # Serve static assets (CSS, JS) for the web UI. Templates reference
    # /static/* — keep this mount at the end so JSON API routes win.
    static_dir = pathlib.Path(__file__).resolve().parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    return app
