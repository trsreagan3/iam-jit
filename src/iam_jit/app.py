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
from .routes.auth import router as auth_router
from .routes.intake import router as intake_router
from .routes.health import router as health_router
from .routes.policy import router as policy_router
from .routes.reports import router as reports_router
from .routes.requests import router as requests_router
from .routes.score import router as score_router
from .routes.tokens import router as tokens_router
from .routes.users import router as users_router
from .routes.web import router as web_router
from .routes.webhooks_stripe import router as webhooks_stripe_router
from .routes.blacklist import router as blacklist_router
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
    finding STRIPE-NO-IDEMPOTENCY (round 1 WB).

    Local-dev fallback: in-memory cache. Production should set
    `IAM_JIT_PROCESSED_EVENTS_TABLE` to a DynamoDB table with
    TTL on a 30-day window (Stripe retries for ~3 days; 30 is a
    safety margin against dashboard-initiated replays).
    """
    from .stripe_webhook import InMemoryProcessedEventsStore

    table = os.environ.get("IAM_JIT_PROCESSED_EVENTS_TABLE")
    if not table:
        return InMemoryProcessedEventsStore()
    # DynamoDB-backed implementation isn't shipped yet; in-memory
    # works for single-instance Lambda. Multi-instance prod
    # deployments should ship a DDB store and wire it here.
    # For now we accept the in-memory store as the default even
    # when the env var is set, with a log warning.
    import logging as _logging
    _logging.getLogger(__name__).warning(
        "IAM_JIT_PROCESSED_EVENTS_TABLE is set but DynamoDB-backed "
        "ProcessedEventsStore is not yet implemented; falling back "
        "to in-memory (single-instance only). Multi-instance Stripe "
        "idempotency will need a DDB-backed store before launch."
    )
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
            return JSONResponse(
                {
                    "detail": "source IP is not in the configured allowlist",
                    "source_ip": decision.source_ip,
                    "reason": decision.reason,
                },
                status_code=403,
            )
        return await call_next(request)

    @app.middleware("http")
    async def _enforce_max_body_size(request, call_next):
        from fastapi.responses import JSONResponse

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
        return await call_next(request)

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
        response = await call_next(request)
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
    app.include_router(score_router)
    app.include_router(policy_router)
    app.include_router(accounts_router)
    app.include_router(admin_router)
    app.include_router(intake_router)
    app.include_router(webhooks_stripe_router)
    app.include_router(blacklist_router)
    app.include_router(web_router)

    # Serve static assets (CSS, JS) for the web UI. Templates reference
    # /static/* — keep this mount at the end so JSON API routes win.
    static_dir = pathlib.Path(__file__).resolve().parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    return app
