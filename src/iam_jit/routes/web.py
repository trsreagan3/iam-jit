"""Web (HTML) routes — humans-facing surface.

These routes use the same underlying stores, lifecycle, review
modules as the JSON API. Form posts redirect to detail pages; sessions live
in signed cookies. Render with Jinja2 templates from `iam_jit/templates/`.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature

from .. import __version__, assume as assume_mod, audit, auth as auth_mod, bans as bans_mod, health as health_mod, lifecycle, magic_link_nonces, onboarding as onboarding_mod, prompt_injection, rate_limit as rate_limit_mod, review, schema
from ..api_tokens_store import APITokenRecord, APITokenStore
from ..auth import issue_api_token
from ..accounts_store import (
    Account,
    AccountAlreadyExists,
    AccountNotFound,
    AccountStore,
    AccountStoreReadOnly,
    utcnow_iso,
)
from ..middleware import (
    _get_secret,
    current_user,
    get_accounts_store,
    get_api_tokens_store,
    get_request_store,
    get_user_store,
    require_approver,
)
from ..store import NotFoundError, RequestStore
from ..users_store import UserNotFound, UserStore
from .._outstanding_request_cap import check_outstanding_cap as _check_outstanding_cap
from .requests import _generate_id

_TEMPLATES_DIR = pathlib.Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter(include_in_schema=False)  # not part of /api OpenAPI


# ---- Template context helpers ----


def _ctx(
    *,
    active: str | None = None,
    user: Any | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the template context. `request` is NOT included here — it's
    passed positionally to TemplateResponse to avoid jinja2's LRU cache
    keying on the context dict (which contains unhashable values).
    """
    is_admin = bool(user) and "admin" in (getattr(user, "roles", None) or [])
    health_issues = health_mod.get_system_health() if is_admin else []
    ticket_required = (os.environ.get("IAM_JIT_REQUIRE_TICKET") or "").lower() in {"1", "true", "yes"}
    ticket_hint = os.environ.get("IAM_JIT_TICKET_HOST_PATTERN") or ""
    return {
        "version": __version__,
        "auth_mode": (os.environ.get("IAM_JIT_AUTH_MODE") or "local").lower(),
        "ai_enabled": review.is_review_enabled(),
        "current_user": user,
        "active": active,
        "flash": None,
        "health_issues": health_issues,
        "ticket_required": ticket_required,
        "ticket_hint": ticket_hint,
        **(extra or {}),
    }


def _render(
    request: Request,
    name: str,
    *,
    status_code: int = 200,
    **ctx_kwargs: Any,
) -> Response:
    return templates.TemplateResponse(
        request, name, _ctx(**ctx_kwargs), status_code=status_code
    )


def _try_current_user(request: Request) -> Any | None:
    """Best-effort user resolution that returns None instead of raising.

    #612 UAT-Web-Admin-04 closure: the web-side helper now ALSO consults
    the server-side session revocation list. The JSON-API middleware
    (`middleware._identify_user`) has always done this, but
    `_try_current_user` was decoding the cookie + looking up the user
    WITHOUT calling `session_revocation.is_revoked()`. The result: after
    a `/logout` (which adds the cookie hash to the revocation list), an
    attacker holding a copy of the cookie could still load `/`,
    `/queue`, `/admin/*`, and every other web route that authenticates
    via this helper. The fix mirrors the middleware's check — same
    fail-closed-with-opt-out posture, same CRITICAL log line on
    fail-open bypass — so the WEB surface gets the same revocation
    enforcement as the JSON surface.
    """
    user_store = getattr(request.app.state, "user_store", None)
    if user_store is None:
        return None
    cookie = request.cookies.get("iam_jit_session")
    if not cookie:
        return None
    try:
        user_id = auth_mod.verify_session(_get_secret(), cookie)
    except (BadSignature, HTTPException):
        return None
    # #612 UAT-Web-Admin-04 closure: server-side revocation check.
    # Same fail-closed-with-opt-out treatment as middleware. A
    # revoked cookie returns None (caller treats as not-logged-in)
    # so the route's normal "no user → redirect to /login" path
    # kicks in. We deliberately do NOT raise — keeping the helper's
    # "best-effort, returns-None" contract — but a revoked-cookie
    # rejection still trips the standard logout flow visually.
    try:
        from .. import session_revocation as _sr

        if _sr.get_default_store().is_revoked(cookie):
            return None
    except Exception:
        import logging as _logging
        import os as _os

        _logging.getLogger("iam_jit.session_revocation").exception(
            "session-revocation check failed in _try_current_user for "
            "user_id=%s",
            user_id,
        )
        if (
            _os.environ.get("IAM_JIT_SESSION_REVOCATION_FAIL_OPEN") or ""
        ).lower() in {"1", "true", "yes"}:
            _logging.getLogger("iam_jit.session_revocation").critical(
                "SESSION_REVOCATION_FAIL_OPEN bypass invoked for "
                "user_id=%s in _try_current_user — store error, but "
                "revocation enforcement was skipped because "
                "IAM_JIT_SESSION_REVOCATION_FAIL_OPEN=1 is set. "
                "ALARM ON THIS LOG.",
                user_id,
            )
        else:
            # Fail-closed: revocation check broken → refuse to
            # authenticate. The user re-logs in once the store
            # recovers. Matches middleware's behavior.
            return None
    try:
        user = user_store.get(user_id)
    except UserNotFound:
        return None
    if not user.enabled:
        return None
    return user


def _infer_assumer_principal_from_user(user: Any) -> str:
    """Derive a principal identifier for `assume_by.principal_arn` from
    the logged-in user. Matches what the new-paste form's placeholder
    promises: blank field defaults to `current_user.id`.

    The user.id format is `email:<email>` (local mode) or `iam:<arn>`
    (aws_iam mode) — both are accepted by the request schema's
    `principal_arn` pattern. Returns "" if the user is None or has no
    id (defensive — caller treats "" as a hard validation failure)."""
    if user is None:
        return ""
    return getattr(user, "id", "") or ""


# ---- Auth ----


_SAFE_RETURN_TO = {
    "/",
    "/queue",
    "/requests/new",
    # /requests/new/chat removed (LOW-17-07 closure): chat route deleted
    # in Stage 4 of [[no-nl-synthesis]]; pinning it in this allowlist
    # would let a post-login redirect bounce to a deleted 404 page.
    "/requests/new/paste",
    "/admin",
    "/admin/accounts",
    "/admin/users",
    "/admin/bans",
}


def _safe_return_to(raw: str | None) -> str:
    """Sanitize a `return_to` query parameter.

    Only same-origin paths starting with `/` AND matching one of the
    iam-jit known surfaces are allowed. Anything else (including
    schemes like `//evil.com/`, `https://evil.com/`, javascript:, or
    a path that just happens to start with `/`) falls back to `/`.

    Why an explicit allowlist: a generic `startswith('/')` check is
    bypassable with `//evil.com/path` (browsers parse that as
    protocol-relative). Listing the safe destinations is verbose but
    leaves no escape.
    """
    if not raw or not isinstance(raw, str):
        return "/"
    base = raw.split("?", 1)[0].split("#", 1)[0]
    if base in _SAFE_RETURN_TO:
        return raw if raw.startswith("/") else "/"
    if base.startswith("/requests/") and "/" not in base[len("/requests/"):].rstrip("/"):
        # /requests/<id> detail pages — allow.
        return raw
    return "/"


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> Response:
    """Render the sign-in form. Surfaces the deployment's actual
    magic-link delivery channel so the page text matches reality —
    "we'll email you" only when SES is configured; otherwise
    "ask your admin to fetch from CloudWatch logs" or (dev mode)
    "we'll show you the link inline." SES is OPTIONAL for iam-jit;
    the login text shouldn't imply it's required."""
    from .. import magic_link_delivery as _delivery
    return _render(
        request, "login.html", active="login", user=None,
        extra={
            "delivery_channel": _delivery.decide().channel,
            "bootstrap_admin_email": os.environ.get(
                "IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", ""
            ),
        },
    )


_EMAIL_FORM_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _normalize_login_email(raw: str) -> str | None:
    """Strict email normalization for the /login form.

    Refuses anything containing a CR, LF, or other control char (email-
    header injection vector for SES — `Bcc:` smuggling). Refuses
    obviously-malformed input. Returns the lowercased trimmed email or
    None if rejected.
    """
    if not isinstance(raw, str):
        return None
    if "\n" in raw or "\r" in raw or "\x00" in raw:
        return None
    candidate = raw.strip().lower()
    if not candidate or len(candidate) > 254:
        return None
    if not _EMAIL_FORM_RE.match(candidate):
        return None
    return candidate


def _login_client_id(request: Request) -> str:
    """Identify the calling client for /login rate limiting.

    Delegates to the shared `trusted_proxy.real_client_from_xff`
    helper — single source of truth shared with
    `routes/score._client_ip`, `network_acl._read_source_ip`,
    `public_url._peer_in_trusted_proxy_cidrs`, and
    `routes/auth._magic_link_client_ip`. Round-4 WB
    WEB-LOGIN-CLIENT-IP-INLINE-CIDR-PARSER closure.
    """
    from .. import trusted_proxy

    peer = request.client.host if request.client else None
    xff = request.headers.get("x-forwarded-for") or ""
    resolved = trusted_proxy.real_client_from_xff(peer, xff)
    if resolved:
        return f"ip:{resolved}"
    if peer:
        return f"ip:{peer}"
    return "ip:unknown"


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    user_store: Annotated[UserStore, Depends(get_user_store)],
    email: Annotated[str, Form()],
) -> Response:
    auth_mode = (os.environ.get("IAM_JIT_AUTH_MODE") or "local").lower()
    if auth_mode != "local":
        from .. import magic_link_delivery as _delivery
        return _render(
            request, "login.html", active="login", user=None,
            extra={"delivery_channel": _delivery.decide().channel},
        )

    # LOGIN-WEB-MAGIC-LINK-NO-MULTI-INSTANCE-GUARD closure: mirror
    # the JSON API path's guard at the HTML form route. Without it,
    # the in-memory nonce store can't enforce single-use across
    # Lambda instances and an attacker can replay a captured link
    # against a cold-started instance.
    _in_lambda = bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
    _has_ddb_nonces = bool(
        (os.environ.get("IAM_JIT_MAGIC_LINK_NONCES_TABLE") or "").strip()
    )
    _allow_insecure = (
        os.environ.get("IAM_JIT_ALLOW_INSECURE_NONCES", "").lower()
        in {"1", "true", "yes"}
    )
    if _in_lambda and not _has_ddb_nonces and not _allow_insecure:
        return _render(
            request,
            "login.html",
            active="login",
            user=None,
            extra={
                "error": (
                    "multi-instance magic-link replay protection is "
                    "not configured. Operator: set "
                    "IAM_JIT_MAGIC_LINK_NONCES_TABLE or "
                    "IAM_JIT_ALLOW_INSECURE_NONCES=1."
                ),
            },
            status_code=503,
        )

    # Per-IP rate limit. Defends against email enumeration (each /login
    # POST triggers a SES send if the email is known, leaking timing
    # info) and SES bill DoS (an attacker submitting thousands of
    # legitimate emails to drive up cost and trip suppression).
    client_id = _login_client_id(request)
    decision = rate_limit_mod.get_default_limiter().check(
        client_id, kind="login"
    )
    if not decision.allowed:
        # Render the same login_sent page so an attacker can't
        # distinguish "rate limited" from "unknown email".
        return _render(
            request,
            "login_sent.html",
            active="login",
            user=None,
            extra={"email": "(rate limited)", "dev_link": None},
        )

    safe_email = _normalize_login_email(email)
    if safe_email is None:
        # Render the same login_sent page with no dev_link so the
        # response is indistinguishable from "unknown user". Don't
        # echo the original email — it could carry control bytes,
        # smuggled SES headers, or HTML payload — render a safe
        # placeholder instead.
        return _render(
            request,
            "login_sent.html",
            active="login",
            user=None,
            extra={"email": "(invalid address)", "dev_link": None},
        )
    email = safe_email
    user_id = f"email:{email}"
    dev_link: str | None = None
    try:
        user = user_store.get(user_id)
        known = user.enabled
    except UserNotFound:
        known = False

    if known:
        token = auth_mod.sign_magic_link(_get_secret(), user_id)
        from .. import public_url as _public_url
        link_base = _public_url.base_for(request)
        # Preserve return_to through the email round-trip. Validate at
        # the callback before redirecting.
        ret = _safe_return_to(request.query_params.get("return_to"))
        if ret == "/":
            link = f"{link_base}/auth/magic-callback?token={token}"
        else:
            from urllib.parse import quote

            link = (
                f"{link_base}/auth/magic-callback?token={token}"
                f"&return_to={quote(ret, safe='/?=&')}"
            )
        from .. import magic_link_delivery

        decision = magic_link_delivery.deliver(
            email=email, user_id=user_id, link=link
        )
        if decision.show_in_response:
            dev_link = link

    return _render(
        request,
        "login_sent.html",
        active="login",
        user=None,
        extra={"email": email, "dev_link": dev_link},
    )


@router.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request) -> Response:
    """Render the bootstrap-claim form. No GET-query secret accepted —
    secrets only flow via POST body so they never land in webserver
    access logs or browser history."""
    return _render(
        request,
        "setup_claim.html",
        active="login",
        user=None,
        extra={"submitted": False, "error": None},
    )


@router.post("/setup", response_class=HTMLResponse)
def setup_submit(
    request: Request,
    user_store: Annotated[UserStore, Depends(get_user_store)],
    email: Annotated[str, Form()],
    key: Annotated[str, Form()],
) -> Response:
    """One-time bootstrap-admin claim.

    The Phase 1 no-email path: the operator deployed with a
    self-generated `BootstrapSetupKey`, kept it locally, and now
    submits it through this form. The secret is never in CFN
    outputs nor in any URL we issue.

    See `iam_jit/bootstrap_claim.py` for the decision logic.
    """
    from .. import bootstrap_claim

    decision_rl = rate_limit_mod.get_default_limiter().check(
        _login_client_id(request), kind="setup"
    )
    if not decision_rl.allowed:
        return Response(
            status_code=429,
            content="too many setup attempts; try again later",
            headers={
                "Retry-After": str(max(1, decision_rl.retry_after_seconds))
            },
        )

    admin_email = (
        os.environ.get("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL") or ""
    ).strip()
    setup_key = (
        os.environ.get("IAM_JIT_BOOTSTRAP_SETUP_KEY") or ""
    ).strip()
    decision = bootstrap_claim.evaluate_and_claim(
        submitted_email=email,
        submitted_key=key,
        admin_bootstrap_email=admin_email,
        bootstrap_setup_key=setup_key,
        user_store=user_store,
    )

    if not decision.success:
        if decision.reason == "already_claimed":
            return _render(
                request,
                "setup_claim.html",
                active="login",
                user=None,
                extra={
                    "submitted": True,
                    "error": (
                        "This bootstrap claim was already consumed. "
                        "Sign in via /login with the admin email to "
                        "get a fresh magic-link instead."
                    ),
                },
            )
        if decision.reason in (
            "no_admin_configured", "no_secret_configured",
            "bootstrap_user_missing",
        ):
            return Response(
                status_code=503,
                content=(
                    "/setup is not available — the bootstrap admin "
                    "record hasn't been seeded yet, or the deployment "
                    "doesn't have IAM_JIT_BOOTSTRAP_SETUP_KEY set. "
                    "Wait for the Lambda's first cold-start to finish, "
                    "then retry — or set the env var and redeploy."
                ),
            )
        # invalid_key / email_mismatch / store_write_failed → uniform
        # 403 so an attacker can't probe which one fired.
        try:
            audit.emit(
                actor=f"setup_attempt:{_login_client_id(request)}",
                kind="security.setup_refused",
                summary=f"/setup claim refused: {decision.reason}",
                details={"reason": decision.reason},
            )
        except Exception:
            pass
        return _render(
            request,
            "setup_claim.html",
            active="login",
            user=None,
            extra={
                "submitted": True,
                "error": "setup credentials rejected",
            },
        )

    cookie_value = auth_mod.sign_session(_get_secret(), decision.user_id)
    response = RedirectResponse(url="/admin/network", status_code=303)
    response.set_cookie(
        key="iam_jit_session",
        value=cookie_value,
        httponly=True,
        secure=not auth_mod.is_dev_insecure_active(),
        samesite="strict",
        path="/",
        max_age=24 * 60 * 60,
    )
    try:
        audit.emit(
            actor=decision.user_id or "unknown",
            kind="security.bootstrap_claimed",
            summary=f"bootstrap admin claimed via /setup: {decision.user_id}",
            details={"user_id": decision.user_id},
        )
    except Exception:
        pass
    return response


@router.get("/auth/magic-callback")
def magic_callback(
    request: Request, token: str, return_to: str = "/"
) -> Response:
    try:
        user_id = auth_mod.verify_magic_link(_get_secret(), token)
    except BadSignature:
        return RedirectResponse(url="/login?error=invalid_or_expired", status_code=303)

    # Single-use enforcement: once a magic-link is consumed, the same
    # token can never be used again — defends against email-archive
    # leaks, browser-history capture, and proxy logs that retain the
    # URL with the token query param.
    try:
        magic_link_nonces.get_default_store().consume_or_reject(
            auth_mod.magic_link_token_id(token)
        )
    except magic_link_nonces.TokenAlreadyUsed:
        return RedirectResponse(
            url="/login?error=link_already_used", status_code=303
        )

    # Banned users cannot sign in — no point issuing them a session
    # cookie that would be refused at every subsequent request. Tell
    # them via the standard suspended-account page.
    try:
        if bans_mod.get_default_store().is_banned(user_id):
            return Response(
                status_code=403,
                content=(
                    "Your account is suspended due to a detected policy "
                    "violation. Contact your iam-jit administrator if you "
                    "believe this was in error."
                ),
            )
    except Exception:
        pass

    cookie_value = auth_mod.sign_session(_get_secret(), user_id)

    # Bootstrap-admin first-sign-in nudge + auto-seed.
    #
    # If this is one of the auto-seeded bootstrap admins:
    #   1. Capture their current source IP and add it to the runtime
    #      CIDR allowlist (only if the allowlist is currently empty
    #      — we never overwrite a configured posture).
    #   2. Redirect them to /admin/network so they can review +
    #      tighten the auto-seeded value.
    target_after_login = _safe_return_to(return_to)
    try:
        from . import cidr_store as _cidr_store
        from . import network_acl as _network_acl

        is_bootstrap_admin = user_id.startswith("email:bootstrap-") and "@iam-jit.local" in user_id
        if not is_bootstrap_admin:
            user_store = getattr(request.app.state, "user_store", None)
            if user_store is not None:
                try:
                    rec = user_store.get(user_id)
                    if rec.notes and "seeded by IAM_JIT_ADMIN_BOOTSTRAP_EMAIL" in rec.notes:
                        is_bootstrap_admin = True
                except Exception:
                    pass
        if is_bootstrap_admin:
            # Pull the caller's IP using the same XFF-trust logic the
            # ACL middleware uses, so the auto-seed lines up with
            # what enforcement will check.
            xff = request.headers.get("x-forwarded-for") or ""
            client_host = request.client.host if request.client else None
            source_ip = None
            if (
                os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
                in {"1", "true", "yes"}
            ) and xff:
                source_ip = xff.split(",")[0].strip()
            if not source_ip:
                source_ip = client_host
            if source_ip:
                _cidr_store.auto_seed_for_bootstrap(
                    source_ip=source_ip, user_id=user_id
                )
            if not _network_acl.is_acl_configured() or not _cidr_store.get_default_store().list():
                target_after_login = "/admin/network"
            else:
                # Even with the allowlist now populated by auto-seed,
                # still nudge them to the page so they can confirm
                # the captured IP and add more ranges.
                target_after_login = "/admin/network"
    except Exception:
        # Never let the nudge logic crash the sign-in path.
        pass

    response = RedirectResponse(url=target_after_login, status_code=303)
    response.set_cookie(
        key="iam_jit_session",
        value=cookie_value,
        httponly=True,
        secure=not auth_mod.is_dev_insecure_active(),
        samesite="strict",
        path="/",
        max_age=24 * 60 * 60,
    )
    return response


@router.get("/logout")
def logout(request: Request) -> Response:
    # BB3-01 closure: server-side revocation. Same posture as the
    # JSON /api/v1/auth/logout route — the cookie hash goes into
    # the revocation list so a saved-elsewhere copy can't outlive
    # the user's logout.
    cookie = request.cookies.get("iam_jit_session")
    if cookie:
        try:
            from .. import session_revocation as _sr

            _sr.get_default_store().revoke(cookie, ttl_seconds=24 * 60 * 60)
        except Exception:
            import logging
            logging.getLogger("iam_jit.session_revocation").exception(
                "failed to revoke session on /logout"
            )
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("iam_jit_session", path="/")
    return response


# ---- Home ----


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    # Read the toggle from the query string. Default is "show cancelled
    # at the bottom for 24h, then hide" (the F7 visibility rule). The
    # toggle hides cancelled entirely.
    hide_cancelled = request.query_params.get("hide_cancelled") in {"1", "true", "on", "yes"}
    store: RequestStore = request.app.state.request_store
    items: list[dict[str, Any]] = []
    for rid in store.list_ids():
        try:
            req = store.get(rid)
        except Exception:
            continue
        if lifecycle.get_owner(req) != user.id:
            continue
        if hide_cancelled and lifecycle.get_state(req) == "cancelled":
            continue
        # Hide cancelled requests after 24h. Direct URL still works;
        # this is just dashboard noise reduction.
        if not lifecycle.is_visible_on_dashboard(req):
            continue
        items.append(lifecycle.summarize(req))
    items = lifecycle.sort_for_dashboard(items)
    return _render(
        request,
        "home.html",
        active="home",
        user=user,
        extra={"requests": items, "hide_cancelled": hide_cancelled},
    )


# ---- Queue (approver inbox) ----


@router.get("/queue", response_class=HTMLResponse)
def queue_page(
    request: Request,
    _: Annotated[Any, Depends(require_approver)],
) -> Response:
    user = _try_current_user(request)
    store: RequestStore = request.app.state.request_store
    pending: list[dict[str, Any]] = []
    total = 0
    for rid in store.list_ids():
        try:
            req = store.get(rid)
        except Exception:
            continue
        total += 1
        if lifecycle.get_state(req) == "pending":
            pending.append(lifecycle.summarize(req))
    return _render(
        request,
        "queue.html",
        active="queue",
        user=user,
        extra={"requests": pending, "all_count": total},
    )


@router.get("/all", response_class=HTMLResponse)
def all_requests_page(request: Request) -> Response:
    """All requests across every state. Approvers/admins see every
    request; requesters see only their own."""
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    store: RequestStore = request.app.state.request_store
    items: list[dict[str, Any]] = []
    for rid in store.list_ids():
        try:
            req = store.get(rid)
        except Exception:
            continue
        if not lifecycle.can_view(req, user):
            continue
        items.append(lifecycle.summarize(req))
    items = lifecycle.sort_for_dashboard(items)
    return _render(
        request,
        "all_requests.html",
        active="queue" if user.is_approver else "home",
        user=user,
        extra={"requests": items},
    )


# ---- New request ----


@router.get("/requests/new", response_class=HTMLResponse)
def new_chooser(request: Request) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    # CRIT-17-02 closure: the AI-enabled branch used to redirect to
    # /requests/new/chat, which was deleted in Stage 4 of
    # [[no-nl-synthesis]]. The chooser now always renders the same
    # template — agents use the MCP tools, humans paste raw JSON via
    # /requests/new/paste.
    return _render(request, "new_request.html", active="new", user=user)



def _check_banned(user: Any) -> Response | None:
    """Return a 403 Response if the user is banned; None otherwise.

    Centralized so every chat / intake entry point applies the same
    check. Banned users see a stable error page that doesn't reveal
    which detection rule fired (that goes to the audit log)."""
    if user is None:
        return None
    try:
        if bans_mod.get_default_store().is_banned(user.id):
            return Response(
                status_code=403,
                content=(
                    "Your account is suspended due to a detected policy "
                    "violation. Contact your iam-jit administrator if you "
                    "believe this was in error."
                ),
            )
    except Exception:
        # Never let a bans-store failure brick the app — fail-open is
        # the correct behavior for an additive safety check.
        import logging

        logging.getLogger("iam_jit.bans").exception("ban check failed")
    return None


def _enforce_no_injection(
    user: Any, *messages: str
) -> Response | None:
    """Inspect each user-supplied string for prompt-injection patterns.

    On a HIGH-confidence detection: ban the user (unless admin), audit,
    return a 403 Response.

    On a MEDIUM-confidence detection: don't ban — just refuse the
    message and audit, return a 400 Response.

    Returns None if everything is clean.
    """
    if user is None:
        return None
    for msg in messages:
        if not msg:
            continue
        verdict = prompt_injection.detect(msg)
        if not verdict.detected:
            continue

        try:
            audit.emit(
                actor=user.id,
                kind="security.prompt_injection",
                summary=f"prompt-injection detected ({verdict.confidence})",
                details={
                    "reasons": verdict.reasons,
                    "snippets": verdict.snippets,
                    "confidence": verdict.confidence,
                },
            )
        except Exception:
            pass

        if verdict.confidence == "high":
            try:
                bans_mod.ban_for_injection(
                    store=bans_mod.get_default_store(),
                    user_id=user.id,
                    reasons=verdict.reasons,
                    snippets=verdict.snippets,
                    confidence=verdict.confidence,
                    is_admin=bool(getattr(user, "is_admin", False)),
                )
            except Exception:
                import logging

                logging.getLogger("iam_jit.bans").exception(
                    "auto-ban on prompt-injection failed"
                )
            return Response(
                status_code=403,
                content=(
                    "Your message was rejected and your account suspended "
                    "for a detected attempt to manipulate the system "
                    "instructions. This decision is final at the system "
                    "level — contact your iam-jit administrator."
                ),
            )
        return Response(
            status_code=400,
            content=(
                "That message contains text that looks like a prompt-"
                "injection attempt and was refused. Rephrase using plain "
                "language about the AWS access you need."
            ),
        )
    return None


# #605 — write-action classification helper for the access_type vs
# policy preview-check at form-submit time. Reuses the scorer's
# `_action_level` (IAM-level lookup backed by policy_sentry) so this
# module does NOT reinvent the read-vs-write classification per
# [[scorer-is-ground-truth]]. The single source of truth for which
# actions count as "Write" lives in `review._service_action_levels`;
# this helper is a thin "list the offenders" wrapper around it.
_WRITE_LEVELS = frozenset({"Write", "Tagging", "Permissions management"})


def _classify_write_actions(parsed_policy: Any) -> list[str]:
    """Return the deduped list of write-class actions found in an Allow
    statement of `parsed_policy`.

    "Write-class" means the scorer (via policy_sentry) classifies the
    action's IAM access level as one of `_WRITE_LEVELS`. Wildcards
    (`*`, `s3:*`, `iam:?reateRole`, etc.) are treated as write
    conservatively because a wildcard can match any mutating action in
    the service — the same conservative treatment the read-only
    scoring path in `review.py` already applies (score 8 hard
    mismatch for wildcards under read-only).

    The list is order-preserved by first appearance so the UX names
    the same actions the user wrote (rather than a sorted/shuffled
    list that hides which Statement holds the offender). Returns an
    empty list when `parsed_policy` is not a dict or has no
    Statements.
    """
    if not isinstance(parsed_policy, dict):
        return []
    statements = parsed_policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    offenders: list[str] = []
    seen: set[str] = set()
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if not review._effect_is_allow(stmt):
            continue
        for action in review._as_list(stmt.get("Action")):
            if not isinstance(action, str) or not action:
                continue
            if action in seen:
                continue
            # Wildcards: treat as write (defense-in-depth — `s3:*`
            # includes `s3:DeleteObject` and friends). Matches the
            # conservative read-only scoring posture in review.py.
            if review._has_wildcard(action):
                offenders.append(action)
                seen.add(action)
                continue
            level = review._action_level(action)
            if level in _WRITE_LEVELS:
                offenders.append(action)
                seen.add(action)
    return offenders


@router.get("/requests/new/paste", response_class=HTMLResponse)
def new_paste_form(request: Request) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    return _render(
        request, "new_paste.html", active="new", user=user, extra={"form": {}, "errors": []}
    )


@router.post("/requests/new/paste", response_class=HTMLResponse)
def new_paste_submit(
    request: Request,
    description: Annotated[str, Form()],
    policy: Annotated[str, Form()],
    accounts: Annotated[str, Form()],
    duration_hours: Annotated[int, Form()],
    access_type: Annotated[str, Form()] = "read-only",
    assume_principal_arn: Annotated[str, Form()] = "",
    assume_session_name: Annotated[str, Form()] = "",
    ticket: Annotated[str, Form()] = "",
) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    # #613 — per-user outstanding-request cap. Refuse BEFORE parsing
    # policy or validating the form so a runaway agent loop cannot
    # waste cycles AND cannot fill the approver queue. Shared helper
    # with routes/requests.py per [[cross-product-agent-parity]].
    # Per [[ibounce-honest-positioning]]: render the form back to the
    # user with a 429 + structured error explaining the cap, the
    # current outstanding count, and how to unblock (cancel existing
    # / wait / admin raise cap). NOT a redirect — keeps the form
    # contents intact so the user doesn't lose their typed policy.
    request_store: RequestStore = request.app.state.request_store
    _cap_result = _check_outstanding_cap(user, request_store)
    if _cap_result.would_exceed:
        _cap_body = _cap_result.to_response_body()
        return _render(
            request,
            "new_paste.html",
            active="new",
            user=user,
            status_code=429,
            extra={
                "form": {
                    "description": description,
                    "policy": policy,
                    "access_type": access_type,
                    "accounts": accounts,
                    "duration_hours": duration_hours,
                    "assume_principal_arn": assume_principal_arn,
                    "assume_session_name": assume_session_name,
                    "ticket": ticket,
                },
                "errors": [
                    f"outstanding_request_cap_exceeded: you have "
                    f"{_cap_result.outstanding_count} outstanding "
                    f"requests (cap = {_cap_result.cap}, source = "
                    f"{_cap_result.cap_source}). Wait for some to "
                    f"complete or cancel existing requests at /. "
                    f"Admin can raise your cap via users.yaml "
                    f"(outstanding_request_cap: N) or via the "
                    f"IAM_JIT_MAX_OUTSTANDING_PER_USER env var."
                ],
                "outstanding_request_cap_exceeded": _cap_body,
            },
        )
    accounts_list = [{"account_id": a.strip()} for a in accounts.split(",") if a.strip()]
    parsed_policy: Any
    try:
        parsed_policy = json.loads(policy)
    except json.JSONDecodeError:
        try:
            from ruamel.yaml import YAML

            parsed_policy = YAML(typ="safe").load(policy)
        except Exception as e:
            return _render(
                request,
                "new_paste.html",
                active="new",
                user=user,
                extra={
                    "form": {
                        "description": description,
                        "policy": policy,
                        "access_type": access_type,
                        "accounts": accounts,
                        "duration_hours": duration_hours,
                    },
                    "errors": [f"could not parse policy as JSON or YAML: {e}"],
                },
            )
    req = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": _generate_id(),
            "requester": {"name": user.display_name or user.id, "email": user.id.removeprefix("email:")},
        },
        "spec": {
            "description": description,
            "access_type": access_type,
            "accounts": accounts_list,
            "duration": {"duration_hours": duration_hours},
            "policy": parsed_policy,
            "provisioning": {"mode": "identity_center"},
        },
    }
    # #594 — principal_arn is required at submit time. Match what the
    # form's placeholder already promises: blank field with a valid
    # session defaults to current_user.id. This closes the silent
    # degradation per [[ibounce-honest-positioning]] where the request
    # would be created with no principal and the detail page would
    # later show a "blocking issue: no principal_arn" warning.
    assume_by: dict[str, Any] = {}
    principal = assume_principal_arn.strip()
    if not principal:
        # user is guaranteed non-None here by the auth gate above; the
        # no-session path is rejected upstream via redirect-to-login.
        principal = _infer_assumer_principal_from_user(user)
    if not principal:
        # Defense in depth: an unauthenticated POST that somehow bypassed
        # the redirect-to-login gate, or a session-user whose id is
        # missing, must be rejected with a clear field-level error
        # rather than silently accepted.
        return _render(
            request,
            "new_paste.html",
            active="new",
            user=user,
            status_code=400,
            extra={
                "form": {
                    "description": description,
                    "policy": policy,
                    "access_type": access_type,
                    "accounts": accounts,
                    "duration_hours": duration_hours,
                    "assume_principal_arn": assume_principal_arn,
                    "assume_session_name": assume_session_name,
                    "ticket": ticket,
                },
                "errors": [
                    "assume_principal_arn: required when not submitting "
                    "through a logged-in session"
                ],
            },
        )
    assume_by["principal_arn"] = principal
    if assume_session_name.strip():
        assume_by["session_name"] = assume_session_name.strip()
    req["spec"]["assume_by"] = assume_by
    if ticket.strip():
        req["spec"]["ticket"] = ticket.strip()
    errors = schema.validate_request(req)
    if errors:
        return _render(
            request,
            "new_paste.html",
            active="new",
            user=user,
            extra={
                "form": {
                    "description": description,
                    "policy": policy,
                    "access_type": access_type,
                    "accounts": accounts,
                    "duration_hours": duration_hours,
                    "assume_principal_arn": assume_principal_arn,
                    "assume_session_name": assume_session_name,
                    "ticket": ticket,
                },
                "errors": errors,
            },
        )

    # #605 — preview-check access_type vs policy. Founder Q 2026-05-25:
    # "what if someone marks a role as read-only, but actually puts
    # write privileges in the policy?" Pre-fix: the form accepted the
    # mismatch and only the scorer's later analysis flagged it (and the
    # request could still slip through depending on the auto-approve
    # config and threshold). The user had lied (intentionally or by
    # mistake) about the request shape and the system silently moved on.
    #
    # Post-fix: when access_type is "read-only" but the policy contains
    # write-class actions, refuse the submission at the form with a
    # 403 + a structured error naming the specific offending actions
    # (first 5 + "+N more" truncation). The user must either change
    # the access_type to "read-write" (honest about writes) or remove
    # the write actions from the policy (honest about read-only).
    #
    # Per [[scorer-is-ground-truth]] the write-vs-read classification
    # is delegated to `_classify_write_actions`, which reuses the
    # scorer's `_action_level` helper — this module does NOT reinvent
    # the IAM access-level table. Per [[ibounce-honest-positioning]]
    # the rejection NAMES the specific write actions rather than
    # saying "policy is wrong" generically, so the user can act on it.
    # Schema validation above guarantees access_type is one of
    # {"read-only", "read-write"}; the check therefore only fires on
    # the "read-only + writes" combination, never on the "read-write"
    # honest case.
    _at_normalized = (access_type or "").strip().lower()
    if _at_normalized in {"read-only", "read_only", "readonly"}:
        _write_actions = _classify_write_actions(parsed_policy)
        if _write_actions:
            _shown = _write_actions[:5]
            _more = len(_write_actions) - len(_shown)
            _names = ", ".join(_shown)
            if _more > 0:
                _names = f"{_names} (+{_more} more)"
            return _render(
                request,
                "new_paste.html",
                active="new",
                user=user,
                status_code=403,
                extra={
                    "form": {
                        "description": description,
                        "policy": policy,
                        "access_type": access_type,
                        "accounts": accounts,
                        "duration_hours": duration_hours,
                        "assume_principal_arn": assume_principal_arn,
                        "assume_session_name": assume_session_name,
                        "ticket": ticket,
                    },
                    "errors": [
                        (
                            f"access_type is 'read-only' but the policy "
                            f"contains write actions: {_names}. Either "
                            f"change access_type to 'read-write' (and "
                            f"re-justify in description), or remove the "
                            f"write actions from the policy. Per "
                            f"[[scorer-is-ground-truth]] the write "
                            f"classification comes from the same "
                            f"policy_sentry table the deterministic "
                            f"scorer uses, so this rejection matches "
                            f"how the scorer would later flag the "
                            f"mismatch — caught up front so it can't "
                            f"slip silently through auto-approve."
                        ),
                    ],
                },
            )

    lifecycle.init_status(req, owner=user)
    # Always compute the deterministic risk-review block — the scorer
    # has no LLM dependency and the score drives the auto-approve gate
    # below. Pre-#598 this branch only ran when `review.is_review_enabled()`
    # (the LLM-narrative toggle), which kept the auto-approve path
    # silently dark on every web submit because review_block was None
    # and the evaluator no-op'd. Match the API path's
    # `_build_review_block`: score always, narrate optionally.
    if isinstance(parsed_policy, dict):
        analysis = review.analyze_policy(parsed_policy, req)
        req.setdefault("status", {})["review"] = analysis.to_dict()
    store: RequestStore = request_store  # already resolved at #613 cap-check
    # #598 — web paste-form submit MUST evaluate the auto-approve gate
    # identically to the API submit path. Without this, the request
    # lands silently in pending even when the deterministic scorer
    # would have auto-approved. Shared helper guarantees parity with
    # routes/requests.py submit_request per
    # [[cross-product-agent-parity]]. Same silent-degradation shape
    # as #596 (web→Slack notification gap, just fixed). Helper logs +
    # swallows evaluation failures so a gate bug cannot block
    # submission per [[ibounce-honest-positioning]].
    from .. import auto_approve_evaluator
    accounts_store = getattr(request.app.state, "accounts_store", None)
    cookie_value = request.cookies.get("iam_jit_session_mfa")
    _eval_result = auto_approve_evaluator.evaluate_and_apply_for_new_request(
        request=req,
        user=user,
        accounts_store=accounts_store,
        cookie_value=cookie_value,
    )
    # #604 — inline MFA gate at form-submit. Founder Q 2026-05-25:
    # "if I haven't 2FA'd, what happens?" Pre-fix, when the auto-
    # approve evaluator's MFA gate fired (per #599 fail-CLOSED logic),
    # the request was stored in pending and the user was redirected to
    # the detail page with no inline signal that MFA was the blocker.
    # The user couldn't tell why their high-risk request wasn't
    # approved without chasing the audit log.
    #
    # Post-fix: detect mfa_block_response from the shared evaluator
    # (the API path already surfaces this in its response body — same
    # signal, different rendering for HTML callers). Render the form
    # back with HTTP 403, the user's typed input preserved, and a
    # structured error listing the risk score, the MFA threshold, the
    # OIDC re-auth link, and the admin-fallback hint. Do NOT persist
    # the request (no queue clutter for a submission the user must
    # re-trigger after stepping up MFA).
    #
    # Per [[mfa-compliance-strategy]] this is the Layer C step-up
    # surface: an OIDC re-auth refreshes the iam_jit_session_mfa
    # cookie, after which a resubmit of the same form will pass the
    # gate. Per [[ibounce-honest-positioning]] the user sees one
    # honest rejection at submit time rather than a silent
    # "stuck-in-pending" surprise. Per [[scorer-is-ground-truth]] this
    # module does NOT recompute the score or threshold — it consumes
    # the evaluator's verdict and renders it.
    _mfa_block_response = (_eval_result or {}).get("mfa_block_response")
    if _mfa_block_response is not None:
        _auto_decision = (_eval_result or {}).get("auto_decision")
        _score = (
            (req.get("status") or {}).get("review") or {}
        ).get("risk_score")
        _floor = None
        if _auto_decision is not None:
            _details = getattr(_auto_decision, "details", {}) or {}
            _floor = _details.get("mfa_step_up_at_score")
        _redirect_to = _mfa_block_response.get(
            "redirect_to", "/api/v1/auth/oidc/login",
        )
        _err_lines = [
            (
                f"mfa_required_for_high_risk: this request scored "
                f"score: {_score} which meets or exceeds the MFA "
                f"step-up threshold "
                f"(score: {_floor if _floor is not None else 'unknown'}). "
                f"Per your deployment's MFA policy, high-risk requests "
                f"require fresh multi-factor authentication before "
                f"they can be auto-approved."
            ),
            (
                f"Action: re-authenticate via OIDC at {_redirect_to} "
                f"and resubmit this form. Your IdP's MFA challenge "
                f"refreshes the iam_jit_session_mfa cookie; iam-jit "
                f"does not run its own TOTP/WebAuthn enrollment in "
                f"this deployment."
            ),
            (
                "Admin alternative: if your deployment does not have "
                "an OIDC provider configured for MFA, an admin can "
                "approve this request via the human-review path "
                "(submit a lower-risk variant, or ask an admin to "
                "enroll OIDC MFA so step-up works for everyone)."
            ),
        ]
        return _render(
            request,
            "new_paste.html",
            active="new",
            user=user,
            status_code=403,
            extra={
                "form": {
                    "description": description,
                    "policy": policy,
                    "access_type": access_type,
                    "accounts": accounts,
                    "duration_hours": duration_hours,
                    "assume_principal_arn": assume_principal_arn,
                    "assume_session_name": assume_session_name,
                    "ticket": ticket,
                },
                "errors": _err_lines,
                "mfa_step_up": {
                    "required": True,
                    "redirect_to": _redirect_to,
                    "risk_score": _score,
                    "threshold": _floor,
                },
            },
        )
    store.put(req["metadata"]["id"], req)
    # #596 — web paste-form submit MUST notify approvers identically to
    # the API submit path. Without this, the request lands silently in
    # the queue and no Slack approver is paged. Shared helper guarantees
    # parity with routes/requests.py submit_request per
    # [[cross-product-agent-parity]]; the silent gap closed here is
    # the same shape as #560 / #594 / MRR-2 Pattern B per
    # [[ibounce-honest-positioning]]. Helper logs + swallows channel
    # failures so a Slack outage cannot block submission. Note the
    # state check is AFTER the auto-approve evaluator runs — if the
    # gate fired, the request is no longer in pending and we correctly
    # skip the approver notification.
    if req.get("status", {}).get("state") == "pending":
        from .. import approval_notifier
        approval_notifier.notify_approvers_for_new_request(req)
    return RedirectResponse(url=f"/requests/{req['metadata']['id']}", status_code=303)


# ---- Detail + actions ----


def _managed_policy_refs_for_request(req: dict[str, Any]) -> list[dict[str, str]]:
    """Look up the AWS-managed reference policy for each service in the
    request's policy. Lets reviewers compare against a known baseline."""
    from .. import debug_bundles

    services: set[str] = set()
    for s in (req.get("spec") or {}).get("policy", {}).get("Statement") or []:
        actions = s.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if isinstance(a, str) and ":" in a:
                services.add(a.split(":", 1)[0])
    refs: list[dict[str, str]] = []
    for svc in sorted(services):
        bundle = debug_bundles.BUNDLES.get(svc)
        if not bundle or "aws_managed_reference" not in bundle:
            continue
        refs.append(
            {
                "service": svc,
                "managed_arn": bundle["aws_managed_reference"],
                "notes": bundle.get("aws_managed_notes", ""),
            }
        )
    return refs


@router.get("/requests/{request_id}", response_class=HTMLResponse)
def detail_page(request_id: str, request: Request) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    store: RequestStore = request.app.state.request_store
    try:
        req = store.get(request_id)
    except NotFoundError:
        raise HTTPException(status_code=404)
    if not lifecycle.can_view(req, user):
        raise HTTPException(status_code=403)
    policy_pretty = json.dumps((req.get("spec") or {}).get("policy") or {}, indent=2)
    assumer_resolved = assume_mod.resolve_assumer_principal(req) is not None
    managed_refs = _managed_policy_refs_for_request(req)
    # Pre-approval CLI preview: show the AWS CLI commands that WOULD be
    # executed if the request were approved right now. Only relevant for
    # not-yet-active states; suppress for terminal states or once the
    # role has actually been provisioned.
    cli_preview = None
    state = lifecycle.get_state(req)
    if state in {"pending", "needs_changes", "provisioning_failed"}:
        try:
            from .. import provision as provision_mod

            accounts_store = request.app.state.accounts_store
            cli_preview = provision_mod.preview(req, accounts_store=accounts_store)
        except Exception:
            cli_preview = None
    # #610 — surface the block-with-override flash when the web approve
    # path refused due to blocking issues (the redirect lands here with
    # `?approve_blocked=...&issues=...`). Template renders a structured
    # error + the override checkbox on the approve form.
    approve_blocked = request.query_params.get("approve_blocked") or None
    approve_blocked_issues_raw = request.query_params.get("issues") or ""
    approve_blocked_issues = (
        [s.strip() for s in approve_blocked_issues_raw.split(";") if s.strip()]
        if approve_blocked_issues_raw else []
    )
    return _render(
        request,
        "request_detail.html",
        active=("queue" if user.is_approver and lifecycle.get_owner(req) != user.id else "home"),
        user=user,
        extra={
            "req": req,
            "policy_pretty": policy_pretty,
            "assumer_resolved": assumer_resolved,
            "managed_refs": managed_refs,
            "cli_preview": cli_preview,
            "approve_blocked": approve_blocked,
            "approve_blocked_issues": approve_blocked_issues,
        },
    )


def _action(action: str, role: str):
    def endpoint(
        request_id: str,
        request: Request,
        comment: Annotated[str | None, Form()] = None,
        reason: Annotated[str | None, Form()] = None,
        suggestions: Annotated[str | None, Form()] = None,
        override_blocking_issues: Annotated[str | None, Form()] = None,
    ) -> Response:
        user = _try_current_user(request)
        if user is None:
            return RedirectResponse(url="/login", status_code=303)
        banned = _check_banned(user)
        if banned is not None:
            return banned
        if role == "approver" and not user.is_approver:
            raise HTTPException(status_code=403)
        store: RequestStore = request.app.state.request_store
        try:
            req = store.get(request_id)
        except NotFoundError:
            raise HTTPException(status_code=404)
        body_reason = reason or comment
        extra: dict[str, Any] = {}
        if action == "request_changes" and suggestions:
            extra["suggestions"] = [s.strip() for s in suggestions.split(",") if s.strip()]

        # #610 — pre-approve block-with-override gate. When the admin
        # clicks Approve on a request whose `provision.preview()` reports
        # blocking issues (e.g. `assume_principal_arn` is not an ARN,
        # account not registered, empty policy), and they have NOT
        # checked the "Override blocking issues" box, refuse the approval
        # at the front door. Per [[ibounce-honest-positioning]] the
        # state machine is honest about what just happened: the request
        # stays `pending`, the admin sees a flash error explaining what
        # would have failed at provisioning, and they choose between
        # fixing the issue OR opting in to "approve anyway and watch
        # it land in provisioning_failed."
        if action == "approve":
            try:
                from .. import provision as provision_mod_local
                accounts_store_for_preview = request.app.state.accounts_store
                _preview = provision_mod_local.preview(
                    req, accounts_store=accounts_store_for_preview,
                )
                blocking_issues = list(_preview.blocking_issues)
            except Exception:
                # Preview failure must not block approval — surface as
                # zero blocking issues so the existing approve path
                # runs and any real provisioning failure shows up via
                # _attempt_provisioning_helper below (which transitions
                # to provisioning_failed honestly).
                blocking_issues = []
            _override = (override_blocking_issues or "").strip().lower() in {
                "1", "true", "on", "yes",
            }
            if blocking_issues and not _override:
                # 303 back to detail page with a flash query param so
                # the template can render the structured error. Per
                # [[cross-product-agent-parity]] the API path's
                # equivalent behavior (block-with-override) is
                # documented in the same #610 commit; both surfaces
                # refuse to silently advance state.
                from urllib.parse import quote
                _issues_param = quote(
                    " ; ".join(blocking_issues)[:512], safe="",
                )
                return RedirectResponse(
                    url=(
                        f"/requests/{request_id}"
                        f"?approve_blocked=would_fail_at_provisioning"
                        f"&issues={_issues_param}"
                    ),
                    status_code=303,
                )

        try:
            lifecycle.apply_transition(req, action=action, actor=user, reason=body_reason, extra=extra)
        except lifecycle.IllegalTransition:
            raise HTTPException(status_code=409)
        except lifecycle.NotAuthorized:
            raise HTTPException(status_code=403)
        if comment:
            lifecycle.add_comment(req, author=user, message=comment)

        # #610 — after the pending→provisioning transition for `approve`,
        # synchronously invoke provisioning. Pre-fix, the web admin path
        # called `lifecycle.apply_transition("approve")` (which only
        # advances state) and never called `_attempt_provisioning_helper`,
        # so admin-approving any other user's request landed in zombie
        # `provisioning` forever (Gap UAT-WEB-ADMIN-01, 2026-05-25).
        # The API path in `routes/requests.py::_transition_endpoint`
        # already did this; the web path was the divergent twin. Per
        # [[cross-product-agent-parity]] both surfaces now produce
        # identical observable behavior (state transitions to either
        # `active` on success or `provisioning_failed` on any exception).
        if action == "approve":
            from .. import (
                assume as assume_mod_local,
                provision as provision_mod_local,
            )
            from .._auto_approve_helpers import (
                attempt_provisioning as _attempt_provisioning_helper,
                safe_mark_failed as _safe_mark_failed_helper,
            )
            accounts_store_local = request.app.state.accounts_store
            try:
                _attempt_provisioning_helper(
                    req,
                    accounts_store=accounts_store_local,
                    provision_mod=provision_mod_local,
                    assume_mod=assume_mod_local,
                    lifecycle=lifecycle,
                )
            except Exception as e:  # pragma: no cover — defense in depth
                # _attempt_provisioning_helper is documented as
                # NEVER-raises but if it does anyway we still must
                # force the request out of `provisioning` so the UI
                # surfaces Cancel + Retry buttons.
                _safe_mark_failed_helper(
                    req,
                    f"provisioning crashed: {e}",
                    lifecycle=lifecycle,
                )

        store.put(request_id, req)
        return RedirectResponse(url=f"/requests/{request_id}", status_code=303)

    endpoint.__name__ = f"web_action_{action}"
    return endpoint


router.post("/requests/{request_id}/approve")(_action("approve", role="approver"))
router.post("/requests/{request_id}/reject")(_action("reject", role="approver"))
router.post("/requests/{request_id}/request-changes")(_action("request_changes", role="approver"))
router.post("/requests/{request_id}/cancel")(_action("cancel", role="owner"))


# #610 — web-form `/retry-provisioning` endpoint. The template's
# Retry-provisioning button (request_detail.html:263) posts to this
# path; pre-fix only the JSON API at `/api/v1/requests/{id}/retry-
# provisioning` existed, so clicking the button from the web UI
# 404'd (or hit an unrelated route in browser routing). Parity with
# the approve / cancel / reject web actions.
@router.post("/requests/{request_id}/retry-provisioning")
def web_retry_provisioning(
    request_id: str,
    request: Request,
) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    banned = _check_banned(user)
    if banned is not None:
        return banned
    if not user.is_approver:
        raise HTTPException(status_code=403)
    store: RequestStore = request.app.state.request_store
    try:
        req = store.get(request_id)
    except NotFoundError:
        raise HTTPException(status_code=404)
    try:
        lifecycle.apply_transition(
            req, action="retry", actor=user, reason="re-running provisioning",
        )
    except lifecycle.IllegalTransition:
        raise HTTPException(status_code=409)
    except lifecycle.NotAuthorized:
        raise HTTPException(status_code=403)

    from .. import (
        assume as assume_mod_local,
        provision as provision_mod_local,
    )
    from .._auto_approve_helpers import (
        attempt_provisioning as _attempt_provisioning_helper,
        safe_mark_failed as _safe_mark_failed_helper,
    )
    accounts_store_local = request.app.state.accounts_store
    try:
        _attempt_provisioning_helper(
            req,
            accounts_store=accounts_store_local,
            provision_mod=provision_mod_local,
            assume_mod=assume_mod_local,
            lifecycle=lifecycle,
        )
    except Exception as e:  # pragma: no cover — defense in depth
        _safe_mark_failed_helper(
            req,
            f"provisioning crashed: {e}",
            lifecycle=lifecycle,
        )
    store.put(request_id, req)
    return RedirectResponse(url=f"/requests/{request_id}", status_code=303)


@router.post("/requests/{request_id}/comments")
def post_comment_form(
    request_id: str,
    request: Request,
    message: Annotated[str, Form()],
) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    banned = _check_banned(user)
    if banned is not None:
        return banned
    if len(message) > 4096:
        raise HTTPException(
            status_code=400, detail="comment too long (max 4096 chars)"
        )
    refused = _enforce_no_injection(user, message)
    if refused is not None:
        return refused
    store: RequestStore = request.app.state.request_store
    try:
        req = store.get(request_id)
    except NotFoundError:
        raise HTTPException(status_code=404)
    if not lifecycle.can_view(req, user):
        raise HTTPException(status_code=403)
    lifecycle.add_comment(req, author=user, message=message.strip())
    store.put(request_id, req)
    return RedirectResponse(url=f"/requests/{request_id}", status_code=303)


# ---- Tokens ----


@router.get("/tokens", response_class=HTMLResponse)
def tokens_page(request: Request) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    store: APITokenStore | None = getattr(request.app.state, "api_tokens_store", None)
    tokens: list[Any] = store.list_for_user(user.id) if store else []
    from .. import public_url as _public_url
    public_url = _public_url.base_for(request)
    return _render(
        request,
        "tokens.html",
        active="tokens",
        user=user,
        extra={"tokens": tokens, "just_minted": None, "public_url": public_url},
    )


@router.post("/tokens", response_class=HTMLResponse)
def tokens_create(
    request: Request,
    label: Annotated[str | None, Form()] = None,
) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    store: APITokenStore | None = getattr(request.app.state, "api_tokens_store", None)
    if store is None:
        raise HTTPException(status_code=500, detail="api_tokens_store not configured")
    issued = issue_api_token(user.id, label=label or None)
    store.put(
        APITokenRecord(
            token_hash=issued.hash,
            user_id=issued.user_id,
            created_at=issued.created_at,
            label=issued.label,
        )
    )
    tokens = store.list_for_user(user.id)
    from .. import public_url as _public_url
    public_url = _public_url.base_for(request)
    return _render(
        request,
        "tokens.html",
        active="tokens",
        user=user,
        extra={
            "tokens": tokens,
            "just_minted": {"token": issued.raw, "hash": issued.hash},
            "public_url": public_url,
        },
    )


@router.post("/tokens/{token_hash}/revoke")
def tokens_revoke(token_hash: str, request: Request) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    store: APITokenStore | None = getattr(request.app.state, "api_tokens_store", None)
    if store is None:
        raise HTTPException(status_code=500, detail="api_tokens_store not configured")
    try:
        record = store.get_by_hash(token_hash)
    except Exception:
        return RedirectResponse(url="/tokens", status_code=303)
    if record.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403)
    store.delete(token_hash)
    return RedirectResponse(url="/tokens", status_code=303)


# ---- Provisioned / rediscover admin views ----


def _dismiss_disabled_reason(user_store: Any) -> str | None:
    """Return a human-readable explanation if the dismiss-warning button
    should be DISABLED at render time, or None if dismissal works.

    #612 UAT-Web-Admin-07 closure: a `FileUserStore`-backed deployment
    can't persist per-admin dismissals (the YAML is the source of
    truth + read-only at runtime by design — see
    `users_store.FileUserStore.put`). Without this gate, the user
    clicks "dismiss for me", the handler tries to `put` the updated
    user record, hits `StoreReadOnly`, and silently redirects to
    `?error=store_write_failed` — the warning stays visible AND the
    redirect-shape looks like a successful action. Same shape as #326
    / #448 / #463 (silent-degradation; reported success that hides a
    failure underneath). Honest fix per
    `[[ibounce-honest-positioning]]`: either persist OR error upfront.
    Returns None when the store DOES accept writes (DynamoDB, in-
    memory test stores).
    """
    from ..users_store import FileUserStore as _FileUserStore

    if isinstance(user_store, _FileUserStore):
        return (
            "Dismissal requires a writable user store. This deployment "
            "uses FileUserStore (YAML), which is read-only at runtime "
            "by design — dismissals can't be persisted across requests. "
            "To enable per-admin dismissal, switch to the DynamoDB user "
            "store (IAM_JIT_USERS_TABLE) or accept that warnings remain "
            "visible until the underlying posture is fixed."
        )
    return None


@router.get("/admin/network", response_class=HTMLResponse)
def admin_network_page(request: Request) -> Response:
    """Show the current source-IP posture and recommend hardening."""
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    from .. import cidr_store as _cidr_store, network_acl
    from .. import security_posture as _sp

    runtime_entries = _cidr_store.get_default_store().list()
    posture = _sp.compute()
    # Filter dismissed warnings out for this admin's view; agents on
    # /healthz still see the unfiltered list.
    posture["issues_undismissed"] = [
        i for i in posture["issues"]
        if not _sp.warning_dismissed_by(user.notes, i["id"])
    ]
    user_store = request.app.state.user_store
    return _render(
        request,
        "admin_network.html",
        active="admin",
        user=user,
        extra={
            "runtime_cidrs": [
                {
                    "cidr": e.cidr,
                    "note": e.note,
                    "added_by": e.added_by,
                    "added_at": e.added_at,
                }
                for e in runtime_entries
            ],
            "env_cidrs": network_acl.get_configured_cidrs(),
            "trust_xff": (
                os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
                in {"1", "true", "yes"}
            ),
            "public_exposure_opt_in": (
                os.environ.get("IAM_JIT_PUBLIC_EXPOSURE_OPT_IN", "false").lower()
                in {"1", "true", "yes"}
            ),
            "posture": posture,
            "dismiss_disabled_reason": _dismiss_disabled_reason(user_store),
        },
    )


@router.post("/admin/network/dismiss-warning", response_class=HTMLResponse)
def admin_network_dismiss_warning(
    request: Request,
    warning_id: Annotated[str, Form()],
) -> Response:
    """Form-POST shim that calls the JSON dismiss-warning admin
    endpoint, then redirects back to /admin/network. Keeps the
    dismiss-button flow zero-JS.

    #612 UAT-Web-Admin-07 closure: when the underlying user store is
    read-only (FileUserStore), don't return a misleading 303-redirect
    with `?error=store_write_failed` — that has the visual shape of a
    successful action but the warning stays visible. Same shape as the
    #326 / #448 / #463 silent-degradation cluster. Instead:
      - Detect the read-only case UPFRONT via `_dismiss_disabled_reason`
        and render the page in-place with an HTTP 409 + explicit
        error banner, NOT a redirect; this matches the disabled-button
        state the GET handler shows so the user understands why their
        click couldn't take effect.
      - Other unexpected `put` failures still redirect with
        `?error=store_write_failed` so operator-visible errors aren't
        lost — but the read-only case (the only one we can detect
        upfront) gets the honest treatment.
    """
    import dataclasses
    import datetime as _dt
    from .. import cidr_store as _cidr_store, network_acl, security_posture as _sp
    from ..users_store import StoreReadOnly as _StoreReadOnly

    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    user_store = request.app.state.user_store
    posture = _sp.compute()
    valid_ids = {i["id"] for i in posture["issues"]}
    if warning_id not in valid_ids:
        return RedirectResponse(
            url="/admin/network?error=unknown_warning_id",
            status_code=303,
        )

    # #612 UAT-Web-Admin-07: upfront read-only refusal. If the store
    # can't accept writes, render the page with an explicit error
    # banner — do NOT redirect with a misleading-success shape.
    upfront_reason = _dismiss_disabled_reason(user_store)
    if upfront_reason is not None:
        posture["issues_undismissed"] = [
            i for i in posture["issues"]
            if not _sp.warning_dismissed_by(user.notes, i["id"])
        ]
        return _render(
            request,
            "admin_network.html",
            active="admin",
            user=user,
            status_code=409,
            extra={
                "runtime_cidrs": [
                    {
                        "cidr": e.cidr,
                        "note": e.note,
                        "added_by": e.added_by,
                        "added_at": e.added_at,
                    }
                    for e in _cidr_store.get_default_store().list()
                ],
                "env_cidrs": network_acl.get_configured_cidrs(),
                "trust_xff": (
                    os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
                    in {"1", "true", "yes"}
                ),
                "public_exposure_opt_in": (
                    os.environ.get("IAM_JIT_PUBLIC_EXPOSURE_OPT_IN", "false").lower()
                    in {"1", "true", "yes"}
                ),
                "posture": posture,
                "dismiss_disabled_reason": upfront_reason,
                "dismiss_attempt_blocked": True,
                "dismiss_attempted_warning_id": warning_id,
            },
        )

    try:
        fresh = user_store.get(user.id)
    except Exception:
        return RedirectResponse(
            url="/admin/network?error=user_not_found",
            status_code=303,
        )
    when = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    updated_notes = _sp.append_dismissal(fresh.notes, warning_id, when)
    try:
        user_store.put(dataclasses.replace(fresh, notes=updated_notes))
    except _StoreReadOnly:
        # Belt-and-suspenders: if a store reports writable at
        # `_dismiss_disabled_reason` time but still raises
        # `StoreReadOnly` (e.g. permission flip mid-request), fall
        # back to the same honest in-place error rather than a
        # misleading-success redirect.
        posture["issues_undismissed"] = [
            i for i in posture["issues"]
            if not _sp.warning_dismissed_by(user.notes, i["id"])
        ]
        return _render(
            request,
            "admin_network.html",
            active="admin",
            user=user,
            status_code=409,
            extra={
                "runtime_cidrs": [
                    {
                        "cidr": e.cidr,
                        "note": e.note,
                        "added_by": e.added_by,
                        "added_at": e.added_at,
                    }
                    for e in _cidr_store.get_default_store().list()
                ],
                "env_cidrs": network_acl.get_configured_cidrs(),
                "trust_xff": (
                    os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
                    in {"1", "true", "yes"}
                ),
                "public_exposure_opt_in": (
                    os.environ.get("IAM_JIT_PUBLIC_EXPOSURE_OPT_IN", "false").lower()
                    in {"1", "true", "yes"}
                ),
                "posture": posture,
                "dismiss_disabled_reason": (
                    "User store is read-only; dismissal could not be "
                    "persisted."
                ),
                "dismiss_attempt_blocked": True,
                "dismiss_attempted_warning_id": warning_id,
            },
        )
    except Exception:
        return RedirectResponse(
            url="/admin/network?error=store_write_failed",
            status_code=303,
        )
    try:
        audit.emit(
            actor=user.id,
            kind="admin.dismiss_warning",
            summary=f"{user.id} dismissed {warning_id}",
            details={"warning_id": warning_id, "at": when},
        )
    except Exception:
        pass
    return RedirectResponse(url="/admin/network", status_code=303)


@router.post("/admin/network/cidrs", response_class=HTMLResponse)
def admin_network_add_cidr(
    request: Request,
    cidr: Annotated[str, Form()],
    note: Annotated[str, Form()] = "",
    confirm_lockout: Annotated[str, Form()] = "",
) -> Response:
    """Form-POST handler for adding a CIDR from the /admin/network UI.

    Per #609 CRIT (UAT-WEB-ADMIN-02 2026-05-25): pre-validate that the
    caller's own source IP would still be covered by the resulting
    allowlist. If not, refuse the change unless the operator explicitly
    ticks `confirm_lockout` — friction-as-feature per
    [[ambient-value-prop-and-friction-framing]] + [[ibounce-honest-positioning]].
    Without this gate, an admin could silently lock themselves out of the
    very page they'd need to remove the bad CIDR; only recovery was a
    server restart."""
    import ipaddress
    import time

    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    from .. import cidr_store as _cidr_store, network_acl as _network_acl

    normalized = _cidr_store.normalize_cidr(cidr)
    if not normalized:
        return RedirectResponse(
            url="/admin/network?error=invalid_cidr", status_code=303
        )

    # Self-preservation gate — does the proposed allowlist cover the
    # operator's current source IP? Skip if they explicitly opted in to
    # the lockout risk via the confirm checkbox.
    confirmed = confirm_lockout.strip().lower() in {"1", "on", "true", "yes"}
    if not confirmed:
        client_host = request.client.host if request.client else None
        caller_ip = _network_acl._read_source_ip(
            client_host, request.headers.get("x-forwarded-for")
        )
        proposed_cidrs = [e.cidr for e in _cidr_store.get_default_store().list()]
        proposed_cidrs.append(normalized)
        caller_covered = _caller_covered_by(caller_ip, proposed_cidrs)
        if not caller_covered:
            # Render the page with a form-level error AND a hidden form
            # that lets the operator re-submit with the confirm gate set
            # — no allowlist mutation happens on this code path.
            return _render_admin_network_lockout_warning(
                request,
                user=user,
                proposed_cidr=normalized,
                note=note.strip()[:200],
                caller_ip=caller_ip,
                proposed_allowlist=proposed_cidrs,
            )

    entry = _cidr_store.CIDREntry(
        cidr=normalized,
        note=note.strip()[:200],
        added_by=user.id,
        added_at=int(time.time()),
    )
    try:
        _cidr_store.get_default_store().add(entry)
    except Exception:
        return RedirectResponse(
            url="/admin/network?error=store_write_failed",
            status_code=303,
        )
    try:
        audit.emit(
            actor=user.id,
            kind="security.cidr_added",
            summary=f"added {normalized} via UI",
            details={
                "cidr": normalized,
                "note": entry.note,
                "confirm_lockout": confirmed,
            },
        )
    except Exception:
        pass
    return RedirectResponse(url="/admin/network", status_code=303)


def _caller_covered_by(caller_ip: str | None, cidrs: list[str]) -> bool:
    """True if `caller_ip` is inside any of `cidrs`. Returns False on any
    parse failure (fail-safe — better to nag the operator than to assume
    coverage we can't verify)."""
    import ipaddress

    if not caller_ip:
        return False
    try:
        addr = ipaddress.ip_address(caller_ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        # Skip IPv4-vs-IPv6 mismatch (avoids TypeError).
        if isinstance(addr, ipaddress.IPv4Address) != isinstance(
            net.network_address, ipaddress.IPv4Address
        ):
            continue
        if addr in net:
            return True
    return False


def _render_admin_network_lockout_warning(
    request: Request,
    *,
    user: Any,
    proposed_cidr: str,
    note: str,
    caller_ip: str | None,
    proposed_allowlist: list[str],
) -> Response:
    """Re-render /admin/network with a form-level "this would lock you
    out" error + a confirm-anyway resubmit form. NO mutation happens
    here; the operator must explicitly tick `confirm_lockout` to proceed."""
    from .. import cidr_store as _cidr_store, network_acl
    from .. import security_posture as _sp

    runtime_entries = _cidr_store.get_default_store().list()
    posture = _sp.compute()
    posture["issues_undismissed"] = [
        i for i in posture["issues"]
        if not _sp.warning_dismissed_by(user.notes, i["id"])
    ]
    return _render(
        request,
        "admin_network.html",
        status_code=400,
        active="admin",
        user=user,
        extra={
            "runtime_cidrs": [
                {
                    "cidr": e.cidr,
                    "note": e.note,
                    "added_by": e.added_by,
                    "added_at": e.added_at,
                }
                for e in runtime_entries
            ],
            "env_cidrs": network_acl.get_configured_cidrs(),
            "trust_xff": (
                os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
                in {"1", "true", "yes"}
            ),
            "public_exposure_opt_in": (
                os.environ.get("IAM_JIT_PUBLIC_EXPOSURE_OPT_IN", "false").lower()
                in {"1", "true", "yes"}
            ),
            "posture": posture,
            "lockout_warning": {
                "code": "would_lock_you_out",
                "proposed_cidr": proposed_cidr,
                "note": note,
                "caller_ip": caller_ip or "(unknown)",
                "proposed_allowlist": proposed_allowlist,
                "message": (
                    f"Applying this allowlist would lock YOU out — your "
                    f"source IP {caller_ip or '(unknown)'} is not covered "
                    f"by any proposed CIDR. Either (a) add "
                    f"{caller_ip or '<your-ip>'}/32 first, or (b) tick "
                    f"the 'I confirm this change may lock me out' "
                    f"checkbox to proceed anyway."
                ),
            },
        },
    )


@router.post("/admin/network/cidrs/{cidr:path}/delete", response_class=HTMLResponse)
def admin_network_delete_cidr(
    request: Request,
    cidr: str,
) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    from .. import cidr_store as _cidr_store

    store = _cidr_store.get_default_store()
    entries = store.list()
    norm = _cidr_store.normalize_cidr(cidr) or ""
    if len(entries) <= 1 and any(e.cidr == norm for e in entries):
        return RedirectResponse(
            url="/admin/network?error=cannot_remove_last_cidr",
            status_code=303,
        )
    removed = store.remove(cidr)
    if removed:
        try:
            audit.emit(
                actor=user.id,
                kind="security.cidr_removed",
                summary=f"removed {cidr} via UI",
                details={"cidr": cidr},
            )
        except Exception:
            pass
    return RedirectResponse(url="/admin/network", status_code=303)


@router.get("/admin/provisioned", response_class=HTMLResponse)
def admin_provisioned_page(request: Request) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    include_revoked = request.query_params.get("include_revoked") in {
        "1", "true", "on", "yes",
    }
    store: RequestStore = request.app.state.request_store
    rows: list[dict[str, Any]] = []
    for rid in store.list_ids():
        try:
            req = store.get(rid)
        except Exception:
            continue
        provisioned = (req.get("status") or {}).get("provisioned") or {}
        if not provisioned.get("role_arn"):
            continue
        state = (req.get("status") or {}).get("state") or ""
        if state == "revoked" and not include_revoked:
            continue
        metadata = req.get("metadata") or {}
        rows.append(
            {
                "request_id": rid,
                "name": metadata.get("name") or "",
                "owner": (req.get("status") or {}).get("owner") or "",
                "role_arn": provisioned.get("role_arn"),
                "role_name": provisioned.get("role_name"),
                "account_id": provisioned.get("account_id"),
                "expires_at": provisioned.get("expires_at"),
                "state": state,
            }
        )
    rows.sort(key=lambda r: r.get("expires_at") or "")
    return _render(
        request,
        "admin_provisioned.html",
        active="admin",
        user=user,
        extra={"rows": rows, "include_revoked": include_revoked},
    )


@router.get("/admin/rediscover", response_class=HTMLResponse)
def admin_rediscover_page(request: Request) -> Response:
    """Render the rediscovery report. Triggering the scan happens on
    POST so a stray refresh doesn't re-hit every destination account."""
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    return _render(
        request,
        "admin_rediscover.html",
        active="admin",
        user=user,
        extra={"report": None, "deployment_filter": ""},
    )


@router.post("/admin/rediscover", response_class=HTMLResponse)
def admin_rediscover_run(
    request: Request,
    deployment_filter: Annotated[str | None, Form()] = None,
) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    from .. import rediscover as rediscover_mod

    accounts_store = request.app.state.accounts_store
    request_store = request.app.state.request_store
    report = rediscover_mod.reconcile(
        accounts_store=accounts_store,
        request_store=request_store,
        deployment_filter=(deployment_filter or None) or None,
    )
    return _render(
        request,
        "admin_rediscover.html",
        active="admin",
        user=user,
        extra={"report": report, "deployment_filter": deployment_filter or ""},
    )


# ---- Accounts wizard (admin-only) ----


def _require_admin_or_redirect(request: Request) -> Any:
    user = _try_current_user(request)
    if user is None:
        return None, RedirectResponse(url="/login", status_code=303)
    if not user.is_admin:
        raise HTTPException(status_code=403)
    return user, None


@router.get("/accounts", response_class=HTMLResponse)
def accounts_list_page(request: Request) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    store: AccountStore = request.app.state.accounts_store
    accounts = store.list(include_disabled=True)
    return _render(
        request,
        "accounts.html",
        active="accounts",
        user=user,
        extra={"accounts": accounts},
    )


@router.get("/accounts/new", response_class=HTMLResponse)
def accounts_new_page(request: Request) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    return _render(
        request,
        "account_new.html",
        active="accounts",
        user=user,
        extra={"form": {}, "errors": [], "plan": None},
    )


@router.post("/accounts/new", response_class=HTMLResponse)
def accounts_new_submit(
    request: Request,
    account_id: Annotated[str, Form()],
    region: Annotated[str, Form()] = "us-east-1",
    account_alias: Annotated[str, Form()] = "",
    alias: Annotated[str, Form()] = "",
    hub_account_id: Annotated[str, Form()] = "",
    provisioning_mode: Annotated[str, Form()] = "classic_iam",
    enable_discovery: Annotated[str, Form()] = "",
) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    # #612 UAT-Web-Admin-05 closure: the web form uses `account_alias`
    # but the JSON-API + POST /accounts/register both name the same
    # field `alias`. Scripts / agents that POST with `alias=...` would
    # silently lose the value at this step — the onboarding plan would
    # render with a blank `<input type="hidden" name="alias" value="" />`
    # and the subsequent Register click would persist an aliasless
    # account. Accept both names with `account_alias` winning if both
    # are present (the form-field is the authoritative name for the
    # web surface).
    effective_alias = (account_alias or "").strip() or (alias or "").strip()
    form = {
        "account_id": account_id,
        "region": region,
        "account_alias": effective_alias,
        "hub_account_id": hub_account_id,
        "provisioning_mode": provisioning_mode,
        "enable_discovery": bool(enable_discovery),
    }
    try:
        plan = onboarding_mod.render_plan(
            account_id=account_id,
            region=region,
            account_alias=effective_alias or None,
            hub_account_id=hub_account_id or None,
            enable_discovery=bool(enable_discovery),
            provisioning_mode=provisioning_mode,
        )
    except ValueError as e:
        return _render(
            request,
            "account_new.html",
            active="accounts",
            user=user,
            extra={"form": form, "errors": [str(e)], "plan": None},
        )
    return _render(
        request,
        "account_new.html",
        active="accounts",
        user=user,
        extra={"form": form, "errors": [], "plan": plan.to_dict()},
    )


@router.post("/accounts/register", response_class=HTMLResponse)
def accounts_register(
    request: Request,
    account_id: Annotated[str, Form()],
    provisioner_role_arn: Annotated[str, Form()],
    provisioner_external_id: Annotated[str, Form()],
    provisioning_mode: Annotated[str, Form()],
    region: Annotated[str, Form()] = "",
    alias: Annotated[str, Form()] = "",
    discovery_role_arn: Annotated[str, Form()] = "",
    discovery_external_id: Annotated[str, Form()] = "",
) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    store: AccountStore = request.app.state.accounts_store
    try:
        existing = store.get(account_id)
    except AccountNotFound:
        existing = None
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"account {account_id} already registered")
    account = Account(
        account_id=account_id,
        provisioner_role_arn=provisioner_role_arn,
        provisioner_external_id=provisioner_external_id,
        provisioning_mode=provisioning_mode,
        alias=alias or None,
        regions=(region,) if region else (),
        discovery_role_arn=discovery_role_arn or None,
        discovery_external_id=discovery_external_id or None,
        registered_at=utcnow_iso(),
        registered_by=user.id,
    )
    try:
        store.put(account)
    except AccountStoreReadOnly as e:
        raise HTTPException(status_code=409, detail=str(e))
    audit.emit(
        actor=user.id,
        kind="account.registered",
        summary=f"registered account {account.account_id}",
        details={
            "account_id": account.account_id,
            "alias": account.alias,
            "provisioning_mode": account.provisioning_mode,
            "via": "web",
        },
    )
    return RedirectResponse(url=f"/accounts/{account_id}", status_code=303)


@router.get("/accounts/{account_id}", response_class=HTMLResponse)
def account_detail_page(account_id: str, request: Request) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    store: AccountStore = request.app.state.accounts_store
    try:
        account = store.get(account_id)
    except AccountNotFound:
        raise HTTPException(status_code=404)
    return _render(
        request,
        "account_detail.html",
        active="accounts",
        user=user,
        extra={"account": account},
    )


@router.post("/accounts/{account_id}/deregister", response_class=HTMLResponse)
def account_deregister(account_id: str, request: Request) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    store: AccountStore = request.app.state.accounts_store
    try:
        store.delete(account_id)
    except AccountNotFound:
        raise HTTPException(status_code=404)
    except AccountStoreReadOnly as e:
        raise HTTPException(status_code=409, detail=str(e))
    audit.emit(
        actor=user.id,
        kind="account.deregistered",
        summary=f"deregistered account {account_id}",
        details={"account_id": account_id, "via": "web"},
    )
    return RedirectResponse(url="/accounts", status_code=303)
