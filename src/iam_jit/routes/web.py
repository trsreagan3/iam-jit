"""Web (HTML) routes — humans-facing surface.

These routes use the same underlying stores, lifecycle, review, and narrowing
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

from .. import __version__, assume as assume_mod, audit, auth as auth_mod, bans as bans_mod, health as health_mod, intake as intake_mod, intake_drafts as intake_drafts_mod, lifecycle, magic_link_nonces, narrow, onboarding as onboarding_mod, prompt_injection, rate_limit as rate_limit_mod, review, schema
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


def _render(request: Request, name: str, **ctx_kwargs: Any) -> Response:
    return templates.TemplateResponse(request, name, _ctx(**ctx_kwargs))


def _try_current_user(request: Request) -> Any | None:
    """Best-effort user resolution that returns None instead of raising."""
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
    try:
        user = user_store.get(user_id)
    except UserNotFound:
        return None
    if not user.enabled:
        return None
    return user


# ---- Auth ----


_SAFE_RETURN_TO = {
    "/",
    "/queue",
    "/requests/new",
    "/requests/new/chat",
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

    The /login endpoint is unauthenticated, so we can't key off
    user.id. Falling back to client IP. When iam-jit runs behind
    CloudFront / ALB, the original IP is in `X-Forwarded-For`; in dev
    `request.client.host` is the actual peer. We take the FIRST IP in
    XFF (closest to the original caller) to defeat trivial spoofing
    via `X-Forwarded-For: 1.1.1.1` from outside the trusted proxy.
    """
    xff = request.headers.get("x-forwarded-for") or ""
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return f"ip:{first}"
    if request.client and request.client.host:
        return f"ip:{request.client.host}"
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
        secure=os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") != "1",
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
def magic_callback(token: str, return_to: str = "/") -> Response:
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
        secure=os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") != "1",
        samesite="strict",
        path="/",
        max_age=24 * 60 * 60,
    )
    return response


@router.get("/logout")
def logout() -> Response:
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
    # When AI is enabled, conversational intake is the primary surface.
    # Paste mode is still linked from the chat page and from the chooser
    # for users who want a deterministic flow.
    if review.is_review_enabled():
        return RedirectResponse(url="/requests/new/chat", status_code=303)
    return _render(request, "new_request.html", active="new", user=user)


_CHAT_OPENING_GREETING = (
    "What can I help you access? Tell me what you're trying to do — which "
    "AWS account, which service (S3, EKS, etc.), and any specific resources "
    "(bucket names, ARNs) if you know them."
)


@router.get("/requests/new/chat", response_class=HTMLResponse)
def new_chat_page(request: Request) -> Response:
    user = _try_current_user(request)
    if user is None:
        # Preserve resume intent across login: ?resume=draft-id stays
        # in the URL so post-login the user lands back here.
        return_to = "/requests/new/chat"
        if request.query_params.get("resume"):
            # Strip any non-alphanumeric+`-` characters from the resume
            # value so a crafted resume= can't smuggle URL syntax.
            import re

            safe_resume = re.sub(
                r"[^A-Za-z0-9\-]", "", request.query_params["resume"]
            )[:32]
            if safe_resume:
                return_to += f"?resume={safe_resume}"
        from urllib.parse import quote

        return RedirectResponse(
            url=f"/login?return_to={quote(return_to, safe='/?=&')}",
            status_code=303,
        )
    banned = _check_banned(user)
    if banned is not None:
        return banned
    if not review.is_review_enabled():
        return RedirectResponse(url="/requests/new/paste?reason=no_ai", status_code=303)

    # Resume-existing-draft path: ?resume=<draft_id> rehydrates the
    # signed token from server-side storage, so a user who closed the
    # tab or whose session expired can pick up where they left off.
    drafts = intake_drafts_mod.get_default_store()
    resume_id = request.query_params.get("resume") or ""
    resume_draft: intake_drafts_mod.IntakeDraft | None = None
    if resume_id:
        resume_draft = drafts.get(resume_id)
        # Only honor it if the draft belongs to the current user — never
        # let one user resume another's draft.
        if resume_draft and resume_draft.user_id != user.id:
            resume_draft = None
    available_draft = None
    if resume_draft is None:
        available_draft = drafts.get_most_recent(user.id)

    if resume_draft is not None:
        history = list(resume_draft.history)
        token = _sign_intake_state(
            history, parse_error_count=resume_draft.parse_error_count
        )
        return _render(
            request,
            "new_chat.html",
            active="new",
            user=user,
            extra={
                "conversation": history,
                "turn": intake_mod.IntakeTurn(
                    ask="(resuming your previous draft — continue where you left off)"
                ),
                "conversation_token": token,
                "resumed_from_draft": True,
                "draft_id": resume_draft.draft_id,
            },
        )

    # Fresh page: hardcoded greeting (no LLM call).
    turn = intake_mod.IntakeTurn(ask=_CHAT_OPENING_GREETING)
    conversation: list[dict[str, str]] = [
        {"role": "assistant", "content": _CHAT_OPENING_GREETING}
    ]
    token = _sign_intake_conversation(conversation)
    return _render(
        request,
        "new_chat.html",
        active="new",
        user=user,
        extra={
            "conversation": [],
            "turn": turn,
            "conversation_token": token,
            # Surface a "resume previous draft?" prompt only if the user
            # actually has one. Mobile-first: don't add UI noise for the
            # 95% case of no prior draft.
            "available_draft": (
                {
                    "id": available_draft.draft_id,
                    "last_updated_at": available_draft.last_updated_at,
                    "turn_count": len(available_draft.history),
                }
                if available_draft is not None
                else None
            ),
        },
    )


_CHAT_PARSE_ERRORS_BEFORE_FALLBACK = 2


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


def _enforce_rate_limit(user: Any, *, kind: str = "chat") -> Response | None:
    """Per-user rate limit. Soft cap → 429 + Retry-After.
    Hard cap → ban via `bans_mod.ban_for_injection` (treated as DDoS,
    same audit category as prompt-injection). Returns a Response on
    refusal, None when allowed."""
    if user is None:
        return None
    try:
        decision = rate_limit_mod.get_default_limiter().check(user.id, kind=kind)
    except Exception:
        return None  # fail-open on limiter error
    if decision.allowed:
        return None

    try:
        audit.emit(
            actor=user.id,
            kind=(
                "security.rate_limit_hard"
                if decision.over_hard
                else "security.rate_limit_soft"
            ),
            summary=(
                f"chat rate-limit: {decision.count} requests in "
                f"{decision.window_seconds}s "
                f"(soft={decision.soft_cap}, hard={decision.hard_cap})"
            ),
            details={
                "kind": kind,
                "count": decision.count,
                "window_seconds": decision.window_seconds,
                "soft_cap": decision.soft_cap,
                "hard_cap": decision.hard_cap,
                "over_hard": decision.over_hard,
            },
        )
    except Exception:
        pass

    if decision.over_hard:
        try:
            bans_mod.ban_for_injection(
                store=bans_mod.get_default_store(),
                user_id=user.id,
                reasons=["chat-rate-ddos"],
                snippets=[
                    f"{decision.count} requests in "
                    f"{decision.window_seconds}s, exceeds hard cap "
                    f"{decision.hard_cap}"
                ],
                confidence="high",
                is_admin=bool(getattr(user, "is_admin", False)),
            )
        except Exception:
            import logging

            logging.getLogger("iam_jit.bans").exception(
                "auto-ban on rate-limit-hard failed"
            )
        return Response(
            status_code=403,
            content=(
                "Account suspended for sustained excessive request rate "
                "(possible DDoS). Contact your iam-jit administrator."
            ),
        )
    return Response(
        status_code=429,
        content=(
            f"Too many requests. Wait {decision.retry_after_seconds}s and "
            "try again."
        ),
        headers={"Retry-After": str(max(1, decision.retry_after_seconds))},
    )


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


@router.post("/requests/new/chat/stream")
def new_chat_stream(
    request: Request,
    conversation: Annotated[str, Form()] = "",
    message: Annotated[str, Form()] = "",
    regenerate: Annotated[str, Form()] = "",
) -> Response:
    """SSE streaming variant of the chat turn.

    Streams raw model tokens to the browser as they arrive (Ollama's
    `stream: true` line-delimited JSON). After the model is done, runs
    the safety nets (account-required check, synthesizer fallback,
    debug-bundle augmentation, etc.) and emits a final `complete` event
    with the structured turn JSON the client uses to replace the
    progressive bubble with the proper rendered state.

    Falls back to non-streaming behavior if the configured backend
    doesn't expose `chat_stream`. Anthropic and Bedrock backends could
    add streaming later; not yet wired."""
    from fastapi.responses import StreamingResponse

    from .. import intake as intake_mod
    from .. import llm

    user = _try_current_user(request)
    if user is None:
        return Response(status_code=401)
    banned = _check_banned(user)
    if banned is not None:
        return banned
    if not review.is_review_enabled():
        return Response(status_code=409, content="LLM disabled in this deployment")

    rate_refused = _enforce_rate_limit(user, kind="chat-stream")
    if rate_refused is not None:
        return rate_refused

    refused = _enforce_no_injection(user, message)
    if refused is not None:
        return refused

    state = _load_intake_state(conversation)
    history = state["history"]
    parse_error_count = state["parse_error_count"]
    if regenerate:
        if history and history[-1].get("role") == "assistant":
            history.pop()
    elif message.strip():
        history.append({"role": "user", "content": message.strip()})
        parse_error_count = 0

    backend = llm.get_backend()

    def _event_stream():
        # Build the full prompt (same as take_turn does internally) so we
        # can stream the model's raw output. We re-implement the wrapping
        # here rather than refactoring intake.take_turn for the streaming
        # case — keeps the non-streaming path simple.
        formatted: list[dict[str, str]] = []
        for msg in history:
            role = msg.get("role")
            content = msg.get("content") or ""
            if role == "user":
                formatted.append(
                    {"role": "user", "content": intake_mod._wrap_user_message(content)}
                )
            elif role == "assistant":
                formatted.append({"role": "assistant", "content": content})
        if not formatted:
            formatted = [
                {
                    "role": "user",
                    "content": intake_mod._wrap_user_message(
                        "(no message yet — please greet the user and ask the opening question)"
                    ),
                }
            ]
        sys_prompt = (
            intake_mod.INTAKE_SYSTEM_PROMPT
            + intake_mod.load_org_context()
            + intake_mod._load_memory_block(history)
        )

        accumulator: list[str] = []
        if hasattr(backend, "chat_stream"):
            try:
                for chunk in backend.chat_stream(
                    system_prompt=sys_prompt, messages=formatted
                ):
                    accumulator.append(chunk)
                    # SSE 'token' event with the chunk text. JSON-encode
                    # so newlines / special chars don't break the
                    # event-stream framing.
                    yield f"event: token\ndata: {json.dumps(chunk)}\n\n"
            except Exception:
                pass
        else:
            text = backend.chat(system_prompt=sys_prompt, messages=formatted)
            accumulator.append(text)
            yield f"event: token\ndata: {json.dumps(text)}\n\n"

        # Run the same parse + safety-net pipeline take_turn would.
        # Build a synthetic turn by replaying through take_turn's
        # post-processing on the accumulated raw text. To avoid duplicating
        # code, we monkey-call a small internal helper.
        full_text = "".join(accumulator)
        turn = intake_mod._postprocess_raw_response(full_text, history)

        if turn.error == "llm_parse_error":
            new_parse_error_count = parse_error_count + 1
        else:
            new_parse_error_count = 0
        suggest_paste = new_parse_error_count >= _CHAT_PARSE_ERRORS_BEFORE_FALLBACK

        new_history = list(history)
        if turn.ask:
            new_history.append({"role": "assistant", "content": turn.ask})

        token = _sign_intake_state(
            new_history, parse_error_count=new_parse_error_count
        )

        # Persist the draft so a refresh / disconnect / re-auth can
        # resume from this point. If the SSE consumer disconnected
        # mid-stream, we never reach here — that's fine, the previous
        # turn's draft is still on disk and we'll try again next turn.
        try:
            intake_drafts_mod.get_default_store().save(
                user_id=user.id,
                history=new_history,
                parse_error_count=new_parse_error_count,
            )
        except Exception:
            import logging

            logging.getLogger("iam_jit.intake_drafts").exception(
                "saving intake draft (stream) failed (non-fatal)"
            )

        complete_payload = {
            "ask": turn.ask,
            "complete": turn.complete,
            "fields": turn.fields,
            "draft_policy": turn.draft_policy,
            "prefill": turn.prefill,
            "error": turn.error,
            "conversation_token": token,
            "parse_error_count": new_parse_error_count,
            "suggest_paste": suggest_paste,
        }
        yield f"event: complete\ndata: {json.dumps(complete_payload)}\n\n"

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable proxy buffering
        },
    )


@router.post("/requests/new/chat", response_class=HTMLResponse)
def new_chat_turn(
    request: Request,
    conversation: Annotated[str, Form()] = "",
    message: Annotated[str, Form()] = "",
    regenerate: Annotated[str, Form()] = "",
) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    banned = _check_banned(user)
    if banned is not None:
        return banned
    if not review.is_review_enabled():
        return RedirectResponse(url="/requests/new/paste?reason=no_ai", status_code=303)

    rate_refused = _enforce_rate_limit(user, kind="chat")
    if rate_refused is not None:
        return rate_refused

    refused = _enforce_no_injection(user, message)
    if refused is not None:
        return refused

    state = _load_intake_state(conversation)
    history = state["history"]
    parse_error_count = state["parse_error_count"]

    if regenerate:
        # User clicked "try again" — drop the trailing assistant turn (if any)
        # so the model gets a clean re-run on the same user history.
        if history and history[-1].get("role") == "assistant":
            history.pop()
    elif message.strip():
        history.append({"role": "user", "content": message.strip()})
        # New user content resets the error counter — a parse failure
        # against fresh input is unrelated to the previous one.
        parse_error_count = 0

    from .. import llm

    backend = llm.get_backend()
    turn = intake_mod.take_turn(history, backend)

    if turn.error == "llm_parse_error":
        parse_error_count += 1
    else:
        parse_error_count = 0

    # Soft escape hatch: if the model has failed twice running, surface
    # a prominent "switch to paste mode" path so the user is never stuck.
    suggest_paste = parse_error_count >= _CHAT_PARSE_ERRORS_BEFORE_FALLBACK

    if turn.ask:
        history.append({"role": "assistant", "content": turn.ask})

    token = _sign_intake_state(history, parse_error_count=parse_error_count)
    history_for_render = list(history[:-1]) if turn.ask else list(history)

    # Persist a server-side draft so the user can resume after close /
    # refresh / session expiry. Best-effort — if the store fails, the
    # signed token in the form remains the source of truth for the
    # active session.
    try:
        intake_drafts_mod.get_default_store().save(
            user_id=user.id,
            history=history,
            parse_error_count=parse_error_count,
        )
    except Exception:
        import logging

        logging.getLogger("iam_jit.intake_drafts").exception(
            "saving intake draft failed (non-fatal)"
        )

    return _render(
        request,
        "new_chat.html",
        active="new",
        user=user,
        extra={
            "conversation": history_for_render,
            "turn": turn,
            "conversation_token": token,
            "parse_error_count": parse_error_count,
            "suggest_paste": suggest_paste,
        },
    )


def _sign_intake_state(
    history: list[dict[str, str]],
    *,
    parse_error_count: int = 0,
) -> str:
    payload = json.dumps(
        {"history": history, "parse_error_count": parse_error_count},
        separators=(",", ":"),
    )
    return auth_mod.sign_intake_state(_get_secret(), payload)


def _sign_intake_conversation(history: list[dict[str, str]]) -> str:
    """Backwards-compat wrapper. Prefer _sign_intake_state."""
    return _sign_intake_state(history, parse_error_count=0)


def _load_intake_state(token: str) -> dict[str, Any]:
    """Decode the signed intake token. Returns a dict with `history` and
    `parse_error_count`. Tolerates the legacy bare-list format."""
    if not token:
        return {"history": [], "parse_error_count": 0}
    try:
        raw = auth_mod.verify_intake_state(_get_secret(), token)
    except Exception:
        return {"history": [], "parse_error_count": 0}
    try:
        data = json.loads(raw)
    except Exception:
        return {"history": [], "parse_error_count": 0}

    if isinstance(data, list):
        # Legacy format: bare history list.
        history_raw = data
        parse_error_count = 0
    elif isinstance(data, dict):
        history_raw = data.get("history") or []
        parse_error_count = int(data.get("parse_error_count") or 0)
    else:
        return {"history": [], "parse_error_count": 0}

    history: list[dict[str, str]] = []
    for item in history_raw:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        content = item.get("content")
        if role in ("user", "assistant") and isinstance(content, str):
            history.append({"role": role, "content": content})
    return {"history": history, "parse_error_count": parse_error_count}


def _load_intake_conversation(token: str) -> list[dict[str, str]]:
    if not token:
        return []
    try:
        raw = auth_mod.verify_intake_state(_get_secret(), token)
    except Exception:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out: list[dict[str, str]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        content = item.get("content")
        if role in ("user", "assistant") and isinstance(content, str):
            out.append({"role": role, "content": content})
    return out


@router.get("/requests/new/generate", response_class=HTMLResponse)
def new_generate_form(request: Request) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    if not review.is_review_enabled():
        return RedirectResponse(url="/requests/new/paste?reason=no_ai", status_code=303)
    return _render(
        request, "new_describe.html", active="new", user=user, extra={"form": {}, "errors": []}
    )


@router.post("/requests/new/generate", response_class=HTMLResponse)
def new_generate_submit(
    request: Request,
    description: Annotated[str, Form()],
    accounts: Annotated[str, Form()],
    duration_hours: Annotated[int, Form()],
    user_store: Annotated[UserStore, Depends(get_user_store)],
    services: Annotated[str, Form()] = "",
    access_type: Annotated[str, Form()] = "read-only",
) -> Response:
    user = _try_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    from .. import suggest as suggest_mod

    services_list = [s.strip() for s in services.split(",") if s.strip()]
    accounts_list = [{"account_id": a.strip()} for a in accounts.split(",") if a.strip()]
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
            "task_intent": {"services": services_list, "actions": ["read", "list"]},
            "accounts": accounts_list,
            "duration": {"duration_hours": duration_hours},
            "provisioning": {"mode": "identity_center"},
        },
    }
    form_state = {
        "description": description,
        "services": services,
        "access_type": access_type,
        "accounts": accounts,
        "duration_hours": duration_hours,
    }
    try:
        req["spec"]["policy"] = suggest_mod.suggest_policy(req)
    except Exception as e:
        return _render(
            request,
            "new_describe.html",
            active="new",
            user=user,
            extra={"form": form_state, "errors": [str(e)]},
        )
    errors = schema.validate_request(req)
    if errors:
        return _render(
            request,
            "new_describe.html",
            active="new",
            user=user,
            extra={"form": form_state, "errors": errors},
        )
    lifecycle.init_status(req, owner=user)
    if review.is_review_enabled():
        analysis = review.analyze_policy(req["spec"]["policy"], req)
        req.setdefault("status", {})["review"] = analysis.to_dict()
    store: RequestStore = request.app.state.request_store
    store.put(req["metadata"]["id"], req)
    return RedirectResponse(url=f"/requests/{req['metadata']['id']}", status_code=303)


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
    assume_by: dict[str, Any] = {}
    if assume_principal_arn.strip():
        assume_by["principal_arn"] = assume_principal_arn.strip()
    if assume_session_name.strip():
        assume_by["session_name"] = assume_session_name.strip()
    if assume_by:
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
    lifecycle.init_status(req, owner=user)
    if review.is_review_enabled() and isinstance(parsed_policy, dict):
        analysis = review.analyze_policy(parsed_policy, req)
        req.setdefault("status", {})["review"] = analysis.to_dict()
    store: RequestStore = request.app.state.request_store
    store.put(req["metadata"]["id"], req)
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
        },
    )


def _action(action: str, role: str):
    def endpoint(
        request_id: str,
        request: Request,
        comment: Annotated[str | None, Form()] = None,
        reason: Annotated[str | None, Form()] = None,
        suggestions: Annotated[str | None, Form()] = None,
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
        try:
            lifecycle.apply_transition(req, action=action, actor=user, reason=body_reason, extra=extra)
        except lifecycle.IllegalTransition:
            raise HTTPException(status_code=409)
        except lifecycle.NotAuthorized:
            raise HTTPException(status_code=403)
        if comment:
            lifecycle.add_comment(req, author=user, message=comment)
        store.put(request_id, req)
        return RedirectResponse(url=f"/requests/{request_id}", status_code=303)

    endpoint.__name__ = f"web_action_{action}"
    return endpoint


router.post("/requests/{request_id}/approve")(_action("approve", role="approver"))
router.post("/requests/{request_id}/reject")(_action("reject", role="approver"))
router.post("/requests/{request_id}/request-changes")(_action("request_changes", role="approver"))
router.post("/requests/{request_id}/cancel")(_action("cancel", role="owner"))


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
        },
    )


@router.post("/admin/network/dismiss-warning", response_class=HTMLResponse)
def admin_network_dismiss_warning(
    request: Request,
    warning_id: Annotated[str, Form()],
) -> Response:
    """Form-POST shim that calls the JSON dismiss-warning admin
    endpoint, then redirects back to /admin/network. Keeps the
    dismiss-button flow zero-JS."""
    import dataclasses
    import datetime as _dt
    from .. import security_posture as _sp

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
) -> Response:
    """Form-POST handler for adding a CIDR from the /admin/network UI."""
    import time

    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    from .. import cidr_store as _cidr_store

    normalized = _cidr_store.normalize_cidr(cidr)
    if not normalized:
        return RedirectResponse(
            url="/admin/network?error=invalid_cidr", status_code=303
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
            details={"cidr": normalized, "note": entry.note},
        )
    except Exception:
        pass
    return RedirectResponse(url="/admin/network", status_code=303)


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
    hub_account_id: Annotated[str, Form()] = "",
    provisioning_mode: Annotated[str, Form()] = "classic_iam",
    enable_discovery: Annotated[str, Form()] = "",
) -> Response:
    user, redir = _require_admin_or_redirect(request)
    if redir is not None:
        return redir
    form = {
        "account_id": account_id,
        "region": region,
        "account_alias": account_alias,
        "hub_account_id": hub_account_id,
        "provisioning_mode": provisioning_mode,
        "enable_discovery": bool(enable_discovery),
    }
    try:
        plan = onboarding_mod.render_plan(
            account_id=account_id,
            region=region,
            account_alias=account_alias or None,
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
