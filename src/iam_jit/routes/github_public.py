"""Anonymous (no-login) GitHub access requests + capability-URL retrieval.

The hosted demo has no SES / no domain, so requesters do NOT log in. They
submit a GitHub access request, get back an unguessable **claim URL**, and poll
it; once an operator approves, the scoped token is shown there exactly once.

Security model (no auth on these routes by design):
  - the IP-allowlist middleware still gates who can reach them;
  - the operator's approval is the real gate — an anonymous submit grants
    NOTHING until a human approves it;
  - retrieval is guarded by an unguessable per-request claim token
    (`{request_id}.{secret}`) compared in constant time.

Operator-side review/approve/revoke stays in the authenticated /queue + detail
UI (web.py); this module is ONLY the requester's anonymous front door.
"""

from __future__ import annotations

import hmac
import secrets as _secrets
import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .. import github_scope, lifecycle, schema
from ..store import NotFoundError, RequestStore
from ..users_store import User
from .web import _ctx, _parse_github_repositories
from .web import _parse_advanced_permissions as _parse_adv
from .web import templates as _templates  # reuse the same Jinja env

router = APIRouter(include_in_schema=False)


def _form_meta() -> dict[str, Any]:
    return {"common_permissions": [
        {"key": c, "desc": github_scope.PERMISSION_DESCRIPTIONS.get(c, "")}
        for c in github_scope.COMMON_GITHUB_PERMISSIONS
    ]}


def _render(request: Request, name: str, *, status_code: int = 200, **extra: Any) -> Response:
    # Anonymous: no current_user (base.html simply hides the nav).
    return _templates.TemplateResponse(
        request, name, _ctx(active="github", user=None, extra=extra), status_code=status_code
    )


def _build_permissions(raw_form) -> dict[str, str]:
    perms: dict[str, str] = {}
    for cat in github_scope.COMMON_GITHUB_PERMISSIONS:
        lvl = (raw_form.get(f"perm_{cat}") or "none").strip().lower()
        if lvl in ("read", "write"):
            perms[cat] = lvl
    perms.update(_parse_adv(raw_form.get("advanced_permissions") or ""))
    return perms


def _submit_common(
    *, store: RequestStore, org: str, repositories: str, permissions: dict[str, str],
    duration_minutes: int, description: str, requester_name: str, requester_email: str,
    requester_key: str = "",
) -> tuple[dict | None, list[str]]:
    """Build + validate + persist an anonymous GitHubTokenRequest. Stays pending
    unless the optional auto-approve policy clears it (read-only, or a prior
    saved approval matched by requester_key). Returns (req, errors)."""
    if not permissions:
        return None, ["pick at least one permission (or add one in the advanced field)."]
    try:
        permissions = github_scope.normalize_permissions(permissions)
    except ValueError as e:
        return None, [str(e)]

    req = schema.scaffold_github_request(
        org=(org or "").strip(),
        repositories=_parse_github_repositories(repositories),
        permissions=permissions,
        duration_minutes=int(duration_minutes or 60),
        description=description or "",
        requester_name=(requester_name or "anonymous").strip() or "anonymous",
        requester_email=(requester_email or "anonymous@requester.local").strip(),
    )
    if (requester_key or "").strip():
        req["spec"]["github"]["requester_key"] = requester_key.strip()
    req["metadata"]["id"] = "ghr-" + uuid.uuid4().hex[:12]
    errors = schema.validate_request(req)
    if errors:
        return None, errors

    owner_id = "email:" + req["metadata"]["requester"]["email"]
    lifecycle.init_status(req, owner=User(id=owner_id, roles=("requester",)))
    # Capability secret for anonymous retrieval. Stored server-only; never in
    # summarize()/lists. The claim URL is {request_id}.{secret}.
    claim_secret = _secrets.token_urlsafe(24)
    req.setdefault("status", {})["_claim_secret"] = claim_secret
    # Optional auto-approve (off by default): a read-only request may auto-issue
    # if an admin enabled it; otherwise it stays pending for human review.
    from .. import github_autoapprove
    issued, _reason = github_autoapprove.maybe_auto_issue(req)
    store.put(req["metadata"]["id"], req)
    if not issued:
        try:
            from .. import approval_notifier
            approval_notifier.notify_approvers_for_new_request(req)
        except Exception:
            import logging
            logging.getLogger("iam_jit.github").warning(
                "approver notification failed for %s (request still queued)",
                req["metadata"].get("id"), exc_info=True)
    return req, []


def _claim_token(req: dict) -> str:
    return f"{req['metadata']['id']}.{req['status']['_claim_secret']}"


def _load_by_claim(store: RequestStore, claim: str) -> dict | None:
    """Resolve a claim token ({request_id}.{secret}) to its request, verifying
    the secret in constant time. Returns None on any mismatch."""
    rid, _, secret = (claim or "").partition(".")
    if not rid or not secret:
        return None
    try:
        req = store.get(rid)
    except NotFoundError:
        return None  # noqa: SD-4 — None IS the not-found signal; caller renders 404
    stored = (req.get("status") or {}).get("_claim_secret") or ""
    if not stored or not hmac.compare_digest(stored, secret):
        return None
    return req


def _public_view(req: dict) -> dict[str, Any]:
    """Requester-facing projection: state + (token once active). Never leaks the
    claim secret or any other request's data."""
    status = req.get("status") or {}
    gh = (status.get("provisioned") or {}).get("github") or {}
    spec_gh = (req.get("spec") or {}).get("github") or {}
    out: dict[str, Any] = {
        "request_id": req["metadata"]["id"],
        "state": lifecycle.get_state(req),
        "org": spec_gh.get("org"),
        "repositories": spec_gh.get("repositories") or [],
        "permissions": spec_gh.get("permissions") or {},
    }
    if out["state"] == "active":
        out["expires_at"] = gh.get("expires_at")
        out["token"] = status.get("_secret_github_token")  # shown while active
    # A durable requester key issued by a "remember" approval — present it on
    # future requests to auto-issue without waiting for a human.
    rk = status.get("_issued_requester_key")
    if rk:
        out["requester_key"] = rk
    return out


# --- web (anonymous browser) ---

@router.get("/github/request", response_class=HTMLResponse)
def github_public_form(request: Request) -> Response:
    return _render(request, "github_public.html", form={}, errors=[], **_form_meta())


@router.post("/github/request", response_class=HTMLResponse)
async def github_public_submit(request: Request) -> Response:
    raw = await request.form()
    store: RequestStore = request.app.state.request_store
    permissions = _build_permissions(raw)
    req, errors = _submit_common(
        store=store, org=raw.get("org") or "", repositories=raw.get("repositories") or "",
        permissions=permissions, duration_minutes=_safe_int(raw.get("duration_minutes"), 60),
        description=raw.get("description") or "",
        requester_name=raw.get("requester_name") or "", requester_email=raw.get("requester_email") or "",
        requester_key=raw.get("requester_key") or "",
    )
    if errors:
        form = {k: raw.get(k) for k in ("org", "repositories", "duration_minutes",
                                        "description", "requester_name", "requester_email")}
        form["advanced_permissions"] = raw.get("advanced_permissions")
        form["selected"] = permissions
        return _render(request, "github_public.html", status_code=400,
                       form=form, errors=errors, **_form_meta())
    return RedirectResponse(url=f"/github/claim/{_claim_token(req)}", status_code=303)


@router.get("/github/claim/{claim:path}", response_class=HTMLResponse)
def github_public_claim(claim: str, request: Request) -> Response:
    store: RequestStore = request.app.state.request_store
    req = _load_by_claim(store, claim)
    if req is None:
        return _render(request, "github_claim.html", status_code=404,
                       view=None, claim=claim)
    return _render(request, "github_claim.html", view=_public_view(req), claim=claim)


# --- JSON API (anonymous agent) ---

@router.post("/api/v1/github/requests")
async def github_public_api_submit(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON body required"}, status_code=400)
    store: RequestStore = request.app.state.request_store
    perms = body.get("permissions") if isinstance(body.get("permissions"), dict) else {}
    req, errors = _submit_common(
        store=store, org=body.get("org") or "",
        repositories=" ".join(body.get("repositories") or []) if isinstance(body.get("repositories"), list) else (body.get("repositories") or ""),
        permissions=perms, duration_minutes=_safe_int(body.get("duration_minutes"), 60),
        description=body.get("description") or "",
        requester_name=body.get("requester_name") or "agent",
        requester_email=body.get("requester_email") or "agent@requester.local",
        requester_key=body.get("requester_key") or "",
    )
    if errors:
        return JSONResponse({"error": "invalid request", "details": errors}, status_code=400)
    return JSONResponse({
        "request_id": req["metadata"]["id"],
        "claim_token": _claim_token(req),
        "state": "pending",
        "poll": f"/api/v1/github/requests/{_claim_token(req)}",
    }, status_code=201)


@router.get("/api/v1/github/requests/{claim:path}")
def github_public_api_status(claim: str, request: Request) -> Response:
    store: RequestStore = request.app.state.request_store
    req = _load_by_claim(store, claim)
    if req is None:
        return JSONResponse({"error": "unknown or invalid claim token"}, status_code=404)
    return JSONResponse(_public_view(req))


def _safe_int(v, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default
