"""Web UI + form routes for the GitHub JIT-token use case.

This is the iam-jit web surface for GitHub scoped/TTL tokens (the AWS
RoleRequest UI has its own routes in web.py + requests.py). It is a thin layer
over `github_requests.GitHubRequestService`: a connected-orgs view, a submit
form that scores + either auto-issues or queues for human approval, an approver
inbox for high-risk requests, and an active-grants list with early revoke.

The minted token is shown EXACTLY ONCE (on the issue/approve response page); it
is never placed in a redirect URL, a flash, or any list view.
"""

from __future__ import annotations

from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from ..github_installations import default_registry_path, load_installations
from ..github_requests import (
    STATUS_ISSUED,
    STATUS_NEEDS_APPROVAL,
    GitHubRequestError,
    GitHubRequestNotFound,
    GitHubRequestService,
)
from ..middleware import current_user, require_approver
from .web import _ctx, _try_current_user
from .web import templates as _templates

router = APIRouter(include_in_schema=False)


def _service(request: Request) -> GitHubRequestService:
    """Return the request service. Tests inject `app.state.github_service`
    (hermetic httpx + fixed clock); production lazily builds one default
    service (cached on app.state so the httpx.Client is reused, not leaked per
    request) talking to the real GitHub API with the configured registry."""
    svc = getattr(request.app.state, "github_service", None)
    if svc is not None:
        return svc
    svc = GitHubRequestService(
        installations_path=default_registry_path(),
        http=httpx.Client(timeout=15.0),
    )
    request.app.state.github_service = svc
    return svc


def _render(request: Request, name: str, *, status_code: int = 200, **extra: Any) -> Response:
    user = _try_current_user(request)
    return _templates.TemplateResponse(
        request,
        name,
        _ctx(active="github", user=user, extra=extra),
        status_code=status_code,
    )


def _parse_repositories(raw: str) -> list[str]:
    """Split a free-text repo list on commas/whitespace."""
    parts = [p.strip() for chunk in (raw or "").split(",") for p in chunk.split()]
    return [p for p in parts if p]


def _parse_permissions(raw: str) -> dict[str, str]:
    """Parse "contents:read, pull_requests:write" → {contents: read, ...}."""
    out: dict[str, str] = {}
    for chunk in (raw or "").replace("\n", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if ":" not in chunk:
            raise GitHubRequestError(f"permission {chunk!r} must be 'name:level'")
        name, _, level = chunk.partition(":")
        name, level = name.strip(), level.strip().lower()
        if not name or level not in ("read", "write", "admin"):
            raise GitHubRequestError(f"permission {chunk!r} must be name:(read|write|admin)")
        out[name] = level
    return out


@router.get("/github", response_class=HTMLResponse)
def github_dashboard(request: Request) -> Response:
    """Connected orgs + queue + active grants. The submit form lives here too."""
    if _try_current_user(request) is None:
        return RedirectResponse(url="/login", status_code=303)
    try:
        installs = load_installations(default_registry_path())
    except Exception:
        installs = []
    svc = _service(request)
    try:
        svc.expire_stale()
        all_reqs = svc.store.list()
    except Exception:
        all_reqs = []
    pending = [r.to_public() for r in all_reqs if r.status == STATUS_NEEDS_APPROVAL]
    active = [r.to_public() for r in all_reqs if r.status == STATUS_ISSUED]
    history = [r.to_public() for r in all_reqs if r.status not in (STATUS_NEEDS_APPROVAL, STATUS_ISSUED)]
    return _render(
        request,
        "github.html",
        installations=[
            {"org": i.org, "alias": i.alias, "enabled": i.enabled} for i in installs
        ],
        pending=pending,
        active=active,
        history=history,
    )


@router.post("/github/requests", response_class=HTMLResponse)
def github_submit(
    request: Request,
    user: Annotated[Any, Depends(current_user)],
    org: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    repositories: Annotated[str, Form()] = "",
    permissions: Annotated[str, Form()] = "",
) -> Response:
    svc = _service(request)
    try:
        repos = _parse_repositories(repositories)
        perms = _parse_permissions(permissions)
        req = svc.submit(
            org=org,
            description=description,
            requester=getattr(user, "id", "anonymous"),
            repositories=repos,
            permissions=perms,
        )
    except (GitHubRequestError, Exception) as exc:  # noqa: BLE001 — surface to UI
        return _render(request, "github.html", error=str(exc), installations=[],
                       pending=[], active=[], history=[], status_code=400)
    # Token shown ONCE here when auto-issued; queued requests show a notice.
    return _render(
        request,
        "github_issued.html",
        req=req.to_public(),
        token=req.token if req.status == STATUS_ISSUED else None,
    )


@router.post("/github/requests/{request_id}/approve", response_class=HTMLResponse)
def github_approve(
    request: Request,
    request_id: str,
    user: Annotated[Any, Depends(require_approver)],
) -> Response:
    svc = _service(request)
    try:
        req = svc.approve(request_id, approver=getattr(user, "id", "admin"))
    except GitHubRequestNotFound:
        return _render(request, "github.html", error="unknown request",
                       installations=[], pending=[], active=[], history=[], status_code=404)
    except GitHubRequestError as exc:
        return _render(request, "github.html", error=str(exc),
                       installations=[], pending=[], active=[], history=[], status_code=400)
    return _render(request, "github_issued.html", req=req.to_public(), token=req.token)


@router.post("/github/requests/{request_id}/deny", response_class=HTMLResponse)
def github_deny(
    request: Request,
    request_id: str,
    user: Annotated[Any, Depends(require_approver)],
) -> Response:
    svc = _service(request)
    try:
        svc.deny(request_id, approver=getattr(user, "id", "admin"))
    except GitHubRequestError:
        pass
    return RedirectResponse(url="/github", status_code=303)


@router.post("/github/requests/{request_id}/revoke", response_class=HTMLResponse)
def github_revoke(
    request: Request,
    request_id: str,
    user: Annotated[Any, Depends(current_user)],
) -> Response:
    svc = _service(request)
    try:
        svc.revoke(request_id, actor=getattr(user, "id", "user"))
    except GitHubRequestError:
        pass
    return RedirectResponse(url="/github", status_code=303)
