"""GitHub token-request store + lifecycle (serve integration).

This is the serve-side complement to `github_scope.py`. The composer
(`scope_github_task`) is standalone and either auto-issues a low-risk token or
returns "needs_approval" and mints NOTHING. That leaves a gap the threat model
cares about: a high-risk request needs a HUMAN to approve it before any token
is minted. This module closes that gap with a persisted request lifecycle that
mirrors the AWS RoleRequest flow (submit → [auto-issue | queue → approve/deny]
→ revoke) without coupling to the ARN-strict RoleRequest schema — GitHub is its
own thing per the design doc.

State machine:

    submit ──low-risk──▶ issued ──▶ (revoke | expire)
       │
       └──high-risk──▶ needs_approval ──approve──▶ issued
                              │
                              └──deny──▶ denied

Storage: one JSON file per request under a 0700 dir (default
~/.iam-jit/github-requests, override IAM_JIT_GITHUB_REQUESTS_DIR). The minted
token is persisted ONLY while the grant is active (status=issued) so an admin
can revoke early; it is cleared on revoke/expiry. The whole dir is owner-only.
"""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import secrets
from collections.abc import Callable
from datetime import datetime, timezone

import httpx

from .github_scope import (
    analyze_github_scope,
    mint_github_token,
    revoke_github_token,
)

# Active grant statuses (token may still be live).
STATUS_NEEDS_APPROVAL = "needs_approval"
STATUS_ISSUED = "issued"
STATUS_DENIED = "denied"
STATUS_REVOKED = "revoked"
STATUS_EXPIRED = "expired"


class GitHubRequestError(Exception):
    """Raised on invalid lifecycle transitions or bad input."""


class GitHubRequestNotFound(GitHubRequestError):
    """Raised when a request id is unknown."""


def _now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_z(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def default_requests_dir() -> str:
    env = os.environ.get("IAM_JIT_GITHUB_REQUESTS_DIR")
    if env:
        return env
    return str(pathlib.Path.home() / ".iam-jit" / "github-requests")


@dataclasses.dataclass
class GitHubTokenRequest:
    id: str
    org: str
    description: str
    requester: str
    repositories: list[str]
    permissions: dict[str, str]
    risk_score: int
    band: str
    risk_factors: list[str]
    status: str
    created_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    expires_at: str | None = None
    # Persisted ONLY while status==issued so an admin can revoke early; cleared
    # on revoke/expiry. Never serialized into list/UI responses.
    token: str | None = None

    def to_public(self) -> dict:
        """Serialize WITHOUT the secret token (for lists / UI / audit)."""
        d = dataclasses.asdict(self)
        d.pop("token", None)
        d["token_active"] = bool(self.token) and self.status == STATUS_ISSUED
        return d


def _request_path(dir_path: str, request_id: str) -> pathlib.Path:
    return pathlib.Path(dir_path) / f"{request_id}.json"


class GitHubRequestStore:
    """File-backed store for GitHub token requests (one JSON file each)."""

    def __init__(self, dir_path: str | None = None) -> None:
        self.dir_path = dir_path or default_requests_dir()

    def _ensure_dir(self) -> None:
        pathlib.Path(self.dir_path).mkdir(parents=True, exist_ok=True, mode=0o700)

    def save(self, req: GitHubTokenRequest) -> None:
        self._ensure_dir()
        path = _request_path(self.dir_path, req.id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(dataclasses.asdict(req), indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def get(self, request_id: str) -> GitHubTokenRequest:
        path = _request_path(self.dir_path, request_id)
        if not path.exists():
            raise GitHubRequestNotFound(f"unknown GitHub request: {request_id}")
        data = json.loads(path.read_text())
        return GitHubTokenRequest(**data)

    def list(self) -> list[GitHubTokenRequest]:
        d = pathlib.Path(self.dir_path)
        if not d.exists():
            return []
        out: list[GitHubTokenRequest] = []
        for f in d.glob("*.json"):
            try:
                out.append(GitHubTokenRequest(**json.loads(f.read_text())))
            except (json.JSONDecodeError, TypeError):
                continue  # skip a corrupt/partial file rather than 500
        out.sort(key=lambda r: r.created_at, reverse=True)
        return out


def _new_id() -> str:
    return "ghr_" + secrets.token_hex(8)


class GitHubRequestService:
    """Lifecycle over a GitHubRequestStore. `http`/`now` are injectable so the
    whole flow is hermetic in tests (httpx.MockTransport + a fixed clock)."""

    def __init__(
        self,
        *,
        installations_path: str,
        store: GitHubRequestStore | None = None,
        http: httpx.Client | None = None,
        now: Callable[[], int] | None = None,
    ) -> None:
        self.installations_path = installations_path
        self.store = store or GitHubRequestStore()
        self._http = http
        self._now = now

    # --- submit -------------------------------------------------------------

    def submit(
        self,
        *,
        org: str,
        description: str,
        requester: str,
        repositories: list[str],
        permissions: dict[str, str],
    ) -> GitHubTokenRequest:
        """Score the request; auto-issue when low-risk, else queue it for human
        approval (minting NOTHING). The high-risk request never reaches GitHub
        until an admin approves it."""
        if not org or not str(org).strip():
            raise GitHubRequestError("org is required")
        if not repositories or not all(isinstance(r, str) and r for r in repositories):
            raise GitHubRequestError("repositories must be a non-empty list of names")
        if not permissions or not isinstance(permissions, dict):
            raise GitHubRequestError("permissions must be a non-empty mapping")

        review = analyze_github_scope(repositories, permissions)
        req = GitHubTokenRequest(
            id=_new_id(),
            org=org,
            description=description or "",
            requester=requester or "anonymous",
            repositories=list(repositories),
            permissions=dict(permissions),
            risk_score=review.risk_score,
            band=review.band,
            risk_factors=list(review.risk_factors),
            status=STATUS_NEEDS_APPROVAL,
            created_at=_now_iso_z(),
        )
        if review.would_auto_approve:
            self._mint_into(req, decided_by="auto-approve")
        self.store.save(req)
        return req

    # --- approve / deny -----------------------------------------------------

    def approve(self, request_id: str, *, approver: str) -> GitHubTokenRequest:
        """Human approves a queued high-risk request → mint the token now."""
        req = self.store.get(request_id)
        if req.status != STATUS_NEEDS_APPROVAL:
            raise GitHubRequestError(
                f"request {request_id} is {req.status}, not awaiting approval"
            )
        self._mint_into(req, decided_by=approver or "admin")
        self.store.save(req)
        return req

    def deny(self, request_id: str, *, approver: str) -> GitHubTokenRequest:
        req = self.store.get(request_id)
        if req.status != STATUS_NEEDS_APPROVAL:
            raise GitHubRequestError(
                f"request {request_id} is {req.status}, not awaiting approval"
            )
        req.status = STATUS_DENIED
        req.decided_at = _now_iso_z()
        req.decided_by = approver or "admin"
        self.store.save(req)
        return req

    # --- revoke -------------------------------------------------------------

    def revoke(self, request_id: str, *, actor: str) -> GitHubTokenRequest:
        """Kill an active grant early (DELETE the installation token). Clears the
        stored token. No-op-safe if already past its TTL."""
        req = self.store.get(request_id)
        if req.status != STATUS_ISSUED:
            raise GitHubRequestError(f"request {request_id} is {req.status}, not active")
        if req.token:
            revoke_github_token(
                installations_path=self.installations_path,
                org=req.org,
                token=req.token,
                http=self._http,
                now=self._now,
            )
        req.token = None
        req.status = STATUS_REVOKED
        req.decided_by = actor or req.decided_by
        self.store.save(req)
        return req

    # --- helpers ------------------------------------------------------------

    def _mint_into(self, req: GitHubTokenRequest, *, decided_by: str) -> None:
        tok = mint_github_token(
            installations_path=self.installations_path,
            org=req.org,
            repositories=req.repositories,
            permissions=req.permissions,
            http=self._http,
            now=self._now,
        )
        req.status = STATUS_ISSUED
        req.token = tok.token
        req.expires_at = tok.expires_at
        req.repositories = list(tok.repositories) or req.repositories
        req.permissions = dict(tok.permissions) or req.permissions
        req.decided_at = _now_iso_z()
        req.decided_by = decided_by

    def expire_stale(self) -> int:
        """Sweep issued grants whose expires_at has passed → status=expired +
        drop the token. Returns the count expired. The UI calls this before
        rendering active grants so a stale token never shows as live."""
        now = datetime.now(timezone.utc)
        n = 0
        for req in self.store.list():
            if req.status != STATUS_ISSUED:
                continue
            exp = _parse_iso_z(req.expires_at)
            if exp is not None and exp <= now:
                req.status = STATUS_EXPIRED
                req.token = None
                self.store.save(req)
                n += 1
        return n
