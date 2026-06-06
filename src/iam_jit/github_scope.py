"""GitHub permission catalog + scoped-token mint/revoke helpers
(see docs/design/github-jit-tokens.md).

GitHub access rides the SAME request lifecycle as AWS roles (a
`GitHubTokenRequest` kind): submit -> queue -> approve -> mint -> revoke. There
is NO risk scorer for GitHub — the requested permissions ARE the GitHub
functionality. A request carries permissions DIRECTLY as a {category: read|write}
map over GitHub's real fine-grained repository catalog; the map is passed
straight to the installation-token mint. Auto-approve eligibility is a simple
property (`permissions_are_read_only`): only an all-read request may ever
auto-approve; any write needs a human / prior history (handled by the
auto-approve policy layer, not here).

This module owns: the permission catalog (schema + UI checklist), the
read-only check, and the mint/revoke helpers the serve lifecycle calls.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from .github_installations import get_installation, provisioner_for

# The request carries GitHub permissions DIRECTLY as {category: read|write},
# drawn from GitHub's real fine-grained repository permission catalog — there is
# NO invented level ladder and NO risk scorer. The map is passed straight to the
# installation-token mint. These constants drive the schema's allowed categories
# + the web UI's checklist; agents/API may send any KNOWN category.
KNOWN_GITHUB_PERMISSIONS: frozenset[str] = frozenset({
    "actions", "administration", "checks", "contents", "deployments",
    "environments", "issues", "metadata", "packages", "pages",
    "pull_requests", "repository_hooks", "repository_projects",
    "secret_scanning_alerts", "secrets", "security_events",
    "statuses", "vulnerability_alerts", "workflows",
})

# The subset surfaced as a checklist in the web form (the long tail is reachable
# via the "advanced" field / the API). Ordered for display.
COMMON_GITHUB_PERMISSIONS: tuple[str, ...] = (
    "contents", "pull_requests", "issues", "actions", "workflows",
    "checks", "deployments", "statuses", "packages",
)

# One-line description of each common category (UI hint).
PERMISSION_DESCRIPTIONS: dict[str, str] = {
    "contents": "repo files / branches / commits (read = clone; write = push)",
    "pull_requests": "open / comment / review PRs",
    "issues": "open / comment issues",
    "actions": "Actions workflow runs + artifacts",
    "workflows": "add / update .github/workflows files",
    "checks": "check runs / suites",
    "deployments": "deployments + statuses",
    "statuses": "commit statuses",
    "packages": "GitHub Packages",
}


def normalize_permissions(permissions: dict[str, str]) -> dict[str, str]:
    """Validate + lowercase a {category: level} permission map. Raises ValueError
    on an unknown category or a level other than read|write. metadata:read is
    GitHub-implicit; we keep whatever the caller sends."""
    if not permissions:
        raise ValueError("at least one permission is required")
    out: dict[str, str] = {}
    for raw_cat, raw_level in permissions.items():
        cat = str(raw_cat).strip().lower()
        level = str(raw_level).strip().lower()
        if cat not in KNOWN_GITHUB_PERMISSIONS:
            raise ValueError(f"unknown GitHub permission category {cat!r}")
        if level not in ("read", "write"):
            raise ValueError(f"permission {cat!r} level must be read|write, got {level!r}")
        out[cat] = level
    return out


def permissions_are_read_only(permissions: dict[str, str]) -> bool:
    """True when every requested permission is read-level. Only a read-only
    request is ever eligible for auto-approval without prior history; anything
    that can MODIFY (any write) requires a human or a prior saved approval."""
    return bool(permissions) and all(
        str(v).strip().lower() == "read" for v in permissions.values()
    )


def mint_github_token(
    *,
    installations_path: str,
    org: str,
    repositories: list[str],
    permissions: dict[str, str],
    http: httpx.Client | None = None,
    now: Callable[[], int] | None = None,
):
    """Resolve the installation and mint a scoped token. NO gating — the caller
    (the serve lifecycle's approve path) owns the allow/deny decision; this only
    mints. Returns the `GitHubScopedToken`."""
    inst = get_installation(installations_path, org)
    prov = provisioner_for(inst, http=http, now=now)
    try:
        return prov.mint_scoped_token(repositories=repositories, permissions=permissions)
    finally:
        prov.close()


def revoke_github_token(
    *,
    installations_path: str,
    org: str,
    token: str,
    http: httpx.Client | None = None,
    now: Callable[[], int] | None = None,
) -> None:
    """Revoke (DELETE) a previously-minted installation token early. Idempotent
    (an already-expired/invalid token is treated as revoked). Used by the serve
    lifecycle's revoke endpoint so an admin can kill an active grant before its
    ≤1h TTL elapses."""
    inst = get_installation(installations_path, org)
    prov = provisioner_for(inst, http=http, now=now)
    try:
        prov.revoke(token)
    finally:
        prov.close()
