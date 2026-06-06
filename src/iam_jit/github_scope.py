"""GitHub scope scorer + standalone self-scoping composer
(see docs/design/github-jit-tokens.md).

`analyze_github_scope` is the deterministic GitHub analog of the AWS policy
scorer: it scores a requested {repos, permissions} set 1–10 so over-broad grants
(the blast-radius footgun — e.g. `contents:write` × many repos) are NOT
auto-approved. This scorer is load-bearing for the "agent already infected when
it requests scope" case in the threat model: a malicious broad request scores
high → human approval required.

`scope_github_task` is the standalone composer (the create-not-assume flow for
GitHub): resolve installation → score → if within the auto-approve band, mint a
scoped token; else return a needs-approval decision WITHOUT minting. No serve /
lifecycle / bouncer dependency — usable on its own.
"""

from __future__ import annotations

import dataclasses
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


# Per-permission risk on a 1–10 scale: (write_or_admin_risk, read_risk).
# Write to code / CI / secrets / settings is the supply-chain vector → high.
_PERM_RISK: dict[str, tuple[int, int]] = {
    "administration": (9, 4),
    "secrets": (9, 9),
    "actions": (8, 2),
    "workflows": (8, 2),
    "contents": (7, 2),
    "environments": (7, 2),
    "deployments": (5, 2),
    "packages": (5, 2),
    "pull_requests": (3, 1),  # open/edit PRs (NOT merge/alter code) — common low-risk agent task
    "issues": (3, 1),
    "checks": (3, 1),
    "statuses": (3, 1),
    "metadata": (1, 1),
}
_DEFAULT_PERM_RISK = (5, 2)  # unknown permission → treat as a mid-risk write

# Auto-approve at or below this score (mirrors the AWS read-only-ish default).
AUTO_APPROVE_MAX_SCORE = 3


def _is_write(level: str) -> bool:
    return level.lower() in ("write", "admin")


def _breadth_addend(n_repos: int) -> tuple[int, str]:
    if n_repos <= 1:
        return 0, ""
    if n_repos <= 5:
        return 1, f"{n_repos} repos"
    if n_repos <= 20:
        return 2, f"{n_repos} repos (broad)"
    return 3, f"{n_repos} repos (very broad)"


@dataclasses.dataclass(frozen=True)
class GitHubScopeReview:
    risk_score: int  # 1–10
    band: str  # "low" | "medium" | "high"
    risk_factors: tuple[str, ...]
    would_auto_approve: bool


def analyze_github_scope(
    repositories: list[str], permissions: dict[str, str]
) -> GitHubScopeReview:
    """Deterministically score a requested GitHub token scope."""
    factors: list[str] = []
    perm_peak = 1
    for perm, level in sorted(permissions.items()):
        write_risk, read_risk = _PERM_RISK.get(perm.lower(), _DEFAULT_PERM_RISK)
        risk = write_risk if _is_write(level) else read_risk
        if risk >= 7:
            factors.append(f"{perm}:{level} (high-impact)")
        perm_peak = max(perm_peak, risk)

    addend, breadth_note = _breadth_addend(len(repositories))
    if breadth_note:
        factors.append(breadth_note)
    if not repositories:
        # Shouldn't reach the scorer (provisioner refuses), but score it max so
        # nothing can ever auto-approve an all-repos grant.
        factors.append("ALL repos (no repository scoping)")
        perm_peak, addend = 10, 0

    score = max(1, min(10, perm_peak + addend))
    band = "low" if score <= 3 else ("medium" if score <= 6 else "high")
    if not factors:
        factors.append("scoped + low-impact")
    return GitHubScopeReview(
        risk_score=score,
        band=band,
        risk_factors=tuple(factors),
        would_auto_approve=score <= AUTO_APPROVE_MAX_SCORE,
    )


@dataclasses.dataclass(frozen=True)
class GitHubScopeDecision:
    decision: str  # "issued" | "needs_approval"
    review: GitHubScopeReview
    repositories: tuple[str, ...]
    permissions: dict[str, str]
    token: str | None = None
    expires_at: str | None = None


def mint_github_token(
    *,
    installations_path: str,
    org: str,
    repositories: list[str],
    permissions: dict[str, str],
    http: httpx.Client | None = None,
    now: Callable[[], int] | None = None,
):
    """Resolve the installation and mint a scoped token — NO scoring gate.

    Used by the auto-approve path (after `analyze_github_scope` cleared it) and
    by the serve lifecycle's human-approval path (after an admin approved a
    high-risk request). Returns the `GitHubScopedToken`. The caller owns the
    gating decision; this only mints."""
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


def scope_github_task(
    *,
    installations_path: str,
    org: str,
    description: str,
    repositories: list[str],
    permissions: dict[str, str],
    auto_approve_max_score: int = AUTO_APPROVE_MAX_SCORE,
    http: httpx.Client | None = None,
    now: Callable[[], int] | None = None,
) -> GitHubScopeDecision:
    """Standalone self-scoping: score the request; if it auto-approves, mint a
    scoped token; otherwise return needs_approval WITHOUT minting anything.

    `description` is accepted for audit parity with the AWS composer (the
    serve/lifecycle layer logs it); the scorer itself is policy-only."""
    review = analyze_github_scope(repositories, permissions)
    if review.risk_score > auto_approve_max_score:
        return GitHubScopeDecision(
            decision="needs_approval",
            review=review,
            repositories=tuple(repositories),
            permissions=dict(permissions),
        )
    tok = mint_github_token(
        installations_path=installations_path,
        org=org,
        repositories=repositories,
        permissions=permissions,
        http=http,
        now=now,
    )
    return GitHubScopeDecision(
        decision="issued",
        review=review,
        repositories=tok.repositories,
        permissions=tok.permissions,
        token=tok.token,
        expires_at=tok.expires_at,
    )
