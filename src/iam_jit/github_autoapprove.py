"""Optional GitHub auto-approve policy + saved approvals (OFF by default).

So routine access isn't blocked while anomalies still queue:
  - an admin policy may auto-approve READ-ONLY requests, and applies a
    breadth cap (e.g. a sudden request for >=5 unrelated repos drops to human
    review even if it'd otherwise pass);
  - "save approval for future" at approval time remembers a requester<->repo
    pairing so future matching requests auto-issue a FRESH <=1h token — no
    standing token to any repo is ever held.

Since requesters can be anonymous, the unit of identity is a durable
**requester key** (rk_...), an identity credential (NOT a token) minted on the
first saved approval and presented on future requests to match it.

Everything here is opt-in: with no policy file, nothing auto-approves and every
request goes to the human queue.
"""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import secrets

from .github_scope import normalize_permissions, permissions_are_read_only

_LEVEL_RANK = {"read": 1, "write": 2}


def default_policy_path() -> str:
    env = os.environ.get("IAM_JIT_GITHUB_AUTOAPPROVE")
    if env:
        return env
    return str(pathlib.Path.home() / ".iam-jit" / "github-auto-approve.yaml")


def default_saved_approvals_path() -> str:
    env = os.environ.get("IAM_JIT_GITHUB_SAVED_APPROVALS")
    if env:
        return env
    return str(pathlib.Path.home() / ".iam-jit" / "github-saved-approvals.json")


@dataclasses.dataclass(frozen=True)
class GitHubAutoApprovePolicy:
    enabled: bool = False
    allow_read_only: bool = True  # only meaningful when enabled
    max_repos_per_request: int = 4  # >= this+1 repos -> always human review

    @property
    def breadth_cap(self) -> int:
        return self.max_repos_per_request


def load_policy(path: str | None = None) -> GitHubAutoApprovePolicy:
    """Load the policy file. Missing/unreadable file -> disabled default (the
    safe state: everything queues)."""
    p = pathlib.Path(path or default_policy_path())
    if not p.exists():
        return GitHubAutoApprovePolicy()
    try:
        from ruamel.yaml import YAML

        data = YAML(typ="safe").load(p.read_text()) or {}
    except Exception:
        return GitHubAutoApprovePolicy()
    if not isinstance(data, dict):
        return GitHubAutoApprovePolicy()
    return GitHubAutoApprovePolicy(
        enabled=bool(data.get("enabled", False)),
        allow_read_only=bool(data.get("allow_read_only", True)),
        max_repos_per_request=int(data.get("max_repos_per_request", 4) or 4),
    )


class SavedApprovalStore:
    """File-backed per-(requester_key, repo) saved approvals. Shape:
    {requester_key: {repo: {category: level}}} — the max level ever approved
    for that requester+repo+category."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or default_saved_approvals_path()

    def _load(self) -> dict:
        p = pathlib.Path(self.path)
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text()) or {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, data: dict) -> None:
        p = pathlib.Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)

    def get_for(self, requester_key: str, repo: str) -> dict[str, str]:
        if not requester_key:
            return {}
        return dict((self._load().get(requester_key) or {}).get(repo) or {})

    def remember(self, requester_key: str, repositories: list[str], permissions: dict[str, str]) -> None:
        """Record (merge, taking the max level) a saved approval for each repo."""
        perms = normalize_permissions(permissions)
        data = self._load()
        rk = data.setdefault(requester_key, {})
        for repo in repositories:
            cur = rk.setdefault(repo, {})
            for cat, level in perms.items():
                if _LEVEL_RANK.get(level, 0) > _LEVEL_RANK.get(cur.get(cat), 0):
                    cur[cat] = level
        self._save(data)


def mint_requester_key() -> str:
    return "rk_" + secrets.token_urlsafe(18)


def _covered(saved: dict[str, str], requested: dict[str, str]) -> bool:
    """True when a saved approval covers every requested {cat: level} (write
    covers read; read does NOT cover write)."""
    for cat, level in requested.items():
        if _LEVEL_RANK.get(saved.get(cat), 0) < _LEVEL_RANK.get(level, 0):
            return False
    return True


def maybe_auto_issue(
    req: dict,
    *,
    github_mint=None,
    policy_path: str | None = None,
    saved_path: str | None = None,
) -> tuple[bool, str]:
    """If the optional policy + saved approvals clear this GitHub request,
    auto-issue it NOW (pending -> provisioning -> active, minting a fresh ≤1h
    token) and return (True, reason). Otherwise leave it pending and return
    (False, reason). Never raises. github_mint is injectable for tests."""
    from . import _auto_approve_helpers, lifecycle
    from .users_store import User

    gh = (req.get("spec") or {}).get("github") or {}
    try:
        ok, reason = evaluate(
            policy=load_policy(policy_path),
            saved_store=SavedApprovalStore(saved_path),
            requester_key=gh.get("requester_key"),
            repositories=gh.get("repositories") or [],
            permissions=gh.get("permissions") or {},
        )
    except Exception as e:  # noqa: BLE001 — a policy hiccup must never block submit
        return False, f"auto-approve check skipped: {e}"
    if not ok:
        return False, reason
    actor = User(id="system:github-auto-approve", roles=("approver",))
    try:
        lifecycle.apply_transition(req, action="approve", actor=actor,
                                   reason=f"github auto-approve: {reason}")
        _auto_approve_helpers.attempt_provisioning(
            req, accounts_store=None, provision_mod=None, assume_mod=None,
            lifecycle=lifecycle, github_mint=github_mint,
        )
    except Exception:  # noqa: BLE001
        return False, "auto-issue attempt failed"
    return lifecycle.get_state(req) == "active", reason


def evaluate(
    *,
    policy: GitHubAutoApprovePolicy,
    saved_store: SavedApprovalStore,
    requester_key: str | None,
    repositories: list[str],
    permissions: dict[str, str],
) -> tuple[bool, str]:
    """Decide whether a GitHub request auto-issues. Returns (auto, reason).

    Order: policy off -> no. Breadth cap exceeded -> no (anomaly). Read-only +
    allow_read_only -> yes. Otherwise (has writes) -> yes ONLY if a saved
    approval for this requester_key covers every repo+permission; else no."""
    if not policy.enabled:
        return False, "auto-approve policy disabled"
    n = len(repositories)
    if n > policy.max_repos_per_request:
        return False, f"breadth cap: {n} repos (> {policy.max_repos_per_request}) — human review"
    perms = normalize_permissions(permissions)
    # Fast path: a read-only request when the policy allows it.
    if permissions_are_read_only(perms) and policy.allow_read_only:
        return True, "read-only auto-approve"
    # Otherwise (any write, or read-only when the fast-path is off) require a
    # prior saved approval for this requester covering every repo+permission.
    if not requester_key:
        return False, "needs human approval (no prior approval on record)"
    for repo in repositories:
        if not _covered(saved_store.get_for(requester_key, repo), perms):
            return False, f"no prior approval on record for {repo} at this level"
    return True, "prior approval on record"
