"""GitHub App installation-token provisioner — the issuer core for the
GitHub JIT-token feature (see docs/design/github-jit-tokens.md).

This is a STANDALONE iam-jit provisioner backend (no bouncer dependency). It
mints **scoped, short-TTL** GitHub tokens so a compromised agent's blast radius
is small — bounded in repos, permissions, and time. The control is the token's
scope, which **GitHub enforces server-side**: a token requested for repo X +
`pull_requests:write` cannot touch repo Y or write `contents`.

Mechanics (GitHub App installation access tokens):
  1. Sign a short-lived RS256 JWT as the App (iss=app_id, exp<=10min).
  2. POST /app/installations/{id}/access_tokens with a `repositories` +
     `permissions` SUBSET -> GitHub returns a ~1h token scoped to exactly that
     subset. The down-scope request body is the whole point.
  3. revoke() -> DELETE /installation/token.

HTTP + clock are injectable so the unit tests are fully hermetic (no network,
no real org). The hermetic test proves we REQUEST the correct down-scope; the
real-org UAT (docs: the blast-radius matrix) proves GitHub ENFORCES it — the
unit test cannot substitute for that.
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable

import httpx
import jwt

_GITHUB_API = "https://api.github.com"
# GitHub rejects App JWTs whose exp is >10 min out; use 9 min + 60s back-dated
# iat to tolerate clock skew.
_JWT_TTL_SECONDS = 9 * 60
_JWT_BACKDATE_SECONDS = 60


class GitHubProvisioningError(Exception):
    """A GitHub App / installation-token operation failed. Carries the GitHub
    status + message so an operator sees exactly what to fix."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclasses.dataclass(frozen=True)
class GitHubAppConfig:
    """Per-installation config (the GitHub analog of an AWS account entry).

    ``private_key_pem`` is the App's PEM private key (used only to sign the
    short-lived App JWT; never leaves the process)."""

    app_id: str
    private_key_pem: str
    installation_id: str
    api_base: str = _GITHUB_API


@dataclasses.dataclass(frozen=True)
class GitHubScopedToken:
    """A minted, down-scoped installation token + what it is scoped to."""

    token: str
    expires_at: str  # ISO-8601 (GitHub-provided)
    repositories: tuple[str, ...]
    permissions: dict[str, str]


def build_app_jwt(app_id: str, private_key_pem: str, *, now: int | None = None) -> str:
    """Sign the App-authentication JWT (RS256). Public so tests can verify it."""
    issued = (now if now is not None else int(time.time())) - _JWT_BACKDATE_SECONDS
    payload = {"iat": issued, "exp": issued + _JWT_BACKDATE_SECONDS + _JWT_TTL_SECONDS, "iss": app_id}
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


class GitHubAppProvisioner:
    """Mints + revokes scoped GitHub App installation tokens.

    ``http`` and ``now`` are injectable for hermetic tests; defaults are a real
    httpx client + wall clock."""

    def __init__(
        self,
        cfg: GitHubAppConfig,
        *,
        http: httpx.Client | None = None,
        now: Callable[[], int] | None = None,
    ) -> None:
        self._cfg = cfg
        self._http = http or httpx.Client(timeout=15.0)
        self._owns_http = http is None
        self._now = now or (lambda: int(time.time()))

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def _app_headers(self) -> dict[str, str]:
        token = build_app_jwt(self._cfg.app_id, self._cfg.private_key_pem, now=self._now())
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def mint_scoped_token(
        self,
        *,
        repositories: list[str],
        permissions: dict[str, str],
    ) -> GitHubScopedToken:
        """Mint a token scoped to exactly ``repositories`` + ``permissions``.

        ``repositories`` are repo NAMES within the installation's org; an empty
        list is REFUSED (an empty list means "all repos in the installation" to
        the GitHub API — the opposite of least privilege, and exactly the
        blast-radius footgun this feature exists to prevent)."""
        if not repositories:
            raise GitHubProvisioningError(
                "refusing to mint a token with no repositories: GitHub treats an "
                "empty repository list as ALL repos in the installation, which "
                "defeats least-privilege. Name the task's repo(s) explicitly."
            )
        if not permissions:
            raise GitHubProvisioningError("refusing to mint a token with no permissions")

        url = f"{self._cfg.api_base}/app/installations/{self._cfg.installation_id}/access_tokens"
        body = {"repositories": list(repositories), "permissions": dict(permissions)}
        try:
            resp = self._http.post(url, headers=self._app_headers(), json=body)
        except httpx.HTTPError as e:
            raise GitHubProvisioningError(f"GitHub token mint request failed: {e}") from e
        if resp.status_code != 201:
            raise GitHubProvisioningError(
                f"GitHub refused the scoped token (HTTP {resp.status_code}): {_err_text(resp)}",
                status=resp.status_code,
            )
        data = resp.json()
        repos = tuple(r.get("name", "") for r in (data.get("repositories") or []))
        return GitHubScopedToken(
            token=data["token"],
            expires_at=data.get("expires_at", ""),
            repositories=repos or tuple(repositories),
            permissions=data.get("permissions") or dict(permissions),
        )

    def revoke(self, token: str) -> None:
        """Revoke a previously-minted installation token (DELETE
        /installation/token). Idempotent: an already-expired/revoked token
        (401) is treated as success."""
        url = f"{self._cfg.api_base}/installation/token"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            resp = self._http.delete(url, headers=headers)
        except httpx.HTTPError as e:
            raise GitHubProvisioningError(f"GitHub token revoke request failed: {e}") from e
        if resp.status_code not in (204, 401):
            raise GitHubProvisioningError(
                f"GitHub refused the revoke (HTTP {resp.status_code}): {_err_text(resp)}",
                status=resp.status_code,
            )


def _err_text(resp: httpx.Response) -> str:
    try:
        j = resp.json()
        msg = j.get("message", "")
        if j.get("errors"):
            msg += f" {j['errors']}"
        return msg or resp.text[:200]
    except Exception:
        return resp.text[:200]
