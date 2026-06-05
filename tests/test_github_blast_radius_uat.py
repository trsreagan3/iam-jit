"""Blast-radius UAT — the HARD gate for the GitHub JIT-token feature.

Unlike the hermetic unit/route tests (which stub GitHub), this exercises a REAL
GitHub App against a REAL test org so we prove the scope is enforced
SERVER-SIDE by GitHub — the whole security claim. It is SKIPPED unless the
operator opts in with real credentials, so CI stays hermetic.

To run (see docs/uat/github-blast-radius.md for full setup):

    export IAM_JIT_GH_UAT=1
    export IAM_JIT_GH_UAT_APP_ID=123456
    export IAM_JIT_GH_UAT_INSTALLATION_ID=98765432
    export IAM_JIT_GH_UAT_PRIVATE_KEY_PATH=/path/to/app.private-key.pem
    export IAM_JIT_GH_UAT_REPO_IN_SCOPE=iam-jit-uat-a      # token is scoped to THIS
    export IAM_JIT_GH_UAT_REPO_OUT_OF_SCOPE=iam-jit-uat-b  # token must NOT reach THIS
    export IAM_JIT_GH_UAT_OWNER=my-test-org
    pytest tests/test_github_blast_radius_uat.py -v

The matrix this proves (each row is GitHub enforcing, not iam-jit):

    ✅  repo-in-scope  + granted perm (contents:read)   -> 200
    ❌  repo-in-scope  + ungranted perm (contents:write) -> 403/404
    ❌  repo-out-of-scope (any perm)                     -> 404
    ❌  after revoke (DELETE /installation/token)        -> 401
"""

from __future__ import annotations

import os

import httpx
import pytest

from iam_jit.github_provisioner import GitHubAppConfig, GitHubAppProvisioner

_REQUIRED = (
    "IAM_JIT_GH_UAT_APP_ID",
    "IAM_JIT_GH_UAT_INSTALLATION_ID",
    "IAM_JIT_GH_UAT_PRIVATE_KEY_PATH",
    "IAM_JIT_GH_UAT_REPO_IN_SCOPE",
    "IAM_JIT_GH_UAT_REPO_OUT_OF_SCOPE",
    "IAM_JIT_GH_UAT_OWNER",
)

pytestmark = pytest.mark.skipif(
    os.environ.get("IAM_JIT_GH_UAT") != "1"
    or any(not os.environ.get(k) for k in _REQUIRED),
    reason="GitHub blast-radius UAT needs real App creds; set IAM_JIT_GH_UAT=1 + "
    "the IAM_JIT_GH_UAT_* vars (see docs/uat/github-blast-radius.md)",
)

_API = "https://api.github.com"


def _cfg() -> GitHubAppConfig:
    return GitHubAppConfig(
        app_id=os.environ["IAM_JIT_GH_UAT_APP_ID"],
        private_key_pem=open(os.environ["IAM_JIT_GH_UAT_PRIVATE_KEY_PATH"]).read(),
        installation_id=os.environ["IAM_JIT_GH_UAT_INSTALLATION_ID"],
    )


def _owner() -> str:
    return os.environ["IAM_JIT_GH_UAT_OWNER"]


def _read_contents(token: str, repo: str) -> httpx.Response:
    with httpx.Client(timeout=20.0) as c:
        return c.get(
            f"{_API}/repos/{_owner()}/{repo}/contents/",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
        )


def _attempt_write(token: str, repo: str) -> httpx.Response:
    """Try to create a file — needs contents:write the token was NOT granted."""
    import base64

    with httpx.Client(timeout=20.0) as c:
        return c.put(
            f"{_API}/repos/{_owner()}/{repo}/contents/iam-jit-uat-probe.txt",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={
                "message": "iam-jit UAT probe (should be rejected)",
                "content": base64.b64encode(b"nope").decode(),
            },
        )


@pytest.fixture
def scoped_read_token() -> str:
    """Mint a token scoped to ONLY the in-scope repo with ONLY contents:read."""
    prov = GitHubAppProvisioner(_cfg())
    try:
        tok = prov.mint_scoped_token(
            repositories=[os.environ["IAM_JIT_GH_UAT_REPO_IN_SCOPE"]],
            permissions={"contents": "read"},
        )
    finally:
        prov.close()
    return tok.token


def test_in_scope_read_succeeds(scoped_read_token: str) -> None:
    r = _read_contents(scoped_read_token, os.environ["IAM_JIT_GH_UAT_REPO_IN_SCOPE"])
    assert r.status_code == 200, f"in-scope read should work: {r.status_code} {r.text[:200]}"


def test_ungranted_write_is_denied(scoped_read_token: str) -> None:
    r = _attempt_write(scoped_read_token, os.environ["IAM_JIT_GH_UAT_REPO_IN_SCOPE"])
    assert r.status_code in (403, 404), (
        f"contents:write was NOT granted — GitHub must deny: {r.status_code} {r.text[:200]}"
    )


def test_out_of_scope_repo_is_invisible(scoped_read_token: str) -> None:
    r = _read_contents(scoped_read_token, os.environ["IAM_JIT_GH_UAT_REPO_OUT_OF_SCOPE"])
    assert r.status_code == 404, (
        f"out-of-scope repo must be unreachable (404): {r.status_code} {r.text[:200]}"
    )


def test_revoked_token_is_dead() -> None:
    prov = GitHubAppProvisioner(_cfg())
    try:
        tok = prov.mint_scoped_token(
            repositories=[os.environ["IAM_JIT_GH_UAT_REPO_IN_SCOPE"]],
            permissions={"contents": "read"},
        )
        # confirm it works first
        assert _read_contents(tok.token, os.environ["IAM_JIT_GH_UAT_REPO_IN_SCOPE"]).status_code == 200
        prov.revoke(tok.token)
    finally:
        prov.close()
    # after revoke, the same token is dead
    r = _read_contents(tok.token, os.environ["IAM_JIT_GH_UAT_REPO_IN_SCOPE"])
    assert r.status_code == 401, f"revoked token must be 401: {r.status_code} {r.text[:200]}"
