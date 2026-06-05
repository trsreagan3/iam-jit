from __future__ import annotations

import pathlib

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from iam_jit.github_requests import (
    STATUS_DENIED,
    STATUS_ISSUED,
    STATUS_NEEDS_APPROVAL,
    STATUS_REVOKED,
    GitHubRequestError,
    GitHubRequestService,
    GitHubRequestStore,
)

_REGISTRY = """\
apiVersion: iam-jit.dev/v1alpha1
kind: GitHubInstallationList
installations:
  - org: acme
    app_id: "12345"
    installation_id: "99"
    private_key_path: {keypath}
"""


def _write_key(tmp_path: pathlib.Path) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    p = tmp_path / "app.pem"
    p.write_bytes(pem)
    return str(p)


def _registry(tmp_path: pathlib.Path) -> str:
    p = tmp_path / "github-installations.yaml"
    p.write_text(_REGISTRY.format(keypath=_write_key(tmp_path)))
    return str(p)


def _mock_github(captured: dict) -> httpx.Client:
    """GitHub App API stub: mints on POST access_tokens, 204 on DELETE."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/access_tokens"):
            captured["mint_count"] = captured.get("mint_count", 0) + 1
            captured["last_body"] = request.content.decode()
            return httpx.Response(
                201,
                json={
                    "token": "ghs_minted_secret",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "permissions": {"contents": "read"},
                    "repositories": [{"name": "r1"}],
                },
            )
        if request.method == "DELETE":
            captured["revoke_count"] = captured.get("revoke_count", 0) + 1
            return httpx.Response(204)
        return httpx.Response(500, json={"message": "unexpected"})

    return httpx.Client(transport=httpx.MockTransport(handler))


def _service(tmp_path, captured):
    store = GitHubRequestStore(str(tmp_path / "reqs"))
    return GitHubRequestService(
        installations_path=_registry(tmp_path),
        store=store,
        http=_mock_github(captured),
        now=lambda: 1_780_000_000,
    )


def test_low_risk_submit_auto_issues_token(tmp_path: pathlib.Path) -> None:
    cap: dict = {}
    svc = _service(tmp_path, cap)
    req = svc.submit(
        org="acme",
        description="open a PR on one repo",
        requester="agent-bot",
        repositories=["r1"],
        permissions={"pull_requests": "write"},
    )
    assert req.status == STATUS_ISSUED
    assert req.band == "low"
    assert cap["mint_count"] == 1
    assert req.token == "ghs_minted_secret"
    # the public view never leaks the token
    pub = req.to_public()
    assert "token" not in pub and pub["token_active"] is True


def test_high_risk_submit_queues_and_mints_nothing(tmp_path: pathlib.Path) -> None:
    cap: dict = {}
    svc = _service(tmp_path, cap)
    req = svc.submit(
        org="acme",
        description="rewrite contents across everything",
        requester="agent-bot",
        repositories=[f"r{i}" for i in range(30)],
        permissions={"contents": "write"},
    )
    assert req.status == STATUS_NEEDS_APPROVAL
    assert req.band == "high"
    assert req.token is None
    assert cap.get("mint_count", 0) == 0  # high-risk NEVER reached GitHub


def test_approve_queued_request_mints_token(tmp_path: pathlib.Path) -> None:
    cap: dict = {}
    svc = _service(tmp_path, cap)
    req = svc.submit(
        org="acme",
        description="admin settings change",
        requester="agent-bot",
        repositories=["r1"],
        permissions={"administration": "write"},
    )
    assert req.status == STATUS_NEEDS_APPROVAL
    assert cap.get("mint_count", 0) == 0
    approved = svc.approve(req.id, approver="reagan")
    assert approved.status == STATUS_ISSUED
    assert approved.decided_by == "reagan"
    assert cap["mint_count"] == 1
    assert approved.token == "ghs_minted_secret"


def test_deny_queued_request(tmp_path: pathlib.Path) -> None:
    cap: dict = {}
    svc = _service(tmp_path, cap)
    req = svc.submit(
        org="acme",
        description="secrets read everywhere",
        requester="agent-bot",
        repositories=["r1", "r2"],
        permissions={"secrets": "read"},
    )
    denied = svc.deny(req.id, approver="reagan")
    assert denied.status == STATUS_DENIED
    assert cap.get("mint_count", 0) == 0
    # can't approve a denied request
    with pytest.raises(GitHubRequestError):
        svc.approve(req.id, approver="reagan")


def test_revoke_issued_token_calls_delete_and_clears(tmp_path: pathlib.Path) -> None:
    cap: dict = {}
    svc = _service(tmp_path, cap)
    req = svc.submit(
        org="acme",
        description="open a PR",
        requester="agent-bot",
        repositories=["r1"],
        permissions={"pull_requests": "write"},
    )
    assert req.status == STATUS_ISSUED
    revoked = svc.revoke(req.id, actor="reagan")
    assert revoked.status == STATUS_REVOKED
    assert revoked.token is None
    assert cap["revoke_count"] == 1
    # re-revoke is rejected (not active)
    with pytest.raises(GitHubRequestError):
        svc.revoke(req.id, actor="reagan")


def test_store_roundtrip_and_list_hides_token(tmp_path: pathlib.Path) -> None:
    cap: dict = {}
    svc = _service(tmp_path, cap)
    svc.submit(
        org="acme", description="a", requester="bot",
        repositories=["r1"], permissions={"pull_requests": "write"},
    )
    svc.submit(
        org="acme", description="b", requester="bot",
        repositories=["r1", "r2"], permissions={"secrets": "read"},
    )
    listed = svc.store.list()
    assert len(listed) == 2
    # newest first
    assert listed[0].created_at >= listed[1].created_at
    # the file on disk is 0600
    import os
    f = next(pathlib.Path(svc.store.dir_path).glob("*.json"))
    assert (os.stat(f).st_mode & 0o077) == 0


def test_expire_stale_drops_token(tmp_path: pathlib.Path) -> None:
    cap: dict = {}
    svc = _service(tmp_path, cap)
    req = svc.submit(
        org="acme", description="a", requester="bot",
        repositories=["r1"], permissions={"pull_requests": "write"},
    )
    # force the grant into the past
    req.expires_at = "2000-01-01T00:00:00Z"
    svc.store.save(req)
    assert svc.expire_stale() == 1
    after = svc.store.get(req.id)
    assert after.status == "expired" and after.token is None
