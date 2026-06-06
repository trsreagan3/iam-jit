"""The GitHub branch of attempt_provisioning mints a scoped token through the
SAME approve→provisioning→active lifecycle as an AWS role, with the access
level mapped directly to a GitHub permission preset."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from iam_jit import _auto_approve_helpers, lifecycle
from iam_jit.github_scope import access_to_permissions, access_is_auto_approve_eligible


def _provisioning_github_req(access: str = "write", minutes: int = 30) -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "GitHubTokenRequest",
        "metadata": {"id": "ghr-1", "requester": {"name": "Bot", "email": "b@e.com"}},
        "spec": {"github": {"org": "acme", "repositories": ["web"], "access": access,
                            "duration_minutes": minutes}},
        "status": {"state": "provisioning", "owner": "b@e.com"},
    }


def test_access_presets_map_to_github_permissions() -> None:
    assert access_to_permissions("read") == {"contents": "read"}
    assert access_to_permissions("pull_requests") == {"contents": "read", "pull_requests": "write"}
    assert access_to_permissions("issues") == {"contents": "read", "issues": "write"}
    assert access_to_permissions("write") == {"contents": "write", "pull_requests": "write"}


def test_only_read_is_auto_approve_eligible() -> None:
    assert access_is_auto_approve_eligible("read") is True
    for level in ("pull_requests", "issues", "write"):
        assert access_is_auto_approve_eligible(level) is False


def test_attempt_provisioning_mints_and_activates() -> None:
    req = _provisioning_github_req(access="write")
    captured: dict = {}

    def mint(*, org, repositories, permissions):
        captured["org"] = org
        captured["repositories"] = repositories
        captured["permissions"] = permissions
        return SimpleNamespace(token="ghs_secret", repositories=tuple(repositories),
                               permissions=permissions, expires_at="2099-01-01T00:00:00Z")

    _auto_approve_helpers.attempt_provisioning(
        req, accounts_store=None, provision_mod=None, assume_mod=None,
        lifecycle=lifecycle, github_mint=mint,
    )
    assert lifecycle.get_state(req) == "active"
    gh = req["status"]["provisioned"]["github"]
    assert gh["org"] == "acme" and gh["access"] == "write" and gh["token_active"] is True
    assert gh["repositories"] == ["web"]
    # the secret token is stored server-only, NOT in provisioned
    assert req["status"]["_secret_github_token"] == "ghs_secret"
    assert "token" not in gh
    # write -> contents:write + pull_requests:write was actually requested
    assert captured["permissions"] == {"contents": "write", "pull_requests": "write"}


def test_attempt_provisioning_mint_failure_is_terminal() -> None:
    req = _provisioning_github_req(access="read")

    def boom(**_):
        raise RuntimeError("github 403")

    _auto_approve_helpers.attempt_provisioning(
        req, accounts_store=None, provision_mod=None, assume_mod=None,
        lifecycle=lifecycle, github_mint=boom,
    )
    # NEVER raises; lands in a terminal-or-actionable state, not stuck in provisioning
    assert lifecycle.get_state(req) == "provisioning_failed"
    assert "_secret_github_token" not in req["status"]


def test_duration_capped_at_60_minutes() -> None:
    req = _provisioning_github_req(access="read", minutes=999)

    def mint(**_):
        return SimpleNamespace(token="t", repositories=("web",), permissions={}, expires_at="x")

    _auto_approve_helpers.attempt_provisioning(
        req, accounts_store=None, provision_mod=None, assume_mod=None,
        lifecycle=lifecycle, github_mint=mint,
    )
    # expires_at is within ~1h of now (capped), proving duration<=60 enforcement
    import datetime as dt
    exp = dt.datetime.strptime(req["status"]["provisioned"]["github"]["expires_at"],
                               "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    assert exp <= dt.datetime.now(dt.UTC) + dt.timedelta(minutes=61)
