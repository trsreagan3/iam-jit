"""Optional GitHub auto-approve policy + saved approvals + requester key.

OFF by default; read-only may auto-issue; breadth cap catches anomalies; any
write needs a prior saved approval matched by requester_key. The "remember"
flow issues a durable requester key that a future request presents to auto-issue.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from iam_jit import github_autoapprove as ga


def _policy(tmp_path, **kw):
    p = tmp_path / "pol.yaml"
    import json
    p.write_text(json.dumps({"enabled": True, **kw}))  # JSON is valid YAML
    return ga.load_policy(str(p))


def test_disabled_by_default(tmp_path) -> None:
    pol = ga.load_policy(str(tmp_path / "missing.yaml"))
    assert pol.enabled is False
    ok, _ = ga.evaluate(policy=pol, saved_store=ga.SavedApprovalStore(str(tmp_path / "s.json")),
                        requester_key=None, repositories=["web"], permissions={"contents": "read"})
    assert ok is False


def test_read_only_auto_approves_when_enabled(tmp_path) -> None:
    pol = _policy(tmp_path)
    store = ga.SavedApprovalStore(str(tmp_path / "s.json"))
    ok, reason = ga.evaluate(policy=pol, saved_store=store, requester_key=None,
                             repositories=["web", "api"], permissions={"contents": "read"})
    assert ok is True and "read-only" in reason


def test_breadth_cap_blocks_many_repos(tmp_path) -> None:
    pol = _policy(tmp_path, max_repos_per_request=4)
    store = ga.SavedApprovalStore(str(tmp_path / "s.json"))
    ok, reason = ga.evaluate(policy=pol, saved_store=store, requester_key=None,
                             repositories=[f"r{i}" for i in range(5)], permissions={"contents": "read"})
    assert ok is False and "breadth cap" in reason


def test_write_needs_prior_saved_approval(tmp_path) -> None:
    pol = _policy(tmp_path)
    store = ga.SavedApprovalStore(str(tmp_path / "s.json"))
    perms = {"contents": "write"}
    # no key / no saved approval -> human
    assert ga.evaluate(policy=pol, saved_store=store, requester_key=None,
                       repositories=["web"], permissions=perms)[0] is False
    assert ga.evaluate(policy=pol, saved_store=store, requester_key="rk_x",
                       repositories=["web"], permissions=perms)[0] is False
    # remember it, then the same request auto-approves
    store.remember("rk_x", ["web"], perms)
    ok, reason = ga.evaluate(policy=pol, saved_store=store, requester_key="rk_x",
                             repositories=["web"], permissions=perms)
    assert ok is True and "prior approval" in reason
    # but a DIFFERENT repo / higher level is still not covered
    assert ga.evaluate(policy=pol, saved_store=store, requester_key="rk_x",
                       repositories=["other"], permissions=perms)[0] is False


def test_saved_approval_write_covers_read(tmp_path) -> None:
    store = ga.SavedApprovalStore(str(tmp_path / "s.json"))
    store.remember("rk_x", ["web"], {"contents": "write"})
    pol = _policy(tmp_path, allow_read_only=False)  # force the saved-approval path
    ok, _ = ga.evaluate(policy=pol, saved_store=store, requester_key="rk_x",
                        repositories=["web"], permissions={"contents": "read"})
    assert ok is True  # write covers read


def _gh_req(permissions, requester_key=None, repos=None):
    gh = {"org": "acme", "repositories": repos or ["web"], "permissions": permissions,
          "duration_minutes": 30}
    if requester_key:
        gh["requester_key"] = requester_key
    return {
        "apiVersion": "iam-jit.dev/v1alpha1", "kind": "GitHubTokenRequest",
        "metadata": {"id": "ghr-1", "requester": {"name": "B", "email": "b@e.com"}},
        "spec": {"github": gh},
        "status": {"state": "pending", "owner": "b@e.com",
                   "history": [{"action": "submit", "by": "b@e.com", "at": "x"}]},
    }


def _mint(**_):
    return SimpleNamespace(token="ghs_auto", repositories=("web",),
                           permissions={"contents": "read"}, expires_at="2099-01-01T00:00:00Z")


def test_maybe_auto_issue_mints_read_only(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_GITHUB_AUTOAPPROVE", str(_enabled_policy(tmp_path)))
    req = _gh_req({"contents": "read"})
    issued, _ = ga.maybe_auto_issue(req, github_mint=_mint)
    assert issued is True
    assert req["status"]["state"] == "active"
    assert req["status"]["_secret_github_token"] == "ghs_auto"


def test_maybe_auto_issue_leaves_write_pending(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_GITHUB_AUTOAPPROVE", str(_enabled_policy(tmp_path)))
    req = _gh_req({"contents": "write"})
    issued, _ = ga.maybe_auto_issue(req, github_mint=_mint)
    assert issued is False
    assert req["status"]["state"] == "pending"


def _enabled_policy(tmp_path) -> str:
    import json
    p = tmp_path / "pol.yaml"
    p.write_text(json.dumps({"enabled": True}))
    return p
