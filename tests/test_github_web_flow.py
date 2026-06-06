"""End-to-end web flow for a GitHub access request riding the SAME request
lifecycle/UI as an AWS role: submit via /requests/new/github -> lands in the
shared /queue as pending -> approver approves -> token minted + shown once ->
revoke. Hermetic: github mint/revoke are monkeypatched (no GitHub network)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest_plugins = ["tests.conftest_routes"]


@pytest.fixture
def fake_github(monkeypatch):
    captured = {}

    def fake_mint(*, installations_path, org, repositories, permissions, http=None, now=None):
        captured["mint"] = {"org": org, "repos": repositories, "permissions": permissions}
        return SimpleNamespace(token="ghs_web_secret", repositories=tuple(repositories),
                               permissions=permissions, expires_at="2099-01-01T00:00:00Z")

    def fake_revoke(*, installations_path, org, token, http=None, now=None):
        captured["revoke"] = {"org": org, "token": token}

    monkeypatch.setattr("iam_jit.github_scope.mint_github_token", fake_mint)
    monkeypatch.setattr("iam_jit.github_scope.revoke_github_token", fake_revoke)
    return captured


def _submit(client, **over):
    data = {"org": "acme", "repositories": "web api", "access": "write",
            "duration_minutes": "30", "description": "ship a fix"}
    data.update(over)
    return client.post("/requests/new/github", data=data, follow_redirects=False)


def test_submit_lands_in_shared_queue_as_pending(shared_app, as_dev, as_admin, fake_github):
    r = _submit(as_dev)
    assert r.status_code == 303, r.text
    loc = r.headers["location"]
    rid = loc.rsplit("/", 1)[-1]
    stored = shared_app.state.request_store.get(rid)
    assert stored["kind"] == "GitHubTokenRequest"
    assert stored["status"]["state"] == "pending"
    assert stored["spec"]["github"]["repositories"] == ["web", "api"]
    # the GitHub request shows in the same approver queue
    q = as_admin.get("/queue")
    assert q.status_code == 200
    assert rid in q.text and "GitHub" in q.text


def test_detail_renders_without_aws_fields(as_dev, fake_github):
    rid = _submit(as_dev).headers["location"].rsplit("/", 1)[-1]
    d = as_dev.get(f"/requests/{rid}")
    assert d.status_code == 200
    assert "GitHub repo access" in d.text
    assert "acme" in d.text and "write" in d.text


def test_approve_mints_token_shown_once_then_revoke(shared_app, as_dev, as_admin, fake_github):
    rid = _submit(as_dev, access="read").headers["location"].rsplit("/", 1)[-1]
    # approver approves through the SAME approve endpoint as AWS
    ap = as_admin.post(f"/requests/{rid}/approve", json={})
    assert ap.status_code in (200, 303), ap.text
    stored = shared_app.state.request_store.get(rid)
    assert stored["status"]["state"] == "active"
    assert stored["status"]["provisioned"]["github"]["access"] == "read"
    assert stored["status"]["_secret_github_token"] == "ghs_web_secret"
    assert fake_github["mint"]["permissions"] == {"contents": "read"}
    # token shown once on the detail page
    d = as_admin.get(f"/requests/{rid}")
    assert "ghs_web_secret" in d.text
    # revoke via the web /revoke endpoint -> DELETE token + cleared
    rv = as_admin.post(f"/requests/{rid}/revoke", data={"reason": "done testing"},
                       follow_redirects=False)
    assert rv.status_code == 303, rv.text
    after = shared_app.state.request_store.get(rid)
    assert after["status"]["state"] == "revoked"
    assert "_secret_github_token" not in after["status"]
    assert fake_github["revoke"]["token"] == "ghs_web_secret"


def test_new_request_page_offers_github_option(as_dev, fake_github):
    page = as_dev.get("/requests/new")
    assert page.status_code == 200
    assert "GitHub repo access" in page.text
    assert "/requests/new/github" in page.text
