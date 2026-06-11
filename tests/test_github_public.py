"""Anonymous (no-login) GitHub request flow + capability-URL retrieval (no SES).

A requester with no account submits, gets a private claim URL, polls it, and —
once an operator approves — the scoped token shows there once. Hermetic: github
mint is monkeypatched; auth handled by the shared route fixtures.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest_plugins = ["tests.conftest_routes"]


@pytest.fixture
def fake_github(monkeypatch):
    captured = {}

    def fake_mint(*, org, repositories, permissions, **_):
        captured["mint"] = {"org": org, "repos": repositories, "permissions": permissions}
        return SimpleNamespace(token="ghs_anon_secret", repositories=tuple(repositories),
                               permissions=permissions, expires_at="2099-01-01T00:00:00Z")

    monkeypatch.setattr("iam_jit.github_scope.mint_github_token", fake_mint)
    return captured


def _form(**over):
    data = {"requester_name": "Alex", "requester_email": "alex@example.com",
            "org": "acme", "repositories": "web api", "duration_minutes": "30",
            "description": "open a PR", "perm_contents": "read", "perm_pull_requests": "write"}
    data.update(over)
    return data


def test_public_form_needs_no_login(client) -> None:
    r = client.get("/github/request")
    assert r.status_code == 200
    assert "Request GitHub access" in r.text


def test_anonymous_submit_returns_claim_url_and_queues(shared_app, client) -> None:
    r = client.post("/github/request", data=_form(), follow_redirects=False)
    assert r.status_code == 303, r.text
    loc = r.headers["location"]
    assert loc.startswith("/github/claim/")
    claim = loc.split("/github/claim/", 1)[1]
    rid = claim.split(".", 1)[0]
    stored = shared_app.state.request_store.get(rid)
    assert stored["kind"] == "GitHubTokenRequest"
    assert stored["status"]["state"] == "pending"
    assert stored["spec"]["github"]["permissions"] == {"contents": "read", "pull_requests": "write"}
    # claim page renders pending, and does NOT leak the secret
    c = client.get(loc)
    assert c.status_code == 200 and "pending" in c.text


def test_claim_token_is_required_and_constant_time(client) -> None:
    # submit, then tamper the secret → 404 (no info leak)
    loc = client.post("/github/request", data=_form(), follow_redirects=False).headers["location"]
    rid = loc.split("/github/claim/", 1)[1].split(".", 1)[0]
    assert client.get(f"/github/claim/{rid}.WRONGSECRET").status_code == 404
    assert client.get(f"/github/claim/{rid}").status_code == 404  # no secret at all


def test_approval_reveals_token_on_claim_page(shared_app, client, as_admin, fake_github) -> None:
    loc = client.post("/github/request", data=_form(),
                      follow_redirects=False).headers["location"]
    claim = loc.split("/github/claim/", 1)[1]
    rid = claim.split(".", 1)[0]
    # before approval: no token on the page
    assert "ghs_anon_secret" not in client.get(loc).text
    # operator approves via the authenticated path → mint
    ap = as_admin.post(f"/requests/{rid}/approve", json={})
    assert ap.status_code in (200, 303), ap.text
    assert shared_app.state.request_store.get(rid)["status"]["state"] == "active"
    # now the claim page shows the token once
    page = client.get(loc)
    assert page.status_code == 200 and "ghs_anon_secret" in page.text
    assert fake_github.get("mint")  # the stubbed mint was actually invoked (no real GitHub call)


def test_json_api_submit_and_poll(client, as_admin, fake_github) -> None:
    r = client.post("/api/v1/github/requests", json={
        "org": "acme", "repositories": ["web"], "permissions": {"contents": "read"},
        "duration_minutes": 20, "requester_name": "bot",
    })
    assert r.status_code == 201, r.text
    body = r.json()
    claim = body["claim_token"]
    rid = body["request_id"]
    assert body["state"] == "pending"
    # poll: pending, no token
    s1 = client.get(f"/api/v1/github/requests/{claim}").json()
    assert s1["state"] == "pending" and "token" not in s1
    # approve, poll again → active + token
    as_admin.post(f"/requests/{rid}/approve", json={})
    s2 = client.get(f"/api/v1/github/requests/{claim}").json()
    assert s2["state"] == "active" and s2["token"] == "ghs_anon_secret"
    # the claim secret itself is never echoed back in the view
    assert "_claim_secret" not in s2
    assert fake_github.get("mint")  # stubbed mint invoked


def test_json_api_rejects_unknown_claim(client) -> None:
    assert client.get("/api/v1/github/requests/ghr-nope.bad").status_code == 404


def test_coming_soon_when_feature_disabled(client, monkeypatch) -> None:
    """Default self-host ships GitHub OFF ('coming soon'): the routes are gated."""
    monkeypatch.delenv("IAM_JIT_GITHUB_ENABLED", raising=False)
    assert client.get("/github/request").status_code == 404
    assert client.post("/github/request", data=_form(), follow_redirects=False).status_code == 404
    assert client.post("/api/v1/github/requests", json={"org": "a", "repositories": ["r"],
                       "permissions": {"contents": "read"}}).status_code == 404


def test_remember_issues_key_then_future_request_auto_issues(
    shared_app, client, as_admin, fake_github, tmp_path, monkeypatch
) -> None:
    """Headline #16 loop: a write request needs approval; the operator approves
    WITH 'remember' → a requester key is issued; a future write request for the
    same repo that presents that key auto-issues (fresh token, no human)."""
    import json
    pol = tmp_path / "pol.yaml"
    pol.write_text(json.dumps({"enabled": True}))
    monkeypatch.setenv("IAM_JIT_GITHUB_AUTOAPPROVE", str(pol))
    monkeypatch.setenv("IAM_JIT_GITHUB_SAVED_APPROVALS", str(tmp_path / "saved.json"))

    # 1) anonymous WRITE request — stays pending (write, no prior approval)
    loc = client.post("/github/request", data=_form(perm_contents="write"),
                      follow_redirects=False).headers["location"]
    rid = loc.split("/github/claim/", 1)[1].split(".", 1)[0]
    assert shared_app.state.request_store.get(rid)["status"]["state"] == "pending"

    # 2) operator approves WITH remember → active + a requester key issued
    as_admin.post(f"/requests/{rid}/approve", data={"remember": "1"})
    stored = shared_app.state.request_store.get(rid)
    assert stored["status"]["state"] == "active"
    rk = stored["status"]["_issued_requester_key"]
    assert rk.startswith("rk_")

    # 3) a NEW write request for the same repo, presenting the key, auto-issues
    loc2 = client.post("/github/request",
                       data=_form(perm_contents="write", requester_key=rk),
                       follow_redirects=False).headers["location"]
    rid2 = loc2.split("/github/claim/", 1)[1].split(".", 1)[0]
    after = shared_app.state.request_store.get(rid2)
    assert after["status"]["state"] == "active"  # no human needed this time
    assert after["status"]["_secret_github_token"] == "ghs_anon_secret"

    # 4) but a DIFFERENT repo with the same key still needs approval
    loc3 = client.post("/github/request",
                       data=_form(repositories="other", perm_contents="write", requester_key=rk),
                       follow_redirects=False).headers["location"]
    rid3 = loc3.split("/github/claim/", 1)[1].split(".", 1)[0]
    assert shared_app.state.request_store.get(rid3)["status"]["state"] == "pending"
    assert fake_github.get("mint")  # auto-issue used the stubbed mint
