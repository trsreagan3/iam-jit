"""Tests for bouncer-presence verification — "off the leash" (#726 / BUILD-5).

Covers:
  * presence-gap detection fires on silence after activity
  * idle-vs-gone distinction (and that even idle eventually goes silent)
  * never-seen is distinct from off-the-leash
  * the signal is HONEST (message says "signal, not proof"; OCSF event
    carries signal_not_proof=True and is not worded as a bypass)
  * default behaviour is advisory (does NOT block issuance)
  * enforce mode (IAM_JIT_REQUIRE_BOUNCER_PRESENCE=1) refuses issuance
  * OCSF event shape
  * healthz + CLI/MCP + route surfaces
"""

from __future__ import annotations

import pytest

from iam_jit import presence as p

pytest_plugins = ["tests.conftest_routes"]


@pytest.fixture(autouse=True)
def _reset_presence() -> None:
    p.reset_for_tests()
    yield
    p.reset_for_tests()


# ---------------------------------------------------------------------------
# Core presence logic
# ---------------------------------------------------------------------------


def test_gap_fires_on_silence_after_activity():
    now = 1000.0
    p.record_check_in("sess-a", now=now)
    # Inside the TTL: present.
    v = p.evaluate_session("sess-a", ttl_seconds=300, now=now + 100)
    assert v.state is p.PresenceState.PRESENT
    assert v.is_present and not v.is_off_the_leash
    # Past the TTL after it WAS checking in: off the leash.
    v = p.evaluate_session("sess-a", ttl_seconds=300, now=now + 301)
    assert v.state is p.PresenceState.OFF_THE_LEASH
    assert v.is_off_the_leash
    assert v.last_check_in_seconds_ago == 301


def test_never_seen_is_distinct_from_off_the_leash():
    v = p.evaluate_session("nobody", ttl_seconds=300, now=1000.0)
    assert v.state is p.PresenceState.NEVER_SEEN
    assert not v.is_off_the_leash
    # Never-seen is NOT a gap — we have no evidence the bouncer was
    # ever in the path, so the "it went silent" story is wrong.
    assert "cannot confirm" in v.to_dict()["message"]


def test_idle_vs_gone_distinction():
    now = 1000.0
    # Bouncer says "I'm in the path but idle" — fresh idle beat is NOT
    # flagged.
    p.record_check_in("sess-idle", idle=True, now=now)
    v = p.evaluate_session("sess-idle", ttl_seconds=300, now=now + 100)
    assert v.state is p.PresenceState.IDLE
    assert v.is_present and not v.is_off_the_leash
    # But once even the idle beats stop past the TTL, we've lost
    # contact → off the leash (idle only suppresses while fresh).
    v = p.evaluate_session("sess-idle", ttl_seconds=300, now=now + 400)
    assert v.state is p.PresenceState.OFF_THE_LEASH


def test_fresh_check_in_clears_the_gap():
    now = 1000.0
    p.record_check_in("sess-b", now=now)
    assert p.evaluate_session("sess-b", ttl_seconds=300, now=now + 400).is_off_the_leash
    # A new check-in re-confirms presence.
    p.record_check_in("sess-b", now=now + 400)
    v = p.evaluate_session("sess-b", ttl_seconds=300, now=now + 410)
    assert v.state is p.PresenceState.PRESENT


def test_forget_session_drops_record():
    now = 1000.0
    p.record_check_in("sess-c", now=now)
    p.forget_session("sess-c")
    # Deliberate session end: a post-end silence is never-seen, not a gap.
    v = p.evaluate_session("sess-c", ttl_seconds=300, now=now + 400)
    assert v.state is p.PresenceState.NEVER_SEEN


# ---------------------------------------------------------------------------
# Honesty: signal, not proof
# ---------------------------------------------------------------------------


def test_message_is_honest_signal_not_proof():
    now = 1000.0
    p.record_check_in("sess-h", now=now)
    v = p.evaluate_session("sess-h", ttl_seconds=300, now=now + 400)
    msg = v.to_dict()["message"]
    assert "signal, not proof" in msg
    assert "verify the agent is still routed" in msg
    # NOT an accusation.
    for forbidden in ("BYPASS DETECTED", "malicious", "attack detected"):
        assert forbidden.lower() not in msg.lower()


def test_ocsf_event_shape_and_honesty():
    now = 1000.0
    p.record_check_in("sess-o", now=now)
    v = p.evaluate_session("sess-o", ttl_seconds=300, now=now + 400)
    ev = p.make_off_the_leash_event(v)
    assert ev["class_uid"] == 6003
    assert ev["category_uid"] == 6
    assert ev["type_uid"] == 600399
    assert ev["metadata"]["version"] == "1.1.0"
    assert ev["metadata"]["product"]["name"] == "ibounce"
    assert ev["metadata"]["product"]["vendor_name"] == "iam-jit"
    # High (worth attention) but explicitly a signal, not a confirmed
    # breach.
    assert ev["severity_id"] == 4
    ext = ev["unmapped"]["iam_jit"]
    assert ext["event_type"] == "BOUNCER_PRESENCE_GAP"
    assert ext["signal_not_proof"] is True
    assert ext["session_id"] == "sess-o"
    assert ext["presence_state"] == "off_the_leash"
    assert "signal, not proof" in ev["status_detail"]


# ---------------------------------------------------------------------------
# Issuance gate: default advisory vs opt-in enforce
# ---------------------------------------------------------------------------


def test_gate_default_is_advisory_does_not_block(monkeypatch):
    monkeypatch.delenv("IAM_JIT_REQUIRE_BOUNCER_PRESENCE", raising=False)
    now = 1000.0
    p.record_check_in("sess-g", now=now)
    dec = p.presence_gate("sess-g", ttl_seconds=300, now=now + 400)
    assert dec.verdict.is_off_the_leash
    # Advisory: surface the signal but ALLOW issuance.
    assert dec.allow is True
    assert dec.enforced is False


def test_gate_enforce_mode_blocks_off_the_leash(monkeypatch):
    monkeypatch.setenv("IAM_JIT_REQUIRE_BOUNCER_PRESENCE", "1")
    now = 1000.0
    p.record_check_in("sess-e", now=now)
    dec = p.presence_gate("sess-e", ttl_seconds=300, now=now + 400)
    assert dec.enforced is True
    assert dec.allow is False
    assert "refusing new role-issuance" in dec.reason


def test_gate_enforce_allows_present_session(monkeypatch):
    monkeypatch.setenv("IAM_JIT_REQUIRE_BOUNCER_PRESENCE", "1")
    now = 1000.0
    p.record_check_in("sess-p", now=now)
    dec = p.presence_gate("sess-p", ttl_seconds=300, now=now + 50)
    assert dec.allow is True


def test_gate_never_seen_not_blocked_even_in_enforce(monkeypatch):
    monkeypatch.setenv("IAM_JIT_REQUIRE_BOUNCER_PRESENCE", "1")
    # No session id / never-seen must NOT break deployments that never
    # wired up check-ins.
    assert p.presence_gate(None).allow is True
    assert p.presence_gate("never-checked-in", now=1000.0).allow is True


def test_ttl_default_is_five_minutes(monkeypatch):
    monkeypatch.delenv("IAM_JIT_BOUNCER_PRESENCE_TTL_SECONDS", raising=False)
    assert p.presence_ttl_seconds() == 300


def test_ttl_env_override_and_bad_value_falls_back(monkeypatch):
    monkeypatch.setenv("IAM_JIT_BOUNCER_PRESENCE_TTL_SECONDS", "60")
    assert p.presence_ttl_seconds() == 60
    monkeypatch.setenv("IAM_JIT_BOUNCER_PRESENCE_TTL_SECONDS", "garbage")
    assert p.presence_ttl_seconds() == 300
    monkeypatch.setenv("IAM_JIT_BOUNCER_PRESENCE_TTL_SECONDS", "-5")
    assert p.presence_ttl_seconds() == 300


# ---------------------------------------------------------------------------
# Status surface
# ---------------------------------------------------------------------------


def test_presence_status_off_the_leash_count(monkeypatch):
    monkeypatch.delenv("IAM_JIT_REQUIRE_BOUNCER_PRESENCE", raising=False)
    now = 1000.0
    p.record_check_in("present-one", now=now + 390)  # fresh-ish
    p.record_check_in("gone-one", now=now)
    st = p.presence_status(ttl_seconds=300, now=now + 400)
    assert st["tracked_sessions"] == 2
    assert st["off_the_leash_count"] == 1
    assert st["off_the_leash_detected"] is True
    assert st["enforced"] is False
    assert st["ttl_seconds"] == 300


def test_presence_status_empty():
    st = p.presence_status(ttl_seconds=300, now=1000.0)
    assert st["tracked_sessions"] == 0
    assert st["off_the_leash_detected"] is False
    assert st["sessions"] == []


# ---------------------------------------------------------------------------
# Route surfaces
# ---------------------------------------------------------------------------


def test_healthz_carries_presence_block(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert "bouncer_presence" in body
    bp = body["bouncer_presence"]
    assert bp is not None
    assert bp["off_the_leash_detected"] is False
    assert "off_the_leash_count" in bp
    # Recon-safe: no per-session detail leaks on the unauthenticated
    # liveness endpoint.
    assert "sessions" not in bp


def test_check_in_and_status_routes(make_client):
    # Admin checks in a session, then queries status.
    admin = make_client("email:admin@example.com")
    r = admin.post("/api/v1/presence/check-in", json={"session_id": "wired"})
    assert r.status_code == 200, r.text
    assert r.json()["recorded"] is True

    r = admin.get("/api/v1/presence/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tracked_sessions"] == 1
    assert any(s["session_id"] == "wired" for s in body["sessions"])


def test_check_in_requires_session_id(make_client):
    admin = make_client("email:admin@example.com")
    r = admin.post("/api/v1/presence/check-in", json={})
    assert r.status_code == 400


def test_status_requires_admin(make_client):
    dev = make_client("email:dev@example.com")
    r = dev.get("/api/v1/presence/status")
    assert r.status_code in (401, 403)


def test_mcp_presence_status_tool():
    from iam_jit import mcp_server

    p.reset_for_tests()
    out = mcp_server._bouncer_presence_status_for_mcp({})
    assert out["tracked_sessions"] == 0
    assert out["off_the_leash_detected"] is False


# ---------------------------------------------------------------------------
# End-to-end issuance gate via the approve route (moto-backed)
# ---------------------------------------------------------------------------


_E2E_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin
    roles: [admin]
  - id: email:approver@example.com
    display_name: Approver
    roles: [approver]
  - id: email:dev@example.com
    display_name: Dev
    roles: [requester]
"""
_E2E_SECRET = "test-secret-for-route-tests-aaaaaaaaa"


def _e2e_payload(*, session_id: str | None) -> dict:
    md: dict = {
        "requester": {
            "name": "Dev",
            "email": "dev@example.com",
            "principal_arn": "arn:aws:iam::060392206767:user/dev",
        }
    }
    if session_id is not None:
        md["bouncer_session_id"] = session_id
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": md,
        "spec": {
            "description": "read s3 config files in account 060392206767",
            "access_type": "read-only",
            "task_intent": {"services": ["s3"], "actions": ["read", "list"]},
            "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
            "duration": {"duration_hours": 24},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": "arn:aws:s3:::example-config",
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
    }


@pytest.fixture
def e2e_app(tmp_path, monkeypatch):
    """iam-jit app with provisioning STUBBED.

    The presence gate runs BEFORE provisioning, so these tests isolate
    the gate decision (issue vs refuse) without exercising the real AWS
    role-creation path (which has its own tests in test_provision.py).
    Provisioning is stubbed to always succeed so a non-409 approve
    deterministically reaches state=active.
    """
    from fastapi.testclient import TestClient

    from iam_jit import auth as auth_mod
    from iam_jit import provision as provision_mod
    from iam_jit.accounts_store import Account, InMemoryAccountStore
    from iam_jit.api_tokens_store import InMemoryAPITokenStore
    from iam_jit.app import create_app
    from iam_jit.store import FilesystemStore
    from iam_jit.users_store import FileUserStore

    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _E2E_SECRET)

    def _stub_provision(req, *, accounts_store, sts_client=None, iam_client_factory=None):  # noqa: SD-2 — signature must match provision.provision() for monkeypatch; extra params intentionally unused in the stub
        spec = req.get("spec") or {}
        account_id = (spec.get("accounts") or [{}])[0].get("account_id") or "060392206767"
        rid = (req.get("metadata") or {}).get("id") or "rq-test"
        return provision_mod.ProvisioningResult(
            role_arn=f"arn:aws:iam::{account_id}:role/iam-jit/iam-jit-grant-{rid}",
            role_name=f"iam-jit-grant-{rid}",
            account_id=account_id,
            assumer_principal_arn="arn:aws:iam::060392206767:user/stub",
            expires_at="2030-01-01T00:00:00Z",
            external_id=f"iam-jit-{account_id}",
            session_name=f"iam-jit-provision-{rid}",
            tags={"managed-by": "iam-jit"},
        )

    monkeypatch.setattr(provision_mod, "provision", _stub_provision)

    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_E2E_USERS_YAML)
    accounts = InMemoryAccountStore()
    accounts.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-060392206767",
            provisioning_mode="classic_iam",
            alias="dev-account",
        )
    )
    app = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
        accounts_store=accounts,
    )

    def _mk(uid):
        c = TestClient(app)
        c.cookies.set("iam_jit_session", auth_mod.sign_session(_E2E_SECRET, uid))
        return c

    yield _mk


def test_approve_advisory_gap_still_issues(e2e_app, monkeypatch):
    """Default advisory mode: an off-the-leash session still gets a role
    (we surface the signal, we don't block)."""
    monkeypatch.delenv("IAM_JIT_REQUIRE_BOUNCER_PRESENCE", raising=False)
    # Record a check-in then expire it via a tiny TTL.
    monkeypatch.setenv("IAM_JIT_BOUNCER_PRESENCE_TTL_SECONDS", "1")
    p.record_check_in("agent-99", now=1.0)  # ancient

    dev = e2e_app("email:dev@example.com")
    approver = e2e_app("email:approver@example.com")
    rid = dev.post(
        "/api/v1/requests", json=_e2e_payload(session_id="agent-99")
    ).json()["request"]["metadata"]["id"]
    resp = approver.post(f"/api/v1/requests/{rid}/approve")
    assert resp.status_code == 200, resp.text
    assert resp.json()["request"]["status"]["state"] == "active"


def test_approve_enforce_mode_refuses_off_the_leash(e2e_app, monkeypatch):
    """Enforce mode: an off-the-leash session is refused with HTTP 409 —
    the spec's 'refuse new role-issuance on heartbeat miss'."""
    monkeypatch.setenv("IAM_JIT_REQUIRE_BOUNCER_PRESENCE", "1")
    monkeypatch.setenv("IAM_JIT_BOUNCER_PRESENCE_TTL_SECONDS", "1")
    p.record_check_in("agent-killed", now=1.0)  # ancient → off the leash

    dev = e2e_app("email:dev@example.com")
    approver = e2e_app("email:approver@example.com")
    rid = dev.post(
        "/api/v1/requests", json=_e2e_payload(session_id="agent-killed")
    ).json()["request"]["metadata"]["id"]
    resp = approver.post(f"/api/v1/requests/{rid}/approve")
    assert resp.status_code == 409, resp.text
    assert "role-issuance" in resp.json()["detail"]


def test_approve_enforce_mode_allows_present_bouncer(e2e_app, monkeypatch):
    """Enforce mode but the bouncer is freshly present → issuance OK."""
    monkeypatch.setenv("IAM_JIT_REQUIRE_BOUNCER_PRESENCE", "1")
    monkeypatch.setenv("IAM_JIT_BOUNCER_PRESENCE_TTL_SECONDS", "300")
    import time as _t
    p.record_check_in("agent-live", now=_t.time())

    dev = e2e_app("email:dev@example.com")
    approver = e2e_app("email:approver@example.com")
    rid = dev.post(
        "/api/v1/requests", json=_e2e_payload(session_id="agent-live")
    ).json()["request"]["metadata"]["id"]
    resp = approver.post(f"/api/v1/requests/{rid}/approve")
    assert resp.status_code == 200, resp.text
    assert resp.json()["request"]["status"]["state"] == "active"


def test_approve_enforce_mode_no_session_id_not_blocked(e2e_app, monkeypatch):
    """Deployments that never wired up a bouncer session must not break
    even in enforce mode."""
    monkeypatch.setenv("IAM_JIT_REQUIRE_BOUNCER_PRESENCE", "1")
    dev = e2e_app("email:dev@example.com")
    approver = e2e_app("email:approver@example.com")
    rid = dev.post(
        "/api/v1/requests", json=_e2e_payload(session_id=None)
    ).json()["request"]["metadata"]["id"]
    resp = approver.post(f"/api/v1/requests/{rid}/approve")
    assert resp.status_code == 200, resp.text
