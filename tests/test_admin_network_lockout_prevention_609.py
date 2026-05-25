"""#609 CRIT — /admin/network CIDR-add must not silently lock out admin.

UAT-Admin-Web 2026-05-25 (Gap UAT-WEB-ADMIN-02): admin visits
`/admin/network`, adds CIDR `10.0.0.0/8` (excludes 127.0.0.1). Their
source IP is immediately denied on every route including the removal
endpoint. Only recovery = server restart.

Per [[ibounce-honest-positioning]] + [[ambient-value-prop-and-friction-framing]]
the form-POST handler must pre-validate that the caller's source IP
will remain covered by the resulting allowlist, and refuse the change
unless the operator explicitly opts in to the lockout risk via the
`confirm_lockout` form field.

State-verification per CONTRIBUTING.md: every test asserts both the
response shape AND the observable allowlist state (mutated vs not).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


pytest_plugins = ["tests.conftest_routes"]


def _list_allowlist() -> list[str]:
    """Read the CURRENT observable allowlist state. State-verification
    helper per CONTRIBUTING.md — tests assert on this, not on the route
    return value alone."""
    from iam_jit import cidr_store

    return [e.cidr for e in cidr_store.get_default_store().list()]


# ---------------------------------------------------------------------------
# 1. POST CIDR excluding caller WITHOUT confirm_lockout → form-level
#    error + allowlist NOT mutated.
# ---------------------------------------------------------------------------


def test_post_cidr_excluding_caller_returns_warning_not_apply(
    make_client,
) -> None:
    # TestClient default client host is 127.0.0.1 — proposing
    # 10.0.0.0/8 alone would exclude it.
    admin = make_client(
        "email:admin@example.com", client=("127.0.0.1", 50000)
    )

    # Pre-state: allowlist is empty.
    assert _list_allowlist() == []

    resp = admin.post(
        "/admin/network/cidrs",
        data={"cidr": "10.0.0.0/8", "note": "datacenter"},
        follow_redirects=False,
    )

    # 1. Reported status: the page re-renders with a 400 + lockout
    #    warning rather than a 303 redirect-to-success.
    assert resp.status_code == 400, (
        f"expected 400 lockout warning, got {resp.status_code}: "
        f"{resp.text[:300]}"
    )
    assert "would_lock_you_out" in resp.text or "lock YOU out" in resp.text, (
        f"response body must surface the lockout warning; got: "
        f"{resp.text[:500]}"
    )

    # 2. Observable state: the allowlist is STILL empty — the lockout
    #    pre-check refused to mutate. This is the load-bearing assertion
    #    per CONTRIBUTING.md state-verification convention.
    assert _list_allowlist() == [], (
        "lockout pre-check claimed to block but allowlist was mutated "
        "anyway — this is the #609 shape (silent footgun)."
    )


# ---------------------------------------------------------------------------
# 2. POST same CIDR WITH confirm_lockout → succeeds (operator opted in).
# ---------------------------------------------------------------------------


def test_post_cidr_excluding_caller_with_confirm_proceeds(
    make_client,
) -> None:
    admin = make_client(
        "email:admin@example.com", client=("127.0.0.1", 50000)
    )

    assert _list_allowlist() == []

    resp = admin.post(
        "/admin/network/cidrs",
        data={
            "cidr": "10.0.0.0/8",
            "note": "datacenter",
            "confirm_lockout": "on",
        },
        follow_redirects=False,
    )

    # Reported status: 303 redirect back to /admin/network on success.
    assert resp.status_code == 303, (
        f"expected 303 redirect on confirmed apply, got {resp.status_code}: "
        f"{resp.text[:200]}"
    )

    # Observable state: the CIDR IS now in the allowlist — operator
    # explicitly opted in to the lockout risk.
    assert "10.0.0.0/8" in _list_allowlist(), (
        "operator confirmed lockout but CIDR was not persisted"
    )


# ---------------------------------------------------------------------------
# 3. POST CIDR INCLUDING caller → succeeds with no confirmation.
# ---------------------------------------------------------------------------


def test_post_cidr_including_caller_proceeds_normally(make_client) -> None:
    admin = make_client(
        "email:admin@example.com", client=("127.0.0.1", 50000)
    )

    assert _list_allowlist() == []

    resp = admin.post(
        "/admin/network/cidrs",
        data={"cidr": "127.0.0.0/8", "note": "loopback"},
        follow_redirects=False,
    )

    assert resp.status_code == 303, (
        f"expected 303 redirect — caller is covered so no confirmation "
        f"needed; got {resp.status_code}: {resp.text[:200]}"
    )

    # Observable state: applied, no confirmation prompted.
    assert "127.0.0.0/8" in _list_allowlist()


# ---------------------------------------------------------------------------
# 4. Multi-CIDR proposed allowlist where NONE cover caller → warn.
# ---------------------------------------------------------------------------


def test_caller_covered_by_handles_multi_cidr_proposal() -> None:
    """The coverage helper evaluates the proposal AS A WHOLE — if the
    caller is inside ANY of the proposed CIDRs, coverage is True; if
    NONE cover the caller, False. Tested at the helper level because
    the form-POST route appends one-at-a-time so a single request
    can't synthesize the multi-CIDR-none-cover case directly (existing
    coverage always carries forward).

    Helper-level coverage matters because the JSON API mirror also
    relies on this exact function for its self-preservation gate, and
    callers can pre-construct multi-entry proposals there."""
    from iam_jit.routes.web import _caller_covered_by

    # Caller 127.0.0.1 + proposed [10/8, 192.168/16] → neither covers.
    assert _caller_covered_by(
        "127.0.0.1", ["10.0.0.0/8", "192.168.0.0/16"]
    ) is False

    # Caller 127.0.0.1 + proposed [10/8, 127.0.0.0/8] → second covers.
    assert _caller_covered_by(
        "127.0.0.1", ["10.0.0.0/8", "127.0.0.0/8"]
    ) is True

    # Empty proposal — nothing covers.
    assert _caller_covered_by("127.0.0.1", []) is False

    # Unknown caller IP — fail-safe (treat as uncovered).
    assert _caller_covered_by(None, ["0.0.0.0/0"]) is False

    # Malformed CIDR in proposal — skip it, continue checking others.
    assert _caller_covered_by(
        "127.0.0.1", ["not-a-cidr", "127.0.0.0/8"]
    ) is True

    # IPv4 caller vs IPv6 CIDR alone — no match (no version cross-talk
    # raising).
    assert _caller_covered_by("127.0.0.1", ["::/0"]) is False


# ---------------------------------------------------------------------------
# 5. 403 response on locked-out request carries recovery_hint.
# ---------------------------------------------------------------------------


def test_403_response_includes_recovery_hint(
    make_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the allowlist middleware blocks a request, the 403 body
    must name the recovery procedure — restart with skip flag or edit
    the YAML — so a locked-out operator isn't stranded."""
    from iam_jit import cidr_store

    # Seed an allowlist that does NOT cover the caller's IP (203.0.113.5).
    cidr_store.get_default_store().add(
        cidr_store.CIDREntry(
            cidr="10.0.0.0/8",
            note="excludes caller",
            added_by="test",
            added_at=0,
        )
    )

    # Make a request from a source IP outside the allowlist.
    caller = make_client(
        "email:admin@example.com", client=("203.0.113.5", 50000)
    )
    resp = caller.get("/api/v1/users/me")

    assert resp.status_code == 403, (
        f"expected 403 from allowlist enforcement; got "
        f"{resp.status_code}: {resp.text[:200]}"
    )
    body = resp.json()
    assert "recovery_hint" in body, (
        f"403 body must include recovery_hint; got keys: {list(body)}"
    )
    hint = body["recovery_hint"].lower()
    assert "restart" in hint or "edit" in hint, (
        f"recovery_hint must name restart-or-edit procedure; got: "
        f"{body['recovery_hint']!r}"
    )
    # Should also still carry the diagnostic fields.
    assert body["reason"] == "ip_not_in_allowlist"
    assert body["source_ip"] == "203.0.113.5"


# ---------------------------------------------------------------------------
# 6. Sabotage check — if _caller_covered_by always returns True,
#    test 1 would falsely pass-through. This verifies the validation is
#    load-bearing, not just decorative.
# ---------------------------------------------------------------------------


def test_sabotage_check_validation_is_load_bearing(
    make_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sabotage: monkeypatch the coverage check to always return True
    (the bug shape — silently claim the caller is covered). The
    bad-CIDR POST should now succeed AND the allowlist should mutate,
    proving the real check in test 1 was the thing preventing the
    lockout. If this sabotage scenario ALSO returned 400, the prod check
    might be dead code."""
    from iam_jit.routes import web as web_mod

    monkeypatch.setattr(
        web_mod, "_caller_covered_by", lambda caller_ip, cidrs: True
    )

    admin = make_client(
        "email:admin@example.com", client=("127.0.0.1", 50000)
    )
    assert _list_allowlist() == []

    resp = admin.post(
        "/admin/network/cidrs",
        data={"cidr": "10.0.0.0/8", "note": "datacenter"},
        follow_redirects=False,
    )

    # With sabotage: the check returns True, the code thinks the
    # caller is fine, and the mutation goes through. This is the
    # WRONG behavior in prod — but seeing it confirms the validation
    # in test 1 is what prevented it there.
    assert resp.status_code == 303, (
        "sabotage: with the coverage check disabled, the form should "
        "redirect (succeed); if it 400s anyway, some OTHER code path is "
        "blocking and the real check is dead code"
    )
    assert "10.0.0.0/8" in _list_allowlist(), (
        "sabotage: with the coverage check disabled, the allowlist "
        "MUST have mutated — otherwise the prod check in test 1 isn't "
        "the thing doing the work"
    )


# ---------------------------------------------------------------------------
# 7. JSON admin endpoint mirror — same lockout protection on
#    POST /api/v1/admin/network/cidrs.
# ---------------------------------------------------------------------------


def test_json_admin_endpoint_mirrors_lockout_protection(make_client) -> None:
    """The JSON admin endpoint POST /api/v1/admin/network/cidrs has
    the same self-preservation gate. Without confirm_lockout, a
    excluding-caller CIDR must return 409 and NOT mutate state."""
    admin = make_client(
        "email:admin@example.com", client=("127.0.0.1", 50000)
    )
    assert _list_allowlist() == []

    resp = admin.post(
        "/api/v1/admin/network/cidrs",
        json={"cidr": "10.0.0.0/8", "note": "datacenter"},
    )

    assert resp.status_code == 409, (
        f"expected 409 conflict on JSON endpoint; got {resp.status_code}: "
        f"{resp.text[:300]}"
    )
    body = resp.json()
    detail = body.get("detail", {})
    assert isinstance(detail, dict)
    assert detail.get("code") == "would_lock_you_out"
    assert "caller_ip" in detail

    # Observable state: allowlist NOT mutated.
    assert _list_allowlist() == [], (
        "JSON endpoint claimed to refuse but allowlist was mutated"
    )

    # With confirm_lockout=True it proceeds.
    resp2 = admin.post(
        "/api/v1/admin/network/cidrs",
        json={
            "cidr": "10.0.0.0/8",
            "note": "datacenter",
            "confirm_lockout": True,
        },
    )
    assert resp2.status_code == 201, (
        f"expected 201 after operator confirmed lockout; got "
        f"{resp2.status_code}: {resp2.text[:300]}"
    )
    assert "10.0.0.0/8" in _list_allowlist()
