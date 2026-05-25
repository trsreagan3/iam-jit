"""#613 — per-user outstanding-request cap.

State-verification tests per docs/CONTRIBUTING.md.

Founder direction 2026-05-25: "each user shouldn't be able to have
more than 20 outstanding submissions/requests at any given time. we
don't want one agent to ddos the whole system."

These tests assert OBSERVABLE state at the HTTP layer (status code +
response body shape) AND at the helper level (count returned matches
store contents). The sabotage check (`test_sabotage_cap_is_load_bearing`)
proves the cap is wired — monkeypatching the helper to always
allow makes the at-cap rejection test pass when it should fail, so
the test correctly catches that regression too.

Per [[cross-product-agent-parity]]: both POST paths (API + web) share
one helper. Parity is asserted in
`test_parity_web_and_api_see_same_count`.

Per [[ibounce-honest-positioning]]: the 429 body is actionable —
names cap + count + recovery + currently-blocking requests.

Per [[ambient-value-prop-and-friction-framing]]: cap-fire emits an
OCSF-shaped audit event for the operator to see.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit import _outstanding_request_cap
from iam_jit._outstanding_request_cap import (
    DEFAULT_CAP,
    ENV_VAR_NAME,
    CapCheckResult,
    check_outstanding_cap,
    count_outstanding_for_user,
)
from iam_jit.users_store import User

pytest_plugins = ["tests.conftest_routes"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pending_request(
    request_id: str,
    *,
    owner: str = "email:dev@example.com",
    state: str = "pending",
) -> dict[str, Any]:
    """Build a minimal valid request dict in the given state.

    Goes straight into the store via `store.put(rid, req)`. Mirrors
    the shape `routes/requests.py:submit_request` produces post-
    init_status / post-auto-approve.
    """
    now = "2026-05-25T12:00:00Z"
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": request_id,
            "name": "seeded test request",
            "requester": {"name": "Dev", "email": "dev@example.com"},
        },
        "spec": {
            "description": "seeded by test",
            "access_type": "read-only",
            "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
            "duration": {"duration_hours": 24},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "*",
                    }
                ],
            },
            "provisioning": {"mode": "identity_center"},
        },
        "status": {
            "state": state,
            "owner": owner,
            "submitted_at": now,
            "last_updated_at": now,
            "comments": [],
            "history": [
                {"action": "submit", "by": owner, "at": now},
            ],
        },
    }


def _seed_n_outstanding(
    app: Any, n: int, owner: str = "email:dev@example.com", state: str = "pending",
) -> list[str]:
    """Seed N outstanding requests for `owner` directly into the
    underlying store. Returns the list of request IDs.

    State-verification check INSIDE the seeder: after seeding, the
    helper's count must match N. If it doesn't, the seeder is
    broken (not the cap), so we surface that here.
    """
    store = app.state.request_store
    ids: list[str] = []
    for i in range(n):
        rid = f"seeded{state}{i:04d}"
        store.put(rid, _make_pending_request(rid, owner=owner, state=state))
        ids.append(rid)
    counted = count_outstanding_for_user(owner, store)
    if state in {"pending", "provisioning"}:
        assert len(counted) == n, (
            f"seeder broken: seeded {n} {state} requests for {owner!r} "
            f"but helper counted {len(counted)}; got={counted!r}"
        )
    else:
        assert len(counted) == 0, (
            f"seeder broken: seeded {n} {state} requests for {owner!r} "
            f"(non-outstanding state) but helper counted {len(counted)}"
        )
    return ids


def _dev_user() -> User:
    return User(id="email:dev@example.com", roles=("requester",))


# ---------------------------------------------------------------------------
# 1. Fresh user
# ---------------------------------------------------------------------------


def test_user_with_zero_outstanding_can_submit_api(
    as_dev: TestClient, request_payload: dict, shared_app: Any,
) -> None:
    """State verification (#613): a user with zero outstanding requests
    submits successfully AND the store ends up with exactly one
    pending/active record owned by that user."""
    resp = as_dev.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 201, resp.text

    # Observable state: count via the helper is now 1 (pending) OR 0
    # (auto-approved → active). Either way the cap did not fire.
    counted = count_outstanding_for_user(
        "email:dev@example.com", shared_app.state.request_store,
    )
    state = resp.json()["request"]["status"]["state"]
    if state == "pending":
        assert len(counted) == 1, counted
    else:
        # active / provisioning / etc. — terminal-or-not-counted
        assert len(counted) == 0 or all(
            c["state"] in {"pending", "provisioning"} for c in counted
        )


# ---------------------------------------------------------------------------
# 2. Just under the cap
# ---------------------------------------------------------------------------


def test_user_at_default_cap_minus_one_can_submit(
    as_dev: TestClient, request_payload: dict, shared_app: Any,
) -> None:
    """Seed DEFAULT_CAP - 1 pending requests, then submit one more.
    Expected: 201 success (count crosses into cap but not OVER it)."""
    _seed_n_outstanding(shared_app, DEFAULT_CAP - 1)
    resp = as_dev.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 201, resp.text


# ---------------------------------------------------------------------------
# 3. At the cap → API 429
# ---------------------------------------------------------------------------


def test_user_at_default_cap_returns_429_api(
    as_dev: TestClient, request_payload: dict, shared_app: Any,
) -> None:
    """Seed DEFAULT_CAP pending requests, then submit one more.

    Observable state:
      - HTTP 429
      - Body carries detail + user_id + outstanding_count + cap +
        cap_source + recovery_hint + current_outstanding list
      - Retry-After header present
      - Store still has exactly DEFAULT_CAP outstanding records (no
        new record was persisted)
    """
    seeded_ids = _seed_n_outstanding(shared_app, DEFAULT_CAP)
    resp = as_dev.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 429, resp.text
    body = resp.json()["detail"]
    assert body["user_id"] == "email:dev@example.com"
    assert body["outstanding_count"] == DEFAULT_CAP
    assert body["cap"] == DEFAULT_CAP
    assert body["cap_source"] == "default"
    assert "recovery_hint" in body
    assert "wait" in body["recovery_hint"].lower()
    assert len(body["current_outstanding"]) == DEFAULT_CAP
    assert resp.headers.get("Retry-After") == "60"

    # State verification: NO new record was persisted.
    final = count_outstanding_for_user(
        "email:dev@example.com", shared_app.state.request_store,
    )
    assert len(final) == DEFAULT_CAP, (
        f"#613 regression: at-cap submission was rejected BUT the "
        f"store grew; expected {DEFAULT_CAP}, got {len(final)}"
    )
    final_ids = {c["request_id"] for c in final}
    assert final_ids == set(seeded_ids)


# ---------------------------------------------------------------------------
# 4. At the cap → web form 429
# ---------------------------------------------------------------------------


def test_user_at_default_cap_returns_form_error_web(
    as_dev: TestClient, shared_app: Any,
) -> None:
    """Web paste-form path. Observable state:
      - HTTP 429 (NOT a redirect — keeps the form intact)
      - Response body (HTML) contains the cap-exceeded marker so the
        operator-facing template can render the error banner
      - Store is unchanged
    """
    _seed_n_outstanding(shared_app, DEFAULT_CAP)
    resp = as_dev.post(
        "/requests/new/paste",
        data={
            "description": "seeded web cap test",
            "policy": '{"Version": "2012-10-17", "Statement": []}',
            "accounts": "060392206767",
            "duration_hours": 1,
            "access_type": "read-only",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 429, resp.text
    # The error message from the route mentions "outstanding_request_cap_exceeded".
    assert "outstanding_request_cap_exceeded" in resp.text

    # State verification: store unchanged.
    final = count_outstanding_for_user(
        "email:dev@example.com", shared_app.state.request_store,
    )
    assert len(final) == DEFAULT_CAP


# ---------------------------------------------------------------------------
# 5. After one completes, user can submit again
# ---------------------------------------------------------------------------


def test_user_at_cap_then_one_terminates_can_submit_again(
    as_dev: TestClient, request_payload: dict, shared_app: Any,
) -> None:
    """Seed DEFAULT_CAP pending; transition one to a terminal state;
    submit again. Expected: 201 success.

    Uses 'cancelled' as the transition because it's the cheapest
    pending→terminal path (no provisioning side effects, no
    approver required). The cap helper must NOT count cancelled
    requests.
    """
    seeded_ids = _seed_n_outstanding(shared_app, DEFAULT_CAP)

    # Mutate one record to a terminal state directly in the store
    # (mirrors the post-cancel persisted shape).
    store = shared_app.state.request_store
    victim_id = seeded_ids[0]
    req = store.get(victim_id)
    req["status"]["state"] = "cancelled"
    store.put(victim_id, req)

    # State verification: helper now counts DEFAULT_CAP - 1 outstanding.
    after = count_outstanding_for_user("email:dev@example.com", store)
    assert len(after) == DEFAULT_CAP - 1

    resp = as_dev.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 201, resp.text


# ---------------------------------------------------------------------------
# 6. Per-user override > default
# ---------------------------------------------------------------------------


def test_user_override_raises_cap_above_default(shared_app: Any) -> None:
    """Per-user `outstanding_request_cap` raises the effective cap above
    the default. Helper-level test (no HTTP) because the User dataclass
    is the seam — the file/DDB stores already pass the field through
    per the schema change."""
    user = User(
        id="email:bigboss@example.com",
        roles=("requester",),
        outstanding_request_cap=50,
    )
    _seed_n_outstanding(shared_app, 30, owner=user.id)
    result = check_outstanding_cap(user, shared_app.state.request_store)
    assert result.cap == 50
    assert result.cap_source == "user_override"
    assert result.outstanding_count == 30
    assert result.would_exceed is False


# ---------------------------------------------------------------------------
# 7. Env override > default
# ---------------------------------------------------------------------------


def test_env_override_takes_precedence_over_default(
    shared_app: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`IAM_JIT_MAX_OUTSTANDING_PER_USER=5` → user with 5 outstanding
    is at-cap; with 4, is under."""
    monkeypatch.setenv(ENV_VAR_NAME, "5")
    _seed_n_outstanding(shared_app, 5)
    user = _dev_user()  # no per-user override
    result = check_outstanding_cap(user, shared_app.state.request_store)
    assert result.cap == 5
    assert result.cap_source == "env_override"
    assert result.outstanding_count == 5
    assert result.would_exceed is True


# ---------------------------------------------------------------------------
# 8. User override > env override
# ---------------------------------------------------------------------------


def test_user_override_takes_precedence_over_env(
    shared_app: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both per-user and env are set; user wins. User cap=50, env=10,
    user has 20 outstanding → under cap → no rejection."""
    monkeypatch.setenv(ENV_VAR_NAME, "10")
    user = User(
        id="email:bigboss2@example.com",
        roles=("requester",),
        outstanding_request_cap=50,
    )
    _seed_n_outstanding(shared_app, 20, owner=user.id)
    result = check_outstanding_cap(user, shared_app.state.request_store)
    assert result.cap == 50
    assert result.cap_source == "user_override"
    assert result.would_exceed is False


# ---------------------------------------------------------------------------
# 9. Cap-fire emits audit event
# ---------------------------------------------------------------------------


def test_cap_fire_emits_audit_event(shared_app: Any) -> None:
    """When the cap fires, an `iam_jit.request_cap_exceeded`-shaped
    audit event is emitted with the expected fields.

    Uses an explicit `audit_emit` callable (the test stub) so we can
    inspect the event without touching the global audit chain."""
    captured: list[dict[str, Any]] = []

    def _stub(**kwargs: Any) -> None:
        captured.append(kwargs)

    _seed_n_outstanding(shared_app, DEFAULT_CAP)
    user = _dev_user()
    result = check_outstanding_cap(
        user, shared_app.state.request_store, audit_emit=_stub,
    )
    assert result.would_exceed is True
    assert len(captured) == 1
    ev = captured[0]
    assert ev["actor"] == user.id
    assert ev["kind"] == "request_cap_exceeded"
    assert "summary" in ev
    details = ev["details"]
    assert details["user_id"] == user.id
    assert details["outstanding_count"] == DEFAULT_CAP
    assert details["cap"] == DEFAULT_CAP
    assert details["cap_source"] == "default"
    assert details["outstanding_by_state"] == {"pending": DEFAULT_CAP}
    assert len(details["outstanding_request_ids"]) == DEFAULT_CAP


def test_cap_under_does_not_emit_audit(shared_app: Any) -> None:
    """No audit event when the cap is NOT exceeded — the event is a
    positive-signal for runaway-detection, not a per-submission log."""
    captured: list[dict[str, Any]] = []

    def _stub(**kwargs: Any) -> None:
        captured.append(kwargs)

    _seed_n_outstanding(shared_app, 5)  # well under DEFAULT_CAP
    user = _dev_user()
    check_outstanding_cap(
        user, shared_app.state.request_store, audit_emit=_stub,
    )
    assert captured == []


# ---------------------------------------------------------------------------
# 10. Audit emit failure does NOT fail the cap check
# ---------------------------------------------------------------------------


def test_audit_emit_failure_does_not_fail_cap_check(shared_app: Any) -> None:
    """If the audit sink raises, the cap check must still return
    `would_exceed=True` so the submission is still refused. The audit
    failure is logged loudly but never swallows the 429."""

    def _broken(**kwargs: Any) -> None:
        raise RuntimeError("audit sink down")

    _seed_n_outstanding(shared_app, DEFAULT_CAP)
    user = _dev_user()
    result = check_outstanding_cap(
        user, shared_app.state.request_store, audit_emit=_broken,
    )
    assert result.would_exceed is True
    assert result.outstanding_count == DEFAULT_CAP
    assert result.cap == DEFAULT_CAP


def test_audit_emit_failure_does_not_block_route_429(
    as_dev: TestClient, request_payload: dict, shared_app: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: even if the global audit.emit raises, the route
    still returns 429. Otherwise an audit outage would silently
    DISABLE the cap (the request would land OK while the audit fail
    propagates as a 500)."""
    import iam_jit.audit as _audit_mod

    def _broken_emit(**kwargs: Any) -> Any:
        raise RuntimeError("audit subsystem down")

    monkeypatch.setattr(_audit_mod, "emit", _broken_emit)
    _seed_n_outstanding(shared_app, DEFAULT_CAP)
    resp = as_dev.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 429, resp.text


# ---------------------------------------------------------------------------
# 11. Terminal states are not counted
# ---------------------------------------------------------------------------


def test_terminal_states_not_counted(shared_app: Any) -> None:
    """A mix of pending + provisioning + terminal states; only
    pending + provisioning should count toward the cap."""
    store = shared_app.state.request_store
    owner = "email:dev@example.com"

    # Seed 5 pending.
    for i in range(5):
        rid = f"mixpending{i:04d}"
        store.put(rid, _make_pending_request(rid, owner=owner, state="pending"))
    # Seed 3 provisioning.
    for i in range(3):
        rid = f"mixprov{i:04d}"
        store.put(rid, _make_pending_request(rid, owner=owner, state="provisioning"))
    # Seed terminal states — NONE of these should count.
    for terminal_state in (
        "active", "rejected", "cancelled", "expired",
        "revoked", "provisioning_failed", "needs_changes",
    ):
        rid = f"mixterm{terminal_state}"
        store.put(rid, _make_pending_request(rid, owner=owner, state=terminal_state))

    counted = count_outstanding_for_user(owner, store)
    assert len(counted) == 8, (
        f"only pending(5) + provisioning(3) = 8 should be counted; "
        f"got {len(counted)}: {counted!r}"
    )
    states_in_count = {c["state"] for c in counted}
    assert states_in_count == {"pending", "provisioning"}


def test_other_users_outstanding_do_not_count(shared_app: Any) -> None:
    """An admin / approver / other requester with many outstanding
    requests does NOT consume dev's cap. Per-user means per-user."""
    _seed_n_outstanding(shared_app, DEFAULT_CAP + 5, owner="email:other@example.com")
    counted_dev = count_outstanding_for_user(
        "email:dev@example.com", shared_app.state.request_store,
    )
    assert counted_dev == []
    counted_other = count_outstanding_for_user(
        "email:other@example.com", shared_app.state.request_store,
    )
    assert len(counted_other) == DEFAULT_CAP + 5


# ---------------------------------------------------------------------------
# 12. Parity: web and API see the same count
# ---------------------------------------------------------------------------


def test_parity_web_and_api_see_same_count(
    as_dev: TestClient, request_payload: dict, shared_app: Any,
) -> None:
    """Per [[cross-product-agent-parity]]: both POST paths share one
    helper and therefore see identical counts.

    Test shape:
      - Seed (DEFAULT_CAP - 1) outstanding.
      - Submit one via API → 201 (cap reached but not crossed).
      - Submit another via WEB form → 429 (now at cap).
      - Submit another via API → 429 (still at cap).
    """
    _seed_n_outstanding(shared_app, DEFAULT_CAP - 1)

    api_first = as_dev.post("/api/v1/requests", json=request_payload)
    assert api_first.status_code == 201, api_first.text

    web_resp = as_dev.post(
        "/requests/new/paste",
        data={
            "description": "parity test web submit",
            "policy": '{"Version": "2012-10-17", "Statement": []}',
            "accounts": "060392206767",
            "duration_hours": 1,
            "access_type": "read-only",
        },
        follow_redirects=False,
    )
    assert web_resp.status_code == 429, web_resp.text

    api_second = as_dev.post("/api/v1/requests", json=request_payload)
    assert api_second.status_code == 429, api_second.text
    api_body = api_second.json()["detail"]
    assert api_body["outstanding_count"] == DEFAULT_CAP
    assert api_body["cap"] == DEFAULT_CAP


# ---------------------------------------------------------------------------
# 13. Sabotage check — proves the cap is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_cap_is_load_bearing(
    as_dev: TestClient, request_payload: dict, shared_app: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If we monkeypatch `_check_outstanding_cap` (as seen by the route
    module) to always return `would_exceed=False`, the at-cap
    submission must SUCCEED (201) — proving the route's gate is
    actually consulting this helper. If a future refactor inlines the
    check or drops the import, this test breaks loudly.

    This is the converse of test_user_at_default_cap_returns_429_api.
    """
    from iam_jit.routes import requests as routes_requests

    def _always_pass(user: Any, store: Any, **kwargs: Any) -> CapCheckResult:
        return CapCheckResult(
            user_id=getattr(user, "id", "?"),
            outstanding_count=0,
            cap=DEFAULT_CAP,
            cap_source="default",
            would_exceed=False,
            current_outstanding=[],
        )

    monkeypatch.setattr(
        routes_requests, "_check_outstanding_cap", _always_pass,
    )
    _seed_n_outstanding(shared_app, DEFAULT_CAP)
    resp = as_dev.post("/api/v1/requests", json=request_payload)
    assert resp.status_code == 201, (
        f"sabotage check failed: with cap helper neutered the request "
        f"should succeed; got {resp.status_code}: {resp.text}"
    )


def test_sabotage_cap_is_load_bearing_web(
    as_dev: TestClient, shared_app: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same sabotage check for the web POST path."""
    from iam_jit.routes import web as routes_web

    def _always_pass(user: Any, store: Any, **kwargs: Any) -> CapCheckResult:
        return CapCheckResult(
            user_id=getattr(user, "id", "?"),
            outstanding_count=0,
            cap=DEFAULT_CAP,
            cap_source="default",
            would_exceed=False,
            current_outstanding=[],
        )

    monkeypatch.setattr(
        routes_web, "_check_outstanding_cap", _always_pass,
    )
    _seed_n_outstanding(shared_app, DEFAULT_CAP)
    resp = as_dev.post(
        "/requests/new/paste",
        data={
            "description": "sabotage web test",
            "policy": '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}',
            "accounts": "060392206767",
            "duration_hours": 1,
            "access_type": "read-only",
        },
        follow_redirects=False,
    )
    # With cap neutered: either 303 (redirect to detail page on
    # success) or 200/400-class for any UNRELATED validation issue —
    # but NOT 429 (which was the cap firing).
    assert resp.status_code != 429, (
        f"sabotage check failed: with cap helper neutered the web "
        f"submit should not return 429; got {resp.status_code}: "
        f"{resp.text[:200]}"
    )


# ---------------------------------------------------------------------------
# Bonus: invalid env values fall through
# ---------------------------------------------------------------------------


def test_garbage_env_value_falls_back_to_default(
    shared_app: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo in IAM_JIT_MAX_OUTSTANDING_PER_USER must NOT silently
    disable the cap — must fall through to the default (per
    [[ibounce-honest-positioning]] honest-degradation)."""
    monkeypatch.setenv(ENV_VAR_NAME, "not-a-number")
    _seed_n_outstanding(shared_app, DEFAULT_CAP)
    user = _dev_user()
    result = check_outstanding_cap(user, shared_app.state.request_store)
    assert result.cap == DEFAULT_CAP
    assert result.cap_source == "default"
    assert result.would_exceed is True


def test_negative_env_value_falls_back_to_default(
    shared_app: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_VAR_NAME, "-5")
    _seed_n_outstanding(shared_app, DEFAULT_CAP)
    user = _dev_user()
    result = check_outstanding_cap(user, shared_app.state.request_store)
    assert result.cap == DEFAULT_CAP
    assert result.cap_source == "default"


def test_negative_user_override_falls_back(
    shared_app: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A negative per-user cap is invalid and must fall through to env
    / default — never silently disable the cap."""
    monkeypatch.setenv(ENV_VAR_NAME, "5")
    user = User(
        id="email:badcap@example.com",
        roles=("requester",),
        outstanding_request_cap=-1,
    )
    _seed_n_outstanding(shared_app, 5, owner=user.id)
    result = check_outstanding_cap(user, shared_app.state.request_store)
    # User override invalid → env (5) applies.
    assert result.cap == 5
    assert result.cap_source == "env_override"
    assert result.would_exceed is True
