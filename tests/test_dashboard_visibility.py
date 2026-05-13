"""Dashboard visibility rules: cancelled-fades-after-24h + bottom-sort."""

from __future__ import annotations

import datetime as _dt

from iam_jit import lifecycle


def _summary(state: str, submitted_at: str, last_updated_at: str) -> dict:
    return {
        "id": f"rq-{state}-{submitted_at}",
        "state": state,
        "submitted_at": submitted_at,
        "last_updated_at": last_updated_at,
    }


def _full(state: str, submitted_at: str, last_updated_at: str) -> dict:
    return {
        "metadata": {"id": f"rq-{state}"},
        "status": {
            "state": state,
            "submitted_at": submitted_at,
            "last_updated_at": last_updated_at,
        },
    }


# ---- visibility ----


def test_active_request_always_visible() -> None:
    req = _full("active", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
    assert lifecycle.is_visible_on_dashboard(
        req, now=_dt.datetime(2030, 1, 1, tzinfo=_dt.UTC)
    )


def test_cancelled_within_24h_is_visible() -> None:
    now = _dt.datetime(2026, 5, 8, 12, 0, 0, tzinfo=_dt.UTC)
    cancelled_recent = _full(
        "cancelled",
        "2026-05-07T10:00:00Z",
        "2026-05-07T11:00:00Z",  # 25 hours? wait let me check
    )
    # 2026-05-08T12 minus 2026-05-07T11 = 25 hours → too old
    assert not lifecycle.is_visible_on_dashboard(cancelled_recent, now=now)

    cancelled_just_now = _full(
        "cancelled",
        "2026-05-08T11:00:00Z",
        "2026-05-08T11:30:00Z",  # 30 min ago → visible
    )
    assert lifecycle.is_visible_on_dashboard(cancelled_just_now, now=now)


def test_cancelled_at_exactly_24h_is_hidden() -> None:
    now = _dt.datetime(2026, 5, 8, 12, 0, 0, tzinfo=_dt.UTC)
    req = _full(
        "cancelled",
        "2026-05-07T12:00:00Z",
        "2026-05-07T12:00:00Z",  # exactly 24h ago
    )
    # >= 24h is hidden (the rule is "after 24h"; we use < 24h to keep visible).
    assert not lifecycle.is_visible_on_dashboard(req, now=now)


def test_cancelled_with_missing_timestamp_stays_visible() -> None:
    """If for some reason the timestamp is missing or unparseable, default
    to keeping it visible (better to show a stray entry than to hide
    something the user might need)."""
    req = {"metadata": {"id": "rq"}, "status": {"state": "cancelled"}}
    assert lifecycle.is_visible_on_dashboard(req)

    req_bad = _full("cancelled", "x", "not a date")
    assert lifecycle.is_visible_on_dashboard(req_bad)


def test_rejected_remains_visible_indefinitely() -> None:
    """Rejected stays visible — auditing/compliance signal."""
    now = _dt.datetime(2030, 1, 1, tzinfo=_dt.UTC)
    for state in ("rejected", "needs_changes"):
        req = _full(state, "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")
        assert lifecycle.is_visible_on_dashboard(req, now=now), state


def test_expired_fades_after_24h() -> None:
    """Expired is a faded terminal state — same TTL as cancelled/revoked."""
    now = _dt.datetime(2026, 5, 8, 12, 0, 0, tzinfo=_dt.UTC)
    fresh = _full("expired", "2026-05-08T11:00:00Z", "2026-05-08T11:30:00Z")
    assert lifecycle.is_visible_on_dashboard(fresh, now=now)
    stale = _full("expired", "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")
    assert not lifecycle.is_visible_on_dashboard(stale, now=now)


def test_revoked_fades_after_24h() -> None:
    now = _dt.datetime(2026, 5, 8, 12, 0, 0, tzinfo=_dt.UTC)
    fresh = _full("revoked", "2026-05-08T08:00:00Z", "2026-05-08T11:30:00Z")
    assert lifecycle.is_visible_on_dashboard(fresh, now=now)
    stale = _full("revoked", "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")
    assert not lifecycle.is_visible_on_dashboard(stale, now=now)


def test_active_with_future_expiry_stays_visible() -> None:
    """Active grants are visible while their grant is still valid in AWS."""
    now = _dt.datetime(2026, 5, 8, 12, 0, 0, tzinfo=_dt.UTC)
    req = _full("active", "2026-05-08T10:00:00Z", "2026-05-08T10:00:00Z")
    req["status"]["provisioned"] = {"expires_at": "2026-05-09T10:00:00Z"}
    assert lifecycle.is_visible_on_dashboard(req, now=now)


def test_active_past_expiry_fades_after_24h() -> None:
    """If the expiry sweep is late, an active grant whose expires_at has
    passed fades on the dashboard timeline — same as expired."""
    now = _dt.datetime(2026, 5, 8, 12, 0, 0, tzinfo=_dt.UTC)
    fresh_past = _full("active", "2026-05-07T10:00:00Z", "2026-05-07T10:00:00Z")
    fresh_past["status"]["provisioned"] = {"expires_at": "2026-05-08T11:00:00Z"}
    assert lifecycle.is_visible_on_dashboard(fresh_past, now=now)

    stale_past = _full("active", "2026-05-06T10:00:00Z", "2026-05-06T10:00:00Z")
    stale_past["status"]["provisioned"] = {"expires_at": "2026-05-07T10:00:00Z"}
    assert not lifecycle.is_visible_on_dashboard(stale_past, now=now)


def test_active_without_expires_at_stays_visible() -> None:
    """Active without a recorded expires_at (legacy / pre-Phase-2) just
    stays visible — no fade signal available."""
    now = _dt.datetime(2030, 1, 1, tzinfo=_dt.UTC)
    req = _full("active", "2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")
    assert lifecycle.is_visible_on_dashboard(req, now=now)


def test_visibility_works_on_summary_shape() -> None:
    """Same rule applies whether we pass a full request or a summary."""
    now = _dt.datetime(2030, 1, 1, tzinfo=_dt.UTC)
    summary = _summary(
        "cancelled",
        "2020-01-01T00:00:00Z",
        "2020-01-01T00:00:00Z",  # ancient
    )
    assert not lifecycle.is_visible_on_dashboard(summary, now=now)


# ---- sort ----


def test_sort_puts_cancelled_at_bottom() -> None:
    items = [
        _summary("cancelled", "2026-05-08T10:00:00Z", "2026-05-08T10:30:00Z"),
        _summary("active", "2026-05-08T09:00:00Z", "2026-05-08T09:00:00Z"),
        _summary("pending", "2026-05-08T11:00:00Z", "2026-05-08T11:00:00Z"),
    ]
    out = lifecycle.sort_for_dashboard(items)
    states = [r["state"] for r in out]
    # cancelled is last
    assert states[-1] == "cancelled"
    # the two non-cancelled are ordered newest-first
    assert states[0] == "pending"
    assert states[1] == "active"


def test_sort_within_each_group_newest_first() -> None:
    items = [
        _summary("cancelled", "2026-05-01T00:00:00Z", "2026-05-01T01:00:00Z"),
        _summary("cancelled", "2026-05-08T00:00:00Z", "2026-05-08T01:00:00Z"),
        _summary("pending", "2026-05-01T00:00:00Z", "2026-05-01T01:00:00Z"),
        _summary("pending", "2026-05-08T00:00:00Z", "2026-05-08T01:00:00Z"),
    ]
    out = lifecycle.sort_for_dashboard(items)
    submitted = [r["submitted_at"] for r in out]
    assert submitted == [
        "2026-05-08T00:00:00Z",
        "2026-05-01T00:00:00Z",
        "2026-05-08T00:00:00Z",
        "2026-05-01T00:00:00Z",
    ]


def test_sort_handles_full_request_shape() -> None:
    items = [
        _full("cancelled", "2026-05-08T10:00:00Z", "2026-05-08T10:30:00Z"),
        _full("active", "2026-05-08T09:00:00Z", "2026-05-08T09:00:00Z"),
    ]
    out = lifecycle.sort_for_dashboard(items)
    assert out[0]["status"]["state"] == "active"
    assert out[1]["status"]["state"] == "cancelled"


def test_sort_empty_input() -> None:
    assert lifecycle.sort_for_dashboard([]) == []


# ---- API toggle ----


import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

pytest_plugins = ["tests.conftest_routes"]


def test_api_list_default_includes_cancelled(
    as_dev: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    cancel = as_dev.post(f"/api/v1/requests/{rid}/cancel")
    assert cancel.status_code == 200
    listed = as_dev.get("/api/v1/requests").json()
    assert rid in {r["id"] for r in listed["requests"]}


def test_api_list_hide_cancelled_filters_them(
    as_dev: TestClient, request_payload: dict
) -> None:
    rid_active = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    rid_cancel = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    as_dev.post(f"/api/v1/requests/{rid_cancel}/cancel")
    listed = as_dev.get("/api/v1/requests?hide_cancelled=true").json()
    ids = {r["id"] for r in listed["requests"]}
    assert rid_active in ids
    assert rid_cancel not in ids


def test_web_home_default_shows_cancelled(
    as_dev: TestClient, request_payload: dict
) -> None:
    rid = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    as_dev.post(f"/api/v1/requests/{rid}/cancel")
    body = as_dev.get("/").text
    assert rid in body
    assert "hide cancelled" in body  # toggle link visible


def test_web_home_hide_cancelled_filters_them(
    as_dev: TestClient, request_payload: dict
) -> None:
    rid_cancel = as_dev.post("/api/v1/requests", json=request_payload).json()["request"]["metadata"]["id"]
    as_dev.post(f"/api/v1/requests/{rid_cancel}/cancel")
    body = as_dev.get("/?hide_cancelled=1").text
    assert rid_cancel not in body
    assert "show cancelled" in body  # inverted toggle link
