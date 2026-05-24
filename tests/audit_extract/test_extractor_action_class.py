"""Phase 2 — tests for the per-aggregate fields added to
``extract_permissions_from_events`` (``action_class`` / ``first_seen`` /
``last_seen`` / ``allow_count`` / ``deny_count``).

Per CONTRIBUTING.md state-verification: every test asserts the OBSERVABLE
state on the returned :class:`PermissionAggregate` (the new fields are
the observable state of the extractor; they ARE what downstream callers
read). The MCP wrapper test additionally verifies the new fields flow
through the dispatch site unchanged.

Per ``docs/PROFILE-GENERATION-DESIGN.md`` §6 Phase 2 acceptance:
    * action_class field per permission aggregate
    * first_seen / last_seen / allow_count / deny_count match underlying
      event data
    * backward-compat — existing extractor tests still pass (verified by
      `tests/audit_extract/test_extractor.py` running green)
    * edge cases: zero events (empty list); single event (counts=1)
"""

from __future__ import annotations

from typing import Any

from iam_jit.audit_extract import (
    extract_permissions_from_events,
)
from iam_jit.mcp_server import (
    _bounce_extract_permissions_from_audit_for_mcp,
)
from iam_jit.profile_heuristic import ActionClass


def _event(
    *,
    action: str,
    resource: str | None = None,
    account: str | None = None,
    region: str | None = None,
    verdict: str | None = None,
    time_ms: int | None = None,
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "metadata": {
            "product": {"name": "ibounce", "vendor_name": "iam-jit"},
        },
        "time": time_ms if time_ms is not None else 1737590400000,
        "api": {"operation": action, "service": {"name": action.split(":")[0]}},
    }
    if resource:
        ev["resources"] = [{"uid": resource, "name": resource}]
    if account or region:
        ev["cloud"] = {}
        if account:
            ev["cloud"]["account"] = {"uid": account}
        if region:
            ev["cloud"]["region"] = region
    if verdict is not None:
        ev["unmapped"] = {"iam_jit": {"verdict": verdict}}
    return ev


# ---------------------------------------------------------------------------
# action_class field
# ---------------------------------------------------------------------------


def test_action_class_field_present_per_aggregate() -> None:
    """Every PermissionAggregate carries an action_class field."""
    events = [
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k"),
        _event(action="s3:PutObject", resource="arn:aws:s3:::b/k"),
        _event(action="iam:CreateRole", resource="arn:aws:iam::1:role/x"),
        _event(action="s3:DeleteObject", resource="arn:aws:s3:::b/k"),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    classes = {p.action: p.action_class for p in result.permissions}
    assert classes["s3:GetObject"] == ActionClass.READ.value
    assert classes["s3:PutObject"] == ActionClass.WRITE_DATA.value
    assert classes["iam:CreateRole"] == ActionClass.ADMIN.value
    assert classes["s3:DeleteObject"] == ActionClass.DESTRUCTIVE_DATA.value


def test_action_class_emitted_in_as_dict() -> None:
    """as_dict carries action_class so the MCP wire-shape exposes it."""
    events = [_event(action="s3:GetObject", resource="arn:aws:s3:::b/k")]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    d = result.as_dict()
    assert "action_class" in d["permissions"][0]
    assert d["permissions"][0]["action_class"] == "read"


def test_action_class_uses_representative_resource_for_kbouncer() -> None:
    """K8s ``delete deployment`` escalates to DESTRUCTIVE_DATA via the
    representative-resource path in the extractor.

    The extractor's existing :func:`_event_action` requires ``service:Action``
    shape (a colon). kbouncer emits ``api.operation`` prefixed (e.g.
    ``kbouncer:delete``) — that's the wire shape preserved here.
    """
    events = [
        {
            "metadata": {"product": {"name": "kbouncer"}},
            "time": 1737590400000,
            "api": {"operation": "kbouncer:delete"},
            "resources": [{"uid": "deployment/api"}],
        },
    ]
    result = extract_permissions_from_events(events, bouncer="kbouncer")
    assert len(result.permissions) == 1
    p = result.permissions[0]
    assert p.action == "kbouncer:delete"
    assert p.action_class == ActionClass.DESTRUCTIVE_DATA.value


def test_action_class_known_adversarial_forces_admin() -> None:
    """``cloudtrail:StopLogging`` is in KNOWN_ADVERSARIAL_PATTERNS;
    classifier short-circuits to ADMIN — verify the extractor surfaces
    that classification on the aggregate."""
    events = [
        _event(action="cloudtrail:StopLogging",
               resource="arn:aws:cloudtrail:us-east-1:1:trail/main"),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    assert result.permissions[0].action_class == ActionClass.ADMIN.value


# ---------------------------------------------------------------------------
# first_seen / last_seen
# ---------------------------------------------------------------------------


def test_first_and_last_seen_match_event_timestamps() -> None:
    """first_seen = earliest event time; last_seen = latest event time.
    Both ISO-8601 UTC."""
    # Three events at well-known epochs (in ms).
    early_ms = 1737590400000   # 2025-01-23T00:00:00Z
    middle_ms = 1737676800000  # 2025-01-24T00:00:00Z
    latest_ms = 1737763200000  # 2025-01-25T00:00:00Z
    events = [
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k1",
               time_ms=middle_ms),
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k2",
               time_ms=early_ms),
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k3",
               time_ms=latest_ms),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    p = result.permissions[0]
    assert p.first_seen == "2025-01-23T00:00:00Z"
    assert p.last_seen == "2025-01-25T00:00:00Z"


def test_first_seen_last_seen_equal_for_single_event() -> None:
    events = [
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k",
               time_ms=1737590400000),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    p = result.permissions[0]
    assert p.first_seen == p.last_seen == "2025-01-23T00:00:00Z"
    assert p.count == 1


def test_missing_time_field_returns_empty_seen() -> None:
    """An event without a parseable timestamp leaves first/last_seen
    empty rather than crashing."""
    ev = _event(action="s3:GetObject", resource="arn:aws:s3:::b/k")
    del ev["time"]
    result = extract_permissions_from_events([ev], bouncer="ibounce")
    p = result.permissions[0]
    assert p.first_seen == ""
    assert p.last_seen == ""


# ---------------------------------------------------------------------------
# allow_count / deny_count
# ---------------------------------------------------------------------------


def test_allow_count_and_deny_count_count_verdicts() -> None:
    """Each event carries a verdict at unmapped.iam_jit.verdict; the
    aggregate's allow_count + deny_count match the event tally."""
    events = [
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k", verdict="allow"),
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k", verdict="allow"),
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k", verdict="deny"),
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k", verdict="ALLOW"),  # case-insensitive
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    p = result.permissions[0]
    assert p.count == 4
    assert p.allow_count == 3
    assert p.deny_count == 1


def test_events_without_verdict_dont_count_to_either() -> None:
    """Verdict-less events keep contributing to count, but allow + deny
    stay zero — caller can detect the gap via allow + deny < count."""
    events = [
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k"),
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k"),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    p = result.permissions[0]
    assert p.count == 2
    assert p.allow_count == 0
    assert p.deny_count == 0


# ---------------------------------------------------------------------------
# backward-compat — existing field shape still works
# ---------------------------------------------------------------------------


def test_backward_compat_existing_fields_present_with_old_values() -> None:
    """Old callers reading ``action`` / ``resources`` / ``count`` keep
    working — adding new fields didn't change those values."""
    events = [
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k1"),
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k2"),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    p = result.permissions[0]
    # Old contract: action / resources tuple / count
    assert p.action == "s3:GetObject"
    assert p.resources == (
        "arn:aws:s3:::b/k1",
        "arn:aws:s3:::b/k2",
    )
    assert p.count == 2

    # Old contract: dict has these keys with the same shapes
    d = p.as_dict()
    assert d["action"] == "s3:GetObject"
    assert d["resources"] == ["arn:aws:s3:::b/k1", "arn:aws:s3:::b/k2"]
    assert d["count"] == 2


def test_backward_compat_no_events_returns_empty_aggregates() -> None:
    """Empty events list → empty permissions tuple; no crash from the
    new aggregation paths."""
    result = extract_permissions_from_events([], bouncer="ibounce")
    assert result.events_analyzed == 0
    assert result.permissions == ()


def test_backward_compat_construct_aggregate_without_new_fields_works() -> None:
    """Defaults on the new fields keep
    ``PermissionAggregate(action=..., resources=..., count=...)`` calls
    compiling — important for any external caller pinning the
    three-field constructor shape."""
    from iam_jit.audit_extract import PermissionAggregate
    p = PermissionAggregate(action="s3:GetObject", resources=("*",), count=1)
    d = p.as_dict()
    # New fields present with safe defaults.
    assert d["action_class"] == "unknown"
    assert d["first_seen"] == ""
    assert d["last_seen"] == ""
    assert d["allow_count"] == 0
    assert d["deny_count"] == 0


# ---------------------------------------------------------------------------
# Single event sanity
# ---------------------------------------------------------------------------


def test_single_event_count_one_and_aggregates_match() -> None:
    """Phase 2 acceptance edge case — single event → counts=1."""
    events = [
        _event(action="iam:CreateRole",
               resource="arn:aws:iam::1:role/x",
               verdict="allow",
               time_ms=1737590400000),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    p = result.permissions[0]
    assert p.count == 1
    assert p.allow_count == 1
    assert p.deny_count == 0
    assert p.first_seen == "2025-01-23T00:00:00Z"
    assert p.last_seen == p.first_seen
    assert p.action_class == ActionClass.ADMIN.value


# ---------------------------------------------------------------------------
# MCP wire-shape — Phase 2 fields flow through bounce_extract_permissions_from_audit
# ---------------------------------------------------------------------------


def test_mcp_dispatch_emits_phase2_fields(monkeypatch) -> None:
    """State-verification: the MCP tool's structured response carries
    the Phase 2 fields end-to-end. Mock the fan-out to keep the test
    hermetic; the rest of the path is real."""
    fake_events = [
        _event(action="s3:GetObject",
               resource="arn:aws:s3:us-east-1:111122223333:bucket/k",
               account="111122223333", region="us-east-1",
               verdict="allow", time_ms=1737590400000),
        _event(action="s3:GetObject",
               resource="arn:aws:s3:us-east-1:111122223333:bucket/k2",
               account="111122223333", region="us-east-1",
               verdict="deny", time_ms=1737676800000),
    ]

    from iam_jit import audit_extract
    from iam_jit.audit_extract import extractor as extractor_mod

    def fake_fanout(**kwargs):
        return extractor_mod.extract_permissions_from_events(
            fake_events,
            bouncer="ibounce",
            time_window={"from": kwargs.get("since") or "", "to": ""},
        )

    monkeypatch.setattr(
        audit_extract, "extract_permissions_via_fanout", fake_fanout,
    )
    monkeypatch.setattr(
        extractor_mod, "extract_permissions_via_fanout", fake_fanout,
    )

    result = _bounce_extract_permissions_from_audit_for_mcp(
        {"since": "1h", "bouncer": "ibounce"},
    )
    assert result["status"] == "ok"
    perm = result["permissions"][0]
    # New Phase 2 fields are observable on the MCP response.
    assert perm["action_class"] == "read"
    assert perm["allow_count"] == 1
    assert perm["deny_count"] == 1
    assert perm["first_seen"] == "2025-01-23T00:00:00Z"
    assert perm["last_seen"] == "2025-01-24T00:00:00Z"
    # Old fields unchanged.
    assert perm["action"] == "s3:GetObject"
    assert perm["count"] == 2
