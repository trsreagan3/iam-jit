"""#419 / §A58 — tests for audit_extract.extractor.

Per founder Phase E spec; covers the aggregation invariants the
CLI / MCP / synthesis chain relies on.
"""

from __future__ import annotations

import json
from typing import Any

from iam_jit.audit_extract import (
    ExtractedPermissions,
    PermissionAggregate,
    extract_permissions_from_events,
)
from iam_jit.mcp_server import (
    _bounce_extract_permissions_from_audit_for_mcp,
)


def _event(
    *,
    action: str,
    resource: str | None = None,
    account: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "metadata": {
            "product": {"name": "ibounce", "vendor_name": "iam-jit"},
        },
        "time": 1737590400000,
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
    return ev


def test_extract_permissions_aggregates_by_action() -> None:
    """One permission row per unique action, regardless of how many
    events map to it."""
    events = [
        _event(action="s3:GetObject", resource="arn:aws:s3:::bucket-a/k1"),
        _event(action="s3:GetObject", resource="arn:aws:s3:::bucket-a/k2"),
        _event(action="s3:GetObject", resource="arn:aws:s3:::bucket-b/k1"),
        _event(action="iam:UpdateAssumeRolePolicy",
               resource="arn:aws:iam::111122223333:role/lambda-staging-1"),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    actions = [p.action for p in result.permissions]
    assert actions == sorted(actions), "actions must be alphabetical"
    assert "s3:GetObject" in actions
    assert "iam:UpdateAssumeRolePolicy" in actions
    s3 = next(p for p in result.permissions if p.action == "s3:GetObject")
    assert s3.count == 3, "three s3:GetObject events → count=3"
    iam_row = next(
        p for p in result.permissions if p.action == "iam:UpdateAssumeRolePolicy"
    )
    assert iam_row.count == 1


def test_extract_permissions_counts_resources() -> None:
    """Distinct resources are collected per action; ordering stable."""
    events = [
        _event(action="s3:GetObject", resource="arn:aws:s3:::z-bucket/k"),
        _event(action="s3:GetObject", resource="arn:aws:s3:::a-bucket/k"),
        _event(action="s3:GetObject", resource="arn:aws:s3:::a-bucket/k"),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    s3 = next(p for p in result.permissions if p.action == "s3:GetObject")
    # Distinct set, sorted.
    assert s3.resources == (
        "arn:aws:s3:::a-bucket/k",
        "arn:aws:s3:::z-bucket/k",
    )
    assert s3.count == 3


def test_extract_permissions_observed_scope_from_audit() -> None:
    """observed_scope.account_ids and regions come from cloud.* block
    + ARN parse fallback."""
    events = [
        _event(
            action="s3:GetObject",
            resource="arn:aws:s3:us-east-1:111122223333:bucket/key",
            account="111122223333",
            region="us-east-1",
        ),
        _event(
            action="ec2:DescribeInstances",
            resource="arn:aws:ec2:us-east-1:111122223333:instance/i-abc",
            account="111122223333",
            region="us-east-1",
        ),
        # Different region — should appear in observed_scope.regions.
        _event(
            action="kms:Decrypt",
            resource="arn:aws:kms:us-west-2:111122223333:key/abcd",
            account="111122223333",
            region="us-west-2",
        ),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    assert result.observed_scope["account_ids"] == ["111122223333"]
    assert result.observed_scope["regions"] == ["us-east-1", "us-west-2"]


def test_extract_permissions_observed_scope_arn_fallback() -> None:
    """When no cloud.* block, parse account_id + region from ARN."""
    events = [
        _event(
            action="s3:GetObject",
            resource="arn:aws:s3:us-east-1:111122223333:bucket/k",
        ),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    assert result.observed_scope["account_ids"] == ["111122223333"]
    assert result.observed_scope["regions"] == ["us-east-1"]


def test_extract_permissions_json_output_schema() -> None:
    """as_dict() emits the contract shape the agent + CLI consumes."""
    events = [_event(action="s3:GetObject", resource="arn:aws:s3:::b/k",
                     account="111122223333", region="us-east-1")]
    result = extract_permissions_from_events(
        events,
        bouncer="ibounce",
        time_window={"from": "2026-05-23T13:00:00Z",
                     "to": "2026-05-23T14:00:00Z"},
    )
    d = result.as_dict()
    assert set(d.keys()) == {
        "time_window", "bouncer", "events_analyzed", "permissions",
        "observed_scope", "notes",
    }
    assert d["bouncer"] == "ibounce"
    assert d["events_analyzed"] == 1
    assert d["time_window"]["from"] == "2026-05-23T13:00:00Z"
    assert d["permissions"][0]["action"] == "s3:GetObject"
    assert d["permissions"][0]["resources"] == ["arn:aws:s3:::b/k"]
    assert d["permissions"][0]["count"] == 1
    assert d["observed_scope"]["account_ids"] == ["111122223333"]
    assert d["observed_scope"]["regions"] == ["us-east-1"]
    # JSON-serialisable.
    assert json.loads(json.dumps(d)) == d


def test_extract_permissions_no_resource_synthesizes_star() -> None:
    """An event without a resource still contributes; '*' is the
    fallback (mirrors how the synthesis layer needs to ASK FOR a
    resource even when the bouncer log didn't carry one)."""
    events = [_event(action="sts:GetCallerIdentity")]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    p = next(p for p in result.permissions if p.action == "sts:GetCallerIdentity")
    assert p.resources == ("*",)
    assert p.count == 1


def test_extract_permissions_empty_events() -> None:
    result = extract_permissions_from_events([], bouncer="ibounce")
    assert result.events_analyzed == 0
    assert result.permissions == ()
    assert result.observed_scope == {"account_ids": [], "regions": []}


def test_extract_permissions_dropped_when_no_action() -> None:
    """Events with no api.operation / no service contribute nothing."""
    events = [
        {"metadata": {"product": {"name": "ibounce"}}, "time": 1},
        _event(action="s3:GetObject", resource="arn:aws:s3:::b/k"),
    ]
    result = extract_permissions_from_events(events, bouncer="ibounce")
    assert result.events_analyzed == 1


def test_mcp_tool_bounce_extract_permissions_from_audit_returns_full_shape(
    monkeypatch,
) -> None:
    """The MCP wrapper returns the full extraction document + status=ok
    when the underlying fan-out is mocked to return events."""
    fake_events = [
        _event(
            action="s3:GetObject",
            resource="arn:aws:s3:us-east-1:111122223333:bucket/k",
            account="111122223333", region="us-east-1",
        ),
    ]

    # Monkey-patch the fan-out to skip real HTTP.
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
    assert result["bouncer"] == "ibounce"
    assert result["events_analyzed"] == 1
    assert result["permissions"][0]["action"] == "s3:GetObject"
    assert result["observed_scope"]["account_ids"] == ["111122223333"]


def test_extract_permissions_dst_endpoint_fallback() -> None:
    """Non-AWS events (kbouncer / dbouncer / gbouncer) use
    dst_endpoint.hostname as the resource."""
    events = [{
        "metadata": {"product": {"name": "dbounce"}},
        "time": 1,
        "api": {"operation": "psql:Query"},
        "dst_endpoint": {"hostname": "prod-db.example.com"},
    }]
    result = extract_permissions_from_events(events, bouncer="dbounce")
    p = next(p for p in result.permissions if p.action == "psql:Query")
    assert p.resources == ("prod-db.example.com",)
