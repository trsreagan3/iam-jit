"""ADOPT-1 / #715 — unit tests for the CycloneDX 1.6 ABOM builder.

Covers:
* component aggregation correctness (every component type),
* valid CycloneDX 1.6 shape (required top-level + metadata fields),
* the `iam-jit:*` property namespace,
* partial-data honesty (empty session, unreachable-bouncer notes),
* JSON validity (round-trips through json),
* bom-ref uniqueness + determinism.

The integration of the fan-out + CLI path is exercised by
tests/integration; this file pins the pure projection.
"""

from __future__ import annotations

import json
import typing

import pytest

from iam_jit.abom import (
    ABOM_PROPERTY_NS,
    CYCLONEDX_SPEC_VERSION,
    build_abom,
)


def _ev(
    *,
    bouncer: str = "ibounce",
    t: int = 1737590400000,
    service: str | None = None,
    operation: str | None = None,
    resources: typing.Sequence[str] = (),
    verdict: str | None = None,
    role_arn: str | None = None,
    profile: str | None = None,
    namespace: str | None = None,
    cluster: str | None = None,
    database: str | None = None,
    host: str | None = None,
    http_method: str | None = None,
    mcp_tool: str | None = None,
    session_id: str = "sid",
) -> dict[str, typing.Any]:
    ev: dict[str, typing.Any] = {"_bouncer": bouncer, "time": t}
    api: dict[str, typing.Any] = {}
    if service:
        api["service"] = {"name": service}
    if operation:
        api["operation"] = operation
    if api:
        ev["api"] = api
    if resources:
        ev["resources"] = [{"uid": r} for r in resources]
    iam: dict[str, typing.Any] = {"agent": {"session_id": session_id}}
    if verdict:
        iam["verdict"] = verdict
    if role_arn:
        iam["role_arn"] = role_arn
    if profile:
        iam["profile"] = profile
    if namespace:
        iam["namespace"] = namespace
    if cluster:
        iam["cluster"] = cluster
    if database:
        iam["database"] = database
    if host:
        iam["host"] = host
    if mcp_tool:
        iam["mcp"] = {"tool": mcp_tool}
    ev["unmapped"] = {"iam_jit": iam}
    if host:
        ev.setdefault("dst_endpoint", {})["hostname"] = host
    if http_method:
        ev["http_request"] = {"http_method": http_method}
    return ev


def _props_map(props: list[dict[str, str]]) -> dict[str, str]:
    """Flatten a CycloneDX properties list into name->value, keeping
    the LAST value for repeated names (observed.notes repeats)."""
    return {p["name"]: p["value"] for p in props}


# ---------------------------------------------------------------------------
# CycloneDX 1.6 shape
# ---------------------------------------------------------------------------


def test_required_cyclonedx_fields_present():
    r = build_abom(session_id="s1", events=[])
    d = r.document
    assert d["bomFormat"] == "CycloneDX"
    assert d["specVersion"] == CYCLONEDX_SPEC_VERSION == "1.6"
    assert d["serialNumber"].startswith("urn:uuid:")
    assert isinstance(d["version"], int) and d["version"] >= 1
    assert "metadata" in d
    assert "timestamp" in d["metadata"]
    assert isinstance(d["components"], list)


def test_metadata_component_is_the_session_subject():
    r = build_abom(session_id="abc-123", events=[])
    meta = r.document["metadata"]
    subj = meta["component"]
    assert subj["type"] == "application"
    assert subj["name"] == "agent-session:abc-123"
    mp = _props_map(meta["properties"])
    assert mp[f"{ABOM_PROPERTY_NS}:session.id"] == "abc-123"


def test_document_is_json_serializable():
    evs = [_ev(service="s3", operation="GetObject", verdict="allow")]
    r = build_abom(session_id="s", events=evs)
    # Round-trip: must not raise + must be stable.
    s = json.dumps(r.document)
    assert json.loads(s)["specVersion"] == "1.6"


def test_property_namespace_prefixes_all_iam_jit_props():
    evs = [_ev(role_arn="arn:aws:iam::1:role/r", verdict="allow")]
    r = build_abom(session_id="s", events=evs)
    # Every metadata property under our namespace.
    for p in r.document["metadata"]["properties"]:
        assert p["name"].startswith(f"{ABOM_PROPERTY_NS}:")
    # Component properties too.
    for c in r.document["components"]:
        for p in c.get("properties", []):
            assert p["name"].startswith(f"{ABOM_PROPERTY_NS}:")


# ---------------------------------------------------------------------------
# Component aggregation
# ---------------------------------------------------------------------------


def test_all_component_types_extracted():
    evs = [
        _ev(
            service="s3",
            operation="GetObject",
            resources=["arn:aws:s3:::b/k"],
            role_arn="arn:aws:iam::1:role/r",
            profile="safe-default",
            verdict="allow",
        ),
        _ev(bouncer="kbounce", namespace="prod", cluster="eks-1", verdict="allow"),
        _ev(bouncer="dbounce", database="orders", host="pg.int", operation="SELECT"),
        _ev(bouncer="gbounce", host="api.stripe.com", http_method="POST"),
        _ev(mcp_tool="iam_jit_request_role"),
    ]
    r = build_abom(session_id="s", events=evs)
    kinds = {
        p["value"]
        for c in r.document["components"]
        for p in c["properties"]
        if p["name"] == f"{ABOM_PROPERTY_NS}:component.kind"
    }
    assert kinds == {
        "iam_role",
        "iam_profile",
        "aws_service",
        "aws_resource",
        "k8s_namespace",
        "database",
        "http_endpoint",
        "mcp_tool",
    }


def test_component_types_use_cyclonedx_semantics():
    evs = [
        _ev(service="s3", operation="GetObject", resources=["arn:aws:s3:::b/k"],
            role_arn="arn:aws:iam::1:role/r"),
        _ev(bouncer="gbounce", host="api.stripe.com"),
        _ev(mcp_tool="t"),
    ]
    r = build_abom(session_id="s", events=evs)
    by_kind = {}
    for c in r.document["components"]:
        kind = _props_map(c["properties"])[f"{ABOM_PROPERTY_NS}:component.kind"]
        by_kind[kind] = c["type"]
    # Credentials/config/resources => data; things the agent calls => service.
    assert by_kind["iam_role"] == "data"
    assert by_kind["aws_resource"] == "data"
    assert by_kind["aws_service"] == "service"
    assert by_kind["http_endpoint"] == "service"
    assert by_kind["mcp_tool"] == "service"


def test_repeated_component_aggregates_counts_and_verdicts():
    evs = [
        _ev(service="s3", operation="GetObject", verdict="allow"),
        _ev(service="s3", operation="PutObject", verdict="deny"),
        _ev(service="s3", operation="GetObject", verdict="allow"),
    ]
    r = build_abom(session_id="s", events=evs)
    svc = [
        c for c in r.document["components"]
        if c["name"] == "s3"
        and _props_map(c["properties"])[f"{ABOM_PROPERTY_NS}:component.kind"]
        == "aws_service"
    ]
    assert len(svc) == 1  # one aggregated component, not three
    mp = _props_map(svc[0]["properties"])
    assert mp[f"{ABOM_PROPERTY_NS}:observed.event_count"] == "3"
    assert mp[f"{ABOM_PROPERTY_NS}:observed.allow_count"] == "2"
    assert mp[f"{ABOM_PROPERTY_NS}:observed.deny_count"] == "1"
    actions = mp[f"{ABOM_PROPERTY_NS}:observed.actions"]
    assert "s3:GetObject" in actions and "s3:PutObject" in actions


def test_only_arn_resources_become_aws_resource_components():
    # A bare hostname resource should NOT create an aws_resource.
    evs = [_ev(service="ec2", operation="X", resources=["not-an-arn"])]
    r = build_abom(session_id="s", events=evs)
    res = [
        c for c in r.document["components"]
        if _props_map(c["properties"])[f"{ABOM_PROPERTY_NS}:component.kind"]
        == "aws_resource"
    ]
    assert res == []


def test_db_host_does_not_double_count_as_http_endpoint():
    evs = [_ev(bouncer="dbounce", database="orders", host="pg.int")]
    r = build_abom(session_id="s", events=evs)
    kinds = [
        _props_map(c["properties"])[f"{ABOM_PROPERTY_NS}:component.kind"]
        for c in r.document["components"]
    ]
    assert "database" in kinds
    assert "http_endpoint" not in kinds


def test_bom_refs_unique_and_deterministic():
    evs = [
        _ev(service="s3", operation="GetObject", resources=["arn:aws:s3:::b/k"]),
        _ev(bouncer="gbounce", host="api.stripe.com"),
    ]
    r1 = build_abom(session_id="s", events=evs, generated_at="2026-01-01T00:00:00Z")
    r2 = build_abom(session_id="s", events=evs, generated_at="2026-01-01T00:00:00Z")
    refs1 = [c["bom-ref"] for c in r1.document["components"]]
    assert len(refs1) == len(set(refs1))  # unique
    refs2 = [c["bom-ref"] for c in r2.document["components"]]
    assert refs1 == refs2  # deterministic across runs


# ---------------------------------------------------------------------------
# Partial-data honesty
# ---------------------------------------------------------------------------


def test_empty_session_is_valid_partial_abom():
    r = build_abom(session_id="empty", events=[])
    assert r.component_count == 0
    assert r.events_analyzed == 0
    assert r.is_partial is True
    assert any("no_events_observed" in reason for reason in r.partial_reasons)
    mp = _props_map(r.document["metadata"]["properties"])
    assert mp[f"{ABOM_PROPERTY_NS}:observed.complete"] == "false"
    # Still a valid, serializable CycloneDX doc.
    json.dumps(r.document)


def test_unreachable_bouncer_note_marks_partial():
    evs = [_ev(service="s3", operation="GetObject", verdict="allow")]
    r = build_abom(
        session_id="s",
        events=evs,
        notes=("kbounce: connection refused",),
    )
    assert r.is_partial is True
    assert any("bouncer_gaps" in reason for reason in r.partial_reasons)
    mp_pairs = [
        p for p in r.document["metadata"]["properties"]
        if p["name"] == f"{ABOM_PROPERTY_NS}:observed.notes"
    ]
    assert any("kbounce" in p["value"] for p in mp_pairs)


def test_complete_session_not_partial():
    evs = [_ev(service="s3", operation="GetObject", verdict="allow")]
    r = build_abom(session_id="s", events=evs)
    assert r.is_partial is False
    mp = _props_map(r.document["metadata"]["properties"])
    assert mp[f"{ABOM_PROPERTY_NS}:observed.complete"] == "true"


def test_disclaimer_always_present():
    # Honesty: never imply completeness, even on a "complete" doc.
    for evs in ([], [_ev(service="s3", operation="X", verdict="allow")]):
        r = build_abom(session_id="s", events=evs)
        mp = _props_map(r.document["metadata"]["properties"])
        disc = mp[f"{ABOM_PROPERTY_NS}:observed.disclaimer"]
        assert "observed" in disc.lower()
        assert "not a proof" in disc.lower()


def test_observed_window_reflects_event_times():
    evs = [
        _ev(t=1737590400000, service="s3", operation="A", verdict="allow"),
        _ev(t=1737590500000, service="s3", operation="B", verdict="allow"),
    ]
    r = build_abom(
        session_id="s",
        events=evs,
        requested_window={"from": "1h", "to": ""},
    )
    mp = _props_map(r.document["metadata"]["properties"])
    assert mp[f"{ABOM_PROPERTY_NS}:requested.window.from"] == "1h"
    assert mp[f"{ABOM_PROPERTY_NS}:observed.window.from"] == "2025-01-23T00:00:00Z"
    assert mp[f"{ABOM_PROPERTY_NS}:observed.window.to"] == "2025-01-23T00:01:40Z"


def test_non_dict_events_are_skipped_not_crashed():
    evs = [None, "garbage", 42, _ev(service="s3", operation="X", verdict="allow")]
    r = build_abom(session_id="s", events=evs)  # type: ignore[list-item]
    assert r.events_analyzed == 1


def test_session_id_in_metadata():
    r = build_abom(session_id="my-sid", events=[])
    mp = _props_map(r.document["metadata"]["properties"])
    assert mp[f"{ABOM_PROPERTY_NS}:session.id"] == "my-sid"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
