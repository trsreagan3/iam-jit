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


def _entities(doc: dict) -> list[dict]:
    """All enumerated entities: components[] + services[]. The ABOM
    splits service-ish kinds into the top-level services[] array per
    CycloneDX 1.6 (where "service" is not a legal component.type)."""
    return list(doc.get("components", [])) + list(doc.get("services", []))


def _all_kinds(doc: dict) -> set[str]:
    return {
        p["value"]
        for e in _entities(doc)
        for p in e["properties"]
        if p["name"] == f"{ABOM_PROPERTY_NS}:component.kind"
    }


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
    # Component AND service properties too.
    for e in _entities(r.document):
        for p in e.get("properties", []):
            assert p["name"].startswith(f"{ABOM_PROPERTY_NS}:")


# ---------------------------------------------------------------------------
# REAL CycloneDX 1.6 schema validation
#
# This is the test that the original PR was MISSING — the old code
# emitted component.type="service", which is NOT a legal CycloneDX 1.6
# component.type enum value, so Dependency-Track / cyclonedx-cli would
# reject the doc. We validate against the OFFICIAL CycloneDX 1.6 JSON
# schema bundled with cyclonedx-python-lib
# (cyclonedx/schema/_res/bom-1.6.SNAPSHOT.schema.json), the same lib the
# UAT agent used, so the validation is against the real spec, not a
# hand-rolled approximation.
# ---------------------------------------------------------------------------


def _official_cyclonedx_16_schema() -> dict:
    """Load the official CycloneDX 1.6 JSON schema shipped inside
    cyclonedx-python-lib. Skips the test (rather than silently passing)
    if the lib / schema is not installed."""
    import importlib.util
    import os

    jsonschema = pytest.importorskip("jsonschema")
    _ = jsonschema  # used by callers; imported here to gate the skip
    spec = importlib.util.find_spec("cyclonedx")
    if spec is None or not spec.submodule_search_locations:
        pytest.skip("cyclonedx-python-lib not installed")
    pkg_dir = spec.submodule_search_locations[0]
    schema_path = os.path.join(
        pkg_dir, "schema", "_res", "bom-1.6.SNAPSHOT.schema.json"
    )
    if not os.path.exists(schema_path):
        pytest.skip(f"bundled CycloneDX 1.6 schema not found at {schema_path}")
    with open(schema_path, encoding="utf-8") as fh:
        return json.load(fh)


def test_abom_validates_against_official_cyclonedx_16_schema():
    import jsonschema

    schema = _official_cyclonedx_16_schema()
    # Build an ABOM exercising ALL 8 kinds (5 data components + 3
    # services), so every code path that emits an entity is validated.
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
    r = build_abom(session_id="schema-check", events=evs)
    assert _all_kinds(r.document) == {
        "iam_role", "iam_profile", "aws_service", "aws_resource",
        "k8s_namespace", "database", "http_endpoint", "mcp_tool",
    }
    # Zero schema errors — this is what failed before the services[] fix.
    errors = sorted(
        jsonschema.Draft7Validator(schema).iter_errors(r.document),
        key=lambda e: list(e.absolute_path),
    )
    assert errors == [], "\n".join(
        f"{list(e.absolute_path)}: {e.message}" for e in errors
    )


def test_empty_abom_validates_against_official_cyclonedx_16_schema():
    import jsonschema

    schema = _official_cyclonedx_16_schema()
    r = build_abom(session_id="empty", events=[])
    errors = list(jsonschema.Draft7Validator(schema).iter_errors(r.document))
    assert errors == [], "\n".join(
        f"{list(e.absolute_path)}: {e.message}" for e in errors
    )


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
    # Kinds are split across components[] (data artifacts) and
    # services[] (network services the agent called) per CycloneDX 1.6.
    kinds = _all_kinds(r.document)
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


def test_service_kinds_emitted_in_services_array_not_components():
    # CycloneDX 1.6: "service" is NOT a legal component.type enum value.
    # AWS service APIs / HTTP endpoints / MCP tools the agent CALLS must
    # live in the top-level services[] array, never as components.
    evs = [
        _ev(service="s3", operation="GetObject", resources=["arn:aws:s3:::b/k"],
            role_arn="arn:aws:iam::1:role/r"),
        _ev(bouncer="gbounce", host="api.stripe.com"),
        _ev(mcp_tool="t"),
    ]
    r = build_abom(session_id="s", events=evs)
    # Every component carries a legal CycloneDX 1.6 component.type and
    # NONE is the illegal "service".
    legal_types = {
        "application", "framework", "library", "container", "platform",
        "operating-system", "device", "device-driver", "firmware",
        "file", "machine-learning-model", "data", "cryptographic-asset",
    }
    comp_kind = {}
    for c in r.document["components"]:
        assert c["type"] in legal_types
        assert c["type"] != "service"
        comp_kind[_props_map(c["properties"])[f"{ABOM_PROPERTY_NS}:component.kind"]] = (
            c["type"]
        )
    # Data artifacts stay components with type=data.
    assert comp_kind["iam_role"] == "data"
    assert comp_kind["aws_resource"] == "data"
    # Service-ish kinds are NOT components at all.
    assert "aws_service" not in comp_kind
    assert "http_endpoint" not in comp_kind
    assert "mcp_tool" not in comp_kind
    # They ARE in services[]; service entries have NO "type" key
    # (#/definitions/service has additionalProperties:false) and carry
    # the same iam-jit:* properties.
    svc_kinds = {}
    for s in r.document["services"]:
        assert "type" not in s
        assert "name" in s and "bom-ref" in s
        svc_kinds[
            _props_map(s["properties"])[f"{ABOM_PROPERTY_NS}:component.kind"]
        ] = s
    assert set(svc_kinds) == {"aws_service", "http_endpoint", "mcp_tool"}


def test_repeated_component_aggregates_counts_and_verdicts():
    evs = [
        _ev(service="s3", operation="GetObject", verdict="allow"),
        _ev(service="s3", operation="PutObject", verdict="deny"),
        _ev(service="s3", operation="GetObject", verdict="allow"),
    ]
    r = build_abom(session_id="s", events=evs)
    # aws_service lives in services[] now (CycloneDX 1.6 spec-correct).
    svc = [
        c for c in r.document.get("services", [])
        if c["name"] == "s3"
        and _props_map(c["properties"])[f"{ABOM_PROPERTY_NS}:component.kind"]
        == "aws_service"
    ]
    assert len(svc) == 1  # one aggregated service, not three
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
    kinds = _all_kinds(r.document)
    assert "database" in kinds
    assert "http_endpoint" not in kinds


def test_bom_refs_unique_and_deterministic():
    evs = [
        _ev(service="s3", operation="GetObject", resources=["arn:aws:s3:::b/k"]),
        _ev(bouncer="gbounce", host="api.stripe.com"),
    ]
    r1 = build_abom(session_id="s", events=evs, generated_at="2026-01-01T00:00:00Z")
    r2 = build_abom(session_id="s", events=evs, generated_at="2026-01-01T00:00:00Z")
    # bom-ref uniqueness is document-wide (components[] + services[]).
    refs1 = [e["bom-ref"] for e in _entities(r1.document)]
    assert len(refs1) == len(set(refs1))  # unique
    refs2 = [e["bom-ref"] for e in _entities(r2.document)]
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
