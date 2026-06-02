# ADOPT-2 / #716 — unit tests for the compliance overlay library.
"""Covers:
* mapping correctness — a known decision -> expected control refs,
* per-framework filtering of both tags and coverage,
* coverage report rollup + event counts,
* cross-protocol matching (AWS / K8s / SQL / HTTP),
* partial/empty-session honesty,
* JSON shape + round-trip,
* catalog integrity (every rule references a defined control).

Per ``docs/CONTRIBUTING.md`` state-verification: assert the observable
projection (tags, counts, coverage) matches the synthetic input.
"""

from __future__ import annotations

import json
import typing

import pytest

from iam_jit.compliance import (
    build_overlay,
    format_summary,
    tags_for_event,
)
from iam_jit.compliance.mapping import (
    CONTROLS,
    FRAMEWORK_IDS,
    FRAMEWORKS,
    MAPPING_RULES,
    PARTIAL_COVERAGE_NOTES,
    controls_for_framework,
    validate_catalog,
)


def _ev(
    action: str,
    *,
    verdict: str = "allow",
    bouncer: str = "ibounce",
    resources: typing.Sequence[str] = (),
    anomalous: bool = False,
    mfa: bool | None = None,
    namespace: str | None = None,
    database: str | None = None,
    http_method: str | None = None,
    session_id: str = "sid",
) -> dict[str, typing.Any]:
    """Build a synthetic OCSF-ish event the overlay can walk."""
    e: dict[str, typing.Any] = {"_bouncer": bouncer}
    if action:
        svc = action.split(":")[0]
        e["api"] = {"operation": action, "service": {"name": svc}}
    iam: dict[str, typing.Any] = {"agent": {"session_id": session_id}}
    if verdict:
        iam["verdict"] = verdict
    if anomalous:
        iam["anomaly_verdict"] = "anomalous"
    if mfa is not None:
        iam["mfa_present"] = mfa
    if namespace:
        iam["namespace"] = namespace
    if database:
        iam["database"] = database
    e["unmapped"] = {"iam_jit": iam}
    if resources:
        e["resources"] = [{"uid": r, "name": r} for r in resources]
    if http_method:
        e["http_request"] = {"http_method": http_method}
    return e


# ---------------------------------------------------------------------------
# Catalog integrity
# ---------------------------------------------------------------------------


def test_catalog_is_internally_consistent():
    # Every rule references a defined control; every control names a
    # registered framework; every framework has a partial-coverage note.
    validate_catalog()
    for fw in FRAMEWORK_IDS:
        assert fw in PARTIAL_COVERAGE_NOTES, fw
        assert FRAMEWORKS[fw]["version"], fw
    # Every framework has at least one mapped control.
    for fw in FRAMEWORK_IDS:
        assert controls_for_framework(fw), fw


# ---------------------------------------------------------------------------
# Mapping correctness — known decision -> expected controls
# ---------------------------------------------------------------------------


def test_priv_escalation_deny_maps_to_expected_controls():
    # A DENY of an IAM privilege-escalation action must touch:
    #  OWASP T02 (priv compromise), MITRE T1098 + T1548, NIST AC-6,
    #  SOC2 CC6.6, EU-AI-ACT Art15 — plus the always-on deny/audit set.
    e = _ev("iam:AttachRolePolicy", verdict="deny")
    tags, cats = tags_for_event(e)
    for expected in (
        "OWASP-AGENTIC-T02", "MITRE-T1098", "MITRE-T1548",
        "NIST-AC-6", "SOC2-CC6.6", "EU-AI-ACT-ART15",
    ):
        assert expected in tags, (expected, tags)
    # Deny-driven least-privilege + audit are also present.
    assert "OWASP-AGENTIC-T01" in tags
    assert "NIST-AU-2" in tags
    assert "privilege-escalation" in cats
    assert "least-privilege" in cats


def test_allow_only_does_not_emit_deny_controls():
    # An ALLOW of a benign read must NOT carry the deny-only
    # least-privilege/human-oversight tags.
    e = _ev("s3:GetObject", verdict="allow", resources=["arn:aws:s3:::b/k"])
    tags, _ = tags_for_event(e)
    # OWASP-AGENTIC-T01 + EU-AI-ACT-ART14 are deny-gated; must be absent.
    assert "OWASP-AGENTIC-T01" not in tags
    assert "EU-AI-ACT-ART14" not in tags
    # But access-enforcement + audit + sensitive-read fire on allow.
    assert "NIST-AC-3" in tags
    assert "NIST-AU-2" in tags
    assert "OWASP-AGENTIC-T06" in tags  # s3:GetObject is a sensitive read


def test_no_verdict_event_is_not_tagged():
    # A telemetry event with no verdict is not a decision; it must not
    # be tagged with the always-on "any decision" controls.
    e = _ev("s3:GetObject", verdict="")
    tags, _ = tags_for_event(e)
    assert tags == []


# ---------------------------------------------------------------------------
# Cross-protocol matching (the differentiator)
# ---------------------------------------------------------------------------


def test_sql_drop_is_destructive():
    e = _ev("postgres:DROP TABLE customers", bouncer="dbounce",
            database="orders")
    tags, cats = tags_for_event(e)
    assert "OWASP-AGENTIC-T05" in tags
    assert "MITRE-T1485" in tags
    assert "destructive-action" in cats


def test_k8s_rbac_widening_is_privilege_escalation():
    e = _ev("rbac.authorization.k8s.io:create clusterrolebinding",
            bouncer="kbounce", verdict="deny", namespace="kube-system")
    tags, cats = tags_for_event(e)
    assert "OWASP-AGENTIC-T02" in tags
    assert "MITRE-T1098" in tags
    assert "privilege-escalation" in cats


def test_http_delete_is_destructive():
    e = _ev("api:DELETE", bouncer="gbounce", http_method="DELETE")
    tags, cats = tags_for_event(e)
    assert "destructive-action" in cats
    assert "OWASP-AGENTIC-T05" in tags


def test_protocol_classification_by_bouncer():
    from iam_jit.compliance.overlay import _event_protocol
    assert _event_protocol(_ev("s3:GetObject", bouncer="ibounce")) == "aws"
    assert _event_protocol(
        _ev("x:y", bouncer="kbounce", namespace="ns")
    ) == "k8s"
    assert _event_protocol(
        _ev("x:y", bouncer="dbounce", database="d")
    ) == "sql"
    assert _event_protocol(
        _ev("x:y", bouncer="gbounce", http_method="GET")
    ) == "http"


# ---------------------------------------------------------------------------
# Anomaly + MFA signals
# ---------------------------------------------------------------------------


def test_anomalous_event_touches_monitoring_controls():
    e = _ev("ec2:RunInstances", anomalous=True)
    tags, cats = tags_for_event(e)
    assert "NIST-SI-4" in tags
    assert "SOC2-CC7.2" in tags
    assert "MITRE-T1110" in tags
    assert "anomaly-monitoring" in cats


def test_single_anomalous_event_fires_t1110_and_rationale_is_honest():
    # The T1110 trigger fires on a SINGLE anomaly-flagged event (no
    # repetition required) — even on an ALLOW. Its rationale must match
    # that trigger: it must NOT promise "repeated" attempts, since the
    # overlay tags individual flagged events and does not correlate
    # repetition. (UAT honesty fix.)
    from iam_jit.compliance.mapping import CONTROLS

    # One lone anomalous allow is enough to fire T1110.
    e = _ev("ec2:RunInstances", verdict="allow", anomalous=True)
    tags, _ = tags_for_event(e)
    assert "MITRE-T1110" in tags

    rationale = CONTROLS["MITRE-T1110"].rationale.lower()
    assert "repeated" not in rationale, rationale
    assert "single" in rationale, rationale


def test_mfa_gated_grant_touches_cc66():
    e = _ev("sts:AssumeRole", mfa=True)
    tags, cats = tags_for_event(e)
    assert "SOC2-CC6.6" in tags
    assert "mfa" in cats


# ---------------------------------------------------------------------------
# Per-framework filtering
# ---------------------------------------------------------------------------


def test_framework_filter_restricts_tags():
    e = _ev("iam:AttachRolePolicy", verdict="deny")
    owasp_tags, _ = tags_for_event(e, framework="owasp")
    assert owasp_tags  # at least one OWASP control
    assert all(CONTROLS[t].framework == "owasp" for t in owasp_tags)
    nist_tags, _ = tags_for_event(e, framework="nist")
    assert all(CONTROLS[t].framework == "nist" for t in nist_tags)


def test_framework_filter_restricts_coverage_report():
    events = [_ev("iam:AttachRolePolicy", verdict="deny")]
    res = build_overlay(session_id="s", events=events, framework="mitre")
    assert res.framework_filter == "mitre"
    assert len(res.coverage) == 1
    assert res.coverage[0].framework == "mitre"
    # Overlay tags are MITRE-only too.
    for te in res.overlay:
        assert all(t.startswith("MITRE-") for t in te.compliance_tags)


def test_unknown_framework_raises():
    with pytest.raises(ValueError):
        build_overlay(session_id="s", events=[], framework="nope")


# ---------------------------------------------------------------------------
# Coverage rollup
# ---------------------------------------------------------------------------


def test_coverage_counts_events_per_control():
    events = [
        _ev("iam:AttachRolePolicy", verdict="deny"),   # priv-esc
        _ev("iam:PutUserPolicy", verdict="deny"),       # priv-esc
        _ev("s3:GetObject", verdict="allow"),           # sensitive read
    ]
    res = build_overlay(session_id="s", events=events)
    # Find NIST coverage.
    nist = next(fc for fc in res.coverage if fc.framework == "nist")
    by_control = {c.control: c for c in nist.controls_touched}
    # AC-6 touched by all three (least-priv on deny + priv-esc + sens-read).
    assert "NIST-AC-6" in by_control
    # AU-2 (audit) touched by every decision event = 3.
    assert by_control["NIST-AU-2"].event_count == 3
    # All five frameworks present (no filter).
    assert {fc.framework for fc in res.coverage} == set(FRAMEWORK_IDS)


def test_full_owasp_catalog_coverage_reported():
    # controls_in_catalog reflects the actual catalog size, not just
    # what was touched.
    res = build_overlay(session_id="s", events=[_ev("s3:GetObject")])
    owasp = next(fc for fc in res.coverage if fc.framework == "owasp")
    assert owasp.controls_in_catalog == len(controls_for_framework("owasp"))


# ---------------------------------------------------------------------------
# Partial / empty honesty
# ---------------------------------------------------------------------------


def test_empty_session_is_partial_but_valid():
    res = build_overlay(session_id="empty", events=[])
    assert res.events_analyzed == 0
    assert res.overlay == ()
    assert res.is_partial is True
    assert any("no_events_observed" in r for r in res.partial_reasons)
    # Still emits all five frameworks with zero touched controls.
    assert len(res.coverage) == len(FRAMEWORK_IDS)
    for fc in res.coverage:
        assert fc.controls_touched_count == 0
    # Disclaimer always present.
    assert "NOT a compliance certification" in res.disclaimer


def test_bouncer_gap_note_flags_partial():
    res = build_overlay(
        session_id="s",
        events=[_ev("s3:GetObject")],
        notes=("kbounce: connection refused",),
    )
    assert res.is_partial is True
    assert any("bouncer_gaps" in r for r in res.partial_reasons)
    assert "kbounce: connection refused" in res.notes


def test_clean_session_not_partial():
    res = build_overlay(session_id="s", events=[_ev("s3:GetObject")])
    assert res.is_partial is False
    assert res.partial_reasons == ()


# ---------------------------------------------------------------------------
# JSON shape
# ---------------------------------------------------------------------------


def test_json_round_trips_and_has_expected_shape():
    res = build_overlay(
        session_id="s",
        events=[_ev("iam:AttachRolePolicy", verdict="deny")],
    )
    payload = res.as_dict()
    # Round-trips cleanly.
    reparsed = json.loads(json.dumps(payload))
    assert reparsed == payload
    # Top-level shape.
    for key in (
        "session_id", "events_analyzed", "framework_filter",
        "overlay", "coverage", "is_partial", "partial_reasons",
        "disclaimer", "notes",
    ):
        assert key in payload, key
    # Overlay entry shape.
    te = payload["overlay"][0]
    for key in (
        "action", "verdict", "protocol", "resources",
        "compliance_tags", "categories",
    ):
        assert key in te, key
    # Coverage entry shape.
    fc = payload["coverage"][0]
    for key in (
        "framework", "name", "version", "controls_touched",
        "controls_touched_count", "controls_in_catalog",
        "partial_coverage_note",
    ):
        assert key in fc, key


def test_summary_renders_versions_and_disclaimer():
    res = build_overlay(
        session_id="s",
        events=[_ev("iam:AttachRolePolicy", verdict="deny")],
    )
    out = format_summary(res)
    # Cites a framework version.
    assert "2026" in out  # OWASP Agentic Top 10 2026
    assert "Rev. 5" in out  # NIST 800-53 Rev 5
    assert "NOT a compliance certification" in out


def test_every_rule_control_is_in_catalog():
    # Defensive: no rule maps to a tag that isn't in the catalog (would
    # KeyError at projection time).
    for rule in MAPPING_RULES:
        for c in rule.controls:
            assert c in CONTROLS, (rule.rule_id, c)
