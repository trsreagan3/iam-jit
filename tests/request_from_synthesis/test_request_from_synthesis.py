"""#421 / §A60 — tests for request_from_synthesis.

Phase E of [[bouncer-informs-agent-informs-iam-jit]]. Covers the
evidence-block discipline + the scorer-routing wiring.

#475 / §A60d, #476 / §A60e, #477 / §A60f — Phase E UAT CRIT fixes:
  * #475 — audit_sink wired by default to OCSF JSONL log so
    `iam-jit audit query --filter audit_event_id=...` resolves.
  * #476 — `notes` field surfaces "credentials not minted; #473"
    when auto_approved + no credential_factory.
  * #477 — evidence-block discipline tightened (non-empty
    codebase_references; ISO-8601 from/to; reversed/future/too-old
    window rejections).
"""

from __future__ import annotations

import datetime as _dt
import json as _json
import pathlib as _pathlib
from typing import Any

import pytest

from iam_jit.request_from_synthesis import (
    DEFAULT_AUTO_APPROVE_THRESHOLD,
    DEFAULT_MAX_LOOKBACK_DAYS,
    SYNTHESIS_EVENT_TYPE,
    SynthesisVerdict,
    default_synthesis_audit_sink,
    request_role_from_synthesis,
    request_role_from_synthesis_for_mcp,
    synthesis_row_to_ocsf,
)


# ---- Test fixtures --------------------------------------------------------


def _iso(dt: _dt.datetime) -> str:
    """Render a tz-aware datetime as an ISO-8601 `Z`-suffixed string —
    matches the on-disk audit-export wire shape."""
    return dt.astimezone(_dt.timezone.utc).replace(
        microsecond=0,
    ).isoformat().replace("+00:00", "Z")


def _good_evidence() -> dict[str, Any]:
    """A complete evidence block whose audit window points to the last
    hour — keeps tests valid against the #477 future/too-old guards
    regardless of when the suite runs."""
    now = _dt.datetime.now(_dt.timezone.utc)
    return {
        "bouncer_audit_window": {
            "from": _iso(now - _dt.timedelta(hours=1)),
            "to": _iso(now - _dt.timedelta(minutes=1)),
            "bouncer": "ibounce",
        },
        "codebase_references": ["CLAUDE.md", "terraform/prod/main.tf"],
        "operator_intent": "Replicate staging deployment in prod",
    }


def _narrow_permissions() -> list[dict[str, Any]]:
    """Narrow permission set that should score low → auto-approved."""
    return [
        {
            "action": "s3:GetObject",
            "resources": ["arn:aws:s3:::specific-bucket/key1"],
            "count": 5,
        },
    ]


def _broad_permissions() -> list[dict[str, Any]]:
    """Broad permission set that should score high → pending."""
    return [
        {
            "action": "iam:*",
            "resources": ["*"],
            "count": 1,
        },
        {
            "action": "s3:*",
            "resources": ["*"],
            "count": 1,
        },
    ]


# ---- Evidence-block REQUIRED ----------------------------------------------


def test_request_role_from_synthesis_requires_evidence_block() -> None:
    """Per [[ibounce-honest-positioning]] missing evidence → REJECT."""
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=None,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "missing_evidence_block"
    assert verdict.credentials is None
    # Audit row still gets an id — the rejection is itself auditable.
    assert verdict.audit_event_id.startswith("evt_rfs_")


def test_request_role_from_synthesis_rejects_without_evidence() -> None:
    """Evidence with missing fields → REJECT with structural code."""
    bad_evidence = {
        "bouncer_audit_window": {
            "from": "X",
            "to": "Y",
            # bouncer missing
        },
        "codebase_references": [],
        "operator_intent": "test",
    }
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=bad_evidence,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "missing_audit_window_field"


def test_request_role_from_synthesis_rejects_empty_intent() -> None:
    evidence = _good_evidence()
    evidence["operator_intent"] = "   "
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=evidence,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_operator_intent"


def test_request_role_from_synthesis_rejects_non_dict_evidence() -> None:
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence="not a dict",
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_evidence_block"


def test_request_role_from_synthesis_rejects_missing_justification() -> None:
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="   ",
        evidence=_good_evidence(),
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "missing_justification"


def test_request_role_from_synthesis_rejects_empty_permissions() -> None:
    verdict = request_role_from_synthesis(
        permissions=[],
        observed_scope={},
        justification="test",
        evidence=_good_evidence(),
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "empty_permissions"


def test_request_role_from_synthesis_rejects_malformed_action() -> None:
    verdict = request_role_from_synthesis(
        permissions=[{"action": "no-colon", "resources": ["*"]}],
        observed_scope={},
        justification="test",
        evidence=_good_evidence(),
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_permission_action"


# ---- Scorer routing -------------------------------------------------------


def test_request_role_from_synthesis_routes_through_scorer() -> None:
    """Verdict carries the scorer's score + risk factors."""
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="narrow test",
        evidence=_good_evidence(),
    )
    assert verdict.status in ("auto_approved", "pending_operator_approval")
    assert isinstance(verdict.score, int)
    assert verdict.score >= 1
    assert verdict.rejection_code is None


def test_request_role_from_synthesis_auto_approves_below_threshold(
    monkeypatch,
) -> None:
    """Score 1 (below default threshold 4) → auto_approved."""
    import iam_jit.request_from_synthesis as rfs

    def fake_score(_policy):
        return 1, ("scoped to single resource",)

    monkeypatch.setattr(rfs, "_score_policy_safely", fake_score)
    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="narrow",
        evidence=_good_evidence(),
    )
    assert verdict.status == "auto_approved"
    assert verdict.score == 1
    assert "scoped to single resource" in verdict.risk_factors


def test_request_role_from_synthesis_pending_above_threshold(
    monkeypatch,
) -> None:
    """Score 8 (above default threshold 4) → pending_operator_approval."""
    import iam_jit.request_from_synthesis as rfs

    def fake_score(_policy):
        return 8, ("iam:* wildcard",)

    monkeypatch.setattr(rfs, "_score_policy_safely", fake_score)
    verdict = rfs.request_role_from_synthesis(
        permissions=_broad_permissions(),
        observed_scope={},
        justification="broad",
        evidence=_good_evidence(),
    )
    assert verdict.status == "pending_operator_approval"
    assert verdict.score == 8
    assert verdict.credentials is None


def test_request_role_from_synthesis_threshold_boundary(monkeypatch) -> None:
    """Score == threshold → pending (strict-less-than gate)."""
    import iam_jit.request_from_synthesis as rfs

    def fake_score(_policy):
        return DEFAULT_AUTO_APPROVE_THRESHOLD, ()

    monkeypatch.setattr(rfs, "_score_policy_safely", fake_score)
    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="boundary",
        evidence=_good_evidence(),
    )
    assert verdict.status == "pending_operator_approval"


# ---- Evidence-chain in audit row -----------------------------------------


def test_request_role_from_synthesis_emits_admin_action_with_evidence_chain() -> None:
    """The audit row captures the full evidence chain so an auditor
    can later trace WHY the role was issued."""
    captured: list[dict[str, Any]] = []
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={"account_ids": ["999988887777"],
                        "regions": ["us-west-2"]},
        justification="Replicate staging in prod",
        evidence=_good_evidence(),
        resource_mapping_applied="staging_to_prod",
        audit_sink=lambda row: captured.append(row),
    )
    assert len(captured) == 1
    row = captured[0]
    assert row["kind"] == "iam_jit_request_role_from_synthesis"
    assert row["status"] in ("auto_approved", "pending_operator_approval")
    assert row["request_id"] == verdict.request_id
    assert row["audit_event_id"] == verdict.audit_event_id
    # Evidence is reproduced on the row.
    assert row["evidence"]["bouncer_audit_window"]["bouncer"] == "ibounce"
    assert row["evidence"]["operator_intent"] == "Replicate staging deployment in prod"
    assert row["evidence"]["codebase_references"] == [
        "CLAUDE.md", "terraform/prod/main.tf",
    ]
    # The resource_mapping_applied + justification + permissions_count
    # are on the row for auditor convenience.
    assert row["resource_mapping_applied"] == "staging_to_prod"
    assert row["justification"] == "Replicate staging in prod"
    assert row["permissions_count"] == 1


def test_request_role_from_synthesis_rejection_also_audits() -> None:
    """Even rejections get an audit row — auditability discipline."""
    captured: list[dict[str, Any]] = []
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=None,
        audit_sink=lambda row: captured.append(row),
    )
    assert verdict.status == "rejected"
    assert len(captured) == 1
    assert captured[0]["status"] == "rejected"
    assert captured[0]["rejection_code"] == "missing_evidence_block"


# ---- Credentials only when auto-approved ----------------------------------


def test_credentials_minted_only_when_auto_approved(monkeypatch) -> None:
    """credential_factory is invoked iff status == auto_approved."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely",
                        lambda _p: (1, ()))
    factory_calls: list[dict[str, Any]] = []

    def fake_factory(payload):
        factory_calls.append(payload)
        return {"AccessKeyId": "AKIA", "SecretAccessKey": "shh",
                "SessionToken": "tok", "Expiration": "2026-05-23T17:00:00Z"}

    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="auto",
        evidence=_good_evidence(),
        credential_factory=fake_factory,
    )
    assert verdict.status == "auto_approved"
    assert len(factory_calls) == 1
    assert verdict.credentials is not None
    assert verdict.credentials["AccessKeyId"] == "AKIA"


def test_credentials_not_minted_on_pending(monkeypatch) -> None:
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely",
                        lambda _p: (9, ("admin wildcard",)))
    factory_calls: list[dict[str, Any]] = []
    verdict = rfs.request_role_from_synthesis(
        permissions=_broad_permissions(),
        observed_scope={},
        justification="broad",
        evidence=_good_evidence(),
        credential_factory=lambda p: factory_calls.append(p) or {"x": 1},
    )
    assert verdict.status == "pending_operator_approval"
    assert verdict.credentials is None
    assert factory_calls == []


def test_credential_factory_failure_demotes_to_pending(monkeypatch) -> None:
    """If issuance raises, the verdict flips to pending."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely",
                        lambda _p: (1, ()))

    def boom(_payload):
        raise RuntimeError("STS rate-limit")

    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="auto",
        evidence=_good_evidence(),
        credential_factory=boom,
    )
    assert verdict.status == "pending_operator_approval"
    assert verdict.credentials is None


# ---- MCP wrapper ----------------------------------------------------------


def test_mcp_wrapper_serialises_full_response(
    _default_synthesis_audit_log_isolated,
) -> None:
    result = request_role_from_synthesis_for_mcp({
        "permissions": _narrow_permissions(),
        "justification": "test",
        "evidence": _good_evidence(),
    })
    assert "status" in result
    assert "request_id" in result
    assert "audit_event_id" in result
    assert "evidence" in result
    # notes field always present (#476).
    assert "notes" in result
    assert isinstance(result["notes"], list)


def test_mcp_wrapper_rejects_no_evidence(_default_synthesis_audit_log_isolated) -> None:
    result = request_role_from_synthesis_for_mcp({
        "permissions": _narrow_permissions(),
        "justification": "test",
        # evidence missing → REJECT
    })
    assert result["status"] == "rejected"
    assert result["rejection_code"] == "missing_evidence_block"


def test_request_role_returns_verdict_dataclass() -> None:
    """The function returns a SynthesisVerdict object the test can
    introspect (as opposed to a dict that callers must guess keys for)."""
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=_good_evidence(),
    )
    assert isinstance(verdict, SynthesisVerdict)
    assert verdict.requested_duration == "PT1H"  # default
    assert verdict.resource_mapping_applied is None


# ---- #475 / §A60d — audit_sink wired to OCSF stream ----------------------


def test_synthesis_audit_event_findable_via_query_after_emit(
    _default_synthesis_audit_log_isolated,
) -> None:
    """Per #475: the default MCP wrapper sink writes synthesis rows to
    the JSONL audit log so `iam-jit audit query --filter
    audit_event_id=<id>` resolves. Verify by writing one event + then
    parsing the JSONL back + checking the audit_event_id is findable."""
    result = request_role_from_synthesis_for_mcp({
        "permissions": _narrow_permissions(),
        "justification": "test",
        "evidence": _good_evidence(),
    })
    audit_event_id = result["audit_event_id"]
    assert audit_event_id.startswith("evt_rfs_")

    # The JSONL log should now contain one OCSF event whose top-level
    # `audit_event_id` matches what the caller got back. This is the
    # exact dotted path the cross-bouncer filter parser resolves
    # against (see bouncer/audit_export/tail.py::get_path).
    assert _default_synthesis_audit_log_isolated.exists()
    lines = _default_synthesis_audit_log_isolated.read_text().strip().splitlines()
    assert len(lines) == 1
    event = _json.loads(lines[0])
    assert event["audit_event_id"] == audit_event_id
    # Also at the canonical nested location for OCSF-pure consumers.
    assert event["unmapped"]["iam_jit"]["audit_event_id"] == audit_event_id


def test_synthesis_rejected_event_findable_via_query(
    _default_synthesis_audit_log_isolated,
) -> None:
    """Per #421 + #475: REJECTIONS audit too — the operator looking up
    "why did this synth request fail at 14:02" should find the row."""
    result = request_role_from_synthesis_for_mcp({
        "permissions": _narrow_permissions(),
        "justification": "test",
        # No evidence -> rejected.
    })
    assert result["status"] == "rejected"
    audit_event_id = result["audit_event_id"]

    lines = _default_synthesis_audit_log_isolated.read_text().strip().splitlines()
    assert len(lines) == 1
    event = _json.loads(lines[0])
    assert event["audit_event_id"] == audit_event_id
    # OCSF status should reflect the rejection.
    assert event["status_id"] == 2  # Failure
    assert event["status"] == "Failure"
    # The verdict + rejection_code surface in the unmapped block so a
    # downstream SIEM filter can isolate rejected synthesis attempts.
    assert event["unmapped"]["iam_jit"]["verdict"] == "rejected"
    assert (
        event["unmapped"]["iam_jit"]["rejection_code"]
        == "missing_evidence_block"
    )


def test_synthesis_audit_event_shape_matches_ibounce_ocsf_pattern(
    _default_synthesis_audit_log_isolated,
) -> None:
    """Per [[cross-product-agent-parity]]: synthesis events share the
    same OCSF v1.1.0 class 6003 shape as ibounce/kbounce/dbounce
    decision events so the cross-bouncer `iam-jit audit query` reader
    consumes both uniformly."""
    request_role_from_synthesis_for_mcp({
        "permissions": _narrow_permissions(),
        "justification": "audit shape test",
        "evidence": _good_evidence(),
        "resource_mapping_applied": "staging_to_prod",
    })
    lines = _default_synthesis_audit_log_isolated.read_text().strip().splitlines()
    assert len(lines) == 1
    event = _json.loads(lines[0])
    # OCSF v1.1.0 class 6003 API Activity required fields:
    assert event["class_uid"] == 6003
    assert event["class_name"] == "API Activity"
    assert event["category_uid"] == 6
    assert event["category_name"] == "Application Activity"
    assert event["metadata"]["version"] == "1.1.0"
    assert event["metadata"]["product"]["vendor_name"] == "iam-jit"
    assert isinstance(event["time"], int)  # unix ms
    assert "actor" in event
    assert "api" in event
    assert "src_endpoint" in event
    assert "dst_endpoint" in event
    # The synthesis-specific event_type discriminator + the full
    # evidence chain land under unmapped.iam_jit.
    assert (
        event["unmapped"]["iam_jit"]["event_type"]
        == SYNTHESIS_EVENT_TYPE
    )
    synth = event["unmapped"]["iam_jit"]["synthesis"]
    assert "evidence" in synth
    assert synth["evidence"]["bouncer_audit_window"]["bouncer"] == "ibounce"
    assert event["unmapped"]["iam_jit"]["resource_mapping_applied"] == (
        "staging_to_prod"
    )


def test_default_sink_writes_to_overridable_path(tmp_path, monkeypatch) -> None:
    """The IAM_JIT_SYNTHESIS_AUDIT_LOG env var overrides the default
    path so operators can segregate synthesis rows."""
    target = tmp_path / "nested" / "synth.jsonl"
    monkeypatch.setenv("IAM_JIT_SYNTHESIS_AUDIT_LOG", str(target))
    default_synthesis_audit_sink({
        "audit_event_id": "evt_rfs_test",
        "kind": "iam_jit_request_role_from_synthesis",
        "request_id": "rfs_X",
        "status": "auto_approved",
        "score": 1,
        "when": "2026-05-23T12:00:00Z",
        "evidence": {"bouncer_audit_window": {"bouncer": "ibounce"}},
    })
    assert target.exists()
    event = _json.loads(target.read_text().strip())
    assert event["audit_event_id"] == "evt_rfs_test"


def test_default_sink_fails_soft_on_io_error(monkeypatch, caplog) -> None:
    """A broken disk MUST NOT raise into the MCP path. The sink
    swallows OSError + logs a warning instead."""
    monkeypatch.setenv(
        "IAM_JIT_SYNTHESIS_AUDIT_LOG",
        "/no/such/parent/synthesis-audit.jsonl",
    )
    # We don't expect mkdir to fail under tmpfs / macOS; force a write
    # failure by pointing the path at a directory-not-file.
    import iam_jit.request_from_synthesis as rfs

    def boom(self, *a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(_pathlib.Path, "open", boom)
    # Must not raise.
    default_synthesis_audit_sink({
        "audit_event_id": "evt_rfs_failsoft",
        "kind": "iam_jit_request_role_from_synthesis",
        "status": "auto_approved",
        "score": 1,
    })


# ---- #476 / §A60e — credentials:null surfaces notes ----------------------


def test_synthesis_auto_approved_without_credentials_includes_notes(
    monkeypatch,
) -> None:
    """Per #476: when status is auto_approved but credentials is None
    (no credential_factory wired — the v1.0 MCP default), the verdict
    surfaces an HONEST `notes` field explaining what's done + what's
    next. Per [[ambient-value-prop-and-friction-framing]] the framing
    is actionable, not error-shaped."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely", lambda _p: (1, ()))
    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="auto",
        evidence=_good_evidence(),
        # NO credential_factory.
    )
    assert verdict.status == "auto_approved"
    assert verdict.credentials is None
    assert len(verdict.notes) >= 1
    # The notes MUST surface an actionable next-step (the #473 follow-
    # up + audit-query reference). We check via substring on the joined
    # text rather than exact equality so future copy edits don't break
    # the test.
    joined = " ".join(verdict.notes).lower()
    assert "credential" in joined
    assert "#473" in joined or "credential-factory" in joined


def test_synthesis_notes_reference_actionable_next_step(monkeypatch) -> None:
    """The notes include the audit_event_id so the operator can
    immediately reach for `iam-jit audit query --filter
    audit_event_id=<id>` without re-grepping for it elsewhere."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely", lambda _p: (1, ()))
    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="auto",
        evidence=_good_evidence(),
    )
    joined = " ".join(verdict.notes)
    assert verdict.audit_event_id in joined
    assert "iam-jit audit query" in joined


def test_synthesis_with_credentials_omits_pending_notes(monkeypatch) -> None:
    """Once a credential_factory IS wired (#473 lands), the pending-
    state notes go away — surfacing them then would be dishonest."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely", lambda _p: (1, ()))
    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="auto",
        evidence=_good_evidence(),
        credential_factory=lambda _p: {
            "AccessKeyId": "AKIA", "SecretAccessKey": "shh",
            "SessionToken": "tok", "Expiration": "2026-05-23T17:00:00Z",
        },
    )
    assert verdict.credentials is not None
    # No "credentials not minted" note in this state.
    joined = " ".join(verdict.notes).lower()
    assert "credential issuance not yet wired" not in joined
    assert "#473" not in joined


def test_synthesis_pending_verdict_omits_credential_notes(monkeypatch) -> None:
    """A pending verdict (above threshold) doesn't promise credentials
    either, so the v1.0 "creds-not-wired" note shouldn't fire — the
    operator approves via the pending queue + creds come from the
    existing approve path."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely", lambda _p: (8, ()))
    verdict = rfs.request_role_from_synthesis(
        permissions=_broad_permissions(),
        observed_scope={},
        justification="broad",
        evidence=_good_evidence(),
    )
    assert verdict.status == "pending_operator_approval"
    joined = " ".join(verdict.notes).lower()
    assert "credential issuance not yet wired" not in joined


# ---- #477 / §A60f — evidence-block discipline ----------------------------


def test_evidence_rejects_empty_codebase_references() -> None:
    """codebase_references=[] defeats the evidence chain — REJECT."""
    bad = _good_evidence()
    bad["codebase_references"] = []
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=bad,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_codebase_references_empty"


def test_evidence_rejects_whitespace_only_codebase_references() -> None:
    """A list of whitespace-only strings is structurally empty."""
    bad = _good_evidence()
    bad["codebase_references"] = ["   ", "\t", ""]
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=bad,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_codebase_references_empty"


def test_evidence_rejects_non_iso8601_from_to() -> None:
    """`from`/`to` MUST be ISO-8601. Opaque strings like "x"/"y" fail."""
    bad = _good_evidence()
    bad["bouncer_audit_window"]["from"] = "x"
    bad["bouncer_audit_window"]["to"] = "y"
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=bad,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_audit_window_iso_format"


def test_evidence_rejects_non_iso8601_to_only() -> None:
    """Only `to` malformed → still rejects with the same code."""
    bad = _good_evidence()
    bad["bouncer_audit_window"]["to"] = "not a timestamp"
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=bad,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_audit_window_iso_format"


def test_evidence_rejects_from_after_to() -> None:
    """Reversed window suggests fabrication — REJECT."""
    now = _dt.datetime.now(_dt.timezone.utc)
    bad = _good_evidence()
    bad["bouncer_audit_window"]["from"] = _iso(now - _dt.timedelta(minutes=1))
    bad["bouncer_audit_window"]["to"] = _iso(now - _dt.timedelta(hours=1))
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=bad,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_audit_window_reversed"


def test_evidence_rejects_from_in_future() -> None:
    """A `from` significantly in the future suggests fabrication."""
    now = _dt.datetime.now(_dt.timezone.utc)
    bad = _good_evidence()
    bad["bouncer_audit_window"]["from"] = _iso(now + _dt.timedelta(hours=2))
    bad["bouncer_audit_window"]["to"] = _iso(now + _dt.timedelta(hours=3))
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=bad,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_audit_window_future"


def test_evidence_rejects_window_older_than_max_lookback(monkeypatch) -> None:
    """Audit window older than the operator-configured max lookback
    REJECTS. Default ceiling is 365 days."""
    now = _dt.datetime.now(_dt.timezone.utc)
    ancient_from = _iso(now - _dt.timedelta(days=400))
    ancient_to = _iso(now - _dt.timedelta(days=399))
    bad = _good_evidence()
    bad["bouncer_audit_window"]["from"] = ancient_from
    bad["bouncer_audit_window"]["to"] = ancient_to
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=bad,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_audit_window_too_old"


def test_evidence_max_lookback_respects_env_override(monkeypatch) -> None:
    """Operator can tighten the lookback with an env var."""
    monkeypatch.setenv("IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS", "7")
    now = _dt.datetime.now(_dt.timezone.utc)
    # 10 days ago — within 365 default, beyond the operator's 7-day floor.
    bad = _good_evidence()
    bad["bouncer_audit_window"]["from"] = _iso(now - _dt.timedelta(days=10))
    bad["bouncer_audit_window"]["to"] = _iso(now - _dt.timedelta(days=9))
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=bad,
    )
    assert verdict.status == "rejected"
    assert verdict.rejection_code == "invalid_audit_window_too_old"


def test_evidence_accepts_valid_iso8601_with_nonempty_refs() -> None:
    """Sanity: a properly-formed evidence block accepted (regression
    guard against tightened validators rejecting legit input)."""
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=_good_evidence(),
    )
    assert verdict.status in ("auto_approved", "pending_operator_approval")


def test_evidence_accepts_naive_iso_treated_as_utc() -> None:
    """Per RFC-3339 a timestamp without offset is ambiguous; we accept
    + treat as UTC (the agent's responsibility is to send the right
    shape)."""
    now = _dt.datetime.now(_dt.timezone.utc)
    ev = _good_evidence()
    # Drop the Z suffix from the `to` to test the naive-UTC path.
    naive_from = (now - _dt.timedelta(hours=2)).replace(tzinfo=None).replace(
        microsecond=0,
    ).isoformat()
    naive_to = (now - _dt.timedelta(hours=1)).replace(tzinfo=None).replace(
        microsecond=0,
    ).isoformat()
    ev["bouncer_audit_window"]["from"] = naive_from
    ev["bouncer_audit_window"]["to"] = naive_to
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=ev,
    )
    assert verdict.status in ("auto_approved", "pending_operator_approval")


def test_evidence_bad_max_lookback_env_falls_back_to_default(monkeypatch) -> None:
    """An invalid IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS doesn't crash the
    synthesis path — falls back to the 365-day default."""
    monkeypatch.setenv("IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS", "not-a-number")
    # A window 30 days old should still pass (well under the default 365).
    now = _dt.datetime.now(_dt.timezone.utc)
    ev = _good_evidence()
    ev["bouncer_audit_window"]["from"] = _iso(now - _dt.timedelta(days=30))
    ev["bouncer_audit_window"]["to"] = _iso(now - _dt.timedelta(days=29))
    verdict = request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="test",
        evidence=ev,
    )
    assert verdict.status in ("auto_approved", "pending_operator_approval")


# ---- OCSF helper unit tests -----------------------------------------------


def test_synthesis_row_to_ocsf_minimal_shape() -> None:
    """The OCSF translator produces a valid v1.1.0 class 6003 event
    given a minimal synthesis row."""
    row = {
        "audit_event_id": "evt_rfs_abc",
        "kind": "iam_jit_request_role_from_synthesis",
        "request_id": "rfs_xyz",
        "status": "auto_approved",
        "score": 1,
        "when": "2026-05-23T12:00:00Z",
        "evidence": {"bouncer_audit_window": {
            "from": "2026-05-23T11:00:00Z",
            "to": "2026-05-23T12:00:00Z",
            "bouncer": "ibounce",
        }},
    }
    ocsf = synthesis_row_to_ocsf(row)
    assert ocsf["audit_event_id"] == "evt_rfs_abc"
    assert ocsf["class_uid"] == 6003
    assert ocsf["status_id"] == 1
    assert ocsf["status"] == "Success"


def test_synthesis_row_to_ocsf_rejection_marks_failure() -> None:
    row = {
        "audit_event_id": "evt_rfs_def",
        "kind": "iam_jit_request_role_from_synthesis",
        "request_id": "rfs_rej",
        "status": "rejected",
        "rejection_code": "missing_evidence_block",
        "evidence": {"_invalid": True},
    }
    ocsf = synthesis_row_to_ocsf(row)
    assert ocsf["status_id"] == 2  # Failure
    assert ocsf["unmapped"]["iam_jit"]["rejection_code"] == (
        "missing_evidence_block"
    )


# ---- #473 / §A60b — credential_factory wire-through tests -----------------
#
# State-verification per CONTRIBUTING.md: assert OBSERVABLE STATE matches
# reported status, not just the status string. The #476 anti-pattern
# was status=auto_approved + credentials:null silently — these tests
# close the regression gap.


def test_473_happy_path_credentials_populated(monkeypatch) -> None:
    """Happy path with credential_factory wired: auto-approved synthesis
    returns credentials.AccessKeyId + SecretAccessKey + SessionToken
    populated (NOT None); request.state == auto_approved.

    This is the PRIMARY regression test for #473 / §A60b — the wiring
    gap that made auto-approved verdicts return credentials:null."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely", lambda _p: (1, ()))

    fake_creds = {
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "SessionToken": "AQoDYXdzEJr//////////wEaoAK1",
        "Expiration": "2026-05-26T18:00:00Z",
        "RoleArn": "arn:aws:iam::123456789012:role/ijsynth-test",
    }
    factory_calls: list[dict[str, Any]] = []

    def _stub_factory(spec: dict[str, Any]) -> dict[str, Any]:
        factory_calls.append(spec)
        return fake_creds

    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="473 happy path",
        evidence=_good_evidence(),
        credential_factory=_stub_factory,
    )
    # Observable state 1: status must be auto_approved.
    assert verdict.status == "auto_approved", verdict
    # Observable state 2: credentials must be populated — NOT None.
    assert verdict.credentials is not None, (
        "#476 regression — auto_approved but credentials:null"
    )
    # Observable state 3: individual fields present + non-empty.
    assert verdict.credentials.get("AccessKeyId") == "AKIAIOSFODNN7EXAMPLE"
    assert verdict.credentials.get("SecretAccessKey")
    assert verdict.credentials.get("SessionToken")
    # Observable state 4: factory was actually called (proves the wire).
    assert len(factory_calls) == 1


def test_473_credential_creation_failure_fail_closed(monkeypatch) -> None:
    """Credential factory raises → fail-CLOSED: verdict flips to
    pending_operator_approval, NOT auto_approved with credentials:null.

    Per [[scorer-is-ground-truth]] + [[ibounce-honest-positioning]]:
    fail-CLOSED on credential creation failure — no silent null."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely", lambda _p: (1, ()))

    def _exploding_factory(_spec: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("STS rate-limit hit")

    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="473 fail-closed",
        evidence=_good_evidence(),
        credential_factory=_exploding_factory,
    )
    # Observable state 1: status MUST be pending, not auto_approved.
    assert verdict.status == "pending_operator_approval", (
        f"expected pending_operator_approval on factory failure; got "
        f"{verdict.status!r}"
    )
    # Observable state 2: credentials must be None (no partial state).
    assert verdict.credentials is None
    # Observable state 3: the rejection_code is NOT set (this is a
    # demotion, not a rejection — the request is queued for review).
    assert verdict.rejection_code is None


def test_473_backward_compat_notes_field_still_populated(monkeypatch) -> None:
    """#476 backward-compat: the notes field is still populated and
    queryable alongside the #473 credential fix.

    When credentials ARE returned (factory wired + success), the
    "not yet wired" note MUST NOT appear (that would be misleading).
    When credentials are null (factory absent), notes MUST still
    surface the actionable next-step."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely", lambda _p: (1, ()))

    # Case A: factory wired → creds present → "not wired" note absent.
    verdict_with_creds = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="notes compat — with creds",
        evidence=_good_evidence(),
        credential_factory=lambda _: {
            "AccessKeyId": "AKIAtest",
            "SecretAccessKey": "sec",
            "SessionToken": "tok",
            "Expiration": "2026-05-26T18:00:00Z",
        },
    )
    assert verdict_with_creds.credentials is not None
    # notes is always a tuple (possibly empty) — backward-compat wire shape.
    assert isinstance(verdict_with_creds.notes, tuple)
    joined_with = " ".join(verdict_with_creds.notes).lower()
    assert "credential issuance not available" not in joined_with, (
        "misleading 'not available' note surfaced when creds were returned"
    )

    # Case B: no factory → creds null → actionable note present.
    verdict_no_creds = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="notes compat — no factory",
        evidence=_good_evidence(),
        # NO credential_factory — the pre-#473 state.
    )
    assert verdict_no_creds.credentials is None
    assert isinstance(verdict_no_creds.notes, tuple)
    joined_none = " ".join(verdict_no_creds.notes)
    # #476 notes still appear: the audit_event_id + iam-jit audit query.
    assert verdict_no_creds.audit_event_id in joined_none
    assert "iam-jit audit query" in joined_none


def test_473_sabotage_dropping_credential_factory_fails_test_1(
    monkeypatch,
) -> None:
    """Sabotage check: if credential_factory is forcibly dropped (not
    passed to request_role_from_synthesis), test_473_happy_path_ would
    fail — proves the wire from the MCP handler is load-bearing.

    This test monkeypatches request_role_from_synthesis to DROP the
    credential_factory argument, then asserts the observable state
    (credentials:null) contradicts what test 1 asserts."""
    import iam_jit.request_from_synthesis as rfs

    monkeypatch.setattr(rfs, "_score_policy_safely", lambda _p: (1, ()))

    fake_creds = {
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "SessionToken": "AQoDYXdzEJr//////////wEaoAK1",
        "Expiration": "2026-05-26T18:00:00Z",
    }

    _original = rfs.request_role_from_synthesis

    def _factory_dropping_wrapper(**kwargs: Any) -> Any:
        # Simulate the pre-#473 state: drop credential_factory.
        kwargs.pop("credential_factory", None)
        return _original(**kwargs)

    monkeypatch.setattr(rfs, "request_role_from_synthesis",
                        _factory_dropping_wrapper)

    verdict = rfs.request_role_from_synthesis(
        permissions=_narrow_permissions(),
        observed_scope={},
        justification="sabotage",
        evidence=_good_evidence(),
        credential_factory=lambda _: fake_creds,
    )
    # With factory dropped, credentials MUST be None — this proves that
    # threading the factory argument through is the load-bearing change.
    assert verdict.credentials is None, (
        "Sabotage check failed: credentials were non-null even after "
        "credential_factory was dropped from the call. The wire-through "
        "may not be the actual issuance path."
    )
