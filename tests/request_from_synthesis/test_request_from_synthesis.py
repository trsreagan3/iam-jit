"""#421 / §A60 — tests for request_from_synthesis.

Phase E of [[bouncer-informs-agent-informs-iam-jit]]. Covers the
evidence-block discipline + the scorer-routing wiring.
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit.request_from_synthesis import (
    DEFAULT_AUTO_APPROVE_THRESHOLD,
    SynthesisVerdict,
    request_role_from_synthesis,
    request_role_from_synthesis_for_mcp,
)


# ---- Test fixtures --------------------------------------------------------


def _good_evidence() -> dict[str, Any]:
    return {
        "bouncer_audit_window": {
            "from": "2026-05-23T13:00:00Z",
            "to": "2026-05-23T14:00:00Z",
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


def test_mcp_wrapper_serialises_full_response() -> None:
    result = request_role_from_synthesis_for_mcp({
        "permissions": _narrow_permissions(),
        "justification": "test",
        "evidence": _good_evidence(),
    })
    assert "status" in result
    assert "request_id" in result
    assert "audit_event_id" in result
    assert "evidence" in result


def test_mcp_wrapper_rejects_no_evidence() -> None:
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
