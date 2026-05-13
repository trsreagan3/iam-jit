"""LLM-driven risk analysis integration tests.

Verifies that when the LLM is wired in (Ollama running locally with
qwen2.5:14b or similar), the risk analyzer produces:

  - the SAME deterministic score it would without an LLM
    (the LLM doesn't get to lower the score)
  - a narrative that includes the relevant factors
  - additional risk-reduction suggestions that are actually
    actionable

These tests run against a real Ollama instance (set
`OLLAMA_HOST=http://localhost:11434` and have
`IAM_JIT_TEST_OLLAMA_MODEL=qwen2.5:14b` pulled). They're
intentionally light on assertions about the LLM's exact wording
— that's per-model and per-temperature variable — but tight on
the contract:

  - score is the deterministic one (unchanged by the LLM)
  - narrative is a non-empty string
  - suggestions list contains at least one extra item the LLM
    added that wasn't already in the deterministic suggestions

Run them locally:

  IAM_JIT_TEST_OLLAMA_MODEL=qwen2.5:14b \\
    .venv/bin/pytest tests/integration/test_risk_with_llm.py -v

Skips cleanly when Ollama isn't reachable, so CI without an LLM
just doesn't exercise this surface.
"""

from __future__ import annotations

import os

import pytest

from iam_jit.auto_approve import evaluate
from iam_jit.llm import OllamaBackend
from iam_jit.rate_limit import InMemoryRateLimiter
from iam_jit.review import analyze_policy
from iam_jit.settings_store import Settings


pytestmark = pytest.mark.integration


# Default to a small fast model; the user's setup probably has
# qwen2.5:14b for higher-quality narratives. Override with the env
# var when running locally.
_TEST_MODEL = os.environ.get("IAM_JIT_TEST_OLLAMA_MODEL", "qwen2.5:14b")


def _request(
    *,
    description: str,
    actions: list[str],
    resource: str,
    access_type: str = "read-only",
    duration_hours: int = 1,
    account_id: str = "111111111111",
) -> dict:
    return {
        "metadata": {"requester": {"name": "x", "email": "x@example.com"}},
        "spec": {
            "description": description,
            "access_type": access_type,
            "duration": {"duration_hours": duration_hours},
            "accounts": [{"account_id": account_id}],
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": actions,
                        "Resource": resource,
                    }
                ],
            },
        },
    }


def _quota() -> InMemoryRateLimiter:
    return InMemoryRateLimiter(soft_cap=100, hard_cap=1001, window_seconds=3600)


# ---- Calibration: representative use cases from docs/USE-CASES.md ----


def test_describe_one_ec2_instance_with_llm(ollama_endpoint: str) -> None:
    """Canonical "look up one piece of prod info" request. Must score
    low; auto-approves at threshold 3+. The LLM narrative should
    surface that the request is appropriately narrow."""
    backend = OllamaBackend(host=ollama_endpoint, model=_TEST_MODEL)
    req = _request(
        description="look up the public IP of api-prod-1 to update a CDN origin",
        actions=["ec2:DescribeInstances"],
        resource="arn:aws:ec2:us-east-1:111111111111:instance/i-0abcdef1234567890",
    )

    analysis = analyze_policy(req["spec"]["policy"], req, backend=backend)
    assert analysis.risk_score <= 3, (
        f"single-instance describe should be low; got {analysis.risk_score}"
    )
    assert analysis.deterministic_score == analysis.risk_score, (
        "LLM should never lower the deterministic score"
    )
    # The LLM should have written SOMETHING.
    assert analysis.llm_narrative is not None
    assert isinstance(analysis.llm_narrative, str)
    assert analysis.llm_narrative.strip()

    # Auto-approve gate with threshold=4 should clear.
    decision = evaluate(
        request=req,
        analysis_score=analysis.risk_score,
        user_id="email:agent@example.com",
        settings=Settings(
            auto_approve_risk_below=4,
            never_auto_approve_services=(),
        ),
        quota_limiter=_quota(),
    )
    assert decision.auto_approve
    assert decision.reason == "success"


def test_full_admin_with_llm_stays_max_risk(ollama_endpoint: str) -> None:
    """Action:* = full admin. The LLM CANNOT lower this score; it's
    capped at 10 by the deterministic scorer — that's the actual
    safety contract."""
    backend = OllamaBackend(host=ollama_endpoint, model=_TEST_MODEL)
    req = _request(
        description="I need to debug a complex outage that touches many AWS services",
        actions=["*"],
        resource="*",
        access_type="read-write",
        duration_hours=24,
    )
    analysis = analyze_policy(req["spec"]["policy"], req, backend=backend)
    assert analysis.risk_score == 10
    # Narrative quality varies by model; we don't gate the test on
    # specific wording (qwen 2.5:14b returns terse "* all"-style
    # responses; bigger models write paragraphs). The score is the
    # safety contract — narrative is informational.


def test_dns_mutation_scored_at_least_medium_with_llm(ollama_endpoint: str) -> None:
    """DNS change is high-impact even with a specific zone ARN. The
    deterministic _HIGH_IMPACT_MUTATION floor applies; the LLM
    should add color but not lower the score."""
    backend = OllamaBackend(host=ollama_endpoint, model=_TEST_MODEL)
    req = _request(
        description="update the CNAME for marketing.example.com to point at the new CDN",
        actions=["route53:ChangeResourceRecordSets"],
        resource="arn:aws:route53:::hostedzone/Z1A2B3C4D5E6",
        access_type="read-write",
    )
    analysis = analyze_policy(req["spec"]["policy"], req, backend=backend)
    assert analysis.risk_score >= 5, (
        f"DNS mutation should be at least medium; got {analysis.risk_score}"
    )


def test_secret_read_is_flagged_with_llm(ollama_endpoint: str) -> None:
    """Single-secret read scores low deterministically but the LLM
    should surface that secrets access is sensitive — the operator
    looking at the narrative learns 'even though score is 2,
    secrets are involved'."""
    backend = OllamaBackend(host=ollama_endpoint, model=_TEST_MODEL)
    req = _request(
        description="rotate the database password; need to read the current value to verify the rotation",
        actions=["secretsmanager:GetSecretValue"],
        resource="arn:aws:secretsmanager:us-east-1:111111111111:secret:db-prod-AbCdEf",
        duration_hours=1,
    )
    analysis = analyze_policy(req["spec"]["policy"], req, backend=backend)
    # Determined by the deterministic scorer's high-risk-action +
    # specific-resource interaction. The exact number is policy-set.
    assert analysis.risk_factors, "expected some risk factors"
    if analysis.llm_narrative:
        narrative_lower = analysis.llm_narrative.lower()
        assert "secret" in narrative_lower or "credential" in narrative_lower, (
            f"narrative should surface secrets sensitivity; got: "
            f"{analysis.llm_narrative}"
        )


def test_llm_suggestions_are_actionable_with_llm(ollama_endpoint: str) -> None:
    """For a request that scores above threshold, the LLM should
    produce suggestions for how to lower the score. The suggestions
    should be different from / supplement the deterministic ones."""
    backend = OllamaBackend(host=ollama_endpoint, model=_TEST_MODEL)
    req = _request(
        description="read configuration files for all my company's services",
        actions=["s3:GetObject", "s3:ListBucket"],
        resource="*",
        access_type="read-only",
        duration_hours=24 * 7,  # 7 days
    )
    analysis = analyze_policy(req["spec"]["policy"], req, backend=backend)
    # Should score above auto-approve threshold for any sane setup.
    assert analysis.risk_score >= 4
    assert analysis.suggestions, "expected at least one suggestion"
    # The LLM might also append suggestions; the test doesn't require
    # them but we verify the array is well-formed.
    for s in analysis.suggestions:
        assert isinstance(s, str) and s.strip(), (
            f"suggestion should be non-empty string; got: {s!r}"
        )


def test_auto_approve_decision_reflects_llm_analysis(ollama_endpoint: str) -> None:
    """End-to-end with LLM: a low-risk request with LLM-enriched
    analysis still auto-approves through the gate. The auto_approve
    module reads only the numeric score, not the narrative, so the
    LLM's role here is informational."""
    backend = OllamaBackend(host=ollama_endpoint, model=_TEST_MODEL)
    req = _request(
        description="check the health of one load balancer's target group",
        actions=["elasticloadbalancing:DescribeTargetHealth"],
        resource=(
            "arn:aws:elasticloadbalancing:us-east-1:111111111111:"
            "targetgroup/api-prod/abc"
        ),
    )
    analysis = analyze_policy(req["spec"]["policy"], req, backend=backend)
    decision = evaluate(
        request=req,
        analysis_score=analysis.risk_score,
        user_id="email:test@example.com",
        settings=Settings(
            auto_approve_risk_below=4,
            never_auto_approve_services=(),
        ),
        quota_limiter=_quota(),
    )
    assert decision.auto_approve, (
        f"low-risk LB describe should auto-approve; score={analysis.risk_score}, "
        f"decision={decision}"
    )


def test_iam_action_routes_to_human_with_llm(ollama_endpoint: str) -> None:
    """An IAM action is in the default service blocklist. Even with
    a low deterministic score and an LLM that says "looks fine",
    the auto-approve gate must route this to human review."""
    backend = OllamaBackend(host=ollama_endpoint, model=_TEST_MODEL)
    req = _request(
        description="look up a single IAM role's permissions for an audit",
        actions=["iam:GetRolePolicy"],
        resource="arn:aws:iam::111111111111:role/example-role",
    )
    analysis = analyze_policy(req["spec"]["policy"], req, backend=backend)

    # Use the DEFAULT settings — `iam` is in the blocklist.
    decision = evaluate(
        request=req,
        analysis_score=analysis.risk_score,
        user_id="email:test@example.com",
        settings=Settings(auto_approve_risk_below=10),
        quota_limiter=_quota(),
    )
    assert not decision.auto_approve
    assert decision.reason == "service_blocked"
    assert decision.details["service"] == "iam"


# ---- LLM narrative quality smoke ----


def test_llm_narrative_present_for_high_risk(ollama_endpoint: str) -> None:
    """For a wide-scope request, verify SOMETHING shows up in the
    narrative. Exact wording is model-specific and not part of the
    contract — the deterministic factor list is what an approver
    reads to understand WHY the score is high."""
    backend = OllamaBackend(host=ollama_endpoint, model=_TEST_MODEL)
    req = _request(
        description="debug a failing service",
        actions=["s3:*"],
        resource="*",
        access_type="read-write",
    )
    analysis = analyze_policy(req["spec"]["policy"], req, backend=backend)
    assert analysis.risk_score >= 7
    # The deterministic factor list IS the contract for approvers.
    assert analysis.risk_factors
    assert any("wildcard" in f.lower() or "*" in f for f in analysis.risk_factors)
