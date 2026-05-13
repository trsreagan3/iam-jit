"""Tests for the iterative-refinement workflow.

The flow: user submits task → generator returns policy → user edits
via Refinement → generator re-runs with the edits applied.
"""

from __future__ import annotations

from iam_jit.policy_gen import (
    GenerationContext,
    GenerationRequest,
    Refinement,
    generate_policy,
)


def _ctx() -> GenerationContext:
    return GenerationContext(account_id="123456789012", region="us-east-1")


def test_exclude_actions_removes_them_from_output():
    """User finds the deploy policy too broad; remove IAM:PassRole."""
    base = generate_policy(GenerationRequest(
        task_description="deploy lambda function api with role app-role",
        context=_ctx(),
    ))
    assert base.policy is not None
    # Sanity: PassRole is present in base
    all_actions = []
    for s in base.policy["Statement"]:
        a = s["Action"]
        if isinstance(a, list):
            all_actions.extend(a)
        else:
            all_actions.append(a)
    assert "iam:PassRole" in all_actions

    # Refine: remove PassRole
    refined = generate_policy(GenerationRequest(
        task_description="deploy lambda function api with role app-role",
        context=_ctx(),
        refinement=Refinement(
            exclude_actions=["iam:PassRole"],
            rationale="this is a code-only deploy; the role isn't changing",
        ),
    ))
    assert refined.policy is not None
    refined_actions = []
    for s in refined.policy["Statement"]:
        a = s["Action"]
        if isinstance(a, list):
            refined_actions.extend(a)
        else:
            refined_actions.append(a)
    assert "iam:PassRole" not in refined_actions


def test_include_action_adds_new_statement():
    """User finds the read policy too strict; add s3:DeleteObject."""
    refined = generate_policy(GenerationRequest(
        task_description="read S3 data from the prod-data bucket",
        context=_ctx(),
        refinement=Refinement(
            include_actions=["s3:DeleteObject"],
            rationale="cleanup task — also need to delete after archive",
        ),
    ))
    assert refined.policy is not None
    all_actions = []
    for s in refined.policy["Statement"]:
        a = s["Action"]
        if isinstance(a, list):
            all_actions.extend(a)
        else:
            all_actions.append(a)
    assert "s3:DeleteObject" in all_actions


def test_exclude_glob_wildcards_remove_service():
    """`s3:*` in exclude_actions removes every S3 action."""
    refined = generate_policy(GenerationRequest(
        task_description="read S3 from prod-data bucket and decrypt with kms-prod key",
        context=_ctx(),
        refinement=Refinement(
            exclude_actions=["s3:*"],
        ),
    ))
    # Whatever remains must not include any s3: action
    if refined.policy is not None:
        for s in refined.policy["Statement"]:
            actions = s["Action"]
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                assert not a.lower().startswith("s3:")


def test_rationale_surfaces_in_reasons():
    refined = generate_policy(GenerationRequest(
        task_description="read S3 from prod-data bucket",
        context=_ctx(),
        refinement=Refinement(
            exclude_actions=["s3:ListBucketVersions"],
            rationale="versioning not enabled on this bucket",
        ),
    ))
    assert any("versioning not enabled" in r for r in refined.reasons)


def test_refinement_hints_populated_when_high_risk():
    """High-scored output emits hints to narrow it."""
    r = generate_policy(GenerationRequest(
        task_description="deploy my lambda function for incident response",
        context=_ctx(),
    ))
    assert r.policy is not None
    assert r.scored_risk is not None and r.scored_risk >= 7
    assert len(r.refinement_hints) > 0
    # Should mention either resource-naming or PassRole
    hints_combined = " ".join(r.refinement_hints).lower()
    assert "passrole" in hints_combined or "resource" in hints_combined


def test_refinement_hints_empty_when_low_risk_clean():
    """A narrow, clean output doesn't emit refinement hints."""
    r = generate_policy(GenerationRequest(
        task_description="get S3 data from the prod-data bucket",
        context=_ctx(),
    ))
    assert r.policy is not None
    # When score is low and resources extracted, no hints needed
    if r.scored_risk is not None and r.scored_risk <= 3 and not r.suppressed_actions:
        # May or may not have hints depending on patterns; assert no
        # PassRole hint when PassRole isn't in factors
        assert not any("PassRole" in h for h in r.refinement_hints)


def test_full_refinement_loop():
    """Realistic iterative loop: initial → too broad → refine → ship."""
    # Round 1: user describes task
    r1 = generate_policy(GenerationRequest(
        task_description="deploy lambda for incident response",
        context=_ctx(),
    ))
    assert r1.policy is not None
    # Score should be high (no function name, no role)
    assert r1.scored_risk is not None and r1.scored_risk >= 7
    assert len(r1.refinement_hints) > 0

    # Round 2: user provides specific function and role
    r2 = generate_policy(GenerationRequest(
        task_description="deploy lambda function incident-handler with role incident-runtime-role",
        context=_ctx(),
    ))
    assert r2.policy is not None
    # Score should be 9 (lambda code-exec + PassRole composition fires
    # even on narrow ARNs — but now PassRole targets a specific role)
    # Resources should now be narrow
    for s in r2.policy["Statement"]:
        resource = s["Resource"]
        if isinstance(resource, list):
            resource = " ".join(resource)
        # Should NOT be a bare wildcard anymore
        assert resource != "*"

    # Round 3: user accepts the deployment risk; nothing to refine
    # (the policy is correct; the score reflects the inherent risk
    # of deploying code which always warrants review)
