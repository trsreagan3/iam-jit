"""Calibration tests for the auto-approve risk scoring.

The user-facing positioning of iam-jit (see `docs/USE-CASES.md`)
makes specific promises about which requests should auto-approve
and which shouldn't. These tests pin those promises against the
deterministic scorer so a refactor of `review.py` that breaks
the calibration fails locally.

The pattern: each test names a representative request, computes
the deterministic risk score, and asserts a band (low / medium /
high). The bands map to:

  low    = score ≤ 3   — eligible for auto-approve at threshold 3+
  med    = 4 ≤ score ≤ 6   — eligible at threshold 6+ but typically
                              human-reviewed in prod
  high   = score ≥ 7   — must reach human review regardless of
                              threshold

If a test fails, EITHER fix the scorer OR update the expectation
deliberately — both are visible changes. Do not loosen a band
silently.
"""

from __future__ import annotations

from typing import Any

from iam_jit.review import analyze_policy


def _request(
    *,
    access_type: str = "read-only",
    duration_hours: int = 1,
    resource_constraints: list[dict] | None = None,
) -> dict[str, Any]:
    """Minimal request shape sufficient for the scorer."""
    return {
        "spec": {
            "access_type": access_type,
            "duration": {"duration_hours": duration_hours},
            "resource_constraints": resource_constraints or [],
        },
    }


def _policy(actions: list[str], resources: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": resources if len(resources) > 1 else resources[0],
            }
        ],
    }


# ---- Calibration: should auto-approve at low threshold ----


def test_describe_single_ec2_instance_is_low_risk() -> None:
    """Use case: agent asks for `ec2:DescribeInstances` on one instance
    ARN to look up its public IP. This is the canonical "one piece of
    prod info" request. Must score low so the auto-approve gate
    triggers immediately."""
    policy = _policy(
        ["ec2:DescribeInstances"],
        ["arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890"],
    )
    a = analyze_policy(policy, _request())
    assert a.risk_score <= 3, (
        f"describe-single-ec2 should be low; scored {a.risk_score} "
        f"with factors: {a.risk_factors}"
    )


def test_describe_single_target_group_is_low_risk() -> None:
    """Use case: agent asks for `elbv2:DescribeTargetGroups` on one
    TG ARN to introspect routing config. Single read, single
    resource — low."""
    policy = _policy(
        ["elasticloadbalancing:DescribeTargetGroups"],
        [
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
            "targetgroup/api-prod-tg/abc123",
        ],
    )
    a = analyze_policy(policy, _request())
    assert a.risk_score <= 3, (
        f"describe-single-target-group should be low; scored "
        f"{a.risk_score} with factors: {a.risk_factors}"
    )


def test_read_one_s3_object_is_low_risk() -> None:
    """Use case: agent asks for `s3:GetObject` on one prefix to read
    a config file. Today's scorer doesn't know prod-vs-staging — the
    test reflects current behavior. Roadmap entry: "Environment-aware
    risk dimension" will let operators amplify prod reads."""
    policy = _policy(
        ["s3:GetObject"],
        ["arn:aws:s3:::team-config/feature-flags.json"],
    )
    a = analyze_policy(policy, _request())
    assert a.risk_score <= 3, (
        f"single-S3-GetObject should be low; scored {a.risk_score} "
        f"with factors: {a.risk_factors}"
    )


def test_list_one_bucket_is_low_risk() -> None:
    """List of one bucket's contents is read-level access; should
    score low when constrained to a single bucket ARN."""
    policy = _policy(
        ["s3:ListBucket"],
        ["arn:aws:s3:::team-config"],
    )
    a = analyze_policy(policy, _request())
    assert a.risk_score <= 3


# ---- Calibration: must NOT auto-approve ----


def test_wildcard_action_is_high_risk() -> None:
    """The `Action: *` case is the textbook full-admin grant.
    Must always be high — never auto-approve."""
    policy = _policy(["*"], ["*"])
    a = analyze_policy(policy, _request(access_type="read-write"))
    assert a.risk_score == 10


def test_wildcard_s3_in_prod_bucket_is_medium_or_high() -> None:
    """`s3:*` on a single bucket is "could do anything in this
    bucket" — must score above the typical auto-approve threshold."""
    policy = _policy(
        ["s3:*"],
        ["arn:aws:s3:::prod-data/*"],
    )
    a = analyze_policy(policy, _request(access_type="read-write"))
    assert a.risk_score >= 7, (
        f"s3:* on a bucket should be high; scored {a.risk_score}"
    )


def test_iam_passrole_wildcard_is_high_risk() -> None:
    """`iam:PassRole` on `*` is a documented privilege-escalation
    path. Never auto-approve."""
    policy = _policy(["iam:PassRole"], ["*"])
    a = analyze_policy(policy, _request(access_type="read-write"))
    assert a.risk_score >= 9


def test_route53_change_recordsets_is_at_least_medium() -> None:
    """DNS mutation should NOT be auto-approved at low thresholds.
    The current scorer doesn't have a per-action-class amplifier, so
    this asserts the lower bound based on the policy shape today —
    if a calibration improvement raises this to 7+ that's
    accepted; if it falls below 4, that's a regression."""
    policy = _policy(
        ["route53:ChangeResourceRecordSets"],
        ["arn:aws:route53:::hostedzone/Z1A2B3C4D5E6"],
    )
    a = analyze_policy(policy, _request(access_type="read-write"))
    # Bound: must be at least "medium" (≥4) because mutating DNS is
    # never trivially safe. If the model gets smarter and raises
    # this to 7+, this assertion still passes.
    assert a.risk_score >= 4, (
        f"DNS mutation should be at least medium; scored "
        f"{a.risk_score} — has the scorer regressed?"
    )


def test_secretsmanager_get_on_arn_is_at_least_low_but_flagged() -> None:
    """Even a single-secret read is sensitive enough to warrant
    surfacing in the risk factors, even if the numeric score is low
    (Read-level access on a specific ARN). Operators with a
    "no secrets auto-approve" policy can then route on the factor."""
    policy = _policy(
        ["secretsmanager:GetSecretValue"],
        ["arn:aws:secretsmanager:us-east-1:123456789012:secret:db-prod-AbCdEf"],
    )
    a = analyze_policy(policy, _request())
    # Today's scorer: single-resource read with constraints → low.
    # This test doesn't enforce a numeric ceiling; it asserts the
    # ANALYZER ran (we got SOME factors) so future calibration
    # improvements (treating secretsmanager as inherently sensitive)
    # have a place to land.
    assert a.risk_factors, "expected some risk_factors for secretsmanager read"


def test_long_duration_amplifies_medium_risk() -> None:
    """A medium-risk policy held for weeks should escalate. Lock the
    existing duration-adjustment behavior so calibration changes are
    visible."""
    policy = _policy(
        ["s3:*"],
        ["arn:aws:s3:::team-data/*"],
    )
    short = analyze_policy(policy, _request(access_type="read-write", duration_hours=1))
    long_ = analyze_policy(policy, _request(access_type="read-write", duration_hours=24 * 60))
    assert long_.risk_score >= short.risk_score


# ---- Calibration: read-only flag actively constrains the analyzer ----


def test_admin_extra_sensitive_services_raise_score() -> None:
    """An admin can mark a service as sensitive via the context
    fields. A wildcard within that service then scores like a
    built-in sensitive service. Use case: orgs that treat
    `athena:*` or `redshift-data:*` as more dangerous than the
    default scorer.
    """
    policy = _policy(["athena:*"], ["*"])
    # Without extra context: scores like a normal service wildcard
    # (score 7).
    a_default = analyze_policy(policy, _request(access_type="read-write"))
    # With athena marked sensitive: scores higher (8+).
    a_extra = analyze_policy(
        policy, _request(access_type="read-write"),
        extra_sensitive_services=("athena",),
    )
    assert a_extra.risk_score > a_default.risk_score, (
        f"adding athena to sensitive services should raise the score; "
        f"default={a_default.risk_score} extra={a_extra.risk_score}"
    )


def test_admin_extra_high_impact_actions_floor_score() -> None:
    """An admin can mark an action as high-impact via the context
    fields. The action then floors the score at 5 even with a
    specific resource ARN — same behavior as a built-in
    high-impact mutation."""
    policy = _policy(
        ["dynamodb:UpdateItem"],
        ["arn:aws:dynamodb:us-east-1:111111111111:table/critical-data"],
    )
    # Without extra context: specific-resource write, low score.
    a_default = analyze_policy(
        policy, _request(access_type="read-write"),
    )
    # With dynamodb:UpdateItem flagged as high-impact: score ≥ 5.
    a_extra = analyze_policy(
        policy, _request(access_type="read-write"),
        extra_high_impact_actions=("dynamodb:UpdateItem",),
    )
    assert a_extra.risk_score >= 5, (
        f"flagged action should floor at 5; got {a_extra.risk_score}"
    )
    assert a_extra.risk_score > a_default.risk_score


def test_admin_context_cannot_lower_score() -> None:
    """The context only EXPANDS the sensitive set / high-impact
    set; it can't shrink them. Trying to 'remove' a built-in via
    the admin context has no effect — the floor in review.py is
    the floor."""
    # `iam` is a built-in sensitive service. Even with an empty
    # extra-context list, it stays sensitive. We verify by scoring
    # an iam:* policy and confirming the sensitive-service factor
    # still fires.
    policy = _policy(["iam:*"], ["*"])
    a = analyze_policy(
        policy, _request(access_type="read-write"),
        extra_sensitive_services=(),  # explicit empty
    )
    assert a.risk_score >= 8
    assert any("sensitive" in f.lower() or "iam" in f.lower() for f in a.risk_factors)


def test_destructive_action_on_wildcard_resource_above_threshold() -> None:
    """Bug-fix regression: a read-write request with destructive
    actions (s3:DeleteObject, s3:DeleteBucket) on Resource: '*'
    was scoring 4 — under the default auto-approve threshold of 5
    — letting destructive permissions sail through auto-approve.

    The fix floors Delete*/Destroy*/Terminate/etc. on Resource: '*'
    at score 7 regardless of access_type, because the blast radius
    is the issue (potentially every resource in the account), not
    whether the service is in the sensitive-services set.
    """
    policy = _policy(
        ["s3:DeleteObject", "s3:DeleteBucket"], ["*"],
    )
    a = analyze_policy(policy, _request(access_type="read-write"))
    assert a.risk_score >= 7, (
        f"destructive S3 actions on Resource: '*' must score >= 7 "
        f"(above the default auto-approve threshold of 5); got "
        f"{a.risk_score}. Factors: {a.risk_factors}"
    )
    # The factor list should explicitly mention the destructive
    # action — not just generic "broad cross-resource read/access"
    # boilerplate. Auditors need to see WHY a request was flagged.
    assert any(
        "destructive" in f.lower() or "blast" in f.lower()
        for f in a.risk_factors
    ), f"missing destructive-action factor; got: {a.risk_factors}"


def test_destructive_action_on_specific_arn_stays_lower() -> None:
    """Scope matters: the SAME destructive action on a SPECIFIC
    resource ARN is much less risky — the requester named exactly
    what they intend to delete. Score should drop below the
    auto-approve threshold so well-scoped destructive operations
    can still auto-approve (the deletion is bounded to one resource
    the requester explicitly named)."""
    policy = _policy(
        ["s3:DeleteObject"],
        ["arn:aws:s3:::specific-test-bucket/temp-file-uuid-abc.tmp"],
    )
    a = analyze_policy(policy, _request(access_type="read-write"))
    # The wildcard-resource penalty should NOT fire here. Score
    # depends on baseline rules but must be lower than the
    # wildcard-resource case.
    assert a.risk_score < 7, (
        f"specific-ARN destructive action should score lower than "
        f"the wildcard-resource case; got {a.risk_score}. "
        f"Factors: {a.risk_factors}"
    )


def test_state_changing_action_on_wildcard_above_threshold() -> None:
    """Non-destructive but still IAM-class-Write actions on
    Resource: '*' (e.g., s3:PutObject across all buckets) score >= 6
    so they don't auto-approve. The verb is less alarming than
    Delete*, but the broad scope is still meaningful."""
    policy = _policy(["s3:PutObject"], ["*"])
    a = analyze_policy(policy, _request(access_type="read-write"))
    assert a.risk_score >= 6, (
        f"s3:PutObject on Resource: '*' must score >= 6 "
        f"(above the default auto-approve threshold); got "
        f"{a.risk_score}. Factors: {a.risk_factors}"
    )


def test_ec2_terminate_on_wildcard_above_threshold() -> None:
    """Cross-service coverage: ec2:TerminateInstances on '*'
    (every EC2 instance in the account) is destructive at the
    same severity as s3:DeleteBucket on '*'. Same calibration."""
    policy = _policy(["ec2:TerminateInstances"], ["*"])
    a = analyze_policy(policy, _request(access_type="read-write"))
    assert a.risk_score >= 7, (
        f"ec2:TerminateInstances on Resource: '*' must score >= 7; "
        f"got {a.risk_score}. Factors: {a.risk_factors}"
    )


def test_read_only_mismatch_is_flagged() -> None:
    """A request marked read-only with a write action in the policy
    must score high — the request is lying about its scope."""
    policy = _policy(
        ["s3:DeleteObject"],
        ["arn:aws:s3:::team-data/*"],
    )
    a = analyze_policy(policy, _request(access_type="read-only"))
    assert a.risk_score >= 7
    assert any("read-only" in f.lower() for f in a.risk_factors)
