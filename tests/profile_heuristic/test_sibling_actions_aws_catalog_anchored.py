"""#580 GAP-1 — state-verification tests anchoring sibling expansion to
the real AWS IAM action catalogue.

Per UAT-A 2026-05-25: ``sibling_action_prefixes()`` was pattern-
generating 15 verb prefixes around ``Object`` verbs without validating
against AWS. UAT-A confirmed 12 hallucinated action names (listed
below) that don't exist in any AWS service.

This file pins:

1. None of the 12 UAT-A hallucinations appear in any sibling output
   for any common source-action shape.
2. Real catalogue actions DO surface when they match a sibling band
   verb + noun shape.
3. The catalogue-anchored filter is load-bearing (sabotage check):
   monkeypatch ``is_real_aws_action`` to always-True + verify the
   hallucination guards fail — proves the filter actually controls
   the gate.

Per CONTRIBUTING.md state-verification convention: each test asserts
the SPECIFIC observable state (the set membership, the catalogue lookup
boolean) rather than just non-emptiness.

Per [[scorer-is-ground-truth]] the AWS IAM catalogue is the calibration
anchor here; the test suite never asks the filter to widen its
definition of "real action" to make a downstream feature look better.
"""

from __future__ import annotations

import pytest

from iam_jit.profile_heuristic import sibling_action_prefixes
from iam_jit.profile_heuristic import aws_catalog


# ---------------------------------------------------------------------------
# The 12 UAT-A-found hallucinations (verb prefixes around "Object" that
# don't exist in AWS IAM for s3).
# ---------------------------------------------------------------------------

UAT_A_HALLUCINATED_S3_OBJECT_SIBLINGS: tuple[str, ...] = (
    "s3:CheckObject*",
    "s3:CountObject*",
    "s3:DescribeObject*",
    "s3:FilterObject*",
    "s3:HasObject*",
    "s3:IsObject*",
    "s3:LookupObject*",
    "s3:QueryObject*",
    "s3:ReadObject*",
    "s3:ScanObject*",
    "s3:SearchObject*",
    "s3:ViewObject*",
)


# ---------------------------------------------------------------------------
# Hallucination guards — per-pattern named tests for diff visibility.
# ---------------------------------------------------------------------------


def test_sibling_expansion_excludes_check_object_hallucination() -> None:
    """``s3:CheckObject*`` is not a real AWS action and must not appear
    in any sibling output (UAT-A: pre-fix it was emitted for
    ``s3:GetObject`` source)."""
    siblings = sibling_action_prefixes("s3:GetObject")
    assert "s3:CheckObject*" not in siblings, (
        f"UAT-A hallucination s3:CheckObject* leaked into siblings: "
        f"{siblings}"
    )


def test_sibling_expansion_excludes_count_object_hallucination() -> None:
    """``s3:CountObject*`` is not a real AWS action."""
    siblings = sibling_action_prefixes("s3:GetObject")
    assert "s3:CountObject*" not in siblings, (
        f"UAT-A hallucination s3:CountObject* leaked: {siblings}"
    )


@pytest.mark.parametrize("hallucinated", UAT_A_HALLUCINATED_S3_OBJECT_SIBLINGS)
def test_sibling_expansion_excludes_all_12_uat_a_hallucinations(
    hallucinated: str,
) -> None:
    """Parametrized guard over all 12 UAT-A-found hallucinations.

    Re-run sibling expansion against every common s3 read source we
    know operators observe in practice (Get, List, Head are the three
    real S3 read verbs); none of the 12 hallucinations may appear in
    any of those expansions.
    """
    for source in ("s3:GetObject", "s3:GetObjectAcl",
                   "s3:GetObjectTagging", "s3:GetObjectAttributes"):
        siblings = sibling_action_prefixes(source)
        assert hallucinated not in siblings, (
            f"UAT-A hallucination {hallucinated} appeared in siblings "
            f"of {source}: {siblings}"
        )


# ---------------------------------------------------------------------------
# Real-catalogue inclusions — verify the filter doesn't over-prune.
# ---------------------------------------------------------------------------


def test_sibling_expansion_includes_real_dynamodb_read_globs() -> None:
    """``dynamodb:Query`` (READ band, no noun suffix) surfaces sibling
    globs for verbs that have real AWS actions in DynamoDB.

    Real DynamoDB read actions: ``dynamodb:GetItem``,
    ``dynamodb:ListTables``, ``dynamodb:DescribeTable``,
    ``dynamodb:Scan``. Globs ``dynamodb:Get*`` / ``List*`` /
    ``Describe*`` / ``Scan*`` all survive the catalogue gate."""
    siblings = sibling_action_prefixes("dynamodb:Query")
    for expected in ("dynamodb:Get*", "dynamodb:List*",
                     "dynamodb:Describe*", "dynamodb:Scan*"):
        assert expected in siblings, (
            f"{expected} missing from dynamodb:Query siblings "
            f"(should survive catalogue gate); got {siblings}"
        )


def test_sibling_expansion_includes_real_lambda_function_writes() -> None:
    """``lambda:CreateFunction`` (CREATE band) surfaces real
    ``lambda:UpdateFunction*`` + ``lambda:PutFunction*`` — both globs
    match multiple real AWS Lambda actions
    (UpdateFunctionCode, PutFunctionConcurrency, …)."""
    siblings = sibling_action_prefixes("lambda:CreateFunction")
    assert "lambda:UpdateFunction*" in siblings, (
        f"lambda:UpdateFunction* missing; got {siblings}"
    )
    assert "lambda:PutFunction*" in siblings, (
        f"lambda:PutFunction* missing; got {siblings}"
    )


def test_sibling_expansion_excludes_unknown_service() -> None:
    """A made-up AWS service produces empty siblings — policy_sentry
    returns no actions for the service, so every pattern fails the
    catalogue gate."""
    siblings = sibling_action_prefixes("madeup-service:GetX")
    assert siblings == set(), (
        f"unknown service should produce empty siblings; "
        f"got {siblings}"
    )


# ---------------------------------------------------------------------------
# is_real_aws_action — direct catalogue-adapter unit tests.
# ---------------------------------------------------------------------------


def test_is_real_aws_action_known_real_literal() -> None:
    """Literal real action returns True."""
    assert aws_catalog.is_real_aws_action("s3:GetObject") is True
    assert aws_catalog.is_real_aws_action("s3:PutObject") is True
    assert aws_catalog.is_real_aws_action("iam:CreateRole") is True


def test_is_real_aws_action_known_fake_literal() -> None:
    """Literal hallucinated action returns False (none of these exist
    in AWS IAM)."""
    assert aws_catalog.is_real_aws_action("s3:CheckObject") is False
    assert aws_catalog.is_real_aws_action("s3:HasObject") is False
    assert aws_catalog.is_real_aws_action("iam:UpdateRolePolicy") is False


def test_is_real_aws_action_glob_with_real_matches() -> None:
    """A glob that matches at least one real action returns True."""
    # s3:Get* matches s3:GetObject + many others.
    assert aws_catalog.is_real_aws_action("s3:Get*") is True
    # s3:PutObject* matches s3:PutObject + s3:PutObjectAcl + others.
    assert aws_catalog.is_real_aws_action("s3:PutObject*") is True


def test_is_real_aws_action_glob_with_no_matches() -> None:
    """A glob that matches NO real action returns False."""
    # s3:Zzz* matches nothing.
    assert aws_catalog.is_real_aws_action("s3:Zzz*") is False
    # The 12 UAT-A hallucinated globs all return False.
    for halluc in UAT_A_HALLUCINATED_S3_OBJECT_SIBLINGS:
        assert aws_catalog.is_real_aws_action(halluc) is False, (
            f"{halluc} should not match any real AWS action"
        )


def test_is_real_aws_action_malformed_input() -> None:
    """Malformed input returns False without raising."""
    assert aws_catalog.is_real_aws_action("") is False
    assert aws_catalog.is_real_aws_action("noColonHere") is False
    assert aws_catalog.is_real_aws_action(":NoService") is False
    assert aws_catalog.is_real_aws_action("s3:") is False
    assert aws_catalog.is_real_aws_action(None) is False  # type: ignore[arg-type]
    assert aws_catalog.is_real_aws_action(123) is False  # type: ignore[arg-type]


def test_is_real_aws_action_case_sensitive() -> None:
    """AWS actions are TitleCase; the matcher preserves case (so a
    lowercase pattern won't accidentally match a TitleCase real action
    via case-insensitive comparison)."""
    # Real: s3:GetObject (TitleCase). Lowercase pattern doesn't match.
    assert aws_catalog.is_real_aws_action("s3:getobject") is False


# ---------------------------------------------------------------------------
# Sabotage check — proves the catalogue filter is load-bearing.
# ---------------------------------------------------------------------------


def test_catalogue_filter_is_load_bearing_sabotage_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Monkeypatch ``is_real_aws_action`` to always-True. The
    hallucination-exclusion test (#1 in this file) MUST then fail —
    proves the filter is the thing that excludes hallucinations, not
    some unrelated short-circuit.

    Without this sabotage check, a regression that removed the filter
    + restored hallucinations would still pass tests that don't
    explicitly assert the hallucinated patterns are absent. This is
    the [[tests-and-independent-uat-required]] discipline — every
    load-bearing assertion gets a sabotage probe.
    """
    # Patch the module-level binding the lazy import inside
    # sibling_action_prefixes resolves at call time.
    from iam_jit.profile_heuristic import aws_catalog as cat_mod

    monkeypatch.setattr(cat_mod, "is_real_aws_action", lambda _p: True)

    siblings = sibling_action_prefixes("s3:GetObject")

    # With the filter neutered, the pre-fix hallucinations re-appear.
    # We verify they re-appear under the sabotage — proving the filter
    # is the thing that excludes them when intact.
    assert "s3:CheckObject*" in siblings, (
        f"with filter sabotaged to always-True, the pre-fix "
        f"hallucination s3:CheckObject* should re-appear (proves the "
        f"filter is load-bearing); got {siblings}"
    )
    assert "s3:HasObject*" in siblings, (
        f"sabotage check: s3:HasObject* should re-appear; got {siblings}"
    )
