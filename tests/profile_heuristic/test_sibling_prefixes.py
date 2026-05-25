"""Phase 3 prerequisite — state-verification tests for
``sibling_action_prefixes``.

Per CONTRIBUTING.md state-verification convention: the returned set IS
the observable state. Each test asserts the SPECIFIC patterns expected
(not just non-emptiness) so the table's coverage is pinned and any
addition / removal of a sibling verb shows up in the diff.

The sibling sets are an initial intuition-derived pass per design §9
guess #4. Phase 10 grading corpus is the gate for expanding coverage.
Per ``[[deliberate-feature-completion]]`` we don't pre-expand.
"""

from __future__ import annotations

import pytest

from iam_jit.profile_heuristic import sibling_action_prefixes
from iam_jit.profile_heuristic.ibounce_classes import (
    CREATE_SIBLING_VERBS,
    READ_SIBLING_VERBS,
    WRITE_SIBLING_VERBS,
)


# ---------------------------------------------------------------------------
# READ sibling adjacency
# ---------------------------------------------------------------------------


def test_s3_get_object_returns_only_real_catalog_anchored_siblings() -> None:
    """Spec example pinned post-#580 GAP-1: ``s3:GetObject`` has no real
    sibling shapes under the per-verb adjacency because AWS S3 read-side
    extensions are all ``Get*`` shapes (``GetObjectAcl``,
    ``GetObjectTagging``, …) — and Get is the SOURCE verb (excluded from
    its own sibling set per the band contract).

    Other sibling verbs (List/Describe/Head/…) do not produce real
    ``s3:*Object*`` actions in the AWS IAM catalogue, so the filter
    drops them. Pre-#580 the unfiltered output emitted hallucinated
    shapes like ``s3:ListObject*`` / ``s3:DescribeObject*`` /
    ``s3:HeadObject*`` that don't exist in AWS — installed as allow
    rules they would silently no-op in production per
    [[ibounce-honest-positioning]].
    """
    siblings = sibling_action_prefixes("s3:GetObject")
    # Per the filter contract: every returned pattern matches at least
    # one real AWS action. For s3:GetObject, the real catalogue has no
    # non-Get verb that produces an ``*Object*`` action — so empty.
    assert siblings == set(), (
        f"s3:GetObject siblings should be empty post-catalogue-filter; "
        f"got {siblings}"
    )


def test_ec2_describe_instances_returns_only_real_catalog_anchored_siblings() -> None:
    """Post-#580 GAP-1: ``ec2:DescribeInstances`` has no real sibling
    shapes — the AWS EC2 catalogue uses ``Describe*`` exclusively for
    instance reads (no ``GetInstances`` / ``ListInstances`` / etc), so
    the pattern-generated siblings all fail the real-catalogue gate.

    Pre-#580 the unfiltered output emitted ``ec2:GetInstances*``,
    ``ec2:ListInstances*``, ``ec2:HeadInstances*`` — none of which exist
    in AWS. Per [[scorer-is-ground-truth]] we anchor to reality.
    """
    siblings = sibling_action_prefixes("ec2:DescribeInstances")
    assert siblings == set(), (
        f"ec2:DescribeInstances siblings should be empty post-"
        f"catalogue-filter (AWS uses Describe* for instances exclusively); "
        f"got {siblings}"
    )


def test_dynamodb_query_returns_real_catalog_read_siblings() -> None:
    """``dynamodb:Query`` has empty noun-suffix, so sibling shape is
    ``dynamodb:Get*``, ``dynamodb:Scan*``, etc. DynamoDB's catalogue
    DOES include real read actions for Get/List/Describe/Scan/Read
    verbs — those globs match real actions and survive the catalogue
    gate."""
    siblings = sibling_action_prefixes("dynamodb:Query")
    # Per real AWS DynamoDB catalogue: dynamodb:GetItem, dynamodb:Scan,
    # dynamodb:ListTables, dynamodb:DescribeTable etc. all exist — so
    # the corresponding ``dynamodb:Get*`` / ``dynamodb:Scan*`` /
    # ``dynamodb:List*`` / ``dynamodb:Describe*`` globs survive the gate.
    assert "dynamodb:Get*" in siblings, (
        f"dynamodb:Get* should survive catalogue gate; got {siblings}"
    )
    assert "dynamodb:Scan*" in siblings
    assert "dynamodb:List*" in siblings
    assert "dynamodb:Describe*" in siblings


# ---------------------------------------------------------------------------
# WRITE + CREATE cross-band adjacency
# ---------------------------------------------------------------------------


def test_iam_put_role_policy_returns_only_real_catalog_anchored_siblings() -> None:
    """Post-#580 GAP-1: ``iam:PutRolePolicy`` has no real sibling shapes
    under WRITE/CREATE-band adjacency. AWS IAM has ``PutRolePolicy``,
    ``DeleteRolePolicy``, ``GetRolePolicy``, ``AttachRolePolicy``,
    ``DetachRolePolicy`` for the noun ``RolePolicy`` — but ``Delete*`` /
    ``Get*`` / ``Attach*`` / ``Detach*`` are NOT in
    WRITE_SIBLING_VERBS or CREATE_SIBLING_VERBS, so the bands don't
    consider them.

    Pre-#580 the unfiltered output emitted hallucinated shapes
    ``iam:UpdateRolePolicy*``, ``iam:CreateRolePolicy*``,
    ``iam:ModifyRolePolicy*``, ``iam:SetRolePolicy*`` — none exist in
    AWS. Per [[ibounce-honest-positioning]] silent-no-op allows are
    unacceptable; per [[scorer-is-ground-truth]] we anchor to reality.
    """
    siblings = sibling_action_prefixes("iam:PutRolePolicy")
    assert siblings == set(), (
        f"iam:PutRolePolicy siblings should be empty post-catalogue-"
        f"filter; got {siblings}"
    )


def test_lambda_create_function_includes_real_put_update_function_siblings() -> None:
    """``lambda:CreateFunction`` siblings include
    ``lambda:UpdateFunction*`` + ``lambda:PutFunction*`` — both real
    AWS catalogue globs (``UpdateFunctionCode``,
    ``UpdateFunctionConfiguration``, ``PutFunctionConcurrency``, …).
    Create bridges to Write band."""
    siblings = sibling_action_prefixes("lambda:CreateFunction")
    assert "lambda:UpdateFunction*" in siblings, (
        f"lambda:UpdateFunction* survives catalogue gate "
        f"(matches UpdateFunctionCode etc); got {siblings}"
    )
    assert "lambda:PutFunction*" in siblings, (
        f"lambda:PutFunction* survives catalogue gate "
        f"(matches PutFunctionConcurrency etc); got {siblings}"
    )
    # Source verb absent.
    assert "lambda:CreateFunction*" not in siblings


def test_s3_update_object_includes_only_real_put_object_sibling() -> None:
    """Post-#580 GAP-1: ``s3:UpdateObject`` (note: itself not a real AWS
    action — used here to exercise the Update sibling band) returns only
    ``s3:PutObject*`` because that's the only WRITE+CREATE-band sibling
    that has a real ``*Object*`` action in the catalogue.

    Pre-#580 also emitted ``s3:CreateObject*`` / ``s3:SetObject*`` /
    ``s3:ModifyObject*`` / ``s3:PatchObject*`` / ``s3:ReplaceObject*``
    — none of which exist in AWS S3.
    """
    siblings = sibling_action_prefixes("s3:UpdateObject")
    assert siblings == {"s3:PutObject*"}, (
        f"s3:UpdateObject siblings should be exactly {{s3:PutObject*}} "
        f"post-catalogue-filter; got {siblings}"
    )


# ---------------------------------------------------------------------------
# Negative / edge cases
# ---------------------------------------------------------------------------


def test_unknown_verb_returns_empty_set() -> None:
    """A verb absent from all sibling bands returns the empty set."""
    # ``Frobnicate`` is not in any band.
    assert sibling_action_prefixes("custom:FrobnicateThing") == set()


def test_non_aws_shape_returns_empty_set() -> None:
    """Non-AWS-shape actions (no colon) return the empty set."""
    assert sibling_action_prefixes("kubectl get pods") == set()
    assert sibling_action_prefixes("SELECT * FROM users") == set()
    assert sibling_action_prefixes("GET /api/v1/users") == set()
    assert sibling_action_prefixes("") == set()


def test_malformed_aws_shape_returns_empty_set() -> None:
    """Half-shaped inputs (empty service / empty action) return empty."""
    assert sibling_action_prefixes(":GetObject") == set()
    assert sibling_action_prefixes("s3:") == set()
    assert sibling_action_prefixes(":") == set()


def test_lowercase_verb_returns_empty_set() -> None:
    """AWS actions are TitleCase by convention. Lowercase actions
    (which shouldn't reach this code path from a real bouncer) return
    the empty set rather than guessing."""
    # AWS doesn't emit lowercase action names; the upstream
    # bouncer/audit pipeline preserves case.
    assert sibling_action_prefixes("s3:getobject") == set()


def test_non_string_input_returns_empty_set() -> None:
    """Defensive: non-string input returns empty set, doesn't crash."""
    assert sibling_action_prefixes(None) == set()  # type: ignore[arg-type]
    assert sibling_action_prefixes(123) == set()  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Band membership — pin the well-known sibling sets per spec
# ---------------------------------------------------------------------------


def test_read_sibling_band_covers_spec_verbs() -> None:
    """Per spec: read siblings include Get / List / Describe / Head /
    Lookup / Search / Filter / Count / Has / Is. Pin the set so any
    removal shows up in the diff."""
    for verb in (
        "Get", "List", "Describe", "Head", "Lookup",
        "Search", "Filter", "Count", "Has", "Is",
    ):
        assert verb in READ_SIBLING_VERBS, f"{verb} missing from READ_SIBLING_VERBS"


def test_write_sibling_band_covers_spec_verbs() -> None:
    """Per spec: write siblings include Put / Update / Modify / Replace
    / Set / Patch."""
    for verb in ("Put", "Update", "Modify", "Replace", "Set", "Patch"):
        assert verb in WRITE_SIBLING_VERBS, f"{verb} missing from WRITE_SIBLING_VERBS"


def test_create_sibling_band_covers_spec_verbs() -> None:
    """Per spec: create siblings include Create / Register (paired with
    Put/Update via the WRITE+CREATE cross-band)."""
    assert "Create" in CREATE_SIBLING_VERBS
    assert "Register" in CREATE_SIBLING_VERBS


# ---------------------------------------------------------------------------
# Source verb never appears in its own sibling set
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verb", [
    "Get", "List", "Describe", "Put", "Update", "Create",
])
def test_source_verb_excluded_from_sibling_set(verb: str) -> None:
    """The caller already has the source verb; including it would cause
    the Phase 3 generator to re-emit the observed allow as a "sibling"
    addition."""
    action = f"s3:{verb}Object"
    siblings = sibling_action_prefixes(action)
    # The source verb's own pattern must not appear.
    assert f"s3:{verb}Object*" not in siblings


# ---------------------------------------------------------------------------
# Pure function discipline
# ---------------------------------------------------------------------------


def test_pure_function_stable_across_repeats() -> None:
    """State-verification: identity-stable result across many calls."""
    first = sibling_action_prefixes("s3:GetObject")
    for _ in range(50):
        assert sibling_action_prefixes("s3:GetObject") == first
