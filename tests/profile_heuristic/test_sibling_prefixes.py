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


def test_s3_get_object_includes_list_describe_head_siblings() -> None:
    """Spec example: ``s3:GetObject`` siblings include ``s3:ListObject*``,
    ``s3:DescribeObject*``, ``s3:HeadObject*``."""
    siblings = sibling_action_prefixes("s3:GetObject")
    assert "s3:ListObject*" in siblings
    assert "s3:DescribeObject*" in siblings
    assert "s3:HeadObject*" in siblings
    # Source verb itself is NOT in the sibling set — caller already
    # has it.
    assert "s3:GetObject*" not in siblings


def test_ec2_describe_instances_includes_get_list_siblings() -> None:
    """Spec example: ``ec2:DescribeInstances`` siblings include
    ``ec2:GetInstance*``, ``ec2:ListInstances*``."""
    siblings = sibling_action_prefixes("ec2:DescribeInstances")
    assert "ec2:GetInstances*" in siblings
    assert "ec2:ListInstances*" in siblings
    assert "ec2:HeadInstances*" in siblings
    # Source verb absent.
    assert "ec2:DescribeInstances*" not in siblings


def test_dynamodb_query_returns_read_siblings() -> None:
    """``dynamodb:Query`` is a Query-shape read; siblings should include
    other read verbs paired with the same noun. Verifies Query is in
    the READ band."""
    siblings = sibling_action_prefixes("dynamodb:Query")
    # Query has no noun suffix in this case, so sibling shape is
    # ``dynamodb:Get*`` etc.
    assert any(s.startswith("dynamodb:Get") for s in siblings)
    assert any(s.startswith("dynamodb:Scan") for s in siblings)


# ---------------------------------------------------------------------------
# WRITE + CREATE cross-band adjacency
# ---------------------------------------------------------------------------


def test_iam_put_role_policy_includes_update_create_siblings() -> None:
    """Spec example: ``iam:PutRolePolicy`` siblings include
    ``iam:UpdateRolePolicy``, ``iam:CreateRolePolicy``.

    Verifies the WRITE band bridges to the CREATE band — Put/Update/Create
    commonly co-occur on the same resource and the operator typically
    needs all three to complete a write flow.
    """
    siblings = sibling_action_prefixes("iam:PutRolePolicy")
    assert "iam:UpdateRolePolicy*" in siblings
    assert "iam:CreateRolePolicy*" in siblings
    # Other write verbs also surface (Modify / Set / Patch / Replace).
    assert "iam:ModifyRolePolicy*" in siblings
    assert "iam:SetRolePolicy*" in siblings


def test_lambda_create_function_includes_put_update_siblings() -> None:
    """``lambda:CreateFunction`` siblings include
    ``lambda:UpdateFunction*``, ``lambda:PutFunction*`` (Create bridges
    to Write band)."""
    siblings = sibling_action_prefixes("lambda:CreateFunction")
    assert "lambda:UpdateFunction*" in siblings
    assert "lambda:PutFunction*" in siblings
    # Source verb absent.
    assert "lambda:CreateFunction*" not in siblings


def test_s3_update_object_includes_put_create_siblings() -> None:
    """``Update``-shape source verb returns ``Put`` + ``Create``
    siblings."""
    siblings = sibling_action_prefixes("s3:UpdateObject")
    assert "s3:PutObject*" in siblings
    assert "s3:CreateObject*" in siblings


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
