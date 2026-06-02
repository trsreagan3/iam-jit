# ADOPT-5 / #719 — tests for the IAM <-> Cedar interop translator.
"""Tests for :mod:`iam_jit.cedar`.

Coverage:
  * round-trip-able simple policies (IAM -> Cedar -> IAM preserves
    semantics);
  * known IAM constructs map to the expected Cedar shape;
  * UNTRANSLATABLE constructs (NotAction/NotResource/NotPrincipal,
    embedded wildcards, exotic condition operators, Cedar `unless` /
    attribute refs) produce explicit notes/markers and are NOT silently
    dropped or wrongly translated;
  * malformed input raises a clean TranslationError;
  * JSON / text shapes from the public API.
"""

from __future__ import annotations

import json

import pytest

from iam_jit.cedar import (
    TranslationError,
    cedar_to_iam,
    iam_to_cedar,
)


# ---------------------------------------------------------------------------
# IAM -> Cedar : known constructs
# ---------------------------------------------------------------------------


def test_allow_single_action_single_resource():
    p = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/key",
            }
        ],
    }
    r = iam_to_cedar(p)
    assert "permit (" in r.output
    assert 'action == Action::"s3:GetObject"' in r.output
    assert 'resource == IamResource::"arn:aws:s3:::bucket/key"' in r.output
    assert not r.is_lossy
    assert not r.has_untranslatable


def test_deny_maps_to_forbid():
    p = {"Statement": [{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}]}
    r = iam_to_cedar(p)
    assert "forbid (" in r.output
    assert "permit (" not in r.output


def test_action_list_maps_to_in():
    p = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*",
            }
        ]
    }
    r = iam_to_cedar(p)
    assert 'action in [Action::"s3:GetObject", Action::"s3:ListBucket"]' in r.output


def test_star_action_is_unconstrained():
    p = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    r = iam_to_cedar(p)
    # bare `action` / `resource` with no `==`
    assert "action," in r.output or "action\n" in r.output
    assert not r.has_untranslatable


def test_sid_emitted_as_comment():
    p = {"Statement": [{"Sid": "AllowRead", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    r = iam_to_cedar(p)
    assert "// Sid: AllowRead" in r.output


def test_single_statement_dict_form():
    # AWS grammar allows Statement to be a single object, not a list.
    p = {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
    r = iam_to_cedar(p)
    assert "permit (" in r.output


def test_resource_based_principal_typed():
    p = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        ]
    }
    r = iam_to_cedar(p)
    assert 'principal == IamPrincipal::"arn:aws:iam::123456789012:root"' in r.output


# ---------------------------------------------------------------------------
# IAM -> Cedar : faithful conditions
# ---------------------------------------------------------------------------


def test_string_equals_condition():
    p = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"StringEquals": {"s3:prefix": "home"}},
            }
        ]
    }
    r = iam_to_cedar(p)
    assert 'context["s3:prefix"] == "home"' in r.output
    assert "when {" in r.output
    assert not r.has_untranslatable


def test_bool_condition():
    p = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}},
            }
        ]
    }
    r = iam_to_cedar(p)
    assert 'context["aws:SecureTransport"] == true' in r.output
    assert not r.has_untranslatable


# ---------------------------------------------------------------------------
# IAM -> Cedar : UNTRANSLATABLE — must be loud, not silently wrong
# ---------------------------------------------------------------------------


def test_not_action_is_untranslatable_and_marked():
    p = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
    r = iam_to_cedar(p)
    assert r.has_untranslatable
    assert "// UNTRANSLATABLE: NotAction" in r.output
    notes = [n for n in r.notes if n.construct == "NotAction"]
    assert notes and notes[0].severity == "untranslatable"
    # The forbidden list must NOT have been emitted as a positive action
    # (that would invert the meaning).
    assert 'Action::"iam:*"' not in r.output


def test_not_resource_is_untranslatable():
    p = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret"}]}
    r = iam_to_cedar(p)
    assert r.has_untranslatable
    assert "// UNTRANSLATABLE: NotResource" in r.output


def test_not_principal_is_untranslatable():
    p = {
        "Statement": [
            {
                "Effect": "Deny",
                "NotPrincipal": {"AWS": "arn:aws:iam::1:root"},
                "Action": "s3:*",
                "Resource": "*",
            }
        ]
    }
    r = iam_to_cedar(p)
    assert r.has_untranslatable
    assert "// UNTRANSLATABLE: NotPrincipal" in r.output


def test_embedded_action_wildcard_is_lossy_not_expanded():
    p = {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}
    r = iam_to_cedar(p)
    assert r.is_lossy
    # Preserved literally — NOT silently expanded to the matching family.
    assert 'Action::"s3:Get*"' in r.output
    notes = [n for n in r.notes if n.construct == "Action"]
    assert notes and notes[0].severity == "lossy"


def test_embedded_resource_wildcard_is_lossy():
    p = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]}
    r = iam_to_cedar(p)
    assert r.is_lossy
    assert 'IamResource::"arn:aws:s3:::bucket/*"' in r.output


def test_exotic_condition_operator_is_untranslatable():
    p = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"StringLike": {"s3:prefix": "home/*"}},
            }
        ]
    }
    r = iam_to_cedar(p)
    assert r.has_untranslatable
    assert "// UNTRANSLATABLE: Condition.StringLike" in r.output
    # Must NOT have emitted a wrong `==` for the StringLike.
    assert 'context["s3:prefix"] ==' not in r.output


def test_mixed_faithful_and_exotic_condition():
    # The faithful operator translates; the exotic one is flagged. The
    # statement is NOT dropped wholesale.
    p = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"s3:prefix": "home"},
                    "DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"},
                },
            }
        ]
    }
    r = iam_to_cedar(p)
    assert 'context["s3:prefix"] == "home"' in r.output
    assert "// UNTRANSLATABLE: Condition.DateGreaterThan" in r.output


# ---------------------------------------------------------------------------
# IAM -> Cedar : malformed input
# ---------------------------------------------------------------------------


def test_missing_statement_raises():
    with pytest.raises(TranslationError):
        iam_to_cedar({"Version": "2012-10-17"})


def test_invalid_effect_raises():
    with pytest.raises(TranslationError):
        iam_to_cedar({"Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}]})


def test_action_missing_raises():
    with pytest.raises(TranslationError):
        iam_to_cedar({"Statement": [{"Effect": "Allow", "Resource": "*"}]})


def test_non_json_string_raises():
    with pytest.raises(TranslationError):
        iam_to_cedar("{not json")


def test_non_dict_input_raises():
    with pytest.raises(TranslationError):
        iam_to_cedar(42)  # type: ignore[arg-type]


def test_accepts_json_string_input():
    s = json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    r = iam_to_cedar(s)
    assert "permit (" in r.output


# ---------------------------------------------------------------------------
# Cedar -> IAM
# ---------------------------------------------------------------------------


def test_cedar_to_iam_basic():
    cedar = 'permit ( principal, action == Action::"s3:GetObject", resource == IamResource::"arn:aws:s3:::b/k" );'
    r = cedar_to_iam(cedar)
    stmt = r.policy["Statement"][0]
    assert stmt["Effect"] == "Allow"
    assert stmt["Action"] == "s3:GetObject"
    assert stmt["Resource"] == "arn:aws:s3:::b/k"


def test_cedar_forbid_to_deny():
    cedar = 'forbid ( principal, action == Action::"s3:DeleteObject", resource );'
    r = cedar_to_iam(cedar)
    stmt = r.policy["Statement"][0]
    assert stmt["Effect"] == "Deny"
    assert stmt["Resource"] == "*"


def test_cedar_action_in_list():
    cedar = 'permit ( principal, action in [Action::"s3:GetObject", Action::"s3:ListBucket"], resource );'
    r = cedar_to_iam(cedar)
    assert r.policy["Statement"][0]["Action"] == ["s3:GetObject", "s3:ListBucket"]


def test_cedar_when_string_equals():
    cedar = (
        'permit ( principal, action == Action::"s3:GetObject", resource )\n'
        'when { context["s3:prefix"] == "home" };'
    )
    r = cedar_to_iam(cedar)
    cond = r.policy["Statement"][0]["Condition"]
    assert cond["StringEquals"]["s3:prefix"] == "home"


def test_cedar_when_bool():
    cedar = (
        'permit ( principal, action == Action::"s3:GetObject", resource )\n'
        'when { context["aws:SecureTransport"] == true };'
    )
    r = cedar_to_iam(cedar)
    assert r.policy["Statement"][0]["Condition"]["Bool"]["aws:SecureTransport"] == "true"


def test_cedar_unless_is_untranslatable():
    cedar = (
        'permit ( principal, action == Action::"s3:GetObject", resource )\n'
        'unless { context["x"] == "y" };'
    )
    r = cedar_to_iam(cedar)
    assert r.has_untranslatable
    notes = [n for n in r.notes if n.construct == "unless"]
    assert notes
    # The negated condition must NOT have been turned into a positive
    # StringEquals (that would invert the meaning).
    assert "Condition" not in r.policy["Statement"][0]


def test_cedar_attribute_ref_is_untranslatable():
    cedar = (
        'permit ( principal, action == Action::"s3:GetObject", resource )\n'
        "when { resource.owner == principal };"
    )
    r = cedar_to_iam(cedar)
    assert r.has_untranslatable
    assert "Condition" not in r.policy["Statement"][0]


def test_cedar_template_slot_is_untranslatable():
    cedar = 'permit ( principal == ?principal, action, resource );'
    r = cedar_to_iam(cedar)
    assert r.has_untranslatable
    # Conservative: principal left as any (*).
    assert r.policy["Statement"][0]["Principal"] == "*"


def test_cedar_malformed_raises():
    with pytest.raises(TranslationError):
        cedar_to_iam("this is not cedar")


def test_cedar_empty_raises():
    with pytest.raises(TranslationError):
        cedar_to_iam("   \n // only a comment \n")


def test_cedar_to_iam_non_string_raises():
    with pytest.raises(TranslationError):
        cedar_to_iam({"not": "a string"})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Round-trip : IAM -> Cedar -> IAM preserves semantics (faithful subset)
# ---------------------------------------------------------------------------


def _roundtrip(stmt: dict) -> dict:
    fwd = iam_to_cedar({"Version": "2012-10-17", "Statement": [stmt]})
    assert not fwd.is_lossy, f"forward unexpectedly lossy: {fwd.notes}"
    back = cedar_to_iam(fwd.output)
    assert not back.is_lossy, f"back unexpectedly lossy: {back.notes}"
    return back.policy["Statement"][0]


def test_roundtrip_single_action_resource():
    out = _roundtrip(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/k"}
    )
    assert out["Effect"] == "Allow"
    assert out["Action"] == "s3:GetObject"
    assert out["Resource"] == "arn:aws:s3:::b/k"


def test_roundtrip_action_list():
    out = _roundtrip(
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "arn:aws:s3:::b"}
    )
    assert out["Action"] == ["s3:GetObject", "s3:ListBucket"]


def test_roundtrip_deny():
    out = _roundtrip({"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"})
    assert out["Effect"] == "Deny"
    assert out["Resource"] == "*"


def test_roundtrip_string_equals_condition():
    out = _roundtrip(
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::b/k",
            "Condition": {"StringEquals": {"s3:prefix": "home"}},
        }
    )
    assert out["Condition"]["StringEquals"]["s3:prefix"] == "home"


def test_roundtrip_multi_statement():
    p = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/k"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ],
    }
    fwd = iam_to_cedar(p)
    assert not fwd.is_lossy
    back = cedar_to_iam(fwd.output)
    assert len(back.policy["Statement"]) == 2
    assert back.policy["Statement"][0]["Effect"] == "Allow"
    assert back.policy["Statement"][1]["Effect"] == "Deny"


# ---------------------------------------------------------------------------
# Public API shapes
# ---------------------------------------------------------------------------


def test_result_as_dict_shape():
    r = iam_to_cedar({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    d = r.as_dict()
    assert d["direction"] == "iam->cedar"
    assert isinstance(d["output"], str)
    assert d["is_lossy"] is False
    assert d["has_untranslatable"] is False
    assert isinstance(d["notes"], list)


def test_cedar_result_includes_policy():
    r = cedar_to_iam('permit ( principal, action == Action::"s3:GetObject", resource );')
    d = r.as_dict()
    assert d["direction"] == "cedar->iam"
    assert "policy" in d
    assert d["policy"]["Version"] == "2012-10-17"


def test_note_severity_levels():
    r = iam_to_cedar({"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]})
    severities = {n.severity for n in r.notes}
    assert "untranslatable" in severities


# ---------------------------------------------------------------------------
# LIST-valued StringEquals conditions (IAM = OR / set membership).
# REGRESSION: a list of values for one key MUST become Cedar set
# membership — NOT an unsatisfiable `&&` chain of equalities that would
# silently turn a Deny/forbid into a no-op shipped as is_lossy=False.
# ---------------------------------------------------------------------------


def test_deny_list_string_equals_is_satisfiable_set_membership():
    # The exact CRIT repro: a Deny whose condition lists two values.
    r = iam_to_cedar(
        {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalTag/team": ["red", "blue"]
                        }
                    },
                }
            ]
        }
    )
    out = r.output
    # Must be a forbid (the Deny) ...
    assert "forbid (" in out
    # ... using set membership that is true when team in {red, blue}.
    assert '["red", "blue"].contains(context["aws:PrincipalTag/team"])' in out
    # The unsatisfiable `&&` form must NOT appear: a single value can't
    # equal two distinct strings, so AND-joining equalities is never true.
    assert (
        'context["aws:PrincipalTag/team"] == "red" &&\n'
        '        context["aws:PrincipalTag/team"] == "blue"'
        not in out
    )
    assert '== "red" &&' not in out
    # Faithful: not lossy, no untranslatable marker, no silent no-op.
    assert not r.is_lossy
    assert not r.has_untranslatable


def test_roundtrip_list_string_equals_preserves_all_values():
    p = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalTag/team": ["red", "blue"]
                    }
                },
            }
        ]
    }
    fwd = iam_to_cedar(p)
    back = cedar_to_iam(fwd.output)
    cond = back.policy["Statement"][0]["Condition"]
    values = cond["StringEquals"]["aws:PrincipalTag/team"]
    # All list values preserved (no silent last-wins drop), order kept.
    assert values == ["red", "blue"]
    assert not back.is_lossy


def test_roundtrip_three_value_list():
    p = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"s3:prefix": ["a", "b", "c"]}
                },
            }
        ]
    }
    fwd = iam_to_cedar(p)
    assert '["a", "b", "c"].contains(context["s3:prefix"])' in fwd.output
    back = cedar_to_iam(fwd.output)
    assert back.policy["Statement"][0]["Condition"]["StringEquals"][
        "s3:prefix"
    ] == ["a", "b", "c"]


def test_allow_list_string_equals_is_set_membership():
    r = iam_to_cedar(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"s3:prefix": ["home", "shared"]}
                    },
                }
            ]
        }
    )
    assert "permit (" in r.output
    assert '["home", "shared"].contains(context["s3:prefix"])' in r.output
    assert '== "home" &&' not in r.output
    assert not r.is_lossy
    assert not r.has_untranslatable
