# #727 / BUILD-6 — unit tests for the role-usage pure-function core.
"""Covers: used-vs-granted diff correctness, narrowed-policy
generation, empty/partial-usage honesty path, and JSON shape.

These tests pin ``all_actions`` explicitly (a small synthetic corpus)
so the granted-count expansion is deterministic + does NOT depend on
whether policy_sentry is installed in the test environment. A separate
test exercises the policy_sentry-absent fallback path directly.
"""

from __future__ import annotations

import typing

from iam_jit.role_usage import (
    NarrowedPolicy,
    RoleUsage,
    build_narrowed_policy,
    compute_role_usage,
    expand_granted,
    extract_granted_globs,
    extract_used,
)


# Synthetic AWS-action corpus so glob expansion is deterministic in
# tests regardless of the installed policy_sentry version.
_CORPUS = (
    "s3:GetObject",
    "s3:GetObjectAcl",
    "s3:GetBucketPolicy",
    "s3:ListBucket",
    "s3:ListAllMyBuckets",
    "s3:PutObject",
    "s3:DeleteObject",
    "ec2:DescribeInstances",
    "ec2:DescribeVolumes",
    "ec2:RunInstances",
    "iam:GetRole",
    "iam:CreateRole",
)


def _ev(
    action: str,
    *,
    resource: str | None = None,
    verdict: str | None = "allow",
) -> dict[str, typing.Any]:
    e: dict[str, typing.Any] = {
        "api": {
            "operation": action,
            "service": {"name": action.split(":")[0]},
        },
    }
    if resource:
        e["resources"] = [{"uid": resource, "name": resource}]
    if verdict is not None:
        e["unmapped"] = {"iam_jit": {"verdict": verdict}}
    return e


# ---------------------------------------------------------------------------
# Granted-set extraction + expansion
# ---------------------------------------------------------------------------


def test_extract_granted_globs_allow_only_str_and_list():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Allow", "Action": ["s3:List*", "ec2:Describe*"]},
            {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
        ],
    }
    globs = extract_granted_globs(policy)
    # Deny statement is excluded; both str + list Action forms picked up.
    assert globs == ["s3:GetObject", "s3:List*", "ec2:Describe*"]


def test_extract_granted_globs_tolerates_single_statement_dict():
    policy = {"Statement": {"Effect": "Allow", "Action": "s3:GetObject"}}
    assert extract_granted_globs(policy) == ["s3:GetObject"]


def test_expand_granted_action_level_count():
    globs = ["s3:Get*", "ec2:DescribeInstances"]
    granted, basis = expand_granted(globs, all_actions=_CORPUS)
    assert basis == "policy_sentry_action_expansion"
    # s3:Get* matches 3 corpus actions; ec2:DescribeInstances is literal.
    assert granted == frozenset({
        "s3:getobject",
        "s3:getobjectacl",
        "s3:getbucketpolicy",
        "ec2:describeinstances",
    })


def test_expand_granted_bare_star_expands_whole_corpus():
    granted, basis = expand_granted(["*"], all_actions=_CORPUS)
    assert basis == "policy_sentry_action_expansion"
    assert len(granted) == len(_CORPUS)


def test_expand_granted_fallback_when_no_corpus():
    # Simulate policy_sentry absent: pass an empty corpus → literal mode.
    granted, basis = expand_granted(
        ["s3:Get*", "s3:GetObject"], all_actions=[],
    )
    assert basis == "literal_glob_count"
    assert granted == frozenset({"s3:get*", "s3:getobject"})


# ---------------------------------------------------------------------------
# Used-set extraction
# ---------------------------------------------------------------------------


def test_extract_used_excludes_denied_calls():
    events = [
        _ev("s3:GetObject", resource="arn:aws:s3:::b/k", verdict="allow"),
        _ev("s3:DeleteObject", verdict="deny"),
    ]
    used = extract_used(events, allowed_only=True)
    assert set(used.keys()) == {"s3:GetObject"}


def test_extract_used_keeps_verdictless_events():
    # Older/synthetic events without a verdict count as used
    # (conservative: keeps more, narrows less).
    events = [_ev("s3:GetObject", verdict=None)]
    used = extract_used(events, allowed_only=True)
    assert set(used.keys()) == {"s3:GetObject"}


# ---------------------------------------------------------------------------
# Narrowed-policy generation
# ---------------------------------------------------------------------------


def test_build_narrowed_policy_scopes_to_observed_resources():
    used = {
        "s3:GetObject": {
            "resources": {"arn:aws:s3:::b/k1", "arn:aws:s3:::b/k2"},
            "count": 2,
        },
    }
    narrowed = build_narrowed_policy(used)
    assert isinstance(narrowed, NarrowedPolicy)
    assert narrowed.statement_count == 1
    stmt = narrowed.policy["Statement"][0]
    assert stmt["Effect"] == "Allow"
    assert stmt["Action"] == ["s3:GetObject"]
    assert stmt["Resource"] == ["arn:aws:s3:::b/k1", "arn:aws:s3:::b/k2"]
    assert narrowed.cannot_narrow_reason is None
    assert narrowed.policy["Version"] == "2012-10-17"


def test_build_narrowed_policy_flags_resourceless_action():
    used = {"s3:ListAllMyBuckets": {"resources": set(), "count": 1}}
    narrowed = build_narrowed_policy(used)
    stmt = narrowed.policy["Statement"][0]
    assert stmt["Resource"] == ["*"]
    assert any("ListAllMyBuckets" in n for n in narrowed.notes)


def test_build_narrowed_policy_empty_is_honest():
    narrowed = build_narrowed_policy({})
    assert narrowed.statement_count == 0
    assert narrowed.policy["Statement"] == []
    assert narrowed.cannot_narrow_reason is not None
    assert "unused" in narrowed.cannot_narrow_reason


# ---------------------------------------------------------------------------
# Top-level orchestrator — diff correctness
# ---------------------------------------------------------------------------


def _granted(actions: list[str]) -> dict[str, typing.Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    }


def test_compute_role_usage_used_vs_granted_correctness():
    granted = _granted(["s3:Get*", "s3:List*", "ec2:Describe*"])
    events = [
        _ev("s3:GetObject", resource="arn:aws:s3:::b/k"),
        _ev("s3:GetObject", resource="arn:aws:s3:::b/k2"),
        _ev("s3:ListBucket", resource="arn:aws:s3:::b"),
        _ev("s3:DeleteObject", verdict="deny"),  # denied -> not used
    ]
    u = compute_role_usage(
        session_id="SID1",
        granted_policy=granted,
        events=events,
        all_actions=_CORPUS,
    )
    # Granted expands: s3:Get* (3) + s3:List* (2) + ec2:Describe* (2) = 7.
    assert u.granted_count == 7
    assert u.granted_count_basis == "policy_sentry_action_expansion"
    # Used = the two distinct allowed actions.
    assert u.used_count == 2
    assert [a.action for a in u.used_actions] == [
        "s3:GetObject", "s3:ListBucket",
    ]
    # Headline is the human framing.
    assert u.headline() == "Used 2 of 7 granted permissions"
    # Unused = granted concrete actions never exercised.
    assert "s3:getobjectacl" in u.unused_permissions
    assert "ec2:describeinstances" in u.unused_permissions
    assert "s3:getobject" not in u.unused_permissions
    # Nothing used outside the grant.
    assert u.used_outside_grant == ()


def test_compute_role_usage_detects_used_outside_grant():
    # Operator passes a read-only policy, but the session somehow shows
    # a write (e.g. cooperative/advisory mode let it through). Honest
    # mismatch signal, not silently dropped.
    granted = _granted(["s3:Get*"])
    events = [
        _ev("s3:GetObject", resource="arn:aws:s3:::b/k"),
        _ev("s3:PutObject", resource="arn:aws:s3:::b/k"),  # not granted
    ]
    u = compute_role_usage(
        session_id="SID2",
        granted_policy=granted,
        events=events,
        all_actions=_CORPUS,
    )
    assert u.used_outside_grant == ("s3:putobject",)
    assert any("not covered" in c for c in u.caveats)


def test_compute_role_usage_empty_usage_honesty_path():
    granted = _granted(["s3:Get*", "ec2:Describe*"])
    u = compute_role_usage(
        session_id="SID3",
        granted_policy=granted,
        events=[],  # read-only session / no gated calls / empty window
        all_actions=_CORPUS,
    )
    assert u.used_count == 0
    assert u.events_analyzed == 0
    assert u.narrowed.cannot_narrow_reason is not None
    # Never claims completeness; surfaces the read-only/empty caveat.
    assert u.usage_is_complete is False
    assert any("read-only" in c.lower() for c in u.caveats)
    assert any("floor" in c.lower() for c in u.caveats)


def test_compute_role_usage_never_claims_completeness_even_when_full():
    # Even when every granted action is used, the narrowed policy is
    # framed as a floor per [[ibounce-honest-positioning]].
    granted = _granted(["s3:GetObject"])
    events = [_ev("s3:GetObject", resource="arn:aws:s3:::b/k")]
    u = compute_role_usage(
        session_id="SID4",
        granted_policy=granted,
        events=events,
        all_actions=_CORPUS,
    )
    assert u.used_count == 1
    assert u.granted_count == 1
    assert u.unused_permissions == ()
    assert u.usage_is_complete is False
    assert any("floor" in c.lower() for c in u.caveats)


def test_compute_role_usage_literal_glob_fallback_caveat():
    granted = _granted(["s3:Get*"])
    events = [_ev("s3:GetObject", resource="arn:aws:s3:::b/k")]
    u = compute_role_usage(
        session_id="SID5",
        granted_policy=granted,
        events=events,
        all_actions=[],  # policy_sentry absent
    )
    assert u.granted_count_basis == "literal_glob_count"
    # s3:Get* glob is "used" because s3:getobject matches it.
    assert u.unused_permissions == ()
    assert any("GLOB count" in c for c in u.caveats)


# ---------------------------------------------------------------------------
# JSON shape
# ---------------------------------------------------------------------------


def test_role_usage_as_dict_shape():
    granted = _granted(["s3:Get*"])
    events = [_ev("s3:GetObject", resource="arn:aws:s3:::b/k")]
    u = compute_role_usage(
        session_id="SID6",
        granted_policy=granted,
        events=events,
        all_actions=_CORPUS,
        notes=("ibounce: ok",),
    )
    d = u.as_dict()
    assert set(d.keys()) == {
        "session_id",
        "events_analyzed",
        "granted_count",
        "used_count",
        "granted_count_basis",
        "used_actions",
        "unused_permissions",
        "used_outside_grant",
        "narrowed",
        "usage_is_complete",
        "caveats",
        "notes",
    }
    assert isinstance(d["used_actions"], list)
    assert d["used_actions"][0] == {
        "action": "s3:GetObject",
        "resources": ["arn:aws:s3:::b/k"],
        "count": 1,
    }
    assert set(d["narrowed"].keys()) == {
        "policy", "statement_count", "cannot_narrow_reason", "notes",
    }
    # Fully JSON-serialisable.
    import json
    json.dumps(d)
    assert isinstance(u, RoleUsage)
