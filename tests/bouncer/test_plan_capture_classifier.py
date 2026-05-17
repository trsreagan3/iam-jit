"""Unit tests for the plan-capture read/write classifier (#145).

The classifier is the deterministic predicate the proxy uses to drive
the read->write phase transition. Per [[scorer-is-ground-truth]] it
reuses `iam_jit.review._action_level` (policy_sentry) so the source of
truth is identical to the scorer's. The verb-prefix fallback covers
unknown-service / unknown-action cases.

Per [[ibounce-honest-positioning]] the classifier is the deterministic
half of a DETERRENT UX helper, not a security boundary — the value of
these tests is keeping the classifier honest about its three outputs
(read / write / unknown) so the UX downstream behaves predictably.
"""

from __future__ import annotations

import pytest

from iam_jit.bouncer.plan_capture.classifier import (
    classify_action,
    is_read,
    is_write,
)


# ---------------------------------------------------------------------------
# policy_sentry-backed classification (authoritative source)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("service,action", [
    # Read/List actions across several services
    ("s3", "GetObject"),
    ("s3", "ListBucket"),
    ("iam", "GetRole"),
    ("iam", "ListRoles"),
    ("ec2", "DescribeInstances"),
    ("sts", "GetCallerIdentity"),
])
def test_classifier_recognizes_read_actions(service, action):
    assert classify_action(service, action) == "read"
    assert is_read(service, action) is True
    assert is_write(service, action) is False


@pytest.mark.parametrize("service,action", [
    # Write / Tagging / Permissions-management actions
    ("s3", "PutObject"),
    ("s3", "DeleteObject"),
    ("iam", "CreateRole"),
    ("iam", "AttachRolePolicy"),  # Permissions management
    ("ec2", "RunInstances"),
    ("ec2", "TerminateInstances"),
    ("kms", "CreateKey"),
    ("lambda", "CreateFunction"),
])
def test_classifier_recognizes_write_actions(service, action):
    assert classify_action(service, action) == "write"
    assert is_write(service, action) is True
    assert is_read(service, action) is False


# ---------------------------------------------------------------------------
# Verb-prefix fallback
# ---------------------------------------------------------------------------


def test_unknown_service_with_write_prefix_classifies_write():
    """When policy_sentry can't resolve a service (brand-new service,
    typo'd name), the verb-prefix heuristic kicks in."""
    out = classify_action("not-a-real-service-xyz", "CreateThing")
    assert out == "write"
    assert is_write("not-a-real-service-xyz", "CreateThing") is True


def test_unknown_service_with_read_prefix_classifies_read():
    out = classify_action("not-a-real-service-xyz", "DescribeThing")
    assert out == "read"


def test_unknown_action_with_no_recognized_prefix_classifies_unknown():
    """An action whose prefix isn't on either heuristic list returns
    'unknown'. The is_write predicate treats unknown as write per the
    conservative-default policy."""
    # `Foozle` isn't a Read or Write prefix
    out = classify_action("not-a-real-service-xyz", "FoozleSomething")
    assert out == "unknown"
    # Conservative default: unknown counts as write for the UX prompt
    assert is_write("not-a-real-service-xyz", "FoozleSomething") is True
    # But NOT as read
    assert is_read("not-a-real-service-xyz", "FoozleSomething") is False


# ---------------------------------------------------------------------------
# Defensive paths
# ---------------------------------------------------------------------------


def test_empty_service_returns_unknown():
    assert classify_action("", "GetObject") == "unknown"


def test_empty_action_returns_unknown():
    assert classify_action("s3", "") == "unknown"


def test_classifier_handles_mixed_case_service():
    """Service is lowercased before policy_sentry lookup so a parser
    that handed us `S3` instead of `s3` still works."""
    assert classify_action("S3", "GetObject") == "read"


def test_classifier_writes_take_precedence_over_reads_on_prefix_collision():
    """Action with both read- and write-prefix-shape: write wins per
    the conservative-default policy.

    `Set` is a write prefix; an action like `SetGetSomething` would
    have BOTH prefixes match (Set first in the iter order). We assert
    that the writing classification wins."""
    # Synthetic action only meaningful in the heuristic path
    out = classify_action("unknown-service-xyz", "SetReadConfig")
    assert out == "write"
