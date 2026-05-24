"""Phase 3 prerequisite — state-verification tests for the public
``is_known_adversarial`` predicate.

Per ``docs/PROFILE-GENERATION-DESIGN.md`` §3.5 acceptance #4 + §7
safeguard #2 the catalogue-match predicate must be a public symbol
shared between three surfaces:

  * ``iam_jit_classify_deny`` (existing — already used the private
    ``_is_known_adversarial`` in classifier.py)
  * ``bounce_simulate_profile`` (Phase 5 — future)
  * ``bounce_grade_profile_for_workflow`` (Phase 7 — future)

This test file pins:
  * Public-import path works (no `_` prefix; module-level visibility).
  * Behaviour matches the pre-extraction private predicate (regression
    check — all 7 KNOWN_ADVERSARIAL override tests from Phase 1 still
    pass; this file adds direct-call coverage of the public predicate).
  * Backward-compat shim ``_is_known_adversarial(action)`` still
    works (evaluator + structured_deny + the classifier itself still
    import the private name).

Per CONTRIBUTING.md state-verification: the predicate's return value
IS the observable state. Tests assert the BOOLEAN return per input;
not just "no crash."
"""

from __future__ import annotations

import pytest

# Public-import path — the load-bearing acceptance for prereq 4.
from iam_jit.deny_classifier import is_known_adversarial
from iam_jit.deny_classifier.classifier import (
    _is_known_adversarial,
    is_known_adversarial as is_known_adversarial_via_classifier,
)


# ---------------------------------------------------------------------------
# Public-import path acceptance
# ---------------------------------------------------------------------------


def test_public_predicate_importable_from_package() -> None:
    """The public predicate must be importable as
    ``from iam_jit.deny_classifier import is_known_adversarial``
    (the package re-export). Pin the public API so future refactors
    don't accidentally make it private again."""
    # The import at module top is the test; verifying callable shape:
    assert callable(is_known_adversarial)
    # Identity check: package re-export is the same callable as the
    # module-level definition.
    assert is_known_adversarial is is_known_adversarial_via_classifier


def test_public_predicate_importable_from_classifier_module() -> None:
    """Both the package and the module path expose the symbol — the
    classifier module path is the direct path used by tests + internal
    callers."""
    from iam_jit.deny_classifier.classifier import is_known_adversarial as _direct
    assert callable(_direct)


# ---------------------------------------------------------------------------
# Regression — pre-extraction private predicate behaviour preserved
# ---------------------------------------------------------------------------


def test_iam_create_access_key_matches() -> None:
    """AWS IAM persistence pattern — pre-extraction case."""
    assert is_known_adversarial("iam:CreateAccessKey") is True


def test_case_insensitive_aws_match() -> None:
    """Case-insensitive: ``iam:createaccesskey`` matches per the
    deny_classifier's legacy behaviour."""
    assert is_known_adversarial("iam:createaccesskey") is True


def test_s3_delete_bucket_matches() -> None:
    """AWS destruction shape."""
    assert is_known_adversarial("s3:DeleteBucket") is True


def test_benign_get_does_not_match() -> None:
    """``s3:GetObject`` is benign — must NOT match."""
    assert is_known_adversarial("s3:GetObject") is False


def test_drop_table_substring_match() -> None:
    """SQL ``DROP TABLE`` is a phrase-level catalogue entry; matches
    via substring."""
    assert is_known_adversarial("DROP TABLE users") is True


def test_unbounded_delete_regex_match() -> None:
    """``DELETE FROM orders`` (no WHERE) matches via the unbounded-
    DELETE regex check (legacy deny_classifier behaviour preserved)."""
    assert is_known_adversarial("DELETE FROM orders") is True


def test_bounded_delete_does_not_match() -> None:
    """``DELETE FROM orders WHERE id = 1`` is bounded; must not match."""
    assert is_known_adversarial("DELETE FROM orders WHERE id = 1") is False


def test_kubectl_delete_namespace_phrase_match() -> None:
    """``kubectl delete namespace prod`` matches via substring."""
    assert is_known_adversarial("kubectl delete namespace prod") is True


def test_kubectl_get_pods_does_not_match() -> None:
    """``kubectl get pods`` is benign; must not match."""
    assert is_known_adversarial("kubectl get pods") is False


def test_empty_action_returns_false() -> None:
    """Empty / None input returns False safely; no crash."""
    assert is_known_adversarial("") is False
    assert is_known_adversarial(None) is False  # type: ignore[arg-type]


def test_benign_ec2_describe_does_not_match() -> None:
    """``ec2:DescribeInstances`` is benign."""
    assert is_known_adversarial("ec2:DescribeInstances") is False


# ---------------------------------------------------------------------------
# New capability — bouncer-aware phrase reconstruction
# ---------------------------------------------------------------------------


def test_kbouncer_phrase_reconstruction_namespace_delete() -> None:
    """The profile_heuristic-style call: action=verb, bouncer=kbouncer,
    resource=resource-string. Reconstructs ``kubectl delete <resource>``
    and matches against catalogue."""
    assert is_known_adversarial(
        "delete", bouncer="kbouncer", resource="namespace/staging"
    ) is True


def test_kbouncer_phrase_reconstruction_benign_pod_get() -> None:
    """Benign K8s read on a non-adversarial resource must not match."""
    assert is_known_adversarial(
        "get", bouncer="kbouncer", resource="pods/web-1"
    ) is False


def test_kbouncer_short_alias_normalised() -> None:
    """``kbounce`` short alias normalises to ``kbouncer``."""
    assert is_known_adversarial(
        "delete", bouncer="kbounce", resource="namespace/prod"
    ) is True


def test_dbounce_phrase_reconstruction_delete_from_users() -> None:
    """Profile_heuristic flow: action=``DELETE``, resource=``FROM users``
    reconstructs ``DELETE FROM USERS`` matching ``DELETE FROM users``."""
    assert is_known_adversarial(
        "DELETE", bouncer="dbounce", resource="FROM users"
    ) is True


def test_dbounce_drop_table_via_resource_composition() -> None:
    """``DROP`` + resource=``TABLE orders`` reconstructs
    ``DROP TABLE ORDERS`` matching ``DROP TABLE``."""
    assert is_known_adversarial(
        "DROP", bouncer="dbounce", resource="TABLE orders"
    ) is True


def test_dbounce_dialect_prefix_stripped() -> None:
    """A ``psql:Drop Table`` action normalises via
    ``strip_dialect_prefix`` and matches the catalogue."""
    assert is_known_adversarial(
        "psql:Drop Table", bouncer="dbounce", resource="users"
    ) is True


def test_ibounce_no_phrase_reconstruction_falls_to_direct_match() -> None:
    """ibounce doesn't reconstruct phrases — the AWS catalogue is
    direct-match only. Verify the bouncer arg doesn't change AWS
    behaviour."""
    assert is_known_adversarial(
        "s3:DeleteBucket", bouncer="ibounce", resource="arn:aws:s3:::b"
    ) is True
    assert is_known_adversarial(
        "s3:GetObject", bouncer="ibounce", resource="arn:aws:s3:::b"
    ) is False


def test_unknown_bouncer_falls_back_to_legacy_match() -> None:
    """An unknown bouncer arg gracefully falls back to the legacy
    case-insensitive catalogue match — no crash."""
    assert is_known_adversarial(
        "iam:CreateAccessKey", bouncer="frobnicator", resource="*"
    ) is True


# ---------------------------------------------------------------------------
# Backward-compat shim — existing private symbol still works
# ---------------------------------------------------------------------------


def test_legacy_private_symbol_delegates_to_public() -> None:
    """The legacy ``_is_known_adversarial(action)`` symbol that
    evaluator + structured_deny + classifier internals import must
    keep working — verify it delegates to the public predicate."""
    # Pre-extraction the private predicate returned True for
    # iam:CreateAccessKey; the shim must too.
    assert _is_known_adversarial("iam:CreateAccessKey") is True
    assert _is_known_adversarial("s3:GetObject") is False
    assert _is_known_adversarial("DROP TABLE users") is True
    assert _is_known_adversarial("") is False


def test_legacy_evaluator_callers_still_work() -> None:
    """The deny_classifier.evaluator module imports
    ``_is_known_adversarial`` directly — verify the symbol is still
    present + functional."""
    from iam_jit.deny_classifier.evaluator import _is_known_adversarial as _via_evaluator
    assert _via_evaluator("iam:CreateAccessKey") is True


def test_structured_deny_callers_still_work() -> None:
    """structured_deny.response imports ``_is_known_adversarial`` per
    the late-binding import in its module body — verify the import
    path remains stable."""
    from iam_jit.deny_classifier.classifier import _is_known_adversarial as _via_classifier
    assert callable(_via_classifier)
    assert _via_classifier("cloudtrail:StopLogging") is True


# ---------------------------------------------------------------------------
# Pure function discipline
# ---------------------------------------------------------------------------


def test_pure_function_stable_across_repeats() -> None:
    """Per the classifier discipline: pure function, same inputs always
    same output. Identity-stable across 100 calls catches accidental
    caches keying wrong."""
    results = [
        is_known_adversarial("iam:CreateAccessKey")
        for _ in range(100)
    ]
    assert all(r is True for r in results)


# ---------------------------------------------------------------------------
# Cross-module identity — profile_heuristic.classify uses the same
# predicate the deny_classifier exposes
# ---------------------------------------------------------------------------


def test_profile_heuristic_uses_public_predicate() -> None:
    """Verify the profile_heuristic.classify module now imports the
    public predicate (not its own private copy). This is the
    "single source of truth" acceptance — when a future change adds a
    new pattern to KNOWN_ADVERSARIAL_PATTERNS, both surfaces see it
    without manual sync."""
    # profile_heuristic.classify imports the public predicate as
    # _public_is_known_adversarial — verify that import path works.
    from iam_jit.profile_heuristic.classify import (
        _public_is_known_adversarial as _imported,
    )
    assert _imported is is_known_adversarial
