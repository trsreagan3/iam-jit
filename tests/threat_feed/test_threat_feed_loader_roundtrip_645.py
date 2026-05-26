"""#645 CRIT regression — threat-feed source enum was rejected by loader.

State-verification tests per [[install-ux-gap-2026-05-26]] discipline:
exercises the FULL chain (no mocks) from threat-feed applier → YAML on disk →
loader validation.

Root cause: loader.py source enum was ("cli", "mcp", "org-distributed",
"imported"); "threat-feed" was missing. Every threat-feed-auto-applied rule
triggered parse_error + bouncer reverted to last-good snapshot silently.

Test inventory:
  1. full_chain_no_parse_error — real applier → real loader; rule IS present.
  2. sabotage_check — monkeypatch VALID_SOURCES to remove "threat-feed";
     confirm loader raises DynamicDenyLoadError (proves enum is load-bearing).
  3. backward_compat — existing four sources all still load successfully.
  4. over_permissive_guard — unknown source still raises (no regression).
  5. applier_regression — extend test_applier pattern: after apply_feed_entries,
     read file + invoke real loader; assert no parse_error.
"""

from __future__ import annotations

import pathlib

import pytest

import iam_jit.dynamic_denies.loader as _loader_mod
from iam_jit.dynamic_denies.loader import (
    DynamicDenyLoadError,
    VALID_SOURCES,
    load_file,
)
from iam_jit.threat_feed import (
    Severity,
    Subscription,
    apply_feed_entries,
    ed25519_keygen,
    ed25519_sign_entry,
)
from iam_jit.threat_feed.models import Feed, FeedEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(rule_id: str = "tf_CRIT_645", severity: Severity = Severity.CRITICAL) -> FeedEntry:
    return FeedEntry(
        rule_id=rule_id,
        rule_kind="dynamic_deny",
        target="arn:aws:iam::*:role/agent-*",
        action=("iam:AttachRolePolicy",),
        severity=severity,
        source_incident="INC-645",
        discovered_at="2026-05-26T00:00:00Z",
        applies_to_bouncers=("ibounce",),
        compliance_tags=("NIST-AC-6",),
        description="#645 regression entry",
    )


def _make_signed_feed(
    entries: list[FeedEntry],
    priv_pem: str,
    pub_pem: str,
) -> tuple[Feed, Subscription]:
    signed = [
        ed25519_sign_entry(e, private_key_pem=priv_pem, publisher="test-645")
        for e in entries
    ]
    feed = Feed(
        schema_version="1.0",
        feed_id="test-645-v1",
        publisher="test-645",
        generated_at="2026-05-26T00:00:00Z",
        entries=tuple(signed),
        manifest_sha256="x",
    )
    sub = Subscription(
        url="file:///tmp/test-645",
        publisher_pubkey=pub_pem,
        verification_mode="ed25519",
        severity_auto_apply_threshold=Severity.HIGH,
    )
    return feed, sub


# ---------------------------------------------------------------------------
# Test 1 — full-chain, no parse_error (THE bug-catching test)
# ---------------------------------------------------------------------------


def test_full_chain_threat_feed_rule_loads_without_parse_error(tmp_path, monkeypatch):
    """Real applier → YAML written to disk → real loader.

    Before #645 fix: loader raised DynamicDenyLoadError (source "threat-feed"
    not in enum) so bouncer silently reverted to last-good snapshot.
    After fix: loader returns a RuleSet that contains the rule.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    deny_path = tmp_path / "dynamic-denies.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(deny_path))
    monkeypatch.setenv("IAM_JIT_THREAT_FEED_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("IAM_JIT_THREAT_FEED_LEDGER_PATH", str(tmp_path / "applied.jsonl"))
    monkeypatch.setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", str(tmp_path / "pending.jsonl"))

    priv, pub = ed25519_keygen()
    entry = _make_entry()
    feed, sub = _make_signed_feed([entry], priv, pub)

    # Apply via REAL applier — writes dynamic-denies.yaml with source="threat-feed"
    outcomes = apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    assert outcomes[0].action in ("auto_apply", "auto_apply_notify"), (
        f"Expected auto-apply outcome; got {outcomes[0].action}"
    )
    assert outcomes[0].applied_artifact_id.startswith("dd_"), (
        f"Expected dd_ artifact id; got {outcomes[0].applied_artifact_id!r}"
    )

    # YAML must now exist on disk
    assert deny_path.exists(), "Applier did not write dynamic-denies.yaml"

    # Invoke REAL loader — this is the integration boundary that was broken
    # #645: loader would raise DynamicDenyLoadError here because "threat-feed"
    # was not in the source enum.
    ruleset = load_file(str(deny_path))

    # Assert rule IS present (no parse_error, no revert-to-empty)
    assert len(ruleset.rules) >= 1, (
        f"Loader returned 0 rules — likely rejected 'threat-feed' source. "
        f"total_rules_in_file={ruleset.total_rules_in_file}"
    )

    # Assert source field equals "threat-feed" on the loaded rule
    rule = ruleset.rules[0]
    assert rule.source == "threat-feed", (
        f"Expected source='threat-feed', got {rule.source!r}"
    )

    # Assert the rule matches the threat-feed entry (provenance + id)
    assert rule.id == outcomes[0].applied_artifact_id, (
        f"Rule id mismatch: loaded={rule.id!r}, applied={outcomes[0].applied_artifact_id!r}"
    )


# ---------------------------------------------------------------------------
# Test 2 — sabotage check (proves the enum is load-bearing)
# ---------------------------------------------------------------------------


def test_sabotage_without_threat_feed_in_enum_causes_parse_error(tmp_path, monkeypatch):
    """Monkeypatch VALID_SOURCES to remove 'threat-feed'; confirm loader
    raises DynamicDenyLoadError. Proves the enum is load-bearing — if this
    test passes without the fix applied, the enum is NOT being consulted.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    deny_path = tmp_path / "dynamic-denies.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(deny_path))
    monkeypatch.setenv("IAM_JIT_THREAT_FEED_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("IAM_JIT_THREAT_FEED_LEDGER_PATH", str(tmp_path / "applied.jsonl"))
    monkeypatch.setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", str(tmp_path / "pending.jsonl"))

    priv, pub = ed25519_keygen()
    entry = _make_entry(rule_id="tf_SABOTAGE_645")
    feed, sub = _make_signed_feed([entry], priv, pub)

    # Apply via real applier to write the YAML with source="threat-feed"
    outcomes = apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    assert deny_path.exists()
    assert outcomes[0].applied_artifact_id.startswith("dd_")

    # Sabotage: remove "threat-feed" from VALID_SOURCES — simulates pre-fix state
    sabotaged = frozenset(s for s in VALID_SOURCES if s != "threat-feed")
    monkeypatch.setattr(_loader_mod, "VALID_SOURCES", sabotaged)

    # Loader must now raise — if it doesn't, the enum isn't being consulted
    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(str(deny_path))

    assert "threat-feed" in str(exc_info.value), (
        f"Expected error mentioning 'threat-feed'; got: {exc_info.value}"
    )


# ---------------------------------------------------------------------------
# Test 3 — backward-compat: all 4 existing sources still load
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source_value", ["cli", "mcp", "org-distributed", "imported"])
def test_existing_sources_still_load(tmp_path, monkeypatch, source_value):
    """Regression guard: adding 'threat-feed' must not break any existing source."""
    monkeypatch.setenv("HOME", str(tmp_path))

    # Write a minimal dynamic-denies.yaml with the given source
    deny_path = tmp_path / "dynamic-denies.yaml"
    deny_path.write_text(
        f"""\
product: iam-jit-dynamic-denies
schema_version: "1.0"
denies:
  - id: dd_01ABCDEFGHJKMNPQRSTVWXYZ12
    targets:
      - "arn:aws:iam::*:role/test-*"
    reason: "backward-compat check source={source_value}"
    duration: permanent
    added_by: "test"
    added_at: "2026-01-01T00:00:00Z"
    applied_to:
      - ibounce
    source: "{source_value}"
""",
        encoding="utf-8",
    )

    ruleset = load_file(str(deny_path))
    assert ruleset.total_rules_in_file == 1, (
        f"source={source_value!r}: expected 1 rule in file, got {ruleset.total_rules_in_file}"
    )
    assert len(ruleset.rules) == 1, (
        f"source={source_value!r}: loader returned 0 ibounce-lane rules (parse_error?)"
    )
    assert ruleset.rules[0].source == source_value


# ---------------------------------------------------------------------------
# Test 4 — over-permissive guard: unknown source still rejected
# ---------------------------------------------------------------------------


def test_unknown_source_still_rejected(tmp_path, monkeypatch):
    """Adding 'threat-feed' must not turn the validator into a no-op.
    An unrecognised source must still raise DynamicDenyLoadError.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    deny_path = tmp_path / "dynamic-denies.yaml"
    deny_path.write_text(
        """\
product: iam-jit-dynamic-denies
schema_version: "1.0"
denies:
  - id: dd_01ABCDEFGHJKMNPQRSTVWXYZ99
    targets:
      - "arn:aws:iam::*:role/test-*"
    reason: "should fail — unrecognised source"
    duration: permanent
    added_by: "test"
    added_at: "2026-01-01T00:00:00Z"
    applied_to:
      - ibounce
    source: "unknown-source"
""",
        encoding="utf-8",
    )

    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(str(deny_path))

    assert "unknown-source" in str(exc_info.value), (
        f"Expected error mentioning 'unknown-source'; got: {exc_info.value}"
    )


# ---------------------------------------------------------------------------
# Test 5 — applier regression (extend test_applier pattern)
# ---------------------------------------------------------------------------


def test_applier_regression_loader_sees_no_parse_error(tmp_path, monkeypatch):
    """After apply_feed_entries writes a rule, the real loader must not raise.

    This is the regression pattern analogous to the existing test_applier.py
    tests, but extended to cross the module boundary into the loader —
    the boundary that was broken by #645.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    deny_path = tmp_path / "dynamic-denies.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(deny_path))
    monkeypatch.setenv("IAM_JIT_THREAT_FEED_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("IAM_JIT_THREAT_FEED_LEDGER_PATH", str(tmp_path / "applied.jsonl"))
    monkeypatch.setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", str(tmp_path / "pending.jsonl"))

    priv, pub = ed25519_keygen()
    entry = _make_entry(rule_id="tf_REGRESSION_645", severity=Severity.CRITICAL)
    feed, sub = _make_signed_feed([entry], priv, pub)

    apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    assert deny_path.exists(), "Applier did not write file"

    # Must not raise — this is the regression guard
    try:
        ruleset = load_file(str(deny_path))
    except DynamicDenyLoadError as exc:
        pytest.fail(
            f"Loader raised DynamicDenyLoadError after applier wrote the file "
            f"(#645 regression): {exc}"
        )

    # At least one rule must be present
    assert ruleset.total_rules_in_file >= 1
    assert len(ruleset.rules) >= 1, (
        "Loader returned 0 ibounce-lane rules after threat-feed apply"
    )
