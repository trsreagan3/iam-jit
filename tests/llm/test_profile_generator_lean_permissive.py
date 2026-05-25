"""Phase 3 of profile-generation design (docs/PROFILE-GENERATION-DESIGN.md
§6 Phase 3) — lean_permissive flag on bounce_profile_generate_from_audit.

Per [[tests-and-independent-uat-required]] + docs/CONTRIBUTING.md
state-verification convention: every test asserts OBSERVABLE state
(parsed YAML content matches expectation, not just function-returns).

The 11 tests cover the design §2 disposition table per-ActionClass +
the safety-floor invariant + the provenance block + the sibling-
expansion gating per Phase 3 prereqs guidance.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from iam_jit.llm import profile_generator as pg


# ---------------------------------------------------------------------------
# Helpers — synthetic audit events covering all four ActionClasses.
# ---------------------------------------------------------------------------


def _ibounce_event(
    *,
    action: str,
    resource: str,
    verdict: str = "allow",
    time_ms: int = 1716412800000,
) -> dict[str, Any]:
    """Build a synthetic ibounce OCSF event for tests."""
    svc, _, op = action.partition(":")
    return {
        "_bouncer": "ibounce",
        "time": time_ms,
        "activity_name": verdict,
        "unmapped": {"iam_jit": {"verdict": verdict}},
        "api": {
            "service": {"name": svc},
            "operation": op,
            "resources": [{"name": resource}],
        },
    }


def _strong_events(action: str, resources: list[str]) -> list[dict[str, Any]]:
    """5+ observations across 2+ distinct resources → STRONG."""
    out: list[dict[str, Any]] = []
    t = 1716412800000
    # 3 observations on first resource + 2 on second = 5 total / 2 resources.
    for _ in range(3):
        out.append(_ibounce_event(action=action, resource=resources[0], time_ms=t))
        t += 1000
    for _ in range(2):
        out.append(_ibounce_event(action=action, resource=resources[1], time_ms=t))
        t += 1000
    return out


def _medium_events(action: str, resource: str) -> list[dict[str, Any]]:
    """2-4 observations → MEDIUM."""
    return [
        _ibounce_event(action=action, resource=resource, time_ms=1716412800000 + i)
        for i in range(3)
    ]


def _weak_events(action: str, resource: str) -> list[dict[str, Any]]:
    """1 observation → WEAK."""
    return [_ibounce_event(action=action, resource=resource)]


def _find_allow_actions(profile: pg.GeneratedProfile) -> set[str]:
    """Parse the GeneratedProfile YAML and return the union of all
    actions across every allow rule."""
    parsed = yaml.safe_load(profile.profile_yaml)
    actions: set[str] = set()
    for rule in parsed.get("allows") or []:
        for a in rule.get("actions") or []:
            actions.add(a)
    return actions


def _find_denies(profile: pg.GeneratedProfile) -> list[dict[str, Any]]:
    parsed = yaml.safe_load(profile.profile_yaml)
    return parsed.get("denies") or []


# ---------------------------------------------------------------------------
# Test 1 — default-off matches legacy.
# ---------------------------------------------------------------------------


def test_default_off_matches_legacy(monkeypatch: pytest.MonkeyPatch):
    """lean_permissive=False (default) → byte-identical to pre-Phase-3
    behaviour. Same event set produces same YAML."""
    events = _strong_events("s3:GetObject", [
        "arn:aws:s3:::bucket-a/key1",
        "arn:aws:s3:::bucket-b/key2",
    ])

    # Ensure no LLM is called (default off).
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    res_default = pg.generate_from_audit(
        events=events,
        time_range="1h",
    )
    res_explicit_off = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=False,
    )

    assert len(res_default.bundle) == 1
    assert len(res_explicit_off.bundle) == 1
    assert (
        res_default.bundle[0].profile_yaml
        == res_explicit_off.bundle[0].profile_yaml
    ), "default vs explicit-off must be byte-identical"

    # State verification: the rendered YAML lacks the lean-permissive
    # marker that would appear only when the heuristic ran.
    assert "lean_permissive heuristic applied" not in res_default.bundle[0].profile_yaml


# ---------------------------------------------------------------------------
# Test 2 — lean_permissive includes READ with sibling expansion.
# ---------------------------------------------------------------------------


def test_lean_permissive_includes_read_with_siblings(
    monkeypatch: pytest.MonkeyPatch,
):
    """STRONG-confidence Query-shape READ → output includes catalogue-
    anchored sibling globs (``dynamodb:Get*``, ``dynamodb:List*``,
    ``dynamodb:Describe*``, ``dynamodb:Scan*``) in the same allow rule.

    Per #580 GAP-1 (UAT-A 2026-05-25): pre-fix this test asserted
    ``s3:ListObject*`` / ``s3:DescribeObject*`` / ``s3:HeadObject*`` for
    a ``s3:GetObject`` source — none of which exist in AWS. Updated to
    ``dynamodb:Query`` source which has real catalogue siblings under
    the per-verb adjacency. Per [[scorer-is-ground-truth]] we anchor to
    the AWS catalogue.
    """
    events = _strong_events("dynamodb:Query", [
        "arn:aws:dynamodb:us-east-1:111122223333:table/orders",
        "arn:aws:dynamodb:us-east-1:111122223333:table/customers",
    ])
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    assert len(result.bundle) == 1
    actions = _find_allow_actions(result.bundle[0])

    # State verification: original + catalogue-anchored siblings present.
    assert "dynamodb:Query" in actions, (
        f"original action missing; got {actions}"
    )
    # Real AWS DynamoDB catalogue includes Get*/List*/Describe*/Scan*
    # actions, so these globs survive the catalogue gate.
    assert "dynamodb:Get*" in actions, (
        f"sibling dynamodb:Get* missing for STRONG READ; got {actions}"
    )
    assert "dynamodb:List*" in actions, (
        f"sibling dynamodb:List* missing for STRONG READ; got {actions}"
    )
    assert "dynamodb:Describe*" in actions, (
        f"sibling dynamodb:Describe* missing for STRONG READ; got {actions}"
    )
    assert "dynamodb:Scan*" in actions, (
        f"sibling dynamodb:Scan* missing for STRONG READ; got {actions}"
    )
    # #580 GAP-1 negative assertion: no hallucinated globs leak through.
    for halluc in ("dynamodb:CheckObject*", "dynamodb:HasObject*",
                   "dynamodb:CountObject*"):
        assert halluc not in actions, (
            f"hallucinated sibling {halluc} present; "
            f"catalogue gate broken: {actions}"
        )


# ---------------------------------------------------------------------------
# Test 3 — lean_permissive skips WEAK WRITE.
# ---------------------------------------------------------------------------


def test_lean_permissive_skips_weak_write(monkeypatch: pytest.MonkeyPatch):
    """WEAK-confidence Put* → NOT included in allows; surfaces in
    skipped[]."""
    events = _weak_events("s3:PutObject", "arn:aws:s3:::onlybucket/key")
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    assert len(result.bundle) == 1
    parsed = yaml.safe_load(result.bundle[0].profile_yaml)
    actions = _find_allow_actions(result.bundle[0])

    # State verification: s3:PutObject MUST NOT appear in any allow.
    assert "s3:PutObject" not in actions, (
        f"WEAK WRITE_DATA should be SKIPPED; got actions {actions}"
    )
    # State verification: skipped[] block names the action + reason.
    skipped = parsed.get("skipped") or []
    assert any("s3:PutObject" in s for s in skipped), (
        f"skipped[] should mention s3:PutObject; got {skipped}"
    )
    assert any("WEAK" in s for s in skipped), (
        f"skipped[] should cite WEAK confidence; got {skipped}"
    )


# ---------------------------------------------------------------------------
# Test 4 — lean_permissive ADMIN strong includes narrow + flagged.
# ---------------------------------------------------------------------------


def test_lean_permissive_admin_strong_includes_narrow(
    monkeypatch: pytest.MonkeyPatch,
):
    """STRONG iam:CreateRole → exact-action allow + flagged_for_review."""
    # iam:CreateRole is ADMIN class (not in KNOWN_ADVERSARIAL_PATTERNS but
    # in the iam:Create* ADMIN prefix table).
    events = _strong_events("iam:CreateRole", [
        "arn:aws:iam::111122223333:role/role-a",
        "arn:aws:iam::111122223333:role/role-b",
    ])
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    assert len(result.bundle) == 1
    parsed = yaml.safe_load(result.bundle[0].profile_yaml)
    actions = _find_allow_actions(result.bundle[0])

    # State verification: action present + narrow (no siblings).
    assert "iam:CreateRole" in actions
    # No sibling expansion for ADMIN class.
    assert "iam:UpdateRole*" not in actions
    assert "iam:PutRole*" not in actions

    # State verification: flagged_for_review names the action.
    flagged = parsed.get("flagged_for_review") or []
    assert any("iam:CreateRole" in f for f in flagged), (
        f"STRONG ADMIN must be flagged; got {flagged}"
    )
    assert any("ADMIN" in f for f in flagged), (
        f"flag should cite ADMIN classification; got {flagged}"
    )


# ---------------------------------------------------------------------------
# Test 5 — lean_permissive ADMIN medium skips.
# ---------------------------------------------------------------------------


def test_lean_permissive_admin_medium_skips(monkeypatch: pytest.MonkeyPatch):
    """MEDIUM iam:CreateRole → SKIPPED + flagged."""
    events = _medium_events("iam:CreateRole", "arn:aws:iam::111122223333:role/sole")
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    assert len(result.bundle) == 1
    parsed = yaml.safe_load(result.bundle[0].profile_yaml)
    actions = _find_allow_actions(result.bundle[0])

    assert "iam:CreateRole" not in actions, (
        f"MEDIUM ADMIN should be SKIPPED; got actions {actions}"
    )

    skipped = parsed.get("skipped") or []
    assert any("iam:CreateRole" in s and "MEDIUM" in s for s in skipped), (
        f"skipped[] should cite MEDIUM ADMIN; got {skipped}"
    )

    flagged = parsed.get("flagged_for_review") or []
    assert any("iam:CreateRole" in f for f in flagged), (
        f"flagged_for_review should mention iam:CreateRole; got {flagged}"
    )


# ---------------------------------------------------------------------------
# Test 6 — lean_permissive DESTRUCTIVE weak skips.
# ---------------------------------------------------------------------------


def test_lean_permissive_destructive_skips_weak(
    monkeypatch: pytest.MonkeyPatch,
):
    """WEAK destructive (single observation) → SKIPPED.

    Tests the dbounce DESTRUCTIVE_DATA path with DELETE on a single
    observation — the heuristic must classify destructive + WEAK + skip.
    We use ibounce s3:DeleteObject for parity with the rest of these
    fixtures so the bouncer routing doesn't add a confound.
    """
    events = _weak_events("s3:DeleteObject", "arn:aws:s3:::bucket-x/key")
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    assert len(result.bundle) == 1
    parsed = yaml.safe_load(result.bundle[0].profile_yaml)
    actions = _find_allow_actions(result.bundle[0])

    assert "s3:DeleteObject" not in actions, (
        f"WEAK DESTRUCTIVE_DATA should be SKIPPED; got actions {actions}"
    )

    skipped = parsed.get("skipped") or []
    assert any("s3:DeleteObject" in s for s in skipped), (
        f"skipped[] should mention s3:DeleteObject; got {skipped}"
    )
    assert any("DESTRUCTIVE_DATA" in s for s in skipped), (
        f"skipped[] should cite DESTRUCTIVE_DATA; got {skipped}"
    )


# ---------------------------------------------------------------------------
# Test 7 — safety floor ALWAYS present even with lean_permissive.
# ---------------------------------------------------------------------------


def test_safety_floor_always_present(monkeypatch: pytest.MonkeyPatch):
    """Even with lean_permissive=True the _SAFETY_FLOOR_DENIES must be
    in the rendered profile. Per design §2.3 + §7 safeguard #3 the
    safety floor is hardcoded — never opt-out."""
    events = _strong_events("s3:GetObject", [
        "arn:aws:s3:::bucket-a/k1",
        "arn:aws:s3:::bucket-b/k2",
    ])
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    assert len(result.bundle) == 1
    denies = _find_denies(result.bundle[0])

    # State verification: the canonical safety-floor reasons are present.
    deny_reasons = [d.get("reason", "") for d in denies]
    expected_floor_reasons = {
        d["reason"] for d in pg._SAFETY_FLOOR_DENIES["ibounce"]
    }
    for expected in expected_floor_reasons:
        assert any(expected in r for r in deny_reasons), (
            f"safety-floor deny {expected!r} missing; got {deny_reasons}"
        )


# ---------------------------------------------------------------------------
# Test 8 — KNOWN_ADVERSARIAL forces ADMIN class.
# ---------------------------------------------------------------------------


def test_known_adversarial_force_admin_class(
    monkeypatch: pytest.MonkeyPatch,
):
    """Observed iam:CreateAccessKey (in KNOWN_ADVERSARIAL_PATTERNS) is
    forced to ADMIN classification regardless of where its prefix match
    would land. Strong-confidence observation therefore lands in the
    ADMIN-strong bucket (narrow + flagged), not the destructive bucket
    (which would not widen) and definitely not WRITE_DATA (which
    wouldn't flag)."""
    events = _strong_events("iam:CreateAccessKey", [
        "arn:aws:iam::111122223333:user/u1",
        "arn:aws:iam::111122223333:user/u2",
    ])
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    parsed = yaml.safe_load(result.bundle[0].profile_yaml)
    flagged = parsed.get("flagged_for_review") or []

    # State verification: classified ADMIN (cited in flag reason).
    assert any(
        "iam:CreateAccessKey" in f and "ADMIN" in f for f in flagged
    ), (
        f"KNOWN_ADVERSARIAL iam:CreateAccessKey must be flagged with "
        f"ADMIN classification; got {flagged}"
    )

    # Cross-check: the heuristic provenance shows it counted as ADMIN.
    provenance = result.bundle[0].profile_yaml
    # Sanity: the action did NOT get sibling expansion (siblings are
    # READ-only per Phase 3 prereqs guidance).
    actions = _find_allow_actions(result.bundle[0])
    assert "iam:CreateAccessKey" in actions
    # No write-sibling spillage — Update/Put/Modify on access keys
    # would be a privilege-escalation hole.
    assert "iam:UpdateAccessKey*" not in actions
    assert "iam:PutAccessKey*" not in actions


# ---------------------------------------------------------------------------
# Test 9 — siblings NOT applied to WRITES.
# ---------------------------------------------------------------------------


def test_siblings_not_applied_to_writes(monkeypatch: pytest.MonkeyPatch):
    """STRONG-confidence Put* does NOT get sibling expansion — sibling
    expansion is READ-only per Phase 3 prereqs guidance from #555."""
    events = _strong_events("s3:PutObject", [
        "arn:aws:s3:::bucket-a/k1",
        "arn:aws:s3:::bucket-b/k2",
    ])
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    actions = _find_allow_actions(result.bundle[0])

    # State verification: the original action is present.
    assert "s3:PutObject" in actions
    # No sibling expansion: Update/Modify/Replace/Create/Set must be
    # absent (those are WRITE_SIBLING_VERBS but only applied to READ
    # observations per the Phase 3 gating).
    forbidden_siblings = {
        "s3:UpdateObject*", "s3:ModifyObject*", "s3:ReplaceObject*",
        "s3:CreateObject*", "s3:SetObject*", "s3:PatchObject*",
    }
    leaked = forbidden_siblings & actions
    assert not leaked, (
        f"sibling expansion leaked into WRITE_DATA STRONG; "
        f"forbidden siblings present: {leaked}"
    )


# ---------------------------------------------------------------------------
# Test 10 — UNKNOWN class always skipped regardless of confidence.
# ---------------------------------------------------------------------------


def test_unknown_class_always_skips(monkeypatch: pytest.MonkeyPatch):
    """An action that doesn't match any class table → UNKNOWN → SKIP
    regardless of confidence. Per design §2.2 the lean-permissive
    heuristic default-denies unclassified shapes."""
    # Use a made-up service:action that none of the prefix tables match.
    # "weird:NonsenseVerb" — neither READ nor WRITE_DATA nor ADMIN nor
    # DESTRUCTIVE classifies it.
    events = _strong_events("weird:NonsenseVerb", [
        "arn:aws:weird:::res-a",
        "arn:aws:weird:::res-b",
    ])
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    parsed = yaml.safe_load(result.bundle[0].profile_yaml)
    actions = _find_allow_actions(result.bundle[0])

    assert "weird:NonsenseVerb" not in actions, (
        f"UNKNOWN class action must be SKIPPED at STRONG; got {actions}"
    )

    skipped = parsed.get("skipped") or []
    assert any(
        "weird:NonsenseVerb" in s and "UNKNOWN" in s for s in skipped
    ), (
        f"skipped[] should cite UNKNOWN classification for "
        f"weird:NonsenseVerb; got {skipped}"
    )


# ---------------------------------------------------------------------------
# Test 11 — provenance block populated correctly.
# ---------------------------------------------------------------------------


def test_provenance_block_populated(monkeypatch: pytest.MonkeyPatch):
    """Verify all five provenance fields per design §6 Phase 3 are
    present + accurate in the rendered profile (flagged_for_review's
    first entry surfaces the mode + distributions for operator
    visibility per [[ibounce-honest-positioning]] no hidden tightening)."""
    # Build a mix: STRONG read + WEAK read + STRONG write to exercise
    # multiple confidence bands and action classes. Per #580 GAP-1 use
    # ``dynamodb:Query`` as the STRONG READ — it has real catalogue-
    # anchored siblings (s3:GetObject's siblings are correctly empty
    # post-fix because S3 reads are all Get*-shape).
    events: list[dict[str, Any]] = []
    events.extend(_strong_events("dynamodb:Query", [
        "arn:aws:dynamodb:us-east-1:111122223333:table/orders",
        "arn:aws:dynamodb:us-east-1:111122223333:table/customers",
    ]))
    events.extend(_weak_events("s3:GetBucketLocation", "arn:aws:s3:::c"))
    events.extend(_strong_events("s3:PutObject", [
        "arn:aws:s3:::d/k1", "arn:aws:s3:::e/k2",
    ]))
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = pg.generate_from_audit(
        events=events,
        time_range="1h",
        lean_permissive=True,
    )

    parsed = yaml.safe_load(result.bundle[0].profile_yaml)
    flagged = parsed.get("flagged_for_review") or []

    # The first flagged entry is the provenance summary per the
    # heuristic's contract. Validate all five fields surface there.
    assert flagged, "flagged_for_review must contain provenance summary"
    summary = flagged[0]
    assert "lean_permissive heuristic applied" in summary, (
        f"provenance summary missing; got {summary!r}"
    )
    # Field 1: mode (implicit in "lean_permissive heuristic applied").
    # Field 2: confidence_distribution — strong/medium/weak counts.
    assert "strong=" in summary
    assert "medium=" in summary
    assert "weak=" in summary
    # Field 3: safety_floor_applied flag.
    assert "safety_floor_applied=True" in summary, (
        f"safety_floor_applied flag must be in summary; got {summary!r}"
    )
    # Field 4: siblings_expanded count.
    assert "siblings_expanded=" in summary

    # State verification: the raw aggregates are also queryable via the
    # heuristic's _provenance return (a private inspection channel for
    # tests + the Phase 5 simulator).
    fallback_dict = pg._lean_permissive_fallback_profile(
        bouncer="ibounce",
        events=events,
        add_safety_denies=True,
    )
    prov = fallback_dict.get("_provenance") or {}
    assert prov.get("mode") == "lean_permissive"
    assert prov.get("safety_floor_applied") is True
    assert isinstance(prov.get("confidence_distribution"), dict)
    assert isinstance(prov.get("action_class_distribution"), dict)
    assert isinstance(prov.get("siblings_expanded_count"), int)
    # Concrete count checks:
    #   dynamodb:Query (READ STRONG)      -> contributes to read + strong
    #   s3:GetBucketLocation (READ WEAK)  -> contributes to read + weak
    #   s3:PutObject (WRITE_DATA STRONG)  -> contributes to write + strong
    assert prov["confidence_distribution"]["strong"] == 2
    assert prov["confidence_distribution"]["weak"] == 1
    assert prov["action_class_distribution"]["read"] == 2
    assert prov["action_class_distribution"]["write_data"] == 1
    # Only the dynamodb:Query STRONG READ gets sibling expansion (the
    # WEAK READ uses the narrow path; the STRONG WRITE is not expanded).
    # Per #580 GAP-1 the dynamodb sibling globs survive the catalogue
    # gate (real DynamoDB read actions exist for Get/List/Describe/Scan).
    assert prov["siblings_expanded_count"] == 1
