"""UC-17 E2E — `bounce_profile_generate_from_audit` lean_permissive flag
via real MCP `tools/call` dispatch.

Per `docs/MRR-1-USE-CASE-AUDIT-2026-05-24.md` UC-17 (CRIT, #1 of 5
pre-deploy blockers): the bounce_profile_generate_from_audit MCP tool
is the canonical "killer UX" of `docs/PROFILE-GENERATION.md` — operator
runs legitimate task, agent calls this tool with the audit window, the
Phase 3 lean_permissive heuristic generates a profile that allows
exactly the observed traffic (sibling-expanded for READ) + skips
the dangerous shapes + layers the safety floor on top.

Phase 3 implementation landed in commit b5b708b (11 unit tests under
`tests/llm/test_profile_generator_lean_permissive.py`). This E2E adds
the load-bearing E2E that exercises the WHOLE MCP path end-to-end:
real `tools/call` dispatcher → cli_profile_generate.generate_from_audit_for_mcp
→ profile_generator.generate_from_audit → _lean_permissive_fallback_profile
→ rendered YAML → observable assertions.

Mirrors UC-20 (commit 88283d5 / tests/integration/uc20_setup_from_config_e2e_test.py):
real MCP dispatch + observable-state verification + sabotage-checked
load-bearing assertion.

Six scenarios + one sabotage-check:
  A: happy path — STRONG READ siblings expanded + WEAK WRITE skipped +
     MEDIUM ADMIN skipped + safety floor present + provenance populated
  A-sabotage: monkeypatch the heuristic to strip sibling expansion;
     prove the sibling-expansion assertion in A actually fires
  B: default-off (lean_permissive omitted / false) byte-identical to
     legacy generator output
  C: KNOWN_ADVERSARIAL force-class — iam:CreateAccessKey at STRONG count
     stays ADMIN (no READ-sibling spillage; flagged)
  D: empty events — degenerate case returns empty bundle without crashing
  E: cross-bouncer safety floor parity — per-bouncer floor injected
     correctly (ibounce iam-tight; kbounce verb-tight; dbounce DCL-tight;
     gbounce egress-tight)
  F: provenance honesty per [[ibounce-honest-positioning]] — mixed-class
     events surface non-zero confidence + class distributions that match
     the input

All assertions verify OBSERVABLE state per `docs/CONTRIBUTING.md`
state-verification convention: parsed rendered YAML content + parsed
flagged_for_review provenance string. Never `assert result["status"] == "ok"`
on its own; that's the #463 silent-success shape this discipline exists
to prevent.

Runtime budget: < 5s total (no LocalStack / subprocess required —
heuristic is pure Python).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml

from iam_jit.llm import profile_generator as pg
from iam_jit.mcp_server import _handle_request


# ---------------------------------------------------------------------------
# Synthetic event builders — match the OCSF shape audit-extract emits per
# bouncer (mirrors tests/llm/test_profile_generator_from_audit.py).
# ---------------------------------------------------------------------------


_T_BASE = 1716412800000  # 2024-05-23T00:00:00Z in ms


def _ibounce_event(
    *,
    action: str,
    resource: str,
    verdict: str = "allow",
    time_ms: int = _T_BASE,
) -> dict[str, Any]:
    """Build a synthetic ibounce OCSF event matching the shape the
    audit-extract module emits."""
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


def _kbounce_event(
    *,
    verb: str = "list",
    namespace: str = "default",
    resource: str = "pods",
    verdict: str = "allow",
    time_ms: int = _T_BASE,
) -> dict[str, Any]:
    """Build a synthetic kbouncer OCSF event."""
    return {
        "_bouncer": "kbounce",
        "time": time_ms,
        "activity_name": verdict,
        "unmapped": {"iam_jit": {
            "verdict": verdict,
            "ext": {"namespace": namespace},
        }},
        "api": {
            "service": {"name": "kbouncer"},
            "operation": verb,  # bare verb so classify_kbouncer matches
            "resources": [{
                "name": f"{namespace}/{resource}",
                "uid": f"namespaces/{namespace}/{resource}",
            }],
        },
    }


def _dbounce_event(
    *,
    statement: str = "SELECT",
    host: str = "db.staging.internal",
    database: str = "analytics",
    verdict: str = "allow",
    time_ms: int = _T_BASE,
) -> dict[str, Any]:
    """Build a synthetic dbouncer OCSF event."""
    return {
        "_bouncer": "dbounce",
        "time": time_ms,
        "activity_name": statement.lower(),
        "unmapped": {"iam_jit": {
            "verdict": verdict,
            "ext": {"database": database},
        }},
        "api": {
            "service": {"name": "postgres"},
            "operation": statement,
            "resources": [{"name": "public.users"}],
        },
        "dst_endpoint": {"hostname": host, "port": 5432},
    }


def _gbounce_event(
    *,
    method: str = "GET",
    path: str = "/v1/items",
    host: str = "api.example.com",
    verdict: str = "allow",
    time_ms: int = _T_BASE,
) -> dict[str, Any]:
    """Build a synthetic gbouncer OCSF event."""
    return {
        "_bouncer": "gbounce",
        "time": time_ms,
        "activity_name": method.lower(),
        "unmapped": {"iam_jit": {"verdict": verdict, "ext": {}}},
        "api": {
            "service": {"name": host},
            "operation": f"{method} {path}",
            "resources": [{
                "name": path,
                "uid": f"https://{host}{path}",
            }],
        },
        "dst_endpoint": {"hostname": host, "port": 443},
    }


def _strong_ibounce(action: str, resources: list[str]) -> list[dict[str, Any]]:
    """5 observations across 2 resources → STRONG confidence band."""
    out: list[dict[str, Any]] = []
    t = _T_BASE
    for _ in range(3):
        out.append(_ibounce_event(action=action, resource=resources[0],
                                  time_ms=t))
        t += 1000
    for _ in range(2):
        out.append(_ibounce_event(action=action, resource=resources[1],
                                  time_ms=t))
        t += 1000
    return out


def _medium_ibounce(action: str, resource: str) -> list[dict[str, Any]]:
    """3 observations on 1 resource → MEDIUM band."""
    return [
        _ibounce_event(action=action, resource=resource, time_ms=_T_BASE + i)
        for i in range(3)
    ]


def _weak_ibounce(action: str, resource: str) -> list[dict[str, Any]]:
    """1 observation → WEAK band."""
    return [_ibounce_event(action=action, resource=resource)]


# ---------------------------------------------------------------------------
# Real MCP tools/call helper — exercises the WHOLE dispatch path so
# TOOLS-array registration + tool-name routing + JSON serialisability
# all get exercised end-to-end.
# ---------------------------------------------------------------------------


def _mcp_call_generate_from_audit(args: dict[str, Any]) -> dict[str, Any]:
    """Drive the real MCP `tools/call` dispatcher for
    bounce_profile_generate_from_audit. Returns the structuredContent
    payload (ProfileResult.to_dict() shape).

    This is the EXACT path the MCP agent client takes — differs from a
    direct import of generate_from_audit_for_mcp in that it exercises:
      * the TOOLS-array registration (must exist or -32601 unknown-tool)
      * the tool-name → handler routing
      * the JSON-serialisable return shape
    """
    req = {
        "jsonrpc": "2.0",
        "id": 17,
        "method": "tools/call",
        "params": {
            "name": "bounce_profile_generate_from_audit",
            "arguments": args,
        },
    }
    resp = _handle_request(req)
    assert resp is not None, "MCP request returned no response"
    assert "result" in resp, f"MCP request returned error: {resp!r}"
    return resp["result"]["structuredContent"]


def _parse_first_profile_yaml(result: dict[str, Any]) -> dict[str, Any]:
    """Pull the first profile from a structuredContent payload + parse
    its rendered YAML into a dict. Asserts bundle non-empty."""
    bundle = result.get("bundle") or []
    assert bundle, f"empty bundle; nothing to verify: {result!r}"
    yaml_text = bundle[0]["profile_yaml"]
    parsed = yaml.safe_load(yaml_text)
    assert isinstance(parsed, dict), (
        f"rendered YAML didn't parse to a dict: {yaml_text!r}"
    )
    return parsed


def _profiles_by_bouncer(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index parsed YAMLs by bouncer for cross-bouncer assertions."""
    out: dict[str, dict[str, Any]] = {}
    for entry in result.get("bundle") or []:
        parsed = yaml.safe_load(entry["profile_yaml"])
        if isinstance(parsed, dict):
            out[entry["bouncer"]] = parsed
    return out


# ---------------------------------------------------------------------------
# Scenario A — happy path: real MCP dispatch → lean_permissive YAML
# ---------------------------------------------------------------------------


def test_uc17_happy_path_lean_permissive_via_real_mcp(
    monkeypatch: pytest.MonkeyPatch,
):
    """Synthetic ibounce events spanning all four ActionClass + confidence
    band combinations the brief enumerates. Verify via REAL MCP dispatch:
      * STRONG READ s3:GetObject has sibling expansion in allows
      * STRONG READ dynamodb:Query has sibling expansion in allows
      * WEAK WRITE s3:PutObject SKIPPED + appears in skipped[]
      * MEDIUM ADMIN iam:CreateRole SKIPPED + appears in skipped[] + flagged
      * Safety floor _SAFETY_FLOOR_DENIES["ibounce"] reasons all present
      * Provenance: mode + distributions + safety_floor_applied=True +
        siblings_expanded_count >= 2 (one for each STRONG READ)
    """
    # Disable bouncer-side LLM so the deterministic Phase 3 path runs
    # without ambient credentials interfering.
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    events: list[dict[str, Any]] = []
    # 8x s3:GetObject across 2 resources → STRONG READ.
    events.extend(_strong_ibounce("s3:GetObject", [
        "arn:aws:s3:::bucket-a/k1",
        "arn:aws:s3:::bucket-b/k2",
    ]))
    # Add 3 more s3:GetObject observations to push count above 5
    # while staying with the same two resources.
    for i in range(3):
        events.append(_ibounce_event(
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket-a/k1",
            time_ms=_T_BASE + 1_000_000 + i,
        ))
    # 6x dynamodb:Query across 2 tables → STRONG READ.
    events.extend(_strong_ibounce("dynamodb:Query", [
        "arn:aws:dynamodb:us-east-1:111122223333:table/orders",
        "arn:aws:dynamodb:us-east-1:111122223333:table/users",
    ]))
    # 2x s3:PutObject on one resource → WEAK WRITE_DATA (single resource,
    # 2 observations falls into WEAK band per Phase 3 confidence rules).
    # Use a single weak observation to be unambiguously WEAK.
    events.extend(_weak_ibounce(
        "s3:PutObject",
        "arn:aws:s3:::bucket-c/k1",
    ))
    # 1x iam:CreateRole → MEDIUM ADMIN (will be skipped per disposition
    # table). The brief asks for iam:CreateAccessKey but that goes through
    # KNOWN_ADVERSARIAL (covered in Scenario C); iam:CreateRole exercises
    # the MEDIUM ADMIN SKIP path described in the brief without the
    # KNOWN_ADVERSARIAL force-class layer confounding things.
    events.extend(_medium_ibounce(
        "iam:CreateRole",
        "arn:aws:iam::111122223333:role/some-role",
    ))

    result = _mcp_call_generate_from_audit({
        "events": events,
        "lean_permissive": True,
        "bouncers": ["ibounce"],
    })

    # Bundle has exactly one ibounce profile.
    bundle = result.get("bundle") or []
    assert len(bundle) == 1, (
        f"expected 1 profile in bundle, got {len(bundle)}: {result!r}"
    )
    assert bundle[0]["bouncer"] == "ibounce"

    parsed = _parse_first_profile_yaml(result)
    yaml_text = bundle[0]["profile_yaml"]

    # Collect all allow actions across all allow rules.
    all_actions: set[str] = set()
    for rule in parsed.get("allows") or []:
        for a in rule.get("actions") or []:
            all_actions.add(a)

    # ===== STRONG READ s3:GetObject — exact-action allow only =====
    assert "s3:GetObject" in all_actions, (
        f"STRONG READ s3:GetObject missing from allows; got {all_actions}"
    )
    # Per #580 GAP-1 (UAT-A 2026-05-25): s3:GetObject has NO catalogue-
    # anchored siblings because AWS S3 reads are all Get*-shape (Get is
    # the source verb, excluded from its own sibling set). Pre-fix this
    # block asserted ``s3:ListObject*`` / ``s3:DescribeObject*`` /
    # ``s3:HeadObject*`` — none exist in AWS. Per
    # [[ibounce-honest-positioning]] silent no-ops are unacceptable; the
    # catalogue gate drops them. Verify the hallucinations are absent.
    for halluc in (
        "s3:ListObject*", "s3:DescribeObject*", "s3:HeadObject*",
        "s3:CheckObject*", "s3:HasObject*", "s3:CountObject*",
    ):
        assert halluc not in all_actions, (
            f"hallucinated sibling {halluc} present; catalogue gate "
            f"broken: {all_actions}"
        )

    # ===== STRONG READ dynamodb:Query + catalogue-anchored siblings =====
    assert "dynamodb:Query" in all_actions, (
        f"STRONG READ dynamodb:Query missing; got {all_actions}"
    )
    dynamodb_siblings = {
        a for a in all_actions
        if a.startswith("dynamodb:") and a != "dynamodb:Query"
    }
    assert dynamodb_siblings, (
        f"STRONG READ dynamodb:Query should expand siblings; got: "
        f"{[a for a in all_actions if a.startswith('dynamodb:')]}"
    )
    # Catalogue-anchored: dynamodb:Get*/List*/Describe*/Scan* all map to
    # real AWS DynamoDB actions, so the globs survive the catalogue gate.
    assert "dynamodb:Get*" in all_actions, (
        f"dynamodb:Get* sibling missing; got {all_actions}"
    )
    assert "dynamodb:List*" in all_actions, (
        f"dynamodb:List* sibling missing; got {all_actions}"
    )

    # ===== WEAK WRITE s3:PutObject SKIPPED =====
    assert "s3:PutObject" not in all_actions, (
        f"WEAK WRITE_DATA s3:PutObject must be SKIPPED, not allowed; "
        f"got {all_actions}"
    )
    skipped = parsed.get("skipped") or []
    assert any("s3:PutObject" in s for s in skipped), (
        f"skipped[] should mention s3:PutObject WEAK WRITE_DATA; "
        f"got {skipped}"
    )
    assert any("WEAK" in s for s in skipped), (
        f"skipped[] should cite WEAK confidence band; got {skipped}"
    )

    # ===== MEDIUM ADMIN iam:CreateRole SKIPPED + flagged =====
    assert "iam:CreateRole" not in all_actions, (
        f"MEDIUM ADMIN iam:CreateRole must be SKIPPED, not allowed; "
        f"got {all_actions}"
    )
    assert any(
        "iam:CreateRole" in s and ("MEDIUM" in s or "ADMIN" in s)
        for s in skipped
    ), (
        f"skipped[] should mention iam:CreateRole + cite MEDIUM/ADMIN; "
        f"got {skipped}"
    )
    flagged = parsed.get("flagged_for_review") or []
    assert any("iam:CreateRole" in f for f in flagged), (
        f"flagged_for_review should mention iam:CreateRole MEDIUM ADMIN; "
        f"got {flagged}"
    )

    # ===== Safety floor _SAFETY_FLOOR_DENIES["ibounce"] all present =====
    denies = parsed.get("denies") or []
    deny_reasons = [d.get("reason", "") for d in denies]
    floor_reasons = {d["reason"] for d in pg._SAFETY_FLOOR_DENIES["ibounce"]}
    for expected in floor_reasons:
        assert any(expected in r for r in deny_reasons), (
            f"safety-floor deny reason {expected!r} missing from "
            f"rendered profile; got {deny_reasons}"
        )

    # ===== Provenance: surfaced as first flagged_for_review entry =====
    # (The renderer drops _provenance — provenance summary lives in the
    # first flagged entry per _lean_permissive_fallback_profile contract.)
    assert flagged, "flagged_for_review must contain provenance summary"
    summary = flagged[0]
    assert "lean_permissive heuristic applied" in summary, (
        f"provenance summary missing from first flagged entry; got: "
        f"{summary!r}"
    )
    assert "strong=" in summary, (
        f"provenance must surface strong count; got: {summary!r}"
    )
    assert "safety_floor_applied=True" in summary, (
        f"provenance must show safety_floor_applied=True; got: {summary!r}"
    )
    # Per #580 GAP-1: siblings_expanded counts only the STRONG READ
    # actions that produced >= 1 catalogue-anchored sibling. s3:GetObject
    # produces empty siblings (S3 reads are all Get*-shape), so only
    # dynamodb:Query contributes. Pre-fix this asserted >= 2 on the
    # assumption that s3:GetObject pattern-generated siblings would
    # count — those were hallucinations + are correctly dropped now.
    import re as _re
    m = _re.search(r"siblings_expanded=(\d+)", summary)
    assert m is not None, (
        f"provenance must surface siblings_expanded counter; got: "
        f"{summary!r}"
    )
    siblings_count = int(m.group(1))
    assert siblings_count >= 1, (
        f"at least one STRONG READ (dynamodb:Query) should contribute "
        f"catalogue-anchored siblings; got {siblings_count} in: "
        f"{summary!r}"
    )

    # ===== Honest: STARTING POINT header in rendered YAML =====
    assert "STARTING POINT" in yaml_text, (
        f"rendered YAML must carry [[ibounce-honest-positioning]] "
        f"STARTING POINT header; got: {yaml_text[:200]!r}"
    )


# ---------------------------------------------------------------------------
# Scenario A-sabotage — prove the load-bearing sibling-expansion
# assertion actually fires.
# ---------------------------------------------------------------------------


def test_uc17_happy_path_sabotage_check_siblings_assertion(
    monkeypatch: pytest.MonkeyPatch,
):
    """Sabotage-check: monkeypatch _lean_permissive_fallback_profile so
    its output strips sibling actions (only the original action stays).
    Re-run the same MCP flow as Scenario A. The "sibling expansion
    present" assertion from Scenario A MUST then raise AssertionError —
    proves that assertion isn't silently short-circuiting on an empty
    set (the #463 silent-success shape this discipline exists to catch).
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    # Capture original; wrap to strip every action that isn't the
    # exact-name original (i.e. remove every sibling) BEFORE returning
    # the profile dict.
    original_fn = pg._lean_permissive_fallback_profile

    def _no_siblings(
        *,
        bouncer: str,
        events: list[dict[str, Any]],
        add_safety_denies: bool,
        friction_budget: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        out = original_fn(
            bouncer=bouncer, events=events,
            add_safety_denies=add_safety_denies,
            friction_budget=friction_budget,
        )
        # Strip everything except the exact-name action from each allow.
        # The "exact-name" is whatever action label has no '*' in it.
        for rule in out.get("allows", []):
            acts = rule.get("actions") or []
            rule["actions"] = [a for a in acts if "*" not in a]
        # Also drop the siblings_expanded counter from provenance so a
        # sibling-count-based assertion would also fire.
        prov = out.get("_provenance") or {}
        if "siblings_expanded_count" in prov:
            prov["siblings_expanded_count"] = 0
        # Rewrite the first flagged entry to reflect the strip.
        flagged = out.get("flagged_for_review") or []
        if flagged and flagged[0].startswith("lean_permissive"):
            flagged[0] = flagged[0].replace(
                "siblings_expanded=", "siblings_expanded=0_was_",
            )
        return out

    monkeypatch.setattr(pg, "_lean_permissive_fallback_profile", _no_siblings)

    # Use dynamodb:Query — its catalogue-anchored siblings ARE non-empty
    # under the post-#580-GAP-1 contract, so stripping them is a
    # meaningful sabotage (vs s3:GetObject whose siblings are correctly
    # empty post-fix and would make the sabotage indistinguishable from
    # the natural behaviour).
    events = _strong_ibounce("dynamodb:Query", [
        "arn:aws:dynamodb:us-east-1:111122223333:table/orders",
        "arn:aws:dynamodb:us-east-1:111122223333:table/customers",
    ])
    result = _mcp_call_generate_from_audit({
        "events": events,
        "lean_permissive": True,
        "bouncers": ["ibounce"],
    })
    parsed = _parse_first_profile_yaml(result)
    all_actions: set[str] = set()
    for rule in parsed.get("allows") or []:
        for a in rule.get("actions") or []:
            all_actions.add(a)

    # The same load-bearing assertion the happy-path test uses MUST raise
    # when siblings were stripped. If this passes silently, the happy-path
    # test is broken (it would also silently pass on a regressed
    # implementation).
    dynamodb_siblings_found = {
        a for a in all_actions
        if a.startswith("dynamodb:") and a != "dynamodb:Query"
    }
    with pytest.raises(AssertionError):
        assert dynamodb_siblings_found, (
            "this is the load-bearing sibling-expansion assertion from "
            "the happy-path test; verifying it actually fires when "
            "siblings are absent"
        )
    # Also sabotage a specific catalogue-anchored sibling check.
    with pytest.raises(AssertionError):
        assert "dynamodb:Get*" in all_actions, (
            "sibling sub-assertion must also fire when siblings stripped"
        )


# ---------------------------------------------------------------------------
# Scenario B — default-off backward-compat via real MCP dispatch
# ---------------------------------------------------------------------------


def test_uc17_default_off_backward_compat_via_real_mcp(
    monkeypatch: pytest.MonkeyPatch,
):
    """Same events; invoke WITHOUT lean_permissive (default off) AND
    with explicit lean_permissive=False. Both responses' first profile
    YAML MUST be byte-identical. Critical for existing callers: zero
    behaviour change unless explicitly opted-in per Phase 3 design §6.

    Also verify the rendered YAML LACKS the lean_permissive marker
    that the heuristic injects when it ran — proves the default path
    isn't silently running the heuristic.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    events = _strong_ibounce("s3:GetObject", [
        "arn:aws:s3:::bucket-a/k1",
        "arn:aws:s3:::bucket-b/k2",
    ])

    res_default = _mcp_call_generate_from_audit({
        "events": events,
        "bouncers": ["ibounce"],
        # Note: lean_permissive intentionally omitted (default False per
        # cli_profile_generate.generate_from_audit_for_mcp).
    })
    res_explicit_off = _mcp_call_generate_from_audit({
        "events": events,
        "bouncers": ["ibounce"],
        "lean_permissive": False,
    })

    bundle_default = res_default.get("bundle") or []
    bundle_explicit = res_explicit_off.get("bundle") or []
    assert len(bundle_default) == 1
    assert len(bundle_explicit) == 1

    # Byte-identical YAML between default + explicit-off invocations.
    assert (
        bundle_default[0]["profile_yaml"]
        == bundle_explicit[0]["profile_yaml"]
    ), (
        "default vs lean_permissive=False MUST be byte-identical; any "
        "drift means default callers see Phase 3 behaviour without "
        "opting in"
    )

    # Heuristic marker MUST NOT appear in default path.
    assert (
        "lean_permissive heuristic applied"
        not in bundle_default[0]["profile_yaml"]
    ), (
        "default path is silently running the lean_permissive heuristic; "
        "backward-compat broken"
    )


# ---------------------------------------------------------------------------
# Scenario C — KNOWN_ADVERSARIAL force-class via real MCP dispatch
# ---------------------------------------------------------------------------


def test_uc17_known_adversarial_force_class_via_real_mcp(
    monkeypatch: pytest.MonkeyPatch,
):
    """iam:CreateAccessKey is in KNOWN_ADVERSARIAL_PATTERNS — classified
    as ADMIN regardless of confidence band. Observed at STRONG-confidence
    count (≥5 / multi-resource) it lands in the ADMIN-strong bucket
    (narrow allow + flagged), NOT the READ-with-siblings bucket (no
    sibling spillage — admin shapes never get sibling expansion).

    Critical security property: if KNOWN_ADVERSARIAL ever stops force-
    classifying these credential-mutation actions as ADMIN, the lean-
    permissive STRONG-by-count path would silently grant them a broad
    allow — exactly the privilege-escalation hole `[[scorer-is-ground-truth]]`
    + `[[don't-give-claude-full-admin]]` discipline exists to prevent.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    # STRONG count: 5 observations across 2 users.
    events = _strong_ibounce("iam:CreateAccessKey", [
        "arn:aws:iam::111122223333:user/u1",
        "arn:aws:iam::111122223333:user/u2",
    ])
    # Plus a few more to be unambiguously STRONG.
    for i in range(3):
        events.append(_ibounce_event(
            action="iam:CreateAccessKey",
            resource="arn:aws:iam::111122223333:user/u3",
            time_ms=_T_BASE + 10_000 + i,
        ))

    result = _mcp_call_generate_from_audit({
        "events": events,
        "lean_permissive": True,
        "bouncers": ["ibounce"],
    })

    parsed = _parse_first_profile_yaml(result)
    all_actions: set[str] = set()
    for rule in parsed.get("allows") or []:
        for a in rule.get("actions") or []:
            all_actions.add(a)

    # ===== Action lands in ADMIN bucket: narrow allow OK + flagged =====
    flagged = parsed.get("flagged_for_review") or []
    assert any(
        "iam:CreateAccessKey" in f and "ADMIN" in f
        for f in flagged
    ), (
        f"KNOWN_ADVERSARIAL iam:CreateAccessKey at STRONG confidence "
        f"must surface ADMIN flag; got flagged_for_review: {flagged}"
    )

    # ===== No READ-sibling spillage =====
    # The classification short-circuit means the action does NOT go
    # through the READ-strong path, so no Get*/List*/Describe*/Head*
    # siblings get added. Likewise no Update/Put/Delete-AccessKey
    # spillage — privilege-escalation hole prevention.
    forbidden_read_siblings = {
        "iam:GetAccessKey*", "iam:ListAccessKey*",
        "iam:DescribeAccessKey*", "iam:HeadAccessKey*",
    }
    leaked_read = forbidden_read_siblings & all_actions
    assert not leaked_read, (
        f"KNOWN_ADVERSARIAL action MUST NOT get READ siblings; "
        f"leaked: {leaked_read}"
    )
    # Write-sibling spillage — the same iam:* root with mutate verbs —
    # would be even worse. Verify absent.
    forbidden_write_siblings = {
        "iam:UpdateAccessKey*", "iam:PutAccessKey*",
        "iam:ModifyAccessKey*", "iam:DeleteAccessKey*",
    }
    leaked_write = forbidden_write_siblings & all_actions
    assert not leaked_write, (
        f"KNOWN_ADVERSARIAL action MUST NOT get WRITE siblings; "
        f"leaked: {leaked_write}"
    )

    # ===== Safety floor still present =====
    denies = parsed.get("denies") or []
    deny_reasons = [d.get("reason", "") for d in denies]
    floor_reasons = {d["reason"] for d in pg._SAFETY_FLOOR_DENIES["ibounce"]}
    for expected in floor_reasons:
        assert any(expected in r for r in deny_reasons), (
            f"safety-floor deny {expected!r} missing for "
            f"KNOWN_ADVERSARIAL scenario; got {deny_reasons}"
        )


# ---------------------------------------------------------------------------
# Scenario D — empty audit events degenerate case
# ---------------------------------------------------------------------------


def test_uc17_empty_events_degenerate_case(
    monkeypatch: pytest.MonkeyPatch,
):
    """Empty events list + lean_permissive=True: MUST NOT crash. Returns
    empty bundle (no profiles to render — nothing observed) with an
    explanation pointing operators at audit query. Per the
    generate_from_audit contract the empty path short-circuits BEFORE
    the heuristic runs, so the bundle is empty.

    This guards against the "agent calls tool with empty audit window"
    UX shape that the founder repeatedly emphasises must never explode.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    result = _mcp_call_generate_from_audit({
        "events": [],
        "lean_permissive": True,
        "bouncers": ["ibounce"],
    })

    # Bundle MUST be empty (no events → no profile to synthesise).
    bundle = result.get("bundle") or []
    assert bundle == [], (
        f"empty events should produce empty bundle; got {bundle!r}"
    )

    # Explanation must be operator-actionable (mentions running an audit
    # query — the next step). Per generate_from_audit:1716-1718 the
    # explanation pins this exact prose.
    explanation = result.get("explanation") or ""
    assert "audit query" in explanation.lower() or "audit" in explanation.lower(), (
        f"empty-events explanation must point at audit query; got: "
        f"{explanation!r}"
    )

    # No crash + JSON-serialisable structure (already verified by the
    # _handle_request return — would have raised otherwise).


# ---------------------------------------------------------------------------
# Scenario E — cross-bouncer safety floor parity via real MCP dispatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bouncer_name", ["ibounce", "kbounce", "dbounce", "gbounce"])
def test_uc17_cross_bouncer_safety_floor_parity(
    bouncer_name: str,
    monkeypatch: pytest.MonkeyPatch,
):
    """Each bouncer has a DIFFERENT safety floor (ibounce iam-tight;
    kbounce verb-tight; dbounce DCL/system-catalog-tight; gbounce
    egress/IMDS-tight). Invoke with bouncers=[X] + minimal X-specific
    events; verify the per-bouncer floor reasons all land in the
    rendered profile's denies — proves the dispatcher routes the right
    safety floor to the right bouncer.

    Floor distinctness is the property under test: ibounce's
    cloudtrail:StopLogging deny doesn't belong in a kbounce profile +
    vice versa. If the dispatcher confused them, agents would think
    "iam-jit installed kbouncer denies on ibounce" → quiet escape hatch.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    # Per-bouncer minimal allowed-event so the bundle isn't empty.
    if bouncer_name == "ibounce":
        events = _strong_ibounce("s3:GetObject", [
            "arn:aws:s3:::bucket-a/k1",
            "arn:aws:s3:::bucket-b/k2",
        ])
    elif bouncer_name == "kbounce":
        events = [
            _kbounce_event(verb="list", namespace="app-staging",
                           resource="pods", time_ms=_T_BASE + i)
            for i in range(5)
        ]
    elif bouncer_name == "dbounce":
        events = [
            _dbounce_event(statement="SELECT",
                           host="db.staging.internal",
                           database="analytics",
                           time_ms=_T_BASE + i)
            for i in range(5)
        ]
    else:  # gbounce
        events = [
            _gbounce_event(method="GET", path="/v1/items",
                           host="api.example.com",
                           time_ms=_T_BASE + i)
            for i in range(5)
        ]

    result = _mcp_call_generate_from_audit({
        "events": events,
        "lean_permissive": True,
        "bouncers": [bouncer_name],
    })

    profiles = _profiles_by_bouncer(result)
    assert bouncer_name in profiles, (
        f"bundle missing {bouncer_name} profile; got bouncers: "
        f"{list(profiles.keys())}"
    )
    parsed = profiles[bouncer_name]
    denies = parsed.get("denies") or []

    # Concat all deny content (reasons + verbs + sql_patterns + targets)
    # for substring matching since the floors use different fields per
    # bouncer kind.
    all_deny_content = json.dumps(denies)

    # The bouncer name in profile_generator's _SAFETY_FLOOR_DENIES uses
    # short form ("kbounce" / "dbounce" / "gbounce" / "ibounce").
    floor = pg._SAFETY_FLOOR_DENIES.get(bouncer_name) or []
    assert floor, (
        f"_SAFETY_FLOOR_DENIES has no entry for {bouncer_name!r}; "
        f"test premise broken"
    )

    for floor_rule in floor:
        # Each floor rule has a "reason" — the most stable identifier.
        reason = floor_rule.get("reason") or ""
        assert reason in all_deny_content, (
            f"safety-floor reason {reason!r} for {bouncer_name} missing "
            f"from rendered denies; got denies: {denies!r}"
        )

    # ===== Floor distinctness check =====
    # No OTHER bouncer's floor reasons should leak into this profile.
    for other_bouncer, other_floor in pg._SAFETY_FLOOR_DENIES.items():
        if other_bouncer == bouncer_name:
            continue
        for other_rule in other_floor:
            other_reason = other_rule.get("reason") or ""
            if not other_reason:
                continue
            # The reason MAY happen to overlap (e.g. similar prose). We
            # only flag clearly cross-bouncer reasons that share NO words
            # with this bouncer's floor reasons.
            this_bouncer_reasons = {
                r.get("reason", "")
                for r in floor
            }
            # If the other bouncer's reason isn't ALSO in this bouncer's
            # floor (no incidental overlap), assert it didn't leak.
            if other_reason not in this_bouncer_reasons:
                assert other_reason not in all_deny_content, (
                    f"{other_bouncer}'s safety-floor reason "
                    f"{other_reason!r} leaked into {bouncer_name}'s "
                    f"profile; cross-bouncer dispatcher broken"
                )


# ---------------------------------------------------------------------------
# Scenario F — provenance honesty per [[ibounce-honest-positioning]]
# ---------------------------------------------------------------------------


def test_uc17_provenance_honesty_via_real_mcp(
    monkeypatch: pytest.MonkeyPatch,
):
    """Mix STRONG READ + WEAK READ + STRONG WRITE → provenance summary
    surfaces distribution counts that MATCH the input. Per
    [[ibounce-honest-positioning]] the heuristic MUST NOT lie about
    what it observed: weak=3 events in → can't read 0 or 99 in the
    summary.

    Specifically validates:
      * confidence_distribution.weak count >= 1 when WEAK events are in
      * confidence_distribution.strong count >= 2 (two STRONG actions)
      * action_class_distribution.read >= 2 (two READ actions)
      * action_class_distribution.write_data >= 1 (one WRITE action)
      * siblings_expanded_count == 1 (only the STRONG READ expands;
        WEAK READ stays narrow + STRONG WRITE never expands per
        Phase 3 prereqs guidance)
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)

    events: list[dict[str, Any]] = []
    # STRONG READ — dynamodb:Query across 2 resources, ≥5 obs. Per #580
    # GAP-1 use a source whose catalogue-anchored siblings are non-empty
    # so the siblings_expanded == 1 honesty check is meaningful.
    events.extend(_strong_ibounce("dynamodb:Query", [
        "arn:aws:dynamodb:us-east-1:111122223333:table/orders",
        "arn:aws:dynamodb:us-east-1:111122223333:table/customers",
    ]))
    # WEAK READ — single observation of s3:GetBucketLocation.
    events.extend(_weak_ibounce(
        "s3:GetBucketLocation",
        "arn:aws:s3:::c",
    ))
    # STRONG WRITE — s3:PutObject across 2 resources, ≥5 obs.
    events.extend(_strong_ibounce("s3:PutObject", [
        "arn:aws:s3:::d/k1", "arn:aws:s3:::e/k2",
    ]))

    result = _mcp_call_generate_from_audit({
        "events": events,
        "lean_permissive": True,
        "bouncers": ["ibounce"],
    })

    parsed = _parse_first_profile_yaml(result)
    flagged = parsed.get("flagged_for_review") or []
    assert flagged, "flagged_for_review must contain provenance summary"
    summary = flagged[0]

    # Extract the distribution counts the heuristic claims.
    import re as _re

    def _grab(field: str) -> int:
        m = _re.search(rf"{field}=(\d+)", summary)
        assert m is not None, (
            f"provenance summary missing {field}=N counter; got: {summary!r}"
        )
        return int(m.group(1))

    strong_count = _grab("strong")
    weak_count = _grab("weak")
    siblings_count = _grab("siblings_expanded")

    # Two STRONG actions (dynamodb:Query + s3:PutObject) → strong >= 2.
    assert strong_count >= 2, (
        f"input had 2 STRONG actions; provenance reports "
        f"strong={strong_count}; honesty violation in: {summary!r}"
    )
    # One WEAK action (s3:GetBucketLocation) → weak >= 1.
    assert weak_count >= 1, (
        f"input had 1 WEAK READ action; provenance reports "
        f"weak={weak_count}; honesty violation in: {summary!r}"
    )
    # Only the STRONG READ dynamodb:Query expands siblings (the WEAK READ
    # goes through narrow path; the STRONG WRITE never expands siblings).
    # Per #580 GAP-1 dynamodb:Query's siblings survive the catalogue gate.
    assert siblings_count == 1, (
        f"only 1 STRONG READ should expand siblings; provenance reports "
        f"siblings_expanded={siblings_count} in: {summary!r}"
    )

    # Cross-check: query the raw _provenance via direct fallback call
    # (the renderer drops _provenance, but the function still returns
    # it for testing — see unit test 11).
    prov = pg._lean_permissive_fallback_profile(
        bouncer="ibounce",
        events=events,
        add_safety_denies=True,
    ).get("_provenance") or {}
    assert prov.get("mode") == "lean_permissive"
    assert prov.get("safety_floor_applied") is True
    # Concrete claim: input had 2 STRONG (Query + Put) + 1 WEAK (Bucket).
    assert prov["confidence_distribution"]["strong"] == 2, (
        f"provenance strong count mismatch: {prov}"
    )
    assert prov["confidence_distribution"]["weak"] == 1, (
        f"provenance weak count mismatch: {prov}"
    )
    # action_class_distribution: 2 READ (Query + GetBucketLocation) +
    # 1 WRITE_DATA (Put).
    assert prov["action_class_distribution"]["read"] == 2, (
        f"provenance read count mismatch: {prov}"
    )
    assert prov["action_class_distribution"]["write_data"] == 1, (
        f"provenance write_data count mismatch: {prov}"
    )
    # Single-STRONG-READ → siblings_expanded_count == 1.
    assert prov["siblings_expanded_count"] == 1, (
        f"provenance siblings count mismatch: {prov}"
    )
