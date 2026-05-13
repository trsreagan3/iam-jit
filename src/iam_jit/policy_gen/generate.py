"""Main policy-generation entry point.

Pipeline:
  1. Pattern-match the task description against the heuristic library.
  2. Extract resources (explicit ARNs, named resources, context-supplied).
  3. Compose an IAM policy:
     - Group matched patterns by service/access shape so we emit one
       statement per group, not one per pattern (cleaner policies).
     - Fill the Resource field with extracted resources OR pattern
       fallbacks (`*` etc.) when nothing matched.
     - Apply bias: union of allow_actions for `allow`, intersection
       with deny_actions for `deny`.
  4. Validate by running the generated policy through `analyze_policy()`.
     The risk score and risk factors are returned alongside the
     policy so the caller can decide whether the result is usable.

The pipeline is intentionally deterministic — same input always
yields the same output. No randomization, no LLM. The patterns ARE
the knowledge; expanding coverage means adding patterns, not
training a model.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..review import analyze_policy
from .patterns import ALL_PATTERNS, Pattern, matched_patterns
from .resources import ExtractedResource, extract_resources
from .result import GenerationRequest, GenerationResult


def generate_policy(request: GenerationRequest) -> GenerationResult:
    """Produce a scored IAM policy from a task description.

    Always returns a `GenerationResult`. When the heuristic pattern
    matcher fails to recognize the task, the result has
    `policy=None` and `unmatched_reason` explains why.
    """
    description = request.task_description.strip()
    if not description:
        return GenerationResult(
            policy=None,
            unmatched_reason="Empty task description.",
            confidence=10,
        )

    patterns = matched_patterns(description, ALL_PATTERNS)
    if not patterns:
        return GenerationResult(
            policy=None,
            unmatched_reason=(
                "No heuristic pattern matched the task description. "
                "Either rephrase using common AWS verbs (read S3, query "
                "DynamoDB, deploy Lambda, ...) or upgrade to the LLM "
                "generation tier for free-form descriptions."
            ),
            confidence=10,
        )

    resources = extract_resources(description, request.context)
    statements, reasons, suppressed = _build_statements(
        patterns, resources, request,
    )

    if not statements:
        return GenerationResult(
            policy=None,
            matched_patterns=[p.name for p in patterns],
            unmatched_reason=(
                "Patterns matched but produced no actionable statements. "
                "Common cause: bias=deny with patterns that don't list "
                "any deny_actions for this task shape."
            ),
            confidence=9,
        )

    # Apply caller refinement (if any) to the assembled statements
    # BEFORE scoring, so the scored output reflects the user's edits.
    if request.refinement is not None:
        statements, refinement_reasons = _apply_refinement(
            statements, request.refinement, resources,
        )
        reasons.extend(refinement_reasons)
        if not statements:
            return GenerationResult(
                policy=None,
                matched_patterns=[p.name for p in patterns],
                reasons=reasons,
                unmatched_reason=(
                    "Refinement removed every action — nothing left to "
                    "grant. Re-issue with fewer exclusions or a wider "
                    "task description."
                ),
                confidence=10,
            )

    policy: dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": statements,
    }

    # Run the generated policy through the deterministic scorer so the
    # caller gets the risk score in the same return value. This is the
    # safety net: even if the generator over-includes actions, the
    # scorer flags it.
    scoring_request = {
        "spec": {
            "access_type": _scoring_access_type(patterns, request),
            "duration": {"duration_hours": request.duration_hours},
        }
    }
    try:
        analysis = analyze_policy(policy, scoring_request)
        scored = analysis.risk_score
        factors = list(analysis.risk_factors)
        suggestions = list(analysis.suggestions)
    except Exception as e:  # defensive — scorer must never crash a grant request
        scored = 10
        factors = [f"Scorer raised exception: {e}"]
        suggestions = []

    confidence = _estimate_confidence(patterns, resources, scored)
    hints = _refinement_hints(patterns, resources, suppressed, scored, factors)

    return GenerationResult(
        policy=policy,
        matched_patterns=[p.name for p in patterns],
        reasons=reasons,
        confidence=confidence,
        scored_risk=scored,
        risk_factors=factors,
        risk_suggestions=suggestions,
        suppressed_actions=suppressed,
        refinement_hints=hints,
    )


def _build_statements(
    patterns: list[Pattern],
    resources: list[ExtractedResource],
    request: GenerationRequest,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Compose IAM statements from matched patterns + extracted resources.

    Groups patterns by their (resource_kinds + access_hint) tuple so
    actions that share a target resource go into the same statement.
    Returns (statements, reasons, suppressed_actions).
    """
    reasons: list[str] = []
    suppressed: list[str] = []

    # Map each pattern → the resources it can consume. A pattern with
    # `resource_kinds=("s3-bucket",)` will pair with every extracted
    # resource whose kind is `s3-bucket`. If none match, the pattern
    # uses its wildcard_resources fallback.
    pattern_groups: dict[tuple[str, ...], list[Pattern]] = defaultdict(list)
    for p in patterns:
        # Group key = sorted resource_kinds tuple + access_hint so two
        # patterns that target the same shape merge.
        key = tuple(sorted(p.resource_kinds)) + (p.access_hint,)
        pattern_groups[key].append(p)

    statements: list[dict[str, Any]] = []
    for _key, group in pattern_groups.items():
        # Union of actions across patterns in the group, filtered by bias
        actions_set: set[str] = set()
        suppressed_local: set[str] = set()
        kinds_set: set[str] = set()
        for p in group:
            kinds_set.update(p.resource_kinds)
            if request.bias == "allow":
                actions_set.update(p.allow_actions)
            else:
                if p.deny_actions:
                    actions_set.update(p.deny_actions)
                    # Track what we suppressed in deny mode for surface
                    suppressed_local.update(
                        a for a in p.allow_actions if a not in p.deny_actions
                    )
                else:
                    # Pattern has no deny_actions → contributes nothing
                    # in deny mode. Note the suppressed allow set so the
                    # caller can prompt the user.
                    suppressed_local.update(p.allow_actions)
                    reasons.append(
                        f"Pattern {p.name!r} matched but had no deny-bias "
                        "action subset; skipped in deny mode."
                    )

        if not actions_set:
            continue

        # Find resources that match any of the group's resource_kinds
        matching_resources = [
            r for r in resources if r.service_kind in kinds_set
        ]
        if matching_resources:
            resource_arns = [r.arn for r in matching_resources]
            reasons.append(
                f"Statement for {sorted(actions_set)[0].split(':', 1)[0]}: "
                f"using {len(resource_arns)} extracted resource(s)."
            )
        else:
            # Fall back to the union of wildcard_resources across the group
            wildcard_set: set[str] = set()
            for p in group:
                wildcard_set.update(p.wildcard_resources)
            resource_arns = sorted(wildcard_set)
            reasons.append(
                f"Statement for {sorted(actions_set)[0].split(':', 1)[0]}: "
                f"no explicit resource — using wildcard fallback "
                f"({len(resource_arns)} ARN pattern(s)). The deterministic "
                "scorer will flag this as broad."
            )

        # iam:PassRole targets IAM role ARNs, not the service resource
        # ARNs the other actions use. If PassRole is in the action set,
        # split it into its own statement so the Resource semantics are
        # honest. The PassRole Resource uses extracted iam-role
        # resources when present, falling back to the role-wildcard
        # `arn:aws:iam::*:role/*` — which the scorer flags as 9-tier,
        # routing to human review (correctly — PassRole on `*` is
        # a textbook privilege-escalation primitive).
        passrole_in_set = "iam:PassRole" in actions_set
        if passrole_in_set:
            actions_set.discard("iam:PassRole")
            iam_role_resources = [
                r.arn for r in resources if r.service_kind == "iam-role"
            ]
            if not iam_role_resources:
                iam_role_resources = ["arn:aws:iam::*:role/*"]
            statements.append({
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": iam_role_resources[0] if len(iam_role_resources) == 1
                            else iam_role_resources,
            })
            reasons.append(
                f"Separate `iam:PassRole` statement (target: "
                f"{len(iam_role_resources)} role ARN(s)) — PassRole "
                "targets role ARNs, not the service resource being "
                "deployed/invoked."
            )

        # Build the main statement (without PassRole). Single-element
        # Action/Resource collapses to a string (matches AWS-managed-
        # policy convention).
        if not actions_set:
            suppressed.extend(sorted(suppressed_local))
            continue

        action_value: Any = sorted(actions_set)
        if len(action_value) == 1:
            action_value = action_value[0]
        resource_value: Any = resource_arns
        if len(resource_value) == 1:
            resource_value = resource_value[0]

        statements.append({
            "Effect": "Allow",
            "Action": action_value,
            "Resource": resource_value,
        })

        suppressed.extend(sorted(suppressed_local))

    return statements, reasons, suppressed


def _scoring_access_type(
    patterns: list[Pattern],
    request: GenerationRequest,
) -> str:
    """Decide the access_type to pass to the scorer.

    The scorer's read-only-mismatch rule only fires when access_type
    is `"read-only"`. We pass through the request's access_type
    unchanged, but if every matched pattern has `access_hint="read"`
    AND the request didn't specify read-write, prefer `"read-only"`
    so the scorer can validate.
    """
    if request.access_type in ("read", "read-only"):
        return "read-only"
    all_read_only = all(p.access_hint == "read" for p in patterns)
    if all_read_only and request.access_type == "read":
        return "read-only"
    return request.access_type


def _apply_refinement(
    statements: list[dict[str, Any]],
    refinement: Any,  # Refinement — quoted to avoid import cycle
    extracted_resources: list[ExtractedResource],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Apply caller-supplied refinement to the generated statements.

    The function is INTENTIONALLY surgical — it doesn't reinterpret the
    user's intent, it just edits the action/resource sets directly per
    the explicit exclude/include lists. The deterministic scorer
    re-validates the result so a refinement that adds catastrophic
    actions doesn't slip past the safety floor.
    """
    import fnmatch as _fn

    reasons: list[str] = []
    exclude_set = {a.lower() for a in refinement.exclude_actions}
    include_set = set(refinement.include_actions)
    exclude_res = set(refinement.exclude_resources)
    include_res = set(refinement.include_resources)

    out: list[dict[str, Any]] = []
    for stmt in statements:
        actions = stmt["Action"]
        if isinstance(actions, str):
            actions = [actions]
        actions = list(actions)

        # Exclude: support exact match (case-insensitive) AND glob
        # patterns like `s3:*` so the caller can remove an entire
        # service in one line.
        kept_actions: list[str] = []
        removed: list[str] = []
        for a in actions:
            a_lc = a.lower()
            if a_lc in exclude_set or any(
                _fn.fnmatchcase(a_lc, pat) for pat in exclude_set
            ):
                removed.append(a)
            else:
                kept_actions.append(a)
        if removed:
            reasons.append(
                f"Refinement removed {len(removed)} action(s): "
                f"{', '.join(removed[:5])}{'...' if len(removed) > 5 else ''}"
            )

        # Resources: same exclude logic.
        resources = stmt["Resource"]
        if isinstance(resources, str):
            resources = [resources]
        resources = [r for r in resources if r not in exclude_res]

        # Skip statements that have no actions left.
        if not kept_actions:
            continue

        # Re-collapse single-element lists per the AWS-managed-policy
        # convention.
        action_value: Any = kept_actions if len(kept_actions) > 1 else kept_actions[0]
        resource_value: Any = resources if len(resources) > 1 else (
            resources[0] if resources else "*"
        )

        out.append({
            "Effect": "Allow",
            "Action": action_value,
            "Resource": resource_value,
        })

    # Include: add NEW actions in their own statement. We don't try to
    # merge them into existing statements because the caller's
    # included actions may target a different service whose resource
    # ARN doesn't match the existing statements'. One include →
    # one statement is cleaner and safer.
    if include_set:
        # Group include_actions by service so each service gets one
        # statement.
        from collections import defaultdict as _dd
        by_service: dict[str, list[str]] = _dd(list)
        for a in sorted(include_set):
            svc = a.split(":", 1)[0] if ":" in a else "_unknown"
            by_service[svc].append(a)

        for svc, svc_actions in by_service.items():
            # Pick include_resources matching this service if any;
            # otherwise extracted resources from the description that
            # share the service prefix.
            svc_matching_resources = [r for r in include_res if f":{svc}:" in r]
            if not svc_matching_resources:
                svc_matching_resources = [
                    r.arn for r in extracted_resources
                    if f":{svc}:" in r.arn or r.service_kind.startswith(svc)
                ]
            if not svc_matching_resources:
                svc_matching_resources = ["*"]
            out.append({
                "Effect": "Allow",
                "Action": svc_actions if len(svc_actions) > 1 else svc_actions[0],
                "Resource": (
                    svc_matching_resources if len(svc_matching_resources) > 1
                    else svc_matching_resources[0]
                ),
            })
        reasons.append(
            f"Refinement added {len(include_set)} action(s): "
            f"{', '.join(sorted(include_set)[:5])}"
        )

    if refinement.rationale:
        reasons.append(f"Refinement rationale: {refinement.rationale}")

    return out, reasons


def _refinement_hints(
    patterns: list[Pattern],
    resources: list[ExtractedResource],
    suppressed: list[str],
    scored_risk: int,
    risk_factors: list[str],
) -> list[str]:
    """Suggestions the caller can use to iterate on the policy.

    Returned alongside the result so a UI or agent can offer
    "too strict? add X" / "too broad? remove Y" buttons.
    """
    hints: list[str] = []

    # If anything was suppressed by deny bias, offer to flip allow.
    if suppressed:
        hints.append(
            f"If too strict: switch bias to `allow` or re-issue with "
            f"`refinement.include_actions = "
            f"{sorted(suppressed)[:3]!r}` to add the suppressed actions."
        )

    # If the scored risk is high (≥7), suggest narrowing.
    if scored_risk >= 7:
        if not resources:
            hints.append(
                "If too broad: name the specific resource (bucket, "
                "function, table, role) in the description so the "
                "generator can produce a narrow ARN instead of `*`. "
                "The score will drop substantially."
            )
        # If multiple patterns matched, suggest narrowing the wording.
        if len(patterns) > 1:
            names = [p.name for p in patterns]
            hints.append(
                f"If too broad: the description matched {len(patterns)} "
                f"patterns ({', '.join(names)}). Narrow the wording to "
                "select only the one you need."
            )

    # If iam:PassRole is in the factors, hint about role-arn extraction.
    if any("PassRole" in f for f in risk_factors):
        hints.append(
            "If you don't need to pass an IAM role, re-issue with "
            "`refinement.exclude_actions = ['iam:PassRole']`. If you "
            "do, name the role explicitly in the description "
            "(\"with role app-runtime-role\") so PassRole's Resource "
            "narrows to that specific role ARN."
        )

    # No matches at all OR no resources extracted: suggest rewording.
    if scored_risk >= 5 and not resources:
        hints.append(
            "Tip: include the resource's name in the description "
            "(e.g. \"the prod-orders DynamoDB table\") for a narrower "
            "policy. The generator falls back to wildcards when names "
            "are missing."
        )

    return hints


def _estimate_confidence(
    patterns: list[Pattern],
    resources: list[ExtractedResource],
    risk_score: int,
) -> int:
    """Confidence 1-10 (higher = less confident).

    Heuristic:
      - +0 if multiple patterns matched AND resources were extracted
      - +1 if no resources were extracted (pure wildcards in output)
      - +1 per matched pattern beyond the first (ambiguous description)
      - +2 if risk_score >= 8 (the scorer is unhappy with the output)
    Clamped to [1, 10].
    """
    score = 1
    if not resources:
        score += 1
    if len(patterns) > 1:
        score += len(patterns) - 1
    if risk_score >= 8:
        score += 2
    return min(10, max(1, score))
