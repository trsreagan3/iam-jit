"""`iam-risk-score` CLI — score an IAM policy from the command line.

Offline-only: runs the deterministic scorer locally without any
network call. Safe in pre-commit hooks, air-gapped CI runners, or
any environment where a hosted scoring API isn't available.

(The hosted remote API mode was removed on 2026-05-24 when the
hosted iam-risk-score Lambda was dropped per [[no-hosted-saas]]
restoration. The deterministic scorer is the moat; the hosted
access shell is no longer maintained.)

  iam-risk-score policy.json

Output formats:

  - `human` (default): colorized terminal output with score,
    factors, and suggestions
  - `json`: programmatic JSON output for piping into other tools
  - `github`: GitHub Actions workflow command format (sets
    outputs, prints annotations)
  - `sarif`: SARIF 2.1.0 output for GitHub Code Scanning, GitLab
    Code Quality, and other security-CI consumers.

Exit codes:

  - 0: scored successfully AND score is below threshold
  - 1: scored successfully but score >= threshold (CI gate fail)
  - 2: invalid input (bad policy file, malformed JSON)

Threshold defaults to 5 (matches iam-jit's default
auto-approve threshold); override with `--threshold N`.

The CLI is intentionally narrow. For full request workflows
(provision, assume, revoke), use the broader `iam-jit` CLI.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


__version__ = "0.1.0"


def _read_policy(path: str) -> dict[str, Any]:
    """Load a policy from a file path or `-` for stdin."""
    if path == "-":
        text = sys.stdin.read()
    else:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"policy file not found: {path}")
        text = p.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"could not parse JSON from {path}: {e}")


def _score_offline(payload: dict[str, Any]) -> dict[str, Any]:
    """Run the deterministic scorer locally. Same shape as the API
    response so downstream tooling treats the two paths
    interchangeably."""
    from iam_jit import review

    policy = payload["policy"]
    request_shape = {
        "spec": {
            "access_type": payload.get("access_type", "read-only"),
            "duration": {
                "duration_hours": payload.get("duration_hours", 1),
            },
            "resource_constraints": [],
        }
    }
    extras_s = tuple(payload.get("additional_sensitive_services") or ())
    extras_a = tuple(payload.get("additional_high_impact_actions") or ())

    analysis = review.analyze_policy(
        policy, request_shape,
        extra_sensitive_services=extras_s,
        extra_high_impact_actions=extras_a,
    )
    score = analysis.risk_score
    tier = "low" if score <= 3 else ("medium" if score <= 5 else "high")
    import hashlib as _h
    fp = "sha256:" + _h.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "score": score,
        "tier": tier,
        "would_auto_approve_at_threshold_5": score < 5,
        "factors": list(analysis.risk_factors),
        "suggestions": list(analysis.suggestions),
        "llm_narrative": analysis.llm_narrative,
        "analyzer": analysis.analyzer,
        "policy_fingerprint": fp,
        "api_version": "v1-offline",
    }


def _format_human(result: dict[str, Any], threshold: int) -> str:
    """Colorized terminal output. ANSI escapes only — no library
    dep. Buffers everything then returns one string."""
    score = result["score"]
    tier = result["tier"]
    color = {
        "low": "\033[32m",        # green
        "medium": "\033[33m",     # yellow
        "high": "\033[31m",       # red
    }.get(tier, "")
    reset = "\033[0m" if color else ""
    bold = "\033[1m"

    pass_fail = "PASS" if score < threshold else "FAIL"
    pf_color = "\033[32m" if score < threshold else "\033[31m"

    lines = [
        f"{bold}IAM Policy Risk Score{reset}",
        "",
        f"  Score:     {color}{bold}{score}/10 ({tier}){reset}",
        f"  Threshold: {threshold} ({pf_color}{pass_fail}{reset})",
        f"  Analyzer:  {result['analyzer']}",
    ]

    if result.get("factors"):
        lines.append("")
        lines.append(f"{bold}Risk factors:{reset}")
        for f in result["factors"]:
            lines.append(f"  - {f}")

    if result.get("suggestions"):
        lines.append("")
        lines.append(f"{bold}Suggestions to reduce risk:{reset}")
        for s in result["suggestions"]:
            lines.append(f"  - {s}")

    if result.get("llm_narrative"):
        lines.append("")
        lines.append(f"{bold}Narrative:{reset}")
        lines.append(f"  {result['llm_narrative']}")

    return "\n".join(lines)


def _format_sarif(
    result: dict[str, Any], threshold: int, *, policy_path: str
) -> str:
    """SARIF 2.1.0 output.

    The Static Analysis Results Interchange Format (OASIS) is the
    lingua franca for CI security tooling: GitHub Code Scanning,
    GitLab Code Quality, and most enterprise SIEMs ingest it
    natively. Emitting SARIF makes iam-jit consumable by any CI
    that already understands "security findings" — no plugin
    required.

    One result per risk factor; the policy file is the artifact;
    threshold-FAIL becomes a `level=error`, otherwise `note`. The
    rule id is the score-tier so dashboards group by severity.
    """
    score = result["score"]
    tier = result["tier"]
    factors = result.get("factors") or []
    suggestions = result.get("suggestions") or []
    fingerprint = result.get("policy_fingerprint", "")
    fail = score >= threshold

    # Stable artifact location: relative path the CI checked out the
    # policy from. "-" (stdin) becomes a synthetic stdin: URI.
    if policy_path == "-":
        artifact_uri = "stdin://policy.json"
    else:
        artifact_uri = policy_path

    sarif_level = "error" if fail else ("warning" if tier == "medium" else "note")

    rules = [
        {
            "id": f"iam-risk-score/{tier}",
            "name": f"IamPolicyRisk{tier.title()}",
            "shortDescription": {
                "text": f"IAM policy scored as {tier} risk ({score}/10)"
            },
            "fullDescription": {
                "text": (
                    "iam-jit's deterministic IAM policy risk scorer "
                    "rates this policy on a 1-10 scale calibrated "
                    "against 1,489 AWS-managed policies and 217 "
                    "documented attack patterns. See "
                    "https://github.com/trsreagan3/iam-jit/blob/main/"
                    "docs/scoring-bands.md for the scoring rubric."
                )
            },
            "defaultConfiguration": {"level": sarif_level},
            "helpUri": (
                "https://github.com/trsreagan3/iam-jit/blob/main/"
                "docs/scoring-bands.md"
            ),
        }
    ]

    results: list[dict[str, Any]] = []
    if not factors:
        # Always emit at least one result so the SARIF artifact has
        # the score in it; otherwise green policies look like the
        # scanner didn't run.
        results.append(
            {
                "ruleId": f"iam-risk-score/{tier}",
                "level": sarif_level,
                "message": {
                    "text": (
                        f"IAM policy score: {score}/10 ({tier}). "
                        f"Threshold: {threshold}. "
                        f"{'FAIL' if fail else 'PASS'}."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri}
                        }
                    }
                ],
                "partialFingerprints": (
                    {"policy.fingerprint/v1": fingerprint}
                    if fingerprint else {}
                ),
            }
        )
    else:
        for i, factor in enumerate(factors):
            suggestion = (
                suggestions[i] if i < len(suggestions) else None
            )
            text = f"{factor}"
            if suggestion:
                text += f"\n\nSuggested mitigation: {suggestion}"
            results.append(
                {
                    "ruleId": f"iam-risk-score/{tier}",
                    "level": sarif_level,
                    "message": {"text": text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": artifact_uri}
                            }
                        }
                    ],
                    "partialFingerprints": (
                        {"policy.fingerprint/v1": fingerprint}
                        if fingerprint else {}
                    ),
                }
            )

    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "iam-risk-score",
                        "version": __version__,
                        "informationUri": "https://github.com/trsreagan3/iam-jit",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "iam_jit.score": score,
                    "iam_jit.tier": tier,
                    "iam_jit.threshold": threshold,
                    "iam_jit.pass": not fail,
                    "iam_jit.analyzer": result.get("analyzer", ""),
                    "iam_jit.api_version": result.get("api_version", ""),
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _format_github(result: dict[str, Any], threshold: int) -> str:
    """GitHub Actions workflow commands.

    Sets output variables the downstream workflow can read (score,
    tier, would_auto_approve). Emits an annotation at the right
    severity (notice/warning/error) so PR diffs show the score
    inline."""
    out_lines = []
    score = result["score"]
    tier = result["tier"]
    fingerprint = result["policy_fingerprint"]
    factors = result.get("factors") or []

    # Set outputs (consumed by `${{ steps.score.outputs.X }}` in workflows)
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as f:
            f.write(f"score={score}\n")
            f.write(f"tier={tier}\n")
            f.write(f"would_auto_approve={'true' if score < threshold else 'false'}\n")
            f.write(f"policy_fingerprint={fingerprint}\n")

    # Annotation: notice/warning/error based on tier
    annotation = {
        "low": "notice",
        "medium": "warning",
        "high": "error",
    }.get(tier, "notice")
    factors_str = "; ".join(factors) if factors else "no factors"
    out_lines.append(
        f"::{annotation} title=IAM Policy Score::"
        f"Score {score}/10 ({tier}). {factors_str}"
    )
    return "\n".join(out_lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iam-risk-score",
        description=__doc__.split("\n\n")[0],
    )
    parser.add_argument(
        "policy_file",
        help="Path to the policy JSON file (use '-' for stdin)",
    )
    parser.add_argument(
        "--access-type", choices=["read-only", "read-write"],
        default="read-only",
        help="Whether the requester intends to mutate state (default: read-only)",
    )
    parser.add_argument(
        "--duration-hours", type=int, default=1,
        help="Grant duration in hours; longer = higher risk (default: 1)",
    )
    parser.add_argument(
        "--description", default=None,
        help="Optional context for the LLM narrative",
    )
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Score threshold for the pass/fail exit code (default: 5)",
    )
    # --offline / --api / --api-key were removed on 2026-05-24 when
    # the hosted iam-risk-score Lambda was dropped per
    # [[no-hosted-saas]] restoration. The CLI is now offline-only;
    # `--offline` is silently accepted as a back-compat no-op so
    # existing CI scripts that pass it keep working through the v1.0
    # transition window. Remove in v1.1.
    parser.add_argument(
        "--offline", action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--format", choices=["human", "json", "github", "sarif"],
        default="human",
        help=(
            "Output format (default: human). "
            "`sarif` emits SARIF 2.1.0 for GitHub Code Scanning, "
            "GitLab Code Quality, and other security-CI consumers."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args(argv)

    try:
        policy = _read_policy(args.policy_file)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    payload = {
        "policy": policy,
        "access_type": args.access_type,
        "duration_hours": args.duration_hours,
    }
    if args.description:
        payload["description"] = args.description

    try:
        result = _score_offline(payload)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    if args.format == "json":
        print(json.dumps(result, indent=2))
    elif args.format == "github":
        print(_format_github(result, args.threshold))
    elif args.format == "sarif":
        print(_format_sarif(
            result, args.threshold, policy_path=args.policy_file,
        ))
    else:
        print(_format_human(result, args.threshold))

    return 0 if result["score"] < args.threshold else 1


if __name__ == "__main__":
    sys.exit(main())
