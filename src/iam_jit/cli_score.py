"""`iam-risk-score` CLI — score an IAM policy from the command line.

Two modes:

  1. **Hosted/remote** (default): POST the policy to a running
     iam-jit scoring API. Use the public hosted service, your own
     self-hosted deployment, or a local `iam-jit serve`.

     iam-risk-score --api https://api.iam-jit.dev policy.json

  2. **Offline**: run the deterministic scorer locally without
     any network call. Useful for pre-commit hooks and air-gapped
     CI runners. The LLM narrative is omitted in offline mode
     (the deterministic score is the same).

     iam-risk-score --offline policy.json

Output formats:

  - `human` (default): colorized terminal output with score,
    factors, and suggestions
  - `json`: programmatic JSON output for piping into other tools
  - `github`: GitHub Actions workflow command format (sets
    outputs, prints annotations)

Exit codes:

  - 0: scored successfully AND score is below threshold
  - 1: scored successfully but score >= threshold (CI gate fail)
  - 2: invalid input (bad policy file, malformed JSON)
  - 3: API error (network, auth, server)

Threshold defaults to 5 (matches iam-jit's default
auto-approve threshold); override with `--threshold N`.

The CLI is intentionally narrow. For full request workflows
(provision, assume, revoke), use the iam-jit web UI or the
broader `iam-jit` CLI.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, request


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


def _score_remote(
    api_url: str,
    api_key: str | None,
    payload: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    """Call the hosted /api/v1/score endpoint."""
    url = api_url.rstrip("/") + "/api/v1/score"
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": f"iam-risk-score/{__version__}"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = request.Request(url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"API returned HTTP {e.code}: {detail[:400]}"
        )
    except error.URLError as e:
        raise RuntimeError(f"could not reach API at {url}: {e.reason}")


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
    parser.add_argument(
        "--api", default=os.environ.get("IAM_RISK_SCORE_API_URL"),
        help=(
            "Hosted scoring API URL (default: $IAM_RISK_SCORE_API_URL). "
            "Required unless --offline is set."
        ),
    )
    parser.add_argument(
        "--api-key", default=os.environ.get("IAM_RISK_SCORE_API_KEY"),
        help="API key for the hosted service (default: $IAM_RISK_SCORE_API_KEY)",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help=(
            "Run the deterministic scorer locally without a network "
            "call. LLM narrative is unavailable in this mode."
        ),
    )
    parser.add_argument(
        "--format", choices=["human", "json", "github"],
        default="human",
        help="Output format (default: human)",
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="API request timeout in seconds (default: 30)",
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
        if args.offline:
            result = _score_offline(payload)
        else:
            if not args.api:
                print(
                    "ERROR: --api or IAM_RISK_SCORE_API_URL must be set, "
                    "or use --offline",
                    file=sys.stderr,
                )
                return 2
            result = _score_remote(
                args.api, args.api_key, payload, args.timeout,
            )
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    if args.format == "json":
        print(json.dumps(result, indent=2))
    elif args.format == "github":
        print(_format_github(result, args.threshold))
    else:
        print(_format_human(result, args.threshold))

    return 0 if result["score"] < args.threshold else 1


if __name__ == "__main__":
    sys.exit(main())
